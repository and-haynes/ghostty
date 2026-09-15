import Crypto
import Foundation
import NIOCore
import NIOSSH

/// The static half of an AES-CTR + HMAC transport protection scheme.
///
/// SSH negotiates cipher and MAC separately, but `NIOSSHTransportProtection`
/// models the pair as one object, so every (cipher, MAC, ordering) combination
/// needs its own type. Rather than a dozen near-identical classes — the shape
/// swift-nio-ssh itself uses, complete with `fatalError` stubs — the varying
/// part is this protocol and the behaviour lives once in a generic class.
protocol AESCTRParameters {
    /// The cipher name as negotiated on the wire, e.g. `aes256-ctr`.
    static var cipherName: String { get }
    /// AES key length in bytes: 16, 24 or 32.
    static var keyLength: Int { get }
    static var mac: SSHMACAlgorithm { get }
    /// True for OpenSSH's `-etm@openssh.com` MACs, which authenticate the
    /// ciphertext and leave the packet length in the clear.
    static var encryptThenMAC: Bool { get }
}

extension AESCTRParameters {
    static var macName: String {
        Self.encryptThenMAC ? Self.mac.etmName : Self.mac.plainName
    }
}

/// AES-CTR with an HMAC, the cipher suite every SSH implementation older or
/// smaller than OpenSSH 6.2 actually offers.
///
/// swift-nio-ssh ships `aes128-gcm@openssh.com` and `aes256-gcm@openssh.com`
/// and nothing else, so a router, a NAS appliance or a Dropbear box — none of
/// which do GCM — has no cipher in common with the client and the handshake
/// dies as `NIOSSHError.keyExchangeNegotiationFailure` before anything useful
/// has happened. That is the bug this type exists to fix.
///
/// ### The two orderings
///
/// * **MAC-then-encrypt** (`hmac-sha2-256`, RFC 4253 §6.4). The whole packet —
///   length included — is encrypted, and the MAC is taken over the *plaintext*
///   preceded by the sequence number. Decryption therefore has to happen before
///   verification, which is the weakness OpenSSH's `-etm` modes were invented
///   to remove; it is implemented here because plenty of servers offer nothing
///   better.
/// * **Encrypt-then-MAC** (`hmac-sha2-256-etm@openssh.com`). The length stays
///   in the clear, the rest is encrypted, and the MAC covers the sequence
///   number, the length and the ciphertext. Verification happens first, so a
///   forged packet never reaches the cipher.
///
/// The padding rules differ accordingly, which is exactly what NIOSSH's
/// `lengthEncrypted` flag selects: when the length is encrypted it counts
/// toward the block-alignment of the packet, and when it is not, it does not.
final class AESCTRTransportProtection<Parameters: AESCTRParameters>: NIOSSHTransportProtection {
    private var inbound: AESCounterMode
    private var outbound: AESCounterMode
    private var inboundMACKey: SymmetricKey
    private var outboundMACKey: SymmetricKey

    static var cipherName: String { Parameters.cipherName }
    static var macName: String? { Parameters.macName }
    static var cipherBlockSize: Int { AESCounterMode.blockSize }
    static var keySizes: ExpectedKeySizes {
        ExpectedKeySizes(
            // CTR's "IV" is the initial counter block: one full AES block.
            ivSize: AESCounterMode.blockSize,
            encryptionKeySize: Parameters.keyLength,
            macKeySize: Parameters.mac.keyLength
        )
    }

    var macBytes: Int { Parameters.mac.tagLength }
    var lengthEncrypted: Bool { !Parameters.encryptThenMAC }

    init(initialKeys: NIOSSHSessionKeys) throws {
        try Self.validate(initialKeys)
        self.inbound = try AESCounterMode(
            key: initialKeys.inboundEncryptionKey,
            iv: initialKeys.initialInboundIV
        )
        self.outbound = try AESCounterMode(
            key: initialKeys.outboundEncryptionKey,
            iv: initialKeys.initialOutboundIV
        )
        self.inboundMACKey = initialKeys.inboundMACKey
        self.outboundMACKey = initialKeys.outboundMACKey
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        try Self.validate(newKeys)
        // A rekey restarts both counters from the freshly derived IVs.
        self.inbound = try AESCounterMode(
            key: newKeys.inboundEncryptionKey,
            iv: newKeys.initialInboundIV
        )
        self.outbound = try AESCounterMode(
            key: newKeys.outboundEncryptionKey,
            iv: newKeys.initialOutboundIV
        )
        self.inboundMACKey = newKeys.inboundMACKey
        self.outboundMACKey = newKeys.outboundMACKey
    }

    /// swift-nio-ssh derives session keys by truncating a *single* key-exchange
    /// hash rather than running RFC 4253 §7.2's expansion, so it cannot produce
    /// more key material than the exchange hash is long. Checking here turns
    /// that into a clean error instead of a MAC failure ten packets later.
    private static func validate(_ keys: NIOSSHSessionKeys) throws {
        let want = Self.keySizes
        guard keys.inboundEncryptionKey.bitCount == want.encryptionKeySize * 8,
            keys.outboundEncryptionKey.bitCount == want.encryptionKeySize * 8
        else {
            throw SSHCipherError.badKeySize(expected: want.encryptionKeySize, actual: keys.inboundEncryptionKey.bitCount / 8)
        }
        guard keys.inboundMACKey.bitCount == want.macKeySize * 8,
            keys.outboundMACKey.bitCount == want.macKeySize * 8
        else {
            throw SSHCipherError.badKeySize(expected: want.macKeySize, actual: keys.inboundMACKey.bitCount / 8)
        }
        guard keys.initialInboundIV.count == want.ivSize,
            keys.initialOutboundIV.count == want.ivSize
        else {
            throw SSHCipherError.badIVSize(expected: want.ivSize, actual: keys.initialInboundIV.count)
        }
    }

    // MARK: - Inbound

    func decryptFirstBlock(_ source: inout ByteBuffer) throws {
        // Encrypt-then-MAC leaves the length in the clear; there is nothing to do
        // and, critically, nothing may be decrypted before the MAC is checked.
        guard Parameters.encryptThenMAC == false else { return }

        // The parser guarantees at least one cipher block is available and
        // promises to hand the *same* buffer to `decryptAndVerifyRemainingPacket`,
        // so decrypting exactly one block in place and leaving the counter where
        // it lands is both sufficient and required.
        try source.withUnsafeMutableReadableBytes { pointer in
            let block = UnsafeMutableRawBufferPointer(
                rebasing: pointer[..<AESCounterMode.blockSize]
            )
            try self.inbound.apply(to: block)
        }
    }

    func decryptAndVerifyRemainingPacket(
        _ source: inout ByteBuffer,
        sequenceNumber: UInt32
    ) throws -> ByteBuffer {
        let macBytes = self.macBytes
        guard let packetLength32 = source.getInteger(at: source.readerIndex, as: UInt32.self) else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }
        let packetLength = Int(packetLength32)
        // The parser sized this slice from the length field itself, so a
        // mismatch here means the framing is not this scheme's.
        guard source.readableBytes == 4 + packetLength + macBytes, packetLength > 0 else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        let encryptedRegion = Parameters.encryptThenMAC ? packetLength : 4 + packetLength
        guard encryptedRegion % AESCounterMode.blockSize == 0 else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        guard let tag = source.getBytes(at: source.readerIndex + 4 + packetLength, length: macBytes)
        else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        if Parameters.encryptThenMAC {
            // Verify over sequence || length || ciphertext, then decrypt.
            let verified = source.withUnsafeMutableReadableBytes { pointer -> Bool in
                Parameters.mac.verify(
                    tag,
                    sequenceNumber: sequenceNumber,
                    over: [Self.region(pointer, from: 0, count: 4 + packetLength)],
                    key: self.inboundMACKey
                )
            }
            guard verified else { throw SSHCipherError.macMismatch }

            try source.withUnsafeMutableReadableBytes { pointer in
                let body = UnsafeMutableRawBufferPointer(
                    rebasing: pointer[4..<(4 + packetLength)]
                )
                try self.inbound.apply(to: body)
            }
        } else {
            // The first cipher block is already plaintext (`decryptFirstBlock`);
            // decrypt what is left, then verify over the whole plaintext packet.
            try source.withUnsafeMutableReadableBytes { pointer in
                guard encryptedRegion > AESCounterMode.blockSize else { return }
                let rest = UnsafeMutableRawBufferPointer(
                    rebasing: pointer[AESCounterMode.blockSize..<encryptedRegion]
                )
                try self.inbound.apply(to: rest)
            }

            let verified = source.withUnsafeMutableReadableBytes { pointer -> Bool in
                Parameters.mac.verify(
                    tag,
                    sequenceNumber: sequenceNumber,
                    over: [Self.region(pointer, from: 0, count: 4 + packetLength)],
                    key: self.inboundMACKey
                )
            }
            guard verified else { throw SSHCipherError.macMismatch }
        }

        // Hand back just the payload, having consumed the length, the padding
        // length byte, the padding and the MAC.
        source.moveReaderIndex(forwardBy: 4)
        guard let paddingLength = source.readInteger(as: UInt8.self), paddingLength >= 4 else {
            throw SSHCipherError.malformedPacket("the packet declares fewer than the four padding bytes RFC 4253 requires")
        }
        let contentLength = packetLength - 1 - Int(paddingLength)
        guard contentLength >= 0, let content = source.readSlice(length: contentLength) else {
            throw SSHCipherError.malformedPacket("the packet declares more padding than it contains")
        }
        source.moveReaderIndex(forwardBy: Int(paddingLength) + macBytes)
        return content
    }

    // MARK: - Outbound

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let packetBytes = destination.readableBytes
        guard packetBytes >= 5 else { throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent") }

        let tag: [UInt8]
        if Parameters.encryptThenMAC {
            try destination.withUnsafeMutableReadableBytes { pointer in
                let body = UnsafeMutableRawBufferPointer(rebasing: pointer[4...])
                try self.outbound.apply(to: body)
            }
            tag = destination.withUnsafeMutableReadableBytes { pointer in
                Parameters.mac.authenticate(
                    sequenceNumber: sequenceNumber,
                    over: [Self.region(pointer, from: 0, count: packetBytes)],
                    key: self.outboundMACKey
                )
            }
        } else {
            tag = destination.withUnsafeMutableReadableBytes { pointer in
                Parameters.mac.authenticate(
                    sequenceNumber: sequenceNumber,
                    over: [Self.region(pointer, from: 0, count: packetBytes)],
                    key: self.outboundMACKey
                )
            }
            try destination.withUnsafeMutableReadableBytes { pointer in
                try self.outbound.apply(to: pointer)
            }
        }

        // The writer index is already at the end of the packet, so the MAC
        // simply appends. The reader index is untouched, which is what the
        // serializer expects to find when it restores its own.
        destination.writeBytes(tag)
    }

    // MARK: - Helpers

    /// A `Data` view over part of a buffer without copying it. Only ever used
    /// inside the `withUnsafeMutableReadableBytes` closure that owns the
    /// pointer, so the no-copy lifetime rule holds.
    private static func region(
        _ pointer: UnsafeMutableRawBufferPointer,
        from offset: Int,
        count: Int
    ) -> Data {
        guard let base = pointer.baseAddress else { return Data() }
        return Data(bytesNoCopy: base + offset, count: count, deallocator: .none)
    }
}

// MARK: - The twelve concrete schemes

enum AES128CTRHMACSHA256: AESCTRParameters {
    static let cipherName = "aes128-ctr"
    static let keyLength = 16
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = false
}

enum AES192CTRHMACSHA256: AESCTRParameters {
    static let cipherName = "aes192-ctr"
    static let keyLength = 24
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = false
}

enum AES256CTRHMACSHA256: AESCTRParameters {
    static let cipherName = "aes256-ctr"
    static let keyLength = 32
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = false
}

enum AES128CTRHMACSHA256ETM: AESCTRParameters {
    static let cipherName = "aes128-ctr"
    static let keyLength = 16
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = true
}

enum AES192CTRHMACSHA256ETM: AESCTRParameters {
    static let cipherName = "aes192-ctr"
    static let keyLength = 24
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = true
}

enum AES256CTRHMACSHA256ETM: AESCTRParameters {
    static let cipherName = "aes256-ctr"
    static let keyLength = 32
    static let mac = SSHMACAlgorithm.hmacSHA256
    static let encryptThenMAC = true
}

enum AES128CTRHMACSHA512: AESCTRParameters {
    static let cipherName = "aes128-ctr"
    static let keyLength = 16
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = false
}

enum AES192CTRHMACSHA512: AESCTRParameters {
    static let cipherName = "aes192-ctr"
    static let keyLength = 24
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = false
}

enum AES256CTRHMACSHA512: AESCTRParameters {
    static let cipherName = "aes256-ctr"
    static let keyLength = 32
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = false
}

enum AES128CTRHMACSHA512ETM: AESCTRParameters {
    static let cipherName = "aes128-ctr"
    static let keyLength = 16
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = true
}

enum AES192CTRHMACSHA512ETM: AESCTRParameters {
    static let cipherName = "aes192-ctr"
    static let keyLength = 24
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = true
}

enum AES256CTRHMACSHA512ETM: AESCTRParameters {
    static let cipherName = "aes256-ctr"
    static let keyLength = 32
    static let mac = SSHMACAlgorithm.hmacSHA512
    static let encryptThenMAC = true
}
