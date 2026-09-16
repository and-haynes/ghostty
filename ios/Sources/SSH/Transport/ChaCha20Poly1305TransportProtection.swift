import Crypto
import Foundation
import NIOCore
import NIOSSH

/// `chacha20-poly1305@openssh.com` as a swift-nio-ssh transport protection.
///
/// The packet construction itself lives in ``ChaCha20Poly1305OpenSSH``, pinned
/// to the RFC 8439 vectors; this type is the adapter that lets NIOSSH drive it.
///
/// ## Why this could not exist before
///
/// Two blockers, both in the library, both now fixed on the fork (#008D0):
///
/// 1. `decryptFirstBlock` had to turn the packet length back into plaintext but
///    was handed no sequence number — and for this cipher the sequence number
///    *is* the nonce the length was encrypted under. The protocol simply had no
///    shape this cipher fit into. It now takes the sequence number.
/// 2. The 64-byte key could not be derived. swift-nio-ssh truncated a single
///    key-exchange hash instead of running RFC 4253 §7.2's expansion, so the
///    most key material it could produce was the exchange hash's length — 32
///    bytes under `curve25519-sha256`. The fork expands.
///
/// ## Framing notes worth knowing
///
/// * **The key is 64 bytes, not 32.** `K_main` (the first half) encrypts the
///   payload, `K_header` (the second) encrypts the 4-byte length, so packet
///   boundaries are hidden from a passive observer.
/// * **The length field is encrypted but does not count toward padding.**
///   OpenSSH treats it as additional authenticated data, so alignment is
///   computed over `padding_length || payload || padding` alone, exactly as the
///   `-etm` modes do. That is what NIOSSH's `lengthEncrypted = false` selects —
///   the flag means "does the length count toward the block alignment", not
///   "is the length in the clear".
/// * **The tag covers the *ciphertext* of the length**, which
///   `decryptFirstBlock` has already overwritten with plaintext by the time the
///   rest of the packet arrives. The four encrypted bytes are therefore kept
///   until `decryptAndVerifyRemainingPacket` runs. The parser calls the two in
///   that order, once each per packet, which is what makes holding the state
///   safe.
final class ChaCha20Poly1305TransportProtection: NIOSSHTransportProtection {
    private var inboundKey: [UInt8]
    private var outboundKey: [UInt8]

    /// The still-encrypted length field of the packet currently being read.
    ///
    /// Set by `decryptFirstBlock` and consumed by
    /// `decryptAndVerifyRemainingPacket`; nil at every other moment.
    private var encryptedLengthField: [UInt8]?

    static var cipherName: String { "chacha20-poly1305@openssh.com" }

    /// nil: this is an AEAD, and like the OpenSSH GCM modes it ignores whatever
    /// the MAC negotiation settles on.
    static var macName: String? { nil }

    /// 8, as in OpenSSH's cipher table. It is not a block size in the AES sense
    /// — ChaCha20 is a stream cipher — but it is the alignment SSH pads to and
    /// the number of bytes the parser waits for before asking for the length.
    static var cipherBlockSize: Int { 8 }

    static var keySizes: ExpectedKeySizes {
        ExpectedKeySizes(
            // No IV: the nonce is the packet sequence number.
            ivSize: 0,
            encryptionKeySize: ChaCha20Poly1305OpenSSH.keySize,
            // No MAC key either, but ask for 16 bytes rather than 0 for the same
            // reason the library's own GCM modes do: nothing downstream has to
            // cope with a zero-length `SymmetricKey`.
            macKeySize: 16
        )
    }

    var macBytes: Int { ChaCha20Poly1305OpenSSH.tagSize }

    /// False. See the framing note above: the length is encrypted, but it is
    /// authenticated data and is excluded from the padding calculation.
    var lengthEncrypted: Bool { false }

    init(initialKeys: NIOSSHSessionKeys) throws {
        self.inboundKey = try Self.key(initialKeys.inboundEncryptionKey)
        self.outboundKey = try Self.key(initialKeys.outboundEncryptionKey)
    }

    func updateKeys(_ newKeys: NIOSSHSessionKeys) throws {
        self.inboundKey = try Self.key(newKeys.inboundEncryptionKey)
        self.outboundKey = try Self.key(newKeys.outboundEncryptionKey)
        // A rekey abandons any half-read packet; the parser will not resume one
        // across a key change, so holding a stale length field would be a bug.
        self.encryptedLengthField = nil
    }

    private static func key(_ key: SymmetricKey) throws -> [UInt8] {
        guard key.bitCount == ChaCha20Poly1305OpenSSH.keySize * 8 else {
            throw SSHCipherError.badKeySize(
                expected: ChaCha20Poly1305OpenSSH.keySize,
                actual: key.bitCount / 8
            )
        }
        return key.withUnsafeBytes { Array($0) }
    }

    // MARK: - Inbound

    func decryptFirstBlock(_ source: inout ByteBuffer, sequenceNumber: UInt32) throws {
        let lengthFieldSize = ChaCha20Poly1305OpenSSH.lengthFieldSize
        guard let encrypted = source.getBytes(at: source.readerIndex, length: lengthFieldSize) else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        let length = try ChaCha20Poly1305OpenSSH.decryptLength(
            encrypted,
            key: self.inboundKey,
            sequenceNumber: sequenceNumber
        )

        // Keep the ciphertext: the Poly1305 tag covers it, not the plaintext we
        // are about to write over it.
        self.encryptedLengthField = encrypted
        source.setInteger(length, at: source.readerIndex)
    }

    func decryptAndVerifyRemainingPacket(
        _ source: inout ByteBuffer,
        sequenceNumber: UInt32
    ) throws -> ByteBuffer {
        let lengthFieldSize = ChaCha20Poly1305OpenSSH.lengthFieldSize
        let tagSize = ChaCha20Poly1305OpenSSH.tagSize

        guard let encryptedLengthField = self.encryptedLengthField else {
            throw SSHCipherError.malformedPacket(
                "the packet body arrived without its length having been decrypted"
            )
        }
        self.encryptedLengthField = nil

        guard let packetLength32 = source.getInteger(at: source.readerIndex, as: UInt32.self),
            packetLength32 > 0
        else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }
        let packetLength = Int(packetLength32)

        // The parser sized this slice from the length field, so a mismatch means
        // the framing is not this scheme's.
        guard source.readableBytes == lengthFieldSize + packetLength + tagSize,
            let body = source.getBytes(at: source.readerIndex + lengthFieldSize, length: packetLength + tagSize)
        else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        // `open` authenticates before it decrypts, which is the whole point of
        // the construction, so a forged packet never reaches the cipher.
        let plaintext = try ChaCha20Poly1305OpenSSH.open(
            sealed: encryptedLengthField + body,
            key: self.inboundKey,
            sequenceNumber: sequenceNumber
        )

        // plaintext is `length || padding_length || payload || padding`.
        let paddingLength = Int(plaintext[lengthFieldSize])
        guard paddingLength >= 4 else {
            throw SSHCipherError.malformedPacket(
                "the packet declares fewer than the four padding bytes RFC 4253 requires"
            )
        }
        let contentLength = packetLength - 1 - paddingLength
        guard contentLength >= 0 else {
            throw SSHCipherError.malformedPacket("the packet declares more padding than it contains")
        }

        let contentStart = lengthFieldSize + 1
        let content = ByteBuffer(bytes: plaintext[contentStart..<(contentStart + contentLength)])

        // Consume the whole packet: the parser checks the slice is empty after.
        source.moveReaderIndex(forwardBy: lengthFieldSize + packetLength + tagSize)
        return content
    }

    // MARK: - Outbound

    func encryptPacket(_ destination: inout ByteBuffer, sequenceNumber: UInt32) throws {
        guard
            let plaintext = destination.getBytes(
                at: destination.readerIndex,
                length: destination.readableBytes
            ), plaintext.count > ChaCha20Poly1305OpenSSH.lengthFieldSize
        else {
            throw SSHCipherError.malformedPacket("the packet length field is missing or inconsistent")
        }

        let sealed = try ChaCha20Poly1305OpenSSH.seal(
            packet: plaintext,
            key: self.outboundKey,
            sequenceNumber: sequenceNumber
        )

        // Rewind over the plaintext and write the sealed packet in its place.
        // The reader index is untouched, which is what the serializer expects to
        // find when it restores its own.
        destination.moveWriterIndex(to: destination.readerIndex)
        destination.writeBytes(sealed)
    }
}
