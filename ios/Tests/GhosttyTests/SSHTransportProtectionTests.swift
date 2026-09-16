import Crypto
import Foundation
import NIOCore
import NIOSSH
import XCTest

@testable import Ghostty

/// The AES-CTR transport protection schemes, driven through exactly the
/// interface swift-nio-ssh drives them through.
///
/// A scheme that passes the cipher vectors can still be wrong about the two
/// things SSH gets to be fussy about: which bytes the MAC covers, and whether
/// the packet length counts toward block alignment. Those differ between the
/// plain and `-etm` MACs, so every combination is round-tripped here the way
/// `SSHPacketSerializer` and `SSHPacketParser` would.
final class SSHTransportProtectionTests: XCTestCase {

    // MARK: - Round trips

    func testAES256CTRWithHMACSHA256RoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES256CTRHMACSHA256>.self)
    }

    func testAES256CTRWithHMACSHA256ETMRoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.self)
    }

    func testAES192CTRWithHMACSHA256RoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES192CTRHMACSHA256>.self)
    }

    func testAES128CTRWithHMACSHA256ETMRoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES128CTRHMACSHA256ETM>.self)
    }

    func testAES256CTRWithHMACSHA512RoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES256CTRHMACSHA512>.self)
    }

    func testAES128CTRWithHMACSHA512ETMRoundTrips() throws {
        try assertRoundTrip(AESCTRTransportProtection<AES128CTRHMACSHA512ETM>.self)
    }

    /// Several packets in a row: CTR keeps its counter across packets, and a
    /// scheme that restarted it per packet would still pass a single round trip
    /// while reusing keystream — the classic catastrophic CTR bug.
    func testCounterAdvancesAcrossPackets() throws {
        let (client, server) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256>.self)
        var ciphertexts: [[UInt8]] = []
        for sequence in 0..<4 {
            let packet = SSHTransportCryptoTests.plaintextPacket(
                payload: Array("same payload every time".utf8),
                blockSize: 16,
                lengthCounts: true
            )
            var buffer = ByteBufferAllocator().buffer(capacity: packet.count + 64)
            buffer.writeBytes(packet)
            try client.encryptPacket(&buffer, sequenceNumber: UInt32(sequence))
            ciphertexts.append(Array(buffer.readableBytesView))

            let plaintext = try decrypt(&buffer, with: server, sequenceNumber: UInt32(sequence))
            XCTAssertEqual(plaintext, Array("same payload every time".utf8))
        }
        XCTAssertEqual(
            Set(ciphertexts.map { Data($0) }).count,
            ciphertexts.count,
            "identical plaintexts must not produce identical ciphertexts"
        )
    }

    // MARK: - Tamper resistance

    func testAFlippedCiphertextBitFailsTheMAC() throws {
        let (client, server) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256>.self)
        var buffer = try seal(client, payload: Array("secret".utf8), lengthCounts: true)
        // Flip a bit well inside the body, past the length field.
        let index = buffer.readerIndex + 8
        var byte = buffer.getInteger(at: index, as: UInt8.self)!
        byte ^= 0x40
        buffer.setInteger(byte, at: index)

        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 0)) { error in
            XCTAssertEqual(error as? SSHCipherError, .macMismatch)
        }
    }

    func testAFlippedCiphertextBitFailsTheMACUnderETM() throws {
        let (client, server) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.self)
        var buffer = try seal(client, payload: Array("secret".utf8), lengthCounts: false)
        let index = buffer.readerIndex + 8
        var byte = buffer.getInteger(at: index, as: UInt8.self)!
        byte ^= 0x40
        buffer.setInteger(byte, at: index)

        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 0)) { error in
            XCTAssertEqual(error as? SSHCipherError, .macMismatch)
        }
    }

    func testAReplayedPacketFailsAtADifferentSequenceNumber() throws {
        let (client, server) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.self)
        var buffer = try seal(client, payload: Array("replay me".utf8), lengthCounts: false)
        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 7)) { error in
            XCTAssertEqual(error as? SSHCipherError, .macMismatch)
        }
    }

    // MARK: - Declared shape

    func testSchemesDeclareTheRightNamesAndSizes() {
        XCTAssertEqual(AESCTRTransportProtection<AES256CTRHMACSHA256>.cipherName, "aes256-ctr")
        XCTAssertEqual(AESCTRTransportProtection<AES256CTRHMACSHA256>.macName, "hmac-sha2-256")
        XCTAssertEqual(
            AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.macName,
            "hmac-sha2-256-etm@openssh.com"
        )
        XCTAssertEqual(AESCTRTransportProtection<AES192CTRHMACSHA256>.cipherName, "aes192-ctr")
        XCTAssertEqual(AESCTRTransportProtection<AES128CTRHMACSHA512>.cipherName, "aes128-ctr")

        let sizes = AESCTRTransportProtection<AES192CTRHMACSHA512>.keySizes
        XCTAssertEqual(sizes.encryptionKeySize, 24)
        XCTAssertEqual(sizes.macKeySize, 64)
        XCTAssertEqual(sizes.ivSize, 16, "CTR's IV is a whole counter block")
        XCTAssertEqual(AESCTRTransportProtection<AES128CTRHMACSHA256>.cipherBlockSize, 16)
    }

    /// The length counts toward padding when it is encrypted, and does not when
    /// it is left in the clear for an `-etm` MAC. This is OpenSSH's `aadlen`
    /// rule, and getting it backwards produces packets a real server rejects.
    func testLengthEncryptionFlagFollowsTheMACOrdering() throws {
        let (plain, _) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256>.self)
        XCTAssertTrue(plain.lengthEncrypted)
        let (etm, _) = try makePair(AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.self)
        XCTAssertFalse(etm.lengthEncrypted)
        XCTAssertEqual(plain.macBytes, 32)
    }

    func testAMistakenKeySizeIsRejectedRatherThanTruncated() {
        // 32 bytes of MAC key where the scheme wants 64: exactly what
        // swift-nio-ssh would hand us under a SHA-256 key exchange.
        let keys = NIOSSHSessionKeys(
            initialInboundIV: [UInt8](repeating: 0, count: 16),
            initialOutboundIV: [UInt8](repeating: 0, count: 16),
            inboundEncryptionKey: SymmetricKey(data: Data(repeating: 1, count: 32)),
            outboundEncryptionKey: SymmetricKey(data: Data(repeating: 2, count: 32)),
            inboundMACKey: SymmetricKey(data: Data(repeating: 3, count: 32)),
            outboundMACKey: SymmetricKey(data: Data(repeating: 4, count: 32))
        )
        XCTAssertThrowsError(try AESCTRTransportProtection<AES256CTRHMACSHA512>(initialKeys: keys))
    }

    // MARK: - Catalog

    func testGCMStaysFirstSoNothingRegresses() {
        let names = SSHTransportProtectionCatalog.cipherNames()
        XCTAssertEqual(
            Array(names.prefix(2)),
            ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"],
            "swift-nio-ssh's own defaults, in its own order, still come first"
        )
        XCTAssertLessThan(
            names.firstIndex(of: "aes256-gcm@openssh.com")!,
            names.firstIndex(of: "aes256-ctr")!,
            "an AEAD must be preferred over CTR plus a bolt-on MAC"
        )
    }

    func testCatalogOffersEveryCTRKeyLength() {
        let names = SSHTransportProtectionCatalog.cipherNames()
        for cipher in ["aes128-ctr", "aes192-ctr", "aes256-ctr"] {
            XCTAssertTrue(names.contains(cipher), "\(cipher) should be offered")
        }
        XCTAssertLessThan(
            names.firstIndex(of: "aes256-ctr")!,
            names.firstIndex(of: "aes128-ctr")!,
            "the strongest key should be preferred"
        )
    }

    func testEncryptThenMACIsPreferred() {
        let macs = SSHTransportProtectionCatalog.macNames()
        XCTAssertEqual(macs.first, "hmac-sha2-512-etm@openssh.com")
        XCTAssertTrue(macs.contains("hmac-sha2-256"))
        XCTAssertLessThan(
            macs.firstIndex(of: "hmac-sha2-512-etm@openssh.com")!,
            macs.firstIndex(of: "hmac-sha2-512")!,
            "encrypt-then-MAC must be preferred over MAC-then-encrypt"
        )
    }

    func testStrongerMACsAreNowPreferred() {
        // hmac-sha2-256 used to come first, and not because it was better: a
        // 64-byte hmac-sha2-512 key could not be derived at all (#008A0). With
        // the key expansion in place (#008D0), preference order can go back to
        // meaning what it says.
        let macs = SSHTransportProtectionCatalog.macNames()
        XCTAssertLessThan(
            macs.firstIndex(of: "hmac-sha2-512-etm@openssh.com")!,
            macs.firstIndex(of: "hmac-sha2-256-etm@openssh.com")!
        )
    }

    func testChaCha20IsOfferedAfterTheHardwareAEADs() {
        let ciphers = SSHTransportProtectionCatalog.cipherNames()
        XCTAssertTrue(ciphers.contains("chacha20-poly1305@openssh.com"))
        XCTAssertLessThan(
            ciphers.firstIndex(of: "aes256-gcm@openssh.com")!,
            ciphers.firstIndex(of: "chacha20-poly1305@openssh.com")!,
            "AES-GCM is hardware-accelerated on every device this runs on"
        )
        XCTAssertLessThan(
            ciphers.firstIndex(of: "chacha20-poly1305@openssh.com")!,
            ciphers.firstIndex(of: "aes256-ctr")!,
            "an AEAD must be preferred over CTR plus a bolt-on MAC"
        )
    }

    /// Every scheme we offer must be keyable under the *shortest* key exchange
    /// the library will negotiate. That used to rule out anything over 32 bytes
    /// against a SHA-256 exchange, because the library truncated a single hash;
    /// it now expands per RFC 4253 §7.2, so the only real bound is that a key be
    /// a size the scheme itself will accept.
    func testEverySchemeCanBeKeyedUnderTheShortestExchange() throws {
        let shortestHash = SSHAlgorithmSupport.keyExchange.map(\.hashBytes).min() ?? 0
        XCTAssertEqual(shortestHash, 32)

        for scheme in SSHTransportProtectionCatalog.clientSchemes {
            let sizes = scheme.keySizes
            XCTAssertNoThrow(
                try scheme.init(
                    initialKeys: NIOSSHSessionKeys(
                        initialInboundIV: (0..<sizes.ivSize).map { UInt8(truncatingIfNeeded: $0) },
                        initialOutboundIV: (0..<sizes.ivSize).map { UInt8(truncatingIfNeeded: $0) },
                        inboundEncryptionKey: SymmetricKey(size: .init(bitCount: sizes.encryptionKeySize * 8)),
                        outboundEncryptionKey: SymmetricKey(size: .init(bitCount: sizes.encryptionKeySize * 8)),
                        inboundMACKey: SymmetricKey(size: .init(bitCount: sizes.macKeySize * 8)),
                        outboundMACKey: SymmetricKey(size: .init(bitCount: sizes.macKeySize * 8))
                    )
                ),
                "\(scheme.cipherName)/\(scheme.macName ?? "aead") rejected its own declared key sizes"
            )
        }
    }

    func testHMACSHA512SchemesAreOfferedOnEveryConnection() {
        // They were quarantined in `longKeySchemes` and only offered after a
        // probe confirmed an ecdh-sha2-nistp521 exchange (#008A0).
        let macs = SSHTransportProtectionCatalog.macNames()
        XCTAssertTrue(macs.contains("hmac-sha2-512-etm@openssh.com"))
        XCTAssertTrue(macs.contains("hmac-sha2-512"))
        XCTAssertEqual(
            SSHTransportProtectionCatalog.schemes(keyExchangeHashBytes: 32).count,
            SSHTransportProtectionCatalog.clientSchemes.count,
            "there is no longer a narrower list for a short exchange"
        )
        XCTAssertEqual(
            SSHTransportProtectionCatalog.schemes(keyExchangeHashBytes: 64).count,
            SSHTransportProtectionCatalog.clientSchemes.count
        )
    }

    // MARK: - Harness

    /// Two protection objects sharing a session: what the client sends, the
    /// server receives, so the keys and IVs are crossed over.
    private func makePair<P: AESCTRParameters>(
        _ type: AESCTRTransportProtection<P>.Type
    ) throws -> (client: AESCTRTransportProtection<P>, server: AESCTRTransportProtection<P>) {
        let sizes = type.keySizes
        let clientToServerKey = SymmetricKey(
            data: Data((0..<sizes.encryptionKeySize).map { UInt8(truncatingIfNeeded: $0 &* 3 &+ 1) })
        )
        let serverToClientKey = SymmetricKey(
            data: Data((0..<sizes.encryptionKeySize).map { UInt8(truncatingIfNeeded: $0 &* 5 &+ 9) })
        )
        let clientToServerMAC = SymmetricKey(
            data: Data((0..<sizes.macKeySize).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 2) })
        )
        let serverToClientMAC = SymmetricKey(
            data: Data((0..<sizes.macKeySize).map { UInt8(truncatingIfNeeded: $0 &* 11 &+ 4) })
        )
        let clientToServerIV = (0..<sizes.ivSize).map { UInt8(truncatingIfNeeded: $0 &+ 0x10) }
        let serverToClientIV = (0..<sizes.ivSize).map { UInt8(truncatingIfNeeded: $0 &+ 0x80) }

        let client = try type.init(
            initialKeys: NIOSSHSessionKeys(
                initialInboundIV: serverToClientIV,
                initialOutboundIV: clientToServerIV,
                inboundEncryptionKey: serverToClientKey,
                outboundEncryptionKey: clientToServerKey,
                inboundMACKey: serverToClientMAC,
                outboundMACKey: clientToServerMAC
            )
        )
        let server = try type.init(
            initialKeys: NIOSSHSessionKeys(
                initialInboundIV: clientToServerIV,
                initialOutboundIV: serverToClientIV,
                inboundEncryptionKey: clientToServerKey,
                outboundEncryptionKey: serverToClientKey,
                inboundMACKey: clientToServerMAC,
                outboundMACKey: serverToClientMAC
            )
        )
        return (client, server)
    }

    private func assertRoundTrip<P: AESCTRParameters>(
        _ type: AESCTRTransportProtection<P>.Type,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        let (client, server) = try makePair(type)
        // Sizes chosen to straddle block boundaries in both directions.
        for length in [0, 1, 10, 15, 16, 17, 63, 64, 300] {
            let payload = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 13) }
            var buffer = try seal(client, payload: payload, lengthCounts: client.lengthEncrypted)
            let plaintext = try decrypt(&buffer, with: server, sequenceNumber: 0)
            XCTAssertEqual(plaintext, payload, "payload of \(length) bytes", file: file, line: line)
        }
    }

    /// Encrypt a packet the way `SSHPacketSerializer` would.
    private func seal<P: AESCTRParameters>(
        _ protection: AESCTRTransportProtection<P>,
        payload: [UInt8],
        lengthCounts: Bool,
        sequenceNumber: UInt32 = 0
    ) throws -> ByteBuffer {
        let packet = SSHTransportCryptoTests.plaintextPacket(
            payload: payload,
            blockSize: AESCounterMode.blockSize,
            lengthCounts: lengthCounts
        )
        var buffer = ByteBufferAllocator().buffer(capacity: packet.count + 128)
        buffer.writeBytes(packet)
        try protection.encryptPacket(&buffer, sequenceNumber: sequenceNumber)
        return buffer
    }

    /// Decrypt a packet the way `SSHPacketParser` would: first block, read the
    /// length, then the rest.
    private func decrypt<P: AESCTRParameters>(
        _ buffer: inout ByteBuffer,
        with protection: AESCTRTransportProtection<P>,
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        try protection.decryptFirstBlock(&buffer, sequenceNumber: sequenceNumber)
        let packetLength = Int(buffer.getInteger(at: buffer.readerIndex, as: UInt32.self)!)
        var slice = buffer.readSlice(length: packetLength + protection.macBytes + 4)!
        let content = try protection.decryptAndVerifyRemainingPacket(
            &slice,
            sequenceNumber: sequenceNumber
        )
        XCTAssertEqual(slice.readableBytes, 0, "the whole packet must be consumed")
        return Array(content.readableBytesView)
    }
}
