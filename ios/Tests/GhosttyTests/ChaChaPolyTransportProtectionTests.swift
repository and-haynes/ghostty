import Crypto
import Foundation
import NIOCore
import NIOSSH
import XCTest

@testable import Ghostty

/// `chacha20-poly1305@openssh.com` driven through exactly the interface
/// swift-nio-ssh drives it through.
///
/// ``ChaCha20Poly1305OpenSSH`` is already pinned to the RFC 8439 vectors in
/// ``SSHTransportCryptoTests``; what is untested until here is the *adapter* —
/// and that is where the interesting mistakes live. The length field is
/// decrypted in one call and authenticated in another, so the adapter has to
/// carry the ciphertext of the length between them; the tag covers the
/// encrypted length, not the plaintext one that has replaced it by then.
final class ChaChaPolyTransportProtectionTests: XCTestCase {

    // MARK: - Round trips

    func testRoundTripsAcrossPayloadSizes() throws {
        let (client, server) = try makePair()
        // Sizes chosen to straddle the 8-byte alignment in both directions.
        for length in [0, 1, 7, 8, 9, 15, 16, 17, 63, 64, 300, 4096] {
            let payload = (0..<length).map { UInt8(truncatingIfNeeded: $0 &* 13) }
            var buffer = try seal(client, payload: payload, sequenceNumber: 0)
            let plaintext = try decrypt(&buffer, with: server, sequenceNumber: 0)
            XCTAssertEqual(plaintext, payload, "payload of \(length) bytes")
        }
    }

    func testEachPacketUsesItsOwnSequenceNumber() throws {
        // The sequence number is the nonce. A scheme that ignored it would
        // reuse keystream across packets — the catastrophic failure for any
        // stream cipher — and would still pass a single round trip.
        let (client, server) = try makePair()
        var ciphertexts: [[UInt8]] = []

        for sequence in UInt32(0)..<4 {
            var buffer = try seal(client, payload: Array("same payload every time".utf8), sequenceNumber: sequence)
            ciphertexts.append(Array(buffer.readableBytesView))
            let plaintext = try decrypt(&buffer, with: server, sequenceNumber: sequence)
            XCTAssertEqual(plaintext, Array("same payload every time".utf8))
        }

        for (index, ciphertext) in ciphertexts.enumerated() {
            for other in ciphertexts[(index + 1)...] {
                XCTAssertNotEqual(ciphertext, other, "identical plaintext must not produce identical ciphertext")
            }
        }
    }

    func testTheLengthFieldIsEncrypted() throws {
        // The point of the second key: a passive observer cannot see packet
        // boundaries. A packet of 100 bytes must not have "100" on the wire.
        let (client, _) = try makePair()
        let payload = (0..<100).map { UInt8(truncatingIfNeeded: $0) }
        let buffer = try seal(client, payload: payload, sequenceNumber: 0)

        let onTheWire = Array(buffer.readableBytesView)
        let plaintextPacket = SSHTransportCryptoTests.plaintextPacket(
            payload: payload,
            blockSize: 8,
            lengthCounts: false
        )
        XCTAssertNotEqual(Array(onTheWire.prefix(4)), Array(plaintextPacket.prefix(4)))
    }

    // MARK: - Rejection

    func testAFlippedCiphertextBitFailsTheTag() throws {
        let (client, server) = try makePair()
        var buffer = try seal(client, payload: Array("hello".utf8), sequenceNumber: 0)

        // Flip a bit in the body, past the length field.
        let index = buffer.readerIndex + 8
        var byte = buffer.getInteger(at: index, as: UInt8.self)!
        byte ^= 0x01
        buffer.setInteger(byte, at: index)

        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 0)) { error in
            XCTAssertEqual(error as? ChaCha20Poly1305OpenSSH.Failure, .tagMismatch)
        }
    }

    func testAFlippedTagBitIsRejected() throws {
        let (client, server) = try makePair()
        var buffer = try seal(client, payload: Array("hello".utf8), sequenceNumber: 0)

        let index = buffer.writerIndex - 1
        var byte = buffer.getInteger(at: index, as: UInt8.self)!
        byte ^= 0x80
        buffer.setInteger(byte, at: index)

        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 0)) { error in
            XCTAssertEqual(error as? ChaCha20Poly1305OpenSSH.Failure, .tagMismatch)
        }
    }

    func testAReplayedPacketFailsAtADifferentSequenceNumber() throws {
        let (client, server) = try makePair()
        var buffer = try seal(client, payload: Array("hello".utf8), sequenceNumber: 7)
        // Decrypting the length under the wrong nonce yields garbage, so this
        // fails before the tag check — either way it must not be accepted.
        XCTAssertThrowsError(try decrypt(&buffer, with: server, sequenceNumber: 8))
    }

    func testTheBodyCannotBeDecryptedWithoutTheLengthFirst() throws {
        // The adapter holds the encrypted length between the two calls. Asking
        // for the body without that step must fail loudly rather than
        // authenticate something it made up.
        let (client, server) = try makePair()
        var buffer = try seal(client, payload: Array("hello".utf8), sequenceNumber: 0)
        XCTAssertThrowsError(try server.decryptAndVerifyRemainingPacket(&buffer, sequenceNumber: 0)) { error in
            guard case .some(.malformedPacket) = error as? SSHCipherError else {
                return XCTFail("expected a malformed-packet error, got \(error)")
            }
        }
    }

    func testAKeyOfTheWrongSizeIsRejected() {
        // 32 bytes is the ChaCha20 key size people expect; this cipher wants 64,
        // and silently using half of one would be a catastrophe rather than a
        // bug. Nothing derives a short key now, but this is the backstop.
        let short = SymmetricKey(size: .bits256)
        XCTAssertThrowsError(
            try ChaCha20Poly1305TransportProtection(
                initialKeys: NIOSSHSessionKeys(
                    initialInboundIV: [],
                    initialOutboundIV: [],
                    inboundEncryptionKey: short,
                    outboundEncryptionKey: short,
                    inboundMACKey: SymmetricKey(size: .bits128),
                    outboundMACKey: SymmetricKey(size: .bits128)
                )
            )
        ) { error in
            XCTAssertEqual(error as? SSHCipherError, .badKeySize(expected: 64, actual: 32))
        }
    }

    // MARK: - What it tells NIOSSH about itself

    func testSchemeDeclaresTheRightNamesAndSizes() {
        let type = ChaCha20Poly1305TransportProtection.self
        XCTAssertEqual(type.cipherName, "chacha20-poly1305@openssh.com")
        XCTAssertNil(type.macName, "an AEAD ignores the MAC negotiation")
        XCTAssertEqual(type.cipherBlockSize, 8)
        XCTAssertEqual(type.keySizes.encryptionKeySize, 64)
        XCTAssertEqual(type.keySizes.ivSize, 0, "the nonce is the sequence number; there is no IV")
    }

    func testTheLengthDoesNotCountTowardPadding() throws {
        // `lengthEncrypted` selects whether the length field counts toward block
        // alignment, and OpenSSH treats it as authenticated data — excluded,
        // exactly as in the -etm modes. Getting this backwards produces packets
        // that a real server rejects while every test here still passes, so it
        // is asserted directly.
        let (client, _) = try makePair()
        XCTAssertFalse(client.lengthEncrypted)
        XCTAssertEqual(client.macBytes, 16)
    }

    func testRekeyingRestartsWithTheNewKeys() throws {
        let (client, server) = try makePair()
        var buffer = try seal(client, payload: Array("before".utf8), sequenceNumber: 0)
        XCTAssertEqual(try decrypt(&buffer, with: server, sequenceNumber: 0), Array("before".utf8))

        let newKeys = Self.sessionKeys(seed: 200)
        try client.updateKeys(newKeys)
        try server.updateKeys(Self.crossed(newKeys))

        var after = try seal(client, payload: Array("after".utf8), sequenceNumber: 0)
        XCTAssertEqual(try decrypt(&after, with: server, sequenceNumber: 0), Array("after".utf8))
    }

    // MARK: - Harness

    private func makePair() throws -> (
        client: ChaCha20Poly1305TransportProtection, server: ChaCha20Poly1305TransportProtection
    ) {
        let keys = Self.sessionKeys(seed: 1)
        return (
            try ChaCha20Poly1305TransportProtection(initialKeys: keys),
            try ChaCha20Poly1305TransportProtection(initialKeys: Self.crossed(keys))
        )
    }

    /// What the client sends, the server receives, so the keys cross over.
    private static func crossed(_ keys: NIOSSHSessionKeys) -> NIOSSHSessionKeys {
        NIOSSHSessionKeys(
            initialInboundIV: keys.initialOutboundIV,
            initialOutboundIV: keys.initialInboundIV,
            inboundEncryptionKey: keys.outboundEncryptionKey,
            outboundEncryptionKey: keys.inboundEncryptionKey,
            inboundMACKey: keys.outboundMACKey,
            outboundMACKey: keys.inboundMACKey
        )
    }

    private static func sessionKeys(seed: UInt8) -> NIOSSHSessionKeys {
        let sizes = ChaCha20Poly1305TransportProtection.keySizes
        return NIOSSHSessionKeys(
            initialInboundIV: [],
            initialOutboundIV: [],
            inboundEncryptionKey: SymmetricKey(
                data: Data((0..<sizes.encryptionKeySize).map { UInt8(truncatingIfNeeded: $0 &* 3 &+ Int(seed)) })
            ),
            outboundEncryptionKey: SymmetricKey(
                data: Data((0..<sizes.encryptionKeySize).map { UInt8(truncatingIfNeeded: $0 &* 5 &+ Int(seed)) })
            ),
            inboundMACKey: SymmetricKey(data: Data(repeating: seed, count: sizes.macKeySize)),
            outboundMACKey: SymmetricKey(data: Data(repeating: seed &+ 1, count: sizes.macKeySize))
        )
    }

    /// Encrypt a packet the way `SSHPacketSerializer` would.
    private func seal(
        _ protection: ChaCha20Poly1305TransportProtection,
        payload: [UInt8],
        sequenceNumber: UInt32
    ) throws -> ByteBuffer {
        let packet = SSHTransportCryptoTests.plaintextPacket(
            payload: payload,
            blockSize: ChaCha20Poly1305TransportProtection.cipherBlockSize,
            lengthCounts: protection.lengthEncrypted
        )
        var buffer = ByteBufferAllocator().buffer(capacity: packet.count + 128)
        buffer.writeBytes(packet)
        try protection.encryptPacket(&buffer, sequenceNumber: sequenceNumber)
        return buffer
    }

    /// Decrypt a packet the way `SSHPacketParser` would: first block, read the
    /// length, then the rest.
    private func decrypt(
        _ buffer: inout ByteBuffer,
        with protection: ChaCha20Poly1305TransportProtection,
        sequenceNumber: UInt32
    ) throws -> [UInt8] {
        try protection.decryptFirstBlock(&buffer, sequenceNumber: sequenceNumber)

        // The real parser bounds the decrypted length before it commits to
        // buffering toward it, and so must this: a length decrypted under the
        // wrong nonce is uniformly distributed over 2^32.
        guard let packetLength = buffer.getInteger(at: buffer.readerIndex, as: UInt32.self),
            packetLength <= 1 << 20,
            var slice = buffer.readSlice(length: Int(packetLength) + protection.macBytes + 4)
        else {
            throw HarnessFailure.implausiblePacketLength
        }

        let content = try protection.decryptAndVerifyRemainingPacket(&slice, sequenceNumber: sequenceNumber)
        XCTAssertEqual(slice.readableBytes, 0, "the whole packet must be consumed")
        return Array(content.readableBytesView)
    }

    private enum HarnessFailure: Error {
        /// The length field did not decrypt to anything a real parser would act on.
        case implausiblePacketLength
    }
}
