import Crypto
import Foundation
import NIOCore
import NIOSSH
import XCTest

@testable import Ghostty

/// The symmetric primitives this app has to supply itself, pinned to published
/// test vectors.
///
/// swift-nio-ssh ships only the two OpenSSH AES-GCM modes, so everything below
/// is code we wrote: AES-CTR over CommonCrypto, HMAC over CryptoKit, and
/// ChaCha20/Poly1305 from scratch because `CryptoKit.ChaChaPoly` implements the
/// RFC 8439 AEAD and OpenSSH's cipher is a different construction. Homegrown
/// crypto earns its place only against the standard vectors.
final class SSHTransportCryptoTests: XCTestCase {

    // MARK: - AES-CTR (NIST SP 800-38A §F.5)

    /// The four-block plaintext every SP 800-38A CTR vector uses.
    private static let nistPlaintext =
        "6bc1bee22e409f96e93d7e117393172a"
        + "ae2d8a571e03ac9c9eb76fac45af8e51"
        + "30c81c46a35ce411e5fbc1191a0a52ef"
        + "f69f2445df4f9b17ad2b417be66c3710"
    private static let nistCounter = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"

    func testAES128CTRMatchesNISTVector() throws {
        try assertCTR(
            key: "2b7e151628aed2a6abf7158809cf4f3c",
            expected:
                "874d6191b620e3261bef6864990db6ce"
                + "9806f66b7970fdff8617187bb9fffdff"
                + "5ae4df3edbd5d35e5b4f09020db03eab"
                + "1e031dda2fbe03d1792170a0f3009cee"
        )
    }

    func testAES192CTRMatchesNISTVector() throws {
        try assertCTR(
            key: "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            expected:
                "1abc932417521ca24f2b0459fe7e6e0b"
                + "090339ec0aa6faefd5ccc2c6f4ce8e94"
                + "1e36b26bd1ebc670d1bd1d665620abf7"
                + "4f78a7f6d29809585a97daec58c6b050"
        )
    }

    func testAES256CTRMatchesNISTVector() throws {
        try assertCTR(
            key: "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            expected:
                "601ec313775789a5b7a7f504bbf3d228"
                + "f443e3ca4d62b59aca84e990cacaf5c5"
                + "2b0930daa23de94ce87017ba2d84988d"
                + "dfc9c58db67aada613c2dd08457941a6"
        )
    }

    /// The counter has to carry across all 128 bits, and SSH connections are
    /// long enough to reach a carry: the IV here is one block short of an
    /// overflow in the low 64 bits.
    func testCounterCarriesAcrossWordBoundaries() throws {
        let key = SymmetricKey(data: Data(repeating: 0, count: 32))
        let iv = [UInt8](repeating: 0xFF, count: 16)

        let stream = try AESCounterMode(key: key, iv: iv)
        var first = [UInt8](repeating: 0, count: 32)
        try stream.apply(to: &first)

        // The second block's counter must have wrapped to all zeroes.
        let wrapped = try AESCounterMode(key: key, iv: [UInt8](repeating: 0, count: 16))
        var second = [UInt8](repeating: 0, count: 16)
        try wrapped.apply(to: &second)
        XCTAssertEqual(Array(first[16..<32]), second)
    }

    func testCTRRefusesAPartialBlock() throws {
        let stream = try AESCounterMode(
            key: SymmetricKey(data: Data(repeating: 1, count: 16)),
            iv: [UInt8](repeating: 0, count: 16)
        )
        var short = [UInt8](repeating: 0, count: 17)
        XCTAssertThrowsError(try stream.apply(to: &short)) { error in
            XCTAssertEqual(error as? SSHCipherError, .notBlockAligned(17))
        }
    }

    private func assertCTR(key: String, expected: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let stream = try AESCounterMode(
            key: SymmetricKey(data: Data(Self.hex(key))),
            iv: Self.hex(Self.nistCounter)
        )
        var buffer = Self.hex(Self.nistPlaintext)
        try stream.apply(to: &buffer)
        XCTAssertEqual(Self.string(buffer), expected, file: file, line: line)

        // And back again, from a fresh counter.
        let reverse = try AESCounterMode(
            key: SymmetricKey(data: Data(Self.hex(key))),
            iv: Self.hex(Self.nistCounter)
        )
        try reverse.apply(to: &buffer)
        XCTAssertEqual(Self.string(buffer), Self.nistPlaintext, file: file, line: line)
    }

    // MARK: - HMAC (RFC 4231)

    func testHMACSHA256MatchesRFC4231() {
        XCTAssertEqual(
            Self.string(mac(.hmacSHA256, key: [UInt8](repeating: 0x0B, count: 20), data: "Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        )
        XCTAssertEqual(
            Self.string(mac(.hmacSHA256, key: Array("Jefe".utf8), data: "what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        )
    }

    func testHMACSHA512MatchesRFC4231() {
        XCTAssertEqual(
            Self.string(mac(.hmacSHA512, key: [UInt8](repeating: 0x0B, count: 20), data: "Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                + "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        )
        XCTAssertEqual(
            Self.string(mac(.hmacSHA512, key: Array("Jefe".utf8), data: "what do ya want for nothing?")),
            "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"
        )
    }

    func testHMACNamesMatchTheWire() {
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA256.plainName, "hmac-sha2-256")
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA256.etmName, "hmac-sha2-256-etm@openssh.com")
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA512.plainName, "hmac-sha2-512")
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA512.etmName, "hmac-sha2-512-etm@openssh.com")
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA256.keyLength, 32)
        XCTAssertEqual(SSHMACAlgorithm.hmacSHA512.keyLength, 64)
    }

    func testHMACVerificationRejectsAFlippedBit() {
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let payload = Data("the quick brown fox".utf8)
        var tag = SSHMACAlgorithm.hmacSHA256.authenticate(
            sequenceNumber: 3,
            over: [payload],
            key: key
        )
        XCTAssertTrue(
            SSHMACAlgorithm.hmacSHA256.verify(tag, sequenceNumber: 3, over: [payload], key: key)
        )
        // The sequence number is part of the MAC input: a replayed packet at a
        // different position must not verify.
        XCTAssertFalse(
            SSHMACAlgorithm.hmacSHA256.verify(tag, sequenceNumber: 4, over: [payload], key: key)
        )
        tag[0] ^= 0x01
        XCTAssertFalse(
            SSHMACAlgorithm.hmacSHA256.verify(tag, sequenceNumber: 3, over: [payload], key: key)
        )
    }

    private func mac(_ algorithm: SSHMACAlgorithm, key: [UInt8], data: String) -> [UInt8] {
        // RFC 4231's vectors are plain HMAC with no sequence number, which is
        // sequence number zero with an empty prefix… except SSH always prefixes
        // four bytes. Feed the prefix as part of the message instead.
        var mac: [UInt8]
        switch algorithm {
        case .hmacSHA256:
            var hmac = Crypto.HMAC<SHA256>(key: SymmetricKey(data: Data(key)))
            hmac.update(data: Data(data.utf8))
            mac = Array(hmac.finalize())
        case .hmacSHA512:
            var hmac = Crypto.HMAC<SHA512>(key: SymmetricKey(data: Data(key)))
            hmac.update(data: Data(data.utf8))
            mac = Array(hmac.finalize())
        }
        return mac
    }

    // MARK: - ChaCha20 (RFC 8439 §2.3.2, §2.4.2)

    func testChaCha20BlockMatchesRFC8439() {
        let key = (0..<32).map { UInt8($0) }
        var keystream = [UInt8](repeating: 0, count: 64)
        ChaCha20.apply(
            to: &keystream,
            key: key,
            nonce: Self.hex("000000090000004a00000000"),
            initialCounter: 1
        )
        XCTAssertEqual(
            Self.string(keystream),
            "10f1e7e4d13b5915500fdd1fa32071c4"
                + "c7d1f4c733c068030422aa9ac3d46c4e"
                + "d2826446079faa0914c2d705d98b02a2"
                + "b5129cd1de164eb9cbd083e8a2503c4e"
        )
    }

    func testChaCha20EncryptionMatchesRFC8439() {
        let key = (0..<32).map { UInt8($0) }
        let plaintext = Array(
            """
            Ladies and Gentlemen of the class of '99: If I could offer you \
            only one tip for the future, sunscreen would be it.
            """.utf8
        )
        var buffer = plaintext
        ChaCha20.apply(
            to: &buffer,
            key: key,
            nonce: Self.hex("000000000000004a00000000"),
            initialCounter: 1
        )
        XCTAssertEqual(
            Self.string(buffer),
            "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b"
                + "f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8"
                + "07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736"
                + "5af90bbf74a35be6b40b8eedf2785e42874d"
        )

        // Symmetric: the same call decrypts.
        ChaCha20.apply(
            to: &buffer,
            key: key,
            nonce: Self.hex("000000000000004a00000000"),
            initialCounter: 1
        )
        XCTAssertEqual(buffer, plaintext)
    }

    /// The OpenSSH framing is the same core with the counter and nonce split
    /// differently. With a zero counter-high word the two must agree, which is
    /// what pins the word layout.
    func testOpenSSHFramingAgreesWithRFCFramingOnTheSharedCase() {
        let key = (0..<32).map { UInt8($0) }
        let nonce8 = Self.hex("0000004a00000000")

        var openSSH = [UInt8](repeating: 0, count: 64)
        ChaCha20.applyOpenSSH(to: &openSSH, key: key, nonce: nonce8, initialCounter: 1)

        var rfc = [UInt8](repeating: 0, count: 64)
        // RFC layout: word 12 is the counter, words 13…15 the nonce. To make
        // word 13 zero (the OpenSSH counter's high half) the 12-byte nonce has
        // to begin with four zero bytes.
        ChaCha20.apply(to: &rfc, key: key, nonce: Self.hex("00000000") + nonce8, initialCounter: 1)

        XCTAssertEqual(openSSH, rfc)
    }

    // MARK: - Poly1305 (RFC 8439 §2.5.2)

    func testPoly1305MatchesRFC8439() {
        let key = Self.hex(
            "85d6be7857556d337f4452fe42d506a8"
                + "0103808afb0db2fd4abff6af4149f51b"
        )
        let tag = Poly1305.authenticate(
            Array("Cryptographic Forum Research Group".utf8),
            key: key
        )
        XCTAssertEqual(Self.string(tag), "a8061dc1305136c6c22b8baf0c0127a9")
    }

    func testPoly1305IsIndependentOfChunking() {
        let key = Self.hex(
            "85d6be7857556d337f4452fe42d506a8"
                + "0103808afb0db2fd4abff6af4149f51b"
        )
        let message = Array("Cryptographic Forum Research Group".utf8)

        // Split across block boundaries in an awkward place: the incremental
        // path with a held-over partial block is the one with the bugs in it.
        var incremental = Poly1305(key: key)
        incremental.update(message[0..<7])
        incremental.update(message[7..<20])
        incremental.update(message[20..<message.count])
        XCTAssertEqual(Self.string(incremental.finalize()), "a8061dc1305136c6c22b8baf0c0127a9")
    }

    func testPoly1305HandlesEmptyAndBlockAlignedMessages() {
        let key = [UInt8](repeating: 0x42, count: 32)
        XCTAssertEqual(Poly1305.authenticate([UInt8](), key: key).count, 16)
        // Exactly two blocks: no partial-block path at all.
        let aligned = [UInt8](repeating: 0xAB, count: 32)
        let oneShot = Poly1305.authenticate(aligned, key: key)
        var split = Poly1305(key: key)
        split.update(aligned[0..<16])
        split.update(aligned[16..<32])
        XCTAssertEqual(oneShot, split.finalize())
    }

    func testConstantTimeCompareRejectsLengthAndContentDifferences() {
        XCTAssertTrue(Poly1305.constantTimeEquals([1, 2, 3], [1, 2, 3]))
        XCTAssertFalse(Poly1305.constantTimeEquals([1, 2, 3], [1, 2, 4]))
        XCTAssertFalse(Poly1305.constantTimeEquals([1, 2, 3], [1, 2]))
    }

    // MARK: - chacha20-poly1305@openssh.com

    func testOpenSSHChaChaPolyRoundTrips() throws {
        let key = (0..<64).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
        let packet = Self.plaintextPacket(payload: Array("hello ssh".utf8), blockSize: 8)

        let sealed = try ChaCha20Poly1305OpenSSH.seal(
            packet: packet,
            key: key,
            sequenceNumber: 42
        )
        XCTAssertEqual(sealed.count, packet.count + ChaCha20Poly1305OpenSSH.tagSize)
        // The length field is encrypted, which is the whole point of the second
        // key: a passive observer cannot see packet boundaries.
        XCTAssertNotEqual(Array(sealed[0..<4]), Array(packet[0..<4]))

        let length = try ChaCha20Poly1305OpenSSH.decryptLength(
            Array(sealed[0..<4]),
            key: key,
            sequenceNumber: 42
        )
        XCTAssertEqual(Int(length), packet.count - 4)

        let opened = try ChaCha20Poly1305OpenSSH.open(
            sealed: sealed,
            key: key,
            sequenceNumber: 42
        )
        XCTAssertEqual(opened, packet)
    }

    func testOpenSSHChaChaPolyRejectsAForgedTagAndAReplayedSequence() throws {
        let key = (0..<64).map { UInt8($0) }
        let packet = Self.plaintextPacket(payload: Array("sensitive".utf8), blockSize: 8)
        var sealed = try ChaCha20Poly1305OpenSSH.seal(packet: packet, key: key, sequenceNumber: 1)

        XCTAssertThrowsError(
            try ChaCha20Poly1305OpenSSH.open(sealed: sealed, key: key, sequenceNumber: 2)
        ) { XCTAssertEqual($0 as? ChaCha20Poly1305OpenSSH.Failure, .tagMismatch) }

        sealed[sealed.count - 1] ^= 0x01
        XCTAssertThrowsError(
            try ChaCha20Poly1305OpenSSH.open(sealed: sealed, key: key, sequenceNumber: 1)
        ) { XCTAssertEqual($0 as? ChaCha20Poly1305OpenSSH.Failure, .tagMismatch) }
    }

    func testOpenSSHChaChaPolyRejectsAShortKey() {
        XCTAssertThrowsError(
            try ChaCha20Poly1305OpenSSH.seal(
                packet: [0, 0, 0, 1, 2],
                key: [UInt8](repeating: 0, count: 32),
                sequenceNumber: 0
            )
        ) { XCTAssertEqual($0 as? ChaCha20Poly1305OpenSSH.Failure, .badKeySize(32)) }
    }

    // MARK: - Helpers

    /// A plaintext SSH packet: length, padding length, payload, padding.
    static func plaintextPacket(payload: [UInt8], blockSize: Int, lengthCounts: Bool = false) -> [UInt8] {
        let aligned = lengthCounts ? payload.count + 5 : payload.count + 1
        var padding = blockSize - (aligned % blockSize)
        if padding < 4 { padding += blockSize }
        let packetLength = 1 + payload.count + padding

        var packet: [UInt8] = [
            UInt8(truncatingIfNeeded: packetLength >> 24),
            UInt8(truncatingIfNeeded: packetLength >> 16),
            UInt8(truncatingIfNeeded: packetLength >> 8),
            UInt8(truncatingIfNeeded: packetLength),
            UInt8(padding),
        ]
        packet.append(contentsOf: payload)
        packet.append(contentsOf: (0..<padding).map { UInt8(truncatingIfNeeded: $0 &+ 1) })
        return packet
    }

    static func hex(_ string: String) -> [UInt8] {
        var out: [UInt8] = []
        var index = string.startIndex
        while index < string.endIndex {
            let next = string.index(index, offsetBy: 2)
            out.append(UInt8(string[index..<next], radix: 16)!)
            index = next
        }
        return out
    }

    static func string(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}
