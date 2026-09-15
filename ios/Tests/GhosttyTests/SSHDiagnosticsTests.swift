import XCTest

@testable import Ghostty

/// Reading a server's algorithm list, and saying in English why a handshake
/// could not be negotiated.
final class SSHKEXInitParserTests: XCTestCase {
    func testParsesARealOpenSSHKEXInit() throws {
        let lists = try XCTUnwrap(
            try SSHKEXInitParser.parse(packet: SSHKEXInitFixtures.openSSH103Packet)
        )
        let offer = SSHKEXInitParser.offer(
            banner: "SSH-2.0-OpenSSH_10.3",
            preamble: [],
            lists: lists
        )

        XCTAssertEqual(offer.softwareVersion, "OpenSSH_10.3")
        XCTAssertTrue(offer.keyExchangeAlgorithms.contains("curve25519-sha256"))
        XCTAssertTrue(offer.keyExchangeAlgorithms.contains("ecdh-sha2-nistp384"))
        XCTAssertEqual(
            offer.hostKeyAlgorithms.prefix(4),
            ["rsa-sha2-512", "rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"]
        )
        XCTAssertTrue(offer.ciphers.contains("aes256-gcm@openssh.com"))
        XCTAssertTrue(offer.ciphers.contains("aes256-ctr"))
        XCTAssertTrue(offer.macs.contains("hmac-sha2-256-etm@openssh.com"))
        XCTAssertEqual(offer.compressionClientToServer, ["none", "zlib@openssh.com"])
    }

    func testDirectionalListsAreIntersectedBeforeUse() throws {
        // swift-nio-ssh only accepts a symmetric negotiation, so a cipher that
        // is offered one way only must not count as available.
        var offer = try makeOffer(SSHKEXInitFixtures.ctrOnlyPacket)
        offer.ciphersServerToClient = ["aes256-ctr"]
        XCTAssertEqual(offer.ciphers, ["aes256-ctr"])
    }

    func testReturnsNilWhileThePacketIsIncomplete() throws {
        let whole = SSHKEXInitFixtures.openSSH103Packet
        XCTAssertNil(try SSHKEXInitParser.parse(packet: Array(whole[0..<4])))
        XCTAssertNil(try SSHKEXInitParser.parse(packet: Array(whole[0..<200])))
        XCTAssertNotNil(try SSHKEXInitParser.parse(packet: whole))
    }

    func testRejectsAnImplausibleLength() {
        let bytes: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x04]
        XCTAssertThrowsError(try SSHKEXInitParser.parse(packet: bytes)) { error in
            XCTAssertEqual(error as? SSHKEXInitParser.Failure, .oversizedPacket(0xFFFF_FFFF))
        }
    }

    func testRejectsAPacketThatIsNotAKEXInit() {
        var packet = SSHKEXInitFixtures.ctrOnlyPacket
        packet[5] = 21  // SSH_MSG_NEWKEYS
        XCTAssertThrowsError(try SSHKEXInitParser.parse(packet: packet)) { error in
            XCTAssertEqual(error as? SSHKEXInitParser.Failure, .notKEXInit(21))
        }
    }

    func testRejectsATruncatedNameList() {
        var packet = SSHKEXInitFixtures.ctrOnlyPacket
        // Claim the first name-list is enormous.
        packet[21] = 0x00
        packet[22] = 0x00
        packet[23] = 0xFF
        packet[24] = 0xFF
        XCTAssertThrowsError(try SSHKEXInitParser.parse(packet: packet)) { error in
            XCTAssertEqual(error as? SSHKEXInitParser.Failure, .truncated)
        }
    }

    private func makeOffer(_ packet: [UInt8]) throws -> SSHServerOffer {
        let lists = try XCTUnwrap(try SSHKEXInitParser.parse(packet: packet))
        return SSHKEXInitParser.offer(banner: "SSH-2.0-test", preamble: [], lists: lists)
    }
}

final class SSHAlgorithmMismatchTests: XCTestCase {
    func testPiACanBeNegotiated() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "pi-a",
            offer: try offer(SSHKEXInitFixtures.openSSH103Packet, banner: "SSH-2.0-OpenSSH_10.3")
        )
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertEqual(mismatch.failures, [])
        XCTAssertEqual(mismatch.hostKeysInCommon.first, "ssh-ed25519")
        XCTAssertEqual(mismatch.ciphersInCommon.first, "aes256-gcm@openssh.com")
        XCTAssertTrue(mismatch.summary.contains("can negotiate"))
    }

    /// The exact shape this ticket is about: RSA host keys and CTR ciphers, no
    /// AEAD. The ciphers now work; the host keys still do not, and the message
    /// has to say which is which.
    func testRSAAndCTROnlyServerNamesTheHostKeyAsTheBlocker() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "Levitt",
            offer: try offer(
                SSHKEXInitFixtures.rsaAndCTROnlyPacket,
                banner: "SSH-2.0-dropbear_2022.83"
            )
        )
        XCTAssertEqual(mismatch.failures, [.hostKey])
        XCTAssertFalse(
            mismatch.ciphersInCommon.isEmpty,
            "aes256-ctr is supported now, so the cipher negotiation must succeed"
        )
        XCTAssertEqual(mismatch.ciphersInCommon.first, "aes256-ctr")
        XCTAssertEqual(mismatch.macsInCommon.first, "hmac-sha2-256")

        let text = mismatch.explanation
        XCTAssertTrue(text.contains("Levitt"))
        XCTAssertTrue(text.contains("SSH-2.0-dropbear_2022.83"), "the banner must be shown")
        XCTAssertTrue(text.contains("ssh-rsa"), "the server's own list must be shown")
        XCTAssertTrue(text.contains("ssh-ed25519"), "our list must be shown")
        XCTAssertTrue(text.contains("Missing: host key."))
        XCTAssertTrue(text.contains("ssh-keygen -A"), "the fix must be concrete")
    }

    func testCTROnlyServerNowNegotiates() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "dropbear-box",
            offer: try offer(SSHKEXInitFixtures.ctrOnlyPacket, banner: "SSH-2.0-dropbear_2020.81")
        )
        XCTAssertTrue(
            mismatch.canNegotiate,
            "a CTR-only server is exactly what this change exists to reach:\n\(mismatch.explanation)"
        )
    }

    /// Before this change, a CTR-only server failed on the cipher. Pinning the
    /// old behaviour proves the fix is the added schemes rather than luck.
    func testCTROnlyServerWouldHaveFailedWithTheStockGCMOnlyList() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "dropbear-box",
            offer: try offer(SSHKEXInitFixtures.ctrOnlyPacket, banner: "SSH-2.0-dropbear_2020.81"),
            supportedCiphers: SSHTransportProtectionCatalog.cipherNames(
                SSHTransportProtectionCatalog.gcmSchemes
            ),
            supportedMACs: SSHTransportProtectionCatalog.macNames(
                SSHTransportProtectionCatalog.gcmSchemes
            )
        )
        XCTAssertEqual(mismatch.failures, [.cipher])
    }

    func testChaChaOnlyServerExplainsTheKeyDerivationCeiling() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "hardened",
            offer: try offer(SSHKEXInitFixtures.chachaOnlyPacket, banner: "SSH-2.0-OpenSSH_9.6")
        )
        XCTAssertEqual(mismatch.failures, [.cipher])
        let text = mismatch.explanation
        XCTAssertTrue(text.contains("64-byte session key"))
        XCTAssertTrue(text.contains("ecdh-sha2-nistp521"))
    }

    func testFiniteFieldDiffieHellmanIsCalledOut() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_6.6",
            preamble: [],
            keyExchangeAlgorithms: ["diffie-hellman-group14-sha1"],
            hostKeyAlgorithms: ["ssh-ed25519"],
            ciphersClientToServer: ["aes256-ctr"],
            ciphersServerToClient: ["aes256-ctr"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        let mismatch = SSHAlgorithmMismatch(hostname: "ancient", offer: offer)
        XCTAssertEqual(mismatch.failures, [.keyExchange])
        XCTAssertTrue(mismatch.explanation.contains("finite-field Diffie-Hellman"))
    }

    /// An AEAD carries its own tag and ignores MAC negotiation, so an empty MAC
    /// intersection is only a failure when every usable cipher needs one.
    func testAMACMismatchIsNotAFailureWhenAnAEADSurvives() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_9.6",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: ["ssh-ed25519"],
            ciphersClientToServer: ["aes256-gcm@openssh.com"],
            ciphersServerToClient: ["aes256-gcm@openssh.com"],
            macsClientToServer: ["umac-64@openssh.com"],
            macsServerToClient: ["umac-64@openssh.com"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        let mismatch = SSHAlgorithmMismatch(hostname: "gcm-only", offer: offer)
        XCTAssertTrue(mismatch.macsInCommon.isEmpty)
        XCTAssertTrue(mismatch.canNegotiate, "GCM ignores MAC negotiation entirely")
    }

    func testPreambleLinesAreSurfaced() throws {
        var serverOffer = try offer(
            SSHKEXInitFixtures.rsaAndCTROnlyPacket,
            banner: "SSH-2.0-dropbear_2022.83"
        )
        serverOffer.preamble = ["Unauthorised access is prohibited."]
        let mismatch = SSHAlgorithmMismatch(hostname: "Levitt", offer: serverOffer)
        XCTAssertTrue(mismatch.explanation.contains("Unauthorised access is prohibited."))
    }

    func testNegotiatedKeyExchangeFollowsClientPreference() throws {
        let piA = try offer(SSHKEXInitFixtures.openSSH103Packet, banner: "SSH-2.0-OpenSSH_10.3")
        // pi-a offers nistp256, nistp384, nistp521 and curve25519; our first
        // preference is nistp384, which hashes to 48 bytes — which is why the
        // 64-byte schemes stay off by default.
        let chosen = SSHAlgorithmSupport.negotiatedKeyExchange(with: piA)
        XCTAssertEqual(chosen?.name, "ecdh-sha2-nistp384")
        XCTAssertEqual(chosen?.hashBytes, 48)
    }

    func testNegotiatedKeyExchangeIsNilWhenNothingMatches() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-x",
            preamble: [],
            keyExchangeAlgorithms: ["diffie-hellman-group1-sha1"],
            hostKeyAlgorithms: [],
            ciphersClientToServer: [],
            ciphersServerToClient: [],
            macsClientToServer: [],
            macsServerToClient: [],
            compressionClientToServer: [],
            compressionServerToClient: []
        )
        XCTAssertNil(SSHAlgorithmSupport.negotiatedKeyExchange(with: offer))
    }

    private func offer(_ packet: [UInt8], banner: String) throws -> SSHServerOffer {
        let lists = try XCTUnwrap(try SSHKEXInitParser.parse(packet: packet))
        return SSHKEXInitParser.offer(banner: banner, preamble: [], lists: lists)
    }
}
