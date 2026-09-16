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

    /// The exact shape #008A0 was about: RSA host keys and CTR ciphers, no AEAD.
    /// Both halves work now — the ciphers since #008A0, the host keys since the
    /// swift-nio-ssh fork of #008D0.
    func testRSAAndCTROnlyServerNowNegotiates() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "Levitt",
            offer: try offer(
                SSHKEXInitFixtures.rsaAndCTROnlyPacket,
                banner: "SSH-2.0-dropbear_2022.83"
            )
        )
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertEqual(mismatch.ciphersInCommon.first, "aes256-ctr")
        XCTAssertEqual(mismatch.macsInCommon.first, "hmac-sha2-256")
        // rsa-sha2-512 ahead of rsa-sha2-256, and ssh-rsa never — it signs with
        // SHA-1, and the server offering it does not make it acceptable.
        XCTAssertEqual(mismatch.hostKeysInCommon, ["rsa-sha2-512", "rsa-sha2-256"])
    }

    /// The same server, if its RSA key were only offered under `ssh-rsa`.
    func testAnSSHRSAOnlyServerIsRefusedWithAReason() throws {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-dropbear_2019.78",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: ["ssh-rsa"],
            ciphersClientToServer: ["aes256-ctr"],
            ciphersServerToClient: ["aes256-ctr"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        let mismatch = SSHAlgorithmMismatch(hostname: "Levitt", offer: offer)
        XCTAssertEqual(mismatch.failures, [.hostKey])

        let text = mismatch.explanation
        XCTAssertTrue(text.contains("Levitt"))
        XCTAssertTrue(text.contains("SSH-2.0-dropbear_2019.78"), "the banner must be shown")
        XCTAssertTrue(text.contains("ssh-rsa"), "the server's own list must be shown")
        XCTAssertTrue(text.contains("Missing: host key."))
        XCTAssertTrue(text.contains("SHA-1"), "the reason must be the reason")
        XCTAssertTrue(text.contains("HostKeyAlgorithms"), "the fix must be concrete")
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

    /// A chacha20-poly1305-only server used to be unreachable twice over: the
    /// 64-byte key could not be derived, and the cipher could not be expressed
    /// as a NIOSSHTransportProtection at all. Both were fixed in the fork.
    func testChaChaOnlyServerNowNegotiates() throws {
        let mismatch = SSHAlgorithmMismatch(
            hostname: "hardened",
            offer: try offer(SSHKEXInitFixtures.chachaOnlyPacket, banner: "SSH-2.0-OpenSSH_9.6")
        )
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertEqual(mismatch.ciphersInCommon, ["chacha20-poly1305@openssh.com"])
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

/// The report the **Test connection** sheet renders and copies.
final class SSHConnectionReportTests: XCTestCase {
    func testAReadyReportSaysSoAndNamesTheAlgorithms() {
        var report = SSHConnectionReport(destination: "andy@pi-a", outcome: .ready)
        report.offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_10.3",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: ["ssh-ed25519"],
            ciphersClientToServer: ["aes256-gcm@openssh.com"],
            ciphersServerToClient: ["aes256-gcm@openssh.com"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        report.negotiatedKeyExchange = "curve25519-sha256"
        report.negotiatedHostKeyAlgorithm = "ssh-ed25519"
        report.negotiatedCipher = "aes256-gcm@openssh.com"
        report.hostKeyType = "ssh-ed25519"
        report.hostKeyFingerprint = "SHA256:abc"
        report.hostKeyMatchesPin = true

        XCTAssertTrue(report.succeeded)
        let text = report.detail
        XCTAssertTrue(text.contains("SSH-2.0-OpenSSH_10.3"))
        XCTAssertTrue(text.contains("aes256-gcm@openssh.com"))
        XCTAssertTrue(text.contains("SHA256:abc"))
        XCTAssertTrue(text.contains("matches the key saved for this host"))
        XCTAssertTrue(text.contains("Authentication succeeded"))
        XCTAssertTrue(text.contains("(the cipher's own)"), "an AEAD negotiates no separate MAC")
    }

    /// The security property worth pinning: a diagnostic must not hand
    /// credentials to a host whose key has never been checked.
    func testAnUntrustedHostKeySaysNothingWasSent() {
        var report = SSHConnectionReport(destination: "andy@new-box", outcome: .hostKeyNotTrusted)
        report.hostKeyType = "ssh-ed25519"
        report.hostKeyFingerprint = "SHA256:xyz"
        report.hostKeyMatchesPin = nil

        XCTAssertFalse(report.succeeded)
        let text = report.detail
        XCTAssertTrue(text.contains("No credential was offered"))
        XCTAssertTrue(text.contains("not saved yet"))
        XCTAssertTrue(text.contains("SHA256:xyz"), "the fingerprint is the whole point of asking")
    }

    func testAChangedHostKeyIsLoud() {
        var report = SSHConnectionReport(destination: "andy@pi-a", outcome: .hostKeyChanged)
        report.hostKeyMatchesPin = false
        report.hostKeyFingerprint = "SHA256:different"
        let text = report.detail
        XCTAssertTrue(text.contains("DOES NOT match"))
        XCTAssertTrue(text.contains("No credential was offered"))
    }

    func testAnUnnegotiableServerCarriesTheWholeExplanation() throws {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_5.3",
            preamble: [],
            keyExchangeAlgorithms: ["diffie-hellman-group1-sha1"],
            hostKeyAlgorithms: ["ssh-dss"],
            ciphersClientToServer: ["3des-cbc"],
            ciphersServerToClient: ["3des-cbc"],
            macsClientToServer: ["hmac-md5"],
            macsServerToClient: ["hmac-md5"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        var report = SSHConnectionReport(destination: "andy@ancient", outcome: .cannotNegotiate)
        report.offer = offer
        report.mismatch = SSHAlgorithmMismatch(hostname: "ancient", offer: offer)

        let text = report.detail
        XCTAssertTrue(text.contains("host key"))
        XCTAssertTrue(text.contains("ssh-dss"))
        XCTAssertTrue(text.contains("ssh-keygen -A"))
    }

    func testAnUnreachableHostSaysWhy() {
        let report = SSHConnectionReport(
            destination: "andy@nowhere",
            outcome: .unreachable("Nothing answered on port 22.")
        )
        XCTAssertTrue(report.headline.contains("Couldn't reach"))
        XCTAssertTrue(report.detail.contains("Nothing answered on port 22."))
    }
}

/// Certificate-signed hosts (#008A3). Certificates are negotiated now, but only
/// when a certificate authority is configured — so a server presenting nothing
/// but certificates is still unreachable for anyone who has not set one up, and
/// the explanation has to say so rather than blaming the server.
final class SSHCertificateHostKeyTests: XCTestCase {
    func testACertificateOnlyServerIsExplainedAsSuch() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_9.6",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: [
                "ssh-ed25519-cert-v01@openssh.com",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            ],
            ciphersClientToServer: ["aes256-ctr"],
            ciphersServerToClient: ["aes256-ctr"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        // The default is what a client with no CA offers.
        let mismatch = SSHAlgorithmMismatch(hostname: "ca-signed", offer: offer)
        XCTAssertEqual(mismatch.failures, [.hostKey])
        let text = mismatch.explanation
        XCTAssertTrue(text.contains("CA-signed host certificates"))
        XCTAssertTrue(text.contains("Settings › SSH certificates"), "the fix must be the CA list")
        XCTAssertFalse(text.contains("ssh-keygen -A"), "the DSA advice does not apply here")
    }

    /// The same server, once a CA is configured: the client names the
    /// certificate algorithms and the negotiation succeeds.
    func testACertificateOnlyServerNegotiatesOnceACAIsConfigured() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_9.6",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: [
                "ssh-ed25519-cert-v01@openssh.com",
                "ecdsa-sha2-nistp256-cert-v01@openssh.com",
            ],
            ciphersClientToServer: ["aes256-ctr"],
            ciphersServerToClient: ["aes256-ctr"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        let mismatch = SSHAlgorithmMismatch(
            hostname: "ca-signed",
            offer: offer,
            supportedHostKeys: SSHAlgorithmSupport.offeredHostKeyAlgorithms(
                trustingCertificateAuthorities: true
            )
        )
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertEqual(mismatch.hostKeysInCommon.first, "ssh-ed25519-cert-v01@openssh.com")
    }

    func testACertificateAlongsideAPlainKeyIsFine() {
        let offer = SSHServerOffer(
            banner: "SSH-2.0-OpenSSH_9.6",
            preamble: [],
            keyExchangeAlgorithms: ["curve25519-sha256"],
            hostKeyAlgorithms: ["ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519"],
            ciphersClientToServer: ["aes256-ctr"],
            ciphersServerToClient: ["aes256-ctr"],
            macsClientToServer: ["hmac-sha2-256"],
            macsServerToClient: ["hmac-sha2-256"],
            compressionClientToServer: ["none"],
            compressionServerToClient: ["none"]
        )
        let mismatch = SSHAlgorithmMismatch(hostname: "ca-signed", offer: offer)
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertEqual(mismatch.hostKeysInCommon, ["ssh-ed25519"])
    }

    func testCertificateNamesAreRecognised() {
        XCTAssertTrue(SSHAlgorithmMismatch.isCertificate("ssh-ed25519-cert-v01@openssh.com"))
        XCTAssertTrue(SSHAlgorithmMismatch.isCertificate("rsa-sha2-512-cert-v01@openssh.com"))
        XCTAssertFalse(SSHAlgorithmMismatch.isCertificate("ssh-ed25519"))
    }
}
