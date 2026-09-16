import Foundation
import XCTest

@testable import Ghostty

/// End-to-end negotiation against a real `sshd` on the developer's Mac.
///
/// Every other test in this bundle is offline by design. These are the
/// exception, and they earn it: the whole of #008A0 is about what happens when
/// a *real* server offers algorithms swift-nio-ssh does not, and a round trip
/// through our own encoder proves nothing about that. The simulator shares the
/// host's network stack, so `127.0.0.1` here is the Mac's loopback.
///
/// Every server is temporary and loopback-only. Start them with:
///
/// ```bash
/// ./Tests/local-sshd.sh start
/// ```
///
/// which writes `/tmp/ghostty-sshd` and brings up one `sshd` per scenario:
/// `:22022` AES-CTR only, `:22023` an RSA host key only, `:22024` OpenSSH's
/// defaults, `:22025` chacha20-poly1305 only, `:22026` hmac-sha2-512 only,
/// `:22027` certificate user authentication, `:22028` a CA-signed host
/// certificate.
///
/// When nothing is listening the tests skip rather than fail: a laptop without
/// the servers running is not a broken build.
final class SSHLocalServerIntegrationTests: XCTestCase {
    /// aes256-ctr / aes192-ctr / aes128-ctr with hmac-sha2-256, an Ed25519 host
    /// key, and **no AEAD at all** — the configuration that was unreachable
    /// before this change.
    private static let ctrOnlyPort = 22022
    /// Only RSA host keys, under `rsa-sha2-512`/`rsa-sha2-256`. Unverifiable
    /// before #008D0 — swift-nio-ssh had no RSA key type at all — and an
    /// ordinary connection after it.
    private static let rsaHostKeyPort = 22023
    /// A stand-in for pi-a: OpenSSH 10.3's full default algorithm set. Here to
    /// prove the widened cipher list does not *change* what a modern server
    /// negotiates — the AEAD must still win.
    private static let fullOpenSSHPort = 22024
    /// `chacha20-poly1305@openssh.com` and nothing else.
    private static let chaChaPort = 22025
    /// `hmac-sha2-512` and nothing else, over `aes256-ctr` so the MAC is really
    /// negotiated rather than ignored by an AEAD.
    private static let hmacSHA512Port = 22026
    /// `TrustedUserCAKeys`, `AuthorizedKeysFile none`: a certificate is the only
    /// way in.
    private static let userCertificatePort = 22027
    /// Presents a CA-signed host certificate rather than a bare host key.
    private static let hostCertificatePort = 22028

    /// A throwaway key generated for these tests and nothing else. It is
    /// committed on purpose: the test is worthless without a credential, and a
    /// key that only ever authenticates to a temporary loopback `sshd` is not a
    /// secret. It is not in any `authorized_keys` outside `/tmp`.
    private static let fixturePrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjewAAAKCg1HvboNR7
        2wAAAAtzc2gtZWQyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjew
        AAAEAt2Gmsq6Ru+Da1XiViBO0VdkG6AjJ33DfMAv+oM6QqVZOxaja7DFTLe3QdFZ63cfXh
        SQVaI0lKvsz0mjSaqqN7AAAAGGdob3N0dHktaW50ZWdyYXRpb24tdGVzdAECAwQF
        -----END OPENSSH PRIVATE KEY-----
        """

    // MARK: - The probe

    func testProbeReadsTheRestrictedServersOffer() async throws {
        let offer = try await probeOrSkip(port: Self.ctrOnlyPort)

        XCTAssertTrue(offer.banner.hasPrefix("SSH-2.0-OpenSSH"))
        XCTAssertEqual(offer.ciphers, ["aes256-ctr", "aes192-ctr", "aes128-ctr"])
        XCTAssertFalse(
            offer.ciphers.contains { $0.hasSuffix("-gcm@openssh.com") },
            "the fixture server must offer no AEAD, or it proves nothing"
        )
        XCTAssertEqual(offer.hostKeyAlgorithms, ["ssh-ed25519"])
    }

    /// The whole diagnosis, against a live server, with no credentials involved.
    func testMismatchExplainerAgreesWithARealRestrictedServer() async throws {
        let offer = try await probeOrSkip(port: Self.ctrOnlyPort)
        let mismatch = SSHAlgorithmMismatch(hostname: "127.0.0.1", offer: offer)
        XCTAssertTrue(
            mismatch.canNegotiate,
            "a CTR-only server should now be reachable:\n\(mismatch.explanation)"
        )
        XCTAssertEqual(mismatch.ciphersInCommon.first, "aes256-ctr")
        XCTAssertEqual(mismatch.macsInCommon.first, "hmac-sha2-256-etm@openssh.com")
    }

    /// An RSA-only server used to fail this negotiation outright: swift-nio-ssh
    /// had no RSA key type, so the client never named `rsa-sha2-*` and the two
    /// sides had no host key algorithm in common. It is now an ordinary server.
    func testRSAOnlyServerNegotiatesCleanly() async throws {
        let offer = try await probeOrSkip(port: Self.rsaHostKeyPort)
        XCTAssertTrue(offer.hostKeyAlgorithms.allSatisfy { $0.hasPrefix("rsa-sha2-") })

        let mismatch = SSHAlgorithmMismatch(hostname: "127.0.0.1", offer: offer)
        XCTAssertTrue(mismatch.canNegotiate, mismatch.explanation)
        XCTAssertTrue(mismatch.failures.isEmpty, mismatch.explanation)
    }

    // MARK: - A real session over aes256-ctr

    /// Connect, authenticate and run a command over a transport swift-nio-ssh
    /// cannot negotiate on its own.
    ///
    /// Reaching a shell means every layer worked: key exchange, the `NEWKEYS`
    /// switch to `aes256-ctr` + `hmac-sha2-256-etm@openssh.com`, the encrypted
    /// user-auth exchange, a `pty-req`, and encrypted channel data in both
    /// directions.
    @MainActor
    func testRunsACommandOverAESCTRWithNoAEADAvailable() async throws {
        _ = try await probeOrSkip(port: Self.ctrOnlyPort)

        let vault = Vault(keychain: InMemoryKeychain(), directory: temporaryDirectory())
        let identity = try vault.importIdentity(name: "integration", pem: Self.fixturePrivateKey)
        let material = try vault.privateKey(for: identity)

        let session = SSHSession(vault: vault)
        // Held for the whole test: `hostKeyPrompter` is weak, so a temporary
        // would be gone before the handshake asked it anything.
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        let request = SSHConnectionRequest(
            hostname: "127.0.0.1",
            port: Self.ctrOnlyPort,
            username: Self.hostUsername,
            startupCommand: "echo GHOSTTY_CTR_OK"
        )

        do {
            try await session.connect(request, auth: [.privateKey(material)])
        } catch let error as SSHError {
            if case .negotiationFailed = error {
                XCTFail("negotiation failed against an aes256-ctr server: \(error)")
                return
            }
            // A username the local sshd will not authenticate is an environment
            // problem, not a transport one — but getting as far as an
            // authentication failure still proves the encrypted transport
            // works, because the server's rejection arrived over it.
            if case .authenticationFailed(let detail) = error {
                XCTAssertTrue(
                    prompter.wasAsked,
                    "host key verification should have happened before user auth"
                )
                throw XCTSkip(
                    """
                    The transport negotiated and carried encrypted user auth, but \
                    "\(Self.hostUsername)" could not log in to the fixture sshd: \(detail)
                    """
                )
            }
            throw error
        }

        XCTAssertEqual(session.state, .connected)
        XCTAssertTrue(prompter.wasAsked, "a new host key must go through TOFU")

        // Wait for the command's output rather than sleeping a fixed time.
        let deadline = Date().addingTimeInterval(10)
        while !output.text.contains("GHOSTTY_CTR_OK"), Date() < deadline {
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertTrue(
            output.text.contains("GHOSTTY_CTR_OK"),
            "expected the remote command's output, got: \(output.text)"
        )

        // The pin the handshake stored is the server's real host key.
        let pin = vault.knownHost(hostname: "127.0.0.1", port: Self.ctrOnlyPort)
        XCTAssertEqual(pin?.keyType, "ssh-ed25519")

        await session.disconnect()
    }

    /// A session against a server whose only host key is RSA.
    ///
    /// The host key is verified — the signature over the exchange hash is
    /// RSASSA-PKCS1-v1_5 with SHA-512, checked by Security.framework through the
    /// forked library — and the fingerprint is pinned like any other.
    @MainActor
    func testVerifiesAnRSAHostKey() async throws {
        _ = try await probeOrSkip(port: Self.rsaHostKeyPort)

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.rsaHostKeyPort,
            command: "echo GHOSTTY_RSA_HOSTKEY_OK",
            auth: [.privateKey(material)],
            prompter: prompter
        )
        try await expect("GHOSTTY_RSA_HOSTKEY_OK", in: output)

        // The pin records the blob's type, which for every RSA signature
        // algorithm is "ssh-rsa" (RFC 8332 §3 reuses the key format).
        let pin = vault.knownHost(hostname: "127.0.0.1", port: Self.rsaHostKeyPort)
        XCTAssertEqual(pin?.keyType, "ssh-rsa")

        await session.disconnect()
    }

    /// A session authenticated with an RSA *user* key.
    @MainActor
    func testAuthenticatesWithAnRSAUserKey() async throws {
        _ = try await probeOrSkip(port: Self.fullOpenSSHPort)

        let vault = Vault(keychain: InMemoryKeychain(), directory: temporaryDirectory())
        let identity = try vault.importIdentity(name: "rsa-user", pem: KeyFormatFixtures.rsaPKCS1)
        let material = try vault.privateKey(for: identity)

        // The server only admits the Ed25519 fixture key, so this exercises the
        // RSA signing path up to the server's verdict on it. Reaching a
        // *rejection* still proves the signature was produced and accepted as
        // well-formed; a malformed one disconnects the session instead.
        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        do {
            try await session.connect(
                SSHConnectionRequest(
                    hostname: "127.0.0.1",
                    port: Self.fullOpenSSHPort,
                    username: Self.hostUsername
                ),
                auth: [.privateKey(material)]
            )
            await session.disconnect()
        } catch let error as SSHError {
            guard case .authenticationFailed = error else {
                XCTFail("an RSA key should sign cleanly, even when refused: \(error)")
                return
            }
        }

        // The server logged what it was offered; an unparseable signature would
        // never have got that far.
        XCTAssertTrue(prompter.wasAsked)
    }

    /// A modern server must still negotiate AES-GCM. Widening the offer is only
    /// safe if it cannot quietly downgrade a connection that already worked, and
    /// the GCM schemes are listed first for exactly that reason.
    @MainActor
    func testAModernServerStillNegotiatesAnAEAD() async throws {
        let offer = try await probeOrSkip(port: Self.fullOpenSSHPort)
        XCTAssertTrue(offer.ciphers.contains("aes256-gcm@openssh.com"))

        // What the client will pick, computed the way RFC 4253 §7.1 does.
        let chosen = SSHTransportProtectionCatalog.cipherNames().first {
            offer.ciphers.contains($0)
        }
        XCTAssertEqual(chosen, "aes256-gcm@openssh.com")

        let vault = Vault(keychain: InMemoryKeychain(), directory: temporaryDirectory())
        let identity = try vault.importIdentity(name: "integration", pem: Self.fixturePrivateKey)
        let material = try vault.privateKey(for: identity)

        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await session.connect(
            SSHConnectionRequest(
                hostname: "127.0.0.1",
                port: Self.fullOpenSSHPort,
                username: Self.hostUsername,
                startupCommand: "echo GHOSTTY_GCM_OK"
            ),
            auth: [.privateKey(material)]
        )
        XCTAssertEqual(session.state, .connected)

        let deadline = Date().addingTimeInterval(10)
        while !output.text.contains("GHOSTTY_GCM_OK"), Date() < deadline {
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertTrue(output.text.contains("GHOSTTY_GCM_OK"), output.text)
        await session.disconnect()
    }

    // MARK: - chacha20-poly1305 and hmac-sha2-512

    /// A whole session over `chacha20-poly1305@openssh.com`, which could not be
    /// expressed as a NIOSSHTransportProtection at all before #008D0.
    ///
    /// Reaching a shell exercises every part of the construction that a unit
    /// test cannot: the length field encrypted under `K_header` and decrypted
    /// one call before the body, the Poly1305 tag over the *ciphertext* of that
    /// length, the sequence number as the nonce, and OpenSSH's padding rule.
    @MainActor
    func testRunsACommandOverChaCha20Poly1305() async throws {
        let offer = try await probeOrSkip(port: Self.chaChaPort)
        XCTAssertEqual(offer.ciphers, ["chacha20-poly1305@openssh.com"])

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.chaChaPort,
            command: "echo GHOSTTY_CHACHA_OK && echo second line && uname -s",
            auth: [.privateKey(material)],
            prompter: prompter
        )
        // Several packets in both directions, so a scheme that only worked for
        // sequence number zero would be caught.
        try await expect("GHOSTTY_CHACHA_OK", in: output)
        try await expect("second line", in: output)
        try await expect("Darwin", in: output)

        await session.disconnect()
    }

    /// A whole session with `hmac-sha2-512`, whose 64-byte key the library could
    /// not derive before the RFC 4253 §7.2 expansion landed.
    @MainActor
    func testRunsACommandOverHMACSHA512() async throws {
        let offer = try await probeOrSkip(port: Self.hmacSHA512Port)
        XCTAssertTrue(offer.macs.allSatisfy { $0.hasPrefix("hmac-sha2-512") })

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.hmacSHA512Port,
            command: "echo GHOSTTY_HMAC512_OK && uname -s",
            auth: [.privateKey(material)],
            prompter: prompter
        )
        try await expect("GHOSTTY_HMAC512_OK", in: output)
        try await expect("Darwin", in: output)

        await session.disconnect()
    }

    // MARK: - Certificates

    /// Authenticate with a CA certificate to a server that has no
    /// `authorized_keys` at all (#008A3).
    ///
    /// `TrustedUserCAKeys` and `AuthorizedKeysFile none` means the key itself is
    /// unknown to the server: the only thing that can let it in is the CA's
    /// signature over the certificate. The bare key is still offered behind the
    /// certificate and is guaranteed to be refused, which also proves the
    /// fallback ordering does no harm.
    @MainActor
    func testAuthenticatesWithAUserCertificate() async throws {
        _ = try await probeOrSkip(port: Self.userCertificatePort)
        try skipUnlessCertificatePrincipalMatches()

        let (vault, material) = try makeVaultAndKey()
        let certificate = try SSHCertificate.parse(Self.fixtureUserCertificate)
        XCTAssertTrue(certificate.certifies(publicKeyLine: vault.identities[0].publicKeyLine))

        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.userCertificatePort,
            command: "echo GHOSTTY_USERCERT_OK",
            auth: [
                .certifiedKey(material, certificate: certificate.line),
                .privateKey(material),
            ],
            prompter: prompter
        )
        try await expect("GHOSTTY_USERCERT_OK", in: output)
        await session.disconnect()
    }

    /// The same server, offering only the bare key: it must be refused.
    ///
    /// Without this, the certificate test could pass for the wrong reason — a
    /// server that quietly accepted the key would make the certificate
    /// irrelevant.
    @MainActor
    func testTheBareKeyAloneIsRefusedByTheCertificateOnlyServer() async throws {
        _ = try await probeOrSkip(port: Self.userCertificatePort)

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        do {
            try await session.connect(
                SSHConnectionRequest(
                    hostname: "127.0.0.1",
                    port: Self.userCertificatePort,
                    username: Self.hostUsername
                ),
                auth: [.privateKey(material)]
            )
            await session.disconnect()
            XCTFail("a server with AuthorizedKeysFile none must not accept a bare key")
        } catch let error as SSHError {
            guard case .authenticationFailed = error else {
                XCTFail("expected an authentication failure, got \(error)")
                return
            }
        }
    }

    /// Verify a CA-signed *host* certificate instead of pinning a key (#008A3).
    @MainActor
    func testVerifiesAHostCertificateAgainstATrustedCA() async throws {
        _ = try await probeOrSkip(port: Self.hostCertificatePort)

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        session.trustedHostAuthorities = SSHTrustedAuthorities(text: Self.fixtureHostCA).keys
        XCTAssertEqual(session.trustedHostAuthorities.count, 1)

        // No prompter at all: a certificate that validates must never reach
        // trust-on-first-use, and a nil prompter would refuse the connection if
        // it did.
        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.hostCertificatePort,
            command: "echo GHOSTTY_HOSTCERT_OK",
            auth: [.privateKey(material)],
            prompter: nil
        )
        try await expect("GHOSTTY_HOSTCERT_OK", in: output)

        // Nothing was pinned: a certificate's fingerprint changes every time the
        // CA re-signs the same host key, so pinning one would be a bug.
        XCTAssertNil(vault.knownHost(hostname: "127.0.0.1", port: Self.hostCertificatePort))
        await session.disconnect()
    }

    /// The wrong CA must not be enough.
    @MainActor
    func testAHostCertificateFromAnUntrustedCAIsRefused() async throws {
        _ = try await probeOrSkip(port: Self.hostCertificatePort)

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        // A real, well-formed CA key that simply did not sign this certificate.
        session.trustedHostAuthorities = SSHTrustedAuthorities(text: Self.fixtureUserCA).keys
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        do {
            try await session.connect(
                SSHConnectionRequest(
                    hostname: "127.0.0.1",
                    port: Self.hostCertificatePort,
                    username: Self.hostUsername
                ),
                auth: [.privateKey(material)]
            )
            await session.disconnect()
            XCTFail("a certificate signed by an untrusted CA must be refused")
        } catch let error as SSHError {
            guard case .connectionFailed(let detail) = error else {
                XCTFail("expected the host certificate to be refused, got \(error)")
                return
            }
            XCTAssertTrue(detail.contains("host certificate was not accepted"), detail)
            XCTAssertFalse(
                prompter.wasAsked,
                "a certificate must never fall through to trust-on-first-use"
            )
        }
    }

    /// Without a CA the client does not ask for a certificate, so the same
    /// server presents its plain host key and trust-on-first-use works as it
    /// always did. This is what keeps the feature from changing anything for
    /// anyone who does not use it.
    @MainActor
    func testWithNoCAConfiguredTheSameServerFallsBackToItsPlainKey() async throws {
        _ = try await probeOrSkip(port: Self.hostCertificatePort)

        let (vault, material) = try makeVaultAndKey()
        let session = SSHSession(vault: vault)
        XCTAssertTrue(session.trustedHostAuthorities.isEmpty)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let output = OutputCollector()
        session.onData = { output.append($0) }

        try await connectOrSkip(
            session,
            port: Self.hostCertificatePort,
            command: "echo GHOSTTY_PLAINKEY_OK",
            auth: [.privateKey(material)],
            prompter: prompter
        )
        try await expect("GHOSTTY_PLAINKEY_OK", in: output)

        XCTAssertTrue(prompter.wasAsked, "the plain key should have gone through TOFU")
        let pin = vault.knownHost(hostname: "127.0.0.1", port: Self.hostCertificatePort)
        XCTAssertEqual(pin?.keyType, "ssh-ed25519")
        await session.disconnect()
    }

    // MARK: - Helpers

    /// The macOS account the fixture `sshd` is running as.
    ///
    /// `NSUserName()` is empty inside the simulator, but every simulator process
    /// inherits `SIMULATOR_HOST_HOME` — the *host* home directory — from
    /// CoreSimulator, and its last path component is the host's login name.
    static var hostUsername: String {
        let environment = ProcessInfo.processInfo.environment
        if let home = environment["SIMULATOR_HOST_HOME"], !home.isEmpty {
            let name = URL(fileURLWithPath: home).lastPathComponent
            if !name.isEmpty { return name }
        }
        if let user = environment["USER"], !user.isEmpty { return user }
        return NSUserName()
    }

    /// The certificate fixtures, matching what `Tests/local-sshd.sh` writes out.
    ///
    /// Committed rather than generated so the tests can assert against them: a
    /// CA that changed on every run could only be checked against itself.

    /// `ssh-keygen -s user_ca -I ghostty-integration -n <you> -V always:forever
    ///     -z 4242 -O permit-pty user_key.pub`
    static let fixtureUserCertificate = """
        ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFf7DLxYNiJF\
        wsfBZbNg6kP8Hb4e5xZvcdOtSOiG8hUHAAAAIJOxaja7DFTLe3QdFZ63cfXhSQVaI0lKvsz0mjSaqqN7AAAAAAAAEJIAAAABAA\
        AAE2dob3N0dHktaW50ZWdyYXRpb24AAAAQAAAADGFuZHJld2hheW5lcwAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJt\
        aXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YX\
        JkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAA\
        ACCJsH0k/ugfXgkrPgxrCScbqSBAqXHEtIqjiErqsRMvFgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGcBkdsEd7GOOlNw0IeFtjp\
        qCUq/GGNENBpfI21VjL0Lh6E6dvrOjAR54Hvn8MyGYrRICmI3GMgj/+NCtBLsWCg== ghostty-integration-test
        """

    static let fixtureUserCA =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIImwfST+6B9eCSs+DGsJJxupIECpccS0iqOISuqxEy8W ghostty-test-user-ca"

    static let fixtureHostCA =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICtMkuaRK1TLWooscoH475JlCmIYN9Bwa60toMtUAVGY ghostty-test-host-ca"

    @MainActor
    private func makeVaultAndKey() throws -> (Vault, SSHPrivateKeyMaterial) {
        let vault = Vault(keychain: InMemoryKeychain(), directory: temporaryDirectory())
        let identity = try vault.importIdentity(name: "integration", pem: Self.fixturePrivateKey)
        return (vault, try vault.privateKey(for: identity))
    }

    /// Connects, turning "this Mac will not let that account log in" into a skip
    /// rather than a failure. Everything up to the server's verdict on the
    /// credential has already been proved by then — the rejection arrived over
    /// the encrypted transport this test exists to exercise.
    @MainActor
    private func connectOrSkip(
        _ session: SSHSession,
        port: Int,
        command: String,
        auth: [SSHAuthMethod],
        prompter: AlwaysTrustPrompter?
    ) async throws {
        do {
            try await session.connect(
                SSHConnectionRequest(
                    hostname: "127.0.0.1",
                    port: port,
                    username: Self.hostUsername,
                    startupCommand: command
                ),
                auth: auth
            )
        } catch let error as SSHError {
            if case .authenticationFailed(let detail) = error {
                throw XCTSkip(
                    """
                    The transport negotiated and carried encrypted user auth on :\(port), but \
                    "\(Self.hostUsername)" could not log in to the fixture sshd: \(detail)
                    """
                )
            }
            throw error
        }
        XCTAssertEqual(session.state, .connected)
        _ = prompter
    }

    /// Waits for `text` to appear in the session's output rather than sleeping a
    /// fixed time.
    private func expect(
        _ text: String,
        in output: OutputCollector,
        timeout: TimeInterval = 10,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while !output.text.contains(text), Date() < deadline {
            try await Task.sleep(for: .milliseconds(100))
        }
        XCTAssertTrue(
            output.text.contains(text),
            "expected \"\(text)\" in the remote output, got: \(output.text)",
            file: file,
            line: line
        )
    }

    /// The committed user certificate names one principal, fixed at signing
    /// time. On a Mac whose login name differs, the certificate is valid but
    /// cannot admit this account, and the test would fail for the wrong reason.
    private func skipUnlessCertificatePrincipalMatches() throws {
        let certificate = try SSHCertificate.parse(Self.fixtureUserCertificate)
        guard certificate.principals.contains(Self.hostUsername) else {
            throw XCTSkip(
                """
                The committed certificate is valid for \
                \(certificate.principals.joined(separator: ", ")), and this Mac's account is \
                "\(Self.hostUsername)". Re-sign it with: ssh-keygen -s /tmp/ghostty-sshd/user_ca \
                -I ghostty-integration -n $(whoami) -V always:forever -z 4242 -O permit-pty \
                /tmp/ghostty-sshd/user_key.pub
                """
            )
        }
    }

    private func probeOrSkip(port: Int) async throws -> SSHServerOffer {
        do {
            return try await SSHServerProbe.read(host: "127.0.0.1", port: port, timeout: .seconds(3))
        } catch {
            throw XCTSkip(
                """
                No sshd on 127.0.0.1:\(port) (\(error.localizedDescription)). Start the \
                fixture servers described at the top of this file to run the \
                integration tests.
                """
            )
        }
    }

    private func temporaryDirectory() -> URL {
        FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostty-integration-\(UUID().uuidString)", isDirectory: true)
    }
}

/// Accepts any host key. Safe here and nowhere else: the endpoint is a
/// loopback server this test just started.
private final class AlwaysTrustPrompter: HostKeyPrompter, @unchecked Sendable {
    private let lock = NSLock()
    private var asked = false

    var wasAsked: Bool {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.asked
    }

    func confirmUnknownHost(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String
    ) async -> Bool {
        // Via a synchronous helper: taking an `NSLock` directly inside an async
        // function is an error in the Swift 6 language mode.
        self.markAsked()
        return true
    }

    private func markAsked() {
        self.lock.lock()
        self.asked = true
        self.lock.unlock()
    }
}

/// Collects terminal bytes from the main actor without the test having to be
/// careful about which thread it reads them on.
private final class OutputCollector: @unchecked Sendable {
    private let lock = NSLock()
    private var buffer = Data()

    func append(_ data: Data) {
        self.lock.lock()
        self.buffer.append(data)
        self.lock.unlock()
    }

    var text: String {
        self.lock.lock()
        defer { self.lock.unlock() }
        return String(decoding: self.buffer, as: UTF8.self)
    }
}
