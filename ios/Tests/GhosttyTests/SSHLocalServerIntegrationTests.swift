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
/// Both servers are temporary, loopback-only, and started by hand:
///
/// ```bash
/// D=/tmp/ghostty-sshd
/// mkdir -p $D && chmod 700 $D
/// ssh-keygen -q -t ed25519 -N '' -f $D/host_ed25519
/// ssh-keygen -q -t rsa -b 3072 -N '' -f $D/host_rsa
/// # the fixture key below; its public half goes in $D/authorized_keys
/// /usr/sbin/sshd -f $D/sshd_ctr.conf -D -e &   # :22022, aes*-ctr only, ed25519 host key
/// /usr/sbin/sshd -f $D/sshd_rsa.conf -D -e &   # :22023, aes*-ctr only, RSA host key only
/// ```
///
/// When nothing is listening the tests skip rather than fail: a laptop without
/// the servers running is not a broken build.
final class SSHLocalServerIntegrationTests: XCTestCase {
    /// aes256-ctr / aes192-ctr / aes128-ctr with hmac-sha2-256, an Ed25519 host
    /// key, and **no AEAD at all** — the configuration that was unreachable
    /// before this change.
    private static let ctrOnlyPort = 22022
    /// The same, but with only RSA host keys: still unreachable, and the point
    /// is that the app now says so in words.
    private static let rsaHostKeyPort = 22023
    /// A stand-in for pi-a: OpenSSH 10.3's full default algorithm set. Here to
    /// prove the widened cipher list does not *change* what a modern server
    /// negotiates — the AEAD must still win.
    private static let fullOpenSSHPort = 22024

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

    func testRSAOnlyServerIsExplainedRatherThanShrugged() async throws {
        let offer = try await probeOrSkip(port: Self.rsaHostKeyPort)
        let mismatch = SSHAlgorithmMismatch(hostname: "127.0.0.1", offer: offer)

        XCTAssertEqual(mismatch.failures, [.hostKey])
        XCTAssertFalse(
            mismatch.ciphersInCommon.isEmpty,
            "the cipher negotiation should succeed even here — only the host key blocks it"
        )
        let text = mismatch.explanation
        XCTAssertTrue(text.contains("rsa-sha2-512"))
        XCTAssertTrue(text.contains("only host keys are RSA"))
        XCTAssertTrue(text.contains("ssh-keygen -A"))
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

    /// The same connection against the RSA-only server must fail with the
    /// explanation, not with a bare `keyExchangeNegotiationFailure`.
    @MainActor
    func testRSAOnlyServerFailsWithAReadableError() async throws {
        _ = try await probeOrSkip(port: Self.rsaHostKeyPort)

        let vault = Vault(keychain: InMemoryKeychain(), directory: temporaryDirectory())
        let identity = try vault.importIdentity(name: "integration", pem: Self.fixturePrivateKey)
        let material = try vault.privateKey(for: identity)

        let session = SSHSession(vault: vault)
        let prompter = AlwaysTrustPrompter()
        session.hostKeyPrompter = prompter

        let request = SSHConnectionRequest(
            hostname: "127.0.0.1",
            port: Self.rsaHostKeyPort,
            username: Self.hostUsername
        )

        do {
            try await session.connect(request, auth: [.privateKey(material)])
            XCTFail("an RSA-only host key should not be accepted")
        } catch let error as SSHError {
            guard case .negotiationFailed(_, let detail) = error else {
                XCTFail("expected a negotiation failure, got \(error)")
                return
            }
            let text = try XCTUnwrap(detail)
            XCTAssertTrue(text.contains("rsa-sha2-512"), text)
            XCTAssertTrue(text.contains("Missing: host key."), text)
            XCTAssertTrue(text.contains("ssh-keygen -A"), text)
        }
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
