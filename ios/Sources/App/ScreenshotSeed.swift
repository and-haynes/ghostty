import Foundation

/// Debug-only launch-argument seeding.
///
/// The UI tests that produce the screenshots in docs/ need a vault with
/// something in it, and they must exercise the *real* code paths — a fake
/// identity drawn on screen would prove nothing. Passing `-ghostty-seed`
/// generates a genuine ed25519 key through `Vault.generateIdentity` and adds
/// sample hosts. It is compiled out of release builds entirely.
enum ScreenshotSeed {
    static var isRequested: Bool {
        #if DEBUG
        return ProcessInfo.processInfo.arguments.contains("-ghostty-seed")
        #else
        return false
        #endif
    }

    @MainActor
    static func apply(to vault: Vault, settings: AppSettings? = nil) {
        #if DEBUG
        guard isRequested else { return }

        // Trust the loopback fixture host CA, so the certificate screens have
        // something real to show and the host-certificate path is exercised rather
        // than described. Harmless anywhere else: it is a throwaway key that has
        // only ever signed a certificate for 127.0.0.1.
        if let settings, settings.trustedCertificateAuthorities.isEmpty {
            settings.trustedCertificateAuthorities = fixtureHostCA
        }

        // Idempotent and self-healing. The app's container survives between
        // test runs, so a seed that bailed out on "hosts already exist" left
        // whatever half-state the previous run produced — including hosts
        // pointing at an identity that failed to generate. Rebuilding the
        // sample hosts every time is cheap and always coherent.
        var identity = vault.identities.first { $0.name == seedIdentityName }
        if identity == nil {
            do {
                identity = try vault.generateIdentity(name: seedIdentityName, type: .ed25519)
            } catch {
                // Surfaced rather than swallowed: when this fails it is almost
                // always a Keychain entitlement problem, and a silent empty key
                // list is a miserable thing to debug.
                NSLog("ghostty: seed key generation failed: \(error)")
            }
        }

        // A second identity carrying a real CA certificate, so the certificate
        // screens show a parsed certificate rather than an empty state.
        var certified = vault.identities.first { $0.name == certifiedIdentityName }
        if certified == nil {
            do {
                certified = try vault.importIdentity(name: certifiedIdentityName, pem: fixtureCertifiedKey)
            } catch {
                NSLog("ghostty: seed certificate key import failed: \(error)")
            }
        }
        if let existing = certified, !existing.hasCertificate {
            do {
                certified = try vault.setCertificate(fixtureUserCertificate, for: existing)
            } catch {
                NSLog("ghostty: seed certificate attach failed: \(error)")
            }
        }

        for sample in samples(identityID: identity?.id, certifiedIdentityID: certified?.id) {
            if let existing = vault.hosts.first(where: { $0.alias == sample.alias }) {
                vault.deleteHost(existing)
            }
            vault.upsert(sample)
        }
        #endif
    }

    private static let seedIdentityName = "iPhone"
    private static let certifiedIdentityName = "CA-signed key"

    // MARK: - Certificate fixtures
    //
    // The same throwaway key, certificate and host CA that `Tests/local-sshd.sh`
    // configures its loopback servers with, so the certificate screens show a
    // real parsed certificate and `cert-demo` really does connect. None of it
    // has ever been trusted by anything outside /tmp.

    private static let fixtureCertifiedKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjewAAAKCg1HvboNR7
        2wAAAAtzc2gtZWQyNTUxOQAAACCTsWo2uwxUy3t0HRWet3H14UkFWiNJSr7M9Jo0mqqjew
        AAAEAt2Gmsq6Ru+Da1XiViBO0VdkG6AjJ33DfMAv+oM6QqVZOxaja7DFTLe3QdFZ63cfXh
        SQVaI0lKvsz0mjSaqqN7AAAAGGdob3N0dHktaW50ZWdyYXRpb24tdGVzdAECAwQF
        -----END OPENSSH PRIVATE KEY-----
        """

    private static let fixtureUserCertificate = """
        ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIFf7DLxYNiJF\
        wsfBZbNg6kP8Hb4e5xZvcdOtSOiG8hUHAAAAIJOxaja7DFTLe3QdFZ63cfXhSQVaI0lKvsz0mjSaqqN7AAAAAAAAEJIAAAABAA\
        AAE2dob3N0dHktaW50ZWdyYXRpb24AAAAQAAAADGFuZHJld2hheW5lcwAAAAAAAAAA//////////8AAAAAAAAAggAAABVwZXJt\
        aXQtWDExLWZvcndhcmRpbmcAAAAAAAAAF3Blcm1pdC1hZ2VudC1mb3J3YXJkaW5nAAAAAAAAABZwZXJtaXQtcG9ydC1mb3J3YX\
        JkaW5nAAAAAAAAAApwZXJtaXQtcHR5AAAAAAAAAA5wZXJtaXQtdXNlci1yYwAAAAAAAAAAAAAAMwAAAAtzc2gtZWQyNTUxOQAA\
        ACCJsH0k/ugfXgkrPgxrCScbqSBAqXHEtIqjiErqsRMvFgAAAFMAAAALc3NoLWVkMjU1MTkAAABAGcBkdsEd7GOOlNw0IeFtjp\
        qCUq/GGNENBpfI21VjL0Lh6E6dvrOjAR54Hvn8MyGYrRICmI3GMgj/+NCtBLsWCg==
        """

    private static let fixtureHostCA =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICtMkuaRK1TLWooscoH475JlCmIYN9Bwa60toMtUAVGY ghostty-test-host-ca"

    /// The account the loopback fixture `sshd` runs as — the principal the
    /// fixture certificate names. Empty inside the simulator via `NSUserName()`,
    /// but CoreSimulator passes the host's home directory through.
    private static var hostUsername: String {
        let environment = ProcessInfo.processInfo.environment
        if let home = environment["SIMULATOR_HOST_HOME"], !home.isEmpty {
            let name = URL(fileURLWithPath: home).lastPathComponent
            if !name.isEmpty { return name }
        }
        return NSUserName()
    }

    private static func samples(identityID: UUID?, certifiedIdentityID: UUID?) -> [Host] {
        [
            // The certificate-only loopback fixture (Tests/local-sshd.sh :22027):
            // `AuthorizedKeysFile none`, so the certificate is the only way in.
            Host(
                alias: "cert-demo",
                hostname: "127.0.0.1",
                port: 22027,
                username: hostUsername,
                identityID: certifiedIdentityID,
                group: "fixtures",
                tags: ["certificate"],
                colorHex: "#CBA6F7",
                notes: "certificate authentication fixture"
            ),
            Host(
                alias: "noether",
                hostname: "10.0.0.81",
                username: "andy",
                identityID: identityID,
                group: "homelab",
                tags: ["linux", "workspace"],
                colorHex: "#4CE066",
                notes: "agent workspace"
            ),
            Host(
                alias: "git.lan",
                hostname: "git.lan",
                username: "git",
                identityID: identityID,
                group: "homelab",
                tags: ["forgejo"],
                colorHex: "#89B4FA"
            ),
            Host(
                alias: "pi-a",
                hostname: "10.0.0.41",
                username: "andy",
                identityID: identityID,
                group: "homelab",
                tags: ["pi", "gateway"],
                colorHex: "#F9E2AF"
            ),
            Host(
                alias: "sagan",
                hostname: "10.0.0.45",
                username: "andy",
                usesPassword: true,
                group: "macs",
                tags: ["mac", "builds"],
                colorHex: "#F5C2E7"
            ),
        ]
    }
}
