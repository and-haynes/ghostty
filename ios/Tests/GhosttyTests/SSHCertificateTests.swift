import Foundation
import NIOSSH
import XCTest

@testable import Ghostty

/// Certificate fixtures, produced by real `ssh-keygen` runs against a throwaway
/// CA. Nothing here has ever been trusted by anything.
enum CertificateFixtures {
    /// `ssh-keygen -t ed25519 -C andy@phone -f user`
    static let userPrivateKey = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACBA81Oxdxe6Z1VPbPJoO7VNQDMGYR3f2f9mGkY1TsHK6wAAAJASoV6yEqFe
        sgAAAAtzc2gtZWQyNTUxOQAAACBA81Oxdxe6Z1VPbPJoO7VNQDMGYR3f2f9mGkY1TsHK6w
        AAAECh67aa2ULnucHIp32fPbUWtQCOPTRMKIQbjJawcp3yEEDzU7F3F7pnVU9s8mg7tU1A
        MwZhHd/Z/2YaRjVOwcrrAAAACmFuZHlAcGhvbmUBAgM=
        -----END OPENSSH PRIVATE KEY-----
        """

    static let userPublicKey =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEDzU7F3F7pnVU9s8mg7tU1AMwZhHd/Z/2YaRjVOwcrr andy@phone"

    /// `ssh-keygen -s ca -I andy@phone -n andy,deploy -V always:forever -z 99 \
    ///     -O permit-pty -O source-address=10.0.0.0/8 user.pub`
    static let userCertificate = """
        ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQtdjAxQG9wZW5zc2guY29tAAAAIDoYwsJJxB29\
        jqkDTkR/g9xqWhS8Jf1i04ty9SVp7mIqAAAAIEDzU7F3F7pnVU9s8mg7tU1AMwZhHd/Z/2YaRjVOwcrrAAAAAAAAAGMAAAABAA\
        AACmFuZHlAcGhvbmUAAAASAAAABGFuZHkAAAAGZGVwbG95AAAAAAAAAAD//////////wAAACQAAAAOc291cmNlLWFkZHJlc3MA\
        AAAOAAAACjEwLjAuMC4wLzgAAACCAAAAFXBlcm1pdC1YMTEtZm9yd2FyZGluZwAAAAAAAAAXcGVybWl0LWFnZW50LWZvcndhcm\
        RpbmcAAAAAAAAAFnBlcm1pdC1wb3J0LWZvcndhcmRpbmcAAAAAAAAACnBlcm1pdC1wdHkAAAAAAAAADnBlcm1pdC11c2VyLXJj\
        AAAAAAAAAAAAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIBXJ2UuaiHnWuF5cffrYvUwvpAZDpUt/y3jdSDRCGfWqAAAAUwAAAAtzc2\
        gtZWQyNTUxOQAAAEBMrCUpVMa3ZmUYzMq4NpG03Ucc8dlpQPK9EXEI4jG+5p/u9nMUNdZoxOVhZpAUNv55ZAqP1l+UwGuvmgqb\
        tPQO andy@phone
        """

    static let certificateAuthority =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBXJ2UuaiHnWuF5cffrYvUwvpAZDpUt/y3jdSDRCGfWq morton-test-ca"

    /// One line, no trailing newline, no comment — the form the app stores.
    static var certificateLine: String {
        let flat = userCertificate.replacingOccurrences(of: "\n", with: "")
        return flat.split(separator: " ").prefix(2).joined(separator: " ")
    }
}

final class SSHCertificateTests: XCTestCase {

    // MARK: - Parsing

    func testParsingAUserCertificate() throws {
        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)

        XCTAssertEqual(certificate.kind, .user)
        XCTAssertEqual(certificate.keyID, "andy@phone")
        XCTAssertEqual(certificate.serial, 99)
        XCTAssertEqual(certificate.principals, ["andy", "deploy"])
        XCTAssertEqual(certificate.comment, "andy@phone")
        XCTAssertTrue(certificate.extensions.contains("permit-pty"))
        XCTAssertEqual(certificate.criticalOptions, ["source-address": "10.0.0.0/8"])

        // `-V always:forever` is validAfter = 0 and validBefore = UInt64.max,
        // neither of which is a date worth showing anyone.
        XCTAssertNil(certificate.validAfter)
        XCTAssertNil(certificate.validBefore)
        XCTAssertTrue(certificate.isCurrentlyValid)
        XCTAssertEqual(certificate.validityDescription, "Valid indefinitely")
    }

    func testTheCertificateNamesItsAuthority() throws {
        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)
        XCTAssertEqual(
            certificate.authorityFingerprint,
            SSHFingerprint.sha256(publicKeyLine: CertificateFixtures.certificateAuthority)
        )
    }

    func testTheCertificateNamesTheKeyItCertifies() throws {
        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)
        XCTAssertEqual(
            certificate.certifiedKeyFingerprint,
            SSHFingerprint.sha256(publicKeyLine: CertificateFixtures.userPublicKey)
        )
        XCTAssertTrue(certificate.certifies(publicKeyLine: CertificateFixtures.userPublicKey))
    }

    func testACertificateDoesNotCertifySomeOtherKey() throws {
        // The check that keeps a certificate from being filed against the wrong
        // key, where it would only fail at the far end of a network round trip.
        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)
        XCTAssertFalse(certificate.certifies(publicKeyLine: CertificateFixtures.certificateAuthority))
        XCTAssertFalse(certificate.certifies(publicKeyLine: "not a key at all"))
    }

    func testNormalisingTheStoredLine() throws {
        // Whatever arrives on the clipboard — trailing newline, comment, the
        // whole -cert.pub file — is stored as "<type> <base64>".
        let certificate = try SSHCertificate.parse("\n  \(CertificateFixtures.userCertificate)  \n")
        XCTAssertEqual(certificate.line, CertificateFixtures.certificateLine)
        XCTAssertEqual(certificate.line.split(separator: " ").count, 2)

        // And re-parsing the stored form produces the same certificate.
        XCTAssertEqual(try SSHCertificate.parse(certificate.line), certificate)
    }

    func testAPlainPublicKeyIsNotACertificate() throws {
        // The commonest mistake: pasting the .pub instead of the -cert.pub.
        XCTAssertThrowsError(try SSHCertificate.parse(CertificateFixtures.userPublicKey)) { error in
            guard case .some(.notACertificate) = error as? SSHCertificateError else {
                return XCTFail("expected notACertificate, got \(error)")
            }
        }
    }

    func testGarbageIsRejected() throws {
        for text in ["", "hello", "ssh-ed25519-cert-v01@openssh.com", "ssh-ed25519-cert-v01@openssh.com !!!!"] {
            XCTAssertThrowsError(try SSHCertificate.parse(text), "\"\(text)\" should not parse")
        }
    }

    func testAPrivateKeyIsNotACertificate() throws {
        XCTAssertThrowsError(try SSHCertificate.parse(CertificateFixtures.userPrivateKey))
    }

    // MARK: - Trusted authorities

    func testParsingTheTrustedAuthoritySetting() throws {
        let text = """
            # The Morton host CA
            \(CertificateFixtures.certificateAuthority)

            \(CertificateFixtures.userPublicKey)
            """
        let authorities = SSHTrustedAuthorities(text: text)

        XCTAssertEqual(authorities.entries.count, 2, "comments and blank lines are not entries")
        XCTAssertEqual(authorities.keys.count, 2)
        XCTAssertEqual(authorities.entries.first?.comment, "morton-test-ca")
        XCTAssertEqual(
            authorities.entries.first?.fingerprint,
            SSHFingerprint.sha256(publicKeyLine: CertificateFixtures.certificateAuthority)
        )
    }

    func testAnUnreadableAuthorityLineIsKeptAndFlagged() throws {
        // Reporting it beats dropping it: a CA with a missing character would
        // otherwise fail silently, much later, as "no host key algorithm in
        // common".
        let authorities = SSHTrustedAuthorities(
            text: "ssh-ed25519 AAAAnot-base64!!\n\(CertificateFixtures.certificateAuthority)"
        )
        XCTAssertEqual(authorities.entries.count, 2)
        XCTAssertEqual(authorities.keys.count, 1)
        XCTAssertFalse(authorities.entries[0].isValid)
        XCTAssertNil(authorities.entries[0].fingerprint)
        XCTAssertTrue(authorities.entries[1].isValid)
    }

    func testAnEmptySettingTrustsNobody() throws {
        XCTAssertTrue(SSHTrustedAuthorities(text: "").isEmpty)
        XCTAssertTrue(SSHTrustedAuthorities(text: "\n  \n# just a comment\n").isEmpty)
    }

    // MARK: - Negotiation

    func testCertificateAlgorithmsAreOnlyOfferedWithACA() throws {
        // Asking for a certificate we cannot check would be worse than not
        // asking: a certified host would present one, we would have nothing to
        // judge it with, and a connection that worked yesterday under
        // trust-on-first-use would start failing.
        let without = SSHAlgorithmSupport.offeredHostKeyAlgorithms(trustingCertificateAuthorities: false)
        XCTAssertFalse(without.contains { $0.hasSuffix("-cert-v01@openssh.com") })
        XCTAssertEqual(without, SSHAlgorithmSupport.plainHostKeyAlgorithms)

        let with = SSHAlgorithmSupport.offeredHostKeyAlgorithms(trustingCertificateAuthorities: true)
        XCTAssertTrue(with.contains("ssh-ed25519-cert-v01@openssh.com"))
        XCTAssertTrue(with.contains("rsa-sha2-512-cert-v01@openssh.com"))
        // Certificates first, plain keys behind them: a certified host presents
        // its certificate, an uncertified one falls back in the same negotiation.
        XCTAssertLessThan(
            with.firstIndex(of: "ssh-ed25519-cert-v01@openssh.com")!,
            with.firstIndex(of: "ssh-ed25519")!
        )
    }

    func testEveryOfferedAlgorithmIsOneTheLibraryKnows() throws {
        // A name we offer but cannot parse a key for is a handshake that
        // negotiates successfully and then dies.
        for algorithm in SSHAlgorithmSupport.hostKeyAlgorithms {
            XCTAssertFalse(algorithm.isEmpty)
        }
        XCTAssertFalse(
            SSHAlgorithmSupport.hostKeyAlgorithms.contains("ssh-rsa"),
            "ssh-rsa signs with SHA-1 and must never be asked for"
        )
        XCTAssertFalse(SSHAlgorithmSupport.hostKeyAlgorithms.contains("ssh-dss"))
    }

    // MARK: - Storage

    @MainActor
    func testAttachingACertificateToAnIdentity() throws {
        let vault = makeVault()
        let identity = try vault.importIdentity(name: "phone", pem: CertificateFixtures.userPrivateKey)
        XCTAssertFalse(identity.hasCertificate)

        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)
        XCTAssertTrue(certificate.certifies(publicKeyLine: identity.publicKeyLine))

        let updated = try vault.setCertificate(certificate.line, for: identity)
        XCTAssertTrue(updated.hasCertificate)
        XCTAssertEqual(updated.certificate, CertificateFixtures.certificateLine)
        XCTAssertEqual(vault.identities.first?.certificate, CertificateFixtures.certificateLine)

        // Removing it leaves the key alone.
        let cleared = try vault.setCertificate(nil, for: identity)
        XCTAssertFalse(cleared.hasCertificate)
        XCTAssertEqual(cleared.fingerprint, identity.fingerprint)
    }

    @MainActor
    func testACertificateSurvivesAReload() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostty-cert-\(UUID().uuidString)", isDirectory: true)
        let keychain = InMemoryKeychain()

        let vault = Vault(keychain: keychain, directory: directory)
        let identity = try vault.importIdentity(name: "phone", pem: CertificateFixtures.userPrivateKey)
        try vault.setCertificate(CertificateFixtures.certificateLine, for: identity)

        let reloaded = Vault(keychain: keychain, directory: directory)
        XCTAssertEqual(reloaded.identities.first?.certificate, CertificateFixtures.certificateLine)
    }

    @MainActor
    func testAnIdentityWrittenBeforeCertificatesExistedStillLoads() throws {
        // The stored JSON gains a field; a record without it must decode rather
        // than take the whole vault down.
        let json = """
            [{
              "id": "\(UUID().uuidString)",
              "name": "old",
              "keyType": "ed25519",
              "publicKeyLine": "\(CertificateFixtures.userPublicKey)",
              "fingerprint": "SHA256:whatever",
              "createdAt": "2024-01-01T00:00:00Z",
              "isSecureEnclave": false,
              "requiresBiometrics": false,
              "syncsToICloud": false
            }]
            """
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ghostty-cert-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try Data(json.utf8).write(to: directory.appendingPathComponent("identities.json"))

        let vault = Vault(keychain: InMemoryKeychain(), directory: directory)
        XCTAssertEqual(vault.identities.count, 1)
        XCTAssertNil(vault.identities.first?.certificate)
        XCTAssertFalse(vault.identities.first?.hasCertificate ?? true)
    }

    // MARK: - Offering

    @MainActor
    func testACertifiedKeyIsOfferedBeforeThePlainKey() async throws {
        // Both, in that order, and never one instead of the other: a host that
        // trusts the CA takes the certificate, a host that has the key in
        // authorized_keys takes the key, and neither needs configuring.
        let vault = makeVault()
        var identity = try vault.importIdentity(name: "phone", pem: CertificateFixtures.userPrivateKey)
        identity = try vault.setCertificate(CertificateFixtures.certificateLine, for: identity)

        let host = Host(alias: "noether", hostname: "10.0.0.81", username: "andy", identityID: identity.id)
        let plan = try await SSHConnectionCoordinator.plan(
            for: host,
            identity: identity,
            vault: vault,
            cols: 80,
            rows: 24
        )

        XCTAssertEqual(plan.authMethods.count, 2)
        guard case .certifiedKey(_, let line) = plan.authMethods[0] else {
            return XCTFail("the certificate should be offered first, got \(plan.authMethods[0].debugLabel)")
        }
        XCTAssertEqual(line, CertificateFixtures.certificateLine)
        guard case .privateKey = plan.authMethods[1] else {
            return XCTFail("the plain key should be offered behind it")
        }
    }

    @MainActor
    func testAKeyWithNoCertificateIsOfferedOnce() async throws {
        let vault = makeVault()
        let identity = try vault.importIdentity(name: "phone", pem: CertificateFixtures.userPrivateKey)
        let host = Host(alias: "noether", hostname: "10.0.0.81", username: "andy", identityID: identity.id)

        let plan = try await SSHConnectionCoordinator.plan(
            for: host,
            identity: identity,
            vault: vault,
            cols: 80,
            rows: 24
        )
        XCTAssertEqual(plan.authMethods.count, 1)
        guard case .privateKey = plan.authMethods[0] else {
            return XCTFail("expected a plain private key offer")
        }
    }

    @MainActor
    func testTheOfferCarriesTheCertificateRatherThanTheBareKey() throws {
        // What changes on the wire: the public half sent to the server is the
        // certificate, not `ssh-ed25519 AAAA…`. The private key still signs.
        let vault = makeVault()
        let identity = try vault.importIdentity(name: "phone", pem: CertificateFixtures.userPrivateKey)
        let material = try vault.privateKey(for: identity)
        let certificate = try SSHCertificate.parse(CertificateFixtures.userCertificate)

        let offer = try material.authenticationOffer(username: "andy", certificate: certificate)
        guard case .privateKey(let privateKeyOffer) = offer.offer else {
            return XCTFail("expected a private key offer")
        }
        XCTAssertEqual(NIOSSHCertifiedPublicKey(privateKeyOffer.publicKey), certificate.certifiedKey)
        XCTAssertNotEqual(privateKeyOffer.publicKey, try material.nioSSHPrivateKey().publicKey)
    }

    // MARK: - Harness

    @MainActor
    private func makeVault() -> Vault {
        Vault(
            keychain: InMemoryKeychain(),
            directory: FileManager.default.temporaryDirectory
                .appendingPathComponent("ghostty-cert-\(UUID().uuidString)", isDirectory: true)
        )
    }
}
