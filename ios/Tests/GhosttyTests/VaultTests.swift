import XCTest
import Foundation
@testable import Ghostty

// MARK: - Test vectors

/// Real, throwaway keys produced by `ssh-keygen -t ed25519|ecdsa -N ''`.
///
/// Parsing output we generated ourselves proves only that our writer and our
/// reader agree. These fixtures come from OpenSSH itself, and the expected
/// public lines and fingerprints are what `ssh-keygen -l` printed for them —
/// which is the property that actually matters, because a server compares our
/// key against a line the user pasted from a terminal.
private enum Vectors {
    static let ed25519PEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
    QyNTUxOQAAACCKXEzxWfVPpLsS9xHen26EKafsrDsZXzjm3i/RtvZJswAAAJgm2amZJtmp
    mQAAAAtzc2gtZWQyNTUxOQAAACCKXEzxWfVPpLsS9xHen26EKafsrDsZXzjm3i/RtvZJsw
    AAAECM/pQOCu67w9hg+r92BkpN+LhEr6pv0EQV1S+ZJI9eKopcTPFZ9U+kuxL3Ed6fboQp
    p+ysOxlfOObeL9G29kmzAAAADnZlY3RvckBnaG9zdHR5AQIDBAUGBw==
    -----END OPENSSH PRIVATE KEY-----
    """

    static let ed25519PublicLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpcTPFZ9U+kuxL3Ed6fboQpp+ysOxlfOObeL9G29kmz vector@ghostty"
    static let ed25519Fingerprint = "SHA256:qfGWJiYsIIwuLiaak59D5dlntQK/4imFltRQZeG5JrU"

    static let ecdsaPEM = """
    -----BEGIN OPENSSH PRIVATE KEY-----
    b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
    1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQS9bzdX/d5XcVWS8CgCHi8G6lb/WQbb
    RKla0IhVGyVWcSaWzVnS+egj58dCnwNJYybRJwH4IHnFZj/NutOzB5T6AAAAqIa+tCSGvr
    QkAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL1vN1f93ldxVZLw
    KAIeLwbqVv9ZBttEqVrQiFUbJVZxJpbNWdL56CPnx0KfA0ljJtEnAfggecVmP82607MHlP
    oAAAAgc6X7YXVhncr5SmiC8FyyOZD3w2YNJs+g5t/OsAV3PfgAAAAOdmVjdG9yQGdob3N0
    dHkBAg==
    -----END OPENSSH PRIVATE KEY-----
    """

    static let ecdsaPublicLine =
        "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBL1vN1f93ldxVZLwKAIeLwbqVv9ZBttEqVrQiFUbJVZxJpbNWdL56CPnx0KfA0ljJtEnAfggecVmP82607MHlPo= vector@ghostty"
    static let ecdsaFingerprint = "SHA256:PpjzfCCtQ08Q0gZx3VW6UuorCgkg4fWq0MLVA7uf9vw"

    /// An unrelated ed25519 public key, used for the fingerprint vector.
    static let knownPublicLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMDUXm/8yg/ZUUXNP6RM90rYQnGDLGqUqAhfXjs4hCKw known@vector"
    /// Verified with `ssh-keygen -l`, not taken on trust.
    static let knownFingerprint = "SHA256:dJyYoWVeMKBVOXeL9zMEYsVqabERCb6N+kcdGrTYRkU"
}

// MARK: - Wire format

final class OpenSSHWireTests: XCTestCase {
    func testStringIsLengthPrefixedBigEndian() {
        XCTAssertEqual(
            [UInt8](OpenSSHWire.writeString("abc")),
            [0x00, 0x00, 0x00, 0x03, 0x61, 0x62, 0x63]
        )
    }

    func testMPIntPadsWhenHighBitIsSet() {
        // 0x80... would read as negative without the leading zero byte.
        XCTAssertEqual(
            [UInt8](OpenSSHWire.writeMPInt(Data([0x80, 0x01]))),
            [0x00, 0x00, 0x00, 0x03, 0x00, 0x80, 0x01]
        )
    }

    func testMPIntStripsLeadingZerosAndEncodesZeroAsEmpty() {
        XCTAssertEqual(
            [UInt8](OpenSSHWire.writeMPInt(Data([0x00, 0x00, 0x7F]))),
            [0x00, 0x00, 0x00, 0x01, 0x7F]
        )
        XCTAssertEqual([UInt8](OpenSSHWire.writeMPInt(Data([0x00]))), [0, 0, 0, 0])
    }

    func testMPIntNormalisesToFixedWidth() {
        // Short (leading zero dropped) and long (padding byte added) both land
        // on the curve's exact scalar size.
        XCTAssertEqual(
            OpenSSHWire.mpintToFixedWidth(Data([0x7F]), byteCount: 4),
            Data([0x00, 0x00, 0x00, 0x7F])
        )
        XCTAssertEqual(
            OpenSSHWire.mpintToFixedWidth(Data([0x00, 0x80, 0x01, 0x02, 0x03]), byteCount: 4),
            Data([0x80, 0x01, 0x02, 0x03])
        )
        XCTAssertNil(OpenSSHWire.mpintToFixedWidth(Data([0x01, 0x02, 0x03]), byteCount: 2))
    }

    func testReaderRefusesToReadPastTheEnd() {
        var reader = OpenSSHWireReader(Data([0x00, 0x00, 0x00, 0x08, 0x41]))
        // Claims 8 bytes but only 1 follows: nil, not a crash.
        XCTAssertNil(reader.readString())
    }
}

// MARK: - Fingerprints

final class SSHFingerprintTests: XCTestCase {
    func testKnownVectorMatchesSSHKeygen() {
        XCTAssertEqual(
            SSHFingerprint.sha256(publicKeyLine: Vectors.knownPublicLine),
            Vectors.knownFingerprint
        )
    }

    func testFingerprintHasNoBase64Padding() {
        let fingerprint = SSHFingerprint.sha256(blob: Data("anything".utf8))
        XCTAssertTrue(fingerprint.hasPrefix("SHA256:"))
        XCTAssertFalse(fingerprint.contains("="), "OpenSSH strips base64 padding")
    }

    func testMalformedLineReturnsNil() {
        XCTAssertNil(SSHFingerprint.sha256(publicKeyLine: "ssh-ed25519"))
        XCTAssertNil(SSHFingerprint.sha256(publicKeyLine: "ssh-ed25519 not!base64!"))
    }
}

// MARK: - Key file

final class OpenSSHKeyFileTests: XCTestCase {
    func testParsesRealEd25519KeyFromSSHKeygen() throws {
        let (material, comment) = try OpenSSHKeyFile.parse(pem: Vectors.ed25519PEM)
        XCTAssertEqual(material.keyType, .ed25519)
        XCTAssertEqual(comment, "vector@ghostty")
        XCTAssertEqual(material.publicKeyLine(comment: comment), Vectors.ed25519PublicLine)
        XCTAssertEqual(material.fingerprint, Vectors.ed25519Fingerprint)
    }

    func testParsesRealECDSAKeyFromSSHKeygen() throws {
        let (material, comment) = try OpenSSHKeyFile.parse(pem: Vectors.ecdsaPEM)
        XCTAssertEqual(material.keyType, .p256)
        XCTAssertEqual(comment, "vector@ghostty")
        XCTAssertEqual(material.publicKeyLine(comment: comment), Vectors.ecdsaPublicLine)
        XCTAssertEqual(material.fingerprint, Vectors.ecdsaFingerprint)
    }

func testEd25519RoundTripIsLossless() throws {
        // `persistableData` is the raw private scalar/seed for a software key,
        // so this is a byte-for-byte comparison of the private half.
        let original = try SSHPrivateKeyMaterial.generate(.ed25519, requiresBiometrics: false)
        let pem = try OpenSSHKeyFile.encode(material: original, comment: "round@trip")

        let (restored, comment) = try OpenSSHKeyFile.parse(pem: pem)
        XCTAssertEqual(restored.keyType, .ed25519)
        XCTAssertEqual(restored.persistableData, original.persistableData)
        XCTAssertEqual(comment, "round@trip")
        XCTAssertEqual(restored.publicKeyLine(comment: comment), original.publicKeyLine(comment: comment))
        XCTAssertEqual(restored.fingerprint, original.fingerprint)
    }

    func testP256RoundTripIsLossless() throws {
        let original = try SSHPrivateKeyMaterial.generate(.p256, requiresBiometrics: false)
        let pem = try OpenSSHKeyFile.encode(material: original, comment: "p256@trip")

        let (restored, comment) = try OpenSSHKeyFile.parse(pem: pem)
        XCTAssertEqual(restored.keyType, .p256)
        XCTAssertEqual(restored.persistableData, original.persistableData)
        XCTAssertEqual(comment, "p256@trip")
        XCTAssertEqual(restored.publicKeyLine(comment: comment), original.publicKeyLine(comment: comment))
    }

    /// Run the ECDSA curves many times over: the mpint encoding of a private
    /// scalar only needs its padding byte when the top bit happens to be set,
    /// so a single random key passes a broken implementation roughly half the
    /// time. Repetition makes that flake deterministic.
    func testECDSARoundTripsAcrossCurvesAndMPIntEdgeCases() throws {
        for _ in 0..<32 {
            for type in [SSHKeyType.p256, .p384, .p521] {
                let original = try SSHPrivateKeyMaterial.generate(type, requiresBiometrics: false)
                let pem = try OpenSSHKeyFile.encode(material: original, comment: "c")
                let (restored, _) = try OpenSSHKeyFile.parse(pem: pem)
                XCTAssertEqual(restored.keyType, type)
                XCTAssertEqual(restored.persistableData, original.persistableData)
                XCTAssertEqual(restored.fingerprint, original.fingerprint)
            }
        }
    }

    func testEncryptedKeyIsRejectedWithAnActionableError() throws {
        // Built by hand rather than shipping a real encrypted key: all that
        // matters is the header, and we must reject before touching the body.
        var container = Data("openssh-key-v1\0".utf8)
        container += OpenSSHWire.writeString("aes256-ctr")
        container += OpenSSHWire.writeString("bcrypt")
        container += OpenSSHWire.writeString(
            OpenSSHWire.writeString(Data([0xDE, 0xAD, 0xBE, 0xEF])) + OpenSSHWire.writeUInt32(16)
        )
        container += OpenSSHWire.writeUInt32(1)
        container += OpenSSHWire.writeString(Data(repeating: 0x2A, count: 51))
        container += OpenSSHWire.writeString(Data(repeating: 0x5A, count: 64))

        let pem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(container.base64EncodedString())
        -----END OPENSSH PRIVATE KEY-----
        """

        XCTAssertThrowsError(try OpenSSHKeyFile.parse(pem: pem)) { error in
            XCTAssertEqual(error as? VaultError, .encryptedKeyUnsupported)
            // The message has to tell the user how to fix it.
            XCTAssertTrue(
                (error as? VaultError)?.errorDescription?.contains("ssh-keygen -p") == true,
                "the error should name the command that decrypts the key"
            )
        }
    }

    func testRSAKeyIsRejectedByAlgorithmName() throws {
        var privateSection = OpenSSHWire.writeUInt32(7) + OpenSSHWire.writeUInt32(7)
        privateSection += OpenSSHWire.writeString("ssh-rsa")

        var container = Data("openssh-key-v1\0".utf8)
        container += OpenSSHWire.writeString("none")
        container += OpenSSHWire.writeString("none")
        container += OpenSSHWire.writeString(Data())
        container += OpenSSHWire.writeUInt32(1)
        container += OpenSSHWire.writeString(Data(repeating: 0x2A, count: 16))
        container += OpenSSHWire.writeString(privateSection)

        let pem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(container.base64EncodedString())
        -----END OPENSSH PRIVATE KEY-----
        """
        XCTAssertThrowsError(try OpenSSHKeyFile.parse(pem: pem)) { error in
            XCTAssertEqual(error as? VaultError, .unsupportedKeyType("ssh-rsa"))
        }
    }

    func testGarbageInputThrowsRatherThanCrashing() {
        for junk in ["", "not a key", "-----BEGIN OPENSSH PRIVATE KEY-----\n!!!\n-----END OPENSSH PRIVATE KEY-----"] {
            XCTAssertThrowsError(try OpenSSHKeyFile.parse(pem: junk))
        }
        // A truncated but structurally plausible container.
        let truncated = Data("openssh-key-v1\0".utf8) + OpenSSHWire.writeString("none")
        let pem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        \(truncated.base64EncodedString())
        -----END OPENSSH PRIVATE KEY-----
        """
        XCTAssertThrowsError(try OpenSSHKeyFile.parse(pem: pem))
    }

    func testEncodedPEMWrapsAtSeventyColumns() throws {
        let material = try SSHPrivateKeyMaterial.generate(.ed25519, requiresBiometrics: false)
        let pem = try OpenSSHKeyFile.encode(material: material, comment: "wrap@test")
        let body = pem.split(whereSeparator: \.isNewline).dropFirst().dropLast()
        XCTAssertFalse(body.isEmpty)
        for line in body {
            XCTAssertLessThanOrEqual(line.count, 70)
        }
    }

    func testSecureEnclaveKeysCannotBeExported() throws {
        try XCTSkipUnless(SSHPrivateKeyMaterial.isSecureEnclaveAvailable, "no Secure Enclave on this device")
        let material = try SSHPrivateKeyMaterial.generate(.secureEnclaveP256, requiresBiometrics: false)
        XCTAssertThrowsError(try OpenSSHKeyFile.encode(material: material, comment: "se")) { error in
            XCTAssertEqual(error as? VaultError, .cannotExportSecureEnclaveKey)
        }
    }
}

// MARK: - TOFU policy

final class KnownHostsPolicyTests: XCTestCase {
    private let line = Vectors.ed25519PublicLine
    private let fingerprint = Vectors.ed25519Fingerprint

    func testUnknownEndpointIsUnknown() {
        let decision = KnownHostsPolicy.decide(
            existing: nil,
            presentedType: "ssh-ed25519",
            presentedFingerprint: fingerprint,
            presentedLine: line
        )
        guard case .unknown(let type, let fp, _) = decision else {
            return XCTFail("expected .unknown, got \(decision)")
        }
        XCTAssertEqual(type, "ssh-ed25519")
        XCTAssertEqual(fp, fingerprint)
    }

    func testMatchingPinIsTrusted() {
        let pin = KnownHost(
            hostname: "h", port: 22, keyType: "ssh-ed25519",
            fingerprint: fingerprint, publicKeyLine: line
        )
        let decision = KnownHostsPolicy.decide(
            existing: pin,
            presentedType: "ssh-ed25519",
            presentedFingerprint: fingerprint,
            presentedLine: line
        )
        guard case .trusted = decision else { return XCTFail("expected .trusted, got \(decision)") }
    }

    func testDifferentFingerprintIsMismatchNotUnknown() {
        let pin = KnownHost(
            hostname: "h", port: 22, keyType: "ssh-ed25519",
            fingerprint: fingerprint, publicKeyLine: line
        )
        let decision = KnownHostsPolicy.decide(
            existing: pin,
            presentedType: "ssh-ed25519",
            presentedFingerprint: Vectors.ecdsaFingerprint,
            presentedLine: Vectors.ecdsaPublicLine
        )
        guard case .mismatch(let expected, _, let presented) = decision else {
            return XCTFail("expected .mismatch, got \(decision)")
        }
        XCTAssertEqual(expected.fingerprint, fingerprint)
        XCTAssertEqual(presented, Vectors.ecdsaFingerprint)
    }

    func testSameFingerprintUnderADifferentAlgorithmIsAMismatch() {
        // A server that "switches" algorithms while reusing a fingerprint is
        // not something to wave through.
        let pin = KnownHost(
            hostname: "h", port: 22, keyType: "ssh-ed25519",
            fingerprint: fingerprint, publicKeyLine: line
        )
        let decision = KnownHostsPolicy.decide(
            existing: pin,
            presentedType: "ecdsa-sha2-nistp256",
            presentedFingerprint: fingerprint,
            presentedLine: line
        )
        guard case .mismatch = decision else { return XCTFail("expected .mismatch, got \(decision)") }
    }
}

// MARK: - Vault

@MainActor
final class VaultTests: XCTestCase {
    private var directory: URL!
    private var keychain: InMemoryKeychain!
    private var vault: Vault!

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("VaultTests-\(UUID().uuidString)", isDirectory: true)
        keychain = InMemoryKeychain()
        vault = Vault(keychain: keychain, directory: directory)
    }

    override func tearDownWithError() throws {
        vault = nil
        keychain = nil
        if let directory { try? FileManager.default.removeItem(at: directory) }
        directory = nil
        try super.tearDownWithError()
    }

    // MARK: Identities

    func testGenerateStoresMetadataAndSecretSeparately() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)

        XCTAssertEqual(vault.identities.map(\.id), [identity.id])
        XCTAssertEqual(identity.keyType, .ed25519)
        XCTAssertTrue(identity.publicKeyLine.hasPrefix("ssh-ed25519 "))
        XCTAssertTrue(identity.fingerprint.hasPrefix("SHA256:"))
        XCTAssertTrue(keychain.contains(account: identity.keychainAccount))

        // The JSON on disk must not contain key material.
        let json = try String(contentsOf: directory.appendingPathComponent("identities.json"), encoding: .utf8)
        XCTAssertTrue(json.contains("laptop"))
        XCTAssertFalse(json.contains("PRIVATE KEY"))
    }

    func testPrivateKeyRoundTripsOutOfTheKeychain() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        let material = try vault.privateKey(for: identity)
        // Same key in, same key out: compare via the derived public half.
        XCTAssertEqual(material.publicKeyLine(comment: "laptop"), identity.publicKeyLine)
        XCTAssertEqual(material.fingerprint, identity.fingerprint)
    }

    func testDefaultKeychainOptionsAreDeviceOnlyAndNotSynchronizable() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        let options = try XCTUnwrap(keychain.storedOptions[identity.keychainAccount])
        XCTAssertTrue(isDeviceOnly(options.accessibility))
        XCTAssertFalse(options.synchronizable)
        XCTAssertFalse(options.requiresBiometrics)
        XCTAssertFalse(identity.syncsToICloud)
    }

    func testICloudToggleMarksTheItemSynchronizable() throws {
        let identity = try vault.generateIdentity(name: "synced", type: .ed25519, syncToICloud: true)
        let options = try XCTUnwrap(keychain.storedOptions[identity.keychainAccount])
        XCTAssertTrue(options.synchronizable)
        // ...ThisDeviceOnly cannot sync, so the accessibility has to widen.
        XCTAssertFalse(isDeviceOnly(options.accessibility))
        XCTAssertTrue(identity.syncsToICloud)
    }

    func testBiometricKeysAreNeverMarkedSynchronizable() throws {
        // iCloud Keychain cannot replicate a `.biometryCurrentSet` policy, so
        // honouring the toggle here would leave the metadata claiming a sync
        // that never happens.
        let identity = try vault.generateIdentity(
            name: "faceid",
            type: .ed25519,
            requiresBiometrics: true,
            syncToICloud: true
        )
        XCTAssertFalse(identity.syncsToICloud)
        XCTAssertTrue(identity.requiresBiometrics)
        let options = try XCTUnwrap(keychain.storedOptions[identity.keychainAccount])
        XCTAssertTrue(options.requiresBiometrics)
        XCTAssertFalse(options.synchronizable)
        XCTAssertTrue(isDeviceOnly(options.accessibility))
    }

    func testDeleteRemovesBothMetadataAndSecret() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        try vault.deleteIdentity(identity)

        XCTAssertTrue(vault.identities.isEmpty)
        XCTAssertFalse(keychain.contains(account: identity.keychainAccount))
        XCTAssertThrowsError(try vault.privateKey(for: identity)) { error in
            XCTAssertEqual(error as? VaultError, .identityNotFound)
        }
    }

    func testDeletingAnIdentityUnlinksHostsThatUsedIt() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        var host = Host(alias: "box", hostname: "10.0.0.5", username: "andy")
        host.identityID = identity.id
        vault.upsert(host)

        try vault.deleteIdentity(identity)
        XCTAssertNil(vault.hosts.first?.identityID)
    }

    func testDuplicateNamesAreRejectedCaseInsensitively() throws {
        _ = try vault.generateIdentity(name: "Laptop", type: .ed25519)
        XCTAssertThrowsError(try vault.generateIdentity(name: "laptop", type: .ed25519)) { error in
            XCTAssertEqual(error as? VaultError, .duplicateName("laptop"))
        }
        XCTAssertEqual(vault.identities.count, 1)
    }

    func testRenameRejectsClashesButAllowsRenamingToItself() throws {
        let a = try vault.generateIdentity(name: "a", type: .ed25519)
        _ = try vault.generateIdentity(name: "b", type: .ed25519)
        XCTAssertThrowsError(try vault.rename(a, to: "b"))
        let renamed = try vault.rename(a, to: "a")
        XCTAssertEqual(renamed.name, "a")
    }

    func testImportRoundTripsThroughExport() throws {
        let identity = try vault.importIdentity(name: "imported", pem: Vectors.ed25519PEM)
        XCTAssertEqual(identity.keyType, .ed25519)
        XCTAssertEqual(identity.fingerprint, Vectors.ed25519Fingerprint)
        // The original comment is preserved — it is what remote
        // authorized_keys files already contain.
        XCTAssertEqual(identity.publicKeyLine, Vectors.ed25519PublicLine)

        let exported = try vault.exportPrivateKey(for: identity)
        let (material, comment) = try OpenSSHKeyFile.parse(pem: exported)
        XCTAssertEqual(comment, "vector@ghostty")
        XCTAssertEqual(material.fingerprint, Vectors.ed25519Fingerprint)
    }

    func testFailedImportLeavesNothingBehind() {
        // Rewrite the kdfname in place (same base64 length, so the rest of the
        // container still decodes) to make the vector look protected.
        let pem = Vectors.ed25519PEM.replacingOccurrences(
            of: "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ",
            with: "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEYm9nbw"
        )
        XCTAssertThrowsError(try vault.importIdentity(name: "bad", pem: pem))
        XCTAssertTrue(vault.identities.isEmpty)
        XCTAssertEqual(keychain.count, 0)
    }

    func testBiometricCancellationSurfacesAsUserCancelled() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        keychain.simulateUserCancel = true
        XCTAssertThrowsError(try vault.privateKey(for: identity)) { error in
            XCTAssertEqual(error as? KeychainError, .userCancelled)
        }
    }

    func testSecureEnclaveIdentitiesNeverSyncToICloud() throws {
        try XCTSkipUnless(SSHPrivateKeyMaterial.isSecureEnclaveAvailable, "no Secure Enclave on this device")
        let identity = try vault.generateIdentity(
            name: "enclave",
            type: .secureEnclaveP256,
            syncToICloud: true   // requested, and must be refused
        )
        XCTAssertFalse(identity.syncsToICloud)
        let options = try XCTUnwrap(keychain.storedOptions[identity.keychainAccount])
        XCTAssertFalse(options.synchronizable)
        XCTAssertThrowsError(try vault.exportPrivateKey(for: identity)) { error in
            XCTAssertEqual(error as? VaultError, .cannotExportSecureEnclaveKey)
        }
    }

    func testSecureEnclaveIsRefusedGracefullyWhereUnavailable() throws {
        try XCTSkipIf(SSHPrivateKeyMaterial.isSecureEnclaveAvailable, "this device has a Secure Enclave")
        // The simulator path: a clear error, not a trap.
        XCTAssertThrowsError(
            try vault.generateIdentity(name: "enclave", type: .secureEnclaveP256)
        ) { error in
            XCTAssertEqual(error as? VaultError, .secureEnclaveUnavailable)
        }
        XCTAssertTrue(vault.identities.isEmpty)
    }

    // MARK: Hosts

    func testUpsertInsertsThenUpdatesInPlace() {
        var host = Host(alias: "box", hostname: "10.0.0.5", username: "andy")
        vault.upsert(host)
        XCTAssertEqual(vault.hosts.count, 1)

        host.alias = "renamed"
        vault.upsert(host)
        XCTAssertEqual(vault.hosts.count, 1)
        XCTAssertEqual(vault.hosts.first?.alias, "renamed")
    }

    func testHostPasswordIsStoredReadBackAndCleared() throws {
        let host = Host(alias: "box", hostname: "10.0.0.5", username: "andy")
        vault.upsert(host)

        XCTAssertNil(try vault.password(for: host))
        try vault.setPassword("hunter2", for: host)
        XCTAssertEqual(try vault.password(for: host), "hunter2")
        XCTAssertEqual(vault.hosts.first?.usesPassword, true)

        try vault.setPassword(nil, for: host)
        XCTAssertNil(try vault.password(for: host))
        XCTAssertEqual(vault.hosts.first?.usesPassword, false)
    }

    func testDeletingAHostClearsItsStoredPassword() throws {
        let host = Host(alias: "box", hostname: "10.0.0.5", username: "andy")
        vault.upsert(host)
        try vault.setPassword("hunter2", for: host)

        vault.deleteHost(host)
        XCTAssertTrue(vault.hosts.isEmpty)
        XCTAssertFalse(keychain.contains(account: host.keychainPasswordAccount))
    }

    // MARK: Known hosts

    func testTOFULifecycle() throws {
        let unknown = vault.verify(
            hostname: "10.0.0.81", port: 22,
            presentedType: "ssh-ed25519",
            presentedFingerprint: Vectors.ed25519Fingerprint,
            presentedLine: Vectors.ed25519PublicLine
        )
        guard case .unknown = unknown else { return XCTFail("expected .unknown, got \(unknown)") }

        _ = try vault.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519",
            fingerprint: Vectors.ed25519Fingerprint,
            publicKeyLine: Vectors.ed25519PublicLine
        )

        let trusted = vault.verify(
            hostname: "10.0.0.81", port: 22,
            presentedType: "ssh-ed25519",
            presentedFingerprint: Vectors.ed25519Fingerprint,
            presentedLine: Vectors.ed25519PublicLine
        )
        guard case .trusted = trusted else { return XCTFail("expected .trusted, got \(trusted)") }
    }

    func testMismatchIsNeverSilentlyUpgraded() throws {
        _ = try vault.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519",
            fingerprint: Vectors.ed25519Fingerprint,
            publicKeyLine: Vectors.ed25519PublicLine
        )

        // A different key on the same endpoint: the dangerous case.
        for _ in 0..<3 {
            let decision = vault.verify(
                hostname: "10.0.0.81", port: 22,
                presentedType: "ecdsa-sha2-nistp256",
                presentedFingerprint: Vectors.ecdsaFingerprint,
                presentedLine: Vectors.ecdsaPublicLine
            )
            guard case .mismatch = decision else {
                return XCTFail("expected .mismatch, got \(decision)")
            }
        }
        // Verifying must not have rewritten the pin.
        XCTAssertEqual(vault.knownHosts.count, 1)
        XCTAssertEqual(vault.knownHosts.first?.fingerprint, Vectors.ed25519Fingerprint)
    }

    func testPinsAreScopedToHostnameAndPort() throws {
        _ = try vault.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519",
            fingerprint: Vectors.ed25519Fingerprint,
            publicKeyLine: Vectors.ed25519PublicLine
        )
        XCTAssertNotNil(vault.knownHost(hostname: "10.0.0.81", port: 22))
        // Same host, different port is a different endpoint — as in OpenSSH.
        XCTAssertNil(vault.knownHost(hostname: "10.0.0.81", port: 2222))
    }

    func testForgetRemovesThePin() throws {
        let pin = try vault.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519",
            fingerprint: Vectors.ed25519Fingerprint,
            publicKeyLine: Vectors.ed25519PublicLine
        )
        vault.forget(pin)
        XCTAssertTrue(vault.knownHosts.isEmpty)
    }

    // MARK: Persistence

    func testASecondVaultOverTheSameDirectorySeesEverything() throws {
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        vault.upsert(Host(alias: "box", hostname: "10.0.0.5", username: "andy"))
        _ = try vault.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519",
            fingerprint: Vectors.ed25519Fingerprint,
            publicKeyLine: Vectors.ed25519PublicLine
        )

        let reopened = Vault(keychain: keychain, directory: directory)
        XCTAssertEqual(reopened.identities.map(\.id), [identity.id])
        XCTAssertEqual(reopened.identities.first?.fingerprint, identity.fingerprint)
        XCTAssertEqual(reopened.hosts.map(\.alias), ["box"])
        XCTAssertEqual(reopened.knownHosts.map(\.id), ["10.0.0.81:22"])
        // And the secret is still reachable through the reopened vault.
        let material = try reopened.privateKey(for: XCTUnwrap(reopened.identities.first))
        XCTAssertEqual(material.fingerprint, identity.fingerprint)
    }

    func testCorruptMetadataIsSetAsideRatherThanLost() throws {
        vault.upsert(Host(alias: "box", hostname: "10.0.0.5", username: "andy"))
        let hostsFile = directory.appendingPathComponent("hosts.json")
        try Data("{ not json".utf8).write(to: hostsFile)

        let reopened = Vault(keychain: keychain, directory: directory)
        XCTAssertTrue(reopened.hosts.isEmpty)
        XCTAssertNotNil(reopened.lastError)

        let salvaged = try FileManager.default
            .contentsOfDirectory(atPath: directory.path)
            .filter { $0.contains("hosts.json.corrupt-") }
        XCTAssertEqual(salvaged.count, 1, "the unreadable file must be kept, not deleted")
    }

    func testPersistedJSONIsSortedAndUsesISO8601Dates() throws {
        _ = try vault.generateIdentity(name: "laptop", type: .ed25519)
        let json = try String(contentsOf: directory.appendingPathComponent("identities.json"), encoding: .utf8)
        // Sorted keys: "createdAt" precedes "fingerprint" precedes "id".
        let created = try XCTUnwrap(json.range(of: "\"createdAt\""))
        let fingerprint = try XCTUnwrap(json.range(of: "\"fingerprint\""))
        XCTAssertTrue(created.lowerBound < fingerprint.lowerBound)
        XCTAssertTrue(json.contains("T"), "ISO8601 timestamps, not epoch doubles")
    }

    // MARK: Preview

    func testPreviewVaultIsUsableAndIsolated() {
        let preview = Vault.preview()
        XCTAssertFalse(preview.hosts.isEmpty)
        XCTAssertTrue(preview.identities.isEmpty)
    }

    // MARK: Helpers

    /// `KeychainAccessibility` is intentionally not `Equatable` in the
    /// contract, so match on the case instead of widening it for tests.
    private func isDeviceOnly(_ accessibility: KeychainAccessibility) -> Bool {
        if case .whenUnlockedThisDeviceOnly = accessibility { return true }
        return false
    }
}
