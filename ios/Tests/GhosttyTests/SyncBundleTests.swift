import Foundation
import XCTest
@testable import Ghostty

// MARK: - Fixtures

/// A snapshot with everything that can go wrong in it: an exportable key, a
/// key that cannot leave the device, several hosts and several pins.
///
/// Dates are whole seconds since the epoch on purpose. The bundle encodes
/// dates as ISO-8601 without fractional seconds (the same convention `Vault`
/// uses on disk), so a fixture built from `Date()` would fail an equality
/// check for a reason that has nothing to do with the code under test.
private enum Fixtures {
    static let timestamp = Date(timeIntervalSince1970: 1_700_000_000)  // 2023-11-14T22:13:20Z
    static let created = Date(timeIntervalSince1970: 1_699_000_000)

    static let laptopKeyID = UUID(uuidString: "5B4E4A2C-0000-4000-8000-000000000001") ?? UUID()
    static let enclaveKeyID = UUID(uuidString: "5B4E4A2C-0000-4000-8000-000000000002") ?? UUID()

    static let pem = """
        -----BEGIN OPENSSH PRIVATE KEY-----
        b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
        QyNTUxOQAAACCKXEzxWfVPpLsS9xHen26EKafsrDsZXzjm3i/RtvZJsw==
        -----END OPENSSH PRIVATE KEY-----
        """

    static let publicLine =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIpcTPFZ9U+kuxL3Ed6fboQpp+ysOxlfOObeL9G29kmz laptop"

    static var laptopIdentity: SyncedIdentity {
        SyncedIdentity(
            identity: Identity(
                id: laptopKeyID,
                name: "laptop key",
                keyType: .ed25519,
                publicKeyLine: publicLine,
                fingerprint: "SHA256:qfGWJiYsIIwuLiaak59D5dlntQK/4imFltRQZeG5JrU",
                createdAt: created,
                isSecureEnclave: false,
                requiresBiometrics: false,
                syncsToICloud: false
            ),
            privateKeyPEM: pem,
            deviceOnly: false
        )
    }

    /// The one that must never cross a sync boundary.
    static var enclaveIdentity: SyncedIdentity {
        SyncedIdentity(
            identity: Identity(
                id: enclaveKeyID,
                name: "phone enclave key",
                keyType: .secureEnclaveP256,
                publicKeyLine: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= phone",
                fingerprint: "SHA256:0000000000000000000000000000000000000000000",
                createdAt: created,
                isSecureEnclave: true,
                requiresBiometrics: true,
                syncsToICloud: false
            ),
            privateKeyPEM: nil,
            deviceOnly: true
        )
    }

    /// `idSuffix` is spelled out rather than derived from the alias: a hashed
    /// id would be stable within one process but could collide, and a test that
    /// fails one run in a thousand is worse than no test.
    static func host(_ alias: String, _ hostname: String, port: Int = 22, idSuffix: Int = 1) -> Host {
        Host(
            id: UUID(uuidString: "A0000000-0000-4000-8000-\(String(format: "%012d", idSuffix))") ?? UUID(),
            alias: alias,
            hostname: hostname,
            port: port,
            username: "andy",
            group: "Homelab",
            tags: ["lan"],
            notes: "seeded by tests"
        )
    }

    static func knownHost(_ hostname: String) -> KnownHost {
        KnownHost(
            hostname: hostname,
            port: 22,
            keyType: "ssh-ed25519",
            fingerprint: "SHA256:\(hostname)",
            publicKeyLine: "ssh-ed25519 AAAA\(hostname)",
            firstSeen: created
        )
    }

    /// 2 identities (one device-only), 3 hosts, 2 known hosts.
    static var snapshot: VaultSnapshot {
        VaultSnapshot(
            identities: [laptopIdentity, enclaveIdentity],
            hosts: [
                host("pi-a", "10.0.0.41", idSuffix: 1),
                host("pi-b", "10.0.0.42", idSuffix: 2),
                host("noether", "10.0.0.81", port: 2222, idSuffix: 3),
            ],
            knownHosts: [knownHost("10.0.0.41"), knownHost("10.0.0.81")],
            updatedAt: timestamp
        )
    }
}

// MARK: - Bundle format

final class EncryptedBundleTests: XCTestCase {
    private let passphrase = "correct horse battery staple"

    // MARK: Round trip

    func testExportImportRoundTripsEverything() throws {
        let original = Fixtures.snapshot
        let data = try EncryptedBundle.export(original, passphrase: passphrase)
        let restored = try EncryptedBundle.import(data, passphrase: passphrase)

        XCTAssertEqual(restored, original)
        // Spelled out as well as compared wholesale: an Equatable failure on a
        // struct this size tells you nothing about which half broke.
        XCTAssertEqual(restored.identities.count, 2)
        XCTAssertEqual(restored.hosts.count, 3)
        XCTAssertEqual(restored.knownHosts.count, 2)
        XCTAssertEqual(restored.updatedAt, Fixtures.timestamp)

        // The device-only key still travels as metadata — with no private half
        // and still flagged — so the other device can show it greyed out
        // rather than silently losing the row the hosts point at.
        let enclave = restored.identities.first { $0.identity.id == Fixtures.enclaveKeyID }
        XCTAssertEqual(enclave?.deviceOnly, true)
        XCTAssertNil(enclave?.privateKeyPEM)

        let laptop = restored.identities.first { $0.identity.id == Fixtures.laptopKeyID }
        XCTAssertEqual(laptop?.privateKeyPEM, Fixtures.pem)
        XCTAssertEqual(laptop?.identity.createdAt, Fixtures.created)
    }

    func testBundleBeginsWithMagicAndVersion() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)
        let bytes = [UInt8](data)

        XCTAssertEqual(Array(bytes[0..<8]), EncryptedBundle.magic)
        XCTAssertEqual(bytes[8], EncryptedBundle.formatVersion)
        XCTAssertEqual(bytes[9], EncryptedBundleKDF.pbkdf2HMACSHA256.rawValue)

        let iterations = UInt32(bytes[10]) << 24 | UInt32(bytes[11]) << 16
            | UInt32(bytes[12]) << 8 | UInt32(bytes[13])
        XCTAssertEqual(iterations, EncryptedBundleKDF.pbkdf2Iterations)
        XCTAssertGreaterThanOrEqual(iterations, 600_000, "OWASP's floor for PBKDF2-HMAC-SHA256")

        XCTAssertEqual(Int(bytes[14]), EncryptedBundle.saltLength)
        XCTAssertEqual(Int(bytes[15]), EncryptedBundle.nonceLength)

        let declared = Int(
            UInt32(bytes[16]) << 24 | UInt32(bytes[17]) << 16 | UInt32(bytes[18]) << 8 | UInt32(bytes[19])
        )
        XCTAssertEqual(
            data.count,
            EncryptedBundle.headerLength + EncryptedBundle.saltLength + EncryptedBundle.nonceLength
                + declared + EncryptedBundle.tagLength,
            "the declared ciphertext length must account for the whole file"
        )
    }

    // MARK: Wrong passphrase

    func testWrongPassphraseThrowsTheSpecificError() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)

        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(data, passphrase: "correct horse battery stapl")
        }

        // The message has to name the two things the user can act on, not
        // repeat CryptoKit's "authenticationFailure".
        let message = EncryptedBundleError.wrongPassphraseOrTampered.localizedDescription
        XCTAssertTrue(message.contains("passphrase is incorrect"), message)
        XCTAssertTrue(message.contains("newer version"), message)
    }

    func testEmptyPassphraseIsRejectedOnBothSides() {
        assertThrows(.emptyPassphrase) {
            _ = try EncryptedBundle.export(Fixtures.snapshot, passphrase: "")
        }
        assertThrows(.emptyPassphrase) {
            _ = try EncryptedBundle.import(Data([0, 1, 2]), passphrase: "")
        }
    }

    // MARK: Damaged files

    func testTruncatedBundleThrows() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)

        // Cut inside the ciphertext: header and magic are intact, so this can
        // only be caught by the length check.
        assertThrows(.truncated) {
            _ = try EncryptedBundle.import(data.prefix(data.count / 2), passphrase: self.passphrase)
        }
        // Cut inside the header itself.
        assertThrows(.truncated) {
            _ = try EncryptedBundle.import(data.prefix(16), passphrase: self.passphrase)
        }
        // One byte short of complete — the case a length-less format would
        // have blamed on the passphrase.
        assertThrows(.truncated) {
            _ = try EncryptedBundle.import(data.prefix(data.count - 1), passphrase: self.passphrase)
        }
        // Cut before even the magic is complete — indistinguishable from a
        // file that was never a bundle.
        assertThrows(.notABundle) {
            _ = try EncryptedBundle.import(data.prefix(4), passphrase: self.passphrase)
        }
    }

    func testCorruptedHeaderThrowsRatherThanDecrypting() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)

        assertThrows(.notABundle) {
            _ = try EncryptedBundle.import(Self.flipping(byte: 2, of: data), passphrase: self.passphrase)
        }

        // Version byte: rejected by the parser with a message that tells the
        // user to update, not by the tag check.
        var wrongVersion = [UInt8](data)
        wrongVersion[8] = 99
        assertThrows(.unsupportedVersion(99)) {
            _ = try EncryptedBundle.import(Data(wrongVersion), passphrase: self.passphrase)
        }

        var wrongKDF = [UInt8](data)
        wrongKDF[9] = 7
        assertThrows(.unsupportedKDF(7)) {
            _ = try EncryptedBundle.import(Data(wrongKDF), passphrase: self.passphrase)
        }

        // Iteration count: steers key derivation *and* is authenticated data,
        // so an edit fails rather than deriving a different key and producing
        // nonsense.
        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(Self.flipping(byte: 11, of: data), passphrase: self.passphrase)
        }

        // Declared salt length must match what version 1 fixes it at; a
        // crafted file does not get to redirect our own slicing.
        var wrongSaltLength = [UInt8](data)
        wrongSaltLength[14] = 32
        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(Data(wrongSaltLength), passphrase: self.passphrase)
        }
    }

    func testFlippedCiphertextByteThrows() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)
        // Well inside the ciphertext: past header (20) + salt (16) + nonce (12).
        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(Self.flipping(byte: 64, of: data), passphrase: self.passphrase)
        }
        // And the authentication tag at the very end.
        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(
                Self.flipping(byte: data.count - 1, of: data),
                passphrase: self.passphrase
            )
        }
    }

    func testFlippedSaltByteThrows() throws {
        let data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)
        // First byte of the salt: a different salt derives a different key.
        assertThrows(.wrongPassphraseOrTampered) {
            _ = try EncryptedBundle.import(Self.flipping(byte: 24, of: data), passphrase: self.passphrase)
        }
    }

    func testTrailingBytesAreRejected() throws {
        var data = try EncryptedBundle.export(Fixtures.snapshot, passphrase: passphrase)
        data.append(contentsOf: [0x00, 0x01])
        XCTAssertThrowsError(try EncryptedBundle.import(data, passphrase: passphrase)) { error in
            guard case .malformedContents = error as? EncryptedBundleError else {
                return XCTFail("expected malformedContents, got \(error)")
            }
        }
    }

    // MARK: Not a bundle at all

    func testRandomBytesAreRejectedAsNotABundle() {
        var random = Data(count: 512)
        for index in random.indices { random[index] = UInt8.random(in: 0...255) }
        // Guard against the 1-in-2^64 fluke that would make this flaky.
        random.replaceSubrange(0..<8, with: Data("NOTGHSTY".utf8))

        assertThrows(.notABundle) {
            _ = try EncryptedBundle.import(random, passphrase: self.passphrase)
        }
    }

    func testJSONFileIsRejectedAsNotABundle() {
        // The likeliest wrong pick: a plain export from some other tool.
        let json = Data(#"{"identities":[],"hosts":[],"knownHosts":[],"updatedAt":"2026-01-01T00:00:00Z"}"#.utf8)
        assertThrows(.notABundle) {
            _ = try EncryptedBundle.import(json, passphrase: self.passphrase)
        }
        assertThrows(.notABundle) {
            _ = try EncryptedBundle.import(Data(), passphrase: self.passphrase)
        }
    }

    func testNotABundleMessageNamesGhostty() {
        let message = EncryptedBundleError.notABundle.localizedDescription
        XCTAssertTrue(message.contains("Ghostty bundle"), message)
    }

    // MARK: Randomness

    func testTwoExportsOfTheSameSnapshotDifferButBothImport() throws {
        let snapshot = Fixtures.snapshot
        let first = try EncryptedBundle.export(snapshot, passphrase: passphrase)
        let second = try EncryptedBundle.export(snapshot, passphrase: passphrase)

        XCTAssertNotEqual(first, second, "salt and nonce must be fresh on every export")

        let saltRange = EncryptedBundle.headerLength..<(EncryptedBundle.headerLength + EncryptedBundle.saltLength)
        XCTAssertNotEqual(first[saltRange], second[saltRange], "salt must differ")

        let nonceRange = saltRange.upperBound..<(saltRange.upperBound + EncryptedBundle.nonceLength)
        XCTAssertNotEqual(first[nonceRange], second[nonceRange], "GCM nonce reuse under one key is fatal")

        XCTAssertEqual(try EncryptedBundle.import(first, passphrase: passphrase), snapshot)
        XCTAssertEqual(try EncryptedBundle.import(second, passphrase: passphrase), snapshot)
    }

    func testEmptySnapshotRoundTrips() throws {
        let data = try EncryptedBundle.export(.empty, passphrase: passphrase)
        XCTAssertEqual(try EncryptedBundle.import(data, passphrase: passphrase), .empty)
    }

    // MARK: Helpers

    private static func flipping(byte index: Int, of data: Data) -> Data {
        var bytes = [UInt8](data)
        guard bytes.indices.contains(index) else { return data }
        bytes[index] ^= 0xFF
        return Data(bytes)
    }

    private func assertThrows(
        _ expected: EncryptedBundleError,
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () throws -> Void
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual(
                error as? EncryptedBundleError,
                expected,
                "got \(error) instead",
                file: file,
                line: line
            )
        }
    }
}

// MARK: - Bundle provider

@MainActor
final class EncryptedBundleProviderTests: XCTestCase {
    private var directory = FileManager.default.temporaryDirectory

    override func setUpWithError() throws {
        try super.setUpWithError()
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("bundle-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
        try super.tearDownWithError()
    }

    func testPushWritesAFileAndPullReadsItBack() async throws {
        let keychain = InMemoryKeychain()
        let provider = EncryptedBundleProvider(keychain: keychain, directory: directory)
        try await provider.connect(.bundlePassphrase("a long enough passphrase"))

        let snapshot = Fixtures.snapshot
        try await provider.push(snapshot)

        let exported = try XCTUnwrap(provider.lastExportedFileURL)
        XCTAssertEqual(exported.pathExtension, EncryptedBundle.fileExtension)
        XCTAssertTrue(exported.lastPathComponent.hasPrefix("Ghostty-vault-"))
        XCTAssertFalse(exported.lastPathComponent.contains(":"), "colons break too many things downstream")
        XCTAssertTrue(FileManager.default.fileExists(atPath: exported.path))

        // Nothing queued yet: a sync run with no picked file is a no-op, not
        // an error.
        let nothing = try await provider.pull()
        XCTAssertNil(nothing)

        provider.pendingImportFileURL = exported
        let restored = try await provider.pull()
        XCTAssertEqual(restored, snapshot)
        // Consumed, so a later background sync does not re-import silently.
        XCTAssertNil(provider.pendingImportFileURL)
    }

    func testPassphraseGoesToTheKeychainDeviceOnly() async throws {
        let keychain = InMemoryKeychain()
        let provider = EncryptedBundleProvider(keychain: keychain, directory: directory)
        try await provider.connect(.bundlePassphrase("a long enough passphrase"))

        XCTAssertTrue(keychain.contains(account: "sync.bundle.passphrase"))
        let options = try XCTUnwrap(keychain.storedOptions["sync.bundle.passphrase"])
        XCTAssertFalse(options.synchronizable, "the passphrase must not follow the file to other devices")

        await provider.disconnect()
        XCTAssertFalse(keychain.contains(account: "sync.bundle.passphrase"))
        XCTAssertFalse(provider.status.isConnected)
    }

    func testShortAndWrongShapedCredentialsAreRejected() async throws {
        let provider = EncryptedBundleProvider(keychain: InMemoryKeychain(), directory: directory)

        await assertThrowsSyncError { try await provider.connect(.bundlePassphrase("short")) }
        await assertThrowsSyncError { try await provider.connect(.none) }
        XCTAssertFalse(provider.status.isConnected)
    }

    func testPushBeforeConnectIsNotConnected() async {
        let provider = EncryptedBundleProvider(keychain: InMemoryKeychain(), directory: directory)
        await assertThrowsSyncError { try await provider.push(Fixtures.snapshot) }
    }

    func testWrongPassphraseOnImportSurfacesTheBundleError() async throws {
        let writer = EncryptedBundleProvider(keychain: InMemoryKeychain(), directory: directory)
        try await writer.connect(.bundlePassphrase("the first passphrase"))
        try await writer.push(Fixtures.snapshot)
        let exported = try XCTUnwrap(writer.lastExportedFileURL)

        let reader = EncryptedBundleProvider(keychain: InMemoryKeychain(), directory: directory)
        try await reader.connect(.bundlePassphrase("a different passphrase"))
        reader.pendingImportFileURL = exported

        do {
            _ = try await reader.pull()
            XCTFail("expected a wrong-passphrase error")
        } catch let error as EncryptedBundleError {
            XCTAssertEqual(error, .wrongPassphraseOrTampered)
        }
        XCTAssertTrue(reader.status.lastResultWasError)
    }

    private func assertThrowsSyncError(
        file: StaticString = #filePath,
        line: UInt = #line,
        _ body: () async throws -> Void
    ) async {
        do {
            try await body()
            XCTFail("expected a VaultSyncError", file: file, line: line)
        } catch is VaultSyncError {
            // expected
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)", file: file, line: line)
        }
    }
}

// MARK: - 1Password Connect transport stub

/// Records every request and answers from a table keyed by "METHOD /path".
///
/// No `URLProtocol` subclass and no local server: the provider's only contact
/// with the network is `OnePasswordConnectTransport`, so that is the seam.
private final class StubConnectTransport: OnePasswordConnectTransport {
    struct Recorded {
        let method: String
        let path: String
        let authorization: String?
        let body: Data?
    }

    enum StubError: Error {
        case malformedRequest
        case noRoute(String)
    }

    private(set) var recorded: [Recorded] = []
    /// "GET /v1/vaults" -> (statusCode, body)
    var responses: [String: (Int, Data)] = [:]
    /// Answer for anything not in the table. Nil makes an unexpected request a
    /// test failure rather than a silent 200.
    var fallback: (Int, Data)?

    func route(_ key: String, status: Int = 200, json: String) {
        responses[key] = (status, Data(json.utf8))
    }

    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        guard let url = request.url else { throw StubError.malformedRequest }
        let method = request.httpMethod ?? "GET"
        // URL.path percent-decodes, so a segment the provider escaped comes
        // back in its original form here.
        let key = "\(method) \(url.path)"

        recorded.append(
            Recorded(
                method: method,
                path: url.path,
                authorization: request.value(forHTTPHeaderField: "Authorization"),
                body: request.httpBody
            )
        )

        guard let (status, body) = responses[key] ?? fallback else {
            throw StubError.noRoute(key)
        }
        guard let http = HTTPURLResponse(url: url, statusCode: status, httpVersion: nil, headerFields: nil) else {
            throw StubError.malformedRequest
        }
        return (body, http)
    }

    func requests(_ method: String) -> [Recorded] { recorded.filter { $0.method == method } }
}

// MARK: - 1Password Connect mapping

@MainActor
final class OnePasswordConnectMappingTests: XCTestCase {
    private let serverURL = URL(string: "https://connect.lan") ?? URL(fileURLWithPath: "/")
    private let token = "eyJhbGciOiJFUzI1NiJ9.stub-connect-token"
    private let vaultID = "abc123vault"

    // MARK: Fixture JSON, as a Connect server would send it

    /// Escapes a value so it can be embedded as a JSON *string*, which is how
    /// 1Password carries both a PEM and our metadata note. Newlines matter as
    /// much as quotes here: a PEM is multi-line, and a raw newline inside a
    /// JSON string is a syntax error.
    private func embedded(_ json: String) -> String {
        json
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\t", with: "\\t")
    }

    private var identityMetadataJSON: String {
        """
        {"createdAt":"2023-11-03T08:26:40Z",\
        "fingerprint":"SHA256:qfGWJiYsIIwuLiaak59D5dlntQK/4imFltRQZeG5JrU",\
        "id":"5B4E4A2C-0000-4000-8000-000000000001",\
        "isSecureEnclave":false,\
        "keyType":"ed25519",\
        "name":"laptop key",\
        "publicKeyLine":"\(embedded(Fixtures.publicLine))",\
        "requiresBiometrics":false,\
        "syncsToICloud":false}
        """
    }

    /// The metadata as it actually travels: wrapped in a schema envelope, so a
    /// future format change is detectable rather than silently misread.
    private var identityNoteJSON: String {
        #"{"schema":"ghostty.identity.v1","identity":"# + identityMetadataJSON + "}"
    }

    private var sshKeyItemJSON: String {
        """
        {
          "id": "sshitem1",
          "title": "laptop key",
          "category": "SSH_KEY",
          "vault": { "id": "\(vaultID)" },
          "tags": ["ghostty-ios"],
          "fields": [
            { "id": "private_key", "label": "private key", "type": "SSHKEY",
              "value": "\(embedded(Fixtures.pem))" },
            { "id": "public_key", "label": "public key", "type": "STRING",
              "value": "\(embedded(Fixtures.publicLine))" },
            { "id": "fingerprint", "label": "fingerprint", "type": "STRING",
              "value": "SHA256:qfGWJiYsIIwuLiaak59D5dlntQK/4imFltRQZeG5JrU" },
            { "id": "notesPlain", "label": "notesPlain", "type": "STRING", "purpose": "NOTES",
              "value": "\(embedded(identityNoteJSON))" }
          ]
        }
        """
    }

    private var hostsNoteJSON: String {
        """
        {"schema":"ghostty.hosts.v1",\
        "hosts":[\
        {"alias":"pi-a","group":"Homelab","hostname":"10.0.0.41",\
        "id":"A0000000-0000-4000-8000-000000000011","notes":"","port":22,\
        "tags":["lan"],"term":"xterm-256color","usesPassword":false,"username":"andy"},\
        {"alias":"noether","group":"Homelab","hostname":"10.0.0.81",\
        "id":"A0000000-0000-4000-8000-000000000012","notes":"","port":2222,\
        "tags":[],"term":"xterm-256color","usesPassword":false,"username":"andy"}],\
        "knownHosts":[\
        {"firstSeen":"2023-11-03T08:26:40Z","fingerprint":"SHA256:pia",\
        "hostname":"10.0.0.41","id":"10.0.0.41:22","keyType":"ssh-ed25519",\
        "port":22,"publicKeyLine":"ssh-ed25519 AAAApia"}],\
        "updatedAt":"2023-11-14T22:13:20Z"}
        """
    }

    private var secureNoteItemJSON: String {
        """
        {
          "id": "notesitem1",
          "title": "Ghostty iOS hosts",
          "category": "SECURE_NOTE",
          "vault": { "id": "\(vaultID)" },
          "tags": ["ghostty-ios"],
          "fields": [
            { "id": "notesPlain", "label": "notesPlain", "type": "STRING", "purpose": "NOTES",
              "value": "\(embedded(hostsNoteJSON))" }
          ]
        }
        """
    }

    // MARK: Setup

    private func connectedProvider(
        _ transport: StubConnectTransport,
        vaultName: String? = "Personal"
    ) async throws -> OnePasswordConnectProvider {
        transport.route("GET /heartbeat", json: ".")
        transport.route("GET /v1/vaults", json: #"[{"id":"abc123vault","name":"Personal"}]"#)

        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain(), transport: transport)
        try await provider.connect(
            .onePasswordConnect(serverURL: serverURL, token: token, vaultName: vaultName)
        )
        return provider
    }

    // MARK: Connect

    func testConnectResolvesTheVaultAndLabelsTheAccount() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        XCTAssertTrue(provider.status.isConnected)
        XCTAssertEqual(provider.status.accountLabel, "Personal · connect.lan")
        // Heartbeat first, so "server unreachable" and "token rejected" are
        // distinguishable.
        XCTAssertEqual(transport.recorded.first?.path, "/heartbeat")
        XCTAssertEqual(transport.recorded.first?.authorization, "Bearer \(token)")
    }

    func testConnectRejectsAnUnknownVaultName() async {
        let transport = StubConnectTransport()
        transport.route("GET /heartbeat", json: ".")
        transport.route("GET /v1/vaults", json: #"[{"id":"abc123vault","name":"Personal"}]"#)

        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain(), transport: transport)
        do {
            try await provider.connect(
                .onePasswordConnect(serverURL: serverURL, token: token, vaultName: "Work")
            )
            XCTFail("expected an error naming the vaults the token can see")
        } catch let error as VaultSyncError {
            XCTAssertTrue(error.localizedDescription.contains("Personal"), error.localizedDescription)
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)")
        }
        XCTAssertFalse(provider.status.isConnected)
    }

    func testConnectRejectsCredentialsForAnotherProvider() async {
        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain(), transport: StubConnectTransport())
        do {
            try await provider.connect(.bundlePassphrase("nope"))
            XCTFail("expected unsupportedCredentials")
        } catch let error as VaultSyncError {
            XCTAssertEqual(error, .unsupportedCredentials(
                "1Password Connect needs your Connect server's URL and a Connect token."
            ))
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)")
        }
    }

    func testConnectMapsA401ToAnActionableMessage() async {
        let transport = StubConnectTransport()
        transport.route("GET /heartbeat", status: 401, json: #"{"message":"nope"}"#)

        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain(), transport: transport)
        do {
            try await provider.connect(.onePasswordConnect(serverURL: serverURL, token: token, vaultName: nil))
            XCTFail("expected a token error")
        } catch let error as VaultSyncError {
            XCTAssertTrue(error.localizedDescription.contains("token"), error.localizedDescription)
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)")
        }
    }

    // MARK: Pull

    func testPullMapsSSHKeyAndSecureNoteItemsIntoASnapshot() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: """
                [
                  {"id":"sshitem1","title":"laptop key","category":"SSH_KEY","tags":["ghostty-ios"]},
                  {"id":"notesitem1","title":"Ghostty iOS hosts","category":"SECURE_NOTE","tags":["ghostty-ios"]}
                ]
                """
        )
        transport.route("GET /v1/vaults/\(vaultID)/items/sshitem1", json: sshKeyItemJSON)
        transport.route("GET /v1/vaults/\(vaultID)/items/notesitem1", json: secureNoteItemJSON)

        let pulled = try await provider.pull()
        let snapshot = try XCTUnwrap(pulled)

        XCTAssertEqual(snapshot.identities.count, 1)
        let identity = try XCTUnwrap(snapshot.identities.first)
        XCTAssertEqual(identity.identity.id, Fixtures.laptopKeyID)
        XCTAssertEqual(identity.identity.name, "laptop key")
        XCTAssertEqual(identity.identity.keyType, .ed25519)
        XCTAssertEqual(identity.identity.publicKeyLine, Fixtures.publicLine)
        XCTAssertEqual(identity.identity.createdAt, Fixtures.created)
        XCTAssertEqual(identity.privateKeyPEM, Fixtures.pem)
        XCTAssertFalse(identity.deviceOnly)

        XCTAssertEqual(snapshot.hosts.count, 2)
        XCTAssertEqual(snapshot.hosts.map(\.alias), ["pi-a", "noether"])
        XCTAssertEqual(snapshot.hosts.last?.port, 2222)
        XCTAssertEqual(snapshot.knownHosts.count, 1)
        XCTAssertEqual(snapshot.knownHosts.first?.id, "10.0.0.41:22")
        // The snapshot clock comes from the note, not from now(): "newest
        // wins" must not be biased toward whichever side pulled last.
        XCTAssertEqual(snapshot.updatedAt, Fixtures.timestamp)
    }

    func testPullReturnsNilWhenNeitherItemExists() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)
        // A vault with somebody else's login in it, and nothing of ours.
        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: #"[{"id":"other","title":"Email","category":"LOGIN"}]"#
        )

        let snapshot = try await provider.pull()
        XCTAssertNil(snapshot, "nil means 'no remote state', which stops the engine merging against empty")
    }

    func testPullSynthesisesMetadataForAKeyCreatedInTheOnePasswordApp() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: #"[{"id":"handmade","title":"work laptop","category":"SSH_KEY"}]"#
        )
        transport.route(
            "GET /v1/vaults/\(vaultID)/items/handmade",
            json: """
                {
                  "id": "handmade",
                  "title": "work laptop",
                  "category": "SSH_KEY",
                  "fields": [
                    { "id": "private_key", "type": "SSHKEY", "value": "\(embedded(Fixtures.pem))" },
                    { "id": "public_key", "type": "STRING", "value": "\(embedded(Fixtures.publicLine))" }
                  ]
                }
                """
        )

        let pulled = try await provider.pull()
        let snapshot = try XCTUnwrap(pulled)
        let identity = try XCTUnwrap(snapshot.identities.first)
        XCTAssertEqual(identity.identity.name, "work laptop")
        XCTAssertEqual(identity.identity.keyType, .ed25519)
        // Derived from the item id, so a second pull does not mint a new
        // identity and orphan the hosts pointing at the first one.
        XCTAssertEqual(identity.identity.id, OnePasswordConnectProvider.stableUUID(from: "handmade"))
        XCTAssertFalse(identity.identity.fingerprint.isEmpty, "fingerprint is derived when absent")
    }

    func testPullSkipsAnItemWithNoPrivateKey() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: #"[{"id":"broken","title":"public only","category":"SSH_KEY"}]"#
        )
        transport.route(
            "GET /v1/vaults/\(vaultID)/items/broken",
            json: """
                {"id":"broken","title":"public only","category":"SSH_KEY",
                 "fields":[{"id":"public_key","type":"STRING","value":"\(embedded(Fixtures.publicLine))"}]}
                """
        )

        let pulled = try await provider.pull()
        let snapshot = try XCTUnwrap(pulled)
        XCTAssertTrue(snapshot.identities.isEmpty, "an identity we cannot authenticate with is worse than none")
        XCTAssertEqual(provider.status.lastResult?.contains("skipped"), true)
    }

    // MARK: Push

    func testPushSkipsDeviceOnlyIdentitiesAndSaysSo() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route("GET /v1/vaults/\(vaultID)/items", json: "[]")
        transport.route("POST /v1/vaults/\(vaultID)/items", json: "{}")

        let secondEnclave = SyncedIdentity(
            identity: Identity(
                id: UUID(uuidString: "5B4E4A2C-0000-4000-8000-000000000003") ?? UUID(),
                name: "ipad enclave key",
                keyType: .secureEnclaveP256,
                publicKeyLine: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= ipad",
                fingerprint: "SHA256:ipad",
                createdAt: Fixtures.created,
                isSecureEnclave: true
            ),
            privateKeyPEM: nil,
            deviceOnly: true
        )
        let snapshot = VaultSnapshot(
            identities: [Fixtures.laptopIdentity, Fixtures.enclaveIdentity, secondEnclave],
            hosts: [Fixtures.host("pi-a", "10.0.0.41")],
            knownHosts: [],
            updatedAt: Fixtures.timestamp
        )
        try await provider.push(snapshot)

        let posts = transport.requests("POST")
        let items = try posts.map { try JSONDecoder().decode(OnePasswordItem.self, from: XCTUnwrap($0.body)) }

        let keyItems = items.filter { $0.category == "SSH_KEY" }
        XCTAssertEqual(keyItems.count, 1, "only the exportable key becomes an SSH_KEY item")
        XCTAssertEqual(keyItems.first?.title, "laptop key")
        XCTAssertEqual(keyItems.first?.tags, ["ghostty-ios"])
        XCTAssertEqual(
            keyItems.first?.field(id: "private_key", label: "private key")?.value,
            Fixtures.pem
        )
        // Connect refuses to create the SSHKEY field type itself.
        XCTAssertEqual(keyItems.first?.field(id: "private_key", label: "private key")?.type, "CONCEALED")

        let titles = items.compactMap(\.title)
        XCTAssertFalse(titles.contains("phone enclave key"))
        XCTAssertFalse(titles.contains("ipad enclave key"))

        let notes = items.filter { $0.category == "SECURE_NOTE" }
        XCTAssertEqual(notes.count, 1)
        XCTAssertEqual(notes.first?.title, "Ghostty iOS hosts")
        XCTAssertNotNil(notes.first?.notesPlain)

        // The user is told, rather than quietly losing two keys.
        let result = try XCTUnwrap(provider.status.lastResult)
        XCTAssertTrue(result.contains("2 device-only keys not synced"), result)
    }

    func testPushRoundTripsIdentityMetadataThroughNotes() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)
        transport.route("GET /v1/vaults/\(vaultID)/items", json: "[]")
        transport.route("POST /v1/vaults/\(vaultID)/items", json: "{}")

        try await provider.push(
            VaultSnapshot(
                identities: [Fixtures.laptopIdentity],
                hosts: [],
                knownHosts: [],
                updatedAt: Fixtures.timestamp
            )
        )

        let posted = try transport.requests("POST")
            .map { try JSONDecoder().decode(OnePasswordItem.self, from: XCTUnwrap($0.body)) }
        let keyItem = try XCTUnwrap(posted.first { $0.category == "SSH_KEY" })

        // Feed the item we would have written back through the reader: a
        // pushed key must come home as the same Identity, UUID and all.
        let restored = try XCTUnwrap(OnePasswordConnectProvider.identity(from: keyItem))
        XCTAssertEqual(restored.identity, Fixtures.laptopIdentity.identity)
        XCTAssertEqual(restored.privateKeyPEM, Fixtures.pem)
    }

    func testPushUpdatesAnExistingItemInsteadOfDuplicatingIt() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: """
                [
                  {"id":"sshitem1","title":"laptop key","category":"SSH_KEY","tags":["ghostty-ios"]},
                  {"id":"notesitem1","title":"Ghostty iOS hosts","category":"SECURE_NOTE","tags":["ghostty-ios"]}
                ]
                """
        )
        transport.route("PUT /v1/vaults/\(vaultID)/items/sshitem1", json: "{}")
        transport.route("PUT /v1/vaults/\(vaultID)/items/notesitem1", json: "{}")

        try await provider.push(
            VaultSnapshot(
                identities: [Fixtures.laptopIdentity],
                hosts: [],
                knownHosts: [],
                updatedAt: Fixtures.timestamp
            )
        )

        XCTAssertTrue(transport.requests("POST").isEmpty, "a second push must not duplicate items")
        XCTAssertEqual(transport.requests("PUT").count, 2)
    }

    func testPushOnlyDeletesItemsItOwns() async throws {
        let transport = StubConnectTransport()
        let provider = try await connectedProvider(transport)

        transport.route(
            "GET /v1/vaults/\(vaultID)/items",
            json: """
                [
                  {"id":"ours","title":"deleted key","category":"SSH_KEY","tags":["ghostty-ios"]},
                  {"id":"theirs","title":"andy's own key","category":"SSH_KEY","tags":["personal"]}
                ]
                """
        )
        transport.route("POST /v1/vaults/\(vaultID)/items", json: "{}")
        transport.route("DELETE /v1/vaults/\(vaultID)/items/ours", json: "")

        try await provider.push(VaultSnapshot(identities: [], hosts: [], knownHosts: [], updatedAt: Fixtures.timestamp))

        let deletedPaths = transport.requests("DELETE").map(\.path)
        XCTAssertEqual(deletedPaths, ["/v1/vaults/\(vaultID)/items/ours"])
        XCTAssertFalse(
            deletedPaths.contains { $0.hasSuffix("theirs") },
            "an untagged SSH key in the same vault belongs to the user"
        )
    }

    func testPushBeforeConnectIsNotConnected() async {
        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain(), transport: StubConnectTransport())
        do {
            try await provider.push(Fixtures.snapshot)
            XCTFail("expected notConnected")
        } catch let error as VaultSyncError {
            XCTAssertEqual(error, .notConnected("1Password Connect"))
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)")
        }
    }

    // MARK: Credentials and configuration

    func testTokenIsStoredInTheKeychainDeviceOnly() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubConnectTransport()
        transport.route("GET /heartbeat", json: ".")
        transport.route("GET /v1/vaults", json: #"[{"id":"abc123vault","name":"Personal"}]"#)

        let provider = OnePasswordConnectProvider(keychain: keychain, transport: transport)
        try await provider.connect(.onePasswordConnect(serverURL: serverURL, token: token, vaultName: nil))

        XCTAssertTrue(keychain.contains(account: "sync.onepassword.connection"))
        let options = try XCTUnwrap(keychain.storedOptions["sync.onepassword.connection"])
        XCTAssertFalse(options.synchronizable, "a bearer token for a whole vault stays on this device")

        await provider.disconnect()
        XCTAssertFalse(keychain.contains(account: "sync.onepassword.connection"))
    }

    func testSelfSignedCertificatesAreOffByDefault() {
        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain())
        XCTAssertFalse(
            provider.allowsSelfSignedCertificates,
            "relaxing TLS is a decision the server's owner makes explicitly"
        )
    }

    func testURLBuildingToleratesATrailingSlash() {
        let withSlash = URL(string: "https://connect.lan:8080/") ?? URL(fileURLWithPath: "/")
        XCTAssertEqual(
            OnePasswordConnectProvider.makeURL(serverURL: withSlash, path: "/v1/vaults")?.absoluteString,
            "https://connect.lan:8080/v1/vaults"
        )
    }

    func testHelpTextExplainsWhyConnectIsRequired() {
        let provider = OnePasswordConnectProvider(keychain: InMemoryKeychain())
        let text = provider.helpText
        // The user needs to understand why this provider alone needs a server.
        XCTAssertTrue(text.contains("no on-device API"), text)
        XCTAssertTrue(text.contains("Connect"), text)
    }

}
