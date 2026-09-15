import XCTest
@testable import Ghostty

final class VaultSyncMergeTests: XCTestCase {
    private func snapshot(
        hosts: [Host] = [],
        identities: [SyncedIdentity] = [],
        knownHosts: [KnownHost] = [],
        at date: Date
    ) -> VaultSnapshot {
        VaultSnapshot(identities: identities, hosts: hosts, knownHosts: knownHosts, updatedAt: date)
    }

    private func host(_ alias: String, id: UUID = UUID(), username: String = "andy") -> Host {
        Host(id: id, alias: alias, hostname: "\(alias).lan", username: username)
    }

    func testAdditionsFromBothSidesSurvive() {
        let local = snapshot(hosts: [host("a")], at: Date(timeIntervalSince1970: 100))
        let remote = snapshot(hosts: [host("b")], at: Date(timeIntervalSince1970: 200))
        let merged = VaultSyncMerge.merge(local: local, remote: remote)
        XCTAssertEqual(Set(merged.hosts.map(\.alias)), ["a", "b"])
    }

    func testNewerSnapshotWinsTheSameRecord() {
        let id = UUID()
        let local = snapshot(hosts: [host("a", id: id, username: "old")], at: Date(timeIntervalSince1970: 100))
        let remote = snapshot(hosts: [host("a", id: id, username: "new")], at: Date(timeIntervalSince1970: 200))

        XCTAssertEqual(VaultSyncMerge.merge(local: local, remote: remote).hosts.first?.username, "new")
        // ...and symmetrically: a newer local copy is not clobbered by a stale
        // remote one, which is the case that would lose a user's edit.
        XCTAssertEqual(VaultSyncMerge.merge(local: remote, remote: local).hosts.first?.username, "new")
    }

    func testMergedTimestampIsTheLater() {
        let early = Date(timeIntervalSince1970: 100)
        let late = Date(timeIntervalSince1970: 200)
        let merged = VaultSyncMerge.merge(local: snapshot(at: early), remote: snapshot(at: late))
        XCTAssertEqual(merged.updatedAt, late)
    }

    func testKnownHostPinsAreUnioned() {
        let a = KnownHost(hostname: "a.lan", port: 22, keyType: "ssh-ed25519", fingerprint: "SHA256:a", publicKeyLine: "x")
        let b = KnownHost(hostname: "b.lan", port: 22, keyType: "ssh-ed25519", fingerprint: "SHA256:b", publicKeyLine: "y")
        let merged = VaultSyncMerge.merge(
            local: snapshot(knownHosts: [a], at: Date(timeIntervalSince1970: 1)),
            remote: snapshot(knownHosts: [b], at: Date(timeIntervalSince1970: 2))
        )
        XCTAssertEqual(Set(merged.knownHosts.map(\.id)), ["a.lan:22", "b.lan:22"])
    }

    func testMergeIsIdempotent() {
        let local = snapshot(hosts: [host("a")], at: Date(timeIntervalSince1970: 100))
        let remote = snapshot(hosts: [host("b")], at: Date(timeIntervalSince1970: 200))
        let once = VaultSyncMerge.merge(local: local, remote: remote)
        let twice = VaultSyncMerge.merge(local: once, remote: once)
        XCTAssertEqual(once.hosts.map(\.id).sorted { $0.uuidString < $1.uuidString },
                       twice.hosts.map(\.id).sorted { $0.uuidString < $1.uuidString })
    }

    func testEmptyRemoteKeepsEverythingLocal() {
        let local = snapshot(hosts: [host("a")], at: Date(timeIntervalSince1970: 100))
        let merged = VaultSyncMerge.merge(local: local, remote: .empty)
        XCTAssertEqual(merged.hosts.count, 1)
    }
}

@MainActor
final class VaultSnapshotTests: XCTestCase {
    private var directory: URL!
    private var keychain: InMemoryKeychain!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("GhosttySyncTests-\(UUID().uuidString)", isDirectory: true)
        keychain = InMemoryKeychain()
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    private func makeVault() -> Vault {
        Vault(keychain: keychain, directory: directory)
    }

    func testSnapshotCarriesExportablePrivateKeys() throws {
        let vault = makeVault()
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        vault.upsert(Host(alias: "noether", hostname: "10.0.0.81", username: "andy", identityID: identity.id))

        let snapshot = vault.snapshot()
        XCTAssertEqual(snapshot.identities.count, 1)
        let synced = try XCTUnwrap(snapshot.identities.first)
        XCTAssertFalse(synced.deviceOnly)
        let pem = try XCTUnwrap(synced.privateKeyPEM)
        XCTAssertTrue(pem.contains("BEGIN OPENSSH PRIVATE KEY"))
        XCTAssertEqual(snapshot.hosts.count, 1)
    }

    func testApplyRestoresKeysHostsAndPinsWithTheirOriginalIdentifiers() throws {
        let source = makeVault()
        let identity = try source.generateIdentity(name: "laptop", type: .ed25519)
        source.upsert(Host(alias: "noether", hostname: "10.0.0.81", username: "andy", identityID: identity.id))
        _ = try source.trust(
            hostname: "10.0.0.81", port: 22,
            keyType: "ssh-ed25519", fingerprint: "SHA256:abc", publicKeyLine: "ssh-ed25519 AAAA"
        )
        let snapshot = source.snapshot()

        // A second, entirely separate device.
        let otherDirectory = directory.appendingPathComponent("device2", isDirectory: true)
        let destination = Vault(keychain: InMemoryKeychain(), directory: otherDirectory)
        let applied = try destination.apply(snapshot)

        XCTAssertEqual(applied.keysAdded, 1)
        XCTAssertEqual(applied.hostsAdded, 1)
        XCTAssertEqual(applied.pinsAdded, 1)
        // The id must survive: a host references its key by id, so minting a
        // new one on import would silently unlink every host.
        XCTAssertEqual(destination.identities.first?.id, identity.id)
        XCTAssertEqual(destination.hosts.first?.identityID, identity.id)
        // And the private key really arrived, not just its metadata.
        XCTAssertNoThrow(try destination.privateKey(for: XCTUnwrap(destination.identities.first)))
    }

    func testApplyIsIdempotent() throws {
        let source = makeVault()
        _ = try source.generateIdentity(name: "laptop", type: .ed25519)
        source.upsert(Host(alias: "noether", hostname: "10.0.0.81", username: "andy"))
        let snapshot = source.snapshot()

        let destination = Vault(keychain: InMemoryKeychain(), directory: directory.appendingPathComponent("d2"))
        _ = try destination.apply(snapshot)
        let second = try destination.apply(snapshot)
        XCTAssertEqual(second.keysAdded, 0)
        XCTAssertEqual(second.hostsAdded, 0)
        XCTAssertEqual(destination.identities.count, 1)
        XCTAssertEqual(destination.hosts.count, 1)
    }

    func testDeviceOnlyIdentitiesArriveAsMetadataOnly() throws {
        let vault = makeVault()
        let identity = Identity(
            name: "enclave",
            keyType: .secureEnclaveP256,
            publicKeyLine: "ecdsa-sha2-nistp256 AAAA enclave",
            fingerprint: "SHA256:enclave",
            isSecureEnclave: true
        )
        let snapshot = VaultSnapshot(
            identities: [SyncedIdentity(identity: identity, privateKeyPEM: nil, deviceOnly: true)],
            hosts: [], knownHosts: [], updatedAt: Date()
        )
        _ = try vault.apply(snapshot)
        XCTAssertEqual(vault.identities.count, 1)
        // Visible, but unusable — which is the honest outcome for a key bound
        // to another device's Secure Enclave.
        XCTAssertThrowsError(try vault.privateKey(for: XCTUnwrap(vault.identities.first)))
    }
}

@MainActor
final class ICloudSyncProviderTests: XCTestCase {
    private var directory: URL!

    override func setUpWithError() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("GhosttyICloudTests-\(UUID().uuidString)", isDirectory: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: directory)
    }

    func testPushThenPullRoundTripsMetadata() async throws {
        let keychain = InMemoryKeychain()
        let vault = Vault(keychain: keychain, directory: directory)
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519)
        vault.upsert(Host(alias: "noether", hostname: "10.0.0.81", username: "andy", identityID: identity.id))

        let provider = ICloudKeychainSyncProvider(vault: vault, keychain: keychain)
        try await provider.connect(.none)
        XCTAssertTrue(provider.status.isConnected)

        try await provider.push(vault.snapshot())
        let fetched = try await provider.pull()
        let pulled = try XCTUnwrap(fetched)
        XCTAssertEqual(pulled.hosts.first?.alias, "noether")
        XCTAssertEqual(pulled.identities.first?.identity.id, identity.id)
        // Private keys are NOT duplicated into the metadata item: they already
        // travel as their own synchronised Keychain items.
        XCTAssertNil(pulled.identities.first?.privateKeyPEM)
    }

    func testPushMovesExportableKeysIntoTheSynchronisedKeychain() async throws {
        let keychain = InMemoryKeychain()
        let vault = Vault(keychain: keychain, directory: directory)
        let identity = try vault.generateIdentity(name: "laptop", type: .ed25519, syncToICloud: false)
        XCTAssertFalse(identity.syncsToICloud)

        let provider = ICloudKeychainSyncProvider(vault: vault, keychain: keychain)
        try await provider.connect(.none)
        try await provider.push(vault.snapshot())

        XCTAssertEqual(vault.identities.first?.syncsToICloud, true)
        XCTAssertEqual(keychain.storedOptions[identity.keychainAccount]?.synchronizable, true)
    }

    func testPullBeforeAnyPushReturnsNil() async throws {
        let keychain = InMemoryKeychain()
        let vault = Vault(keychain: keychain, directory: directory)
        let provider = ICloudKeychainSyncProvider(vault: vault, keychain: keychain)
        try await provider.connect(.none)
        let pulled = try await provider.pull()
        XCTAssertNil(pulled)
    }

    func testOperationsRequireConnection() async {
        let keychain = InMemoryKeychain()
        let vault = Vault(keychain: keychain, directory: directory)
        let provider = ICloudKeychainSyncProvider(vault: vault, keychain: keychain)
        do {
            _ = try await provider.pull()
            XCTFail("pull should refuse while disconnected")
        } catch {
            XCTAssertTrue(error is VaultSyncError)
        }
    }

    func testRejectsCredentialsItDoesNotUnderstand() async {
        let keychain = InMemoryKeychain()
        let vault = Vault(keychain: keychain, directory: directory)
        let provider = ICloudKeychainSyncProvider(vault: vault, keychain: keychain)
        do {
            try await provider.connect(.bundlePassphrase("nope"))
            XCTFail("iCloud should not accept a bundle passphrase")
        } catch {
            XCTAssertTrue(error is VaultSyncError)
        }
    }
}
