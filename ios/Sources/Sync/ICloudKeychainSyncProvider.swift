import Foundation

/// iCloud Keychain, refactored behind `VaultSyncProvider`.
///
/// This is the one provider that does not really "transfer" anything: private
/// keys already replicate themselves when their Keychain items are marked
/// `kSecAttrSynchronizable`, and iOS does the moving. What is missing is the
/// *non-secret* half — hosts, known-hosts pins, key metadata — which lives in
/// Application Support and does not sync at all.
///
/// So push writes that metadata into one synchronisable Keychain item and
/// flips each exportable key's item into the synchronised Keychain; pull reads
/// the metadata item back. Secure Enclave keys are left alone, because a
/// reference to one chip is meaningless on another device.
@MainActor
final class ICloudKeychainSyncProvider: VaultSyncProvider {
    let kind: VaultSyncProviderKind = .iCloudKeychain

    var helpText: String {
        "Keys already sync themselves when iCloud Keychain is on; this adds "
            + "hosts, pinned host keys and key metadata, which otherwise stay on "
            + "this device. Secure Enclave keys never leave."
    }

    var status: VaultSyncStatus

    private let keychain: KeychainStore
    private unowned let vault: Vault

    /// One item, synchronised, holding the non-secret half of the vault.
    private let metadataAccount = "sync.icloud.snapshot"

    init(vault: Vault, keychain: KeychainStore = SystemKeychain()) {
        self.vault = vault
        self.keychain = keychain
        self.status = VaultSyncStatus()
    }

    func connect(_ credentials: VaultSyncCredentials) async throws {
        guard case .none = credentials else {
            throw VaultSyncError.unsupportedCredentials(
                "iCloud Keychain uses the device's own iCloud account; there is nothing to enter."
            )
        }
        status.isConnected = true
        status.accountLabel = "This device's iCloud account"
        status.lastResult = "Connected."
        status.lastResultWasError = false
    }

    func disconnect() async {
        // Deliberately does not un-sync existing keys: turning the provider off
        // should stop future syncing, not reach into iCloud Keychain and delete
        // what is already there and possibly in use on another device.
        status = VaultSyncStatus()
    }

    func push(_ snapshot: VaultSnapshot) async throws {
        guard status.isConnected else { throw VaultSyncError.notConnected(displayName) }

        var moved = 0
        var skipped = 0
        for synced in snapshot.identities {
            if synced.deviceOnly {
                skipped += 1
                continue
            }
            guard !synced.identity.syncsToICloud else { continue }
            try vault.restoreProtection(for: synced.identity, syncToICloud: true)
            moved += 1
        }

        // Only the non-secret half goes in the metadata item: the private keys
        // are already synchronised as their own Keychain items, and duplicating
        // them here would put a second copy of every secret in a single blob.
        let metadata = VaultSnapshot(
            identities: snapshot.identities.map {
                SyncedIdentity(identity: $0.identity, privateKeyPEM: nil, deviceOnly: $0.deviceOnly)
            },
            hosts: snapshot.hosts,
            knownHosts: snapshot.knownHosts,
            updatedAt: snapshot.updatedAt
        )
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        try keychain.set(
            try encoder.encode(metadata),
            account: metadataAccount,
            options: KeychainItemOptions(
                accessibility: .whenUnlocked,
                requiresBiometrics: false,
                synchronizable: true
            )
        )

        status.lastSync = Date()
        status.lastResultWasError = false
        var sentence = "Pushed \(snapshot.summary)."
        if moved > 0 { sentence += " \(moved) key\(moved == 1 ? "" : "s") moved into iCloud Keychain." }
        if skipped > 0 { sentence += " \(skipped) device-only key\(skipped == 1 ? "" : "s") not synced." }
        status.lastResult = sentence
    }

    func pull() async throws -> VaultSnapshot? {
        guard status.isConnected else { throw VaultSyncError.notConnected(displayName) }
        guard let data = try keychain.get(account: metadataAccount, prompt: nil) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        do {
            return try decoder.decode(VaultSnapshot.self, from: data)
        } catch {
            throw VaultSyncError.badResponse(
                "The iCloud Keychain copy of the vault could not be read: \(error.localizedDescription)"
            )
        }
    }
}
