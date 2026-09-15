import Foundation
import SwiftUI

/// Owns the sync providers and the one merge policy they all obey.
///
/// Providers push and pull whole snapshots and know nothing about conflict
/// resolution. Keeping that here means every provider behaves the same way and
/// the rule itself (`VaultSyncMerge`) is testable without a network, a
/// keychain, or a server.
@MainActor
final class VaultSyncEngine: ObservableObject {
    @Published private(set) var statuses: [VaultSyncProviderKind: VaultSyncStatus] = [:]
    @Published private(set) var busy: Set<VaultSyncProviderKind> = []

    private var providers: [VaultSyncProviderKind: any VaultSyncProvider] = [:]
    private unowned let vault: Vault
    private let defaults: UserDefaults

    init(vault: Vault, keychain: KeychainStore = SystemKeychain(), defaults: UserDefaults = .standard) {
        self.vault = vault
        self.defaults = defaults

        register(ICloudKeychainSyncProvider(vault: vault, keychain: keychain))
        register(BitwardenSyncProvider(keychain: keychain))
        register(OnePasswordConnectProvider(keychain: keychain))
        register(EncryptedBundleProvider(keychain: keychain))

        restoreStatuses()
        // Credentials outlive a launch (they are in the Keychain), so a
        // provider that was connected last time should come back connected
        // rather than silently pretending it was never set up.
        Task { await restoreConnections() }
    }

    /// Re-establish provider sessions from Keychain-persisted credentials.
    private func restoreConnections() async {
        for (kind, provider) in providers where statuses[kind]?.isConnected == true {
            switch provider {
            case let bitwarden as BitwardenSyncProvider:
                _ = bitwarden.restoreSession()
            case let onePassword as OnePasswordConnectProvider:
                _ = await onePassword.restoreConnection()
            default:
                // iCloud and the bundle provider hold everything they need in
                // the Keychain already and restore in their own init.
                continue
            }
            commit(provider)
        }
    }

    private func register(_ provider: any VaultSyncProvider) {
        providers[provider.kind] = provider
        statuses[provider.kind] = provider.status
    }

    func provider(_ kind: VaultSyncProviderKind) -> (any VaultSyncProvider)? { providers[kind] }

    func status(_ kind: VaultSyncProviderKind) -> VaultSyncStatus {
        statuses[kind] ?? .disconnected
    }

    func isBusy(_ kind: VaultSyncProviderKind) -> Bool { busy.contains(kind) }

    var connectedKinds: [VaultSyncProviderKind] {
        VaultSyncProviderKind.allCases.filter { status($0).isConnected }
    }

    // MARK: - Actions

    func connect(_ kind: VaultSyncProviderKind, credentials: VaultSyncCredentials) async {
        guard let provider = providers[kind] else { return }
        busy.insert(kind)
        defer { busy.remove(kind) }
        do {
            try await provider.connect(credentials)
        } catch {
            provider.status.isConnected = false
            provider.status.lastResult = error.localizedDescription
            provider.status.lastResultWasError = true
        }
        commit(provider)
    }

    func disconnect(_ kind: VaultSyncProviderKind) async {
        guard let provider = providers[kind] else { return }
        busy.insert(kind)
        defer { busy.remove(kind) }
        await provider.disconnect()
        commit(provider)
    }

    /// Pull, merge, apply locally, push the merged result back.
    ///
    /// Pushing the *merged* snapshot rather than the local one is what makes a
    /// second device converge in one round instead of ping-ponging: after this
    /// runs, both sides hold the same set.
    func syncNow(_ kind: VaultSyncProviderKind) async {
        guard let provider = providers[kind] else { return }
        busy.insert(kind)
        defer { busy.remove(kind) }

        do {
            let local = vault.snapshot()
            let remote = try await provider.pull()
            let merged = remote.map { VaultSyncMerge.merge(local: local, remote: $0) } ?? local
            let applied = try vault.apply(merged)
            try await provider.push(merged)

            provider.status.lastSync = Date()
            provider.status.lastResultWasError = false
            provider.status.lastResult = Self.sentence(for: applied, merged: merged, hadRemote: remote != nil)
            Haptics.shared.fire(.syncSucceeded)
        } catch {
            Haptics.shared.fire(.syncFailed)
            provider.status.lastSync = Date()
            provider.status.lastResultWasError = true
            provider.status.lastResult = error.localizedDescription
        }
        commit(provider)
    }

    func syncAllConnected() async {
        for kind in connectedKinds {
            await syncNow(kind)
        }
    }

    private static func sentence(
        for applied: (keysAdded: Int, hostsAdded: Int, pinsAdded: Int),
        merged: VaultSnapshot,
        hadRemote: Bool
    ) -> String {
        guard hadRemote else { return "First sync — uploaded \(merged.summary)." }
        let gained = applied.keysAdded + applied.hostsAdded + applied.pinsAdded
        if gained == 0 { return "Up to date — \(merged.summary)." }
        var parts: [String] = []
        if applied.keysAdded > 0 { parts.append("\(applied.keysAdded) key\(applied.keysAdded == 1 ? "" : "s")") }
        if applied.hostsAdded > 0 { parts.append("\(applied.hostsAdded) host\(applied.hostsAdded == 1 ? "" : "s")") }
        if applied.pinsAdded > 0 { parts.append("\(applied.pinsAdded) pinned key\(applied.pinsAdded == 1 ? "" : "s")") }
        return "Received " + parts.joined(separator: ", ") + "."
    }

    // MARK: - Status persistence
    //
    // Status is non-secret (it is a date and a sentence), so UserDefaults is
    // the right home. The credentials behind it live in the Keychain, held by
    // each provider.

    private func commit(_ provider: any VaultSyncProvider) {
        statuses[provider.kind] = provider.status
        guard let data = try? JSONEncoder().encode(provider.status) else { return }
        defaults.set(data, forKey: Self.statusKey(provider.kind))
    }

    private func restoreStatuses() {
        for kind in VaultSyncProviderKind.allCases {
            guard let data = defaults.data(forKey: Self.statusKey(kind)),
                  let status = try? JSONDecoder().decode(VaultSyncStatus.self, from: data)
            else { continue }
            statuses[kind] = status
            providers[kind]?.status = status
        }
    }

    private static func statusKey(_ kind: VaultSyncProviderKind) -> String {
        "sync.status.\(kind.rawValue)"
    }
}
