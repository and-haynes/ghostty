import Foundation

// MARK: - What travels

/// An identity as it crosses a sync boundary.
///
/// Secure Enclave keys have no exportable private half — that is the entire
/// point of them — so they travel as metadata with `deviceOnly` set and are
/// shown with a badge rather than silently appearing on the other device as a
/// key that cannot be used.
struct SyncedIdentity: Codable, Sendable, Equatable {
    var identity: Identity
    /// Unencrypted openssh-key-v1 PEM, or nil when the key cannot leave.
    var privateKeyPEM: String?
    var deviceOnly: Bool

    var canAuthenticateElsewhere: Bool { privateKeyPEM != nil }
}

/// Everything a provider stores: the whole vault, minus what cannot leave.
struct VaultSnapshot: Codable, Sendable, Equatable {
    var identities: [SyncedIdentity]
    var hosts: [Host]
    var knownHosts: [KnownHost]
    /// When this snapshot was taken. The conflict rule is "newest wins", and
    /// this is the clock it is judged by.
    var updatedAt: Date

    static let empty = VaultSnapshot(identities: [], hosts: [], knownHosts: [], updatedAt: .distantPast)

    var isEmpty: Bool { identities.isEmpty && hosts.isEmpty && knownHosts.isEmpty }

    var summary: String {
        "\(identities.count) key\(identities.count == 1 ? "" : "s"), "
            + "\(hosts.count) host\(hosts.count == 1 ? "" : "s"), "
            + "\(knownHosts.count) pinned"
    }
}

// MARK: - Merge

/// Snapshot-level newest-wins merge.
///
/// Records are unioned by identity; where the same id exists on both sides the
/// *newer snapshot's* copy is kept. This is deliberately coarse: `Identity`,
/// `Host` and `KnownHost` carry no per-record modification time, and inventing
/// one would mean rewriting records the user never touched. The practical
/// effect is that editing the same host on two devices between syncs loses the
/// older edit — which is what "newest wins" means — while additions and
/// deletions on either side always survive.
enum VaultSyncMerge {
    static func merge(local: VaultSnapshot, remote: VaultSnapshot) -> VaultSnapshot {
        let remoteWins = remote.updatedAt > local.updatedAt
        let winner = remoteWins ? remote : local
        let loser = remoteWins ? local : remote

        return VaultSnapshot(
            identities: union(winner.identities, loser.identities, id: { $0.identity.id }),
            hosts: union(winner.hosts, loser.hosts, id: { $0.id }),
            knownHosts: union(winner.knownHosts, loser.knownHosts, id: { $0.id }),
            updatedAt: max(local.updatedAt, remote.updatedAt)
        )
    }

    private static func union<T, ID: Hashable>(
        _ winner: [T],
        _ loser: [T],
        id: (T) -> ID
    ) -> [T] {
        var seen = Set(winner.map(id))
        var out = winner
        for item in loser where !seen.contains(id(item)) {
            seen.insert(id(item))
            out.append(item)
        }
        return out
    }
}

// MARK: - Providers

enum VaultSyncProviderKind: String, Codable, CaseIterable, Identifiable, Sendable {
    case iCloudKeychain
    case bitwarden
    case onePasswordConnect
    case encryptedBundle

    var id: String { rawValue }

    var displayName: String {
        switch self {
        case .iCloudKeychain: return "iCloud Keychain"
        case .bitwarden: return "Bitwarden / Vaultwarden"
        case .onePasswordConnect: return "1Password Connect"
        case .encryptedBundle: return "Encrypted bundle"
        }
    }

    var systemImage: String {
        switch self {
        case .iCloudKeychain: return "icloud"
        case .bitwarden: return "shield.lefthalf.filled"
        case .onePasswordConnect: return "lock.square.stack"
        case .encryptedBundle: return "doc.zipper"
        }
    }
}

/// Credentials for `connect`. One case per way in; a provider rejects the
/// shapes it does not understand.
enum VaultSyncCredentials: Sendable {
    /// iCloud Keychain needs nothing: the Keychain items carry the flag.
    case none
    case bitwardenPassword(serverURL: URL, email: String, masterPassword: String, totp: String?)
    case bitwardenAPIKey(serverURL: URL, clientID: String, clientSecret: String, masterPassword: String)
    case onePasswordConnect(serverURL: URL, token: String, vaultName: String?)
    /// The passphrase protecting an exported bundle.
    case bundlePassphrase(String)
}

struct VaultSyncStatus: Codable, Equatable, Sendable {
    var isConnected = false
    /// "andy@example.com · vault.lan" — shown under the provider name.
    var accountLabel: String?
    var lastSync: Date?
    /// One human sentence describing the last attempt, success or failure.
    var lastResult: String?
    var lastResultWasError = false

    static let disconnected = VaultSyncStatus()
}

enum VaultSyncError: Error, LocalizedError, Equatable {
    case notConnected(String)
    case unsupportedCredentials(String)
    case server(String)
    case crypto(String)
    case badResponse(String)
    case cancelled

    var errorDescription: String? {
        switch self {
        case .notConnected(let provider):
            return "\(provider) is not connected. Connect it in Settings ▸ Sync first."
        case .unsupportedCredentials(let detail):
            return "Those credentials aren't the kind this provider accepts: \(detail)"
        case .server(let detail):
            return detail
        case .crypto(let detail):
            return "The vault data could not be decrypted: \(detail)"
        case .badResponse(let detail):
            return "The server replied with something unexpected: \(detail)"
        case .cancelled:
            return "Cancelled."
        }
    }
}

/// One place to keep a copy of the vault.
///
/// Providers are deliberately dumb: they push and pull whole snapshots and
/// know nothing about merging. `VaultSyncEngine` owns the policy so every
/// provider behaves identically, and so the merge rule is testable on its own.
@MainActor
protocol VaultSyncProvider: AnyObject {
    var kind: VaultSyncProviderKind { get }
    /// One or two sentences shown under the provider in Settings.
    var helpText: String { get }
    var status: VaultSyncStatus { get set }

    func connect(_ credentials: VaultSyncCredentials) async throws
    func disconnect() async

    func push(_ snapshot: VaultSnapshot) async throws
    /// nil when the provider has nothing stored yet.
    func pull() async throws -> VaultSnapshot?
}

extension VaultSyncProvider {
    var displayName: String { kind.displayName }
}
