import Foundation

/// Outcome of pinning one host's key.
struct HostKeyPinResult: Identifiable, Equatable {
    enum Outcome: Equatable {
        /// Never seen before; now pinned.
        case pinned(fingerprint: String, keyType: String)
        /// Already pinned and the key still matches.
        case unchanged(fingerprint: String)
        /// Pinned before and the key is *different*. Not re-pinned.
        case changed(expected: String, presented: String)
        case unreachable(String)
    }

    var id: String { "\(hostname):\(port)" }
    let hostname: String
    let port: Int
    let outcome: Outcome

    var isProblem: Bool {
        if case .changed = outcome { return true }
        return false
    }
}

/// The thing that actually talks to a server, so tests can substitute one.
@MainActor
protocol HostKeyProbing: AnyObject {
    /// Connect far enough to see the host key, and no further.
    func probe(hostname: String, port: Int, username: String) async -> HostKeyPinResult.Outcome
}

/// Fetches and pins host keys for a batch of hosts.
///
/// "Pinning" here is the same code path a normal connection takes: the session
/// hands the key to the vault's TOFU check, and an unknown key is written only
/// because this prompter says yes. Nothing special-cases the pin, which is the
/// point — a key pinned here is pinned exactly as one accepted by hand.
///
/// Authentication is expected to *fail* afterwards and that is fine: the key
/// exchange completes before user auth begins, so the key is known by then. We
/// disconnect as soon as we have it.
@MainActor
final class HostKeyPinner: ObservableObject {
    @Published private(set) var results: [HostKeyPinResult] = []
    @Published private(set) var isRunning = false
    @Published private(set) var progress: Double = 0

    private let vault: Vault
    private let prober: any HostKeyProbing
    private var task: Task<Void, Never>?

    init(vault: Vault, prober: (any HostKeyProbing)? = nil) {
        self.vault = vault
        self.prober = prober ?? SSHHostKeyProber(vault: vault)
    }

    func cancel() {
        task?.cancel()
        task = nil
        isRunning = false
    }

    func pin(_ hosts: [Host]) async {
        guard !hosts.isEmpty, !isRunning else { return }
        isRunning = true
        progress = 0
        results = []
        defer { isRunning = false }

        for (index, host) in hosts.enumerated() {
            if Task.isCancelled { break }
            let outcome = await prober.probe(
                hostname: host.hostname,
                port: host.port,
                username: host.username
            )
            results.append(
                HostKeyPinResult(hostname: host.hostname, port: host.port, outcome: outcome)
            )
            if case .unreachable = outcome {} else {
                vault.markSeen(host)
            }
            progress = Double(index + 1) / Double(hosts.count)
        }

        Haptics.shared.fire(results.contains(where: \.isProblem) ? .hostKeyMismatch : .syncSucceeded)
    }

    var summary: String {
        let pinned = results.filter { if case .pinned = $0.outcome { return true } else { return false } }.count
        let changed = results.filter(\.isProblem).count
        let unreachable = results.filter {
            if case .unreachable = $0.outcome { return true } else { return false }
        }.count
        var parts: [String] = []
        if pinned > 0 { parts.append("\(pinned) pinned") }
        if changed > 0 { parts.append("\(changed) CHANGED") }
        if unreachable > 0 { parts.append("\(unreachable) unreachable") }
        if parts.isEmpty { parts.append("all already pinned") }
        return parts.joined(separator: ", ")
    }
}

/// The real prober: a normal SSH connection, abandoned once the key is known.
@MainActor
final class SSHHostKeyProber: HostKeyProbing {
    private let vault: Vault

    init(vault: Vault) {
        self.vault = vault
    }

    func probe(hostname: String, port: Int, username: String) async -> HostKeyPinResult.Outcome {
        let existing = vault.knownHost(hostname: hostname, port: port)
        let recorder = AutoAcceptingPrompter()

        let session = SSHSession(vault: vault)
        session.hostKeyPrompter = recorder

        let request = SSHConnectionRequest(
            hostname: hostname,
            port: port,
            username: username.isEmpty ? "ghostty" : username,
            term: "xterm-256color",
            cols: 80,
            rows: 24
        )

        do {
            // `.none` auth: we want the handshake, not a session. The server
            // will refuse, by which point the key has already been seen.
            try await session.connect(request, auth: [.none])
            await session.disconnect()
        } catch let error as SSHError {
            await session.disconnect()
            if case .hostKeyMismatch(let expected, let presented) = error {
                return .changed(expected: expected, presented: presented)
            }
            // Authentication failure means the key exchange succeeded, which
            // is all we wanted.
            if let seen = recorder.seen {
                return existing == nil
                    ? .pinned(fingerprint: seen.fingerprint, keyType: seen.keyType)
                    : .unchanged(fingerprint: seen.fingerprint)
            }
            if let existing, case .authenticationFailed = error {
                return .unchanged(fingerprint: existing.fingerprint)
            }
            return .unreachable(error.localizedDescription)
        } catch {
            await session.disconnect()
            return .unreachable(error.localizedDescription)
        }

        if let seen = recorder.seen {
            return existing == nil
                ? .pinned(fingerprint: seen.fingerprint, keyType: seen.keyType)
                : .unchanged(fingerprint: seen.fingerprint)
        }
        if let existing { return .unchanged(fingerprint: existing.fingerprint) }
        return .unreachable("The server did not present a host key.")
    }
}

/// Accepts an unknown host key and remembers what it was.
///
/// Only ever used from the explicit "Pin host keys" action, where the user has
/// asked for exactly this. A *mismatched* key never reaches a prompter — the
/// session refuses it outright — so this cannot be used to paper over one.
private final class AutoAcceptingPrompter: HostKeyPrompter, @unchecked Sendable {
    struct Seen {
        let keyType: String
        let fingerprint: String
    }

    private let lock = NSLock()
    private var storage: Seen?

    var seen: Seen? { lock.withLock { storage } }

    /// Scoped `withLock` rather than lock/unlock around the assignment: this
    /// is an async method, and holding a lock across a potential suspension
    /// point is an error in the Swift 6 language mode.
    func confirmUnknownHost(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String
    ) async -> Bool {
        lock.withLock { storage = Seen(keyType: keyType, fingerprint: fingerprint) }
        return true
    }
}
