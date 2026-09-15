import Foundation

/// Turns a saved `Host` into the two things `SSHSession.connect` needs: a
/// request and an ordered list of credentials to try.
///
/// Deliberately free of SwiftUI and of NIO. The UI passes in a callback for the
/// interactive password prompt; everything else comes out of the vault. Keeping
/// this separate from `SSHSession` means the "which credential, in what order"
/// policy is testable without opening a socket.
enum SSHConnectionCoordinator {

    /// What a session needs to be opened.
    struct Plan: Sendable {
        var request: SSHConnectionRequest
        /// Tried in this order, each at most once.
        var authMethods: [SSHAuthMethod]
    }

    /// Prompts the user for a password. Return nil if they cancel.
    typealias PasswordPrompt = @MainActor (_ host: Host) async -> String?

    /// Builds the plan for `host`.
    ///
    /// Ordering, and why:
    /// 1. **The host's identity key**, if it has one. Public key auth is the
    ///    thing we want to succeed; it is also the only method that works with
    ///    a Secure Enclave key.
    /// 2. **A stored password**, if the host is marked `usesPassword` and the
    ///    vault has one.
    /// 3. **An interactive prompt** — but only when the first two produced
    ///    nothing. Asking for a password when a key is configured would train
    ///    people to type their password into a sheet that appears for no
    ///    reason, which is how you get phished.
    ///
    /// - Parameters:
    ///   - host: The saved destination.
    ///   - identity: The `Identity` referenced by `host.identityID`, already
    ///     resolved by the caller. Passed in rather than looked up so this stays
    ///     independent of how the vault indexes identities.
    ///   - vault: Source of key material and stored passwords.
    ///   - cols/rows: The terminal's current size, so the pty starts correct.
    ///   - promptForPassword: Last-resort interactive prompt. Omit it in
    ///     contexts that cannot show UI (a background reconnect, a test).
    /// - Throws: `SSHError.noAuthenticationMethods` when there is nothing to
    ///   try, or the vault's own error when unlocking the only available key
    ///   fails.
    @MainActor
    static func plan(
        for host: Host,
        identity: Identity?,
        vault: Vault,
        cols: Int,
        rows: Int,
        promptForPassword: PasswordPrompt? = nil
    ) async throws -> Plan {
        let request = SSHConnectionRequest(
            hostname: host.hostname,
            port: host.port,
            username: host.username,
            term: host.term,
            cols: max(cols, 1),
            rows: max(rows, 1),
            startupCommand: host.startupCommand.flatMap { $0.isEmpty ? nil : $0 },
            environment: ["LANG": "en_US.UTF-8"]
        )

        var methods: [SSHAuthMethod] = []
        // Remembered so that, if we end up with nothing to offer, we can explain
        // *why* rather than just saying "no credentials".
        var keyUnlockFailure: Error?

        if let identity {
            do {
                let material = try vault.privateKey(
                    for: identity,
                    prompt: "Unlock \"\(identity.name)\" to connect to \(host.displayName)"
                )
                methods.append(.privateKey(material))
            } catch {
                // Face ID cancelled, item missing, key revoked… Don't give up
                // yet: a password may still get the user in. If nothing else
                // turns up, this error is what we report.
                keyUnlockFailure = error
            }
        }

        if host.usesPassword {
            // A missing stored password is normal (the host is flagged for
            // password auth but nothing is saved yet) — fall through to the
            // prompt. A vault error, though, is worth surfacing.
            if let stored = try vault.password(for: host), !stored.isEmpty {
                methods.append(.password(stored))
            }
        }

        if methods.isEmpty, let promptForPassword {
            if let typed = await promptForPassword(host), !typed.isEmpty {
                methods.append(.password(typed))
            }
        }

        guard !methods.isEmpty else {
            if let keyUnlockFailure {
                throw SSHError.authenticationFailed(
                    "Couldn't use the key \"\(identity?.name ?? "")\": "
                        + "\(keyUnlockFailure.localizedDescription) There's no other credential "
                        + "configured for \(host.displayName)."
                )
            }
            throw SSHError.noAuthenticationMethods
        }

        return Plan(request: request, authMethods: methods)
    }
}
