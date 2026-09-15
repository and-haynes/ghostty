import SwiftUI

/// A host key we have never seen, waiting on the user's verdict.
struct HostKeyPromptRequest: Identifiable {
    let id = UUID()
    let hostname: String
    let port: Int
    let keyType: String
    let fingerprint: String
    let respond: (Bool) -> Void
}

/// A password the connection needs before it can continue.
struct PasswordPromptRequest: Identifiable {
    let id = UUID()
    let host: Host
    let respond: (String?) -> Void
}

/// Owns the open terminals and the machinery to start new ones.
///
/// It is also the app's `HostKeyPrompter`: NIOSSH asks whether an unknown host
/// key is acceptable from deep inside the handshake, and the only honest
/// answer comes from a human looking at a fingerprint. The request is
/// published here and the handshake waits on a continuation until the alert is
/// answered.
@MainActor
final class SessionManager: ObservableObject {
    @Published private(set) var sessions: [TerminalSession] = []
    @Published var selectedID: TerminalSession.ID?
    @Published var hostKeyPrompt: HostKeyPromptRequest?
    @Published var passwordPrompt: PasswordPromptRequest?
    @Published var lastError: String?

    private weak var vault: Vault?
    private weak var settings: AppSettings?

    func configure(vault: Vault, settings: AppSettings) {
        self.vault = vault
        self.settings = settings
    }

    // MARK: - Opening

    @discardableResult
    func openDemo(settings: AppSettings) -> TerminalSession? {
        do {
            let session = try TerminalSession.demo(
                theme: settings.theme,
                fontSize: CGFloat(settings.fontSize)
            )
            append(session)
            return session
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    func connect(to host: Host) throws {
        guard let vault, let settings else {
            throw SSHError.connectionFailed("The vault is not ready yet.")
        }
        let transport = SSHTransport(
            host: host,
            vault: vault,
            defaultTerm: settings.defaultTerm,
            prompter: self,
            passwordPrompt: { [weak self] host in
                await self?.askPassword(for: host) ?? nil
            }
        )
        let session = try TerminalSession(
            displayName: host.displayName,
            transport: transport,
            theme: settings.theme,
            fontSize: CGFloat(host.fontSize ?? settings.fontSize),
            accentHex: host.colorHex
        )
        append(session)
    }

    private func append(_ session: TerminalSession) {
        sessions.append(session)
        selectedID = session.id
    }

    func close(_ session: TerminalSession) {
        session.stop()
        sessions.removeAll { $0.id == session.id }
        if selectedID == session.id { selectedID = sessions.last?.id }
    }

    func closeAll() {
        sessions.forEach { $0.stop() }
        sessions.removeAll()
        selectedID = nil
    }
}

// MARK: - Password prompting

extension SessionManager {
    /// Ask for a password interactively. Only reached when the host has no key
    /// and no stored password — see SSHConnectionCoordinator for why the order
    /// matters.
    func askPassword(for host: Host) async -> String? {
        await withCheckedContinuation { continuation in
            var answered = false
            self.passwordPrompt = PasswordPromptRequest(host: host) { password in
                guard !answered else { return }
                answered = true
                continuation.resume(returning: password)
            }
        }
    }
}

// MARK: - Host key prompting

extension SessionManager: HostKeyPrompter {
    nonisolated func confirmUnknownHost(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String
    ) async -> Bool {
        await withCheckedContinuation { continuation in
            Task { @MainActor in
                // A continuation must be resumed exactly once; `answered`
                // guards against an alert that somehow fires both buttons.
                var answered = false
                self.hostKeyPrompt = HostKeyPromptRequest(
                    hostname: hostname,
                    port: port,
                    keyType: keyType,
                    fingerprint: fingerprint
                ) { accepted in
                    guard !answered else { return }
                    answered = true
                    continuation.resume(returning: accepted)
                }
            }
        }
    }
}
