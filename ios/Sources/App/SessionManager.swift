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
    /// Bumped when something (the console's `ssh`) wants the Sessions tab
    /// brought forward. A counter rather than a Bool so two requests in a row
    /// both register.
    @Published private(set) var sessionsTabRequest = 0

    private weak var vault: Vault?
    private weak var settings: AppSettings?

    /// The console is permanent: it is a tab, not a session, and closing every
    /// session must not take it away.
    private(set) var console: TerminalSession?

    func configure(vault: Vault, settings: AppSettings) {
        self.vault = vault
        self.settings = settings
        ensureConsole()
    }

    @discardableResult
    func ensureConsole() -> TerminalSession? {
        if let console { return console }
        guard let settings else { return nil }
        do {
            let session = try TerminalSession.console(
                commandHost: self,
                theme: settings.theme,
                fontSize: CGFloat(settings.fontSize)
            )
            console = session
            return session
        } catch {
            lastError = error.localizedDescription
            return nil
        }
    }

    // MARK: - Opening

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

    private func requestSessionsTab() {
        sessionsTabRequest &+= 1
    }

    private func append(_ session: TerminalSession) {
        sessions.append(session)
        selectedID = session.id
        // Start immediately rather than waiting for the terminal view to
        // appear. Tapping a host should begin the handshake — including the
        // host key prompt — even if the user stays on the list; deferring it
        // made a connected-looking session sit at "Not connected" until it was
        // opened.
        session.startIfNeeded()
        requestSessionsTab()
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


// MARK: - Console command host

extension SessionManager: ConsoleCommandHost {
    var consoleHosts: [Host] { vault?.hosts ?? [] }
    var consoleIdentities: [Identity] { vault?.identities ?? [] }
    var consoleLocalServices: [LocalService] { vault?.localServices ?? [] }

    /// Resolve `ssh` against the vault and open a session.
    ///
    /// A saved host wins over an ad-hoc one so that `ssh noether` inherits its
    /// key, TERM, font size and startup command — typing a name you already
    /// configured should not quietly give you a different, dumber connection.
    func consoleOpenSSH(_ request: ConsoleSSHRequest) -> String {
        guard let vault else { return "the vault isn't ready yet" }

        let needle = request.host.lowercased()
        // The last two clauses are what makes a scanned host usable: reverse
        // DNS hands back "noether.lan" and Bonjour "noether", so the alias a
        // LAN import saved is rarely the bare name someone types. Matching the
        // first label of either is the difference between `ssh noether` and
        // having to remember which form the scan happened to learn.
        let saved = vault.hosts.first { $0.alias.lowercased() == needle }
            ?? vault.hosts.first { $0.hostname.lowercased() == needle }
            ?? vault.hosts.first { SessionManager.firstLabel(of: $0.alias) == needle }
            ?? vault.hosts.first { SessionManager.firstLabel(of: $0.hostname) == needle }

        var host = saved ?? Host(
            alias: "",
            hostname: request.host,
            port: 22,
            username: request.user ?? NSUserName(),
            group: "Ad hoc",
            term: settings?.defaultTerm ?? "xterm-256color"
        )

        // An ad-hoc host must not be written to the vault: typing a hostname
        // once is not the same as saving it, and silently accumulating hosts
        // from typos would be its own annoyance.
        if let user = request.user { host.username = user }
        if let port = request.port { host.port = port }

        if let name = request.identityName {
            guard let identity = vault.identities.first(where: {
                $0.name.compare(name, options: .caseInsensitive) == .orderedSame
            }) else {
                let known = vault.identities.map(\.name).joined(separator: ", ")
                return "no key named \"\(name)\""
                    + (known.isEmpty ? "" : " (have: \(known))")
            }
            host.identityID = identity.id
            host.usesPassword = false
        }

        guard !host.username.isEmpty else {
            return "no username — try ssh user@\(host.hostname)"
        }

        do {
            try connect(to: host)
            let via = vault.identity(withID: host.identityID).map { " using key \($0.name)" } ?? ""
            return "connecting to \(host.username)@\(host.destination)\(via)…"
        } catch {
            return error.localizedDescription
        }
    }

    /// "noether.lan" -> "noether". An IPv4 literal has no label worth taking,
    /// so it is left whole rather than becoming its first octet.
    nonisolated static func firstLabel(of name: String) -> String {
        let lowered = name.lowercased()
        guard LANSubnet.parse(lowered) == nil else { return lowered }
        return String(lowered.prefix(while: { $0 != "." }))
    }
}
