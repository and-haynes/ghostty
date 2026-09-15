import Combine
import Foundation

/// Adapts an `SSHSession` to the terminal's `TerminalTransport` seam.
///
/// The terminal knows nothing about SSH and the SSH layer knows nothing about
/// terminals; this is the twenty lines that join them. Keeping the seam means
/// `ConsoleTransport` can stand in for a real connection, which is how the
/// renderer gets tested without a server.
@MainActor
final class SSHTransport: TerminalTransport {
    var onReceive: ((Data) -> Void)?
    var onStatusChange: (() -> Void)?

    private(set) var statusLabel: String = "idle"
    private(set) var isConnected = false
    private(set) var isError = false

    private let host: Host
    private let vault: Vault
    private let defaultTerm: String
    private let session: SSHSession
    private let passwordPrompt: SSHConnectionCoordinator.PasswordPrompt?
    private var cancellables = Set<AnyCancellable>()
    private var connectTask: Task<Void, Never>?
    private var lastHapticState: SSHConnectionState?

    init(
        host: Host,
        vault: Vault,
        defaultTerm: String,
        prompter: any HostKeyPrompter,
        passwordPrompt: SSHConnectionCoordinator.PasswordPrompt? = nil
    ) {
        self.host = host
        self.vault = vault
        self.defaultTerm = defaultTerm
        self.passwordPrompt = passwordPrompt
        self.session = SSHSession(vault: vault)
        session.hostKeyPrompter = prompter

        session.onData = { [weak self] data in self?.onReceive?(data) }
        // stderr from the far end belongs on screen too: a login failure
        // message that only exists in a log the user cannot see is useless.
        session.onStdErr = { [weak self] data in self?.onReceive?(data) }

        session.$state
            .receive(on: RunLoop.main)
            .sink { [weak self] state in self?.apply(state) }
            .store(in: &cancellables)
    }

    // MARK: - TerminalTransport

    func start(cols: Int, rows: Int) {
        connectTask?.cancel()
        connectTask = Task { [weak self] in
            guard let self else { return }
            do {
                let plan = try await SSHConnectionCoordinator.plan(
                    for: self.host,
                    identity: self.vault.identity(withID: self.host.identityID),
                    vault: self.vault,
                    cols: cols,
                    rows: rows,
                    promptForPassword: self.passwordPrompt
                )
                var request = plan.request
                if request.term.isEmpty { request.term = self.defaultTerm }
                try await self.session.connect(request, auth: plan.authMethods)
            } catch {
                self.fail(with: error)
            }
        }
    }

    func send(_ data: Data) {
        session.send(data)
    }

    func resize(cols: Int, rows: Int, pixelWidth: Int, pixelHeight: Int) {
        session.resize(cols: cols, rows: rows, pixelWidth: pixelWidth, pixelHeight: pixelHeight)
    }

    func stop() {
        connectTask?.cancel()
        Task { await session.disconnect() }
    }

    func reconnect() {
        Task { await session.reconnect() }
    }

    // MARK: - State plumbing

    private func apply(_ state: SSHConnectionState) {
        hapticFor(state)
        statusLabel = "\(host.username)@\(host.destination) · \(state.label)"
        isConnected = state.isConnected
        isError = state.isError
        if let message = session.lastError, state.isError {
            statusLabel = message
        }
        onStatusChange?()
    }

    /// One buzz per meaningful transition, and only on a transition — `apply`
    /// runs for every published state including repeats.
    private func hapticFor(_ state: SSHConnectionState) {
        guard state != lastHapticState else { return }
        lastHapticState = state
        switch state {
        case .connected:
            Haptics.shared.fire(.connected)
        case .reconnecting:
            Haptics.shared.fire(.reconnecting)
        case .disconnected:
            Haptics.shared.fire(.disconnected)
        case .failed:
            Haptics.shared.fire(.authenticationFailed)
        default:
            break
        }
    }

    private func fail(with error: Error) {
        let sshError = error as? SSHError ?? SSHSession.translate(error)
        // A host key that does not match its pin is not the same class of
        // problem as a wrong password, and should not feel like one.
        if case .hostKeyMismatch = sshError {
            Haptics.shared.fire(.hostKeyMismatch)
        } else {
            Haptics.shared.fire(.authenticationFailed)
        }
        isError = true
        isConnected = false
        statusLabel = sshError.summary
        onStatusChange?()
        // Put the reason on screen as well as in the status bar: the status bar
        // truncates and the terminal is where the user is looking.
        onReceive?(Data("\r\n\u{1b}[1;31m\(sshError.localizedDescription)\u{1b}[0m\r\n".utf8))
    }
}
