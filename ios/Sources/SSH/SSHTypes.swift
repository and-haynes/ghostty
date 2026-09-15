import Foundation

// Vocabulary shared by the SSH layer and the UI. Nothing in this file imports
// NIO: the terminal view, the status bar and the tests should be able to talk
// about connection state without pulling the networking stack in.

// MARK: - Connection state

/// Where a session is in its lifecycle. Drives the status bar verbatim.
enum SSHConnectionState: Equatable, Sendable {
    case idle
    case resolving
    case connecting
    case verifyingHostKey
    case authenticating
    case connected
    case reconnecting(attempt: Int)
    /// A closed session. `reason` is nil for a disconnect we initiated.
    case disconnected(reason: String?)
    case failed(message: String)

    /// True while the session owns network resources (or is trying to). Use
    /// this to decide whether "Disconnect" should be offered, and to refuse a
    /// second `connect()` on a live session.
    var isActive: Bool {
        switch self {
        case .resolving, .connecting, .verifyingHostKey, .authenticating, .connected,
            .reconnecting:
            return true
        case .idle, .disconnected, .failed:
            return false
        }
    }

    /// True only when a shell is actually running at the far end — i.e. when
    /// it is safe to send keystrokes.
    var isConnected: Bool { self == .connected }

    /// Short human phrase for the status bar. Sentence case, no trailing dot.
    var label: String {
        switch self {
        case .idle:
            return "Not connected"
        case .resolving:
            return "Looking up host"
        case .connecting:
            return "Connecting"
        case .verifyingHostKey:
            return "Checking host key"
        case .authenticating:
            return "Authenticating"
        case .connected:
            return "Connected"
        case .reconnecting(let attempt):
            return "Reconnecting (attempt \(attempt))"
        case .disconnected(let reason):
            guard let reason, !reason.isEmpty else { return "Disconnected" }
            return "Disconnected — \(reason)"
        case .failed(let message):
            return message
        }
    }

    /// Whether the status bar should render in its error style.
    ///
    /// Deliberately false for `.disconnected`: a session ending — even because
    /// the far end hung up — is an outcome, not a fault. Only `.failed` means
    /// "this did not work and you should look at why". The detail lives in
    /// `SSHSession.lastError`.
    var isError: Bool {
        if case .failed = self { return true }
        return false
    }
}

// MARK: - Authentication

/// One thing we are willing to try when the server asks us to authenticate.
///
/// `@unchecked Sendable`: the payloads are immutable value types, but
/// `SSHPrivateKeyMaterial` wraps CryptoKit key handles whose `Sendable`
/// conformance we do not control. They are never mutated after construction,
/// so crossing an isolation boundary with one is safe.
enum SSHAuthMethod: @unchecked Sendable {
    case password(String)
    case privateKey(SSHPrivateKeyMaterial)
    /// The "none" method — some servers (and some jump-box setups) accept it,
    /// and it is also the polite way to ask a server which methods it wants.
    case none

    /// Which NIOSSH auth method this offer satisfies, so the delegate can skip
    /// offers the server has already said it will not accept.
    var requiresPublicKeyMethod: Bool {
        if case .privateKey = self { return true }
        return false
    }

    var requiresPasswordMethod: Bool {
        if case .password = self { return true }
        return false
    }

    /// Never include secret material — this string ends up in logs and in the
    /// `authenticationFailed` message shown to the user.
    var debugLabel: String {
        switch self {
        case .password: return "password"
        case .privateKey(let material): return "public key (\(material.keyType.displayName))"
        case .none: return "none"
        }
    }
}

// MARK: - Connection request

/// Everything needed to open one interactive session. Assembled by
/// `SSHConnectionCoordinator` from a `Host`, or by hand in tests.
struct SSHConnectionRequest: Sendable, Equatable {
    var hostname: String
    var port: Int
    var username: String
    /// TERM to request in the pty. Remote machines almost never have ghostty's
    /// terminfo installed, so the sane default is xterm-256color.
    var term: String
    var cols: Int
    var rows: Int
    /// Run this instead of an interactive login shell (`exec` rather than
    /// `shell`). Nil or empty means "give me a shell".
    var startupCommand: String?
    /// Sent as one `env` request each. Most sshd configs only accept names
    /// listed in `AcceptEnv`, so these are best-effort and never fatal.
    var environment: [String: String]

    init(
        hostname: String,
        port: Int = 22,
        username: String,
        term: String = "xterm-256color",
        cols: Int = 80,
        rows: Int = 24,
        startupCommand: String? = nil,
        environment: [String: String] = ["LANG": "en_US.UTF-8"]
    ) {
        self.hostname = hostname
        self.port = port
        self.username = username
        self.term = term
        self.cols = cols
        self.rows = rows
        self.startupCommand = startupCommand
        self.environment = environment
    }

    /// "user@host" or "user@host:port" — for error messages and the title bar.
    var destinationDescription: String {
        port == 22 ? "\(username)@\(hostname)" : "\(username)@\(hostname):\(port)"
    }
}

// MARK: - Errors

/// Every failure the SSH layer can surface. `errorDescription` is shown to the
/// user verbatim, so each one has to say what happened *and* what to do next.
enum SSHError: Error, LocalizedError, Equatable, Sendable {
    /// The user was asked to trust a new host key and said no.
    case hostKeyRejectedByUser
    /// The pinned key for this endpoint does not match the key presented.
    case hostKeyMismatch(expected: String, presented: String)
    case authenticationFailed(String)
    case noAuthenticationMethods
    /// The server will only do keyboard-interactive, which NIOSSH cannot do.
    case keyboardInteractiveUnsupported
    case rsaKeysUnsupported
    case channelClosed(String?)
    case notConnected
    case connectionFailed(String)

    var errorDescription: String? {
        switch self {
        case .hostKeyRejectedByUser:
            return """
                You chose not to trust this server's host key, so the connection \
                was closed. Nothing was sent to the server.
                """

        case .hostKeyMismatch(let expected, let presented):
            // The loud one. A changed host key is either a rebuilt server or
            // someone sitting in the middle of the connection, and we cannot
            // tell which — so we refuse and say so plainly. There is
            // deliberately no "connect anyway" button anywhere in this app.
            return """
                WARNING: THE HOST KEY HAS CHANGED.

                Someone may be intercepting this connection, or the server may \
                have been rebuilt or replaced.

                Expected: \(expected)
                Presented: \(presented)

                The connection was refused before your username, password or key \
                was sent. If you know the server was rebuilt, remove its saved \
                key in Settings › Known Hosts and connect again. If you don't, \
                do not connect — check with whoever runs the server first.
                """

        case .authenticationFailed(let detail):
            return "Authentication failed. \(detail)"

        case .noAuthenticationMethods:
            return """
                There's nothing to authenticate with. Attach an identity key to \
                this host, or turn on password authentication for it, and try \
                again.
                """

        case .keyboardInteractiveUnsupported:
            return """
                This server only offers keyboard-interactive authentication \
                (the type used for one-time codes and PAM prompts), which this \
                app can't do. Enable password or public-key authentication on \
                the server, or connect with a key instead.
                """

        case .rsaKeysUnsupported:
            return """
                RSA keys aren't supported. This app's SSH stack can only sign \
                with Ed25519 and ECDSA (P-256/384/521) keys. Generate an Ed25519 \
                key and add it to the server's authorized_keys.
                """

        case .channelClosed(let detail):
            guard let detail, !detail.isEmpty else {
                return "The remote session closed."
            }
            return "The remote session closed: \(detail)"

        case .notConnected:
            return "Not connected. Open the connection before sending input."

        case .connectionFailed(let detail):
            return "Couldn't connect. \(detail)"
        }
    }
}

extension SSHError {
    /// Two or three words for the status bar, where `errorDescription` — which
    /// is a paragraph for the serious ones — will not fit. The full text goes
    /// in `SSHSession.lastError` and belongs in an alert or a detail sheet.
    var summary: String {
        switch self {
        case .hostKeyRejectedByUser: return "Host key not trusted"
        case .hostKeyMismatch: return "HOST KEY CHANGED"
        case .authenticationFailed: return "Authentication failed"
        case .noAuthenticationMethods: return "No credentials"
        case .keyboardInteractiveUnsupported: return "Unsupported authentication"
        case .rsaKeysUnsupported: return "RSA keys unsupported"
        case .channelClosed: return "Session closed"
        case .notConnected: return "Not connected"
        case .connectionFailed: return "Connection failed"
        }
    }
}

// MARK: - Bytes coming back from the remote

/// One run of bytes from the remote, tagged with which stream it arrived on.
///
/// Reads are delivered as an *ordered array* of these rather than one callback
/// per chunk: it lets the channel handler coalesce a whole read burst into a
/// single main-queue hop without ever reordering stdout against stderr.
struct SSHOutputSegment: Sendable {
    enum Stream: Sendable, Equatable {
        case stdout
        case stderr
    }

    var stream: Stream
    var bytes: Data
}

/// Out-of-band things that happen on the session channel.
enum SSHSessionChannelEvent: Sendable {
    case exitStatus(Int)
    case exitSignal(name: String, message: String, dumpedCore: Bool)
    /// The channel went away. `reason` is nil for an orderly close.
    case closed(reason: String?)
}
