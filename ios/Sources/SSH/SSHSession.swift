import Combine
import Dispatch
import Foundation
import NIOCore
import NIOPosix
import NIOSSH

// MARK: - Event loop group

/// The one event loop group the whole app uses.
///
/// One thread, created lazily on first use, and **never shut down**. That is
/// deliberate: `syncShutdownGracefully()` blocks the calling thread, and on iOS
/// the only moment we would want to call it is app termination — when the
/// process is about to be reclaimed anyway. Shutting it down at any other point
/// would break every other session in the app. (NIO's own
/// `MultiThreadedEventLoopGroup.singleton` exists for exactly this reason and
/// behaves the same way; we keep our own so the thread count is ours to pick.)
///
/// One thread is plenty for terminal traffic and has a useful side effect: all
/// of a connection's channels — parent and children — share a loop, so reads
/// are delivered in a single, totally ordered stream.
enum SSHEventLoopGroupProvider {
    static let shared: MultiThreadedEventLoopGroup = MultiThreadedEventLoopGroup(numberOfThreads: 1)
}

// MARK: - Terminal modes

extension SSHTerminalModes {
    /// POSIX modes for an interactive login shell.
    ///
    /// The remote side is a real pty doing canonical-mode line editing and
    /// signal generation; libghostty-vt on our end is a dumb-ish renderer that
    /// just wants the resulting byte stream. So: echo on, signals on, CR→NL on
    /// input, NL→CRNL on output — i.e. what OpenSSH's client asks for.
    static let interactiveDefaults = SSHTerminalModes([
        // Input
        .ICRNL: 1,  // Return key sends CR; the shell wants NL.
        .IXON: 1,  // ^S/^Q flow control, as users expect.
        .IMAXBEL: 1,
        // Local
        .ISIG: 1,  // ^C / ^Z produce signals rather than literal bytes.
        .ICANON: 1,
        .IEXTEN: 1,
        .ECHO: 1,  // The remote echoes; we never echo locally.
        .ECHOE: 1,
        .ECHOK: 1,
        .ECHOCTL: 1,
        .ECHOKE: 1,
        // Output
        .OPOST: 1,
        .ONLCR: 1,
        // Control
        .CS8: 1,  // 8-bit clean — required for UTF-8.
        // Special characters, matching a modern Linux/macOS tty.
        .VINTR: 3,  // ^C
        .VQUIT: 28,  // ^\
        .VERASE: 127,  // DEL, not ^H — this is what iOS's Delete key sends.
        .VKILL: 21,  // ^U
        .VEOF: 4,  // ^D
        .VSTART: 17,  // ^Q
        .VSTOP: 19,  // ^S
        .VSUSP: 26,  // ^Z
        .VREPRINT: 18,  // ^R
        .VWERASE: 23,  // ^W
        .VLNEXT: 22,  // ^V
        // Nominal line speed. Some programs (notably vi) read this to decide
        // how lazy they can be about redrawing; claim something fast.
        .TTY_OP_ISPEED: 38400,
        .TTY_OP_OSPEED: 38400,
    ])
}

// MARK: - Transport error handler

/// Sits at the end of the *parent* channel's pipeline and turns transport-level
/// blow-ups into something a person can read, stashing them where the session
/// can find them before the channel dies and takes the context with it.
private final class SSHTransportErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private let failureRecorder: SSHFailureRecorder

    init(failureRecorder: SSHFailureRecorder) {
        self.failureRecorder = failureRecorder
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.failureRecorder.record(SSHSession.translate(error))
        context.close(promise: nil)
    }
}

// MARK: - Session channel handler

/// Lives in the session child channel and owns everything that happens there:
/// it issues `pty-req`/`env`/`shell`, correlates the replies, and pumps inbound
/// bytes out to the session.
///
/// Entirely event-loop confined — every method here runs on the child channel's
/// loop, so the mutable state needs no locking. The only things that leave are
/// the two `@Sendable` sinks.
private final class SSHSessionChannelHandler: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData

    /// Channel requests we asked for a reply to, in the order we asked. RFC 4254
    /// §4 guarantees the peer replies in request order, so a FIFO is enough to
    /// know which `ChannelSuccess`/`ChannelFailure` belongs to which request.
    private enum PendingReply {
        case pseudoTerminal
        case startup
    }

    private let request: SSHConnectionRequest
    private let startupPromise: EventLoopPromise<Void>
    private let onOutput: @Sendable ([SSHOutputSegment]) -> Void
    private let onEvent: @Sendable (SSHSessionChannelEvent) -> Void

    private var pendingReplies: [PendingReply] = []
    private var pendingOutput: [SSHOutputSegment] = []
    private var startupResolved = false
    private var closeReason: String?

    init(
        request: SSHConnectionRequest,
        startupPromise: EventLoopPromise<Void>,
        onOutput: @escaping @Sendable ([SSHOutputSegment]) -> Void,
        onEvent: @escaping @Sendable (SSHSessionChannelEvent) -> Void
    ) {
        self.request = request
        self.startupPromise = startupPromise
        self.onOutput = onOutput
        self.onEvent = onEvent
    }

    // MARK: Lifecycle

    func channelActive(context: ChannelHandlerContext) {
        context.fireChannelActive()

        // The child channel is open and confirmed; now turn it into a terminal.
        // Order is load-bearing: pty first, then environment, then the shell —
        // a shell started before the pty exists comes up with TERM=dumb and no
        // job control.
        let pty = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: self.request.term,
            terminalCharacterWidth: max(self.request.cols, 1),
            terminalRowHeight: max(self.request.rows, 1),
            // Zero means "use the character dimensions", which is what we want:
            // the remote only ever needs rows/cols.
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            terminalModes: .interactiveDefaults
        )
        self.pendingReplies.append(.pseudoTerminal)
        context.triggerUserOutboundEvent(pty, promise: nil)

        // Sorted so the order is reproducible in logs and tests. `wantReply` is
        // false on purpose: most sshd configs only honour names listed in
        // `AcceptEnv` and reject the rest, and a rejected LANG must not take the
        // session down with it.
        for (name, value) in self.request.environment.sorted(by: { $0.key < $1.key }) {
            let env = SSHChannelRequestEvent.EnvironmentRequest(
                wantReply: false,
                name: name,
                value: value
            )
            context.triggerUserOutboundEvent(env, promise: nil)
        }

        self.pendingReplies.append(.startup)
        if let command = self.request.startupCommand, !command.isEmpty {
            let exec = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
            context.triggerUserOutboundEvent(exec, promise: nil)
        } else {
            let shell = SSHChannelRequestEvent.ShellRequest(wantReply: true)
            context.triggerUserOutboundEvent(shell, promise: nil)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        // Flush before announcing the close so the terminal renders the last
        // bytes (a shell's goodbye, a command's final line) before the UI says
        // the session ended.
        self.flushOutput()
        self.resolveStartup(
            failure: .channelClosed(self.closeReason ?? "The session ended before the shell started.")
        )
        self.onEvent(.closed(reason: self.closeReason))
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        // Belt and braces: an unfulfilled promise is a hard error in NIO.
        self.resolveStartup(failure: .channelClosed(self.closeReason))
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        let translated = SSHSession.translate(error)
        self.closeReason = translated.errorDescription
        self.resolveStartup(failure: translated)
        context.close(promise: nil)
    }

    // MARK: Inbound data

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = channelData.data, buffer.readableBytes > 0 else {
            return
        }

        let stream: SSHOutputSegment.Stream
        switch channelData.type {
        case .channel:
            stream = .stdout
        case .stdErr:
            stream = .stderr
        default:
            // An extended data type we don't know. It is not terminal output;
            // dropping it is better than writing garbage into the VT parser.
            return
        }

        let bytes = Data(buffer.readableBytesView)

        // Coalesce adjacent same-stream runs. This is what lets a whole read
        // burst cross to the main actor in one hop without disturbing the
        // relative order of stdout and stderr.
        if let last = self.pendingOutput.last, last.stream == stream {
            self.pendingOutput[self.pendingOutput.count - 1].bytes.append(bytes)
        } else {
            self.pendingOutput.append(SSHOutputSegment(stream: stream, bytes: bytes))
        }
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        self.flushOutput()
        context.fireChannelReadComplete()
    }

    // MARK: Channel requests and replies

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case is ChannelSuccessEvent:
            self.handleReply(succeeded: true, context: context)

        case is ChannelFailureEvent:
            self.handleReply(succeeded: false, context: context)

        case let status as SSHChannelRequestEvent.ExitStatus:
            self.flushOutput()
            self.onEvent(.exitStatus(status.exitStatus))

        case let signal as SSHChannelRequestEvent.ExitSignal:
            self.flushOutput()
            self.closeReason = "killed by SIG\(signal.signalName)"
            self.onEvent(
                .exitSignal(
                    name: signal.signalName,
                    message: signal.errorMessage,
                    dumpedCore: signal.dumpedCore
                )
            )

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    private func handleReply(succeeded: Bool, context: ChannelHandlerContext) {
        guard !self.pendingReplies.isEmpty else {
            // A reply to something we didn't ask about. Harmless; ignore it.
            return
        }
        let reply = self.pendingReplies.removeFirst()

        switch (reply, succeeded) {
        case (.pseudoTerminal, true):
            break  // Good. Wait for the shell reply.

        case (.startup, true):
            self.resolveStartupSuccess()

        case (.pseudoTerminal, false):
            // No pty means no interactive terminal at all. Fail rather than
            // hand the user a shell with no job control and TERM unset.
            self.resolveStartup(
                failure: .connectionFailed(
                    "The server refused to allocate a pseudo-terminal. If this is a "
                        + "restricted or command-only account, it can't host an "
                        + "interactive shell."
                )
            )
            context.close(promise: nil)

        case (.startup, false):
            let what =
                (self.request.startupCommand?.isEmpty == false)
                ? "run the startup command" : "start a shell"
            self.resolveStartup(
                failure: .connectionFailed(
                    "The server refused to \(what) for \"\(self.request.username)\". The "
                        + "account may have a forced command, or no shell assigned."
                )
            )
            context.close(promise: nil)
        }
    }

    // MARK: Helpers

    private func flushOutput() {
        guard !self.pendingOutput.isEmpty else { return }
        let batch = self.pendingOutput
        self.pendingOutput.removeAll(keepingCapacity: true)
        self.onOutput(batch)
    }

    private func resolveStartupSuccess() {
        guard !self.startupResolved else { return }
        self.startupResolved = true
        self.startupPromise.succeed(())
    }

    private func resolveStartup(failure: SSHError) {
        guard !self.startupResolved else { return }
        self.startupResolved = true
        self.startupPromise.fail(failure)
    }
}

// MARK: - Session

/// One SSH connection carrying one interactive session. This is the object a
/// terminal view owns and talks to.
///
/// Isolation model, because it is the thing most likely to be got wrong here:
///
/// * The class is `@MainActor`. Every property, every published change, and
///   both output callbacks happen on the main actor. A terminal view can read
///   `state` and call `send(_:)` without ceremony.
/// * NIO calls back on its own loop thread. Those callbacks never touch this
///   object directly — they go through `@Sendable` sinks that hop via
///   `DispatchQueue.main.async`.
/// * `DispatchQueue.main.async` rather than `Task { @MainActor in … }` is a
///   correctness requirement, not a style choice — see `makeOutputSink`.
@MainActor
final class SSHSession: ObservableObject {
    // MARK: Published state

    @Published private(set) var state: SSHConnectionState = .idle
    /// Full, user-facing text of the most recent failure. `state.label` is the
    /// short version for a status bar; this is the one to put in an alert.
    @Published private(set) var lastError: String?
    /// Exit status of the remote command, once it has exited.
    @Published private(set) var exitStatus: Int?

    // MARK: Callbacks

    /// Bytes from the remote's stdout, delivered on the main actor in arrival
    /// order. Feed these straight to `ghostty_terminal_vt_write`.
    var onData: ((Data) -> Void)?
    /// Bytes from the remote's stderr. With a pty attached the remote usually
    /// merges stderr into stdout, so this normally only fires for `exec`.
    var onStdErr: ((Data) -> Void)?

    /// Asked to confirm host keys we have never seen.
    ///
    /// Weak: the prompter is almost always the view model that owns this
    /// session, and a strong reference here would be a retain cycle. If it has
    /// gone away when an unknown key shows up, we refuse the connection rather
    /// than trust silently.
    weak var hostKeyPrompter: (any HostKeyPrompter)?

    /// Certificate authorities trusted to vouch for a host, from Settings.
    ///
    /// Two things turn on this being non-empty: the client offers the
    /// `*-cert-v01@openssh.com` host key algorithms, so a certified host gets
    /// the chance to present its certificate; and ``TOFUHostKeyDelegate`` has
    /// something to check one against. Empty — the default — leaves host
    /// verification exactly as it was: plain keys, trust on first use.
    var trustedHostAuthorities: [NIOSSHPublicKey] = []

    /// Held strongly and for the session's whole life.
    ///
    /// The vault is an app-lifetime object, and the session must be able to
    /// consult and update the known-hosts pin at any point during a handshake.
    /// A weak reference would introduce a state where a nil vault silently
    /// disables host key pinning — precisely the failure we must not have.
    private let vault: Vault

    // MARK: Connection

    private var parentChannel: Channel?
    private var childChannel: Channel?
    private var lastRequest: SSHConnectionRequest?
    /// Retained so `reconnect()` can re-authenticate without another round of
    /// prompts. Note this keeps any password (and any unlocked key handle) in
    /// memory for the life of the session — the cost of seamless reconnects on
    /// a phone that drops Wi-Fi constantly. Dropped by `disconnect()`.
    private var lastAuth: [SSHAuthMethod]?

    /// Bumped on every connection attempt. Callbacks capture the value current
    /// when they were created and drop anything that arrives after a newer
    /// attempt has begun — without it, a dying old channel's `.closed` event
    /// would knock a freshly established session offline.
    private var generation: UInt64 = 0
    /// Suppresses the fine-grained progress states during a reconnect, so the
    /// status bar can keep showing "Reconnecting (attempt 3)".
    private var publishesProgress = true

    // `nonisolated`: pure constants and pure functions, needed from the NIO
    // event loop (the pipeline error handler) as well as from the main actor.
    nonisolated static let maxReconnectAttempts = 5
    nonisolated private static let connectTimeout = TimeAmount.seconds(20)
    nonisolated private static let handshakeTimeout = TimeAmount.seconds(30)

    init(vault: Vault) {
        self.vault = vault
    }

    // MARK: - Connect

    func connect(_ request: SSHConnectionRequest, auth: [SSHAuthMethod]) async throws {
        guard !self.state.isActive else {
            throw SSHError.connectionFailed(
                "A session to \(self.lastRequest?.destinationDescription ?? "this host") is "
                    + "already open. Disconnect it before starting another."
            )
        }
        guard !auth.isEmpty else {
            self.publish(failure: .noAuthenticationMethods)
            throw SSHError.noAuthenticationMethods
        }

        self.lastRequest = request
        self.lastAuth = auth
        self.exitStatus = nil
        self.lastError = nil

        do {
            try await self.establish(request, auth: auth, publishesProgress: true)
        } catch let error as SSHError {
            guard case .negotiationFailed = error else { throw error }
            try await self.retryOrExplainNegotiationFailure(error, request: request, auth: auth)
        }
    }

    /// Turn a bare negotiation failure into either a working connection or an
    /// explanation.
    ///
    /// swift-nio-ssh reports "no algorithm in common" as
    /// `NIOSSHError.keyExchangeNegotiationFailure` and nothing else — not which
    /// of the four negotiations failed, not what the server wanted. The server's
    /// whole menu is sent in the clear before any negotiation, though, so we can
    /// simply go and read it.
    ///
    /// Two things come out of that:
    ///
    /// * **A retry that can succeed**, with a scheme list widened to whatever
    ///   this server's key exchange can key. Since #008D0 the library expands
    ///   key material per RFC 4253 §7.2, so every scheme is offerable on every
    ///   connection and the widened list is the same list — but the machinery
    ///   stays, because the next scheme that outgrows an exchange will need it
    ///   and this is where the decision belongs.
    /// * **An error worth reading**, naming the server's algorithms, ours, and
    ///   what is missing.
    private func retryOrExplainNegotiationFailure(
        _ failure: SSHError,
        request: SSHConnectionRequest,
        auth: [SSHAuthMethod]
    ) async throws {
        let offer: SSHServerOffer
        do {
            offer = try await SSHServerProbe.read(host: request.hostname, port: request.port)
        } catch {
            // The probe is a diagnostic, not a dependency: if it cannot reach
            // the server either, report the original failure unembellished.
            self.publish(failure: failure)
            throw failure
        }

        let hashBytes = SSHAlgorithmSupport.negotiatedKeyExchange(with: offer)?.hashBytes ?? 0
        if hashBytes >= 64 {
            let extended = SSHTransportProtectionCatalog.schemes(keyExchangeHashBytes: hashBytes)
            let widened = SSHAlgorithmMismatch(
                hostname: request.hostname,
                offer: offer,
                supportedHostKeys: SSHAlgorithmSupport.offeredHostKeyAlgorithms(
                    trustingCertificateAuthorities: !self.trustedHostAuthorities.isEmpty
                ),
                supportedCiphers: SSHTransportProtectionCatalog.cipherNames(extended),
                supportedMACs: SSHTransportProtectionCatalog.macNames(extended)
            )
            if widened.canNegotiate {
                try await self.establish(
                    request,
                    auth: auth,
                    publishesProgress: true,
                    schemes: extended
                )
                return
            }
        }

        let mismatch = SSHAlgorithmMismatch(
            hostname: request.hostname,
            offer: offer,
            supportedHostKeys: SSHAlgorithmSupport.offeredHostKeyAlgorithms(
                trustingCertificateAuthorities: !self.trustedHostAuthorities.isEmpty
            )
        )
        let explained = SSHError.negotiationFailed(
            headline: mismatch.summary,
            detail: mismatch.explanation
        )
        self.publish(failure: explained)
        throw explained
    }

    private func establish(
        _ request: SSHConnectionRequest,
        auth: [SSHAuthMethod],
        publishesProgress: Bool,
        schemes: [NIOSSHTransportProtection.Type] = SSHTransportProtectionCatalog.clientSchemes
    ) async throws {
        // Boxed so the metatypes can cross into the channel initialiser, which
        // is `@Sendable`. See `SSHTransportProtectionSchemes`.
        let protection = SSHTransportProtectionSchemes(schemes)
        self.generation &+= 1
        let generation = self.generation
        self.publishesProgress = publishesProgress

        // Where the delegates leave the *real* reason a handshake died. Once a
        // delegate fails its promise NIOSSH tears the connection down, and every
        // future after that point reports a generic `ChannelError.eof`, which is
        // useless to a user.
        let recorder = SSHFailureRecorder()

        // Set directly rather than via `advance`, which deliberately refuses to
        // move out of a settled state — this *is* the fresh start.
        if publishesProgress {
            self.state = .resolving
        }

        let authorities = self.trustedHostAuthorities
        let hostKeyAlgorithms = SSHAlgorithmSupport.offeredHostKeyAlgorithms(
            trustingCertificateAuthorities: !authorities.isEmpty
        ).map { Substring($0) }

        let hostKeyDelegate = TOFUHostKeyDelegate(
            hostname: request.hostname,
            port: request.port,
            failureRecorder: recorder,
            trustedAuthorities: authorities
        ) { [weak self] keyType, fingerprint, publicKeyLine in
            guard let self else {
                return .failure(.notConnected)
            }
            return await self.evaluateHostKey(
                generation: generation,
                hostname: request.hostname,
                port: request.port,
                keyType: keyType,
                fingerprint: fingerprint,
                publicKeyLine: publicKeyLine
            )
        }

        let authDelegate = SSHUserAuthDelegate(
            username: request.username,
            methods: auth,
            failureRecorder: recorder
        ) { [weak self] in
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    self?.advance(to: .authenticating, generation: generation)
                }
            }
        }

        // TODO(jump host): per-host ProxyJump would slot in here. Instead of a
        // `ClientBootstrap` straight to `request.hostname`, connect to the jump
        // host first, then ask its `NIOSSHHandler` for a
        // `.directTCPIP(targetHost: request.hostname, targetPort: request.port)`
        // child channel and run this same `NIOSSHHandler` pipeline inside it
        // (see NIOSSHClient's PortForwardingServer for the channel-in-channel
        // shape). Everything below — TOFU, user auth, the session channel — is
        // unchanged; only how we obtain the byte stream differs.
        let bootstrap = ClientBootstrap(group: SSHEventLoopGroupProvider.shared)
            .connectTimeout(Self.connectTimeout)
            // Terminals write one keystroke at a time. Nagle would hold those
            // back waiting for company and make local echo feel broken.
            .channelOption(ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY), value: 1)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let sync = channel.pipeline.syncOperations
                    var configuration = SSHClientConfiguration(
                        userAuthDelegate: authDelegate,
                        serverAuthDelegate: hostKeyDelegate,
                        globalRequestDelegate: nil,
                        // swift-nio-ssh offers the two OpenSSH AES-GCM modes and
                        // nothing else, which leaves every router, NAS and
                        // Dropbear box unreachable. See
                        // `SSHTransportProtectionCatalog` for what this adds and
                        // the order it adds it in.
                        transportProtectionSchemes: protection.schemes
                    )
                    // Certificate algorithms only when there is a CA to judge
                    // them with; see `trustedHostAuthorities`.
                    configuration.serverHostKeyAlgorithms = hostKeyAlgorithms
                    let ssh = NIOSSHHandler(
                        role: .client(configuration),
                        allocator: channel.allocator,
                        // We never accept channels opened by the server.
                        inboundChildChannelInitializer: nil
                    )
                    try sync.addHandler(ssh)
                    try sync.addHandler(SSHTransportErrorHandler(failureRecorder: recorder))
                }
            }

        self.advance(to: .connecting, generation: generation)

        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: request.hostname, port: request.port).get()
        } catch {
            let failure = recorder.recorded ?? Self.translate(error, connectingTo: request)
            self.publish(failure: failure, generation: generation)
            throw failure
        }
        self.parentChannel = channel

        // The TCP connect future fires the moment the socket is up, long before
        // key exchange and user auth finish. A server that accepts the socket
        // and then says nothing would leave us waiting forever, so put a clock
        // on the rest of the handshake.
        let deadline = channel.eventLoop.scheduleTask(in: Self.handshakeTimeout) {
            recorder.record(
                .connectionFailed(
                    "The SSH handshake with \(request.hostname) timed out. The server "
                        + "accepted the connection but never finished negotiating."
                )
            )
            channel.close(promise: nil)
        }

        let startupPromise = channel.eventLoop.makePromise(of: Void.self)
        let childPromise = channel.eventLoop.makePromise(of: Channel.self)
        let outputSink = self.makeOutputSink(generation: generation)
        let eventSink = self.makeEventSink(generation: generation)

        // `NIOSSHHandler.createChannel` is explicitly not thread-safe; it has to
        // be called on the channel's loop. `pipeline.handler(type:)` completes
        // there, so this closure is already in the right place.
        channel.pipeline.handler(type: NIOSSHHandler.self).whenComplete { result in
            switch result {
            case .failure(let error):
                childPromise.fail(error)

            case .success(let sshHandler):
                sshHandler.createChannel(childPromise, channelType: .session) { childChannel, channelType in
                    guard channelType == .session else {
                        return childChannel.eventLoop.makeFailedFuture(
                            SSHError.connectionFailed(
                                "The server opened an unexpected kind of SSH channel."
                            )
                        )
                    }
                    // `allowRemoteHalfClosure` first: without it, a remote that
                    // closes its side (a shell exiting) tears the channel down
                    // before we can read the last of its output or its exit
                    // status. The handler is built inside the callback so that
                    // only Sendable values cross the closure boundary.
                    return childChannel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                        .flatMapThrowing {
                            let handler = SSHSessionChannelHandler(
                                request: request,
                                startupPromise: startupPromise,
                                onOutput: outputSink,
                                onEvent: eventSink
                            )
                            try childChannel.pipeline.syncOperations.addHandler(handler)
                        }
                }
            }
        }

        do {
            let child = try await childPromise.futureResult.get()
            self.childChannel = child
            // Resolves once the server has confirmed the shell (or exec) —
            // only then is it honest to say "connected".
            try await startupPromise.futureResult.get()
            deadline.cancel()
        } catch {
            deadline.cancel()
            // If the child channel never got made, nobody completed the startup
            // promise; NIO treats an unfulfilled promise as a programmer error.
            startupPromise.fail(error)

            let failure = recorder.recorded ?? Self.translate(error, connectingTo: request)
            await self.teardownChannels()
            self.publish(failure: failure, generation: generation)
            throw failure
        }

        guard generation == self.generation else {
            // A newer attempt started while we were handshaking; this one is
            // stale. Drop it rather than let two sessions fight over the view.
            await self.teardownChannels()
            throw SSHError.channelClosed("Superseded by a newer connection attempt.")
        }

        self.publishesProgress = true
        self.lastError = nil
        self.state = .connected
    }

    // MARK: - Host key verification

    /// Runs on the main actor because the vault and the prompter both do. The
    /// NIO event loop is parked on a promise while this happens, which is fine —
    /// NIOSSH is explicitly happy for host key validation to take as long as a
    /// human needs.
    private func evaluateHostKey(
        generation: UInt64,
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String,
        publicKeyLine: String
    ) async -> Result<Void, SSHError> {
        self.advance(to: .verifyingHostKey, generation: generation)

        let decision = self.vault.verify(
            hostname: hostname,
            port: port,
            presentedType: keyType,
            presentedFingerprint: fingerprint,
            presentedLine: publicKeyLine
        )

        switch decision {
        case .trusted:
            return .success(())

        case .mismatch(let expected, _, let presentedFingerprint):
            // No prompt, no override, no "continue anyway". Refusing here means
            // the handshake aborts before user auth, so nothing secret has been
            // offered to whoever is on the other end.
            return .failure(
                .hostKeyMismatch(expected: expected.fingerprint, presented: presentedFingerprint)
            )

        case .unknown(let presentedType, let presentedFingerprint, let presentedLine):
            guard let prompter = self.hostKeyPrompter else {
                return .failure(
                    .connectionFailed(
                        "\(hostname) presented a host key this app has never seen, and there "
                            + "was no way to ask you to confirm it. The connection was refused."
                    )
                )
            }

            let accepted = await prompter.confirmUnknownHost(
                hostname: hostname,
                port: port,
                keyType: presentedType,
                fingerprint: presentedFingerprint
            )
            guard accepted else {
                return .failure(.hostKeyRejectedByUser)
            }

            do {
                _ = try self.vault.trust(
                    hostname: hostname,
                    port: port,
                    keyType: presentedType,
                    fingerprint: presentedFingerprint,
                    publicKeyLine: presentedLine
                )
            } catch {
                // Connecting without pinning would mean being asked again next
                // time and never detecting a change. Refuse instead.
                return .failure(
                    .connectionFailed(
                        "Couldn't save the host key for \(hostname): "
                            + "\(error.localizedDescription) The connection was stopped rather "
                            + "than continue without pinning the key."
                    )
                )
            }
            return .success(())
        }
    }

    // MARK: - Sending

    /// Send bytes to the remote — keystrokes, pastes, bracketed-paste markers.
    ///
    /// Safe and cheap to call at keystroke rate: `writeAndFlush` does the hop to
    /// the channel's event loop itself, so there is no `Task`, no allocation of
    /// a continuation, and emphatically no `wait()` (which on the main actor
    /// would deadlock the app against the loop it is waiting for).
    ///
    /// Dropping input when there is no channel is deliberate — throwing on every
    /// keypress after a disconnect would be unusable. `state.isConnected` is the
    /// thing to check before letting the user type.
    func send(_ data: Data) {
        guard !data.isEmpty, let channel = self.childChannel else { return }

        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        channel.writeAndFlush(
            SSHChannelData(type: .channel, data: .byteBuffer(buffer)),
            promise: nil
        )
    }

    /// Tell the remote the window changed, so the shell can `SIGWINCH` and
    /// full-screen programs can redraw at the new size.
    func resize(cols: Int, rows: Int, pixelWidth: Int = 0, pixelHeight: Int = 0) {
        // Remember the size even when there is no channel, so a reconnect comes
        // back at the size the user is actually looking at.
        self.lastRequest?.cols = max(cols, 1)
        self.lastRequest?.rows = max(rows, 1)

        guard let channel = self.childChannel else { return }

        let event = SSHChannelRequestEvent.WindowChangeRequest(
            terminalCharacterWidth: max(cols, 1),
            terminalRowHeight: max(rows, 1),
            terminalPixelWidth: max(pixelWidth, 0),
            terminalPixelHeight: max(pixelHeight, 0)
        )
        channel.triggerUserOutboundEvent(event, promise: nil)
    }

    // MARK: - Teardown

    /// Close the session cleanly: channel first (so the remote sees
    /// `SSH_MSG_CHANNEL_CLOSE` and the shell gets a proper hangup), then the
    /// transport.
    func disconnect() async {
        // Invalidate in-flight callbacks before tearing anything down, so the
        // resulting `.closed` events don't rewrite the state we're about to set.
        self.generation &+= 1
        self.publishesProgress = true
        await self.teardownChannels()
        self.lastAuth = nil
        self.state = .disconnected(reason: nil)
    }

    private func teardownChannels() async {
        let child = self.childChannel
        let parent = self.parentChannel
        self.childChannel = nil
        self.parentChannel = nil

        // `try?`: closing an already-closed channel throws
        // `ChannelError.alreadyClosed`, which is exactly the state we want.
        if let child {
            try? await child.close().get()
        }
        if let parent {
            try? await parent.close().get()
        }
    }

    // MARK: - Reconnect

    /// Re-run the last request with bounded retries and exponential backoff.
    ///
    /// Only transport-shaped failures are retried. A host key mismatch, a
    /// rejected key or a bad password are not going to fix themselves, and
    /// retrying credentials burns through the server's `MaxAuthTries` and can
    /// lock the account out.
    func reconnect() async {
        self.publishesProgress = true
        guard let request = self.lastRequest, let auth = self.lastAuth else {
            self.publish(failure: .notConnected)
            return
        }

        self.generation &+= 1
        await self.teardownChannels()

        for attempt in 1...Self.maxReconnectAttempts {
            if attempt > 1 {
                let delay = Self.backoffMilliseconds(beforeAttempt: attempt)
                try? await Task.sleep(for: .milliseconds(delay))
                if Task.isCancelled {
                    self.publishesProgress = true
                    self.state = .disconnected(reason: "Reconnect cancelled")
                    return
                }
            }

            self.state = .reconnecting(attempt: attempt)

            do {
                try await self.establish(request, auth: auth, publishesProgress: false)
                return
            } catch {
                let failure = (error as? SSHError) ?? Self.translate(error, connectingTo: request)
                self.lastError = failure.errorDescription
                guard Self.isRetryable(failure) else {
                    self.publishesProgress = true
                    self.state = .failed(message: failure.summary)
                    return
                }
            }
        }

        self.publishesProgress = true
        self.state = .failed(
            message: "Couldn't reconnect to \(request.destinationDescription)"
        )
    }

    /// 1s, 2s, 4s, 8s, capped at 15s, plus up to 250ms of jitter so a fleet of
    /// sessions coming back after a Wi-Fi drop doesn't stampede the server.
    nonisolated private static func backoffMilliseconds(beforeAttempt attempt: Int) -> Int {
        let exponent = max(0, min(attempt - 2, 8))
        let base = min(15_000, 1_000 << exponent)
        return base + Int.random(in: 0...250)
    }

    nonisolated private static func isRetryable(_ error: SSHError) -> Bool {
        switch error {
        case .connectionFailed, .channelClosed, .notConnected:
            return true
        case .hostKeyMismatch, .hostKeyRejectedByUser, .authenticationFailed,
            .noAuthenticationMethods, .keyboardInteractiveUnsupported,
            .negotiationFailed:
            // An algorithm mismatch is a configuration fact, not a blip. Every
            // retry would fail identically and cost the user twenty seconds.
            return false
        }
    }

    // MARK: - Main-actor plumbing

    /// Builds the sink the channel handler pushes inbound bytes through.
    ///
    /// **Byte ordering.** The terminal's screen is a function of the byte stream
    /// in the order it was produced; one swapped chunk and the VT parser is
    /// mid-escape-sequence with the wrong bytes and the display is corrupt. So:
    ///
    /// * `DispatchQueue.main.async`, *not* `Task { @MainActor in … }`. Tasks are
    ///   scheduled, not queued — several enqueued from the same thread can and
    ///   do run out of order. `DispatchQueue.main.async` is FIFO per submitting
    ///   thread, and every read for a connection is submitted from that
    ///   connection's single event loop thread, so global order is preserved.
    /// * `MainActor.assumeIsolated` rather than another hop: the block is
    ///   already running on the main thread, so this is an assertion, not a
    ///   suspension — and it keeps the delivery synchronous inside the block.
    /// * The handler coalesces a whole read burst into one array, so throughput
    ///   costs one main-queue hop per `channelReadComplete`, not one per packet.
    ///
    /// Order matters more than latency here. Do not "optimise" this into
    /// `Task {}`.
    private func makeOutputSink(generation: UInt64) -> @Sendable ([SSHOutputSegment]) -> Void {
        { [weak self] segments in
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    self?.deliver(segments, generation: generation)
                }
            }
        }
    }

    private func makeEventSink(generation: UInt64) -> @Sendable (SSHSessionChannelEvent) -> Void {
        { [weak self] event in
            // Same queue as the output sink, so an exit status can never
            // overtake the output that preceded it.
            DispatchQueue.main.async { [weak self] in
                MainActor.assumeIsolated {
                    self?.handle(event, generation: generation)
                }
            }
        }
    }

    private func deliver(_ segments: [SSHOutputSegment], generation: UInt64) {
        guard generation == self.generation else { return }
        for segment in segments {
            switch segment.stream {
            case .stdout:
                self.onData?(segment.bytes)
            case .stderr:
                self.onStdErr?(segment.bytes)
            }
        }
    }

    private func handle(_ event: SSHSessionChannelEvent, generation: UInt64) {
        guard generation == self.generation else { return }

        switch event {
        case .exitStatus(let status):
            self.exitStatus = status

        case .exitSignal(let name, let message, let dumpedCore):
            var text = "The remote process was killed by SIG\(name)."
            if !message.isEmpty { text += " \(message)" }
            if dumpedCore { text += " It dumped core." }
            self.lastError = text

        case .closed(let reason):
            self.childChannel = nil
            if let parent = self.parentChannel {
                parent.close(promise: nil)
                self.parentChannel = nil
            }
            // A failure already published a better explanation than "closed".
            guard !self.state.isError else { return }
            self.publishesProgress = true
            self.state = .disconnected(reason: reason)
        }
    }

    /// Moves forward through the handshake without ever regressing a settled
    /// state (a late `.authenticating` must not un-connect a live session).
    private func advance(to newState: SSHConnectionState, generation: UInt64) {
        guard generation == self.generation, self.publishesProgress else { return }
        switch self.state {
        case .idle, .resolving, .connecting, .verifyingHostKey, .authenticating:
            self.state = newState
        case .connected, .reconnecting, .disconnected, .failed:
            return
        }
    }

    private func publish(failure: SSHError, generation: UInt64? = nil) {
        if let generation, generation != self.generation { return }
        self.lastError = failure.errorDescription
        // During a reconnect run the retry loop owns what is on screen: it keeps
        // `.reconnecting(attempt:)` visible between tries and decides when the
        // whole run has failed. Without this guard the status bar would flicker
        // to `.failed` for the length of every backoff.
        guard self.publishesProgress else { return }
        self.state = .failed(message: failure.summary)
    }

    // MARK: - Error translation

    /// Turns a NIO/NIOSSH error into something with a sentence a person can act
    /// on. Used both by the pipeline error handler and by the connect path.
    nonisolated static func translate(_ error: Error) -> SSHError {
        if let sshError = error as? SSHError {
            return sshError
        }
        if let nioSSHError = error as? NIOSSHError {
            // Keep this one distinguishable: it is the only handshake failure
            // with a specific, readable explanation available, and `connect`
            // goes and fetches it.
            if nioSSHError.type == .keyExchangeNegotiationFailure {
                return .negotiationFailed(
                    headline: "No encryption algorithm in common.",
                    detail: nil
                )
            }
            return .connectionFailed("The SSH handshake failed: \(nioSSHError).")
        }
        if let channelError = error as? ChannelError {
            switch channelError {
            case .eof, .alreadyClosed, .ioOnClosedChannel:
                return .channelClosed("The connection was closed by the other end.")
            case .connectTimeout:
                return .connectionFailed("The connection timed out.")
            default:
                return .connectionFailed("\(channelError)")
            }
        }
        return .connectionFailed(error.localizedDescription)
    }

    nonisolated private static func translate(
        _ error: Error,
        connectingTo request: SSHConnectionRequest
    ) -> SSHError {
        if let sshError = error as? SSHError {
            return sshError
        }
        if error is NIOConnectionError {
            return .connectionFailed(
                "Couldn't reach \(request.hostname) on port \(request.port). Check the "
                    + "hostname and port, and that this device is on a network that can see "
                    + "that machine."
            )
        }
        if let channelError = error as? ChannelError, case .connectTimeout = channelError {
            return .connectionFailed(
                "\(request.hostname) didn't answer on port \(request.port) within "
                    + "\(Self.connectTimeout.nanoseconds / 1_000_000_000) seconds."
            )
        }
        return Self.translate(error)
    }
}
