import Foundation
import NIOCore
import NIOPosix
import NIOSSH

/// What "Test connection" found out.
struct SSHConnectionReport: Sendable {
    enum Outcome: Sendable, Equatable {
        /// The server was reached, the algorithms line up, and the credentials
        /// were accepted.
        case ready
        /// Reached and negotiable, but the host key is not pinned yet, so no
        /// credential was offered. Connect normally once to pin it.
        case hostKeyNotTrusted
        /// Reached and negotiable, but the pinned key does not match.
        case hostKeyChanged
        /// Reached, but there is no set of algorithms in common.
        case cannotNegotiate
        /// Reached, negotiated, and the credentials were refused.
        case authenticationRefused(String)
        /// Could not get far enough to say anything.
        case unreachable(String)
    }

    var destination: String
    var outcome: Outcome
    /// Present whenever the server answered at all.
    var offer: SSHServerOffer?
    /// Present whenever the algorithms could be compared.
    var mismatch: SSHAlgorithmMismatch?
    /// The host key the server presented, once a handshake got that far.
    var hostKeyType: String?
    var hostKeyFingerprint: String?
    /// True when the presented key matches the pin in the vault.
    var hostKeyMatchesPin: Bool?

    /// What the negotiation will settle on, worked out from the server's own
    /// offer the way RFC 4253 §7.1 does.
    var negotiatedKeyExchange: String?
    var negotiatedHostKeyAlgorithm: String?
    var negotiatedCipher: String?
    var negotiatedMAC: String?

    var succeeded: Bool { self.outcome == .ready }

    var headline: String {
        switch self.outcome {
        case .ready:
            return "\(destination) is reachable and your credentials work."
        case .hostKeyNotTrusted:
            return "\(destination) answered, but its host key has not been trusted yet."
        case .hostKeyChanged:
            return "\(destination) presented a different host key from the one saved."
        case .cannotNegotiate:
            return mismatch?.summary ?? "No algorithm in common with \(destination)."
        case .authenticationRefused:
            return "\(destination) refused the credentials configured for it."
        case .unreachable:
            return "Couldn't reach \(destination)."
        }
    }

    /// The whole report, as shown in the sheet and copied by the Copy button.
    var detail: String {
        var lines: [String] = [headline, ""]

        if let offer {
            lines.append("Banner: \(offer.banner)")
            for line in offer.preamble where !line.isEmpty {
                lines.append("Also said: \(line)")
            }
            lines.append("")
        }

        if let negotiatedKeyExchange {
            lines.append("Would negotiate")
            lines.append("  key exchange  \(negotiatedKeyExchange)")
            lines.append("  host key      \(negotiatedHostKeyAlgorithm ?? "—")")
            lines.append("  cipher        \(negotiatedCipher ?? "—")")
            lines.append("  MAC           \(negotiatedMAC ?? "(the cipher's own)")")
            lines.append("")
        }

        if let hostKeyFingerprint {
            lines.append("Host key")
            lines.append("  \(hostKeyType ?? "unknown") \(hostKeyFingerprint)")
            switch hostKeyMatchesPin {
            case .some(true):
                lines.append("  matches the key saved for this host")
            case .some(false):
                lines.append("  DOES NOT match the key saved for this host")
            case nil:
                lines.append("  not saved yet — connect once to pin it")
            }
            lines.append("")
        }

        switch outcome {
        case .ready:
            lines.append("Authentication succeeded. A session would open.")
        case .authenticationRefused(let detail):
            lines.append("Authentication: \(detail)")
        case .hostKeyNotTrusted:
            lines.append(
                """
                No credential was offered: this app never sends a password or a key \
                to a host whose key it has not pinned. Connect normally once, check \
                the fingerprint above, and trust it.
                """
            )
        case .hostKeyChanged:
            lines.append(
                """
                No credential was offered. Either the server was rebuilt, or \
                something is sitting in the middle of this connection. Remove the \
                saved key in Keys ▸ Known hosts only if you know it was rebuilt.
                """
            )
        case .cannotNegotiate:
            if let mismatch { lines.append(mismatch.explanation) }
        case .unreachable(let reason):
            lines.append(reason)
        }

        return lines.joined(separator: "\n")
    }
}

/// Runs the "Test connection" check.
///
/// Two phases, and the split matters:
///
/// 1. **Probe.** Read the banner and algorithm list with no authentication at
///    all. This alone answers "is anything there", "is it SSH", and "can we
///    negotiate" — the questions that were previously unanswerable from the
///    phone.
/// 2. **Handshake.** Only if the algorithms line up: run a real key exchange,
///    look at the host key, and — *only when that key is already pinned and
///    matches* — offer the host's credentials and open a bare session channel
///    to prove auth works. No pty, no shell, nothing run on the far end.
///
/// The refusal to authenticate against an untrusted key is deliberate. A
/// diagnostic that sends your password to whatever answered the port is worse
/// than no diagnostic.
enum SSHConnectionTester {
    @MainActor
    static func run(
        request: SSHConnectionRequest,
        auth: [SSHAuthMethod],
        vault: Vault
    ) async -> SSHConnectionReport {
        var report = SSHConnectionReport(
            destination: request.destinationDescription,
            outcome: .unreachable("")
        )

        // MARK: Phase 1 — the offer
        let offer: SSHServerOffer
        do {
            offer = try await SSHServerProbe.read(host: request.hostname, port: request.port)
        } catch {
            report.outcome = .unreachable(
                (error as? LocalizedError)?.errorDescription ?? error.localizedDescription
            )
            return report
        }
        report.offer = offer

        let mismatch = SSHAlgorithmMismatch(hostname: request.hostname, offer: offer)
        report.mismatch = mismatch
        report.negotiatedKeyExchange = mismatch.keyExchangeInCommon.first
        report.negotiatedHostKeyAlgorithm = mismatch.hostKeysInCommon.first
        report.negotiatedCipher = mismatch.ciphersInCommon.first
        report.negotiatedMAC =
            mismatch.ciphersInCommon.first.map(SSHAlgorithmMismatch.requiresSeparateMAC) == true
            ? mismatch.macsInCommon.first : nil

        guard mismatch.canNegotiate else {
            report.outcome = .cannotNegotiate
            return report
        }

        // MARK: Phase 2 — a real handshake
        let pin = vault.knownHost(hostname: request.hostname, port: request.port)
        let recorder = SSHFailureRecorder()
        let observer = HostKeyObserver()

        let hostKeyDelegate = TOFUHostKeyDelegate(
            hostname: request.hostname,
            port: request.port,
            failureRecorder: recorder
        ) { keyType, fingerprint, _ in
            observer.record(type: keyType, fingerprint: fingerprint)
            guard let pin else {
                // Unknown host: stop here rather than continue to user auth.
                return .failure(
                    .connectionFailed("The host key is not pinned; nothing was sent.")
                )
            }
            guard pin.fingerprint == fingerprint, pin.keyType == keyType else {
                return .failure(
                    .hostKeyMismatch(expected: pin.fingerprint, presented: fingerprint)
                )
            }
            return .success(())
        }

        let authDelegate = SSHUserAuthDelegate(
            username: request.username,
            methods: auth,
            failureRecorder: recorder
        )

        do {
            try await Self.handshake(
                request: request,
                hostKeyDelegate: hostKeyDelegate,
                authDelegate: authDelegate,
                recorder: recorder
            )
            report.hostKeyType = observer.keyType
            report.hostKeyFingerprint = observer.fingerprint
            report.hostKeyMatchesPin = true
            report.outcome = .ready
            return report
        } catch {
            report.hostKeyType = observer.keyType
            report.hostKeyFingerprint = observer.fingerprint

            let failure = recorder.recorded ?? SSHSession.translate(error)
            switch failure {
            case .hostKeyMismatch:
                report.hostKeyMatchesPin = false
                report.outcome = .hostKeyChanged
            case .authenticationFailed(let detail):
                report.hostKeyMatchesPin = true
                report.outcome = .authenticationRefused(detail)
            case .noAuthenticationMethods:
                report.hostKeyMatchesPin = pin != nil ? true : nil
                report.outcome = .authenticationRefused(
                    "There is no key or password configured for this host."
                )
            case .keyboardInteractiveUnsupported:
                report.hostKeyMatchesPin = true
                report.outcome = .authenticationRefused(
                    "The server only offers keyboard-interactive authentication."
                )
            case .negotiationFailed:
                report.outcome = .cannotNegotiate
            default:
                if pin == nil, observer.fingerprint != nil {
                    report.hostKeyMatchesPin = nil
                    report.outcome = .hostKeyNotTrusted
                } else {
                    report.outcome = .unreachable(
                        failure.errorDescription ?? "The handshake did not complete."
                    )
                }
            }
            return report
        }
    }

    /// Key exchange, user auth, and a bare session channel — then hang up.
    ///
    /// Opening the channel is the proof: `NIOSSHHandler.createChannel` only
    /// succeeds once user auth has completed. No `pty-req` and no `shell`
    /// follow it, so nothing runs on the far end.
    private static func handshake(
        request: SSHConnectionRequest,
        hostKeyDelegate: TOFUHostKeyDelegate,
        authDelegate: SSHUserAuthDelegate,
        recorder: SSHFailureRecorder
    ) async throws {
        let protection = SSHTransportProtectionSchemes(
            SSHTransportProtectionCatalog.clientSchemes
        )
        let bootstrap = ClientBootstrap(group: SSHEventLoopGroupProvider.shared)
            .connectTimeout(.seconds(15))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let sync = channel.pipeline.syncOperations
                    try sync.addHandler(
                        NIOSSHHandler(
                            role: .client(
                                SSHClientConfiguration(
                                    userAuthDelegate: authDelegate,
                                    serverAuthDelegate: hostKeyDelegate,
                                    globalRequestDelegate: nil,
                                    transportProtectionSchemes: protection.schemes
                                )
                            ),
                            allocator: channel.allocator,
                            inboundChildChannelInitializer: nil
                        )
                    )
                }
            }

        let channel = try await bootstrap.connect(host: request.hostname, port: request.port).get()
        defer { channel.close(promise: nil) }

        let deadline = channel.eventLoop.scheduleTask(in: .seconds(20)) {
            recorder.record(.connectionFailed("The handshake timed out."))
            channel.close(promise: nil)
        }
        defer { deadline.cancel() }

        let childPromise = channel.eventLoop.makePromise(of: Channel.self)
        channel.pipeline.handler(type: NIOSSHHandler.self).whenComplete { result in
            switch result {
            case .failure(let error):
                childPromise.fail(error)
            case .success(let handler):
                handler.createChannel(childPromise, channelType: .session) { child, _ in
                    child.eventLoop.makeSucceededVoidFuture()
                }
            }
        }

        let child = try await childPromise.futureResult.get()
        try? await child.close().get()
    }
}

/// Captures the host key a handshake presented, from the event loop.
private final class HostKeyObserver: @unchecked Sendable {
    private let lock = NSLock()
    private var storedType: String?
    private var storedFingerprint: String?

    func record(type: String, fingerprint: String) {
        self.lock.lock()
        self.storedType = type
        self.storedFingerprint = fingerprint
        self.lock.unlock()
    }

    var keyType: String? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.storedType
    }

    var fingerprint: String? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.storedFingerprint
    }
}
