import Foundation
import NIOCore
import NIOPosix

/// Reads a server's banner and algorithm list without authenticating.
///
/// Everything this needs is sent in the clear before any negotiation happens:
/// the identification string, then `SSH_MSG_KEXINIT`. No key exchange, no user
/// auth, nothing offered to the server beyond our own identification string —
/// so this is safe to run against a host we have not decided to trust yet, and
/// it is what turns `NIOSSHError.keyExchangeNegotiationFailure` into a sentence.
///
/// Used in two places: the **Test connection** button, and automatically after a
/// negotiation failure so the error the user sees names the actual problem.
enum SSHServerProbe {
    enum Failure: Error, LocalizedError, Equatable {
        case timedOut(host: String, port: Int, seconds: Int)
        case closedEarly(String?)
        case noVersionString

        var errorDescription: String? {
            switch self {
            case .timedOut(let host, let port, let seconds):
                return """
                    \(host) accepted a connection on port \(port) but sent nothing \
                    within \(seconds) seconds. That is usually a firewall or a \
                    port-forward pointing somewhere unexpected rather than an SSH \
                    server.
                    """
            case .closedEarly(let banner):
                guard let banner, !banner.isEmpty else {
                    return "The server closed the connection before sending its algorithm list."
                }
                return """
                    The server closed the connection after saying "\(banner)" and \
                    before sending its algorithm list.
                    """
            case .noVersionString:
                return """
                    The service on that port did not send an SSH identification \
                    string. It is probably not an SSH server.
                    """
            }
        }
    }

    /// Our identification string.
    ///
    /// Sent because RFC 4253 §4.2 has both sides send one and some servers wait
    /// for the client's before proceeding. It names the probe rather than the
    /// app so a server's auth log distinguishes a diagnostic from a real
    /// connection attempt.
    static let identification = "SSH-2.0-Ghostty_probe\r\n"

    static func read(
        host: String,
        port: Int,
        timeout: TimeAmount = .seconds(8),
        group: EventLoopGroup = SSHEventLoopGroupProvider.shared
    ) async throws -> SSHServerOffer {
        let promise = group.next().makePromise(of: SSHServerOffer.self)
        let handler = ProbeHandler(promise: promise, host: host, port: port, timeout: timeout)

        let bootstrap = ClientBootstrap(group: group)
            .connectTimeout(timeout)
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }

        let channel: Channel
        do {
            channel = try await bootstrap.connect(host: host, port: port).get()
        } catch {
            promise.fail(error)
            return try await promise.futureResult.get()
        }

        defer { channel.close(promise: nil) }
        return try await promise.futureResult.get()
    }
}

/// Accumulates the preamble, the identification string and the first packet.
///
/// Event-loop confined, so the mutable buffers need no locking.
private final class ProbeHandler: ChannelInboundHandler {
    typealias InboundIn = ByteBuffer

    private let promise: EventLoopPromise<SSHServerOffer>
    private let host: String
    private let port: Int
    private let timeout: TimeAmount

    private var pending: [UInt8] = []
    private var preamble: [String] = []
    private var banner: String?
    private var resolved = false
    private var deadline: Scheduled<Void>?

    /// Enough for a banner and a KEXINIT several times over; past this the peer
    /// is not speaking SSH and should not be allowed to grow our buffer.
    private static let maximumBytes = 128 * 1024

    init(promise: EventLoopPromise<SSHServerOffer>, host: String, port: Int, timeout: TimeAmount) {
        self.promise = promise
        self.host = host
        self.port = port
        self.timeout = timeout
    }

    func channelActive(context: ChannelHandlerContext) {
        self.deadline = context.eventLoop.scheduleTask(in: self.timeout) { [weak self] in
            guard let self else { return }
            self.finish(
                .failure(
                    SSHServerProbe.Failure.timedOut(
                        host: self.host,
                        port: self.port,
                        seconds: Int(self.timeout.nanoseconds / 1_000_000_000)
                    )
                ),
                context: context
            )
        }

        var buffer = context.channel.allocator.buffer(capacity: 32)
        buffer.writeString(SSHServerProbe.identification)
        // `NIOAny` rather than `wrapOutboundOut`: this handler is inbound-only,
        // and the bytes go straight to the socket underneath it.
        context.writeAndFlush(NIOAny(buffer), promise: nil)
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        guard !self.resolved else { return }
        var buffer = self.unwrapInboundIn(data)
        self.pending.append(contentsOf: buffer.readableBytesView)
        buffer.moveReaderIndex(to: buffer.writerIndex)

        guard self.pending.count <= Self.maximumBytes else {
            self.finish(.failure(SSHServerProbe.Failure.noVersionString), context: context)
            return
        }

        // Consume lines until the identification string turns up. RFC 4253 §4.2
        // lets a server send arbitrary lines first; that is where a TCP-wrappers
        // refusal or a legal banner arrives, and it is worth showing.
        while self.banner == nil {
            guard let newline = self.pending.firstIndex(of: UInt8(ascii: "\n")) else { return }
            var lineBytes = Array(self.pending[..<newline])
            if lineBytes.last == UInt8(ascii: "\r") { lineBytes.removeLast() }
            self.pending.removeFirst(newline + 1)
            let line = String(decoding: lineBytes, as: UTF8.self)
            if line.hasPrefix("SSH-") {
                self.banner = line
            } else {
                self.preamble.append(line)
            }
        }

        guard let banner = self.banner else { return }
        do {
            guard let lists = try SSHKEXInitParser.parse(packet: self.pending) else { return }
            self.finish(
                .success(
                    SSHKEXInitParser.offer(banner: banner, preamble: self.preamble, lists: lists)
                ),
                context: context
            )
        } catch {
            self.finish(.failure(error), context: context)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.finish(.failure(SSHServerProbe.Failure.closedEarly(self.banner)), context: context)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.finish(.failure(error), context: context)
    }

    private func finish(_ result: Result<SSHServerOffer, Error>, context: ChannelHandlerContext) {
        guard !self.resolved else { return }
        self.resolved = true
        self.deadline?.cancel()
        self.deadline = nil
        self.promise.completeWith(result)
        context.close(promise: nil)
    }
}
