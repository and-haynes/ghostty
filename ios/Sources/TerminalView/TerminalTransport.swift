import Foundation

/// The far end of a terminal.
///
/// On a desktop this would be a pty. iOS has no pty and no shell, so the only
/// real implementation is an SSH channel; `DemoTransport` exists so the
/// terminal, the renderer and the key bar can be exercised (and screenshotted)
/// without a network or credentials.
@MainActor
protocol TerminalTransport: AnyObject {
    /// Bytes arriving from the far end. Called on the main actor, in order.
    var onReceive: ((Data) -> Void)? { get set }
    /// Called when `statusLabel` / `isConnected` change.
    var onStatusChange: (() -> Void)? { get set }

    var statusLabel: String { get }
    var isConnected: Bool { get }
    var isError: Bool { get }

    func start(cols: Int, rows: Int)
    func send(_ data: Data)
    func resize(cols: Int, rows: Int, pixelWidth: Int, pixelHeight: Int)
    func stop()
}
