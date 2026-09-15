import Foundation
import GhosttyVt
import SwiftUI

/// One terminal: emulator state, render state, encoders, and the transport
/// carrying bytes to and from the far end.
///
/// Everything here is main-actor confined. libghostty-vt leaves locking to the
/// caller, and the only other candidate thread is NIO's event loop, so the
/// transport hops to the main actor before delivering bytes. That also keeps
/// byte ordering trivially correct, which matters more than latency: bytes
/// delivered out of order do not merely look wrong, they corrupt the screen.
@MainActor
final class TerminalSession: ObservableObject, Identifiable {
    let id = UUID()

    let terminal: VTTerminal
    let transport: TerminalTransport

    private let renderState: VTRenderState
    private let keyEncoder: VTKeyEncoder
    private let mouseEncoder: VTMouseEncoder

    @Published private(set) var title: String
    @Published private(set) var statusLabel: String = ""
    @Published private(set) var isConnected: Bool = false
    @Published private(set) var isError: Bool = false
    @Published private(set) var cols: Int = 80
    @Published private(set) var rows: Int = 24
    @Published var theme: TerminalTheme {
        didSet {
            terminal.applyTheme(theme)
            renderState.invalidate()
            onNeedsRedraw?()
        }
    }
    @Published var fontSize: CGFloat

    /// Name shown in the sessions list.
    let displayName: String
    /// Accent for the status bar, if the host defines one.
    let accentHex: String?

    /// Set by the view; called whenever the screen may have changed.
    var onNeedsRedraw: (() -> Void)?
    var onBell: (() -> Void)?

    private var started = false

    init(
        displayName: String,
        transport: TerminalTransport,
        theme: TerminalTheme = .ghosttyDefault,
        fontSize: CGFloat = 12,
        accentHex: String? = nil
    ) throws {
        self.displayName = displayName
        self.transport = transport
        self.theme = theme
        self.fontSize = fontSize
        self.accentHex = accentHex
        self.title = displayName

        self.terminal = try VTTerminal(cols: 80, rows: 24)
        self.renderState = try VTRenderState()
        self.keyEncoder = try VTKeyEncoder()
        self.mouseEncoder = try VTMouseEncoder()

        terminal.applyTheme(theme)

        terminal.writeToPty = { [weak self] data in
            // Terminal replies (DA, DSR, in-band size reports) go to the far
            // end just like keystrokes do.
            self?.transport.send(data)
        }
        terminal.onBell = { [weak self] in self?.onBell?() }
        terminal.onTitleChanged = { [weak self] newTitle in
            guard let self else { return }
            self.title = newTitle.isEmpty ? self.displayName : newTitle
        }

        transport.onReceive = { [weak self] data in self?.receive(data) }
        transport.onStatusChange = { [weak self] in self?.syncStatus() }
        syncStatus()
    }

    // MARK: - Lifecycle

    func startIfNeeded() {
        guard !started else { return }
        started = true
        transport.start(cols: cols, rows: rows)
    }

    func stop() {
        transport.stop()
    }

    private func syncStatus() {
        statusLabel = transport.statusLabel
        isConnected = transport.isConnected
        isError = transport.isError
    }

    // MARK: - Data in

    func receive(_ data: Data) {
        terminal.write(data)
        onNeedsRedraw?()
    }

    // MARK: - Data out

    func sendRaw(_ data: Data) {
        guard !data.isEmpty else { return }
        transport.send(data)
        // Typing pins the viewport to the bottom, as every terminal does.
        scrollToBottom()
    }

    /// Encode and send a key press.
    @discardableResult
    func sendKey(_ key: GhosttyKey, mods: VTMods = [], text: String? = nil) -> Bool {
        // Sync every time: a program can turn on the Kitty keyboard protocol
        // or application cursor keys at any moment, and the very next key must
        // already honour it.
        keyEncoder.sync(from: terminal)
        guard let data = keyEncoder.encode(key: key, mods: mods, text: text) else { return false }
        sendRaw(data)
        return true
    }

    /// Send literal text (the soft keyboard's normal path).
    func sendText(_ text: String, mods: VTMods = []) {
        for character in text {
            let scalar = character.unicodeScalars.first
            if character == "\n" || character == "\r" {
                sendKey(GHOSTTY_KEY_ENTER, mods: mods)
                continue
            }
            let key = HIDKeyMap.key(forCharacter: character)
            if key != GHOSTTY_KEY_UNIDENTIFIED || mods.isEmpty {
                sendKey(key, mods: mods, text: String(character))
            } else if let scalar, scalar.isASCII {
                // Unmapped character with a live modifier: fall back to the
                // codepoint so ctrl-<punctuation> still does something.
                sendKey(GHOSTTY_KEY_UNIDENTIFIED, mods: mods, text: String(character))
            }
        }
    }

    // MARK: - Paste

    /// Whether a paste of this text would be flagged as risky.
    func pasteIsSafe(_ text: String) -> Bool { VTPaste.isSafe(text) }

    func paste(_ text: String) {
        guard let data = VTPaste.encode(text, bracketed: terminal.bracketedPasteEnabled) else { return }
        sendRaw(data)
    }

    // MARK: - Geometry

    func resize(cols newCols: Int, rows newRows: Int, cellWidth: CGFloat, cellHeight: CGFloat) {
        let clampedCols = max(2, newCols)
        let clampedRows = max(1, newRows)
        guard clampedCols != cols || clampedRows != rows else { return }
        cols = clampedCols
        rows = clampedRows
        _ = terminal.resize(
            cols: clampedCols,
            rows: clampedRows,
            cellWidthPx: Int(cellWidth.rounded()),
            cellHeightPx: Int(cellHeight.rounded())
        )
        transport.resize(
            cols: clampedCols,
            rows: clampedRows,
            pixelWidth: Int((cellWidth * CGFloat(clampedCols)).rounded()),
            pixelHeight: Int((cellHeight * CGFloat(clampedRows)).rounded())
        )
        renderState.invalidate()
        onNeedsRedraw?()
    }

    // MARK: - Rendering

    /// Pull the next frame, or nil when nothing changed.
    func nextFrame() -> VTFrame? {
        try? renderState.frame(from: terminal)
    }

    func invalidateRender() {
        renderState.invalidate()
        onNeedsRedraw?()
    }

    // MARK: - Scrollback

    var canScrollBack: Bool { !terminal.alternateScreenActive && terminal.scrollbackRows > 0 }

    func scroll(rows delta: Int) {
        guard delta != 0 else { return }
        terminal.scrollViewport(delta: delta)
        invalidateRender()
    }

    func scrollToBottom() {
        guard !terminal.viewportIsActive else { return }
        terminal.scrollToBottom()
        invalidateRender()
    }

    // MARK: - Selection

    func selectWord(atColumn column: Int, row: Int) {
        guard terminal.selectWord(atViewportX: column, y: row) else { return }
        invalidateRender()
    }

    func extendSelection(from origin: (x: Int, y: Int), to point: (x: Int, y: Int)) {
        guard terminal.select(from: origin, to: point) else { return }
        invalidateRender()
    }

    func clearSelection() {
        terminal.clearSelection()
        invalidateRender()
    }

    var selectedText: String? { terminal.selectionText() }

    // MARK: - Mouse forwarding

    var wantsMouseEvents: Bool { terminal.mouseTrackingEnabled }

    func sendMouse(
        action: GhosttyMouseAction,
        button: GhosttyMouseButton,
        column: Int,
        row: Int,
        cellWidth: CGFloat,
        cellHeight: CGFloat
    ) {
        mouseEncoder.sync(from: terminal)
        guard let data = mouseEncoder.encode(
            action: action,
            button: button,
            mods: [],
            column: column,
            row: row,
            cellWidth: Double(cellWidth),
            cellHeight: Double(cellHeight)
        ) else { return }
        transport.send(data)
    }

    // MARK: - Convenience constructors

    /// The local console. Always present, never connected to anything but the
    /// app's own command interpreter.
    static func console(
        commandHost: ConsoleCommandHost?,
        theme: TerminalTheme = .ghosttyDefault,
        fontSize: CGFloat = 12
    ) throws -> TerminalSession {
        try TerminalSession(
            displayName: "Console",
            transport: ConsoleTransport(commandHost: commandHost),
            theme: theme,
            fontSize: fontSize
        )
    }
}
