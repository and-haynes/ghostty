import Foundation
import GhosttyVt

/// A Ghostty terminal emulator: the VT parser, screen, scrollback and mode
/// state, with no I/O of its own.
///
/// On iOS there is no pty and no shell, so "the pty" for this terminal is an
/// SSH channel (or, in the demo, a local echoer). Bytes from the far end go
/// into `write(_:)`; bytes the terminal wants to send back — DA/DSR replies,
/// in-band size reports — come out through `writeToPty`.
///
/// ## Ownership
/// The C handle is owned by this object and freed in `deinit`. The C API's
/// callbacks carry an opaque userdata pointer; we pass an *unretained*
/// pointer to `self` because every callback fires synchronously inside a call
/// this object is already making, so `self` is guaranteed alive. Retaining
/// would create a cycle that never breaks.
///
/// Not thread-safe. Confine one terminal to one thread (this app keeps them
/// on the main actor) — libghostty-vt explicitly leaves locking to the caller.
final class VTTerminal {
    private(set) var handle: GhosttyTerminal

    /// Bytes the terminal wants written back to the far end.
    var writeToPty: ((Data) -> Void)?
    /// BEL.
    var onBell: (() -> Void)?
    /// OSC 0/2 title change; the new title is already readable from `title`.
    var onTitleChanged: ((String) -> Void)?

    // MARK: Lifecycle

    init(cols: UInt16 = 80, rows: UInt16 = 24) throws {
        var handle: GhosttyTerminal?
        let result = ghostty_terminal_new(nil, &handle, max(1, cols), max(1, rows))
        try VTError.check(result, "ghostty_terminal_new")
        guard let handle else { throw VTError.result(GHOSTTY_OUT_OF_MEMORY, "ghostty_terminal_new") }
        self.handle = handle

        let selfPtr = UnsafeMutableRawPointer(Unmanaged.passUnretained(self).toOpaque())
        ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_USERDATA, selfPtr)
        // Callback options take the function pointer itself as the value, not
        // a pointer to it (see GHOSTTY_TERMINAL_OPT_* "Input type" docs: the
        // types without a trailing `*` are passed by value through void*).
        ghostty_terminal_set(
            handle,
            GHOSTTY_TERMINAL_OPT_WRITE_PTY,
            unsafeBitCast(vtWritePtyTrampoline, to: UnsafeRawPointer.self)
        )
        ghostty_terminal_set(
            handle,
            GHOSTTY_TERMINAL_OPT_BELL,
            unsafeBitCast(vtBellTrampoline, to: UnsafeRawPointer.self)
        )
        ghostty_terminal_set(
            handle,
            GHOSTTY_TERMINAL_OPT_TITLE_CHANGED,
            unsafeBitCast(vtTitleChangedTrampoline, to: UnsafeRawPointer.self)
        )
    }

    deinit {
        ghostty_terminal_free(handle)
    }

    // MARK: Input

    /// Feed bytes from the far end into the parser.
    func write(_ data: Data) {
        guard !data.isEmpty else { return }
        data.withUnsafeBytes { raw in
            guard let base = raw.bindMemory(to: UInt8.self).baseAddress else { return }
            ghostty_terminal_vt_write(handle, base, raw.count)
        }
    }

    func write(_ string: String) {
        write(Data(string.utf8))
    }

    /// Full reset (RIS).
    func reset() {
        ghostty_terminal_reset(handle)
    }

    // MARK: Geometry

    var cols: Int {
        var v: UInt16 = 0
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_COLS, &v)
        return Int(v)
    }

    var rows: Int {
        var v: UInt16 = 0
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_ROWS, &v)
        return Int(v)
    }

    var scrollbackRows: Int {
        var v: Int = 0
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_SCROLLBACK_ROWS, &v)
        return v
    }

    var totalRows: Int {
        var v: Int = 0
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_TOTAL_ROWS, &v)
        return v
    }

    /// True when the viewport is pinned to the active (bottom) area.
    var viewportIsActive: Bool {
        var v = false
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_VIEWPORT_ACTIVE, &v)
        return v
    }

    @discardableResult
    func resize(cols: Int, rows: Int, cellWidthPx: Int = 0, cellHeightPx: Int = 0) -> Bool {
        let result = ghostty_terminal_resize(
            handle,
            UInt16(clamping: max(1, cols)),
            UInt16(clamping: max(1, rows)),
            UInt32(clamping: max(0, cellWidthPx)),
            UInt32(clamping: max(0, cellHeightPx))
        )
        return result == GHOSTTY_SUCCESS
    }

    // MARK: Scrollback

    func scrollViewport(delta: Int) {
        var behavior = GhosttyTerminalScrollViewport()
        behavior.tag = GHOSTTY_SCROLL_VIEWPORT_DELTA
        behavior.value.delta = delta
        ghostty_terminal_scroll_viewport(handle, behavior)
    }

    /// Scroll so `row` (0 = top of scrollback) becomes the first visible row.
    func scrollViewport(toRow row: Int) {
        var behavior = GhosttyTerminalScrollViewport()
        behavior.tag = GHOSTTY_SCROLL_VIEWPORT_ROW
        behavior.value.row = max(0, row)
        ghostty_terminal_scroll_viewport(handle, behavior)
    }

    func scrollToBottom() {
        // A delta larger than any possible scrollback is clamped by the library.
        scrollViewport(delta: Int(Int32.max))
    }

    /// Row offset of the viewport within the scrollable area, and the total
    /// scrollable height — enough to draw a scroll indicator.
    var scrollbar: (offset: Int, viewport: Int, total: Int)? {
        var bar = GhosttyTerminalScrollbar()
        guard ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_SCROLLBAR, &bar) == GHOSTTY_SUCCESS
        else { return nil }
        return (Int(bar.offset), Int(bar.len), Int(bar.total))
    }

    // MARK: Modes

    /// Read a DEC private or ANSI mode.
    func mode(_ number: UInt16, ansi: Bool = false) -> Bool {
        var cfg = GhosttyTerminalModeConfig()
        cfg.mode = ghostty_mode_new(number, ansi)
        guard ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_MODE, &cfg) == GHOSTTY_SUCCESS
        else { return false }
        return cfg.value
    }

    /// Mode 2004. Decides whether a paste is wrapped in ESC[200~ … ESC[201~.
    var bracketedPasteEnabled: Bool { mode(2004) }

    /// Mode 1049/47 — the alternate screen has no scrollback, so the UI hides
    /// its scroll affordances while it is up.
    var alternateScreenActive: Bool {
        var screen: GhosttyTerminalScreen = GHOSTTY_TERMINAL_SCREEN_PRIMARY
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_ACTIVE_SCREEN, &screen)
        return screen != GHOSTTY_TERMINAL_SCREEN_PRIMARY
    }

    /// Any mouse tracking mode being on means the remote program wants the
    /// events, so taps should be forwarded instead of driving selection.
    var mouseTrackingEnabled: Bool {
        var tracking = false
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_MOUSE_TRACKING, &tracking)
        return tracking
    }

    // MARK: Title

    var title: String? {
        var s = GhosttyString()
        guard ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_TITLE, &s) == GHOSTTY_SUCCESS,
              let ptr = s.ptr, s.len > 0
        else { return nil }
        return String(decoding: UnsafeBufferPointer(start: ptr, count: s.len), as: UTF8.self)
    }

    // MARK: Selection

    /// Build a grid reference for a viewport coordinate, or nil if it is off
    /// the grid. Grid refs are snapshots: they are only valid until the next
    /// mutating call, so never store one.
    func gridRef(viewportX x: Int, y: Int) -> GhosttyGridRef? {
        var point = GhosttyPoint()
        point.tag = GHOSTTY_POINT_TAG_VIEWPORT
        point.value.coordinate = GhosttyPointCoordinate(x: UInt16(clamping: x), y: UInt32(clamping: y))
        var ref = GhosttyGridRef()
        ref.size = MemoryLayout<GhosttyGridRef>.size
        guard ghostty_terminal_grid_ref(handle, point, &ref) == GHOSTTY_SUCCESS else { return nil }
        return ref
    }

    /// Select the inclusive range between two viewport coordinates.
    @discardableResult
    func select(from: (x: Int, y: Int), to: (x: Int, y: Int), rectangle: Bool = false) -> Bool {
        guard let start = gridRef(viewportX: from.x, y: from.y),
              let end = gridRef(viewportX: to.x, y: to.y)
        else { return false }
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        selection.start = start
        selection.end = end
        selection.rectangle = rectangle
        return ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    /// Select the word under a viewport coordinate (the long-press gesture).
    @discardableResult
    func selectWord(atViewportX x: Int, y: Int) -> Bool {
        guard let ref = gridRef(viewportX: x, y: y) else { return false }
        var options = GhosttyTerminalSelectWordOptions()
        options.size = MemoryLayout<GhosttyTerminalSelectWordOptions>.size
        options.ref = ref
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        guard ghostty_terminal_select_word(handle, &options, &selection) == GHOSTTY_SUCCESS
        else { return false }
        return ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    @discardableResult
    func selectAll() -> Bool {
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        guard ghostty_terminal_select_all(handle, &selection) == GHOSTTY_SUCCESS else { return false }
        return ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    func clearSelection() {
        ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, nil)
    }

    var hasSelection: Bool {
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        return ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    /// The selected text, formatted the way Ghostty's own copy does it.
    func selectionText() -> String? {
        var options = GhosttyTerminalSelectionFormatOptions()
        options.size = MemoryLayout<GhosttyTerminalSelectionFormatOptions>.size
        options.emit = GHOSTTY_FORMATTER_FORMAT_PLAIN
        options.unwrap = true
        options.trim = true
        options.selection = nil  // use the terminal's active selection

        var ptr: UnsafeMutablePointer<UInt8>?
        var len = 0
        guard ghostty_terminal_selection_format_alloc(handle, nil, options, &ptr, &len) == GHOSTTY_SUCCESS,
              let ptr, len > 0
        else { return nil }
        defer { ghostty_free(nil, ptr, len) }
        return String(decoding: UnsafeBufferPointer(start: ptr, count: len), as: UTF8.self)
    }

    // MARK: Whole-screen text (used by tests and by "copy all")

    /// Format the whole active screen as plain text.
    func screenText(trim: Bool = true) -> String? {
        var options = GhosttyFormatterTerminalOptions()
        options.size = MemoryLayout<GhosttyFormatterTerminalOptions>.size
        options.emit = GHOSTTY_FORMATTER_FORMAT_PLAIN
        options.trim = trim

        var formatter: GhosttyFormatter?
        guard ghostty_formatter_terminal_new(nil, &formatter, handle, options) == GHOSTTY_SUCCESS,
              let formatter
        else { return nil }
        defer { ghostty_formatter_free(formatter) }

        var ptr: UnsafeMutablePointer<UInt8>?
        var len = 0
        guard ghostty_formatter_format_alloc(formatter, nil, &ptr, &len) == GHOSTTY_SUCCESS,
              let ptr, len > 0
        else { return nil }
        defer { ghostty_free(nil, ptr, len) }
        return String(decoding: UnsafeBufferPointer(start: ptr, count: len), as: UTF8.self)
    }
}

// MARK: - C trampolines
//
// These must capture nothing to be convertible to C function pointers. They
// recover the owning VTTerminal from the userdata pointer installed in init.

private let vtWritePtyTrampoline: @convention(c) (
    GhosttyTerminal?, UnsafeMutableRawPointer?, UnsafePointer<UInt8>?, Int
) -> Void = { _, userdata, data, len in
    guard let userdata, let data, len > 0 else { return }
    let terminal = Unmanaged<VTTerminal>.fromOpaque(userdata).takeUnretainedValue()
    terminal.writeToPty?(Data(bytes: data, count: len))
}

private let vtBellTrampoline: @convention(c) (
    GhosttyTerminal?, UnsafeMutableRawPointer?
) -> Void = { _, userdata in
    guard let userdata else { return }
    let terminal = Unmanaged<VTTerminal>.fromOpaque(userdata).takeUnretainedValue()
    terminal.onBell?()
}

private let vtTitleChangedTrampoline: @convention(c) (
    GhosttyTerminal?, UnsafeMutableRawPointer?
) -> Void = { _, userdata in
    guard let userdata else { return }
    let terminal = Unmanaged<VTTerminal>.fromOpaque(userdata).takeUnretainedValue()
    terminal.onTitleChanged?(terminal.title ?? "")
}

// MARK: - Colour scheme

extension VTTerminal {
    /// Install a colour scheme.
    ///
    /// These are the *defaults*; a program is still free to override them
    /// with OSC 10/11/4, which is why they go through the terminal rather
    /// than being applied at draw time. Doing it at draw time would make
    /// "reset colours" (OSC 104/110/111) impossible to honour.
    func applyTheme(foreground: VTColor, background: VTColor, cursor: VTColor, palette: [VTColor]) {
        var fg = GhosttyColorRgb(r: foreground.r, g: foreground.g, b: foreground.b)
        var bg = GhosttyColorRgb(r: background.r, g: background.g, b: background.b)
        var cur = GhosttyColorRgb(r: cursor.r, g: cursor.g, b: cursor.b)
        ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_COLOR_FOREGROUND, &fg)
        ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_COLOR_BACKGROUND, &bg)
        ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_COLOR_CURSOR, &cur)

        guard palette.count >= 256 else { return }
        var raw = palette.prefix(256).map { GhosttyColorRgb(r: $0.r, g: $0.g, b: $0.b) }
        _ = raw.withUnsafeMutableBufferPointer { buf in
            ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_COLOR_PALETTE, buf.baseAddress)
        }
    }

    func applyTheme(_ theme: TerminalTheme) {
        applyTheme(
            foreground: theme.foreground,
            background: theme.background,
            cursor: theme.cursor,
            palette: theme.palette
        )
    }
}

// MARK: - Semantic selection

extension VTTerminal {
    /// Select the line under a viewport coordinate.
    ///
    /// With `semanticBoundary` and a shell that emits OSC 133, this is the
    /// command line rather than the visual row — the prompt itself is excluded
    /// and a wrapped command is taken whole.
    func selectLine(atViewportX x: Int, y: Int, semanticBoundary: Bool = true) -> Bool {
        guard let ref = gridRef(viewportX: x, y: y) else { return false }
        var options = GhosttyTerminalSelectLineOptions()
        options.size = MemoryLayout<GhosttyTerminalSelectLineOptions>.size
        options.ref = ref
        options.semantic_prompt_boundary = semanticBoundary
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        guard ghostty_terminal_select_line(handle, &options, &selection) == GHOSTTY_SUCCESS
        else { return false }
        return ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    /// Select the command output containing a viewport coordinate. Requires
    /// OSC 133 marks; returns false without them.
    func selectOutput(atViewportX x: Int, y: Int) -> Bool {
        guard let ref = gridRef(viewportX: x, y: y) else { return false }
        var selection = GhosttySelection()
        selection.size = MemoryLayout<GhosttySelection>.size
        guard ghostty_terminal_select_output(handle, ref, &selection) == GHOSTTY_SUCCESS
        else { return false }
        return ghostty_terminal_set(handle, GHOSTTY_TERMINAL_OPT_SELECTION, &selection) == GHOSTTY_SUCCESS
    }

    /// Whether the shell is reporting prompt boundaries (OSC 133).
    var hasShellIntegration: Bool {
        var atPrompt = false
        ghostty_terminal_get(handle, GHOSTTY_TERMINAL_DATA_CURSOR_AT_PROMPT, &atPrompt)
        return atPrompt
    }
}
