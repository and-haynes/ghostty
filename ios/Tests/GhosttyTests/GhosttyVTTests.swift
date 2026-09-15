import GhosttyVt
import XCTest
@testable import Ghostty

/// These tests run the real libghostty-vt, not a stub. That is the point: the
/// wrapper's whole job is to get the C API's ownership and sized-struct rules
/// right, and only the real library can tell us whether it did.
final class GhosttyVTTerminalTests: XCTestCase {
    func testWriteAndReadBackCells() throws {
        let terminal = try VTTerminal(cols: 20, rows: 5)
        terminal.write("hello\r\nworld")

        let renderState = try VTRenderState()
        let frame = try XCTUnwrap(renderState.frame(from: terminal))

        XCTAssertEqual(frame.cols, 20)
        XCTAssertEqual(frame.rowCount, 5)
        XCTAssertEqual(frame.dirty, .full)
        XCTAssertEqual(frame.lines.count, 5)

        XCTAssertEqual(text(of: frame.lines[0]), "hello")
        XCTAssertEqual(text(of: frame.lines[1]), "world")
        XCTAssertEqual(text(of: frame.lines[2]), "")
    }

    func testCleanFrameReturnsNilWhenNothingChanged() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        let renderState = try VTRenderState()
        _ = try renderState.frame(from: terminal)     // first frame is always full
        XCTAssertNil(try renderState.frame(from: terminal))

        terminal.write("x")
        let partial = try XCTUnwrap(renderState.frame(from: terminal))
        XCTAssertEqual(partial.dirty, .partial)
        // Only the row that changed is carried; that is what makes partial
        // redraw possible in the view.
        XCTAssertEqual(partial.lines.map(\.y), [0])
    }

    func testResizeReflowsAndReportsNewGeometry() throws {
        let terminal = try VTTerminal(cols: 20, rows: 5)
        terminal.write("abcdefghij")
        XCTAssertTrue(terminal.resize(cols: 5, rows: 4))
        XCTAssertEqual(terminal.cols, 5)
        XCTAssertEqual(terminal.rows, 4)

        let renderState = try VTRenderState()
        let frame = try XCTUnwrap(renderState.frame(from: terminal))
        XCTAssertEqual(frame.cols, 5)
        // Wraparound is on by default, so the line reflows rather than truncating.
        XCTAssertEqual(text(of: frame.lines[0]), "abcde")
        XCTAssertEqual(text(of: frame.lines[1]), "fghij")
    }

    func testSGRProducesStyledCells() throws {
        let terminal = try VTTerminal(cols: 40, rows: 3)
        // bold + palette red, then a 24-bit orange, then reset.
        terminal.write("\u{1b}[1;31mR\u{1b}[0m\u{1b}[38;2;255;128;0mO\u{1b}[0m\u{1b}[4mU\u{1b}[0m")

        let renderState = try VTRenderState()
        let frame = try XCTUnwrap(renderState.frame(from: terminal))
        let cells = frame.lines[0].cells

        XCTAssertEqual(cells[0].text, "R")
        XCTAssertTrue(cells[0].bold)
        XCTAssertEqual(cells[0].fg, frame.palette[1], "palette red should resolve through the palette")

        XCTAssertEqual(cells[1].text, "O")
        XCTAssertEqual(cells[1].fg, VTColor(r: 255, g: 128, b: 0))
        XCTAssertFalse(cells[1].bold)

        XCTAssertEqual(cells[2].text, "U")
        XCTAssertEqual(cells[2].underline, .single)
    }

    func testCursorPositionTracksWrites() throws {
        let terminal = try VTTerminal(cols: 10, rows: 4)
        terminal.write("abc")
        let renderState = try VTRenderState()
        let frame = try XCTUnwrap(renderState.frame(from: terminal))
        let cursor = try XCTUnwrap(frame.cursor)
        XCTAssertEqual(cursor.x, 3)
        XCTAssertEqual(cursor.y, 0)
        XCTAssertTrue(cursor.visible)
    }

    func testSelectionRoundTripsAsText() throws {
        let terminal = try VTTerminal(cols: 20, rows: 3)
        terminal.write("hello world")
        XCTAssertTrue(terminal.select(from: (0, 0), to: (4, 0)))
        XCTAssertTrue(terminal.hasSelection)
        XCTAssertEqual(terminal.selectionText(), "hello")

        terminal.clearSelection()
        XCTAssertFalse(terminal.hasSelection)
    }

    func testWritePtyCallbackReceivesDeviceStatusReply() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        var replies = Data()
        terminal.writeToPty = { replies.append($0) }
        // Cursor position report: the terminal must answer on its own.
        terminal.write("\u{1b}[6n")
        XCTAssertFalse(replies.isEmpty, "the write_pty callback should have fired")
        XCTAssertTrue(String(decoding: replies, as: UTF8.self).hasPrefix("\u{1b}["))
    }

    func testBracketedPasteModeIsObserved() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        XCTAssertFalse(terminal.bracketedPasteEnabled)
        terminal.write("\u{1b}[?2004h")
        XCTAssertTrue(terminal.bracketedPasteEnabled)
        terminal.write("\u{1b}[?2004l")
        XCTAssertFalse(terminal.bracketedPasteEnabled)
    }

    func testDefaultPaletteIsPopulated() {
        XCTAssertEqual(VTPalette.default.count, 256)
        // The 6x6x6 cube starts at 16 and its first entry is pure black.
        XCTAssertEqual(VTPalette.default[16], VTColor(r: 0, g: 0, b: 0))
        XCTAssertNotEqual(VTPalette.default[1], VTPalette.default[9], "red and bright red differ")
    }

    private func text(of row: VTRow) -> String {
        String(row.cells.map { $0.text.isEmpty ? " " : Character($0.text) }.map(Character.init))
            .trimmingCharacters(in: .whitespaces)
    }
}

final class GhosttyVTKeyEncoderTests: XCTestCase {
    func testArrowKeysEncodeAsCSI() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        let encoder = try VTKeyEncoder()
        encoder.sync(from: terminal)

        XCTAssertEqual(string(encoder.encode(key: GHOSTTY_KEY_ARROW_UP)), "\u{1b}[A")
        XCTAssertEqual(string(encoder.encode(key: GHOSTTY_KEY_ARROW_DOWN)), "\u{1b}[B")
        XCTAssertEqual(string(encoder.encode(key: GHOSTTY_KEY_ARROW_RIGHT)), "\u{1b}[C")
        XCTAssertEqual(string(encoder.encode(key: GHOSTTY_KEY_ARROW_LEFT)), "\u{1b}[D")
    }

    func testApplicationCursorKeysChangeTheEncoding() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        let encoder = try VTKeyEncoder()

        terminal.write("\u{1b}[?1h")  // DECCKM on
        encoder.sync(from: terminal)
        XCTAssertEqual(
            string(encoder.encode(key: GHOSTTY_KEY_ARROW_UP)), "\u{1b}OA",
            "application cursor keys use SS3, which is why the encoder is re-synced per keystroke"
        )
    }

    func testControlCEncodesToETX() throws {
        let encoder = try VTKeyEncoder()
        let data = try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_C, mods: [.ctrl]))
        XCTAssertEqual(Array(data), [0x03])
    }

    func testPlainLetterEncodesToItself() throws {
        let encoder = try VTKeyEncoder()
        let data = try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_A, text: "a"))
        XCTAssertEqual(Array(data), [0x61])
    }

    func testEnterAndTabAndBackspace() throws {
        let encoder = try VTKeyEncoder()
        XCTAssertEqual(Array(try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_ENTER))), [0x0D])
        XCTAssertEqual(Array(try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_TAB))), [0x09])
        XCTAssertEqual(Array(try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_BACKSPACE))), [0x7F])
    }

    func testEscapeEncodesToESC() throws {
        let encoder = try VTKeyEncoder()
        XCTAssertEqual(Array(try XCTUnwrap(encoder.encode(key: GHOSTTY_KEY_ESCAPE))), [0x1B])
    }

    private func string(_ data: Data?) -> String? {
        data.map { String(decoding: $0, as: UTF8.self) }
    }
}

final class GhosttyVTPasteTests: XCTestCase {
    func testNewlinesAreUnsafe() {
        XCTAssertTrue(VTPaste.isSafe("ls -la"))
        XCTAssertFalse(VTPaste.isSafe("ls -la\nrm -rf /"))
        XCTAssertFalse(VTPaste.isSafe("x\u{1b}[201~y"), "the bracketed-paste terminator escapes the brackets")
    }

    func testBracketedPasteWraps() throws {
        let data = try XCTUnwrap(VTPaste.encode("echo hi", bracketed: true))
        XCTAssertEqual(String(decoding: data, as: UTF8.self), "\u{1b}[200~echo hi\u{1b}[201~")
    }

    func testUnbracketedPasteTurnsNewlinesIntoCarriageReturns() throws {
        let data = try XCTUnwrap(VTPaste.encode("a\nb", bracketed: false))
        XCTAssertEqual(Array(data), [0x61, 0x0D, 0x62])
    }

    func testThemeAppliesToTerminalColours() throws {
        let terminal = try VTTerminal(cols: 10, rows: 3)
        terminal.applyTheme(.gruvboxDark)
        let renderState = try VTRenderState()
        let frame = try XCTUnwrap(renderState.frame(from: terminal))
        XCTAssertEqual(frame.background, TerminalTheme.gruvboxDark.background)
        XCTAssertEqual(frame.foreground, TerminalTheme.gruvboxDark.foreground)
        XCTAssertEqual(frame.palette[1], TerminalTheme.gruvboxDark.ansi[1])
    }
}
