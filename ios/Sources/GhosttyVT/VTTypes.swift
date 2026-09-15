import CoreGraphics
import Foundation
import GhosttyVt

// Swift-side value types for everything the renderer reads out of
// libghostty-vt. The C API hands out borrowed pointers and iterator handles
// whose lifetimes end at the next mutating terminal call, so the wrapper
// copies what a frame needs into plain values. That is what makes it safe to
// hand a frame to UIKit's draw pass, which runs whenever it likes.

/// An 8-bit-per-channel colour, the only kind libghostty-vt deals in.
struct VTColor: Equatable, Hashable {
    var r: UInt8
    var g: UInt8
    var b: UInt8

    init(r: UInt8, g: UInt8, b: UInt8) {
        self.r = r
        self.g = g
        self.b = b
    }

    init(_ c: GhosttyColorRgb) {
        self.init(r: c.r, g: c.g, b: c.b)
    }

    /// Parse "#rrggbb" or "rrggbb". Returns nil on anything else.
    init?(hex: String) {
        var s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.hasPrefix("#") { s.removeFirst() }
        guard s.count == 6, let v = UInt32(s, radix: 16) else { return nil }
        self.init(
            r: UInt8((v >> 16) & 0xFF),
            g: UInt8((v >> 8) & 0xFF),
            b: UInt8(v & 0xFF)
        )
    }

    var hexString: String { String(format: "#%02X%02X%02X", r, g, b) }

    var cgColor: CGColor {
        CGColor(
            red: CGFloat(r) / 255.0,
            green: CGFloat(g) / 255.0,
            blue: CGFloat(b) / 255.0,
            alpha: 1.0
        )
    }

    static let black = VTColor(r: 0, g: 0, b: 0)
    static let white = VTColor(r: 0xFF, g: 0xFF, b: 0xFF)
}

/// How a cell relates to double-width characters.
enum VTCellWidth: Int32 {
    case narrow = 0
    case wide = 1
    /// The right half of a wide character: draw nothing, the head drew it.
    case spacerTail = 2
    /// A blank inserted at the end of a line so a wide char can wrap whole.
    case spacerHead = 3

    // Switched rather than bridged by rawValue: how Swift imports a C enum's
    // raw type (Int32 vs UInt32) is a detail we do not want to depend on.
    init(_ c: GhosttyCellWide) {
        switch c {
        case GHOSTTY_CELL_WIDE_WIDE: self = .wide
        case GHOSTTY_CELL_WIDE_SPACER_TAIL: self = .spacerTail
        case GHOSTTY_CELL_WIDE_SPACER_HEAD: self = .spacerHead
        default: self = .narrow
        }
    }
}

/// SGR underline styles (mirrors GhosttySgrUnderline).
enum VTUnderlineStyle: Int32 {
    case none = 0
    case single = 1
    case double = 2
    case curly = 3
    case dotted = 4
    case dashed = 5
}

/// Everything the renderer needs to draw one cell.
struct VTCell: Equatable {
    /// The grapheme cluster, already assembled. Empty means a blank cell.
    var text: String
    /// Resolved foreground, or nil to use the frame's default foreground.
    var fg: VTColor?
    /// Resolved background, or nil to use the frame's default background.
    var bg: VTColor?
    var underlineColor: VTColor?
    var bold = false
    var italic = false
    var faint = false
    var blink = false
    var inverse = false
    var invisible = false
    var strikethrough = false
    var overline = false
    var underline: VTUnderlineStyle = .none
    var width: VTCellWidth = .narrow
    var selected = false

    static let blank = VTCell(text: "")

    var isBlank: Bool {
        text.isEmpty && bg == nil && !selected && underline == .none
            && !strikethrough && !overline
    }
}

/// One viewport row of a frame.
struct VTRow: Equatable {
    /// Row index within the viewport, 0 at the top.
    var y: Int
    var cells: [VTCell]
}

enum VTCursorStyle: Int32 {
    case bar = 0
    case block = 1
    case underline = 2
    case blockHollow = 3

    init(_ c: GhosttyRenderStateCursorVisualStyle) {
        switch c {
        case GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_BAR: self = .bar
        case GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_UNDERLINE: self = .underline
        case GHOSTTY_RENDER_STATE_CURSOR_VISUAL_STYLE_BLOCK_HOLLOW: self = .blockHollow
        default: self = .block
        }
    }
}

struct VTCursor: Equatable {
    var x: Int
    var y: Int
    var style: VTCursorStyle
    var visible: Bool
    var blinking: Bool
    /// True when the cursor sits on the tail half of a wide character.
    var wideTail: Bool
    /// True when the terminal believes a password is being typed; a renderer
    /// may want to avoid drawing anything that leaks length.
    var passwordInput: Bool
}

enum VTDirty: Int32 {
    case clean = 0
    case partial = 1
    case full = 2

    init(_ c: GhosttyRenderStateDirty) {
        switch c {
        case GHOSTTY_RENDER_STATE_DIRTY_PARTIAL: self = .partial
        case GHOSTTY_RENDER_STATE_DIRTY_FULL: self = .full
        default: self = .clean
        }
    }
}

/// A complete, self-contained description of one frame.
struct VTFrame {
    var cols: Int = 0
    /// Number of rows in the viewport (not the number of rows in `lines`).
    var rowCount: Int = 0
    var background: VTColor = .black
    var foreground: VTColor = .white
    var cursorColor: VTColor?
    var palette: [VTColor] = []
    var cursor: VTCursor?
    /// Rows present in this frame. On a partial update this holds only the
    /// rows that changed; `dirty` says which case you are in.
    var lines: [VTRow] = []
    var dirty: VTDirty = .clean

    static let empty = VTFrame()
}

/// Errors surfaced by the thin C wrapper.
enum VTError: Error, LocalizedError {
    case result(GhosttyResult, String)

    var errorDescription: String? {
        switch self {
        case .result(let r, let what):
            return "libghostty-vt \(what) failed: \(VTError.name(r))"
        }
    }

    static func name(_ r: GhosttyResult) -> String {
        switch r {
        case GHOSTTY_SUCCESS: return "success"
        case GHOSTTY_OUT_OF_MEMORY: return "out of memory"
        case GHOSTTY_INVALID_VALUE: return "invalid value"
        case GHOSTTY_OUT_OF_SPACE: return "out of space"
        case GHOSTTY_NO_VALUE: return "no value"
        case GHOSTTY_IO_ERROR: return "I/O error"
        case GHOSTTY_LIMIT_EXCEEDED: return "limit exceeded"
        case GHOSTTY_REJECTED: return "rejected"
        default: return "unknown (\(r.rawValue))"
        }
    }

    /// Throw unless the call succeeded.
    static func check(_ r: GhosttyResult, _ what: @autoclosure () -> String) throws {
        guard r == GHOSTTY_SUCCESS else { throw VTError.result(r, what()) }
    }
}

/// The stock Ghostty 256-colour palette, straight from the library so the
/// app and a desktop Ghostty agree on what "colour 4" means.
enum VTPalette {
    static let `default`: [VTColor] = {
        var raw = [GhosttyColorRgb](repeating: GhosttyColorRgb(), count: 256)
        raw.withUnsafeMutableBufferPointer { buf in
            ghostty_color_palette_default(buf.baseAddress)
        }
        return raw.map(VTColor.init)
    }()
}
