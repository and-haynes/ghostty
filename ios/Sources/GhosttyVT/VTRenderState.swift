import Foundation
import GhosttyVt

/// Incremental render state: the bridge between terminal state and pixels.
///
/// libghostty-vt keeps this object up to date from a terminal in one call
/// (`update`), tracks which rows changed since the last frame, and hands the
/// renderer cells through iterators. We drain those iterators into plain
/// Swift values (`VTFrame`) because the handles and pointers they expose are
/// invalidated by the next mutating terminal call, and UIKit draws whenever
/// it feels like it.
///
/// Reusing one `VTRenderState` (and its iterator/cells handles) across frames
/// is the whole point — creating them per frame would allocate on every
/// keystroke.
final class VTRenderState {
    private var state: GhosttyRenderState
    private var rowIterator: GhosttyRenderStateRowIterator
    private var rowCells: GhosttyRenderStateRowCells

    /// Set when a resize or a full-screen change means the next frame must
    /// redraw everything even if the library only reports partial dirt.
    private var forceFullNextFrame = true

    init() throws {
        var state: GhosttyRenderState?
        try VTError.check(ghostty_render_state_new(nil, &state), "ghostty_render_state_new")
        guard let state else { throw VTError.result(GHOSTTY_OUT_OF_MEMORY, "ghostty_render_state_new") }
        self.state = state

        var iterator: GhosttyRenderStateRowIterator?
        var cells: GhosttyRenderStateRowCells?
        let iterResult = ghostty_render_state_row_iterator_new(nil, &iterator)
        let cellsResult = ghostty_render_state_row_cells_new(nil, &cells)
        guard iterResult == GHOSTTY_SUCCESS, let iterator,
              cellsResult == GHOSTTY_SUCCESS, let cells
        else {
            ghostty_render_state_free(state)
            throw VTError.result(GHOSTTY_OUT_OF_MEMORY, "render state iterators")
        }
        self.rowIterator = iterator
        self.rowCells = cells
    }

    deinit {
        ghostty_render_state_row_cells_free(rowCells)
        ghostty_render_state_row_iterator_free(rowIterator)
        ghostty_render_state_free(state)
    }

    /// Force the next `frame(from:)` to emit every row.
    func invalidate() {
        forceFullNextFrame = true
    }

    /// Snapshot a frame from `terminal`.
    ///
    /// Returns nil when nothing changed and nothing forced a redraw, which is
    /// the common case between keystrokes — the caller should skip drawing.
    func frame(from terminal: VTTerminal) throws -> VTFrame? {
        try VTError.check(
            ghostty_render_state_update(state, terminal.handle),
            "ghostty_render_state_update"
        )

        var dirtyRaw = GHOSTTY_RENDER_STATE_DIRTY_FALSE
        ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_DIRTY, &dirtyRaw)
        let dirty = VTDirty(dirtyRaw)

        let wantsFull = forceFullNextFrame || dirty == .full
        if dirty == .clean && !wantsFull { return nil }

        var frame = VTFrame()
        frame.dirty = wantsFull ? .full : dirty

        var cols: UInt16 = 0
        var rows: UInt16 = 0
        ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_COLS, &cols)
        ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_ROWS, &rows)
        frame.cols = Int(cols)
        frame.rowCount = Int(rows)

        // Colours come back as one big sized struct (background, foreground,
        // cursor, and the live 256-entry palette) so palette lookups below
        // need no further C calls.
        var colors = GhosttyRenderStateColors()
        colors.size = MemoryLayout<GhosttyRenderStateColors>.size
        var palette = VTPalette.default
        if ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_COLORS, &colors) == GHOSTTY_SUCCESS {
            frame.background = VTColor(colors.background)
            frame.foreground = VTColor(colors.foreground)
            frame.cursorColor = colors.cursor_has_value ? VTColor(colors.cursor) : nil
            palette = withUnsafeBytes(of: &colors.palette) { raw in
                raw.bindMemory(to: GhosttyColorRgb.self).map(VTColor.init)
            }
        }
        frame.palette = palette

        var cursor = GhosttyRenderStateCursor()
        cursor.size = MemoryLayout<GhosttyRenderStateCursor>.size
        if ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_CURSOR, &cursor) == GHOSTTY_SUCCESS,
           cursor.viewport_has_value {
            frame.cursor = VTCursor(
                x: Int(cursor.viewport_x),
                y: Int(cursor.viewport_y),
                style: VTCursorStyle(cursor.visual_style),
                visible: cursor.visible,
                blinking: cursor.blinking,
                wideTail: cursor.wide_tail,
                passwordInput: cursor.password_input
            )
        }

        // Bind the reusable iterator to this frame's rows.
        var iterator: GhosttyRenderStateRowIterator? = rowIterator
        try VTError.check(
            ghostty_render_state_get(state, GHOSTTY_RENDER_STATE_DATA_ROW_ITERATOR, &iterator),
            "render state row iterator"
        )
        if let iterator { rowIterator = iterator }

        frame.lines.reserveCapacity(wantsFull ? Int(rows) : 8)
        if wantsFull {
            var y = 0
            while ghostty_render_state_row_iterator_next(rowIterator) {
                frame.lines.append(VTRow(y: y, cells: readCurrentRow(columns: frame.cols)))
                y += 1
            }
        } else {
            var y: UInt16 = 0
            while ghostty_render_state_row_iterator_next_dirty(rowIterator, &y) {
                frame.lines.append(VTRow(y: Int(y), cells: readCurrentRow(columns: frame.cols)))
            }
        }

        ghostty_render_state_clean(state)
        forceFullNextFrame = false
        return frame
    }

    // MARK: - Cell decoding

    private func readCurrentRow(columns: Int) -> [VTCell] {
        // Row-local selection is one call per row instead of one per cell.
        var selection = GhosttyRenderStateRowSelection()
        selection.size = MemoryLayout<GhosttyRenderStateRowSelection>.size
        let selectionResult = ghostty_render_state_row_get(
            rowIterator, GHOSTTY_RENDER_STATE_ROW_DATA_SELECTION, &selection
        )
        let selectedRange: ClosedRange<Int>? = selectionResult == GHOSTTY_SUCCESS
            ? Int(selection.start_x)...Int(selection.end_x)
            : nil

        var cells: GhosttyRenderStateRowCells? = rowCells
        guard ghostty_render_state_row_get(
            rowIterator, GHOSTTY_RENDER_STATE_ROW_DATA_CELLS, &cells
        ) == GHOSTTY_SUCCESS, let cells else {
            return Array(repeating: .blank, count: columns)
        }
        rowCells = cells

        var out = [VTCell]()
        out.reserveCapacity(columns)
        var x = 0
        while ghostty_render_state_row_cells_next(cells) {
            out.append(decodeCell(cells, selected: selectedRange?.contains(x) ?? false))
            x += 1
        }
        // A short row (shouldn't happen) is padded so the renderer can index
        // by column without bounds checks everywhere.
        while out.count < columns { out.append(.blank) }
        return out
    }

    private func decodeCell(_ cells: GhosttyRenderStateRowCells, selected: Bool) -> VTCell {
        var cell = VTCell(text: "")
        cell.selected = selected

        var graphemeLen: UInt32 = 0
        ghostty_render_state_row_cells_get(
            cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_GRAPHEMES_LEN, &graphemeLen
        )

        if graphemeLen > 0 {
            // 64 bytes covers any realistic grapheme cluster (a base plus a
            // handful of combining marks or a flag sequence). Anything longer
            // is truncated rather than allocated for on a per-cell path.
            var buf = [UInt8](repeating: 0, count: 64)
            buf.withUnsafeMutableBufferPointer { raw in
                var out = GhosttyBuffer(ptr: raw.baseAddress, cap: raw.count, len: 0)
                if ghostty_render_state_row_cells_get(
                    cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_GRAPHEMES_UTF8, &out
                ) == GHOSTTY_SUCCESS, out.len > 0 {
                    cell.text = String(
                        decoding: UnsafeBufferPointer(start: raw.baseAddress, count: out.len),
                        as: UTF8.self
                    )
                }
            }
        }

        // The raw cell carries the wide/spacer flag, which decides whether a
        // glyph spans two columns or must not be drawn at all.
        var raw: GhosttyCell = 0
        if ghostty_render_state_row_cells_get(
            cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_RAW, &raw
        ) == GHOSTTY_SUCCESS {
            var wide = GHOSTTY_CELL_WIDE_NARROW
            if ghostty_cell_get(raw, GHOSTTY_CELL_DATA_WIDE, &wide) == GHOSTTY_SUCCESS {
                cell.width = VTCellWidth(wide)
            }
        }

        var hasStyling = false
        ghostty_render_state_row_cells_get(
            cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_HAS_STYLING, &hasStyling
        )
        if hasStyling {
            var style = GhosttyStyle()
            style.size = MemoryLayout<GhosttyStyle>.size
            if ghostty_render_state_row_cells_get(
                cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_STYLE, &style
            ) == GHOSTTY_SUCCESS {
                cell.bold = style.bold
                cell.italic = style.italic
                cell.faint = style.faint
                cell.blink = style.blink
                cell.inverse = style.inverse
                cell.invisible = style.invisible
                cell.strikethrough = style.strikethrough
                cell.overline = style.overline
                cell.underline = VTUnderlineStyle(rawValue: Int32(style.underline)) ?? .none
                if style.underline_color.tag == GHOSTTY_STYLE_COLOR_RGB {
                    cell.underlineColor = VTColor(style.underline_color.value.rgb)
                }
            }
        }

        // Resolved colours flatten palette indices and content-tag colours;
        // GHOSTTY_INVALID_VALUE means "no explicit colour, use the default".
        var fg = GhosttyColorRgb()
        if ghostty_render_state_row_cells_get(
            cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_FG_COLOR, &fg
        ) == GHOSTTY_SUCCESS {
            cell.fg = VTColor(fg)
        }
        var bg = GhosttyColorRgb()
        if ghostty_render_state_row_cells_get(
            cells, GHOSTTY_RENDER_STATE_ROW_CELLS_DATA_BG_COLOR, &bg
        ) == GHOSTTY_SUCCESS {
            cell.bg = VTColor(bg)
        }

        return cell
    }
}
