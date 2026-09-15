import CoreText
import GhosttyVt
import UIKit

/// The terminal grid, drawn with CoreText.
///
/// ## Why a UIView and not SwiftUI
/// A terminal repaints on every keystroke and every byte from the network, at
/// cell granularity. SwiftUI's diffing is the wrong tool: the view hierarchy
/// would be thousands of nodes and the work per frame would dwarf the drawing.
/// Here a frame is a bitmap blit of the rows that actually changed.
///
/// ## Incremental redraw
/// libghostty-vt reports which rows are dirty. We keep a full model of the
/// screen (partial frames only carry the changed rows) and call
/// `setNeedsDisplay(_:)` once per dirty row rect; UIKit preserves the rest of
/// the layer's contents, so untouched rows are never rasterised again. The
/// cursor's old and new rows are added by hand — a cursor move does not
/// necessarily dirty a row's contents, but it does change its pixels.
@MainActor
final class TerminalUIView: UIView {
    // MARK: Model

    var session: TerminalSession? {
        didSet {
            oldValue?.onNeedsRedraw = nil
            guard let session else { return }
            session.onNeedsRedraw = { [weak self] in self?.pump() }
            session.onBell = { [weak self] in self?.bell() }
            fontSet = TerminalFontSet(size: session.fontSize)
            lines = []
            model = VTFrame()
            syncGeometry(force: true)
            session.startIfNeeded()
            pump()
        }
    }

    /// Called when the user pinches, so the owning view can persist the size.
    var onFontSizeChanged: ((CGFloat) -> Void)?
    /// Called when a paste is requested but the clipboard text looks unsafe;
    /// the host UI decides whether to confirm.
    var onUnsafePaste: ((String, @escaping (Bool) -> Void) -> Void)?
    /// Whether to show the accessory key bar. Someone with a hardware keyboard
    /// does not need it and it costs 46 points of terminal.
    var keyBarEnabled = true {
        didSet {
            guard keyBarEnabled != oldValue, isFirstResponder else { return }
            // inputAccessoryView is only re-read when the responder chain is
            // rebuilt, so bounce first-responder status to apply the change.
            reloadInputViews()
        }
    }

    private(set) var fontSet = TerminalFontSet(size: 12)
    private var model = VTFrame()
    private var lines: [VTRow] = []
    private var lastCursor: (x: Int, y: Int)?

    private let padding = CGSize(width: 4, height: 4)

    // MARK: Input state

    lazy var keyBarView: TerminalKeyBar = {
        let bar = TerminalKeyBar()
        bar.delegate = self
        return bar
    }()

    private var editMenuInteraction: UIEditMenuInteraction?
    private var selectionAnchor: (x: Int, y: Int)?
    private var scrollAccumulator: CGFloat = 0
    private var pinchStartFontSize: CGFloat = 12

    // MARK: Init

    override init(frame: CGRect) {
        super.init(frame: frame)
        commonInit()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    private func commonInit() {
        backgroundColor = .black
        isOpaque = true
        contentMode = .redraw
        // Partial invalidation only pays off if UIKit keeps the rest of the
        // layer; clearing the whole context every draw would defeat it.
        clearsContextBeforeDrawing = true
        isMultipleTouchEnabled = true

        let tap = UITapGestureRecognizer(target: self, action: #selector(handleTap))
        addGestureRecognizer(tap)

        let pan = UIPanGestureRecognizer(target: self, action: #selector(handlePan))
        pan.maximumNumberOfTouches = 2
        addGestureRecognizer(pan)

        let longPress = UILongPressGestureRecognizer(target: self, action: #selector(handleLongPress))
        longPress.minimumPressDuration = 0.35
        addGestureRecognizer(longPress)
        // Selection wins over scrolling once a long press has begun.
        pan.require(toFail: longPress)

        let pinch = UIPinchGestureRecognizer(target: self, action: #selector(handlePinch))
        addGestureRecognizer(pinch)

        let interaction = UIEditMenuInteraction(delegate: self)
        addInteraction(interaction)
        editMenuInteraction = interaction
    }

    // MARK: Geometry

    override func layoutSubviews() {
        super.layoutSubviews()
        syncGeometry()
    }

    private var gridSize: (cols: Int, rows: Int) {
        let usableWidth = max(0, bounds.width - padding.width * 2)
        let usableHeight = max(0, bounds.height - padding.height * 2)
        return (
            max(2, Int(usableWidth / fontSet.cellWidth)),
            max(1, Int(usableHeight / fontSet.cellHeight))
        )
    }

    private func syncGeometry(force: Bool = false) {
        guard let session, bounds.width > 0, bounds.height > 0 else { return }
        let size = gridSize
        guard force || size.cols != session.cols || size.rows != session.rows else { return }

        // Drop the cached screen *before* resizing, not after. `session.resize`
        // invalidates the render state and calls back into `pump()`
        // synchronously, which refills `lines`; clearing afterwards threw that
        // fresh frame away and left the view blank until the next byte
        // arrived. That is exactly the bug that made a freshly opened terminal
        // show nothing but its background colour.
        lines = []
        setNeedsDisplay()
        session.resize(
            cols: size.cols,
            rows: size.rows,
            cellWidth: fontSet.cellWidth,
            cellHeight: fontSet.cellHeight
        )
    }

    func setFontSize(_ size: CGFloat) {
        guard let session else { return }
        let clamped = min(max(size, 7), 28)
        guard abs(clamped - fontSet.size) > 0.01 else { return }
        fontSet = TerminalFontSet(size: clamped)
        session.fontSize = clamped
        onFontSizeChanged?(clamped)
        syncGeometry(force: true)
        session.invalidateRender()
    }

    private func rowRect(_ y: Int) -> CGRect {
        CGRect(
            x: 0,
            y: padding.height + CGFloat(y) * fontSet.cellHeight,
            width: bounds.width,
            height: fontSet.cellHeight
        )
    }

    private func gridPoint(at location: CGPoint) -> (x: Int, y: Int) {
        let column = Int((location.x - padding.width) / fontSet.cellWidth)
        let row = Int((location.y - padding.height) / fontSet.cellHeight)
        return (
            min(max(0, column), max(0, model.cols - 1)),
            min(max(0, row), max(0, model.rowCount - 1))
        )
    }

    // MARK: Frame pump

    private func pump() {
        guard let session, let frame = session.nextFrame() else { return }

        var dirty = Set<Int>()
        let rowCount = frame.rowCount

        if frame.dirty == .full || lines.count != rowCount {
            lines = Array(repeating: VTRow(y: 0, cells: []), count: rowCount)
            for row in frame.lines where row.y < rowCount { lines[row.y] = row }
            dirty.formUnion(0..<rowCount)
        } else {
            for row in frame.lines where row.y < rowCount {
                lines[row.y] = row
                dirty.insert(row.y)
            }
        }

        model = frame
        model.lines = []  // the full model lives in `lines`; don't keep two copies

        // A cursor move repaints two rows even when neither row's text changed.
        if let old = lastCursor { dirty.insert(old.y) }
        if let cursor = frame.cursor { dirty.insert(cursor.y) }
        lastCursor = frame.cursor.map { ($0.x, $0.y) }

        backgroundColor = UIColor(cgColor: frame.background.cgColor)

        if dirty.count >= rowCount {
            setNeedsDisplay()
        } else {
            for y in dirty { setNeedsDisplay(rowRect(y)) }
        }
    }

    private func bell() {
        // No sound: a terminal that beeps in a pocket is a bad citizen.
        UIImpactFeedbackGenerator(style: .light).impactOccurred()
    }

    // MARK: Drawing

    override func draw(_ rect: CGRect) {
        guard let ctx = UIGraphicsGetCurrentContext() else { return }

        ctx.setFillColor(model.background.cgColor)
        ctx.fill(rect)
        guard !lines.isEmpty else { return }

        let first = max(0, Int((rect.minY - padding.height) / fontSet.cellHeight))
        let last = min(lines.count - 1, Int((rect.maxY - padding.height) / fontSet.cellHeight))
        guard first <= last else { return }

        for y in first...last {
            drawRow(lines[y], at: y, in: ctx)
        }

        if let cursor = model.cursor, cursor.visible,
           cursor.y >= first, cursor.y <= last {
            drawCursor(cursor, in: ctx)
        }
    }

    private func drawRow(_ row: VTRow, at y: Int, in ctx: CGContext) {
        guard !row.cells.isEmpty else { return }
        let top = padding.height + CGFloat(y) * fontSet.cellHeight
        let baseline = top + fontSet.ascent

        let theme = session?.theme ?? .ghosttyDefault
        let defaultFg = model.foreground
        let defaultBg = model.background

        // Pass 1: backgrounds, coalesced into spans so a filled line is one
        // rect rather than eighty.
        var spanStart = 0
        var spanColor: VTColor?
        func flushSpan(end: Int) {
            guard let color = spanColor, end > spanStart else { return }
            ctx.setFillColor(color.cgColor)
            ctx.fill(CGRect(
                x: padding.width + CGFloat(spanStart) * fontSet.cellWidth,
                y: top,
                width: CGFloat(end - spanStart) * fontSet.cellWidth,
                height: fontSet.cellHeight
            ))
        }
        for (x, cell) in row.cells.enumerated() {
            let color = backgroundColor(for: cell, theme: theme, defaultFg: defaultFg, defaultBg: defaultBg)
            if color != spanColor {
                flushSpan(end: x)
                spanStart = x
                spanColor = color
            }
        }
        flushSpan(end: row.cells.count)

        // Pass 2: glyphs, bucketed by (face, colour) so each bucket is one
        // CTFontDrawGlyphs call with explicit per-cell positions. Explicit
        // positions are what keeps the grid aligned: shaping a run as a string
        // would let kerning drift it.
        var buckets: [GlyphBucketKey: GlyphBucket] = [:]
        var complex: [(text: String, x: Int, font: CTFont, color: VTColor)] = []

        for (x, cell) in row.cells.enumerated() {
            // The tail of a wide character draws nothing: the head already
            // painted across both columns.
            guard cell.width != .spacerTail, !cell.text.isEmpty, !cell.invisible else { continue }

            let colors = resolvedColors(for: cell, theme: theme, defaultFg: defaultFg, defaultBg: defaultBg)
            var fg = colors.fg
            if cell.faint { fg = fade(fg, towards: colors.bg, amount: 0.4) }

            let font = fontSet.font(bold: cell.bold, italic: cell.italic)
            let originX = padding.width + CGFloat(x) * fontSet.cellWidth

            var units = Array(cell.text.utf16)
            if units.count == 1 {
                var glyph = CGGlyph()
                if CTFontGetGlyphsForCharacters(font, &units, &glyph, 1), glyph != 0 {
                    let key = GlyphBucketKey(font: font, color: fg)
                    // y is 0 because glyphs are drawn inside a per-row context
                    // flipped about the baseline; see drawGlyphs.
                    buckets[key, default: GlyphBucket()].append(
                        glyph: glyph,
                        at: CGPoint(x: originX, y: 0)
                    )
                    continue
                }
            }
            complex.append((cell.text, x, font, fg))
        }

        drawGlyphs(buckets: buckets, complex: complex, baseline: baseline, in: ctx)

        // Pass 3: decorations.
        for (x, cell) in row.cells.enumerated() {
            guard cell.width != .spacerTail else { continue }
            guard cell.underline != .none || cell.strikethrough || cell.overline else { continue }
            let colors = resolvedColors(for: cell, theme: theme, defaultFg: defaultFg, defaultBg: defaultBg)
            let lineColor = cell.underlineColor ?? colors.fg
            let originX = padding.width + CGFloat(x) * fontSet.cellWidth
            let width = fontSet.cellWidth * (cell.width == .wide ? 2 : 1)

            if cell.underline != .none {
                drawUnderline(
                    cell.underline,
                    color: lineColor,
                    x: originX,
                    y: baseline + fontSet.underlineOffset,
                    width: width,
                    in: ctx
                )
            }
            if cell.strikethrough {
                ctx.setFillColor(colors.fg.cgColor)
                ctx.fill(CGRect(
                    x: originX,
                    y: baseline - fontSet.ascent * 0.32,
                    width: width,
                    height: fontSet.underlineThickness
                ))
            }
            if cell.overline {
                ctx.setFillColor(colors.fg.cgColor)
                ctx.fill(CGRect(x: originX, y: top, width: width, height: fontSet.underlineThickness))
            }
        }
    }

    /// Draw a row's glyphs.
    ///
    /// CoreText glyph positions are in *text* space, which the text matrix maps
    /// into user space. A text matrix that flips y therefore flips the
    /// positions too and throws every glyph off the top of the view — which is
    /// exactly what it did before this was written this way. The reliable form
    /// is to leave the text matrix alone and flip the context itself about the
    /// baseline, so glyphs sit at y = 0 in a y-up space.
    private func drawGlyphs(
        buckets: [GlyphBucketKey: GlyphBucket],
        complex: [(text: String, x: Int, font: CTFont, color: VTColor)],
        baseline: CGFloat,
        in ctx: CGContext
    ) {
        guard !buckets.isEmpty || !complex.isEmpty else { return }
        ctx.saveGState()
        defer { ctx.restoreGState() }

        ctx.textMatrix = .identity
        ctx.translateBy(x: 0, y: baseline)
        ctx.scaleBy(x: 1, y: -1)

        for (key, bucket) in buckets {
            ctx.setFillColor(key.color.cgColor)
            bucket.draw(font: key.font, in: ctx)
        }

        for item in complex {
            let attributed = NSAttributedString(string: item.text, attributes: [
                .font: item.font,
                .foregroundColor: UIColor(cgColor: item.color.cgColor),
                .ligature: 0,
            ])
            let line = CTLineCreateWithAttributedString(attributed)
            ctx.textPosition = CGPoint(x: padding.width + CGFloat(item.x) * fontSet.cellWidth, y: 0)
            CTLineDraw(line, ctx)
        }
    }

    private func drawUnderline(
        _ style: VTUnderlineStyle,
        color: VTColor,
        x: CGFloat,
        y: CGFloat,
        width: CGFloat,
        in ctx: CGContext
    ) {
        ctx.setFillColor(color.cgColor)
        let thickness = fontSet.underlineThickness
        switch style {
        case .none:
            return
        case .single, .curly:
            // A curly underline is approximated by a solid one; drawing a real
            // sine wave per cell is not worth the cycles on a phone.
            ctx.fill(CGRect(x: x, y: y, width: width, height: thickness))
        case .double:
            ctx.fill(CGRect(x: x, y: y, width: width, height: thickness))
            ctx.fill(CGRect(x: x, y: y + thickness * 2, width: width, height: thickness))
        case .dotted, .dashed:
            let step = style == .dotted ? thickness * 2 : thickness * 4
            var dx: CGFloat = 0
            while dx < width {
                ctx.fill(CGRect(x: x + dx, y: y, width: min(step / 2, width - dx), height: thickness))
                dx += step
            }
        }
    }

    private func drawComplexGlyph(
        _ text: String,
        font: CTFont,
        color: VTColor,
        column: Int,
        baseline: CGFloat,
        in ctx: CGContext
    ) {
        // Multi-codepoint grapheme clusters (emoji, combining marks) need real
        // shaping; CTLine handles font fallback too, which bare glyph lookup
        // does not.
        ctx.saveGState()
        defer { ctx.restoreGState() }
        ctx.textMatrix = .identity
        ctx.translateBy(x: 0, y: baseline)
        ctx.scaleBy(x: 1, y: -1)

        let attributed = NSAttributedString(string: text, attributes: [
            .font: font,
            .foregroundColor: UIColor(cgColor: color.cgColor),
            .ligature: 0,
        ])
        let line = CTLineCreateWithAttributedString(attributed)
        ctx.textPosition = CGPoint(x: padding.width + CGFloat(column) * fontSet.cellWidth, y: 0)
        CTLineDraw(line, ctx)
    }

    private func drawCursor(_ cursor: VTCursor, in ctx: CGContext) {
        let theme = session?.theme ?? .ghosttyDefault
        let color = model.cursorColor ?? theme.cursor
        let x = padding.width + CGFloat(cursor.x) * fontSet.cellWidth
        let y = padding.height + CGFloat(cursor.y) * fontSet.cellHeight
        let width = fontSet.cellWidth
        let height = fontSet.cellHeight

        ctx.setFillColor(color.cgColor)
        switch cursor.style {
        case .block:
            ctx.fill(CGRect(x: x, y: y, width: width, height: height))
            // Re-draw the covered glyph in the background colour so the cell
            // under a block cursor stays legible.
            if cursor.y < lines.count, cursor.x < lines[cursor.y].cells.count {
                let cell = lines[cursor.y].cells[cursor.x]
                if !cell.text.isEmpty {
                    drawComplexGlyph(
                        cell.text,
                        font: fontSet.font(bold: cell.bold, italic: cell.italic),
                        color: model.background,
                        column: cursor.x,
                        baseline: y + fontSet.ascent,
                        in: ctx
                    )
                }
            }
        case .blockHollow:
            ctx.setStrokeColor(color.cgColor)
            ctx.stroke(CGRect(x: x + 0.5, y: y + 0.5, width: width - 1, height: height - 1), width: 1)
        case .bar:
            ctx.fill(CGRect(x: x, y: y, width: max(1, width * 0.15), height: height))
        case .underline:
            ctx.fill(CGRect(x: x, y: y + height - 2, width: width, height: 2))
        }
    }

    // MARK: Colour resolution

    private func resolvedColors(
        for cell: VTCell,
        theme: TerminalTheme,
        defaultFg: VTColor,
        defaultBg: VTColor
    ) -> (fg: VTColor, bg: VTColor) {
        var fg = cell.fg ?? defaultFg
        var bg = cell.bg ?? defaultBg
        if cell.inverse { swap(&fg, &bg) }
        if cell.selected {
            bg = theme.selectionBackground
            if let selectionFg = theme.selectionForeground { fg = selectionFg }
        }
        return (fg, bg)
    }

    private func backgroundColor(
        for cell: VTCell,
        theme: TerminalTheme,
        defaultFg: VTColor,
        defaultBg: VTColor
    ) -> VTColor? {
        if cell.selected { return theme.selectionBackground }
        if cell.inverse { return cell.fg ?? defaultFg }
        return cell.bg
    }

    private func fade(_ color: VTColor, towards other: VTColor, amount: Double) -> VTColor {
        func mix(_ a: UInt8, _ b: UInt8) -> UInt8 {
            UInt8(max(0, min(255, Double(a) * (1 - amount) + Double(b) * amount)))
        }
        return VTColor(r: mix(color.r, other.r), g: mix(color.g, other.g), b: mix(color.b, other.b))
    }

    // MARK: Gestures

    @objc private func handleTap(_ gesture: UITapGestureRecognizer) {
        if let session, session.terminal.hasSelection {
            session.clearSelection()
            return
        }
        if !isFirstResponder { becomeFirstResponder() }
    }

    @objc private func handlePan(_ gesture: UIPanGestureRecognizer) {
        guard let session else { return }
        switch gesture.state {
        case .began:
            scrollAccumulator = 0
        case .changed:
            let translation = gesture.translation(in: self)
            gesture.setTranslation(.zero, in: self)
            scrollAccumulator += translation.y
            let rowsMoved = Int(scrollAccumulator / fontSet.cellHeight)
            guard rowsMoved != 0 else { return }
            scrollAccumulator -= CGFloat(rowsMoved) * fontSet.cellHeight
            // Dragging down should reveal older output, i.e. scroll back.
            session.scroll(rows: -rowsMoved)
        default:
            break
        }
    }

    @objc private func handleLongPress(_ gesture: UILongPressGestureRecognizer) {
        guard let session else { return }
        let point = gridPoint(at: gesture.location(in: self))
        switch gesture.state {
        case .began:
            selectionAnchor = point
            session.selectWord(atColumn: point.x, row: point.y)
            UIImpactFeedbackGenerator(style: .medium).impactOccurred()
        case .changed:
            guard let anchor = selectionAnchor else { return }
            session.extendSelection(from: anchor, to: point)
        case .ended, .cancelled:
            presentEditMenu(at: gesture.location(in: self))
        default:
            break
        }
    }

    @objc private func handlePinch(_ gesture: UIPinchGestureRecognizer) {
        switch gesture.state {
        case .began:
            pinchStartFontSize = fontSet.size
        case .changed:
            setFontSize(pinchStartFontSize * gesture.scale)
        default:
            break
        }
    }

    private func presentEditMenu(at location: CGPoint) {
        guard let editMenuInteraction else { return }
        editMenuInteraction.presentEditMenu(with: UIEditMenuConfiguration(identifier: nil, sourcePoint: location))
    }

    // MARK: Actions

    @objc func copySelection() {
        guard let text = session?.selectedText, !text.isEmpty else { return }
        UIPasteboard.general.string = text
        session?.clearSelection()
    }

    @objc func pasteFromClipboard() {
        guard let session, let text = UIPasteboard.general.string, !text.isEmpty else { return }
        // A paste containing a newline runs whatever precedes it the moment it
        // lands, so ask first — unless the user has turned the confirmation
        // off, in which case no handler is installed and we paste as asked
        // rather than silently doing nothing.
        if !session.pasteIsSafe(text), let onUnsafePaste {
            onUnsafePaste(text) { [weak session] confirmed in
                if confirmed { session?.paste(text) }
            }
            return
        }
        session.paste(text)
    }

    override func canPerformAction(_ action: Selector, withSender sender: Any?) -> Bool {
        switch action {
        case #selector(copySelection):
            return session?.terminal.hasSelection ?? false
        case #selector(pasteFromClipboard):
            return UIPasteboard.general.hasStrings
        default:
            return super.canPerformAction(action, withSender: sender)
        }
    }
}

// MARK: - Glyph batching

private struct GlyphBucketKey: Hashable {
    let font: CTFont
    let color: VTColor

    static func == (lhs: GlyphBucketKey, rhs: GlyphBucketKey) -> Bool {
        lhs.color == rhs.color && CFEqual(lhs.font, rhs.font)
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(color)
        hasher.combine(CFHash(font))
    }
}

private struct GlyphBucket {
    var glyphs: [CGGlyph] = []
    var positions: [CGPoint] = []

    mutating func append(glyph: CGGlyph, at position: CGPoint) {
        glyphs.append(glyph)
        positions.append(position)
    }

    func draw(font: CTFont, in ctx: CGContext) {
        guard !glyphs.isEmpty else { return }
        CTFontDrawGlyphs(font, glyphs, positions, glyphs.count, ctx)
    }
}
