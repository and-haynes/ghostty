import CoreText
import UIKit

/// The four font faces a terminal needs, plus the cell metrics derived from
/// them.
///
/// Cell width comes from the advance of a single glyph rather than from
/// measuring a string: a terminal grid is defined by one advance repeated, and
/// measuring a string would let kerning or shaping creep in and slowly
/// de-align the grid.
struct TerminalFontSet {
    let size: CGFloat
    let regular: CTFont
    let bold: CTFont
    let italic: CTFont
    let boldItalic: CTFont

    let cellWidth: CGFloat
    let cellHeight: CGFloat
    let ascent: CGFloat
    let descent: CGFloat
    let underlineOffset: CGFloat
    let underlineThickness: CGFloat

    init(size: CGFloat) {
        let clamped = min(max(size, 6), 32)
        self.size = clamped

        let regularUI = UIFont.monospacedSystemFont(ofSize: clamped, weight: .regular)
        let boldUI = UIFont.monospacedSystemFont(ofSize: clamped, weight: .bold)
        regular = regularUI as CTFont
        bold = boldUI as CTFont
        italic = TerminalFontSet.italicised(regularUI)
        boldItalic = TerminalFontSet.italicised(boldUI)

        ascent = CTFontGetAscent(regular)
        descent = CTFontGetDescent(regular)
        let leading = CTFontGetLeading(regular)
        cellHeight = (ascent + descent + leading).rounded(.up)

        var glyph = CGGlyph()
        var character: UniChar = 0x4D  // "M"
        var advance = CGSize.zero
        if CTFontGetGlyphsForCharacters(regular, &character, &glyph, 1) {
            CTFontGetAdvancesForGlyphs(regular, .horizontal, &glyph, &advance, 1)
        }
        // A zero advance would divide by zero when sizing the grid; the
        // fallback is deliberately ugly rather than crashing.
        cellWidth = advance.width > 0 ? advance.width.rounded(.up) : (clamped * 0.6).rounded(.up)

        underlineOffset = max(1, abs(CTFontGetUnderlinePosition(regular)))
        underlineThickness = max(1, CTFontGetUnderlineThickness(regular).rounded(.up))
    }

    func font(bold isBold: Bool, italic isItalic: Bool) -> CTFont {
        switch (isBold, isItalic) {
        case (false, false): return regular
        case (true, false): return bold
        case (false, true): return italic
        case (true, true): return boldItalic
        }
    }

    private static func italicised(_ font: UIFont) -> CTFont {
        // Most monospaced system fonts have no true italic; the matrix skew is
        // what Terminal.app and friends fall back to, and it is better than
        // silently rendering italics as regular.
        if let descriptor = font.fontDescriptor.withSymbolicTraits(
            font.fontDescriptor.symbolicTraits.union(.traitItalic)
        ) {
            let candidate = UIFont(descriptor: descriptor, size: font.pointSize)
            if candidate.fontDescriptor.symbolicTraits.contains(.traitItalic) {
                return candidate as CTFont
            }
        }
        let skew = CGAffineTransform(a: 1, b: 0, c: 0.21, d: 1, tx: 0, ty: 0)
        return CTFontCreateCopyWithAttributes(font as CTFont, font.pointSize, [skew], nil)
    }
}
