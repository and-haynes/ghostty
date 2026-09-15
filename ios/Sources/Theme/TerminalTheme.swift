import Foundation

/// A terminal colour scheme.
///
/// Themes are data, not code: each is 16 ANSI colours plus the four
/// "chrome" colours. The remaining 240 palette entries (the 6×6×6 cube and
/// the greyscale ramp) are identical across every scheme, so they are taken
/// from libghostty-vt's own default palette rather than restated here.
struct TerminalTheme: Identifiable, Hashable {
    var id: String { name }
    let name: String
    let background: VTColor
    let foreground: VTColor
    let cursor: VTColor
    let selectionBackground: VTColor
    /// nil means "keep each cell's own foreground under the selection".
    let selectionForeground: VTColor?
    /// The 16 ANSI colours, in order: black..white then bright black..bright white.
    let ansi: [VTColor]

    /// The full 256-entry palette: this theme's 16 ANSI colours over the
    /// library's default cube and ramp.
    var palette: [VTColor] {
        var p = VTPalette.default
        for (i, c) in ansi.prefix(16).enumerated() { p[i] = c }
        return p
    }

    private static func c(_ hex: String) -> VTColor {
        // Every literal below is a checked-in constant, so a nil here is a
        // typo in this file and nothing a user can trigger.
        VTColor(hex: hex) ?? .black
    }

    /// Ghostty's own defaults, so a session looks the same as it does on the
    /// desktop app.
    static let ghosttyDefault = TerminalTheme(
        name: "Ghostty",
        background: c("#282C34"),
        foreground: c("#FFFFFF"),
        cursor: c("#FFFFFF"),
        selectionBackground: c("#3E4451"),
        selectionForeground: nil,
        ansi: VTPalette.default.prefix(16).map { $0 }
    )

    static let catppuccinMocha = TerminalTheme(
        name: "Catppuccin Mocha",
        background: c("#1E1E2E"),
        foreground: c("#CDD6F4"),
        cursor: c("#F5E0DC"),
        selectionBackground: c("#585B70"),
        selectionForeground: c("#CDD6F4"),
        ansi: [
            c("#45475A"), c("#F38BA8"), c("#A6E3A1"), c("#F9E2AF"),
            c("#89B4FA"), c("#F5C2E7"), c("#94E2D5"), c("#BAC2DE"),
            c("#585B70"), c("#F38BA8"), c("#A6E3A1"), c("#F9E2AF"),
            c("#89B4FA"), c("#F5C2E7"), c("#94E2D5"), c("#A6ADC8"),
        ]
    )

    static let gruvboxDark = TerminalTheme(
        name: "Gruvbox Dark",
        background: c("#282828"),
        foreground: c("#EBDBB2"),
        cursor: c("#EBDBB2"),
        selectionBackground: c("#504945"),
        selectionForeground: c("#EBDBB2"),
        ansi: [
            c("#282828"), c("#CC241D"), c("#98971A"), c("#D79921"),
            c("#458588"), c("#B16286"), c("#689D6A"), c("#A89984"),
            c("#928374"), c("#FB4934"), c("#B8BB26"), c("#FABD2F"),
            c("#83A598"), c("#D3869B"), c("#8EC07C"), c("#EBDBB2"),
        ]
    )

    static let solarizedDark = TerminalTheme(
        name: "Solarized Dark",
        background: c("#002B36"),
        foreground: c("#839496"),
        cursor: c("#93A1A1"),
        selectionBackground: c("#073642"),
        selectionForeground: c("#93A1A1"),
        ansi: [
            c("#073642"), c("#DC322F"), c("#859900"), c("#B58900"),
            c("#268BD2"), c("#D33682"), c("#2AA198"), c("#EEE8D5"),
            c("#002B36"), c("#CB4B16"), c("#586E75"), c("#657B83"),
            c("#839496"), c("#6C71C4"), c("#93A1A1"), c("#FDF6E3"),
        ]
    )

    static let nord = TerminalTheme(
        name: "Nord",
        background: c("#2E3440"),
        foreground: c("#D8DEE9"),
        cursor: c("#D8DEE9"),
        selectionBackground: c("#434C5E"),
        selectionForeground: c("#ECEFF4"),
        ansi: [
            c("#3B4252"), c("#BF616A"), c("#A3BE8C"), c("#EBCB8B"),
            c("#81A1C1"), c("#B48EAD"), c("#88C0D0"), c("#E5E9F0"),
            c("#4C566A"), c("#BF616A"), c("#A3BE8C"), c("#EBCB8B"),
            c("#81A1C1"), c("#B48EAD"), c("#8FBCBB"), c("#ECEFF4"),
        ]
    )

    static let all: [TerminalTheme] = [
        .ghosttyDefault, .catppuccinMocha, .gruvboxDark, .solarizedDark, .nord,
    ]

    static func named(_ name: String) -> TerminalTheme {
        all.first { $0.name == name } ?? .ghosttyDefault
    }
}
