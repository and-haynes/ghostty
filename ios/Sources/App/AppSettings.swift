import SwiftUI

/// User preferences. Small enough to live in UserDefaults; none of it is
/// secret (secrets are Keychain-only, by construction).
@MainActor
final class AppSettings: ObservableObject {
    private enum Key {
        static let fontSize = "settings.fontSize"
        static let theme = "settings.theme"
        static let term = "settings.term"
        static let keyBar = "settings.keyBarEnabled"
        static let iCloudSync = "settings.iCloudSyncDefault"
        static let scrollbackWarning = "settings.confirmUnsafePaste"
        static let lastUsername = "settings.lastUsername"
    }

    private let defaults: UserDefaults

    @Published var fontSize: Double { didSet { defaults.set(fontSize, forKey: Key.fontSize) } }
    @Published var themeName: String { didSet { defaults.set(themeName, forKey: Key.theme) } }
    @Published var defaultTerm: String { didSet { defaults.set(defaultTerm, forKey: Key.term) } }
    @Published var keyBarEnabled: Bool { didSet { defaults.set(keyBarEnabled, forKey: Key.keyBar) } }
    /// Default for *new* identities only; changing it never moves an existing
    /// key between the local and the synced Keychain.
    @Published var iCloudSyncDefault: Bool { didSet { defaults.set(iCloudSyncDefault, forKey: Key.iCloudSync) } }
    @Published var confirmUnsafePaste: Bool { didSet { defaults.set(confirmUnsafePaste, forKey: Key.scrollbackWarning) } }
    /// Default username for hosts imported from a LAN scan — almost always the
    /// same one across a homelab, and retyping it per host is tedious.
    @Published var lastUsername: String { didSet { defaults.set(lastUsername, forKey: Key.lastUsername) } }

    var theme: TerminalTheme { .named(themeName) }

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        let storedSize = defaults.double(forKey: Key.fontSize)
        fontSize = storedSize > 0 ? storedSize : 12
        themeName = defaults.string(forKey: Key.theme) ?? TerminalTheme.ghosttyDefault.name
        // xterm-256color, not xterm-ghostty: a remote host will almost never
        // have ghostty's terminfo installed, and an unknown TERM breaks every
        // curses program on the far side.
        defaultTerm = defaults.string(forKey: Key.term) ?? "xterm-256color"
        keyBarEnabled = defaults.object(forKey: Key.keyBar) as? Bool ?? true
        iCloudSyncDefault = defaults.object(forKey: Key.iCloudSync) as? Bool ?? false
        confirmUnsafePaste = defaults.object(forKey: Key.scrollbackWarning) as? Bool ?? true
        lastUsername = defaults.string(forKey: Key.lastUsername) ?? ""
    }
}
