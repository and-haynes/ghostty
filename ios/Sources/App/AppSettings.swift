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
        static let trustedCAs = "settings.trustedCertificateAuthorities"
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

    /// Public keys of the certificate authorities trusted to vouch for a *host*,
    /// one per line, as they appear in the CA's `.pub` file. OpenSSH's
    /// `@cert-authority` lines, without the pattern.
    ///
    /// Public keys, so UserDefaults is the right home — but it is the pivot the
    /// whole host-certificate feature turns on, because a client only offers the
    /// `*-cert-v01@openssh.com` host key algorithms when this is non-empty. With
    /// no CA configured, a certified host presents its plain key and
    /// trust-on-first-use works exactly as it did before.
    @Published var trustedCertificateAuthorities: String {
        didSet { defaults.set(trustedCertificateAuthorities, forKey: Key.trustedCAs) }
    }

    /// The parsed form, with the unparseable lines kept so the UI can point at
    /// them rather than silently ignoring a typo'd CA.
    var trustedAuthorities: SSHTrustedAuthorities {
        SSHTrustedAuthorities(text: self.trustedCertificateAuthorities)
    }

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
        trustedCertificateAuthorities = defaults.string(forKey: Key.trustedCAs) ?? ""
    }
}
