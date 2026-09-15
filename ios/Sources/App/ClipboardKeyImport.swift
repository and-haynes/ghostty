import SwiftUI
import UIKit

/// Getting a key out of 1Password and into this app.
///
/// 1Password has no on-device API a third-party iOS app may call — no
/// extension, no local vault access, nothing. The only route for a key stored
/// there is: open the item, reveal the private key, copy it, come back here.
/// That is three taps in another app followed by, previously, opening a sheet,
/// tapping into a text view and pasting. This makes the last part one tap.
///
/// The clipboard read has to go through `UIPasteControl`, and the reason is
/// worth writing down because the obvious approach does not work. Reading
/// `UIPasteboard.general.string` directly is privacy-gated: iOS puts up an
/// "Allow Paste?" alert *and returns nil immediately*, granting access only to
/// some later read. So a plain button gives the user an alert, an empty field,
/// and the need to tap again. `UIPasteControl` is the system control that
/// treats a tap as consent, hands over the contents on the spot, and shows no
/// alert at all.
///
/// The only thing consulted unprompted is `hasStrings`, which iOS exempts
/// deliberately, and which is enough to decide whether to offer the control.
@MainActor
enum ClipboardKeyImport {
    /// Whether to offer the import button at all.
    ///
    /// Deliberately cheap and deliberately vague: this cannot tell a key from a
    /// shopping list without reading the clipboard, and reading it is the thing
    /// we are avoiding until the user asks.
    static var mayHaveKey: Bool {
        UIPasteboard.general.hasStrings
    }

    /// What the clipboard turned out to hold.
    enum Contents {
        case key(text: String, format: PEMKeyFormat, suggestedName: String)
        case encryptedKey
        case notAKey
        case empty
    }

    /// Classify text that arrived from the clipboard.
    static func classify(_ text: String) -> Contents {
        guard !text.isEmpty else { return .empty }
        let format = PEMPrivateKey.detect(text)
        switch format {
        case .encrypted:
            return .encryptedKey
        case .unrecognised:
            return .notAKey
        case .openSSHV1, .pkcs8, .pkcs1RSA, .sec1EC:
            return .key(text: text, format: format, suggestedName: Self.suggestName(for: text))
        }
    }

    /// Wipe the clipboard after a successful import.
    ///
    /// A private key sitting on the system pasteboard is readable by every app
    /// the user opens next, and on a Mac signed into the same iCloud account
    /// through Universal Clipboard. Clearing it is the least we can do, and the
    /// user has just told us they are finished with it.
    static func clear() {
        // Both, deliberately. Emptying `items` is the documented way, but a
        // pasteboard that has been through Universal Clipboard can be left with
        // a promised representation that `items = []` alone does not settle;
        // writing an empty string first guarantees `hasStrings` goes false.
        UIPasteboard.general.string = ""
        UIPasteboard.general.items = []
    }

    /// Read and classify the clipboard directly.
    ///
    /// Raises the system's "Allow Paste?" alert and returns nil until the user
    /// has allowed it, so this is the fallback path for the plain button —
    /// ``PasteKeyControl`` is the one that works first time.
    static func read() -> Contents {
        guard let text = UIPasteboard.general.string else { return .empty }
        return Self.classify(text)
    }

    /// A name to prefill, from the key's own comment where it has one.
    ///
    /// Only `openssh-key-v1` carries a comment; PKCS#8 and PKCS#1 are anonymous,
    /// so those fall back to something the user will recognise as a placeholder.
    private static func suggestName(for text: String) -> String {
        if let parsed = try? PEMPrivateKey.parse(text), !parsed.comment.isEmpty {
            return parsed.comment
        }
        return "1Password key"
    }
}

/// A system paste button that hands over the clipboard without an alert.
///
/// `UIPasteControl` is the only way to read the pasteboard on a single tap:
/// UIKit treats pressing it as the user's consent, so there is no "Allow
/// Paste?" prompt and no nil-on-first-read. The label is the system's, which is
/// why the surrounding row says what the paste is *for*.
struct PasteKeyControl: UIViewRepresentable {
    /// Called on the main actor with whatever text arrived.
    var onPaste: (String) -> Void

    func makeCoordinator() -> Coordinator { Coordinator(onPaste: onPaste) }

    func makeUIView(context: Context) -> UIPasteControl {
        let configuration = UIPasteControl.Configuration()
        configuration.displayMode = .iconAndLabel
        configuration.cornerStyle = .capsule
        let control = UIPasteControl(configuration: configuration)
        control.target = context.coordinator
        return control
    }

    func updateUIView(_ control: UIPasteControl, context: Context) {
        context.coordinator.onPaste = onPaste
        control.target = context.coordinator
    }

    /// `UIPasteControl` delivers through `paste(itemProviders:)`, so its target
    /// has to be a `UIResponder` (which already conforms to
    /// `UIPasteConfigurationSupporting`). This is that responder and nothing
    /// else.
    final class Coordinator: UIResponder {
        var onPaste: (String) -> Void

        init(onPaste: @escaping (String) -> Void) {
            self.onPaste = onPaste
            super.init()
            self.pasteConfiguration = UIPasteConfiguration(
                forAccepting: NSString.self
            )
        }

        override func paste(itemProviders: [NSItemProvider]) {
            for provider in itemProviders where provider.canLoadObject(ofClass: NSString.self) {
                provider.loadObject(ofClass: NSString.self) { [weak self] object, _ in
                    guard let text = object as? NSString else { return }
                    DispatchQueue.main.async { self?.onPaste(text as String) }
                }
                return
            }
        }
    }
}

/// The in-app guide: how to get a key out of 1Password.
struct OnePasswordImportGuide: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    Text(
                        """
                        1Password has no on-device API for third-party apps — no extension, \
                        no local vault access, nothing an iOS app is allowed to call. \
                        Copying the key across by hand is the only route, and it takes \
                        about ten seconds.
                        """
                    )
                    .font(.callout)
                }

                Section("From 1Password") {
                    step(1, "Open the SSH key item.")
                    step(2, "Tap the private key field, then **Reveal**.")
                    step(3, "Tap **Copy** (or press and hold, then Copy).")
                    step(4, "Switch back to Ghostty.")
                }

                Section {
                    step(5, "Keys ▸ + ▸ **Import key from clipboard**.")
                    step(6, "Give it a name and tap Import.")
                } header: {
                    Text("In Ghostty")
                } footer: {
                    Text(
                        """
                        The clipboard is cleared as soon as the key is in the Keychain, so \
                        the next app you open cannot read it.
                        """
                    )
                }

                Section {
                    Text(
                        """
                        Keys exported from 1Password are usually PKCS#8 \
                        (-----BEGIN PRIVATE KEY-----). Ghostty reads that, PKCS#1 \
                        (-----BEGIN RSA PRIVATE KEY-----), SEC 1 \
                        (-----BEGIN EC PRIVATE KEY-----) and OpenSSH's own format. A \
                        passphrase-protected key has to be decrypted first:
                        """
                    )
                    .font(.callout)
                    Text("ssh-keygen -p -N \"\" -f key")
                        .font(.caption.monospaced())
                        .textSelection(.enabled)
                } header: {
                    Text("Formats")
                }

                Section {
                    Text(
                        """
                        If you host **1Password Connect**, Settings ▸ Sync can pull SSH key \
                        items automatically and this whole dance goes away. Connect is a \
                        REST server you run yourself; it is the only automatic route \
                        1Password offers a third-party app.
                        """
                    )
                    .font(.callout)
                } header: {
                    Text("The automatic way")
                }
            }
            .navigationTitle("Import from 1Password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) { Button("Done") { dismiss() } }
            }
        }
    }

    private func step(_ number: Int, _ text: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text("\(number)")
                .font(.caption.weight(.semibold).monospacedDigit())
                .frame(width: 20, height: 20)
                .background(Color.accentColor.opacity(0.18), in: Circle())
            Text(.init(text)).font(.callout)
        }
        .padding(.vertical, 1)
    }
}
