import GhosttyVt
import UIKit

// MARK: - Keyboard input
//
// `UIKeyInput` is the minimum that makes the software keyboard appear and
// deliver text. Full `UITextInput` conformance would additionally give marked
// text (IME composition) and the system text-selection UI; a terminal wants
// neither — it has its own selection model and a shell has no text document
// to navigate. What that costs us is CJK/IME composition, which is a stated
// limitation rather than an oversight.
extension TerminalUIView: UIKeyInput, UITextInputTraits {
    override var canBecomeFirstResponder: Bool { true }

    override var inputAccessoryView: UIView? { keyBarEnabled ? keyBarView : nil }

    var hasText: Bool { true }

    func insertText(_ text: String) {
        guard let session else { return }
        let mods = keyBarView.consumeStickyMods()
        session.sendText(text, mods: mods)
    }

    func deleteBackward() {
        guard let session else { return }
        let mods = keyBarView.consumeStickyMods()
        session.sendKey(GHOSTTY_KEY_BACKSPACE, mods: mods)
    }

    // Terminals want raw bytes, not an autocorrected, capitalised,
    // smart-quoted approximation of what you typed.
    var autocorrectionType: UITextAutocorrectionType {
        get { .no }
        set { _ = newValue }
    }
    var autocapitalizationType: UITextAutocapitalizationType {
        get { .none }
        set { _ = newValue }
    }
    var spellCheckingType: UITextSpellCheckingType {
        get { .no }
        set { _ = newValue }
    }
    var smartQuotesType: UITextSmartQuotesType {
        get { .no }
        set { _ = newValue }
    }
    var smartDashesType: UITextSmartDashesType {
        get { .no }
        set { _ = newValue }
    }
    var smartInsertDeleteType: UITextSmartInsertDeleteType {
        get { .no }
        set { _ = newValue }
    }
    var keyboardType: UIKeyboardType {
        get { .asciiCapable }
        set { _ = newValue }
    }
    var returnKeyType: UIReturnKeyType {
        get { .default }
        set { _ = newValue }
    }
    var enablesReturnKeyAutomatically: Bool {
        get { false }
        set { _ = newValue }
    }
}

// MARK: - Hardware keyboard

extension TerminalUIView {
    override func pressesBegan(_ presses: Set<UIPress>, with event: UIPressesEvent?) {
        guard let session else {
            super.pressesBegan(presses, with: event)
            return
        }

        var unhandled = Set<UIPress>()
        for press in presses {
            guard let key = press.key else {
                unhandled.insert(press)
                continue
            }

            var mods = HIDKeyMap.mods(from: key.modifierFlags)
            mods.formUnion(keyBarView.stickyMods)

            if let mapped = HIDKeyMap.key(forHIDUsage: key.keyCode),
               HIDKeyMap.isNonTextKey(key.keyCode) {
                _ = keyBarView.consumeStickyMods()
                session.sendKey(mapped, mods: mods)
                continue
            }

            // A modified character (ctrl-c, alt-b) has to be encoded from the
            // logical key: `insertText` would only ever see the plain text,
            // and for ctrl combinations iOS often delivers no text at all.
            if !mods.isDisjoint(with: [.ctrl, .alt, .command]),
               let character = key.charactersIgnoringModifiers.first {
                _ = keyBarView.consumeStickyMods()
                let logical = HIDKeyMap.key(forCharacter: character)
                session.sendKey(
                    logical,
                    mods: mods,
                    text: logical == GHOSTTY_KEY_UNIDENTIFIED ? String(character) : nil
                )
                continue
            }

            // Everything else is plain text: let UIKit route it to insertText
            // so dead keys and layouts keep working.
            unhandled.insert(press)
        }

        if !unhandled.isEmpty {
            super.pressesBegan(unhandled, with: event)
        }
    }
}

// MARK: - Key bar

extension TerminalUIView: TerminalKeyBarDelegate {
    func keyBar(_ bar: TerminalKeyBar, didPress action: TerminalKeyBar.Action) {
        guard let session else { return }
        let mods = bar.consumeStickyMods()

        switch action {
        case .escape: session.sendKey(GHOSTTY_KEY_ESCAPE, mods: mods)
        case .tab: session.sendKey(GHOSTTY_KEY_TAB, mods: mods)
        case .up: session.sendKey(GHOSTTY_KEY_ARROW_UP, mods: mods)
        case .down: session.sendKey(GHOSTTY_KEY_ARROW_DOWN, mods: mods)
        case .left: session.sendKey(GHOSTTY_KEY_ARROW_LEFT, mods: mods)
        case .right: session.sendKey(GHOSTTY_KEY_ARROW_RIGHT, mods: mods)
        case .home: session.sendKey(GHOSTTY_KEY_HOME, mods: mods)
        case .end: session.sendKey(GHOSTTY_KEY_END, mods: mods)
        case .pageUp: session.sendKey(GHOSTTY_KEY_PAGE_UP, mods: mods)
        case .pageDown: session.sendKey(GHOSTTY_KEY_PAGE_DOWN, mods: mods)
        case .literal(let text): session.sendText(text, mods: mods)
        case .paste: pasteFromClipboard()
        case .hideKeyboard: resignFirstResponder()
        }
    }

    func keyBarDidChangeStickyMods(_ bar: TerminalKeyBar) {
        // Nothing to do: the bar draws its own armed state. Hook point for a
        // future status-bar indicator.
    }
}

// MARK: - Edit menu

extension TerminalUIView: @preconcurrency UIEditMenuInteractionDelegate {
    func editMenuInteraction(
        _ interaction: UIEditMenuInteraction,
        menuFor configuration: UIEditMenuConfiguration,
        suggestedActions: [UIMenuElement]
    ) -> UIMenu? {
        var actions: [UIAction] = []
        if session?.terminal.hasSelection == true {
            actions.append(UIAction(title: "Copy", image: UIImage(systemName: "doc.on.doc")) { [weak self] _ in
                self?.copySelection()
            })
        }
        if UIPasteboard.general.hasStrings {
            actions.append(UIAction(title: "Paste", image: UIImage(systemName: "doc.on.clipboard")) { [weak self] _ in
                self?.pasteFromClipboard()
            })
        }
        actions.append(UIAction(title: "Select All", image: UIImage(systemName: "selection.pin.in.out")) { [weak self] _ in
            guard let session = self?.session else { return }
            _ = session.terminal.selectAll()
            session.invalidateRender()
        })
        return actions.isEmpty ? nil : UIMenu(children: actions)
    }
}
