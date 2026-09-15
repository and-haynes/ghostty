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

    override var inputAccessoryView: UIView? { keyBarEnabled ? keyBarHost : nil }

    var hasText: Bool { true }

    func insertText(_ text: String) {
        guard let session else { return }
        session.sendText(text, mods: keyBarModel.consumeMods())
    }

    func deleteBackward() {
        guard let session else { return }
        session.sendKey(GHOSTTY_KEY_BACKSPACE, mods: keyBarModel.consumeMods())
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
            mods.formUnion(keyBarModel.activeMods)

            if let mapped = HIDKeyMap.key(forHIDUsage: key.keyCode),
               HIDKeyMap.isNonTextKey(key.keyCode) {
                _ = keyBarModel.consumeMods()
                session.sendKey(mapped, mods: mods)
                continue
            }

            // A modified character (ctrl-c, alt-b) has to be encoded from the
            // logical key: `insertText` would only ever see the plain text,
            // and for ctrl combinations iOS often delivers no text at all.
            if !mods.isDisjoint(with: [.ctrl, .alt, .command]),
               let character = key.charactersIgnoringModifiers.first {
                _ = keyBarModel.consumeMods()
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

extension TerminalUIView {
    func handleKeyBar(_ action: KeyBarAction, mods: VTMods) {
        guard let session else { return }
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
        case .function(let index):
            guard let key = HIDKeyMap.functionKey(index) else { return }
            session.sendKey(key, mods: mods)
        case .literal(let text): session.sendText(text, mods: mods)
        case .paste: pasteFromClipboard()
        case .hideKeyboard: resignFirstResponder()
        }
    }

    override func becomeFirstResponder() -> Bool {
        let became = super.becomeFirstResponder()
        updateKeyboardButton()
        return became
    }

    override func resignFirstResponder() -> Bool {
        let resigned = super.resignFirstResponder()
        // A modifier armed for a key you never pressed should not survive the
        // keyboard going away and surprise the next thing you type.
        keyBarModel.clearMods()
        updateKeyboardButton()
        return resigned
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
