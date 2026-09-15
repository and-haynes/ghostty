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
        case .hideKeyboard: _ = resignFirstResponder()
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
    /// The terminal's edit menu: the system's standard items first, then ours.
    ///
    /// `suggestedActions` is where Copy / Paste / Select All come from, built by
    /// UIKit from `canPerformAction(_:withSender:)`. Using them rather than
    /// hand-rolled look-alikes is what makes Paste work without the "Allow
    /// Paste?" alert, and it is what an XCUITest finds when it looks for a menu
    /// item called "Paste".
    ///
    /// The fallback matters too: this interaction can be triggered while the
    /// terminal is not the first responder (the keyboard is hidden, or a
    /// hardware keyboard is attached), and an empty `suggestedActions` in that
    /// state would otherwise mean an empty menu.
    func editMenuInteraction(
        _ interaction: UIEditMenuInteraction,
        menuFor configuration: UIEditMenuConfiguration,
        suggestedActions: [UIMenuElement]
    ) -> UIMenu? {
        var children: [UIMenuElement] = suggestedActions
        if children.isEmpty {
            children = fallbackEditActions()
        }
        children.append(contentsOf: terminalSelectionActions())
        return children.isEmpty ? nil : UIMenu(children: children)
    }

    /// Copy / Paste / Select All, for the case where UIKit offered none.
    private func fallbackEditActions() -> [UIMenuElement] {
        var actions: [UIMenuElement] = []
        if session?.terminal.hasSelection == true {
            actions.append(
                UIAction(title: "Copy", image: UIImage(systemName: "doc.on.doc")) { [weak self] _ in
                    self?.copySelection()
                }
            )
        }
        if UIPasteboard.general.hasStrings {
            actions.append(
                UIAction(title: "Paste", image: UIImage(systemName: "doc.on.clipboard")) { [weak self] _ in
                    self?.pasteFromClipboard()
                }
            )
        }
        actions.append(
            UIAction(title: "Select All", image: UIImage(systemName: "selection.pin.in.out")) {
                [weak self] _ in
                self?.selectAll(nil)
            }
        )
        return actions
    }

    /// The terminal-specific selections: the word under the finger, and the
    /// input/output ranges the selection helper also offers as chips.
    private func terminalSelectionActions() -> [UIMenuElement] {
        guard session != nil else { return [] }
        var actions: [UIAction] = [
            UIAction(title: "Select Word", image: UIImage(systemName: "textformat.abc")) {
                [weak self] _ in
                self?.selectWordAtMenuPoint()
            }
        ]
        let derived = currentSelectionSuggestion()
        if derived.inputRows != nil {
            actions.append(
                UIAction(title: "Select Input", image: UIImage(systemName: "chevron.right")) {
                    [weak self] _ in
                    self?.selectSuggested(.input)
                }
            )
        }
        if derived.outputRows != nil {
            actions.append(
                UIAction(title: "Select Output", image: UIImage(systemName: "text.alignleft")) {
                    [weak self] _ in
                    self?.selectSuggested(.output)
                }
            )
        }
        return [UIMenu(title: "", options: .displayInline, children: actions)]
    }
}
