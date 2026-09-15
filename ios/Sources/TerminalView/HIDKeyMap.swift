import GhosttyVt
import UIKit

/// Translates iOS key identities into libghostty-vt's logical keys.
///
/// Two sources, two shapes. A hardware keyboard gives a HID usage code, which
/// maps 1:1 onto a physical key — that is exactly what the encoder wants. The
/// software keyboard gives *text*, from which we recover a logical key so that
/// a sticky Ctrl from the key bar can still turn "c" into 0x03. Text without a
/// recognisable key still works: the encoder falls back to the UTF-8 it was
/// given.
enum HIDKeyMap {
    static func key(forCharacter character: Character) -> GhosttyKey {
        switch character {
        case "a": return GHOSTTY_KEY_A
        case "b": return GHOSTTY_KEY_B
        case "c": return GHOSTTY_KEY_C
        case "d": return GHOSTTY_KEY_D
        case "e": return GHOSTTY_KEY_E
        case "f": return GHOSTTY_KEY_F
        case "g": return GHOSTTY_KEY_G
        case "h": return GHOSTTY_KEY_H
        case "i": return GHOSTTY_KEY_I
        case "j": return GHOSTTY_KEY_J
        case "k": return GHOSTTY_KEY_K
        case "l": return GHOSTTY_KEY_L
        case "m": return GHOSTTY_KEY_M
        case "n": return GHOSTTY_KEY_N
        case "o": return GHOSTTY_KEY_O
        case "p": return GHOSTTY_KEY_P
        case "q": return GHOSTTY_KEY_Q
        case "r": return GHOSTTY_KEY_R
        case "s": return GHOSTTY_KEY_S
        case "t": return GHOSTTY_KEY_T
        case "u": return GHOSTTY_KEY_U
        case "v": return GHOSTTY_KEY_V
        case "w": return GHOSTTY_KEY_W
        case "x": return GHOSTTY_KEY_X
        case "y": return GHOSTTY_KEY_Y
        case "z": return GHOSTTY_KEY_Z
        case "0": return GHOSTTY_KEY_DIGIT_0
        case "1": return GHOSTTY_KEY_DIGIT_1
        case "2": return GHOSTTY_KEY_DIGIT_2
        case "3": return GHOSTTY_KEY_DIGIT_3
        case "4": return GHOSTTY_KEY_DIGIT_4
        case "5": return GHOSTTY_KEY_DIGIT_5
        case "6": return GHOSTTY_KEY_DIGIT_6
        case "7": return GHOSTTY_KEY_DIGIT_7
        case "8": return GHOSTTY_KEY_DIGIT_8
        case "9": return GHOSTTY_KEY_DIGIT_9
        case " ": return GHOSTTY_KEY_SPACE
        case "-": return GHOSTTY_KEY_MINUS
        case "=": return GHOSTTY_KEY_EQUAL
        case "[": return GHOSTTY_KEY_BRACKET_LEFT
        case "]": return GHOSTTY_KEY_BRACKET_RIGHT
        case "\\": return GHOSTTY_KEY_BACKSLASH
        case ";": return GHOSTTY_KEY_SEMICOLON
        case "'": return GHOSTTY_KEY_QUOTE
        case "`": return GHOSTTY_KEY_BACKQUOTE
        case ",": return GHOSTTY_KEY_COMMA
        case ".": return GHOSTTY_KEY_PERIOD
        case "/": return GHOSTTY_KEY_SLASH
        case "\t": return GHOSTTY_KEY_TAB
        default:
            // Uppercase letters are the same physical key as lowercase; the
            // encoder derives the shift from the mods bitmask, not the text.
            let lowered = Character(character.lowercased())
            if lowered != character { return key(forCharacter: lowered) }
            return GHOSTTY_KEY_UNIDENTIFIED
        }
    }

    // swiftlint:disable:next cyclomatic_complexity
    static func key(forHIDUsage usage: UIKeyboardHIDUsage) -> GhosttyKey? {
        switch usage {
        case .keyboardEscape: return GHOSTTY_KEY_ESCAPE
        case .keyboardReturnOrEnter, .keypadEnter: return GHOSTTY_KEY_ENTER
        case .keyboardTab: return GHOSTTY_KEY_TAB
        case .keyboardDeleteOrBackspace: return GHOSTTY_KEY_BACKSPACE
        case .keyboardDeleteForward: return GHOSTTY_KEY_DELETE
        case .keyboardUpArrow: return GHOSTTY_KEY_ARROW_UP
        case .keyboardDownArrow: return GHOSTTY_KEY_ARROW_DOWN
        case .keyboardLeftArrow: return GHOSTTY_KEY_ARROW_LEFT
        case .keyboardRightArrow: return GHOSTTY_KEY_ARROW_RIGHT
        case .keyboardHome: return GHOSTTY_KEY_HOME
        case .keyboardEnd: return GHOSTTY_KEY_END
        case .keyboardPageUp: return GHOSTTY_KEY_PAGE_UP
        case .keyboardPageDown: return GHOSTTY_KEY_PAGE_DOWN
        case .keyboardInsert: return GHOSTTY_KEY_INSERT
        case .keyboardF1: return GHOSTTY_KEY_F1
        case .keyboardF2: return GHOSTTY_KEY_F2
        case .keyboardF3: return GHOSTTY_KEY_F3
        case .keyboardF4: return GHOSTTY_KEY_F4
        case .keyboardF5: return GHOSTTY_KEY_F5
        case .keyboardF6: return GHOSTTY_KEY_F6
        case .keyboardF7: return GHOSTTY_KEY_F7
        case .keyboardF8: return GHOSTTY_KEY_F8
        case .keyboardF9: return GHOSTTY_KEY_F9
        case .keyboardF10: return GHOSTTY_KEY_F10
        case .keyboardF11: return GHOSTTY_KEY_F11
        case .keyboardF12: return GHOSTTY_KEY_F12
        case .keyboardSpacebar: return GHOSTTY_KEY_SPACE
        default: return nil
        }
    }

    /// True for keys whose meaning is entirely in the HID usage, so
    /// `pressesBegan` should handle them and `insertText` must not.
    static func isNonTextKey(_ usage: UIKeyboardHIDUsage) -> Bool {
        key(forHIDUsage: usage) != nil && usage != .keyboardSpacebar
    }

    /// F1–F12 by number, for the key bar's Fn row.
    static func functionKey(_ index: Int) -> GhosttyKey? {
        switch index {
        case 1: return GHOSTTY_KEY_F1
        case 2: return GHOSTTY_KEY_F2
        case 3: return GHOSTTY_KEY_F3
        case 4: return GHOSTTY_KEY_F4
        case 5: return GHOSTTY_KEY_F5
        case 6: return GHOSTTY_KEY_F6
        case 7: return GHOSTTY_KEY_F7
        case 8: return GHOSTTY_KEY_F8
        case 9: return GHOSTTY_KEY_F9
        case 10: return GHOSTTY_KEY_F10
        case 11: return GHOSTTY_KEY_F11
        case 12: return GHOSTTY_KEY_F12
        default: return nil
        }
    }

    static func mods(from flags: UIKeyModifierFlags) -> VTMods {
        var mods: VTMods = []
        if flags.contains(.shift) { mods.insert(.shift) }
        if flags.contains(.control) { mods.insert(.ctrl) }
        if flags.contains(.alternate) { mods.insert(.alt) }
        if flags.contains(.command) { mods.insert(.command) }
        if flags.contains(.alphaShift) { mods.insert(.capsLock) }
        return mods
    }
}
