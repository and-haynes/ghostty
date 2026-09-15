import Foundation
import Observation
import SwiftUI

/// What a key bar press means to the terminal.
enum KeyBarAction: Equatable {
    case escape, tab
    case up, down, left, right
    case home, end, pageUp, pageDown
    case function(Int)
    case literal(String)
    case paste
    case hideKeyboard
}

/// State behind the accessory key bar.
///
/// Modifiers are tri-state, following the pattern Andy likes in Jot: one tap
/// arms it for the next key, a second tap within the double-tap window locks
/// it until tapped off. A phone gives you one thumb, so "hold ctrl and press
/// c" has to become two taps — and a lock is what makes `ctrl-a ctrl-d` style
/// sequences bearable.
@MainActor
final class KeyBarModel: ObservableObject {
    enum Modifier: String, CaseIterable, Identifiable, Sendable {
        case control = "ctrl"
        case alt = "alt"

        var id: String { rawValue }
        var label: String {
            switch self {
            case .control: return "Ctrl"
            case .alt: return "Alt"
            }
        }
        var mods: VTMods { self == .control ? .ctrl : .alt }
    }

    enum ModifierState: Equatable, Sendable { case off, sticky, locked }

    @Published private(set) var states: [Modifier: ModifierState] = [:]
    /// F-keys are behind a toggle: they are rarely needed and would otherwise
    /// push everything useful off the end of the scroll.
    @Published var showsFunctionKeys = false

    /// Double-tap window for locking.
    var lockWindow: TimeInterval = 0.4
    /// Injected for tests.
    var now: () -> Date = Date.init

    private var lastTap: [Modifier: Date] = [:]

    var onAction: ((KeyBarAction, VTMods) -> Void)?

    func state(of modifier: Modifier) -> ModifierState { states[modifier] ?? .off }

    var activeMods: VTMods {
        Modifier.allCases.reduce(into: VTMods()) { result, modifier in
            if state(of: modifier) != .off { result.formUnion(modifier.mods) }
        }
    }

    var hasActiveMods: Bool { !activeMods.isEmpty }

    func tap(_ modifier: Modifier) {
        let time = now()
        let wasOff = state(of: modifier) == .off
        let isDouble = lastTap[modifier].map { time.timeIntervalSince($0) <= lockWindow } ?? false
        lastTap[modifier] = time

        switch state(of: modifier) {
        case .off:
            states[modifier] = .sticky
        case .sticky:
            states[modifier] = isDouble ? .locked : .off
        case .locked:
            states[modifier] = .off
        }
        // Engaging a modifier is a commitment; releasing one is a let-go. They
        // should not feel the same.
        Haptics.shared.fire(wasOff || state(of: modifier) == .locked ? .modifierEngage : .modifierRelease)
    }

    /// Consume armed modifiers after a real keystroke. Locked ones survive.
    @discardableResult
    func consumeMods() -> VTMods {
        let mods = activeMods
        for modifier in Modifier.allCases where state(of: modifier) == .sticky {
            states[modifier] = .off
        }
        return mods
    }

    func clearMods() {
        states.removeAll()
    }

    func perform(_ action: KeyBarAction) {
        // A modifier must not be eaten by the button that toggles the F-key
        // row or hides the keyboard — those are bar chrome, not keystrokes.
        switch action {
        case .hideKeyboard:
            Haptics.shared.fire(.keyboardHide)
            onAction?(action, [])
        case .paste:
            Haptics.shared.fire(.paste)
            onAction?(action, consumeMods())
        case .up, .down, .left, .right:
            // Auto-repeat routes through here too, so this is the rate-limited
            // one rather than a full key tap.
            Haptics.shared.fire(.arrowRepeat)
            onAction?(action, consumeMods())
        default:
            Haptics.shared.fire(.keyPress)
            onAction?(action, consumeMods())
        }
    }
}
