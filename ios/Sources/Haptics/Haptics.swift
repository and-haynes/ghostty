import CoreHaptics
import Foundation
import UIKit

/// Everything in the app that is worth feeling.
///
/// Named by *event*, not by generator: the mapping from "a connection came up"
/// to "success notification" is a design decision that belongs in one place,
/// and naming the cases after the hardware would scatter it across every call
/// site.
enum HapticEvent: String, CaseIterable, Sendable {
    // Key bar
    case keyPress
    case modifierEngage
    case modifierRelease
    case functionRowToggle
    case arrowRepeat
    case keyboardShow
    case keyboardHide
    case paste

    // Selection
    case selectionStart
    case selectionExtend
    case selectionChip
    case copyConfirmed

    // Terminal
    case bell

    // Connection
    case connected
    case disconnected
    case reconnecting
    case authenticationFailed
    case hostKeyMismatch
    case hostKeyTrusted

    // App
    case tabSwitch
    case listAction
    case keyGenerated
    case syncSucceeded
    case syncFailed
    case consoleCommand

    /// What the event feels like.
    var style: HapticStyle {
        switch self {
        case .keyPress, .selectionExtend, .consoleCommand, .listAction:
            return .impact(.light, intensity: 0.7)
        case .arrowRepeat:
            // Auto-repeat fires many times a second; a full tap each time is
            // unpleasant and drains the taptic engine's budget.
            return .impact(.light, intensity: 0.35)
        case .modifierEngage, .hostKeyTrusted:
            return .impact(.rigid, intensity: 1.0)
        case .modifierRelease, .functionRowToggle, .keyboardShow, .keyboardHide:
            return .impact(.soft, intensity: 0.8)
        case .paste, .selectionStart:
            return .impact(.medium, intensity: 0.9)
        case .selectionChip, .tabSwitch:
            return .selection
        case .copyConfirmed, .connected, .keyGenerated, .syncSucceeded:
            return .notification(.success)
        case .disconnected, .reconnecting:
            return .notification(.warning)
        case .authenticationFailed, .hostKeyMismatch, .syncFailed:
            return .notification(.error)
        case .bell:
            return .pattern(.bell)
        }
    }

    /// The lowest intensity setting at which this event fires.
    ///
    /// Rich events are the ones that would be noise at a normal setting — a
    /// tick per arrow repeat, a tick per selected word — so they are opt-in.
    var minimumLevel: HapticLevel {
        switch self {
        case .arrowRepeat, .selectionExtend, .consoleCommand, .listAction:
            return .rich
        case .keyPress, .functionRowToggle, .keyboardShow, .keyboardHide, .tabSwitch:
            return .normal
        default:
            // Subtle keeps only the events that report something happening
            // rather than acknowledging something you did.
            return .subtle
        }
    }
}

enum HapticStyle: Equatable, Sendable {
    case impact(UIImpactFeedbackGenerator.FeedbackStyle, intensity: CGFloat)
    case selection
    case notification(UINotificationFeedbackGenerator.FeedbackType)
    case pattern(HapticPattern)
}

/// CoreHaptics patterns, for the few things a canned generator cannot say.
enum HapticPattern: String, Equatable, Sendable {
    /// Two quick taps and a decay — a bell, not a notification.
    case bell
    /// A rising double pulse, for a long operation completing.
    case flourish
}

enum HapticLevel: String, Codable, CaseIterable, Identifiable, Sendable {
    case off, subtle, normal, rich

    var id: String { rawValue }

    var title: String {
        switch self {
        case .off: return "Off"
        case .subtle: return "Subtle"
        case .normal: return "Normal"
        case .rich: return "Rich"
        }
    }

    var detail: String {
        switch self {
        case .off: return "No haptics at all."
        case .subtle: return "Only things that happened on their own — connections, errors, the bell."
        case .normal: return "Adds feedback for keys, modifiers and the keyboard toggle."
        case .rich: return "Everything, including arrow repeats and selection changes."
        }
    }

    var rank: Int {
        switch self {
        case .off: return 0
        case .subtle: return 1
        case .normal: return 2
        case .rich: return 3
        }
    }

    func allows(_ event: HapticEvent) -> Bool {
        self != .off && rank >= event.minimumLevel.rank
    }

    /// Scales impact intensity so "Subtle" is quieter, not just rarer.
    var intensityScale: CGFloat {
        switch self {
        case .off: return 0
        case .subtle: return 0.6
        case .normal: return 1.0
        case .rich: return 1.0
        }
    }
}

/// The hardware, behind a seam so tests can record instead of vibrate.
@MainActor
protocol HapticBackend: AnyObject {
    func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle, intensity: CGFloat)
    func selectionChanged()
    func notification(_ type: UINotificationFeedbackGenerator.FeedbackType)
    func play(_ pattern: HapticPattern)
    /// Warm the generator that `event` will use, so the first tap is not late.
    func prepare(for event: HapticEvent)
}

/// The app's haptics.
///
/// Three rules the call sites do not have to think about:
/// * one buzz per event — a rate limiter collapses bursts;
/// * nothing while the app is in the background, where a vibration from an app
///   you cannot see is just confusing;
/// * nothing at all when the user has turned it off.
@MainActor
final class Haptics: ObservableObject {
    static let shared = Haptics()

    @Published var level: HapticLevel {
        didSet {
            guard level != oldValue else { return }
            defaults?.set(level.rawValue, forKey: Self.defaultsKey)
            if level != .off { prepare(for: .keyPress) }
        }
    }

    private let backend: HapticBackend
    private let defaults: UserDefaults?
    private var lastFired: [HapticEvent: Date] = [:]
    /// Injected so tests do not have to sleep.
    var now: () -> Date = Date.init
    /// Overridable so tests need no UIApplication.
    var isActive: () -> Bool = { UIApplication.shared.applicationState != .background }

    /// Minimum gap between two of the *same* event. Chosen to be shorter than
    /// the arrow auto-repeat interval (60 ms) would need, so repeats still feel
    /// continuous, but long enough to collapse a duplicated call.
    private static let minimumGap: TimeInterval = 0.04
    private static let defaultsKey = "settings.hapticLevel"

    init(backend: HapticBackend? = nil, defaults: UserDefaults? = .standard) {
        self.backend = backend ?? SystemHapticBackend()
        self.defaults = defaults
        let stored = defaults?.string(forKey: Self.defaultsKey)
        self.level = stored.flatMap(HapticLevel.init(rawValue:)) ?? .normal
    }

    /// Warm the relevant generator. Call before a gesture begins — a cold
    /// generator can be tens of milliseconds late, which reads as a missed tap.
    func prepare(for event: HapticEvent) {
        guard level.allows(event), isActive() else { return }
        backend.prepare(for: event)
    }

    func fire(_ event: HapticEvent) {
        guard level.allows(event), isActive() else { return }

        let time = now()
        if let previous = lastFired[event], time.timeIntervalSince(previous) < Self.minimumGap {
            return
        }
        lastFired[event] = time

        switch event.style {
        case .impact(let style, let intensity):
            backend.impact(style, intensity: min(1, intensity * level.intensityScale))
        case .selection:
            backend.selectionChanged()
        case .notification(let type):
            backend.notification(type)
        case .pattern(let pattern):
            backend.play(pattern)
        }
    }
}

// MARK: - The real hardware

@MainActor
final class SystemHapticBackend: HapticBackend {
    private var impactGenerators: [UIImpactFeedbackGenerator.FeedbackStyle: UIImpactFeedbackGenerator] = [:]
    private let selectionGenerator = UISelectionFeedbackGenerator()
    private let notificationGenerator = UINotificationFeedbackGenerator()
    private var engine: CHHapticEngine?

    private func impactGenerator(_ style: UIImpactFeedbackGenerator.FeedbackStyle) -> UIImpactFeedbackGenerator {
        if let existing = impactGenerators[style] { return existing }
        let generator = UIImpactFeedbackGenerator(style: style)
        impactGenerators[style] = generator
        return generator
    }

    func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle, intensity: CGFloat) {
        let generator = impactGenerator(style)
        generator.impactOccurred(intensity: intensity)
        // Re-prepare: a generator goes cold seconds after use, and key presses
        // come in runs.
        generator.prepare()
    }

    func selectionChanged() {
        selectionGenerator.selectionChanged()
        selectionGenerator.prepare()
    }

    func notification(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        notificationGenerator.notificationOccurred(type)
        notificationGenerator.prepare()
    }

    func prepare(for event: HapticEvent) {
        switch event.style {
        case .impact(let style, _): impactGenerator(style).prepare()
        case .selection: selectionGenerator.prepare()
        case .notification: notificationGenerator.prepare()
        case .pattern: startEngineIfNeeded()
        }
    }

    // MARK: CoreHaptics

    private func startEngineIfNeeded() {
        guard CHHapticEngine.capabilitiesForHardware().supportsHaptics, engine == nil else { return }
        engine = try? CHHapticEngine()
        // The engine is stopped by the system on interruption; restarting
        // lazily on the next play is simpler than tracking the lifecycle.
        engine?.resetHandler = { [weak self] in try? self?.engine?.start() }
        engine?.stoppedHandler = { _ in }
        try? engine?.start()
    }

    func play(_ pattern: HapticPattern) {
        startEngineIfNeeded()
        guard let engine, let built = try? Self.build(pattern) else {
            // Without a taptic engine (older hardware, or the simulator) a
            // canned generator is better than silence.
            notificationGenerator.notificationOccurred(pattern == .bell ? .warning : .success)
            return
        }
        do {
            let player = try engine.makePlayer(with: built)
            try player.start(atTime: CHHapticTimeImmediate)
        } catch {
            notificationGenerator.notificationOccurred(.warning)
        }
    }

    private static func build(_ pattern: HapticPattern) throws -> CHHapticPattern {
        switch pattern {
        case .bell:
            // Two sharp taps then a short ring-out: unmistakably a bell rather
            // than a notification, which is the point of not using one.
            return try CHHapticPattern(events: [
                CHHapticEvent(eventType: .hapticTransient, parameters: [
                    .init(parameterID: .hapticIntensity, value: 1.0),
                    .init(parameterID: .hapticSharpness, value: 0.9),
                ], relativeTime: 0),
                CHHapticEvent(eventType: .hapticTransient, parameters: [
                    .init(parameterID: .hapticIntensity, value: 0.7),
                    .init(parameterID: .hapticSharpness, value: 0.8),
                ], relativeTime: 0.08),
                CHHapticEvent(eventType: .hapticContinuous, parameters: [
                    .init(parameterID: .hapticIntensity, value: 0.25),
                    .init(parameterID: .hapticSharpness, value: 0.3),
                ], relativeTime: 0.14, duration: 0.25),
            ], parameters: [])
        case .flourish:
            return try CHHapticPattern(events: [
                CHHapticEvent(eventType: .hapticTransient, parameters: [
                    .init(parameterID: .hapticIntensity, value: 0.5),
                    .init(parameterID: .hapticSharpness, value: 0.4),
                ], relativeTime: 0),
                CHHapticEvent(eventType: .hapticTransient, parameters: [
                    .init(parameterID: .hapticIntensity, value: 1.0),
                    .init(parameterID: .hapticSharpness, value: 0.7),
                ], relativeTime: 0.1),
            ], parameters: [])
        }
    }
}

/// Records instead of vibrating, for tests.
@MainActor
final class RecordingHapticBackend: HapticBackend {
    struct Call: Equatable {
        var style: HapticStyle
    }

    private(set) var calls: [Call] = []
    private(set) var prepared: [HapticEvent] = []

    func impact(_ style: UIImpactFeedbackGenerator.FeedbackStyle, intensity: CGFloat) {
        calls.append(Call(style: .impact(style, intensity: intensity)))
    }

    func selectionChanged() {
        calls.append(Call(style: .selection))
    }

    func notification(_ type: UINotificationFeedbackGenerator.FeedbackType) {
        calls.append(Call(style: .notification(type)))
    }

    func play(_ pattern: HapticPattern) {
        calls.append(Call(style: .pattern(pattern)))
    }

    func prepare(for event: HapticEvent) {
        prepared.append(event)
    }

    func reset() {
        calls.removeAll()
        prepared.removeAll()
    }
}
