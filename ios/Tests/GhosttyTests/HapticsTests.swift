import UIKit
import XCTest
@testable import Ghostty

@MainActor
final class HapticsTests: XCTestCase {
    private var backend: RecordingHapticBackend!
    private var defaults: UserDefaults!
    private var haptics: Haptics!

    override func setUpWithError() throws {
        backend = RecordingHapticBackend()
        // A throwaway suite so the tests never read or write the real settings.
        let name = "HapticsTests-\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: name))
        haptics = Haptics(backend: backend, defaults: defaults)
        haptics.isActive = { true }
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: defaults.description)
    }

    // MARK: Event → generator mapping

    func testEventsMapToTheIntendedGenerators() {
        haptics.level = .rich
        let expectations: [(HapticEvent, HapticStyle)] = [
            (.keyPress, .impact(.light, intensity: 0.7)),
            (.modifierEngage, .impact(.rigid, intensity: 1.0)),
            (.modifierRelease, .impact(.soft, intensity: 0.8)),
            (.paste, .impact(.medium, intensity: 0.9)),
            (.selectionStart, .impact(.medium, intensity: 0.9)),
            (.selectionChip, .selection),
            (.tabSwitch, .selection),
            (.copyConfirmed, .notification(.success)),
            (.connected, .notification(.success)),
            (.keyGenerated, .notification(.success)),
            (.syncSucceeded, .notification(.success)),
            (.disconnected, .notification(.warning)),
            (.reconnecting, .notification(.warning)),
            (.authenticationFailed, .notification(.error)),
            (.hostKeyMismatch, .notification(.error)),
            (.syncFailed, .notification(.error)),
            (.bell, .pattern(.bell)),
        ]
        for (event, expected) in expectations {
            XCTAssertEqual(event.style, expected, "\(event.rawValue) should map to \(expected)")
        }
    }

    func testTheBellIsNotANotification() {
        // A bell that feels like an error notification is worse than no bell:
        // it trains you to look for a problem that isn't there.
        guard case .pattern = HapticEvent.bell.style else {
            return XCTFail("the bell should be its own CoreHaptics pattern")
        }
    }

    func testArrowRepeatIsWeakerThanAKeyPress() {
        guard case .impact(_, let repeatIntensity) = HapticEvent.arrowRepeat.style,
              case .impact(_, let keyIntensity) = HapticEvent.keyPress.style
        else { return XCTFail("both should be impacts") }
        XCTAssertLessThan(repeatIntensity, keyIntensity)
    }

    func testEveryEventHasAStyle() {
        // Guards against a new case being added without a decision about how
        // it should feel.
        for event in HapticEvent.allCases {
            _ = event.style
            _ = event.minimumLevel
        }
    }

    // MARK: Intensity setting

    func testOffFiresNothing() {
        haptics.level = .off
        for event in HapticEvent.allCases { haptics.fire(event) }
        XCTAssertTrue(backend.calls.isEmpty)
    }

    func testSubtleKeepsOnlyUnpromptedEvents() {
        haptics.level = .subtle
        haptics.fire(.connected)
        haptics.fire(.bell)
        haptics.fire(.keyPress)
        haptics.fire(.arrowRepeat)
        XCTAssertEqual(backend.calls.count, 2, "subtle should drop key presses and repeats")
    }

    func testNormalAddsKeysButNotRepeats() {
        haptics.level = .normal
        haptics.fire(.keyPress)
        backend.reset()
        haptics.fire(.arrowRepeat)
        haptics.fire(.selectionExtend)
        XCTAssertTrue(backend.calls.isEmpty, "arrow repeats and per-cell ticks are rich-only")
    }

    func testRichFiresEverything() {
        haptics.level = .rich
        var fired = 0
        for event in HapticEvent.allCases {
            backend.reset()
            haptics.now = { Date(timeIntervalSince1970: Double(fired) * 10) }
            haptics.fire(event)
            fired += 1
            XCTAssertEqual(backend.calls.count, 1, "\(event.rawValue) should fire at rich")
        }
    }

    func testSubtleScalesImpactIntensityDown() {
        haptics.level = .subtle
        haptics.fire(.selectionStart)
        guard case .impact(_, let intensity)? = backend.calls.first?.style else {
            return XCTFail("expected an impact")
        }
        XCTAssertLessThan(intensity, 0.9, "subtle should be quieter, not just rarer")
    }

    // MARK: One per event

    func testRepeatedEventsWithinTheWindowCollapse() {
        haptics.level = .rich
        let instant = Date(timeIntervalSince1970: 1000)
        haptics.now = { instant }
        haptics.fire(.keyPress)
        haptics.fire(.keyPress)
        haptics.fire(.keyPress)
        XCTAssertEqual(backend.calls.count, 1, "at most one buzz per event")
    }

    func testDifferentEventsAreNotCollapsedTogether() {
        haptics.level = .rich
        let instant = Date(timeIntervalSince1970: 1000)
        haptics.now = { instant }
        haptics.fire(.keyPress)
        haptics.fire(.paste)
        XCTAssertEqual(backend.calls.count, 2)
    }

    func testTheSameEventFiresAgainAfterTheWindow() {
        haptics.level = .rich
        var clock = Date(timeIntervalSince1970: 1000)
        haptics.now = { clock }
        haptics.fire(.keyPress)
        clock = clock.addingTimeInterval(1)
        haptics.fire(.keyPress)
        XCTAssertEqual(backend.calls.count, 2)
    }

    // MARK: Background

    func testNothingFiresWhileBackgrounded() {
        haptics.level = .rich
        haptics.isActive = { false }
        haptics.fire(.connected)
        haptics.fire(.bell)
        XCTAssertTrue(backend.calls.isEmpty, "a buzz from an app you cannot see is just confusing")
    }

    func testPrepareIsAlsoSuppressed() {
        haptics.level = .off
        haptics.prepare(for: .keyPress)
        XCTAssertTrue(backend.prepared.isEmpty)

        haptics.level = .rich
        // Changing the level warms a generator itself, so start from a clean
        // slate before asserting what an explicit prepare does.
        backend.reset()
        haptics.prepare(for: .keyPress)
        XCTAssertEqual(backend.prepared, [.keyPress])
    }

    // MARK: Persistence

    func testLevelPersistsAcrossInstances() {
        haptics.level = .subtle
        let reloaded = Haptics(backend: RecordingHapticBackend(), defaults: defaults)
        XCTAssertEqual(reloaded.level, .subtle)
    }

    func testDefaultLevelIsNormal() throws {
        let fresh = try XCTUnwrap(UserDefaults(suiteName: "HapticsDefault-\(UUID().uuidString)"))
        XCTAssertEqual(Haptics(backend: RecordingHapticBackend(), defaults: fresh).level, .normal)
    }
}
