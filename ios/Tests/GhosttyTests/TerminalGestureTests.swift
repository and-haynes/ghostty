import CoreGraphics
import XCTest

@testable import Ghostty

/// Arbitration between "long press to open the edit menu" and "long press and
/// drag to select".
///
/// This is the regression suite for #008A5: the terminal used to start a word
/// selection the instant a long press began and then suppress the edit menu
/// because a selection existed, so the iOS **Paste** item never appeared and
/// there was no way to paste into a session at all.
final class TerminalGestureTests: XCTestCase {
    func testStationaryLongPressOpensTheEditMenu() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: CGPoint(x: 100, y: 100))
        XCTAssertFalse(arbiter.isSelecting)
        XCTAssertEqual(arbiter.ended(), .presentEditMenu)
    }

    func testLongPressWithFingerRollStillOpensTheEditMenu() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: CGPoint(x: 100, y: 100))
        // Well inside the threshold: a finger resting on glass never holds
        // perfectly still, and that must not read as a drag.
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: 104, y: 103)), .wait)
        XCTAssertFalse(arbiter.isSelecting)
        XCTAssertEqual(arbiter.ended(), .presentEditMenu)
    }

    func testMovingLongPressStartsASelection() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: CGPoint(x: 100, y: 100))
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: 140, y: 100)), .beginSelection)
        XCTAssertTrue(arbiter.isSelecting)
        // Every later sample extends rather than restarts.
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: 160, y: 120)), .extendSelection)
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: 100, y: 100)), .extendSelection)
        XCTAssertEqual(arbiter.ended(), .keepSelection)
    }

    func testSelectionBeginsExactlyOnceThresholdIsCrossed() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: .zero)
        let justInside = LongPressArbiter.movementThreshold - 0.5
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: justInside, y: 0)), .wait)
        let justOutside = LongPressArbiter.movementThreshold + 0.5
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: justOutside, y: 0)), .beginSelection)
    }

    func testMovementIsMeasuredInBothAxes() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: CGPoint(x: 50, y: 50))
        // A purely vertical drag is a selection too — it used to be the only
        // way to scroll, which is why it is worth pinning.
        XCTAssertEqual(arbiter.moved(to: CGPoint(x: 50, y: 90)), .beginSelection)
    }

    func testCancellationResetsToIdle() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: .zero)
        _ = arbiter.moved(to: CGPoint(x: 100, y: 0))
        XCTAssertTrue(arbiter.isSelecting)
        arbiter.cancelled()
        XCTAssertFalse(arbiter.isSelecting)
        // An `ended` with no `began` must not claim anything happened.
        XCTAssertEqual(arbiter.ended(), .wait)
    }

    func testASecondPressAfterASelectionStartsFresh() {
        var arbiter = LongPressArbiter()
        arbiter.began(at: .zero)
        _ = arbiter.moved(to: CGPoint(x: 100, y: 0))
        XCTAssertEqual(arbiter.ended(), .keepSelection)

        arbiter.began(at: CGPoint(x: 10, y: 10))
        XCTAssertFalse(arbiter.isSelecting, "a new press must not inherit the last one's phase")
        XCTAssertEqual(arbiter.ended(), .presentEditMenu)
    }
}
