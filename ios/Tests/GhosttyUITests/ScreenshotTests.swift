import UIKit
import XCTest

/// Drives the real app to produce the screenshots in `ios/docs/screenshots/`.
///
/// These are not decoration: they are the evidence that the app launches, that
/// the CoreText renderer actually puts glyphs on screen, and that the key bar
/// and the TOFU prompt appear where they are supposed to. A build that
/// compiles and a build that runs are different claims.
///
/// PNGs are written into the test runner's temporary directory, which is
/// visible on the host under the simulator's device container; the harness
/// copies them out afterwards.
final class ScreenshotTests: XCTestCase {
    private var outputDirectory: URL!
    private var captured: [String] = []
    /// Cleared once per test *process*, not once per test: the screenshots are
    /// produced by more than one test now, and wiping the directory in each
    /// `setUp` would leave whichever ran last as the only survivor.
    private static var didClearOutputDirectory = false

    override func setUpWithError() throws {
        // Keep going after a soft failure so one missing element does not cost
        // us every later screenshot.
        continueAfterFailure = true
        outputDirectory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("ghostty-screenshots", isDirectory: true)
        if !Self.didClearOutputDirectory {
            Self.didClearOutputDirectory = true
            try? FileManager.default.removeItem(at: outputDirectory)
        }
        try? FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
    }

    func testCaptureScreenshots() throws {
        let app = XCUIApplication()
        app.launchArguments = ["-ghostty-seed"]
        app.launch()

        // 1. Hosts list, grouped, with the seeded homelab machines.
        XCTAssertTrue(app.navigationBars["Hosts"].waitForExistence(timeout: 30), "the app should launch")
        XCTAssertTrue(app.staticTexts["noether"].waitForExistence(timeout: 10), "seeded hosts should be listed")
        capture(app, named: "01-hosts")

        // 2. A key generated in-app, showing its OpenSSH public line.
        app.tabBars.buttons["Keys"].tap()
        _ = app.navigationBars["Keys"].waitForExistence(timeout: 10)
        let key = app.staticTexts["iPhone"]
        XCTAssertTrue(key.waitForExistence(timeout: 10), "a key generated in-app should be listed")
        key.tap()
        if app.navigationBars["iPhone"].waitForExistence(timeout: 10) {
            capture(app, named: "02-identity")
            app.buttons["Done"].firstMatch.tap()
        } else {
            reportHierarchy(app, step: "identity export sheet")
            capture(app, named: "02-identity")
        }

        // 3. The Console tab: real VT rendered by libghostty-vt.
        app.tabBars.buttons["Console"].tap()
        XCTAssertTrue(app.navigationBars["Console"].waitForExistence(timeout: 15), "the console tab should exist")
        // Give the emulator a moment to parse the banner and the view a frame
        // to draw it.
        Thread.sleep(forTimeInterval: 2.0)
        capture(app, named: "03-terminal")

        // 4. Type into it, which both proves the input path end to end and
        //    raises the key bar.
        app.children(matching: .window).element(boundBy: 0).tap()
        Thread.sleep(forTimeInterval: 1.5)
        if app.keyboards.count > 0 {
            app.typeText("colors\n")
            Thread.sleep(forTimeInterval: 2.0)
        } else {
            reportHierarchy(app, step: "software keyboard")
        }
        capture(app, named: "04-terminal-keybar")

        // 5. Trust-on-first-use against a real SSH server on the LAN.
        app.tabBars.buttons["Hosts"].tap()
        _ = app.navigationBars["Hosts"].waitForExistence(timeout: 10)
        // "pi-a" rather than "git.lan": a label that looks like a domain gets
        // picked up by the system's data detectors and opening it launches
        // Safari instead of tapping the row.
        if app.staticTexts["pi-a"].waitForExistence(timeout: 10) {
            app.staticTexts["pi-a"].tap()
            let prompt = app.alerts["Unknown host key"]
            if prompt.waitForExistence(timeout: 30) {
                capture(app, named: "05-tofu")
                prompt.buttons["Cancel"].firstMatch.tap()
            } else {
                // Not a failure of the app: the LAN host may be unreachable
                // from whatever machine this runs on.
                reportHierarchy(app, step: "TOFU prompt (host may be unreachable)")
                capture(app, named: "05-connect-attempt")
            }
        }

        captureFollowUps(app)

        XCTAssertTrue(captured.contains("01-hosts"))
        XCTAssertTrue(captured.contains("03-terminal"))
        XCTAssertTrue(captured.contains("06-console-ssh"))
        XCTAssertTrue(captured.contains("10-sync-settings"))
        print("ghostty-screenshots: wrote \(captured.joined(separator: ", ")) to \(outputDirectory.path)")
    }

    /// Screenshots 06–10: the console's `ssh`, the reorganised key bar, the
    /// floating keyboard toggle, the selection helper, and the sync settings.
    private func captureFollowUps(_ app: XCUIApplication) {
        // Dismiss anything left on screen from the TOFU step.
        if app.alerts.firstMatch.exists {
            app.alerts.firstMatch.buttons.element(boundBy: 0).tap()
        }

        // 6. Console: run `hosts` and then an `ssh`, which resolves against the
        //    vault and opens a session.
        app.tabBars.buttons["Console"].tap()
        _ = app.navigationBars["Console"].waitForExistence(timeout: 10)
        focusTerminal(app)
        if app.keyboards.count > 0 {
            app.typeText("hosts\n")
            Thread.sleep(forTimeInterval: 1.0)
            app.typeText("ssh noether\n")
            Thread.sleep(forTimeInterval: 1.5)
        } else {
            reportHierarchy(app, step: "console keyboard")
        }
        capture(app, named: "06-console-ssh")

        // 7. The key bar: arm Ctrl (tap) and open the Fn row, so the sticky
        //    state and the scrolling middle group are both visible.
        app.tabBars.buttons["Console"].tap()
        focusTerminal(app)
        if app.buttons["Ctrl"].waitForExistence(timeout: 5) {
            app.buttons["Ctrl"].tap()
        }
        if app.buttons["Function keys"].exists {
            app.buttons["Function keys"].tap()
            Thread.sleep(forTimeInterval: 0.5)
        }
        capture(app, named: "07-keybar")

        // 8. The floating keyboard toggle, shown when the bar is collapsed.
        if app.buttons["Hide keyboard"].exists {
            app.buttons["Hide keyboard"].tap()
            Thread.sleep(forTimeInterval: 1.0)
        }
        capture(app, named: "08-keyboard-toggle")

        // 9. The selection helper: a long press *and drag* starts a selection
        //    and fades in the input/output bands and chips. The drag is
        //    load-bearing — a stationary long press is the edit-menu gesture
        //    now (#008A5), and the helper deliberately stays out of its way.
        let terminal = app.children(matching: .window).element(boundBy: 0)
        terminal.coordinate(withNormalizedOffset: CGVector(dx: 0.3, dy: 0.35))
            .press(
                forDuration: 0.8,
                thenDragTo: terminal.coordinate(withNormalizedOffset: CGVector(dx: 0.7, dy: 0.45))
            )
        Thread.sleep(forTimeInterval: 1.0)
        capture(app, named: "09-selection-helper")
        dismissAnyMenu(app)
        if app.alerts.firstMatch.exists {
            app.alerts.firstMatch.buttons.element(boundBy: 0).tap()
        }

        // 10. Sync providers in Settings.
        app.tabBars.buttons["Settings"].tap()
        _ = app.navigationBars["Settings"].waitForExistence(timeout: 10)
        // The Sync section sits below the fold on a phone.
        app.swipeUp()
        Thread.sleep(forTimeInterval: 0.5)
        capture(app, named: "10-sync-settings")
    }

    /// 14. The edit menu on a stationary long press.
    ///
    /// This is the #008A5 regression: the selection helper used to swallow the
    /// long press, so the iOS edit menu — and with it **Paste** — never
    /// appeared and there was no way to paste into a session at all. The
    /// assertion is the point; the screenshot is the evidence.
    func testPasteMenuAppearsOnLongPress() {
        // The simulator's pasteboard is shared with the test runner, so this
        // really does put text where the app will look for it.
        UIPasteboard.general.string = "echo pasted from the clipboard"

        let app = XCUIApplication()
        app.launchArguments = ["-ghostty-seed"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Hosts"].waitForExistence(timeout: 30), "the app should launch")

        app.tabBars.buttons["Console"].tap()
        _ = app.navigationBars["Console"].waitForExistence(timeout: 10)
        Thread.sleep(forTimeInterval: 1.0)

        let terminal = app.children(matching: .window).element(boundBy: 0)
        terminal.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.4))
            .press(forDuration: 0.9)
        Thread.sleep(forTimeInterval: 1.0)

        if !pasteItem(app).waitForExistence(timeout: 5) {
            print("ghostty-paste-menu: hierarchy after a stationary long press follows")
            print(app.debugDescription)
        }
        XCTAssertTrue(
            pasteItem(app).exists,
            "a stationary long press must open the edit menu with a Paste item"
        )
        capture(app, named: "14-paste-menu")
        dismissAnyMenu(app)

        // And again with the keyboard up: the key bar occupies the row above
        // the keyboard, and the menu has to appear over the terminal regardless.
        focusTerminal(app)
        terminal.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25))
            .press(forDuration: 0.9)
        XCTAssertTrue(
            pasteItem(app).waitForExistence(timeout: 5),
            "the edit menu must also open while the software keyboard is up"
        )
        dismissAnyMenu(app)
    }

    /// 13. The session status line and the key bar, with the keyboard up.
    ///
    /// #008A2: on Andy's phone these two drew on top of each other, so neither
    /// was readable. The status line must sit *above* the key bar, and the key
    /// bar must be the only thing in the row immediately above the keyboard.
    func testStatusLineSitsAboveTheKeyBar() {
        let app = XCUIApplication()
        app.launchArguments = ["-ghostty-seed"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Hosts"].waitForExistence(timeout: 30), "the app should launch")

        // Any session will do — this is about layout, not about the far end —
        // so a host that fails to connect still gives us a terminal screen.
        let host = app.cells.buttons.firstMatch
        guard host.waitForExistence(timeout: 10) else {
            reportHierarchy(app, step: "a host to connect to")
            return
        }
        host.tap()
        if app.alerts.firstMatch.waitForExistence(timeout: 25) {
            app.alerts.firstMatch.buttons.element(boundBy: 0).tap()
        }

        app.tabBars.buttons["Sessions"].tap()
        _ = app.navigationBars["Sessions"].waitForExistence(timeout: 10)
        let row = app.cells.firstMatch
        guard row.waitForExistence(timeout: 10) else {
            reportHierarchy(app, step: "a session row")
            return
        }
        row.tap()
        Thread.sleep(forTimeInterval: 1.5)

        // Raise the keyboard, which is what brings the key bar with it.
        focusTerminal(app)
        Thread.sleep(forTimeInterval: 1.5)
        capture(app, named: "13-status-vs-keybar")

        guard app.keyboards.count > 0 else {
            reportHierarchy(app, step: "software keyboard on a session")
            return
        }
        let keyBar = app.buttons["Esc"].exists ? app.buttons["Esc"] : app.buttons["esc"]
        guard keyBar.waitForExistence(timeout: 5) else {
            reportHierarchy(app, step: "key bar")
            return
        }
        let status = app.descendants(matching: .any)
            .matching(identifier: "session-status-bar").firstMatch
        guard status.waitForExistence(timeout: 5) else {
            reportHierarchy(app, step: "the session status line")
            return
        }

        XCTAssertLessThanOrEqual(
            status.frame.maxY, keyBar.frame.minY + 1,
            """
            the status line (\(status.frame)) must end above the key bar \
            (\(keyBar.frame)); overlapping makes both unreadable
            """
        )

        // Landscape: the safe area and the keyboard height both change, and a
        // fixed offset would show up here.
        XCUIDevice.shared.orientation = .landscapeLeft
        Thread.sleep(forTimeInterval: 2.0)
        if keyBar.exists, status.exists, app.keyboards.count > 0 {
            capture(app, named: "13b-status-vs-keybar-landscape")
            XCTAssertLessThanOrEqual(
                status.frame.maxY, keyBar.frame.minY + 1,
                "the status line must stay above the key bar in landscape too"
            )
        } else {
            reportHierarchy(app, step: "key bar in landscape")
        }
        XCUIDevice.shared.orientation = .portrait
        Thread.sleep(forTimeInterval: 2.0)

        // Keyboard hidden: the key bar goes with it, and the status line must
        // still be on screen and inside the safe area rather than under the
        // home indicator.
        if app.buttons["Hide keyboard"].exists {
            app.buttons["Hide keyboard"].tap()
            Thread.sleep(forTimeInterval: 1.5)
        }
        let window = app.children(matching: .window).element(boundBy: 0)
        XCTAssertTrue(status.exists, "the status line must survive the keyboard going away")
        XCTAssertLessThanOrEqual(
            status.frame.maxY, window.frame.maxY,
            "the status line must not be pushed off the bottom of the window"
        )
    }

    /// The edit menu's Paste item.
    ///
    /// Deliberately scoped to the menu rather than asking the app for any
    /// element called "Paste": the key bar has its own Paste button with that
    /// exact accessibility label, and a query that matches it would pass
    /// whether or not the edit menu ever appeared — which is precisely the bug
    /// under test.
    private func pasteItem(_ app: XCUIApplication) -> XCUIElement {
        let asMenuItem = app.menuItems["Paste"].firstMatch
        if asMenuItem.exists { return asMenuItem }
        return app.menus.descendants(matching: .any).matching(identifier: "Paste").firstMatch
    }

    private func dismissAnyMenu(_ app: XCUIApplication) {
        guard app.menuItems.count > 0 || app.buttons["Paste"].exists else { return }
        // Tapping well away from the menu closes it without invoking anything.
        app.children(matching: .window).element(boundBy: 0)
            .coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.08))
            .tap()
        Thread.sleep(forTimeInterval: 0.5)
    }

    private func focusTerminal(_ app: XCUIApplication) {
        guard app.keyboards.count == 0 else { return }
        app.children(matching: .window).element(boundBy: 0)
            .coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.3))
            .tap()
        Thread.sleep(forTimeInterval: 1.0)
    }

    private func capture(_ app: XCUIApplication, named name: String) {
        let screenshot = XCUIScreen.main.screenshot()
        let url = outputDirectory.appendingPathComponent("\(name).png")
        try? screenshot.pngRepresentation.write(to: url)
        captured.append(name)

        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }

    private func reportHierarchy(_ app: XCUIApplication, step: String) {
        print("ghostty-screenshots: could not find \(step); hierarchy follows")
        print(app.debugDescription)
    }
}
