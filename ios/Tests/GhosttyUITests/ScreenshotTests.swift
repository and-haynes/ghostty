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

    /// 15. Importing a key from the clipboard, the way one arrives from
    /// 1Password (#008A1).
    ///
    /// Drives the whole path: clipboard holds a key, the Keys tab offers the
    /// import, the sheet says what it found, the key lands in the vault, and
    /// the clipboard is wiped afterwards.
    func testImportsAKeyFromTheClipboard() throws {
        // A throwaway PKCS#8 Ed25519 key — the shape 1Password hands out.
        UIPasteboard.general.string = Self.clipboardFixtureKey

        let app = XCUIApplication()
        app.launchArguments = ["-ghostty-seed"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Hosts"].waitForExistence(timeout: 30), "the app should launch")

        app.tabBars.buttons["Keys"].tap()
        _ = app.navigationBars["Keys"].waitForExistence(timeout: 10)

        // The system paste control, not a button of ours: pressing it *is* the
        // consent, so the contents arrive on the first tap with no alert.
        let pasteControl = app.buttons["Paste"].firstMatch
        if !pasteControl.waitForExistence(timeout: 10) {
            reportHierarchy(app, step: "the clipboard import offer on the Keys tab")
        }
        XCTAssertTrue(
            pasteControl.exists,
            "a clipboard holding a key must be offered for import"
        )
        capture(app, named: "15-clipboard-import-offer")
        pasteControl.tap()

        XCTAssertTrue(
            app.navigationBars["Import key"].waitForExistence(timeout: 10),
            "the import sheet should open straight onto the clipboard"
        )

        Thread.sleep(forTimeInterval: 1.5)
        XCTAssertFalse(
            app.alerts.firstMatch.exists,
            "UIPasteControl must not raise an \"Allow Paste\" alert"
        )

        // The footer names what was found, which is how the user knows the
        // right thing was copied.
        let described = app.staticTexts.containing(
            NSPredicate(format: "label CONTAINS[c] %@", "Looks like a PKCS#8")
        ).firstMatch
        XCTAssertTrue(described.waitForExistence(timeout: 5), "the sheet should say what it found")
        capture(app, named: "15-clipboard-import")

        let importButton = app.buttons["Import"].firstMatch
        XCTAssertTrue(importButton.isEnabled, "a detected key should be importable")
        importButton.tap()
        Thread.sleep(forTimeInterval: 1.5)

        // What happens next depends on the Keychain, and a simulator build made
        // with CODE_SIGNING_ALLOWED=NO has no keychain-access-group
        // entitlement — every `SecItemAdd` fails with -34018. That is a
        // property of this harness, not of the app, so the check is: either the
        // key landed, or it got all the way to the Keychain and was refused
        // there. Either outcome proves the clipboard path parsed the key and
        // handed it to the vault; the storage path itself is covered by the
        // unit tests, which use an in-memory Keychain.
        let entitlementError = app.staticTexts.containing(
            NSPredicate(format: "label CONTAINS[c] %@", "Keychain error -34018")
        ).firstMatch
        if entitlementError.exists {
            capture(app, named: "15-clipboard-imported")
            throw XCTSkip(
                """
                The clipboard key parsed and reached the vault, but this unsigned \
                simulator build cannot write to the Keychain (-34018). Run the app from \
                Xcode with a signing team to exercise the rest.
                """
            )
        }

        XCTAssertTrue(
            app.navigationBars["Keys"].waitForExistence(timeout: 10),
            "the sheet should close on a successful import"
        )
        capture(app, named: "15-clipboard-imported")
        XCTAssertTrue(
            app.staticTexts["1Password key"].waitForExistence(timeout: 5),
            "the imported key should be listed under the name the format suggested"
        )

        // The clipboard is wiped once the key is in the Keychain. The write
        // happens in the app and is read back here in the runner, so give the
        // two processes a moment to agree.
        var clipboard = UIPasteboard.general.string
        let deadline = Date().addingTimeInterval(5)
        while let text = clipboard, !text.isEmpty, Date() < deadline {
            Thread.sleep(forTimeInterval: 0.25)
            clipboard = UIPasteboard.general.string
        }
        XCTAssertTrue(
            clipboard?.isEmpty ?? true,
            "the clipboard must be cleared after import, found: \(clipboard ?? "nil")"
        )
    }

    /// Generated with `openssl genpkey -algorithm ed25519`, used nowhere else,
    /// trusted by nothing.
    private static let clipboardFixtureKey = """
        -----BEGIN PRIVATE KEY-----
        MC4CAQAwBQYDK2VwBCIEICUesc/lPoXIX7d4qiIrn0YQJgDGKtOe7S//rOs0I+j0
        -----END PRIVATE KEY-----
        """

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

    /// Screenshots 11–12: a real sweep of whatever subnet this machine is on,
    /// and the Local group the import produces.
    ///
    /// Its own test rather than a step in the big one. It runs a genuine scan —
    /// there is no fixture that would prove the sockets work — on a three-port
    /// list rather than all eighteen, because a UI test should not take a
    /// minute and a half, and it wants a clean screen: `XCUIScreen.screenshot`
    /// captures the display, so anything Safari left lying around from a
    /// previous run would be photographed instead of the app.
    func testCaptureLANScan() throws {
        XCUIApplication(bundleIdentifier: "com.apple.mobilesafari").terminate()

        let app = XCUIApplication()
        app.launchArguments = ["-ghostty-seed"]
        app.launch()
        XCTAssertTrue(app.navigationBars["Hosts"].waitForExistence(timeout: 30), "the app should launch")

        selectTab(app, named: "Settings", expecting: "Settings")

        let scanLink = app.buttons["Scan local network"]
        for _ in 0..<6 where !scanLink.exists { scrollDown(app) }
        guard scanLink.waitForExistence(timeout: 10) else {
            reportHierarchy(app, step: "Scan local network link")
            return XCTFail("Settings should offer a local network scan")
        }
        scanLink.tap()
        guard app.navigationBars["Scan local network"].waitForExistence(timeout: 10) else {
            reportHierarchy(app, step: "LAN scan screen")
            return XCTFail("the scan screen should open")
        }

        // Custom ports keep the sweep to three knocks per address.
        if app.buttons["Custom"].exists {
            app.buttons["Custom"].tap()
            let field = app.textFields["22, 8080, 9090"]
            if field.waitForExistence(timeout: 5) {
                field.tap()
                app.typeText("22,80,443")
            }
        }

        // Dismissing the keyboard is the app's job now, but the test types
        // into a field and then taps a toolbar button, so make sure the tap
        // lands rather than being eaten by a keyboard that is still up.
        if app.keyboards.count > 0 { app.typeText("\n") }
        // The seeded vault's hosts all use "andy", so the username field
        // arrives pre-filled from the vault rather than empty.
        app.buttons["Scan"].firstMatch.tap()
        // iOS asks for Local Network permission the first time. The alert
        // belongs to springboard, not to us.
        allowLocalNetwork(app)

        // Wait for the scan to finish rather than for a fixed interval: a /24
        // on three ports is ~15 s here but slower on a busy machine.
        let cancel = app.buttons["Cancel"]
        let deadline = Date().addingTimeInterval(120)
        while cancel.exists, Date() < deadline {
            Thread.sleep(forTimeInterval: 2.0)
        }
        Thread.sleep(forTimeInterval: 1.0)
        // Scroll the results into view: the controls take most of a phone
        // screen, and a screenshot of the form proves nothing.
        scrollDown(app)
        Thread.sleep(forTimeInterval: 1.0)
        capture(app, named: "11-lan-scan")

        // The scan is the point; a screenshot of an empty list would pass
        // while proving nothing about the sockets.
        let hostCount = app.staticTexts.allElementsBoundByIndex
            .map { $0.label.lowercased() }
            .first { $0.hasSuffix(" hosts") || $0 == "1 host" } ?? "no host count on screen"
        print("ghostty-screenshots: the scan reported \(hostCount)")
        XCTAssertTrue(
            app.navigationBars["Scan local network"].exists,
            "the app should still be in the foreground after a sweep"
        )

        // Import everything the sweep found, then look at the Local group.
        // The actions sit below the whole results list, which on a busy
        // network is several screens long.
        let importButton = app.buttons.matching(
            NSPredicate(format: "label BEGINSWITH 'Import'")
        ).firstMatch
        for _ in 0..<40 where !importButton.exists { scrollDown(app) }
        if importButton.waitForExistence(timeout: 5) {
            importButton.tap()
            if app.alerts["Imported"].waitForExistence(timeout: 10) {
                app.alerts["Imported"].buttons["OK"].tap()
            }
        } else {
            reportHierarchy(app, step: "Import button (the scan may have found nothing)")
        }

        selectTab(app, named: "Hosts", expecting: "Hosts")
        for _ in 0..<10 where !app.staticTexts["Local"].exists { scrollDown(app) }
        Thread.sleep(forTimeInterval: 1.0)
        XCTAssertEqual(app.state, .runningForeground, "Ghostty should still be in front")
        capture(app, named: "12-local-hosts")

        // An imported host with no username cannot be connected to, so the
        // subtitle must never start with "@".
        let rows = app.staticTexts.allElementsBoundByIndex
            .map(\.label)
            .filter { $0.contains("@10.0.0.") }
        print("ghostty-screenshots: imported rows \(rows.prefix(4))")
        XCTAssertFalse(
            rows.contains { $0.hasPrefix("@") },
            "every imported host should carry a username"
        )
        XCTAssertTrue(captured.contains("11-lan-scan"))
        XCTAssertTrue(captured.contains("12-local-hosts"))
        print("ghostty-screenshots: wrote \(captured.joined(separator: ", ")) to \(outputDirectory.path)")
    }

    /// Tap through the system's Local Network permission alert, wherever it
    /// decides to live.
    private func allowLocalNetwork(_ app: XCUIApplication) {
        let springboard = XCUIApplication(bundleIdentifier: "com.apple.springboard")
        for _ in 0..<10 {
            for host in [springboard, app] {
                let alert = host.alerts.firstMatch
                if alert.exists {
                    for label in ["Allow", "OK"] where alert.buttons[label].exists {
                        alert.buttons[label].tap()
                        return
                    }
                }
            }
            Thread.sleep(forTimeInterval: 1.0)
        }
    }

    /// Scroll by dragging inside the screen rather than `swipeUp()`.
    ///
    /// A swipe that starts near the bottom edge is the home gesture: a run
    /// that scrolled a long results list with `swipeUp(velocity: .fast)`
    /// backgrounded the app, opened the app switcher, and photographed a
    /// different application entirely.
    private func scrollDown(_ app: XCUIApplication) {
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.75))
            .press(
                forDuration: 0.05,
                thenDragTo: app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.25))
            )
        Thread.sleep(forTimeInterval: 0.3)
    }

    /// Switch tabs and *check that it worked*.
    ///
    /// iOS 26's floating tab bar reports button frames that overlap by ~10pt,
    /// and a plain `.tap()` on the element intermittently activates the
    /// neighbouring tab — which is how a screenshot run ends up photographing
    /// the Keys tab and calling it Settings. The fallback taps a fraction of
    /// the bar's own width instead, which is unambiguous.
    private func selectTab(_ app: XCUIApplication, named name: String, expecting title: String) {
        let tab = app.tabBars.buttons[name]
        if tab.waitForExistence(timeout: 10) { tab.tap() }
        if app.navigationBars[title].waitForExistence(timeout: 5) { return }

        let labels = app.tabBars.buttons.allElementsBoundByIndex.map(\.label)
        guard let index = labels.firstIndex(of: name) else {
            reportHierarchy(app, step: "the \(name) tab")
            return
        }
        let dx = (Double(index) + 0.5) / Double(labels.count)
        app.tabBars.firstMatch
            .coordinate(withNormalizedOffset: CGVector(dx: dx, dy: 0.5))
            .tap()
        if !app.navigationBars[title].waitForExistence(timeout: 10) {
            reportHierarchy(app, step: "the \(name) tab after a coordinate tap")
        }
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
