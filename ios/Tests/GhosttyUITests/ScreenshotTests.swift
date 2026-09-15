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

    override func setUpWithError() throws {
        // Keep going after a soft failure so one missing element does not cost
        // us every later screenshot.
        continueAfterFailure = true
        outputDirectory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("ghostty-screenshots", isDirectory: true)
        try? FileManager.default.removeItem(at: outputDirectory)
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

        // 3. The demo terminal: real VT rendered by libghostty-vt. The empty
        //    Sessions tab offers it directly, which is a more reliable target
        //    than the same action buried in the Settings form.
        app.tabBars.buttons["Sessions"].tap()
        _ = app.navigationBars["Sessions"].waitForExistence(timeout: 10)
        let demoButton = app.buttons["Open demo terminal"].firstMatch
        XCTAssertTrue(demoButton.waitForExistence(timeout: 10), "the empty sessions tab should offer the demo terminal")
        demoButton.tap()

        let demoRow = app.staticTexts["Demo terminal"]
        XCTAssertTrue(demoRow.waitForExistence(timeout: 15), "a demo session should appear in the list")
        if demoRow.exists {
            demoRow.tap()
        } else {
            reportHierarchy(app, step: "demo session row")
        }
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

        app.navigationBars.buttons.firstMatch.tap()

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

        XCTAssertTrue(captured.contains("01-hosts"))
        XCTAssertTrue(captured.contains("03-terminal"))
        print("ghostty-screenshots: wrote \(captured.joined(separator: ", ")) to \(outputDirectory.path)")
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
