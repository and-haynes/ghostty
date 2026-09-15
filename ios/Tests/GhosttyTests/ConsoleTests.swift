import XCTest
@testable import Ghostty

final class ConsoleSSHParsingTests: XCTestCase {
    func testBareHost() throws {
        let request = try ConsoleTransport.parseSSH(["noether"])
        XCTAssertEqual(request, ConsoleSSHRequest(user: nil, host: "noether", port: nil, identityName: nil))
    }

    func testUserAtHost() throws {
        let request = try ConsoleTransport.parseSSH(["andy@10.0.0.81"])
        XCTAssertEqual(request.user, "andy")
        XCTAssertEqual(request.host, "10.0.0.81")
    }

    func testPortFlagAndIdentity() throws {
        let request = try ConsoleTransport.parseSSH(["git@git.lan", "-p", "2222", "-i", "iPhone"])
        XCTAssertEqual(request.user, "git")
        XCTAssertEqual(request.host, "git.lan")
        XCTAssertEqual(request.port, 2222)
        XCTAssertEqual(request.identityName, "iPhone")
    }

    func testEmbeddedPort() throws {
        // "host:2222" is a habit from other tools; accepting it costs nothing.
        let request = try ConsoleTransport.parseSSH(["andy@pi-a:2222"])
        XCTAssertEqual(request.host, "pi-a")
        XCTAssertEqual(request.port, 2222)
    }

    func testExplicitPortFlagBeatsEmbedded() throws {
        let request = try ConsoleTransport.parseSSH(["pi-a:2222", "-p", "22"])
        XCTAssertEqual(request.port, 22)
    }

    func testRejectsNonsense() {
        XCTAssertThrowsError(try ConsoleTransport.parseSSH([]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["@host"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["user@"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["host", "-p"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["host", "-p", "0"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["host", "-p", "99999"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["host", "-i"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["one", "two"]))
        XCTAssertThrowsError(try ConsoleTransport.parseSSH(["host", "--nope"]))
    }

    func testTokeniserHonoursQuotes() {
        XCTAssertEqual(ConsoleTransport.tokenise("echo hello world"), ["echo", "hello", "world"])
        XCTAssertEqual(ConsoleTransport.tokenise("echo \"hello world\""), ["echo", "hello world"])
        XCTAssertEqual(ConsoleTransport.tokenise("echo 'a b' c"), ["echo", "a b", "c"])
        XCTAssertEqual(ConsoleTransport.tokenise("   "), [])
    }
}

@MainActor
final class ConsoleTransportTests: XCTestCase {
    /// Collects everything the console emits, decoded as text.
    private func makeConsole(host: ConsoleCommandHost? = nil) -> (ConsoleTransport, () -> String) {
        let transport = ConsoleTransport(commandHost: host)
        var output = Data()
        transport.onReceive = { output.append($0) }
        return (transport, { String(decoding: output, as: UTF8.self) })
    }

    func testUnknownCommandIsFriendly() {
        let (console, text) = makeConsole()
        console.run("frobnicate")
        XCTAssertTrue(text().contains("not a console command"))
        XCTAssertTrue(text().contains("ssh user@host"), "the hint should point at the thing people want")
    }

    func testEchoPrintsArguments() {
        let (console, text) = makeConsole()
        console.run("echo hello world")
        XCTAssertTrue(text().contains("hello world"))
    }

    func testHelpMentionsEveryCommand() {
        let (console, text) = makeConsole()
        console.run("help")
        for command in ["ssh", "hosts", "keys", "echo", "demo", "clear"] {
            XCTAssertTrue(text().contains(command), "help should mention \(command)")
        }
    }

    func testHostsAndKeysUseTheHost() {
        let stub = StubCommandHost()
        stub.hosts = [Host(alias: "noether", hostname: "10.0.0.81", username: "andy")]
        stub.identities = [Identity(
            name: "iPhone",
            keyType: .ed25519,
            publicKeyLine: "ssh-ed25519 AAAA test",
            fingerprint: "SHA256:abc"
        )]
        let (console, text) = makeConsole(host: stub)
        console.run("hosts")
        console.run("keys")
        XCTAssertTrue(text().contains("noether"))
        XCTAssertTrue(text().contains("andy@10.0.0.81"))
        XCTAssertTrue(text().contains("iPhone"))
        XCTAssertTrue(text().contains("SHA256:abc"))
    }

    func testSSHDelegatesToTheHost() {
        let stub = StubCommandHost()
        let (console, text) = makeConsole(host: stub)
        console.run("ssh andy@pi-a -p 2222")
        XCTAssertEqual(stub.opened?.host, "pi-a")
        XCTAssertEqual(stub.opened?.user, "andy")
        XCTAssertEqual(stub.opened?.port, 2222)
        XCTAssertTrue(text().contains("connecting"))
    }

    func testSSHReportsParseErrorsWithoutOpening() {
        let stub = StubCommandHost()
        let (console, text) = makeConsole(host: stub)
        console.run("ssh")
        XCTAssertNil(stub.opened)
        XCTAssertTrue(text().contains("usage:"))
    }

    func testTypingIsEchoedAndEnterRuns() {
        let stub = StubCommandHost()
        let (console, text) = makeConsole(host: stub)
        console.send(Data("echo hi\r".utf8))
        XCTAssertTrue(text().contains("echo hi"), "typed characters should be echoed locally")
        XCTAssertTrue(text().contains("hi\r\n"))
    }

    func testBackspaceErases() {
        let (console, text) = makeConsole()
        console.send(Data("echo hix".utf8))
        console.send(Data([0x7F]))
        console.send(Data("\r".utf8))
        // "hix" minus the x: the command ran as `echo hi`.
        XCTAssertTrue(text().hasSuffix("$ ") || text().contains("hi"))
        XCTAssertFalse(text().contains("hix\r\n"))
    }
}

@MainActor
private final class StubCommandHost: ConsoleCommandHost {
    var hosts: [Host] = []
    var identities: [Identity] = []
    var opened: ConsoleSSHRequest?

    var consoleHosts: [Host] { hosts }
    var consoleIdentities: [Identity] { identities }

    func consoleOpenSSH(_ request: ConsoleSSHRequest) -> String {
        opened = request
        return "connecting to \(request.host)…"
    }
}

// MARK: - Key bar

@MainActor
final class KeyBarModelTests: XCTestCase {
    func testSingleTapArmsAndIsConsumedOnce() {
        let model = KeyBarModel()
        model.tap(.control)
        XCTAssertEqual(model.state(of: .control), .sticky)
        XCTAssertEqual(model.activeMods, .ctrl)
        XCTAssertEqual(model.consumeMods(), .ctrl)
        XCTAssertEqual(model.state(of: .control), .off, "an armed modifier fires once")
    }

    func testDoubleTapLocksAndSurvivesConsumption() {
        let model = KeyBarModel()
        var clock = Date(timeIntervalSince1970: 0)
        model.now = { clock }

        model.tap(.control)
        clock = clock.addingTimeInterval(0.1)
        model.tap(.control)
        XCTAssertEqual(model.state(of: .control), .locked)

        XCTAssertEqual(model.consumeMods(), .ctrl)
        XCTAssertEqual(model.state(of: .control), .locked, "a locked modifier stays until tapped off")
        XCTAssertEqual(model.consumeMods(), .ctrl)
    }

    func testSlowSecondTapTurnsOffRatherThanLocking() {
        let model = KeyBarModel()
        var clock = Date(timeIntervalSince1970: 0)
        model.now = { clock }
        model.tap(.control)
        clock = clock.addingTimeInterval(5)
        model.tap(.control)
        XCTAssertEqual(model.state(of: .control), .off)
    }

    func testTappingALockedModifierTurnsItOff() {
        let model = KeyBarModel()
        var clock = Date(timeIntervalSince1970: 0)
        model.now = { clock }
        model.tap(.alt)
        clock = clock.addingTimeInterval(0.1)
        model.tap(.alt)
        XCTAssertEqual(model.state(of: .alt), .locked)
        model.tap(.alt)
        XCTAssertEqual(model.state(of: .alt), .off)
    }

    func testModifiersCombine() {
        let model = KeyBarModel()
        model.tap(.control)
        model.tap(.alt)
        XCTAssertEqual(model.activeMods, [.ctrl, .alt])
    }

    func testHideKeyboardDoesNotEatArmedModifiers() {
        let model = KeyBarModel()
        var received: [(KeyBarAction, VTMods)] = []
        model.onAction = { received.append(($0, $1)) }
        model.tap(.control)
        model.perform(.hideKeyboard)
        XCTAssertEqual(model.state(of: .control), .sticky, "bar chrome is not a keystroke")
        model.perform(.escape)
        XCTAssertEqual(received.last?.1, .ctrl)
        XCTAssertEqual(model.state(of: .control), .off)
    }
}

// MARK: - Selection helper

final class SelectionSuggestionTests: XCTestCase {
    private func row(_ y: Int, prompt: VTSemanticPrompt = .none) -> VTRow {
        VTRow(y: y, cells: [], semanticPrompt: prompt)
    }

    func testWithoutMarksInputIsTheCursorRowAndOutputIsEverythingAbove() {
        let lines = (0..<10).map { row($0) }
        let suggestion = SelectionSuggestion.derive(lines: lines, cursorRow: 7)
        XCTAssertFalse(suggestion.fromShellIntegration)
        XCTAssertEqual(suggestion.inputRows, 7...7)
        XCTAssertEqual(suggestion.outputRows, 0...6)
    }

    func testWithMarksInputRunsFromPromptToCursor() {
        var lines = (0..<10).map { row($0) }
        lines[2].semanticPrompt = .prompt
        lines[6].semanticPrompt = .prompt
        let suggestion = SelectionSuggestion.derive(lines: lines, cursorRow: 7)
        XCTAssertTrue(suggestion.fromShellIntegration)
        XCTAssertEqual(suggestion.inputRows, 6...7)
        XCTAssertEqual(suggestion.outputRows, 3...5, "output is what sits between the two commands")
    }

    func testContinuationLinesBelongToThePreviousCommand() {
        var lines = (0..<10).map { row($0) }
        lines[1].semanticPrompt = .prompt
        lines[2].semanticPrompt = .promptContinuation
        lines[6].semanticPrompt = .prompt
        let suggestion = SelectionSuggestion.derive(lines: lines, cursorRow: 6)
        XCTAssertEqual(suggestion.outputRows, 3...5, "the continuation row is input, not output")
    }

    func testNoOutputWhenThePromptIsAtTheTop() {
        var lines = (0..<4).map { row($0) }
        lines[0].semanticPrompt = .prompt
        let suggestion = SelectionSuggestion.derive(lines: lines, cursorRow: 0)
        XCTAssertEqual(suggestion.inputRows, 0...0)
        XCTAssertNil(suggestion.outputRows)
    }

    func testBothSpansTheUnion() {
        let suggestion = SelectionSuggestion(inputRows: 6...7, outputRows: 3...5, fromShellIntegration: true)
        XCTAssertEqual(suggestion.bothRows, 3...7)
    }

    func testEmptyFrameSuggestsNothing() {
        XCTAssertTrue(SelectionSuggestion.derive(lines: [], cursorRow: nil).isEmpty)
    }

    func testCursorBeyondTheFrameIsClamped() {
        let lines = (0..<3).map { row($0) }
        let suggestion = SelectionSuggestion.derive(lines: lines, cursorRow: 99)
        XCTAssertEqual(suggestion.inputRows, 2...2)
    }
}
