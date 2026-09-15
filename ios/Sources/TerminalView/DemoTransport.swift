import Foundation

/// A tiny local fake shell.
///
/// This is not a feature, it is a test fixture that ships: it lets the
/// terminal emulator, the CoreText renderer, the key bar and the gesture
/// handling be verified on a simulator with no network, no server and no
/// credentials. Everything it emits is real VT — it is libghostty-vt that
/// interprets it, exactly as it would interpret bytes off an SSH channel.
@MainActor
final class DemoTransport: TerminalTransport {
    var onReceive: ((Data) -> Void)?
    var onStatusChange: (() -> Void)?

    private(set) var statusLabel = "demo"
    let isConnected = true
    let isError = false

    private var line = ""
    private var cols = 80
    private var rows = 24

    private let prompt = "\u{1b}[1;32mghostty\u{1b}[0m:\u{1b}[1;34m~\u{1b}[0m$ "

    func start(cols: Int, rows: Int) {
        self.cols = cols
        self.rows = rows
        emit(banner())
        emit("\r\n" + prompt)
    }

    func stop() {}

    func resize(cols: Int, rows: Int, pixelWidth: Int, pixelHeight: Int) {
        self.cols = cols
        self.rows = rows
        statusLabel = "demo \(cols)×\(rows)"
        onStatusChange?()
    }

    func send(_ data: Data) {
        for byte in data {
            switch byte {
            case 0x0D, 0x0A:            // CR / LF: run the line
                emit("\r\n")
                run(line)
                line = ""
                emit(prompt)
            case 0x7F, 0x08:            // DEL / BS
                if !line.isEmpty {
                    line.removeLast()
                    emit("\u{8} \u{8}")
                }
            case 0x03:                  // ctrl-c
                emit("^C\r\n" + prompt)
                line = ""
            case 0x0C:                  // ctrl-l
                emit("\u{1b}[2J\u{1b}[H" + prompt + line)
            case 0x20...0x7E:
                let ch = String(UnicodeScalar(byte))
                line.append(ch)
                emit(ch)
            default:
                // Escape sequences (arrow keys and friends) are swallowed;
                // a real shell would do line editing with them.
                break
            }
        }
    }

    // MARK: - The "shell"

    private func run(_ command: String) {
        let parts = command.split(separator: " ", maxSplits: 1).map(String.init)
        guard let verb = parts.first else { return }
        let rest = parts.count > 1 ? parts[1] : ""

        switch verb {
        case "help":
            emit("""
            Demo commands: \u{1b}[1mhelp colors banner date echo ls clear\u{1b}[0m\r\n\
            This terminal is libghostty-vt. There is no shell on iOS — for a\r\n\
            real session, add a host in the Hosts tab and connect over SSH.\r\n
            """)
        case "colors":
            emitColorChart()
        case "banner":
            emit(banner())
        case "date":
            emit(Date().formatted(date: .complete, time: .standard) + "\r\n")
        case "echo":
            emit(rest + "\r\n")
        case "ls":
            emit("\u{1b}[1;34mhosts\u{1b}[0m  \u{1b}[1;34midentities\u{1b}[0m  \u{1b}[1;34mknown_hosts\u{1b}[0m  README.md\r\n")
        case "clear":
            emit("\u{1b}[2J\u{1b}[H")
        case "":
            break
        default:
            emit("\u{1b}[31m\(verb): command not found\u{1b}[0m (try `help`)\r\n")
        }
    }

    private func banner() -> String {
        var s = ""
        s += "\u{1b}[1;35m  ▄▄ Ghostty for iOS ▄▄\u{1b}[0m\r\n"
        s += "  terminal core: \u{1b}[1mlibghostty-vt\u{1b}[0m   transport: \u{1b}[1mSSH\u{1b}[0m (swift-nio-ssh)\r\n"
        s += "  \u{1b}[2mbold\u{1b}[0m \u{1b}[1mbold\u{1b}[0m  \u{1b}[3mitalic\u{1b}[0m  \u{1b}[4munderline\u{1b}[0m  \u{1b}[9mstrike\u{1b}[0m  \u{1b}[7minverse\u{1b}[0m\r\n"
        s += "  "
        for i in 1...6 { s += "\u{1b}[4\(i)m  \u{1b}[0m" }
        s += "  \u{1b}[38;2;255;128;0mtruecolour\u{1b}[0m  \u{1b}[38;5;213m256-colour\u{1b}[0m\r\n"
        s += "  type \u{1b}[1mhelp\u{1b}[0m for demo commands\r\n"
        return s
    }

    private func emitColorChart() {
        var s = ""
        for row in 0..<16 {
            for col in 0..<16 {
                let idx = row * 16 + col
                s += "\u{1b}[48;5;\(idx)m\u{1b}[38;5;\(idx > 240 ? 16 : 231)m\(String(format: "%4d", idx))\u{1b}[0m"
            }
            s += "\r\n"
        }
        emit(s)
    }

    private func emit(_ text: String) {
        onReceive?(Data(text.utf8))
    }
}
