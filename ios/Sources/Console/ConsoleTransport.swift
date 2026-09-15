import Foundation

/// What the console needs from the rest of the app to answer a command.
///
/// Kept as a protocol so the interpreter can be unit-tested without a
/// `SessionManager`, a `Vault`, or a socket.
@MainActor
protocol ConsoleCommandHost: AnyObject {
    var consoleHosts: [Host] { get }
    var consoleIdentities: [Identity] { get }
    /// Non-SSH things a LAN scan found. Listed by `hosts` so the console is a
    /// complete picture of the network, not just the parts it can connect to.
    var consoleLocalServices: [LocalService] { get }
    /// Open a session for this request. Returns the line to print back.
    func consoleOpenSSH(_ request: ConsoleSSHRequest) -> String
}

extension ConsoleCommandHost {
    /// Defaulted so a test double (and any host that never scans) does not
    /// have to care that local services exist.
    var consoleLocalServices: [LocalService] { [] }
}

/// A parsed `ssh` invocation.
struct ConsoleSSHRequest: Equatable {
    var user: String?
    var host: String
    var port: Int?
    var identityName: String?
}

/// The local console: a terminal with no far end but this interpreter.
///
/// iOS has no shell, so this is not a shell — it is a command line for the app
/// itself. Its real job is `ssh`, which is the fastest way to reach a machine
/// that *does* have a shell; everything else is there so the console is a
/// usable place to stand rather than a single-purpose prompt.
@MainActor
final class ConsoleTransport: TerminalTransport {
    var onReceive: ((Data) -> Void)?
    var onStatusChange: (() -> Void)?

    private(set) var statusLabel = "console"
    let isConnected = true
    let isError = false

    weak var commandHost: ConsoleCommandHost?

    private var line = ""
    private var history: [String] = []
    private var cols = 80

    private let prompt = "\u{1b}[1;32mghostty\u{1b}[0m:\u{1b}[1;34m~\u{1b}[0m$ "

    init(commandHost: ConsoleCommandHost? = nil) {
        self.commandHost = commandHost
    }

    func start(cols: Int, rows: Int) {
        self.cols = cols
        emit(banner())
        emit("\r\n" + prompt)
    }

    func stop() {}

    func resize(cols: Int, rows: Int, pixelWidth: Int, pixelHeight: Int) {
        self.cols = cols
        statusLabel = "console \(cols)×\(rows)"
        onStatusChange?()
    }

    func send(_ data: Data) {
        // The console does its own line editing because there is no remote
        // shell to do it: every byte here is echoed by us or by nobody.
        for byte in data {
            switch byte {
            case 0x0D, 0x0A:
                emit("\r\n")
                let command = line
                line = ""
                if !command.trimmingCharacters(in: .whitespaces).isEmpty {
                    history.append(command)
                }
                run(command)
                emit(prompt)
            case 0x7F, 0x08:
                if !line.isEmpty {
                    line.removeLast()
                    emit("\u{8} \u{8}")
                }
            case 0x03:
                emit("^C\r\n" + prompt)
                line = ""
            case 0x0C:
                emit("\u{1b}[2J\u{1b}[H" + prompt + line)
            case 0x15:  // ctrl-u
                if !line.isEmpty {
                    emit(String(repeating: "\u{8} \u{8}", count: line.count))
                    line = ""
                }
            case 0x20...0x7E:
                let ch = String(UnicodeScalar(byte))
                line.append(ch)
                emit(ch)
            default:
                break
            }
        }
    }

    // MARK: - Interpreter

    func run(_ command: String) {
        let argv = ConsoleTransport.tokenise(command)
        guard let verb = argv.first else { return }
        Haptics.shared.fire(.consoleCommand)
        let args = Array(argv.dropFirst())

        switch verb {
        case "help", "?":
            emitHelp()
        case "clear":
            emit("\u{1b}[2J\u{1b}[H")
        case "hosts":
            emitHosts()
        case "keys":
            emitKeys()
        case "echo":
            emit(args.joined(separator: " ") + "\r\n")
        case "demo":
            emit(banner())
        case "history":
            for (index, entry) in history.enumerated() {
                emit(String(format: "%4d  ", index + 1) + entry + "\r\n")
            }
        case "ssh":
            runSSH(args)
        default:
            emit("\u{1b}[31m\(verb)\u{1b}[0m: not a console command. "
                 + "Try \u{1b}[1mhelp\u{1b}[0m, or \u{1b}[1mssh user@host\u{1b}[0m to connect.\r\n")
        }
    }

    private func runSSH(_ args: [String]) {
        do {
            let request = try ConsoleTransport.parseSSH(args)
            guard let commandHost else {
                emit("\u{1b}[31mssh\u{1b}[0m: the console isn't wired to the session manager.\r\n")
                return
            }
            emit(commandHost.consoleOpenSSH(request) + "\r\n")
        } catch let error as ConsoleError {
            emit("\u{1b}[31mssh\u{1b}[0m: \(error.message)\r\n")
        } catch {
            emit("\u{1b}[31mssh\u{1b}[0m: \(error.localizedDescription)\r\n")
        }
    }

    struct ConsoleError: Error {
        let message: String
    }


    /// `ssh [user@]host [-p port] [-i identity-name]`
    ///
    /// `nonisolated` because it is pure string work with no state — the parser
    /// should be testable without hopping to the main actor.
    nonisolated static func parseSSH(_ args: [String]) throws -> ConsoleSSHRequest {
        var target: String?
        var port: Int?
        var identity: String?
        var index = 0

        while index < args.count {
            let arg = args[index]
            switch arg {
            case "-p", "--port":
                index += 1
                guard index < args.count, let value = Int(args[index]), (1...65535).contains(value) else {
                    throw ConsoleError(message: "-p needs a port between 1 and 65535")
                }
                port = value
            case "-i", "--identity":
                index += 1
                guard index < args.count else {
                    throw ConsoleError(message: "-i needs the name of a key from the Keys tab")
                }
                identity = args[index]
            default:
                guard !arg.hasPrefix("-") else {
                    throw ConsoleError(message: "unknown option \(arg). Usage: ssh [user@]host [-p port] [-i key]")
                }
                guard target == nil else {
                    throw ConsoleError(message: "more than one host given. Usage: ssh [user@]host [-p port] [-i key]")
                }
                target = arg
            }
            index += 1
        }

        guard let target, !target.isEmpty else {
            throw ConsoleError(message: "usage: ssh [user@]host [-p port] [-i key]")
        }

        // "user@host" and "host" both work; a bare "@host" is a typo worth
        // catching rather than silently connecting as nobody.
        var user: String?
        var hostname = target
        if let at = target.firstIndex(of: "@") {
            let candidate = String(target[target.startIndex..<at])
            guard !candidate.isEmpty else {
                throw ConsoleError(message: "no username before the @ in \(target)")
            }
            user = candidate
            hostname = String(target[target.index(after: at)...])
            guard !hostname.isEmpty else {
                throw ConsoleError(message: "no host after the @ in \(target)")
            }
        }

        // An embedded port ("host:2222") is a common habit from other tools.
        if let colon = hostname.lastIndex(of: ":"),
           let embedded = Int(hostname[hostname.index(after: colon)...]),
           (1...65535).contains(embedded) {
            port = port ?? embedded
            hostname = String(hostname[hostname.startIndex..<colon])
        }

        return ConsoleSSHRequest(user: user, host: hostname, port: port, identityName: identity)
    }

    /// Whitespace split that honours single and double quotes.
    nonisolated static func tokenise(_ input: String) -> [String] {
        var out: [String] = []
        var current = ""
        var quote: Character?
        for character in input {
            if let active = quote {
                if character == active { quote = nil } else { current.append(character) }
            } else if character == "\"" || character == "'" {
                quote = character
            } else if character.isWhitespace {
                if !current.isEmpty { out.append(current); current = "" }
            } else {
                current.append(character)
            }
        }
        if !current.isEmpty { out.append(current) }
        return out
    }

    // MARK: - Output

    private func emitHelp() {
        emit("""
        \u{1b}[1mConsole commands\u{1b}[0m\r\n\
          \u{1b}[1mssh\u{1b}[0m [user@]host [-p port] [-i key]   connect, opening a session\r\n\
          \u{1b}[1mhosts\u{1b}[0m                              list saved hosts and local services\r\n\
          \u{1b}[1mkeys\u{1b}[0m                               list keys in the vault\r\n\
          \u{1b}[1mecho\u{1b}[0m <text>                        print text\r\n\
          \u{1b}[1mdemo\u{1b}[0m                               the colour and style banner\r\n\
          \u{1b}[1mhistory\u{1b}[0m                            commands you have run\r\n\
          \u{1b}[1mclear\u{1b}[0m                              clear the screen\r\n\
        \r\n\
        This is the app's own command line, not a shell — iOS has none. The\r\n\
        terminal itself is libghostty-vt, the same emulator an SSH session uses.\r\n
        """)
    }

    private func emitHosts() {
        let hosts = commandHost?.consoleHosts ?? []
        let services = commandHost?.consoleLocalServices ?? []
        guard !hosts.isEmpty || !services.isEmpty else {
            emit("No saved hosts. Add one in the Hosts tab, scan the local network in\r\n"
                 + "Settings, or just `ssh user@host`.\r\n")
            return
        }

        let width = max(hosts.map(\.displayName.count).max() ?? 8, 8)
        for host in hosts.sorted(by: { $0.displayName < $1.displayName }) {
            let name = host.displayName.padding(toLength: width, withPad: " ", startingAt: 0)
            emit("  \u{1b}[1m\(name)\u{1b}[0m  \(host.username)@\(host.destination)"
                 + (host.group.isEmpty ? "" : "  \u{1b}[2m\(host.group)\u{1b}[0m") + "\r\n")
        }

        // Listed but not connectable: the console's `ssh` cannot speak HTTP or
        // SMB, and saying so beats a name that silently does nothing.
        guard !services.isEmpty else { return }
        let serviceWidth = max(services.map(\.alias.count).max() ?? 8, 8)
        emit("\r\n  \u{1b}[2mlocal services (not connectable from here)\u{1b}[0m\r\n")
        for service in services.sorted(by: { $0.urlString < $1.urlString }) {
            let name = service.alias.padding(toLength: serviceWidth, withPad: " ", startingAt: 0)
            emit("  \u{1b}[1m\(name)\u{1b}[0m  \(service.urlString)"
                 + "  \u{1b}[2m\(service.serviceType)\u{1b}[0m\r\n")
        }
    }

    private func emitKeys() {
        let identities = commandHost?.consoleIdentities ?? []
        guard !identities.isEmpty else {
            emit("No keys yet. Generate one in the Keys tab.\r\n")
            return
        }
        for identity in identities {
            let badge = identity.isSecureEnclave ? "  \u{1b}[32m[secure enclave]\u{1b}[0m" : ""
            emit("  \u{1b}[1m\(identity.name)\u{1b}[0m  \u{1b}[2m\(identity.keyType.displayName)\u{1b}[0m\(badge)\r\n")
            emit("    \u{1b}[2m\(identity.fingerprint)\u{1b}[0m\r\n")
        }
    }

    private func banner() -> String {
        var s = ""
        s += "\u{1b}[1;35m  ▄▄ Ghostty for iOS ▄▄\u{1b}[0m\r\n"
        s += "  terminal core: \u{1b}[1mlibghostty-vt\u{1b}[0m   transport: \u{1b}[1mSSH\u{1b}[0m (swift-nio-ssh)\r\n"
        s += "  \u{1b}[2mfaint\u{1b}[0m \u{1b}[1mbold\u{1b}[0m  \u{1b}[3mitalic\u{1b}[0m  \u{1b}[4munderline\u{1b}[0m  \u{1b}[9mstrike\u{1b}[0m  \u{1b}[7minverse\u{1b}[0m\r\n"
        s += "  "
        for i in 1...6 { s += "\u{1b}[4\(i)m  \u{1b}[0m" }
        s += "  \u{1b}[38;2;255;128;0mtruecolour\u{1b}[0m  \u{1b}[38;5;213m256-colour\u{1b}[0m\r\n"
        s += "  type \u{1b}[1mhelp\u{1b}[0m, or \u{1b}[1mssh user@host\u{1b}[0m to connect\r\n"
        return s
    }

    private func emit(_ text: String) {
        onReceive?(Data(text.utf8))
    }
}
