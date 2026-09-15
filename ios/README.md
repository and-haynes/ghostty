# Ghostty for iOS

An SSH-first terminal for iPhone and iPad whose terminal emulation is
Ghostty's own.

## Why this shape

Upstream Ghostty removed its iOS app target. What still builds for iOS is
**libghostty-vt** — see `src/build/Config.zig`, which gates the iOS target down
to the VT library alone. That library is the terminal: the escape-sequence
parser, the screen and scrollback, reflow on resize, render state, and the key,
mouse and paste encoders. It is deliberately *not* a terminal application: it
has no pty, no renderer, no shell.

Two of those three are ours to supply, and the third cannot exist. iOS has no
shell and no `fork`. So the far end of this terminal is always a **network**:
an SSH channel to a machine that does have a shell. That is not a compromise
around the platform, it is the only honest design for a terminal on iOS — and
it means the app needs a real vault of SSH identities and pinned host keys, not
a settings toggle.

```
┌──────────────────────────────────────────────────────────────┐
│ SwiftUI app  (Sources/App)                                   │
│   Hosts · Keys · Sessions · Settings · TOFU + password alerts │
└───────────────┬──────────────────────────────┬───────────────┘
                │                              │
┌───────────────▼──────────────┐  ┌────────────▼───────────────┐
│ TerminalView (UIKit)         │  │ Vault (Sources/Vault)      │
│  · CoreText grid, dirty-row  │  │  · Identity / Host /       │
│    redraw, selection, pinch  │  │    KnownHost metadata JSON │
│  · UIKeyInput + pressesBegan │  │  · Keychain-only secrets   │
│  · mobile key bar            │  │  · openssh-key-v1 parser   │
└───────────────┬──────────────┘  │  · pure TOFU policy        │
                │                 └────────────┬───────────────┘
      ┌─────────▼─────────┐                    │
      │ TerminalSession   │                    │
      │  bytes in ⇄ out   │                    │
      └────┬─────────┬────┘                    │
           │         │                         │
 ┌─────────▼──┐  ┌───▼────────────────┐        │
 │ GhosttyVT  │  │ TerminalTransport  │        │
 │ (C wrapper)│  ├────────────────────┤        │
 │            │  │ SSHTransport ──────┼────────┘
 │  libghostty│  │ DemoTransport      │   (keys, passwords,
 │  -vt .a    │  └────────┬───────────┘    host-key pins)
 └────────────┘           │
                  ┌───────▼────────┐
                  │ SSHSession     │  swift-nio-ssh
                  │  pty-req/shell │  Curve25519 · P-256/384/521
                  │  window-change │  Secure Enclave P-256
                  └────────────────┘
```

Bytes off the SSH channel go into `ghostty_terminal_vt_write`. Key presses go
through `ghostty_key_encoder_encode`, with the encoder's options refreshed from
the terminal (`ghostty_key_encoder_setopt_from_terminal`) before **every**
keystroke — a program can enable application cursor keys or the Kitty keyboard
protocol at any moment and the very next key has to honour it. Resize is
`ghostty_terminal_resize` plus an SSH `window-change`. Paste goes through
`ghostty_paste_encode`, honouring bracketed-paste mode, with
`ghostty_paste_is_safe` deciding whether to warn first.

## Building

```bash
# 1. Build and stage libghostty-vt as an XCFramework (~5-10 min; reuses an
#    existing zig-out build unless you pass --force).
./build-libvt.sh

# 2. Generate the Xcode project. Xcode resolves the SwiftPM packages over the
#    network on first open/build.
xcodegen generate

# 3. Build and test.
xcodebuild build -scheme Ghostty -project Ghostty.xcodeproj \
  -destination 'generic/platform=iOS Simulator' \
  -derivedDataPath /tmp/ghosttybuild CODE_SIGNING_ALLOWED=NO

xcodebuild test -scheme Ghostty -project Ghostty.xcodeproj \
  -destination 'platform=iOS Simulator,name=iPhone 17' \
  -derivedDataPath /tmp/ghosttybuild CODE_SIGNING_ALLOWED=NO
```

`Frameworks/` is gitignored — the xcframework is a build artifact, not source.

Two build settings are load-bearing and both were learned the hard way:

* **No explicit `HEADER_SEARCH_PATHS` for the xcframework.** Xcode adds the
  matching slice's `Headers` directory itself. Adding it again makes clang read
  `module.modulemap` twice and fail with *Redefinition of module 'GhosttyVt'*.
* **`EXCLUDED_ARCHS[sdk=iphonesimulator*] = x86_64`.** The xcframework ships
  `ios-arm64` and `ios-arm64-simulator` only, so an x86_64 simulator slice has
  nothing to link against.

## Security model of the vault

| Thing | Where it lives |
|---|---|
| Private keys | Keychain, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` |
| Biometry-protected keys | Keychain + `SecAccessControl(.biometryCurrentSet)` |
| Secure Enclave keys | Inside the Enclave; the Keychain holds only a reference blob |
| Host passwords | Keychain, same protection class |
| Public keys, fingerprints, host metadata, known-hosts pins | JSON in Application Support, written atomically |

A filesystem dump of the app container therefore leaks host names and public
keys and nothing else. Keychain access goes through a `KeychainStore` protocol
so tests use an in-memory implementation — the simulator's real Keychain leaks
state across runs, and biometry and the Enclave are not testable there at all.

**iCloud Keychain sync is opt-in and off by default**, and is *refused* rather
than ignored for Secure Enclave and biometry-protected keys: a Secure Enclave
key is a reference to one specific chip and a `.biometryCurrentSet` policy is
bound to this device's enrolled biometrics. Honouring the toggle would leave
the metadata claiming a protection the stored item does not have.

**Host keys are pinned trust-on-first-use.** The first connection to an
endpoint stops the handshake and shows the key type and the OpenSSH-format
`SHA256:` fingerprint for a human to check (`ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` on the server). A key that does *not* match
an existing pin fails the handshake outright — there is deliberately no "accept
anyway" button, because that button is how pinning stops meaning anything. The
pin can be removed explicitly from **Keys ▸ Known hosts**, which is the
supported way to handle a re-imaged box.

## Feature matrix

### Done

| Area | |
|---|---|
| Terminal | Full libghostty-vt emulation: VT/ANSI parsing, scrollback, reflow on resize, alternate screen, modes |
| Rendering | CoreText grid, dirty-row incremental redraw, 256-colour + truecolour, bold/italic/faint/inverse/invisible, underline (single/double/dotted/dashed), strikethrough, overline, wide (CJK) cells, grapheme clusters |
| Cursor | Block / bar / underline / hollow, visibility and blink state from the terminal |
| Themes | Ghostty default, Catppuccin Mocha, Gruvbox Dark, Solarized Dark, Nord — applied through the terminal so OSC 4/10/11/104 still work |
| Input | Software keyboard via `UIKeyInput`; hardware keyboard via `pressesBegan` (modifiers, arrows, Esc, F1–F12, Home/End/PgUp/PgDn) |
| Key bar | Esc, Tab, sticky Ctrl, sticky Alt, arrows, `- / \| ~ :`, Home/End, PgUp/PgDn, Paste, hide-keyboard |
| Gestures | Pinch to resize the font, pan to scroll the viewport through scrollback, long-press to select a word and drag to extend, edit menu with Copy / Paste / Select All |
| Paste | Bracketed-paste aware, unsafe-paste confirmation |
| SSH | Connect, host key verification, `pty-req` (configurable TERM), `env`, `shell` or `exec`, `window-change`, clean disconnect, bounded reconnect with backoff |
| Auth | Password (stored or prompted), public key: Ed25519, ECDSA P-256/384/521, **Secure Enclave P-256** |
| Keys | Generate in-app, import unencrypted openssh-key-v1 (paste or Files), export/copy/share the public line, delete with confirmation, SHA256 fingerprints |
| Vault | Hosts with alias/group/tags/colour/TERM/font size/startup command/notes, known-hosts list with forget |
| Tests | 66 unit tests + a UI test that drives the real app and captures the screenshots below |

### Partial

* **Mouse reporting** — the encoder is wired (`VTMouseEncoder`, synced from
  terminal state) but no gesture currently forwards events to it, so programs
  that turn on mouse tracking see nothing. The seam is there; the gesture
  routing is not.
* **Selection** — long-press-and-drag works and copies correctly. There are no
  draggable selection handles, and rectangular selection is not exposed.
* **Curly underline** is drawn as a solid underline.
* **Reconnect** retries transport failures with backoff, but does not reattach
  to a remote session — if the far end's shell died, it died. Use `tmux`.
* **Session persistence** — sessions live only as long as the app process.

### TODO / not supported

* **RSA client keys.** Not a gap in this app: swift-nio-ssh has no RSA client
  key support at all. Ed25519 or ECDSA only.
* **Encrypted private key import.** A passphrase-protected key is refused with
  the command that fixes it (`ssh-keygen -p -N "" -f key`); the bcrypt-KDF +
  aes256-ctr path is unimplemented.
* **keyboard-interactive auth.** swift-nio-ssh 0.15.0 exposes only
  `privateKey`, `password`, `hostBased` and `none`. A server that offers
  *only* keyboard-interactive is reported as such rather than failing vaguely.
* **Jump hosts / ProxyJump.** Marked `// TODO(jump host)` in `SSHSession.swift`
  with the concrete shape (a `.directTCPIP` child channel running the same
  pipeline).
* **mosh.** Would need a UDP datagram protocol and a state-sync implementation;
  out of scope.
* **Port forwarding, SFTP, agent forwarding.**
* **IME / marked text.** `UIKeyInput` is implemented, full `UITextInput` is
  not, so CJK composition does not work.
* **Split panes and tabs** — one terminal per session, sessions in a list.

## Screenshots

Captured by `Tests/GhosttyUITests/ScreenshotTests.swift` driving the real app
on an iPhone 17 simulator.

| | |
|---|---|
| ![Hosts](docs/screenshots/01-hosts.png) | ![Identity](docs/screenshots/02-identity.png) |
| Hosts, grouped, with per-host accent colours | A key generated in-app, with its `authorized_keys` line |
| ![Terminal](docs/screenshots/03-terminal.png) | ![Key bar](docs/screenshots/04-terminal-keybar.png) |
| The demo terminal: real VT rendered by libghostty-vt — bold, italic, underline, strikethrough, inverse, truecolour | Key bar above the keyboard, 256-colour chart echoed locally |
| ![TOFU](docs/screenshots/05-tofu.png) | |
| A real first connection to a LAN host. The fingerprint shown matches `ssh-keyscan 10.0.0.41 \| ssh-keygen -lf -` exactly. | |

## Toolchain

| | |
|---|---|
| Xcode | 27.0 (27A266a) |
| Swift language mode | 5 |
| Deployment target | iOS 17.0, iPhone + iPad |
| zig (for libghostty-vt) | 0.16.0 |
| xcodegen | 2.46.0 |
| swift-nio-ssh | 0.15.0 |
| swift-nio | 2.102.0 |
| swift-crypto | 3.15.1 |
| Bundle id | `com.morton.ghostty` |

## Layout

```
ios/
├── build-libvt.sh              build + stage the xcframework
├── project.yml                 xcodegen spec
├── Sources/
│   ├── GhosttyVT/              Swift wrapper over the libghostty-vt C API
│   ├── TerminalView/           UIKit CoreText grid, key bar, transports
│   ├── SSH/                    swift-nio-ssh client, TOFU, auth
│   ├── Vault/                  identities, hosts, known hosts, Keychain
│   ├── Theme/                  colour schemes
│   └── App/                    SwiftUI screens
└── Tests/
    ├── GhosttyTests/           unit tests (VT, key encoding, vault, TOFU)
    └── GhosttyUITests/         drives the app, captures the screenshots
```

### A note on the demo terminal

`DemoTransport` is a tiny local fake shell reachable from **Settings ▸ Open
demo terminal**. It is a test fixture that ships: it is the only way to
exercise the emulator, the renderer, the gestures and the key bar on a
simulator with no server and no credentials. Everything it emits is real VT,
interpreted by libghostty-vt exactly as it would interpret bytes off a socket.
Type `help` for its command list.
