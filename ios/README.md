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
│   Hosts · Sessions · Console · Keys · Settings                │
│   TOFU + password alerts · Sync settings · Haptics            │
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
 │            │  │ SSHTransport ──────┼────────┤
 │  libghostty│  │ ConsoleTransport   │   (keys, passwords,
 │  -vt .a    │  └────────┬───────────┘    host-key pins)
 └────────────┘           │                     │
                          │          ┌──────────▼──────────────┐
                          │          │ VaultSyncEngine         │
                          │          │  newest-wins merge      │
                          │          ├─────────────────────────┤
                          │          │ iCloud Keychain         │
                          │          │ Bitwarden / Vaultwarden │
                          │          │ 1Password Connect       │
                          │          │ Encrypted bundle        │
                          │          └─────────────────────────┘
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

## Vault sync

Four providers behind one `VaultSyncProvider` protocol. Providers push and pull
whole snapshots and know nothing about conflict resolution — `VaultSyncEngine`
owns the single policy so every provider behaves identically and the rule
itself is testable without a network.

**The conflict rule is newest-wins at snapshot granularity.** Records are
unioned by id; where the same id exists on both sides, the newer snapshot's
copy is kept. This is deliberately coarse: `Identity`, `Host` and `KnownHost`
carry no per-record modification time, and inventing one would mean rewriting
records the user never touched. Additions and deletions on either side always
survive; editing *the same host* on two devices between syncs loses the older
edit. Per-record timestamps are a TODO.

**Secure Enclave keys are never synced by any provider.** They travel as
metadata with a `device-only` flag so the other device can see the key exists
and why it is unusable there, rather than silently missing a host's credential.

| Provider | What it needs | Where things go |
|---|---|---|
| **iCloud Keychain** | Nothing — the device's iCloud account | Private keys already replicate as `kSecAttrSynchronizable` Keychain items; this adds the non-secret half (hosts, pins, key metadata) as one synchronised Keychain item |
| **Bitwarden / Vaultwarden** | Server URL + email/master password (+ TOTP), or API key + master password | Keys as native **SSH key items** (cipher type 5); hosts and pins as one secure note, `Ghostty iOS hosts` |
| **1Password Connect** | Connect server URL + token | Keys as **SSH_KEY** items; hosts and pins as a **SECURE_NOTE**, `Ghostty iOS hosts` |
| **Encrypted bundle** | A passphrase | One AES-GCM file you move yourself, via the share sheet or Files |

The Bitwarden client does the real client-side crypto: `prelogin` for KDF
parameters, PBKDF2-SHA256 master key, HKDF stretch, unwrap of the user
symmetric key, and AES-256-CBC + HMAC-SHA256 `EncString` type 2 with the MAC
verified in constant time *before* decryption. The master password never leaves
the device; only a one-iteration hash of it is sent, exactly as the official
clients do.

**1Password has no on-device API for third-party apps** — no extension, no
local vault access, nothing an iOS app may call. Connect is a REST server you
host yourself, and it is the only supported route. This is stated in the app's
own Settings help text too, so nobody wastes an afternoon looking for the
integration that does not exist.

The encrypted bundle is the generic path for everything else (KeePass, Proton
Pass, …): one file, one passphrase, moved by hand.

## The Console tab

iOS has no shell, so the Console is not one — it is the app's own command line,
running on the same libghostty-vt emulator an SSH session uses. It is a
permanent tab because its real job is `ssh`:

```
ssh [user@]host [-p port] [-i identity-name]
```

The host resolves against the vault by alias or hostname, so `ssh noether`
inherits that host's key, TERM, font size and startup command; an unrecognised
name connects ad-hoc without being saved. Also `help`, `hosts`, `keys`, `echo`,
`demo`, `history` and `clear`. Unknown commands print a hint rather than an
error.

## The key bar

`[Esc Tab Ctrl Alt] | [arrows · symbols · Home/End/PgUp/PgDn · Fn] | [paste ⌨]`

The keys you reach for without looking are pinned; everything else scrolls
between them, so muscle memory survives a scroll position. **Ctrl and Alt are
tri-state**: one tap arms for the next key, a second tap within 400 ms locks
until tapped off (a phone gives you one thumb, so "hold ctrl and press c" has
to become two taps, and a lock is what makes `ctrl-a ctrl-d` bearable). Arrows
are one cluster with press-and-hold auto-repeat. F1–F12 hide behind an `Fn`
toggle so they do not push everything useful off the end.

The keyboard toggle uses the real `keyboard.chevron.compact.down` symbol, and
when the bar is collapsed a floating `keyboard` button appears bottom-right of
the terminal — the way back is always one tap away.

## The selection helper

Long-press to start a selection and a suggestion fades in: translucent bands
behind the **input** (the current command line) and the **output** (the
previous command's), plus `Input · Output · Both` chips near your finger.
Tapping a chip sets that exact selection; your own drag keeps working
untouched, because the chips are sibling views rather than a gesture and a
finger already owned by the drag stays owned by it.

With OSC 133 shell integration the ranges come from real prompt marks and the
chips use `ghostty_terminal_select_line` / `ghostty_terminal_select_output`,
which trim the prompt itself and take a wrapped command whole. Without it the
input is the cursor row and the output is everything above it in the viewport —
a suggestion that is sometimes approximate is far more useful than one that
only appears for people who have configured their shell.

## Haptics

One `Haptics` service, named by *event* rather than by generator, because the
mapping from "a connection came up" to "success notification" is a design
decision that belongs in one place. Impact (light/medium/rigid/soft), selection
and notification generators are kept warm ahead of gestures; the terminal bell
gets its own CoreHaptics pattern so `BEL` is distinguishable from every other
buzz the app makes.

**Settings ▸ Input ▸ Haptics** is Off / Subtle / Normal / **Rich**, default
Normal. Subtle keeps only events that happened on their own (connections,
errors, the bell) and scales impacts down; Normal adds keys, modifiers and the
keyboard toggle; Rich adds arrow repeats and per-cell selection ticks.

Three rules the call sites do not have to think about: one buzz per event (a
rate limiter collapses bursts), nothing while the app is backgrounded, and
nothing at all when it is off. Scrolling terminal output is deliberately silent.

## Feature matrix

### Done

| Area | |
|---|---|
| Terminal | Full libghostty-vt emulation: VT/ANSI parsing, scrollback, reflow on resize, alternate screen, modes |
| Rendering | CoreText grid, dirty-row incremental redraw, 256-colour + truecolour, bold/italic/faint/inverse/invisible, underline (single/double/dotted/dashed), strikethrough, overline, wide (CJK) cells, grapheme clusters |
| Cursor | Block / bar / underline / hollow, visibility and blink state from the terminal |
| Themes | Ghostty default, Catppuccin Mocha, Gruvbox Dark, Solarized Dark, Nord — applied through the terminal so OSC 4/10/11/104 still work |
| Input | Software keyboard via `UIKeyInput`; hardware keyboard via `pressesBegan` (modifiers, arrows, Esc, F1–F12, Home/End/PgUp/PgDn) |
| Key bar | Fixed Esc/Tab/Ctrl/Alt group, scrolling middle (arrow cluster with auto-repeat, symbols, Home/End/PgUp/PgDn, F1–F12 behind `Fn`), fixed paste + keyboard toggle; tri-state sticky/locked modifiers; floating keyboard button when collapsed |
| Console | Permanent tab with `ssh`, `hosts`, `keys`, `echo`, `demo`, `history`, `help`, `clear`; resolves hosts against the vault |
| Selection helper | Input/output bands and `Input · Output · Both` chips on long-press, OSC 133 aware with a cursor-based fallback |
| Sync | iCloud Keychain, Bitwarden/Vaultwarden, 1Password Connect, encrypted bundle; newest-wins merge; per-provider status in Settings |
| Haptics | Off/Subtle/Normal/Rich, ~25 mapped events, CoreHaptics bell, rate-limited, silent in the background |
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
* **Sync conflict resolution** is newest-wins per *snapshot*, not per record —
  see the Vault sync section. Simultaneous edits to the same host on two
  devices lose the older one.
* **Argon2id KDF** for Bitwarden accounts and for the encrypted bundle is
  stubbed behind a protocol with a clear error; PBKDF2 (which is what
  Vaultwarden's default is) is the shipped path. Wiring
  `tmthecoder/Argon2Swift` is a package addition away.
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
* **Sync deletions do not propagate.** A record removed on one device
  reappears from the other's copy; only additions and edits travel.

## Screenshots

Captured by `Tests/GhosttyUITests/ScreenshotTests.swift` driving the real app
on an iPhone 17 simulator.

| | |
|---|---|
| ![Hosts](docs/screenshots/01-hosts.png) | ![Identity](docs/screenshots/02-identity.png) |
| Hosts, grouped, with per-host accent colours | A key generated in-app, with its `authorized_keys` line |
| ![Terminal](docs/screenshots/03-terminal.png) | ![Key bar](docs/screenshots/04-terminal-keybar.png) |
| The demo terminal: real VT rendered by libghostty-vt — bold, italic, underline, strikethrough, inverse, truecolour | Key bar above the keyboard, 256-colour chart echoed locally |
| ![TOFU](docs/screenshots/05-tofu.png) | ![Console](docs/screenshots/06-console-ssh.png) |
| A real first connection to a LAN host. The fingerprint shown matches `ssh-keyscan 10.0.0.41 \| ssh-keygen -lf -` exactly. | The Console tab: `hosts` and `ssh`, resolved against the vault |
| ![Key bar](docs/screenshots/07-keybar.png) | ![Keyboard toggle](docs/screenshots/08-keyboard-toggle.png) |
| The reorganised key bar with Ctrl armed and the `Fn` row open | The floating keyboard button, shown when the bar is collapsed |
| ![Selection helper](docs/screenshots/09-selection-helper.png) | ![Sync](docs/screenshots/10-sync-settings.png) |
| Input/output bands and the selection chips | Sync providers in Settings |

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
│   ├── TerminalView/           UIKit CoreText grid, key bar, selection helper
│   ├── Console/                the app's own command line
│   ├── SSH/                    swift-nio-ssh client, TOFU, auth
│   ├── Vault/                  identities, hosts, known hosts, Keychain
│   ├── Sync/                   sync engine + iCloud/Bitwarden/1Password/bundle
│   ├── Haptics/                the haptics service
│   ├── Theme/                  colour schemes
│   └── App/                    SwiftUI screens
└── Tests/
    ├── GhosttyTests/           unit tests (VT, key encoding, vault, TOFU)
    └── GhosttyUITests/         drives the app, captures the screenshots
```

### Testing against a real Vaultwarden

The homelab runs Vaultwarden at `https://vault.lan` (health: `/alive`). Its
unauthenticated `POST /identity/accounts/prelogin` was used to confirm the
real-world shape of the KDF response used in the test fixtures. There is **no
account available to this repo**, so the Bitwarden crypto is tested against
published test vectors and recorded `prelogin` / `sync` fixtures rather than a
live login. Nothing in the test suite touches the network.
