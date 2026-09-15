import Foundation
import GhosttyVt

/// Keyboard modifiers, mapped onto libghostty-vt's bitmask.
struct VTMods: OptionSet, Hashable {
    let rawValue: UInt16

    init(rawValue: UInt16) { self.rawValue = rawValue }

    static let shift = VTMods(rawValue: UInt16(GHOSTTY_MODS_SHIFT))
    static let ctrl = VTMods(rawValue: UInt16(GHOSTTY_MODS_CTRL))
    static let alt = VTMods(rawValue: UInt16(GHOSTTY_MODS_ALT))
    static let command = VTMods(rawValue: UInt16(GHOSTTY_MODS_SUPER))
    static let capsLock = VTMods(rawValue: UInt16(GHOSTTY_MODS_CAPS_LOCK))
}

/// Encodes key events the way the far end expects them.
///
/// The encoding is not a fixed table: it depends on terminal state (DECCKM,
/// application keypad, the Kitty keyboard protocol flags a program has asked
/// for). `sync(from:)` copies that state out of the terminal, which is why
/// every keystroke path calls it before encoding — a program can enable the
/// Kitty protocol at any moment and the very next key must honour it.
final class VTKeyEncoder {
    private var encoder: GhosttyKeyEncoder
    /// One reusable event; the C API explicitly supports mutating and
    /// re-encoding the same event rather than allocating per keystroke.
    private var event: GhosttyKeyEvent

    init() throws {
        var encoder: GhosttyKeyEncoder?
        try VTError.check(ghostty_key_encoder_new(nil, &encoder), "ghostty_key_encoder_new")
        guard let encoder else { throw VTError.result(GHOSTTY_OUT_OF_MEMORY, "ghostty_key_encoder_new") }
        self.encoder = encoder

        var event: GhosttyKeyEvent?
        let result = ghostty_key_event_new(nil, &event)
        guard result == GHOSTTY_SUCCESS, let event else {
            ghostty_key_encoder_free(encoder)
            throw VTError.result(result, "ghostty_key_event_new")
        }
        self.event = event
    }

    deinit {
        ghostty_key_event_free(event)
        ghostty_key_encoder_free(encoder)
    }

    /// Pull DECCKM / keypad / Kitty-protocol state out of the terminal.
    func sync(from terminal: VTTerminal) {
        ghostty_key_encoder_setopt_from_terminal(encoder, terminal.handle)
    }

    /// Encode a key press. Returns nil when the key produces no bytes (a bare
    /// modifier, say), which is normal and not an error.
    func encode(
        key: GhosttyKey,
        mods: VTMods = [],
        action: GhosttyKeyAction = GHOSTTY_KEY_ACTION_PRESS,
        text: String? = nil,
        unshiftedCodepoint: UInt32? = nil
    ) -> Data? {
        ghostty_key_event_set_action(event, action)
        ghostty_key_event_set_key(event, key)
        ghostty_key_event_set_mods(event, mods.rawValue)
        ghostty_key_event_set_consumed_mods(event, 0)
        ghostty_key_event_set_composing(event, false)
        ghostty_key_event_set_unshifted_codepoint(event, unshiftedCodepoint ?? 0)

        // set_utf8 borrows the pointer, so the encode has to happen inside the
        // withCString scope. C0 controls and PUA function-key codes must not be
        // passed as text: the header is explicit that the encoder derives those
        // from the logical key instead.
        if let text, !text.isEmpty, text.unicodeScalars.allSatisfy({ !isControlOrPUA($0) }) {
            return text.withCString { cstr -> Data? in
                ghostty_key_event_set_utf8(event, cstr, strlen(cstr))
                defer { ghostty_key_event_set_utf8(event, nil, 0) }
                return runEncode()
            }
        }

        ghostty_key_event_set_utf8(event, nil, 0)
        return runEncode()
    }

    private func isControlOrPUA(_ scalar: Unicode.Scalar) -> Bool {
        let v = scalar.value
        return v < 0x20 || v == 0x7F || (v >= 0xF700 && v <= 0xF8FF)
    }

    private func runEncode() -> Data? {
        // Almost every sequence fits in 128 bytes; grow only if the library
        // says it needs more (it reports the required size in out_len).
        var buf = [CChar](repeating: 0, count: 128)
        var written = 0
        var result = buf.withUnsafeMutableBufferPointer { raw in
            ghostty_key_encoder_encode(encoder, event, raw.baseAddress, raw.count, &written)
        }
        if result == GHOSTTY_OUT_OF_SPACE {
            buf = [CChar](repeating: 0, count: written)
            result = buf.withUnsafeMutableBufferPointer { raw in
                ghostty_key_encoder_encode(encoder, event, raw.baseAddress, raw.count, &written)
            }
        }
        guard result == GHOSTTY_SUCCESS, written > 0 else { return nil }
        return buf.withUnsafeBufferPointer { raw in
            raw.baseAddress.map { Data(bytes: $0, count: written) }
        }
    }
}
