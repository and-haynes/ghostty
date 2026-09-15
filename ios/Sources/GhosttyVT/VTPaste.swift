import Foundation
import GhosttyVt

/// Paste encoding.
///
/// Pasting into a terminal is not "write the string": a paste that contains a
/// newline runs whatever precedes it the moment it lands, and a paste that
/// contains the bracketed-paste terminator can break out of the brackets and
/// inject a command. libghostty-vt owns both rules, so the app asks it rather
/// than reimplementing them.
enum VTPaste {
    /// Whether `text` is safe to paste under the strict rule (no newlines, no
    /// ESC[201~). The UI warns before an unsafe paste.
    static func isSafe(_ text: String) -> Bool {
        let bytes = Array(text.utf8)
        return bytes.withUnsafeBufferPointer { raw in
            guard let base = raw.baseAddress else { return true }
            return base.withMemoryRebound(to: CChar.self, capacity: raw.count) { cstr in
                ghostty_paste_is_safe(cstr, raw.count)
            }
        }
    }

    /// Encode `text` for the far end: strips dangerous control bytes, wraps in
    /// ESC[200~ / ESC[201~ when the program has asked for bracketed paste,
    /// and turns newlines into carriage returns when it has not.
    static func encode(_ text: String, bracketed: Bool) -> Data? {
        // ghostty_paste_encode mutates the input in place, so hand it a copy.
        var input = Array(text.utf8).map { CChar(bitPattern: $0) }
        guard !input.isEmpty else { return nil }

        // The only growth is the bracketed-paste prefix and suffix (6 bytes
        // each), so size the output up front rather than doing a probing call
        // — probing would mutate the input buffer twice.
        var capacity = input.count + 16
        var written = 0
        var out = [CChar](repeating: 0, count: capacity)
        var result = input.withUnsafeMutableBufferPointer { src -> GhosttyResult in
            out.withUnsafeMutableBufferPointer { dst in
                ghostty_paste_encode(
                    src.baseAddress, src.count, bracketed,
                    dst.baseAddress, dst.count, &written
                )
            }
        }
        if result == GHOSTTY_OUT_OF_SPACE {
            capacity = written
            out = [CChar](repeating: 0, count: capacity)
            result = input.withUnsafeMutableBufferPointer { src -> GhosttyResult in
                out.withUnsafeMutableBufferPointer { dst in
                    ghostty_paste_encode(
                        src.baseAddress, src.count, bracketed,
                        dst.baseAddress, dst.count, &written
                    )
                }
            }
        }
        guard result == GHOSTTY_SUCCESS, written > 0 else { return nil }
        return out.withUnsafeBufferPointer { raw in
            raw.baseAddress.map { Data(bytes: $0, count: written) }
        }
    }
}
