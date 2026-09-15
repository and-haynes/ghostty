import Foundation
import GhosttyVt

/// Encodes pointer events for programs that turned on mouse tracking.
///
/// On a phone the "mouse" is a finger: a tap becomes press-then-release at a
/// cell, and a two-finger scroll becomes button 4/5 presses. Programs like vim
/// and less care, so this is worth wiring even though there is no cursor.
final class VTMouseEncoder {
    private var encoder: GhosttyMouseEncoder
    private var event: GhosttyMouseEvent

    init() throws {
        var encoder: GhosttyMouseEncoder?
        try VTError.check(ghostty_mouse_encoder_new(nil, &encoder), "ghostty_mouse_encoder_new")
        guard let encoder else { throw VTError.result(GHOSTTY_OUT_OF_MEMORY, "ghostty_mouse_encoder_new") }
        self.encoder = encoder

        var event: GhosttyMouseEvent?
        let result = ghostty_mouse_event_new(nil, &event)
        guard result == GHOSTTY_SUCCESS, let event else {
            ghostty_mouse_encoder_free(encoder)
            throw VTError.result(result, "ghostty_mouse_event_new")
        }
        self.event = event
    }

    deinit {
        ghostty_mouse_event_free(event)
        ghostty_mouse_encoder_free(encoder)
    }

    func sync(from terminal: VTTerminal) {
        ghostty_mouse_encoder_setopt_from_terminal(encoder, terminal.handle)
    }

    func reset() {
        ghostty_mouse_encoder_reset(encoder)
    }

    /// Encode one button event at a grid position (viewport coordinates).
    func encode(
        action: GhosttyMouseAction,
        button: GhosttyMouseButton,
        mods: VTMods,
        column: Int,
        row: Int,
        cellWidth: Double,
        cellHeight: Double
    ) -> Data? {
        ghostty_mouse_event_set_action(event, action)
        ghostty_mouse_event_set_button(event, button)
        ghostty_mouse_event_set_mods(event, mods.rawValue)

        // The encoder works in surface pixels and derives the cell itself, so
        // aim at the middle of the target cell to avoid off-by-one at edges.
        var position = GhosttyMousePosition()
        position.x = Float((Double(column) + 0.5) * cellWidth)
        position.y = Float((Double(row) + 0.5) * cellHeight)
        ghostty_mouse_event_set_position(event, position)

        var buf = [CChar](repeating: 0, count: 64)
        var written = 0
        let result = buf.withUnsafeMutableBufferPointer { raw in
            ghostty_mouse_encoder_encode(encoder, event, raw.baseAddress, raw.count, &written)
        }
        guard result == GHOSTTY_SUCCESS, written > 0 else { return nil }
        return buf.withUnsafeBufferPointer { raw in
            raw.baseAddress.map { Data(bytes: $0, count: written) }
        }
    }
}
