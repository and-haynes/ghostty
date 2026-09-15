import UIKit

/// The row ranges the helper offers while a selection is being made.
///
/// Computed from OSC 133 prompt marks when the remote shell emits them, and
/// from the cursor position when it does not — a suggestion that is sometimes
/// approximate is far more useful than one that only appears on shells with
/// integration configured.
struct SelectionSuggestion: Equatable {
    /// The command line being edited (or the cursor row without marks).
    var inputRows: ClosedRange<Int>?
    /// The previous command's output.
    var outputRows: ClosedRange<Int>?
    /// True when the ranges came from real prompt marks.
    var fromShellIntegration: Bool

    var bothRows: ClosedRange<Int>? {
        switch (inputRows, outputRows) {
        case let (input?, output?):
            return min(input.lowerBound, output.lowerBound)...max(input.upperBound, output.upperBound)
        case let (input?, nil): return input
        case let (nil, output?): return output
        default: return nil
        }
    }

    var isEmpty: Bool { inputRows == nil && outputRows == nil }

    /// Derive a suggestion from a rendered frame.
    static func derive(lines: [VTRow], cursorRow: Int?) -> SelectionSuggestion {
        guard !lines.isEmpty else {
            return SelectionSuggestion(inputRows: nil, outputRows: nil, fromShellIntegration: false)
        }
        let cursor = min(max(0, cursorRow ?? lines.count - 1), lines.count - 1)
        let promptRows = lines.indices.filter { lines[$0].semanticPrompt == .prompt }

        guard let currentPrompt = promptRows.last(where: { $0 <= cursor }) else {
            // No marks (or none above the cursor): the cursor row is the
            // command line, and everything above it in the viewport is the
            // output you most likely want.
            let input = cursor...cursor
            let output = cursor > 0 ? 0...(cursor - 1) : nil
            return SelectionSuggestion(inputRows: input, outputRows: output, fromShellIntegration: false)
        }

        // Input runs from the prompt row through any continuation lines to the
        // cursor — a multi-line command is one input, not several.
        let input = currentPrompt...max(currentPrompt, cursor)

        // Output is what sits between the previous command line and this one.
        let previousPrompt = promptRows.last { $0 < currentPrompt }
        let outputStart = previousPrompt.map { start -> Int in
            var row = start
            while row + 1 < lines.count, lines[row + 1].semanticPrompt == .promptContinuation {
                row += 1
            }
            return row + 1
        } ?? 0
        let outputEnd = currentPrompt - 1
        let output = outputStart <= outputEnd ? outputStart...outputEnd : nil

        return SelectionSuggestion(inputRows: input, outputRows: output, fromShellIntegration: true)
    }
}

/// Which suggestion a chip stands for.
enum SelectionChip: CaseIterable {
    case input, output, both

    var title: String {
        switch self {
        case .input: return "Input"
        case .output: return "Output"
        case .both: return "Both"
        }
    }

    var systemImage: String {
        switch self {
        case .input: return "chevron.right"
        case .output: return "text.alignleft"
        case .both: return "square.stack"
        }
    }
}

/// Three floating chips offering the suggested selections.
///
/// Deliberately a sibling view rather than a gesture: it must never take a
/// touch away from the drag that is still in progress. A finger already owned
/// by the long-press recogniser stays owned by it; only a *new* tap lands on a
/// chip.
@MainActor
final class SelectionChipBar: UIView {
    var onSelect: ((SelectionChip) -> Void)?

    private let stack = UIStackView()
    private var buttons: [SelectionChip: UIButton] = [:]

    override init(frame: CGRect) {
        super.init(frame: frame)
        stack.axis = .horizontal
        stack.spacing = 6
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor),
            stack.trailingAnchor.constraint(equalTo: trailingAnchor),
            stack.topAnchor.constraint(equalTo: topAnchor),
            stack.bottomAnchor.constraint(equalTo: bottomAnchor),
        ])

        for chip in SelectionChip.allCases {
            var config = UIButton.Configuration.filled()
            config.title = chip.title
            config.image = UIImage(systemName: chip.systemImage)
            config.imagePadding = 4
            config.cornerStyle = .capsule
            config.buttonSize = .small
            config.baseBackgroundColor = UIColor.tintColor.withAlphaComponent(0.9)
            config.baseForegroundColor = .black
            let button = UIButton(configuration: config)
            button.accessibilityLabel = "Select \(chip.title.lowercased())"
            button.addAction(UIAction { [weak self] _ in
                self?.onSelect?(chip)
            }, for: .touchUpInside)
            stack.addArrangedSubview(button)
            buttons[chip] = button
        }

        alpha = 0
        isHidden = true
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { nil }

    /// Hide chips that have nothing to offer rather than showing a dead button.
    func configure(for suggestion: SelectionSuggestion) {
        buttons[.input]?.isHidden = suggestion.inputRows == nil
        buttons[.output]?.isHidden = suggestion.outputRows == nil
        buttons[.both]?.isHidden = suggestion.inputRows == nil || suggestion.outputRows == nil
    }

    func setVisible(_ visible: Bool) {
        guard isHidden == visible else { return }
        if visible { isHidden = false }
        UIView.animate(withDuration: 0.18, delay: 0, options: [.beginFromCurrentState]) {
            self.alpha = visible ? 1 : 0
        } completion: { _ in
            if !visible { self.isHidden = true }
        }
    }
}
