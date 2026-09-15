import Foundation
import NIOCore
import NIOSSH

// MARK: - Prompter

/// The UI's side of trust-on-first-use: shown the fingerprint of a host key we
/// have never seen, return whether the user accepts it.
///
/// Only ever asked about *unknown* hosts. A mismatch against a pinned key never
/// reaches here — `TOFUHostKeyDelegate` refuses those outright, because
/// offering an "accept anyway" button is how people click through a real
/// machine-in-the-middle.
protocol HostKeyPrompter: AnyObject, Sendable {
    func confirmUnknownHost(
        hostname: String,
        port: Int,
        keyType: String,
        fingerprint: String
    ) async -> Bool
}

// MARK: - Delegate

/// Bridges NIOSSH's promise-based host key callback to the async TOFU policy
/// that lives on `SSHSession` (and, behind it, the `Vault`).
///
/// NIOSSH calls `validateHostKey` on the connection's event loop and expects the
/// promise to be completed eventually — it is happy for that to take a while,
/// which is what makes an interactive "do you trust this key?" sheet possible.
/// `Sendable`: every stored property is a `let` holding a `Sendable` value, and
/// the object is handed to NIOSSH from the main actor but used on the loop.
final class TOFUHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, Sendable {
    /// Asked to rule on a presented key. Returns `.success` to let the
    /// handshake continue, `.failure` to abort it.
    ///
    /// Supplied by `SSHSession`, which owns the `Vault` and the prompter. It is
    /// `@Sendable` because it is invoked from a detached `Task`, not the loop.
    typealias Validator = @Sendable (
        _ keyType: String,
        _ fingerprint: String,
        _ publicKeyLine: String
    ) async -> Result<Void, SSHError>

    private let hostname: String
    private let port: Int
    private let validate: Validator
    /// Where a rejection is stashed so `SSHSession` can report *why* the
    /// handshake died: once we fail the promise, NIOSSH tears the connection
    /// down and every downstream future fails with a generic `ChannelError`,
    /// losing our specific message.
    private let failureRecorder: SSHFailureRecorder

    init(
        hostname: String,
        port: Int,
        failureRecorder: SSHFailureRecorder,
        validate: @escaping Validator
    ) {
        self.hostname = hostname
        self.port = port
        self.failureRecorder = failureRecorder
        self.validate = validate
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // "<algo> <base64>" — no comment field, because the key came off the
        // wire rather than out of a known_hosts file.
        let line = String(openSSHPublicKey: hostKey)

        guard let keyType = line.split(separator: " ", maxSplits: 1).first.map(String.init),
            !keyType.isEmpty
        else {
            let error = SSHError.connectionFailed(
                "The server sent a host key this app couldn't parse. Its SSH "
                    + "implementation may be too old or non-standard."
            )
            self.failureRecorder.record(error)
            validationCompletePromise.fail(error)
            return
        }

        guard let fingerprint = SSHFingerprint.sha256(publicKeyLine: line) else {
            let error = SSHError.connectionFailed(
                "The server's \(keyType) host key couldn't be fingerprinted, so "
                    + "it can't be verified."
            )
            self.failureRecorder.record(error)
            validationCompletePromise.fail(error)
            return
        }

        // Hop off the event loop to ask (the answer may involve a UI sheet and
        // a Keychain write), then hop the verdict back onto the loop that owns
        // the promise. Completing a promise from an arbitrary thread is a data
        // race; `eventLoop.execute` is how NIO says "run this on my thread".
        let loop = validationCompletePromise.futureResult.eventLoop
        let recorder = self.failureRecorder
        let validate = self.validate

        Task {
            let verdict = await validate(keyType, fingerprint, line)
            if case .failure(let error) = verdict {
                recorder.record(error)
            }
            loop.execute {
                switch verdict {
                case .success:
                    validationCompletePromise.succeed(())
                case .failure(let error):
                    // Failing here aborts the handshake *before* user auth, so
                    // no password and no public key is ever offered to a server
                    // we do not trust. That ordering is the whole point.
                    validationCompletePromise.fail(error)
                }
            }
        }
    }
}

// MARK: - Failure recorder

/// A one-shot, thread-safe box for the *first* meaningful error in a
/// connection attempt.
///
/// NIOSSH reports handshake failures by tearing the channel down, after which
/// every pending future fails with `ChannelError.eof` or
/// `NIOSSHError.creatingChannelAfterClosure`. Neither of those is something we
/// can show a person. The delegates therefore record the real reason here on
/// their way out, and `SSHSession` prefers it over whatever generic error it
/// catches.
///
/// `@unchecked Sendable` with an explicit lock: it is written from the event
/// loop and from detached tasks, and read from the main actor.
final class SSHFailureRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var error: SSHError?

    init() {}

    /// First writer wins — the first failure is the cause, anything after it is
    /// fallout from the teardown.
    func record(_ error: SSHError) {
        self.lock.lock()
        defer { self.lock.unlock() }
        if self.error == nil {
            self.error = error
        }
    }

    var recorded: SSHError? {
        self.lock.lock()
        defer { self.lock.unlock() }
        return self.error
    }
}
