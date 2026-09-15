import Foundation
import NIOCore
import NIOSSH

/// Offers an ordered list of authentication methods, one at a time, until one
/// is accepted or we run out.
///
/// NIOSSH drives this: after each failure the server tells us which methods it
/// is still willing to consider, and NIOSSH calls back here for the next offer.
/// The contract is "complete the promise" — succeed with an offer, succeed with
/// nil to give up quietly, or fail it to give up with a reason. We always fail
/// it, because a quiet `nil` produces a bare `NIOSSHError.authenticationFailed`
/// in the UI and a person cannot act on that.
///
/// Called on the connection's event loop, but constructed on the main actor, so
/// the mutable cursor is guarded by a lock rather than relying on loop
/// confinement.
/// `@unchecked Sendable`: constructed on the main actor, used on the event loop,
/// and its only mutable state is behind `lock`.
final class SSHUserAuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {
    private let username: String
    private let failureRecorder: SSHFailureRecorder
    /// Called (off the main actor) the first time the server asks us for
    /// credentials, so the UI can move to "Authenticating".
    private let onFirstAttempt: (@Sendable () -> Void)?

    private let lock = NSLock()
    private var methods: [SSHAuthMethod]
    /// Parallel to `methods`: true once an entry has been offered. Each method
    /// is offered at most once — re-offering a rejected password just burns
    /// through the server's `MaxAuthTries` and can lock the account out.
    private var consumed: [Bool]
    private var offeredAnything = false
    private var announcedAttempt = false
    /// Set when a configured credential turned out to be one the SSH library
    /// cannot use, so the give-up message can name it.
    private var unusableKeyType: String?

    init(
        username: String,
        methods: [SSHAuthMethod],
        failureRecorder: SSHFailureRecorder,
        onFirstAttempt: (@Sendable () -> Void)? = nil
    ) {
        self.username = username
        self.methods = methods
        self.consumed = Array(repeating: false, count: methods.count)
        self.failureRecorder = failureRecorder
        self.onFirstAttempt = onFirstAttempt
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        let announce: Bool = self.lock.withLockHeld {
            guard !self.announcedAttempt else { return false }
            self.announcedAttempt = true
            return true
        }
        if announce {
            self.onFirstAttempt?()
        }

        // NIOSSH builds `availableMethods` from the server's failure message and
        // silently drops methods it does not implement. An *empty* set therefore
        // means "the server named methods, and we understand none of them" —
        // which in practice is always keyboard-interactive. (The very first
        // callback is handed `.all`, so this can only be a real server reply.)
        if availableMethods.isEmpty {
            let error = SSHError.keyboardInteractiveUnsupported
            self.failureRecorder.record(error)
            nextChallengePromise.fail(error)
            return
        }

        let outcome: Outcome = self.lock.withLockHeld {
            self.nextOfferLocked(availableMethods: availableMethods)
        }

        switch outcome {
        case .offer(let offer):
            nextChallengePromise.succeed(offer)
        case .exhausted(let error):
            self.failureRecorder.record(error)
            nextChallengePromise.fail(error)
        }
    }

    // MARK: - Selection

    private enum Outcome {
        case offer(NIOSSHUserAuthenticationOffer)
        case exhausted(SSHError)
    }


    /// Must be called with `lock` held.
    private func nextOfferLocked(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods
    ) -> Outcome {
        var sawUnusable = false

        for index in self.methods.indices where !self.consumed[index] {
            let method = self.methods[index]
            guard Self.isUsable(method, given: availableMethods) else {
                // Not consumed: a `partialSuccess` can widen the acceptable set
                // later on, and then this entry becomes offerable again.
                sawUnusable = true
                continue
            }

            self.consumed[index] = true
            guard let offer = self.makeOffer(for: method) else {
                // The only way this happens is an RSA key, which the vault can
                // hold but swift-nio-ssh cannot sign with. Consume it and carry
                // on: a password on the same host should still get the user in.
                self.unusableKeyType = method.debugLabel
                continue
            }
            self.offeredAnything = true
            return .offer(offer)
        }

        // Nothing left to offer. Say which of the two situations it is.
        let serverMethods = Self.describe(availableMethods)

        if !self.offeredAnything {
            if let unusableKeyType = self.unusableKeyType {
                return .exhausted(
                    .authenticationFailed(
                        "The only credential configured for this host is an \(unusableKeyType), "
                            + "and the SSH library this app is built on cannot sign with RSA. "
                            + "Add an Ed25519 key, or turn on password authentication for the host."
                    )
                )
            }
            if sawUnusable {
                return .exhausted(
                    .authenticationFailed(
                        "This server accepts only \(serverMethods), and none of the "
                            + "credentials configured for it are of that kind. Attach a "
                            + "matching identity key or password to the host and try again."
                    )
                )
            }
            return .exhausted(.noAuthenticationMethods)
        }

        let tried = self.methods.map(\.debugLabel).joined(separator: ", ")
        return .exhausted(
            .authenticationFailed(
                "The server rejected every credential offered for \"\(self.username)\" "
                    + "(\(tried)). It will still accept \(serverMethods) — check the "
                    + "username, and that the key is in the account's authorized_keys."
            )
        )
    }

    /// nil when the credential cannot be turned into an offer at all — today
    /// that means only an RSA key.
    private func makeOffer(for method: SSHAuthMethod) -> NIOSSHUserAuthenticationOffer? {
        switch method {
        case .password(let password):
            return NIOSSHUserAuthenticationOffer(
                username: self.username,
                serviceName: "",
                offer: .password(.init(password: password))
            )
        case .privateKey(let material):
            return try? material.authenticationOffer(username: self.username)
        case .none:
            return NIOSSHUserAuthenticationOffer(
                username: self.username,
                serviceName: "",
                offer: .none
            )
        }
    }

    private static func isUsable(
        _ method: SSHAuthMethod,
        given available: NIOSSHAvailableUserAuthenticationMethods
    ) -> Bool {
        switch method {
        case .privateKey:
            return available.contains(.publicKey)
        case .password:
            return available.contains(.password)
        case .none:
            // "none" has no bit in the option set; it is always legal to try and
            // is how you ask a server what it wants.
            return true
        }
    }

    private static func describe(_ methods: NIOSSHAvailableUserAuthenticationMethods) -> String {
        var names: [String] = []
        if methods.contains(.publicKey) { names.append("public-key") }
        if methods.contains(.password) { names.append("password") }
        // NIOSSH cannot actually perform host-based auth, but naming it makes
        // the message honest about what the server asked for.
        if methods.contains(.hostBased) { names.append("host-based") }
        guard !names.isEmpty else { return "no authentication method this app supports" }
        if names.count == 1 { return "\(names[0]) authentication" }
        return names.dropLast().joined(separator: ", ") + " and " + (names.last ?? "")
            + " authentication"
    }
}

// MARK: - Lock helper

extension NSLock {
    /// Foundation gained `NSLock.withLock` in iOS 16, but overload resolution
    /// against it is a needless source of ambiguity. A distinctly named helper
    /// guarantees the unlock on every exit path with no such risk.
    fileprivate func withLockHeld<T>(_ body: () throws -> T) rethrows -> T {
        self.lock()
        defer { self.unlock() }
        return try body()
    }
}
