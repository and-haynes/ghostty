import Foundation
import NIOCore
import NIOSSH

/// The cipher suites this app offers, in preference order.
///
/// swift-nio-ssh's defaults are `aes128-gcm@openssh.com` and
/// `aes256-gcm@openssh.com` and nothing else. That is fine against a modern
/// OpenSSH and useless against everything else: a router, a NAS, a Dropbear
/// box or an older appliance typically offers AES-CTR with an HMAC and no GCM
/// at all, so there is no cipher in common and the handshake dies as
/// `NIOSSHError.keyExchangeNegotiationFailure` — the bare, unexplained failure
/// ticket #008A0 was opened about.
///
/// ## Order, and why it is this order
///
/// `SSHKeyExchangeStateMachine` builds the KEXINIT cipher list by mapping this
/// array to `cipherName` and the MAC list by mapping it to `macName`, so the
/// array's order *is* the client's stated preference for both. Hence:
///
/// 1. **GCM first.** It is AEAD, it is what NIOSSH has always used, and it is
///    the best thing on offer. Nothing about this change may make a connection
///    that worked yesterday negotiate something weaker.
/// 2. **Then AES-CTR, strongest key first,** paired with encrypt-then-MAC
///    before MAC-then-encrypt. `-etm` authenticates the ciphertext, so a forged
///    packet never reaches the cipher; the plain variants exist because plenty
///    of servers offer nothing else.
/// 3. **`hmac-sha2-256` before `hmac-sha2-512`** — see the key-derivation note
///    below. This is the one place where the *weaker-sounding* choice is the
///    correct one.
///
/// ## The 48-byte ceiling
///
/// swift-nio-ssh 0.15 derives session keys by truncating a **single**
/// key-exchange hash rather than running RFC 4253 §7.2's expansion loop, so it
/// can never produce more key material than that hash is long: 32 bytes under
/// `curve25519-sha256` and `ecdh-sha2-nistp256`, 48 under
/// `ecdh-sha2-nistp384`, 64 only under `ecdh-sha2-nistp521`. Asking for more
/// trips an `assert` inside the library in debug builds and yields a truncated
/// key in release ones.
///
/// NIOSSH's own key-exchange preference begins with `ecdh-sha2-nistp384`, so
/// against any ordinary server the ceiling is **48 bytes**. `hmac-sha2-512`
/// needs a 64-byte MAC key and `chacha20-poly1305@openssh.com` needs a 64-byte
/// cipher key; both are therefore only safe when the exchange is known in
/// advance to be `ecdh-sha2-nistp521`. `longKeySchemes` exists for exactly that
/// case and is only used once a probe of the server has confirmed it.
/// A `Sendable` wrapper for a list of transport protection *metatypes*.
///
/// `NIOSSHTransportProtection.Type` is not `Sendable` — metatypes of
/// non-`Sendable` protocols never are — but a list of them is immutable, has no
/// storage, and is only ever read. Without this box the array cannot cross into
/// a `ClientBootstrap.channelInitializer`, which is the one place it needs to go.
struct SSHTransportProtectionSchemes: @unchecked Sendable {
    let schemes: [NIOSSHTransportProtection.Type]

    init(_ schemes: [NIOSSHTransportProtection.Type]) {
        self.schemes = schemes
    }
}

enum SSHTransportProtectionCatalog {
    /// The schemes offered on every connection.
    ///
    /// Every entry's key material fits inside 48 bytes, so none of them can ask
    /// swift-nio-ssh for a key it cannot derive.
    static let clientSchemes: [NIOSSHTransportProtection.Type] = gcmSchemes + shortKeySchemes

    /// The GCM pair swift-nio-ssh ships, kept first so nothing regresses.
    static let gcmSchemes: [NIOSSHTransportProtection.Type] =
        Constants.bundledTransportProtectionSchemesForClients

    /// AES-CTR with HMAC-SHA2-256. 32-byte keys: derivable under every key
    /// exchange swift-nio-ssh implements.
    static let shortKeySchemes: [NIOSSHTransportProtection.Type] = [
        AESCTRTransportProtection<AES256CTRHMACSHA256ETM>.self,
        AESCTRTransportProtection<AES192CTRHMACSHA256ETM>.self,
        AESCTRTransportProtection<AES128CTRHMACSHA256ETM>.self,
        AESCTRTransportProtection<AES256CTRHMACSHA256>.self,
        AESCTRTransportProtection<AES192CTRHMACSHA256>.self,
        AESCTRTransportProtection<AES128CTRHMACSHA256>.self,
    ]

    /// AES-CTR with HMAC-SHA2-512. 64-byte MAC keys, so only offered when the
    /// key exchange is known to hash to 64 bytes.
    static let longKeySchemes: [NIOSSHTransportProtection.Type] = [
        AESCTRTransportProtection<AES256CTRHMACSHA512ETM>.self,
        AESCTRTransportProtection<AES192CTRHMACSHA512ETM>.self,
        AESCTRTransportProtection<AES128CTRHMACSHA512ETM>.self,
        AESCTRTransportProtection<AES256CTRHMACSHA512>.self,
        AESCTRTransportProtection<AES192CTRHMACSHA512>.self,
        AESCTRTransportProtection<AES128CTRHMACSHA512>.self,
    ]

    /// The schemes to offer a server whose key exchange will hash to
    /// `keyExchangeHashBytes` bytes.
    ///
    /// Call this only with a value derived from a real probe of the server's
    /// KEXINIT — guessing high is how a handshake negotiates a cipher whose key
    /// cannot be derived.
    static func schemes(keyExchangeHashBytes: Int) -> [NIOSSHTransportProtection.Type] {
        guard keyExchangeHashBytes >= 64 else { return Self.clientSchemes }
        return Self.clientSchemes + Self.longKeySchemes
    }

    // MARK: - What we can say we support

    /// Cipher names, de-duplicated, in preference order. For the mismatch
    /// explainer and the Test connection sheet.
    static func cipherNames(
        _ schemes: [NIOSSHTransportProtection.Type] = SSHTransportProtectionCatalog.clientSchemes
    ) -> [String] {
        Self.uniqued(schemes.map { $0.cipherName })
    }

    /// MAC names, de-duplicated, in preference order.
    static func macNames(
        _ schemes: [NIOSSHTransportProtection.Type] = SSHTransportProtectionCatalog.clientSchemes
    ) -> [String] {
        Self.uniqued(schemes.compactMap { $0.macName })
    }

    private static func uniqued(_ names: [String]) -> [String] {
        var seen = Set<String>()
        return names.filter { seen.insert($0).inserted }
    }
}

// MARK: - The library's own defaults

/// swift-nio-ssh keeps `Constants.bundledTransportProtectionSchemes` internal,
/// so the GCM pair has to be named rather than borrowed. Building a throwaway
/// `SSHClientConfiguration` to read them back would need delegates we do not
/// have here, and the names are stable API.
private enum Constants {
    static let bundledTransportProtectionSchemesForClients: [NIOSSHTransportProtection.Type] = {
        // Constructed via a configuration so that, if swift-nio-ssh ever
        // changes its defaults, we inherit the change instead of pinning a
        // stale pair.
        SSHClientConfiguration(
            userAuthDelegate: NoOpUserAuthDelegate(),
            serverAuthDelegate: NoOpServerAuthDelegate()
        ).transportProtectionSchemes
    }()
}

private struct NoOpUserAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: NIOCore.EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        nextChallengePromise.succeed(nil)
    }
}

private struct NoOpServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(
        hostKey: NIOSSHPublicKey,
        validationCompletePromise: NIOCore.EventLoopPromise<Void>
    ) {
        validationCompletePromise.succeed(())
    }
}
