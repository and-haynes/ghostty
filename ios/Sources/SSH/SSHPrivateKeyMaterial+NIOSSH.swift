import Crypto
import NIOSSH

// The vault holds key material as `SSHPrivateKeyMaterial` (Sources/Vault) and
// knows nothing about NIO. This file is the single seam where that material is
// handed to swift-nio-ssh, which keeps the vault — and its tests — free of a
// NIO dependency. If you find yourself importing NIOSSH in Sources/Vault,
// add a mapping here instead.
//
// Note the `import Crypto`: swift-crypto re-exports CryptoKit on Apple
// platforms, so `P256.Signing.PrivateKey` here is the *same* type NIOSSH's
// initialisers expect. Importing CryptoKit directly would give us look-alike
// types that do not match NIOSSH's API.

extension SSHPrivateKeyMaterial {
    /// The NIOSSH representation of this key.
    ///
    /// Non-throwing on purpose: every case the vault can hold has a matching
    /// NIOSSH initialiser (Secure Enclave P-256 included, as of nio-ssh 0.15.0),
    /// so there is no failure mode to report. RSA is deliberately absent from
    /// `SSHPrivateKeyMaterial` because NIOSSH cannot sign with it at all — that
    /// gap is surfaced to the user as `SSHError.rsaKeysUnsupported` at import
    /// time rather than being silently swallowed here.
    var nioSSHPrivateKey: NIOSSHPrivateKey {
        switch self {
        case .ed25519(let key):
            return NIOSSHPrivateKey(ed25519Key: key)
        case .p256(let key):
            return NIOSSHPrivateKey(p256Key: key)
        case .p384(let key):
            return NIOSSHPrivateKey(p384Key: key)
        case .p521(let key):
            return NIOSSHPrivateKey(p521Key: key)
        case .secureEnclaveP256(let key):
            // The private half never leaves the Enclave; NIOSSH calls back into
            // it for each user-auth signature, which is why the key handle (not
            // raw bytes) is what we carry around.
            return NIOSSHPrivateKey(secureEnclaveP256Key: key)
        }
    }

    /// Wraps this key into the offer NIOSSH's user-auth delegate must produce.
    ///
    /// `serviceName` is accepted by the initialiser but ignored by NIOSSH — it
    /// always requests "ssh-connection" — so we pass the empty string that
    /// NIOSSH's own `SimplePasswordDelegate` uses.
    func authenticationOffer(username: String) -> NIOSSHUserAuthenticationOffer {
        NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: self.nioSSHPrivateKey))
        )
    }
}
