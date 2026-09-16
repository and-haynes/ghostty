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
    /// Throwing because the RSA case can: `NIOSSHPrivateKey(rsaKey:)` asks
    /// Security.framework to re-read the key and rejects one it cannot use.
    /// Every other case is a straight wrap.
    func nioSSHPrivateKey() throws -> NIOSSHPrivateKey {
        switch self {
        case .rsa(let key):
            // The fork signs with `rsa-sha2-512` by default. `ssh-rsa` (SHA-1)
            // is never offered — OpenSSH has refused it since 8.8 — so a key
            // only usable that way would fail here rather than downgrade.
            return try NIOSSHPrivateKey(rsaKey: key.secKey, signatureAlgorithm: .sha512)
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
    func authenticationOffer(username: String) throws -> NIOSSHUserAuthenticationOffer {
        NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: try self.nioSSHPrivateKey()))
        )
    }

    /// The same, offering a CA certificate over this key rather than the bare
    /// key.
    ///
    /// What changes on the wire is the public half: the server is sent the
    /// certificate — nonce, principals, validity, the CA's signature and all —
    /// instead of `ssh-ed25519 AAAA…`, and decides whether to trust it by
    /// checking the CA rather than by looking the key up in `authorized_keys`.
    /// The private key still produces the user auth signature, unchanged.
    func authenticationOffer(
        username: String,
        certificate: SSHCertificate
    ) throws -> NIOSSHUserAuthenticationOffer {
        NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(
                .init(privateKey: try self.nioSSHPrivateKey(), certifiedKey: certificate.certifiedKey)
            )
        )
    }
}
