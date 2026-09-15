import XCTest
import Crypto
@testable import Ghostty

// MARK: - Shared fixtures
//
// Nothing in this file touches the network. Every HTTP exchange is a recorded
// response replayed through `StubBitwardenTransport`, and every ciphertext was
// produced outside Swift (openssl + Python) so the parser is pinned against an
// independent implementation rather than against itself.

enum BitwardenFixtures {
    // MARK: Published KDF test vector
    //
    // Bitwarden's long-standing published vector: email "test@bitwarden.com",
    // master password "test", PBKDF2-SHA256 at 100 000 iterations.
    //
    // The expected values below were NOT copied from a blog post. They were
    // computed three independent ways before being written down, and all three
    // agreed:
    //
    //   1. python3 hashlib.pbkdf2_hmac('sha256', b"test", b"test@bitwarden.com", 100000, 32)
    //   2. a hand-written PBKDF2 loop over hmac/sha256 (no library PBKDF2 at all)
    //   3. openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:test \
    //        -kdfopt salt:test@bitwarden.com -kdfopt iter:100000 -binary PBKDF2
    //
    // The stretched halves were likewise cross-checked against
    //   openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt mode:EXPAND_ONLY \
    //     -kdfopt hexkey:<master key> -kdfopt hexinfo:656e63 -binary HKDF
    static let vectorEmail = "test@bitwarden.com"
    static let vectorPassword = "test"
    static let vectorIterations = 100_000
    static let vectorMasterKey = "/0MLlY7udF3gHWTpZe2wtu7VN/LRt33RbthSJI8zjko="
    static let vectorMasterPasswordHash = "/fLMc6m0bwpU1bYko8NY/gl/+SaxfSGGQc6arJoDOaE="
    static let vectorStretchedEnc = "izSR78Rp39xUN48fZKkx9DV7f+i5z2AYCYyRJCAE8ms="
    static let vectorStretchedMac = "hdcV8uLHaJyTtTBUKw7ZtZKuk+LbcAWzZIa1EdmiWPs="

    /// The 64-byte user key every cipher fixture below is encrypted with.
    static let userKeyBase64 =
        "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dzj6vH4/wYNFBsiKTA3PkVMU1phaG92fYSLkpmgp661vA=="

    static func userKey() throws -> BitwardenSymmetricKey {
        let data = try XCTUnwrap(Data(base64Encoded: userKeyBase64))
        return try BitwardenSymmetricKey(concatenated: data)
    }

    // MARK: Recorded EncString
    //
    // Produced entirely outside this codebase so it pins the parser rather than
    // merely proving it is self-consistent:
    //
    //   iv  = 000102030405060708090a0b0c0d0e0f
    //   key = stretched master key of the published vector above
    //   ct  = openssl enc -aes-256-cbc -K <enc half> -iv <iv>
    //   mac = HMAC-SHA256(<mac half>, iv || ct)
    static let recordedPlaintext = "ghostty-encstring-fixture-v1"
    static let recordedEncString =
        "2.AAECAwQFBgcICQoLDA0ODw==|jTy7gpypFURKBlYUcqNcVmyyv75FJVem2Nyjk6BpYKU=|"
        + "yHl5XIMSOJRsTrkw57LOESNsklwC2J1ehqYgJoR6/5g="

    // MARK: Keys inside the recorded vault

    static let identityUUID = UUID(uuidString: "6B4E3A1C-0D2F-4A8B-9C7E-1F2A3B4C5D6E")
    static let hostUUID = UUID(uuidString: "A1B2C3D4-E5F6-4A7B-8C9D-0E1F2A3B4C5D")
    static let fingerprint1 = "SHA256:xAzE1W2AOZP5vzeRZ0heDQkKbO7VSiSpmDW2H53U1uY"
    static let fingerprint2 = "SHA256:rpAM+zaj3HQPpza2naIcrO4n18lBDGLr3/m4X+UmYt0"

    static let publicKeyLine1 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL7GCJ1c+CCvgkpL4974gAR4DJ9GkWWQZK8ccCl7OLXg andy@sagan"
    static let publicKeyLine2 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOonr7aj01Z8HJxqFBKXeRytD5oHYZ+PvU721qRFKnJv andy@faraday"

    static let privateKeyPEM1 = #"""
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC+xgidXPggr4JKS+Pe+IAEeAyfRpFlkGSvHHApezi14AAAAJDnXPoU51z6
FAAAAAtzc2gtZWQyNTUxOQAAACC+xgidXPggr4JKS+Pe+IAEeAyfRpFlkGSvHHApezi14A
AAAECTzSrXFwOWkQPLOnVI22ZhpkdjlsAvIlOZKpx4ypdJmL7GCJ1c+CCvgkpL4974gAR4
DJ9GkWWQZK8ccCl7OLXgAAAACmFuZHlAc2FnYW4BAgM=
-----END OPENSSH PRIVATE KEY-----
"""#
        + "\n"

    static let privateKeyPEM2 = #"""
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDqJ6+2o9NWfBycahQSl3kcrQ+aB2Gfj71O9takRSpybwAAAJApUI6qKVCO
qgAAAAtzc2gtZWQyNTUxOQAAACDqJ6+2o9NWfBycahQSl3kcrQ+aB2Gfj71O9takRSpybw
AAAEAhdGNZkwiQBJhxIEknAW8kAr4qoiBQfFTj+jgMS7fheeonr7aj01Z8HJxqFBKXeRyt
D5oHYZ+PvU721qRFKnJvAAAADGFuZHlAZmFyYWRheQE=
-----END OPENSSH PRIVATE KEY-----
"""#
        + "\n"

    // MARK: Recorded HTTP bodies

    /// Live, unauthenticated response from the homelab's Vaultwarden 2026.6.0
    /// at https://vault.lan — copied verbatim, including the nulls.
    static let preloginJSON = #"""
    {"kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null}
    """#

    /// Same shape, Argon2id account, for the KDF-mapping test.
    static let preloginArgon2JSON = #"""
    {"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4}
    """#

    static let tokenJSON = #"""
{
  "access_token": "fixture-access-token",
  "expires_in": 3600,
  "token_type": "Bearer",
  "refresh_token": "fixture-refresh-token",
  "scope": "api offline_access",
  "Key": "2.oKGio6SlpqeoqaqrrK2urw==|Cfjw2Zd8yCcwooLZlL8Vbt5EMJDhqsu4bKxcnWqehgJMMiAlau+EoJkPMxI7cLHXpa6u1Vj38j5cWFjrkQPsO9eYFPYlgPntKRffM8gU1X8=|aGjOYrhPYeQETqJ2QeZdHKW2DGy0bG0HZtJcZyiz4i4=",
  "PrivateKey": null,
  "Kdf": 0,
  "KdfIterations": 600000,
  "KdfMemory": null,
  "KdfParallelism": null,
  "ResetMasterPassword": false,
  "ForcePasswordReset": false
}
"""#

    /// One type-5 SSH key, one type-2 secure note named "Ghostty iOS hosts",
    /// and one type-1 login that must be ignored.
    static let syncJSON = #"""
{
  "object": "sync",
  "profile": {
    "object": "profile",
    "id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    "email": "test@bitwarden.com",
    "name": "Andy",
    "key": "2.oKGio6SlpqeoqaqrrK2urw==|Cfjw2Zd8yCcwooLZlL8Vbt5EMJDhqsu4bKxcnWqehgJMMiAlau+EoJkPMxI7cLHXpa6u1Vj38j5cWFjrkQPsO9eYFPYlgPntKRffM8gU1X8=|aGjOYrhPYeQETqJ2QeZdHKW2DGy0bG0HZtJcZyiz4i4=",
    "organizations": []
  },
  "folders": [],
  "collections": [],
  "policies": [],
  "sends": [],
  "ciphers": [
    {
      "object": "cipherDetails",
      "id": "11111111-2222-3333-4444-555555555555",
      "organizationId": null,
      "folderId": null,
      "type": 5,
      "name": "2.a6KVgEHDJDUaq1/J1ZocHw==|4GW7guCHjhNWIl8D7gFrgg==|rBniR1D9PO1uVJvbv7OM1sB5CYQtPe47VjJczI2Wwyg=",
      "notes": "2.1FvGPleKa4sG65Oy7h5NCw==|x0jivfoqwH2udz/Ws5AWUatRdXjEvCAs8KkhFtH9PqDRquMs3d0AKvwTfAh/wBhEbipxYzy4KWCPqa/HKpmBhn1xEmVOTPyvPO+IwR9mNtPjVFDT6SIvIpA4RTlmHXhSpwUd1VQy3gDIe7d6nvNNyM/DBEXw01jV4G3lh/xt1znvLW00NY23PvcrMGibig0tJdKBpiZMqdjkQ+WgT4VyJCnb2lqVlvgExB8ZkHK5jzhf+lsYSCm3qwbMUvormWSrP2mCw4/mbbO08Y6UqesRDw==|rAonTr1pZSy+fIkhX/A4XnQ8JBoa64tMgMNESyv2HFc=",
      "favorite": false,
      "reprompt": 0,
      "sshKey": {
        "privateKey": "2.iviARF8zS7pn8vU/h/mYzg==|zMVPO6KSKHC+GlkCcTDx94PNIwmUVcK+la52UGJGNUI5rRUP0b/BzcnqYLAy+OtKMc5KjCaCRBoubIgvciBMIMBU+82Wa4FTfsL51Z7VXNsSKY1eMSvJ2rcV2rlQbjN0mGYDv3Fs10cbOsBB/668/JiP5Guj2ILnWxkUPVuPkSYHsTVCFjxD22a+0qmUIJ42uS6wna1RrXIGQbMoNowVAZI3gZm+U3ULrdqj3l6mk0JthCmHrcsOqQLoU1Z/hKgJdGEj7pONGhpY2Doo2JONCM8VJzzvOiLAQSW7IoLzbl1tj8qt7xmkgL429Dzl6QGKfR5kQEvvJHF3ClHRE2HKn6dSRvCWqW2lYW2VFHIrLgLOxH/J0T69w0bzjASJJguNFYtH+cPOkvMecv2xIJxpL7mFXcwprswsOxNhMMl3/LSFQIa0LudTI4k96ZV6/EjCGmfgzfRpW/JJBRcFXTAEY9VquAdpOt8LA43fJwK75Ma5rHfQp+1GX6c6AqknIZmbH/blscQhWPmWBCTuGL22Xw==|2FDW2Ha81/2o/wfPJvjPGsHSHc+W62E1LGPwmaJBss4=",
        "publicKey": "2.sSkQZSFVE9YR5J7VnDe1ew==|XL+RxHaKicc63lYLl5eWzPGaEG8hCmwtpnguTFK+tk74bpHaz7tluxV4yv4Ewhh81P3c4vmuL7pfK/1ntWzpS+uf+I6bjf4+Wn1eH7cZOlhn/aUP4dsMDGj/0Fs0bbtv|MuHBZQS59bPamEUPogogG5lxC/oUITiOUav9P/DVWkc=",
        "keyFingerprint": "2.jA8RGWLkC5Rsiqp9V7mrUw==|LQKZJ2u6McEpsivf3hUWY43iXn3lqAv+nyD9jULhXtbNrJxaiICuIVsyGKKJvAOSYSBfUf1eOKgFTo5ibWqZqw==|cf+yBNzn/Vd1Pidumrp8J+7h+08NGAGN6/i9WsGXXYc="
      },
      "revisionDate": "2026-09-14T12:00:00.0000000Z",
      "deletedDate": null
    },
    {
      "object": "cipherDetails",
      "id": "66666666-7777-8888-9999-aaaaaaaaaaaa",
      "organizationId": null,
      "folderId": null,
      "type": 2,
      "name": "2.U8oxkX76BQ9o8aYAnZspsw==|ar4N5SUtfrCz3DiiGBfi99KB1W4OIvvcnKgNR/H3750=|C+ghPFvXfuCh1gwuf1gUnHCE/c/E9Rslx3lOoxeWqak=",
      "notes": "2.Feq3d0bxFfIdPMYwKAc2Jw==|m7VI/5/7xYzZ83wH5or4jwbzoL+iJgNHAuQqUJ/aXS7F9YisEra7rsgM4Yd35YgEFcBR4I5JnRuBdIpT7YCknri7iRhLyIWydi2XfWfstoY/9RkSwpgwTp2TjryXQhXs6Ao3AvHjcyB31Jg3m1gqTkNzRrt5VyNa+UFFexbvO98pWEa8pziSjS7KEEeFquGw/MeqocvzOFV7lJdpYvksPUt28cAuY4mLnrAxpGAP7mHR5JP41qde8RNjjzJYfqlnWBO0ewAAxufDd1UxT4oVNNalVp9x/nCRkmQ3alsWMWCu3cH0pYd9GUKu9JDSya78pUNAkxRYR0ydv84LgGWeFMKZV1dG/QJAXkdGRGjSedqXTnM6VuHEl8MsdWfFaQ+e7bUqeri19MPnThWcNMa7E7OTJ9NJePKJu+3gCSh7XsRtXffOLoVitmrxDngVFQos7jeEcnFiJgqP35/ZoSxOXP/bc0adsTnwWfYbrsMxArfgJkMbsTWrhnB9gg8c2C9R5epkVOvAWm9JH/uJjwhuuyMIimRRhgvcf62OReuZ0el2JBdm5gZRTmhLn3S/6JI/gP8CQeavjtleoRVECQ67+fw/NP0laTCiHMIL0FAVJEpJQfADUAmIYYknpImDbCnTeK6Gw/Uyb6/9Qk9iYEEWwgAn6rfdWLPfq2axXC2CJVPljYs1YHLwUqqKpOLi69qIZ2wQI4LIJ9jyxgW4ykzgBYVfm0hJcYQaaT2uHYNGXVm7CkBhQSMKCcWK1ILqkxc9zrxjmAQTKngsRsYmGcHPVqFfahigbPSFWW/9GE02A23091TKWsJK0OJCk5ts8EvqcLKh5h9ee41YgNQSg3FvhA==|qvRu5NLArvvSPxRFxvl35FF4ymz7AXTC851BBDazOwA=",
      "favorite": false,
      "reprompt": 0,
      "secureNote": {
        "type": 0
      },
      "revisionDate": "2026-09-14T12:05:00.0000000Z",
      "deletedDate": null
    },
    {
      "object": "cipherDetails",
      "id": "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
      "organizationId": null,
      "folderId": null,
      "type": 1,
      "name": "2.Lo4Y5xIUgjcDDqghEl5p5A==|FqB4OSxIefRjHLKkqkRHVQ==|NBRzf0wE4/je3w6icDSOID4zf6lWkAunUFkZPPGlS6U=",
      "notes": null,
      "favorite": false,
      "reprompt": 0,
      "login": {
        "username": "2.Swkt3ChbIcOlyHtIgVcLXg==|EknVA00cr5vtUuxfVKkcqw==|03pw5Trbl8BDIUcUjDWEvXkwuh6yOYNusuYuhsR5wrw=",
        "password": "2.AwzIWi67VKcC4YAAaOHRew==|8t9H6xnDUuGWZScPGcTafw==|LxGeZI3PYRY7CU6Jm2Tymm11YiBetNv6HK3zZ5alzHI=",
        "uris": [],
        "totp": null
      },
      "revisionDate": "2026-09-10T09:00:00.0000000Z",
      "deletedDate": null
    }
  ]
}
"""#

    /// A vault whose only SSH key was made in the Bitwarden app: no Ghostty
    /// metadata in `notes`, so it is not ours to delete.
    static let syncForeignKeyJSON = #"""
{
  "object": "sync",
  "profile": {
    "object": "profile",
    "id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    "email": "test@bitwarden.com",
    "name": "Andy",
    "key": "2.oKGio6SlpqeoqaqrrK2urw==|Cfjw2Zd8yCcwooLZlL8Vbt5EMJDhqsu4bKxcnWqehgJMMiAlau+EoJkPMxI7cLHXpa6u1Vj38j5cWFjrkQPsO9eYFPYlgPntKRffM8gU1X8=|aGjOYrhPYeQETqJ2QeZdHKW2DGy0bG0HZtJcZyiz4i4=",
    "organizations": []
  },
  "folders": [],
  "collections": [],
  "ciphers": [
    {
      "object": "cipherDetails",
      "id": "cccccccc-dddd-eeee-ffff-000000000000",
      "organizationId": null,
      "folderId": null,
      "type": 5,
      "name": "2.RdQvX9nL7hmgvXYK2vRdxg==|EoNhXyQCOOwZPRnxCSsCcCVUYGHUOXJCqh+EuKRV9U0=|4VPvItaAWIpxWXFRhMtwNHxpzTdpOiikst5SThHiv5c=",
      "notes": null,
      "favorite": false,
      "reprompt": 0,
      "sshKey": {
        "privateKey": "2.iviARF8zS7pn8vU/h/mYzg==|zMVPO6KSKHC+GlkCcTDx94PNIwmUVcK+la52UGJGNUI5rRUP0b/BzcnqYLAy+OtKMc5KjCaCRBoubIgvciBMIMBU+82Wa4FTfsL51Z7VXNsSKY1eMSvJ2rcV2rlQbjN0mGYDv3Fs10cbOsBB/668/JiP5Guj2ILnWxkUPVuPkSYHsTVCFjxD22a+0qmUIJ42uS6wna1RrXIGQbMoNowVAZI3gZm+U3ULrdqj3l6mk0JthCmHrcsOqQLoU1Z/hKgJdGEj7pONGhpY2Doo2JONCM8VJzzvOiLAQSW7IoLzbl1tj8qt7xmkgL429Dzl6QGKfR5kQEvvJHF3ClHRE2HKn6dSRvCWqW2lYW2VFHIrLgLOxH/J0T69w0bzjASJJguNFYtH+cPOkvMecv2xIJxpL7mFXcwprswsOxNhMMl3/LSFQIa0LudTI4k96ZV6/EjCGmfgzfRpW/JJBRcFXTAEY9VquAdpOt8LA43fJwK75Ma5rHfQp+1GX6c6AqknIZmbH/blscQhWPmWBCTuGL22Xw==|2FDW2Ha81/2o/wfPJvjPGsHSHc+W62E1LGPwmaJBss4=",
        "publicKey": "2.sSkQZSFVE9YR5J7VnDe1ew==|XL+RxHaKicc63lYLl5eWzPGaEG8hCmwtpnguTFK+tk74bpHaz7tluxV4yv4Ewhh81P3c4vmuL7pfK/1ntWzpS+uf+I6bjf4+Wn1eH7cZOlhn/aUP4dsMDGj/0Fs0bbtv|MuHBZQS59bPamEUPogogG5lxC/oUITiOUav9P/DVWkc=",
        "keyFingerprint": "2.jA8RGWLkC5Rsiqp9V7mrUw==|LQKZJ2u6McEpsivf3hUWY43iXn3lqAv+nyD9jULhXtbNrJxaiICuIVsyGKKJvAOSYSBfUf1eOKgFTo5ibWqZqw==|cf+yBNzn/Vd1Pidumrp8J+7h+08NGAGN6/i9WsGXXYc="
      },
      "revisionDate": "2026-08-01T00:00:00.0000000Z",
      "deletedDate": null
    }
  ]
}
"""#

    static let syncEmptyJSON = #"""
{
  "object": "sync",
  "profile": {
    "object": "profile",
    "id": "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0",
    "email": "test@bitwarden.com",
    "name": "Andy",
    "key": "2.oKGio6SlpqeoqaqrrK2urw==|Cfjw2Zd8yCcwooLZlL8Vbt5EMJDhqsu4bKxcnWqehgJMMiAlau+EoJkPMxI7cLHXpa6u1Vj38j5cWFjrkQPsO9eYFPYlgPntKRffM8gU1X8=|aGjOYrhPYeQETqJ2QeZdHKW2DGy0bG0HZtJcZyiz4i4=",
    "organizations": []
  },
  "folders": [],
  "collections": [],
  "ciphers": []
}
"""#

    static let twoFactorJSON = #"""
    {"error":"invalid_grant","error_description":"Two factor required.",
     "TwoFactorProviders":["0"],"TwoFactorProviders2":{"0":null}}
    """#
}

// MARK: - Stub transport

/// Replays recorded responses and records what was asked for.
///
/// Deliberately not a `URLProtocol` subclass: that would still route through
/// `URLSession`, and a test that can reach the network is a test that will,
/// one day, reach the network.
final class StubBitwardenTransport: BitwardenTransport {
    struct Exchange {
        var method: String
        var path: String
        var body: Data?
    }

    private(set) var exchanges: [Exchange] = []
    /// Set to fail the test if any request is made at all.
    var refusesAllRequests = false

    private let route: (Exchange) throws -> (status: Int, body: Data)

    init(route: @escaping (Exchange) throws -> (status: Int, body: Data)) {
        self.route = route
    }

    /// The common case: a vault that answers prelogin, token, sync, and echoes
    /// cipher writes back with a server-assigned id.
    static func vault(
        prelogin: String = BitwardenFixtures.preloginJSON,
        token: String = BitwardenFixtures.tokenJSON,
        sync: String = BitwardenFixtures.syncJSON,
        tokenStatus: Int = 200
    ) -> StubBitwardenTransport {
        StubBitwardenTransport { exchange in
            if exchange.path.hasSuffix("/identity/accounts/prelogin") {
                return (200, Data(prelogin.utf8))
            }
            if exchange.path.hasSuffix("/identity/connect/token") {
                return (tokenStatus, Data(token.utf8))
            }
            if exchange.path.hasSuffix("/api/sync") {
                return (200, Data(sync.utf8))
            }
            if exchange.path.contains("/api/ciphers") {
                if exchange.method == "DELETE" { return (200, Data("{}".utf8)) }
                // Echo the written cipher back the way the server does, with an
                // id the client could then reuse.
                var echoed: [String: Any] = ["object": "cipherDetails", "id": "server-assigned"]
                if let body = exchange.body,
                   let parsed = try? JSONSerialization.jsonObject(with: body) as? [String: Any] {
                    echoed["type"] = parsed["type"]
                    echoed["name"] = parsed["name"]
                    echoed["notes"] = parsed["notes"]
                }
                if echoed["type"] == nil { echoed["type"] = 5 }
                let data = try JSONSerialization.data(withJSONObject: echoed)
                return (200, data)
            }
            throw VaultSyncError.badResponse("No stub route for \(exchange.method) \(exchange.path)")
        }
    }

    func send(_ request: URLRequest) async throws -> (data: Data, response: HTTPURLResponse) {
        guard !refusesAllRequests else {
            throw VaultSyncError.server("This test must not perform any request.")
        }
        let exchange = Exchange(
            method: request.httpMethod ?? "GET",
            path: request.url?.path ?? "",
            body: request.httpBody
        )
        exchanges.append(exchange)

        let (status, body) = try route(exchange)
        guard let url = request.url,
              let response = HTTPURLResponse(
                url: url,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
              )
        else {
            throw VaultSyncError.badResponse("Could not build a stub HTTP response.")
        }
        return (body, response)
    }

    // MARK: Introspection

    func writes(to pathFragment: String) -> [Exchange] {
        exchanges.filter { $0.method != "GET" && $0.path.contains(pathFragment) }
    }

    var cipherWrites: [Exchange] {
        exchanges.filter { $0.path.contains("/api/ciphers") && ($0.method == "POST" || $0.method == "PUT") }
    }

    var cipherDeletes: [Exchange] {
        exchanges.filter { $0.path.contains("/api/ciphers") && $0.method == "DELETE" }
    }
}

/// Records what the Argon2 seam is handed, so the salt rule can be asserted
/// without an Argon2 implementation being present.
final class RecordingArgon2: Argon2Hashing {
    var salt: Data?
    var iterations: Int?
    var memoryKiB: Int?
    var parallelism: Int?
    var outputByteCount: Int?

    func hash(
        password: Data,
        salt: Data,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        outputByteCount: Int
    ) throws -> Data {
        self.salt = salt
        self.iterations = iterations
        self.memoryKiB = memoryKiB
        self.parallelism = parallelism
        self.outputByteCount = outputByteCount
        return Data(repeating: 0x42, count: outputByteCount)
    }
}

// MARK: - Crypto

final class BitwardenCryptoTests: XCTestCase {
    func testMasterKeyMatchesPublishedVector() throws {
        let key = try BitwardenCrypto.masterKey(
            password: BitwardenFixtures.vectorPassword,
            email: BitwardenFixtures.vectorEmail,
            kdf: .pbkdf2(iterations: BitwardenFixtures.vectorIterations)
        )
        XCTAssertEqual(key.rawData.base64EncodedString(), BitwardenFixtures.vectorMasterKey)
        XCTAssertEqual(key.rawData.count, 32)
    }

    func testMasterPasswordHashMatchesPublishedVector() throws {
        let key = try BitwardenCrypto.masterKey(
            password: BitwardenFixtures.vectorPassword,
            email: BitwardenFixtures.vectorEmail,
            kdf: .pbkdf2(iterations: BitwardenFixtures.vectorIterations)
        )
        let hash = try BitwardenCrypto.masterPasswordHash(
            masterKey: key,
            password: BitwardenFixtures.vectorPassword
        )
        XCTAssertEqual(hash, BitwardenFixtures.vectorMasterPasswordHash)
        // The hash must not be the master key itself — that would hand the
        // vault's root secret to the server.
        XCTAssertNotEqual(hash, BitwardenFixtures.vectorMasterKey)
    }

    func testEmailSaltIsTrimmedAndLowercased() throws {
        let canonical = try BitwardenCrypto.masterKey(
            password: "test",
            email: "test@bitwarden.com",
            kdf: .pbkdf2(iterations: 5_000)
        )
        let messy = try BitwardenCrypto.masterKey(
            password: "test",
            email: "  TEST@Bitwarden.COM \n",
            kdf: .pbkdf2(iterations: 5_000)
        )
        XCTAssertEqual(canonical.rawData, messy.rawData)
    }

    func testPBKDF2RejectsZeroIterations() {
        XCTAssertThrowsError(
            try BitwardenCrypto.masterKey(password: "x", email: "a@b.c", kdf: .pbkdf2(iterations: 0))
        ) { error in
            XCTAssertTrue("\(error)".contains("at least 1"), "\(error)")
        }
    }

    // MARK: Argon2

    func testArgon2SaltIsSHA256OfEmailNotTheEmail() throws {
        let recorder = RecordingArgon2()
        _ = try BitwardenCrypto.masterKey(
            password: "test",
            email: "  TEST@Bitwarden.com ",
            kdf: .argon2id(iterations: 3, memoryMiB: 64, parallelism: 4),
            argon2: recorder
        )
        let expected = Data(SHA256.hash(data: Data("test@bitwarden.com".utf8)))
        XCTAssertEqual(recorder.salt, expected)
        XCTAssertNotEqual(recorder.salt, Data("test@bitwarden.com".utf8))
        // MiB on the wire, KiB into Argon2.
        XCTAssertEqual(recorder.memoryKiB, 64 * 1024)
        XCTAssertEqual(recorder.iterations, 3)
        XCTAssertEqual(recorder.parallelism, 4)
        XCTAssertEqual(recorder.outputByteCount, 32)
    }

    func testArgon2UnavailableFailsWithAnActionableMessage() {
        XCTAssertThrowsError(
            try BitwardenCrypto.masterKey(
                password: "test",
                email: "test@bitwarden.com",
                kdf: .argon2id(iterations: 3, memoryMiB: 64, parallelism: 4)
            )
        ) { error in
            guard case VaultSyncError.crypto(let detail) = error else {
                return XCTFail("expected a crypto error, got \(error)")
            }
            XCTAssertTrue(detail.contains("Argon2id KDF is not available in this build"), detail)
            // An error that only says "failed" is not actionable; this one must
            // tell the user what to do instead.
            XCTAssertTrue(detail.contains("PBKDF2"), detail)
        }
    }

    // MARK: Stretching

    func testStretchMatchesPublishedVectorAndSplitsCleanly() throws {
        let masterKeyData = try XCTUnwrap(Data(base64Encoded: BitwardenFixtures.vectorMasterKey))
        let stretched = BitwardenCrypto.stretch(masterKey: SymmetricKey(data: masterKeyData))

        XCTAssertEqual(stretched.encKey.rawData.base64EncodedString(), BitwardenFixtures.vectorStretchedEnc)
        XCTAssertEqual(stretched.macKey.rawData.base64EncodedString(), BitwardenFixtures.vectorStretchedMac)
        XCTAssertEqual(stretched.encKey.rawData.count, 32)
        XCTAssertEqual(stretched.macKey.rawData.count, 32)
        // The two halves must differ; one key used for both jobs would break
        // the encrypt-then-MAC construction.
        XCTAssertNotEqual(stretched.encKey.rawData, stretched.macKey.rawData)
        XCTAssertEqual(stretched.concatenated.count, 64)
    }

    func testStretchIsDeterministic() throws {
        let masterKeyData = try XCTUnwrap(Data(base64Encoded: BitwardenFixtures.vectorMasterKey))
        let first = BitwardenCrypto.stretch(masterKey: SymmetricKey(data: masterKeyData))
        let second = BitwardenCrypto.stretch(masterKey: SymmetricKey(data: masterKeyData))
        XCTAssertEqual(first.concatenated, second.concatenated)
    }

    func testSymmetricKeyRejectsWrongLength() {
        XCTAssertThrowsError(try BitwardenSymmetricKey(concatenated: Data(repeating: 0, count: 32))) { error in
            XCTAssertTrue("\(error)".contains("64 bytes"), "\(error)")
        }
    }

    func testSymmetricKeySplitSurvivesASlicedBuffer() throws {
        // A `Data` slice keeps its parent's indices; splitting one with
        // prefix/suffix on raw indices is a classic silent corruption.
        let padded = Data(repeating: 0xEE, count: 8) + Data((0..<64).map { UInt8($0) })
        let slice = padded[8...]
        let key = try BitwardenSymmetricKey(concatenated: slice)
        XCTAssertEqual(Array(key.encKey.rawData), Array(0..<32).map { UInt8($0) })
        XCTAssertEqual(Array(key.macKey.rawData), Array(32..<64).map { UInt8($0) })
    }
}

// MARK: - EncString

final class BitwardenEncStringTests: XCTestCase {
    private func vectorKey() throws -> BitwardenSymmetricKey {
        let masterKeyData = try XCTUnwrap(Data(base64Encoded: BitwardenFixtures.vectorMasterKey))
        return BitwardenCrypto.stretch(masterKey: SymmetricKey(data: masterKeyData))
    }

    func testRecordedFixtureDecrypts() throws {
        let key = try vectorKey()
        let parsed = try EncString.parse(BitwardenFixtures.recordedEncString)
        XCTAssertEqual(parsed.type, .aesCbc256_HmacSha256_B64)
        XCTAssertEqual(parsed.iv.count, 16)
        XCTAssertEqual(try parsed.decryptToString(key: key), BitwardenFixtures.recordedPlaintext)
    }

    func testDescriptionRoundTripsTheRecordedFixture() throws {
        let parsed = try EncString.parse(BitwardenFixtures.recordedEncString)
        XCTAssertEqual(parsed.description, BitwardenFixtures.recordedEncString)
    }

    func testRoundTrip() throws {
        let key = try vectorKey()
        for plaintext in ["", "a", "hello", String(repeating: "x", count: 16), String(repeating: "y", count: 1024), "ünïcødé ✅"] {
            let sealed = try EncString.encrypt(plaintext, key: key)
            let reparsed = try EncString.parse(sealed.description)
            XCTAssertEqual(try reparsed.decryptToString(key: key), plaintext)
        }
    }

    func testEncryptUsesAFreshIVEachTime() throws {
        let key = try vectorKey()
        let a = try EncString.encrypt("same plaintext", key: key)
        let b = try EncString.encrypt("same plaintext", key: key)
        XCTAssertNotEqual(a.iv, b.iv)
        XCTAssertNotEqual(a.ciphertext, b.ciphertext)
    }

    func testTamperedMACIsRejected() throws {
        let key = try vectorKey()
        let sealed = try EncString.encrypt("transfer 100 to andy", key: key)
        var mac = try XCTUnwrap(sealed.mac)
        mac[0] ^= 0x01
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: sealed.iv, ciphertext: sealed.ciphertext, mac: mac)

        XCTAssertThrowsError(try tampered.decrypt(key: key)) { error in
            guard case VaultSyncError.crypto(let detail) = error else {
                return XCTFail("expected a crypto error, got \(error)")
            }
            XCTAssertTrue(detail.contains("authentication check"), detail)
        }
    }

    func testTamperedCiphertextIsRejected() throws {
        let key = try vectorKey()
        let sealed = try EncString.encrypt("transfer 100 to andy", key: key)
        var ciphertext = sealed.ciphertext
        ciphertext[0] ^= 0x80
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: sealed.iv, ciphertext: ciphertext, mac: sealed.mac)

        // The MAC covers iv || ciphertext, so this must fail authentication —
        // it must NOT reach the cipher and fail on padding, which is the
        // padding-oracle shape we are avoiding.
        XCTAssertThrowsError(try tampered.decrypt(key: key)) { error in
            guard case VaultSyncError.crypto(let detail) = error else {
                return XCTFail("expected a crypto error, got \(error)")
            }
            XCTAssertTrue(detail.contains("authentication check"), detail)
            XCTAssertFalse(detail.contains("padding"), "authentication must fail before decryption: \(detail)")
        }
    }

    func testTamperedIVIsRejected() throws {
        let key = try vectorKey()
        let sealed = try EncString.encrypt("transfer 100 to andy", key: key)
        var iv = sealed.iv
        iv[0] ^= 0x40
        let tampered = EncString(type: .aesCbc256_HmacSha256_B64, iv: iv, ciphertext: sealed.ciphertext, mac: sealed.mac)
        XCTAssertThrowsError(try tampered.decrypt(key: key))
    }

    func testWrongKeyIsRejected() throws {
        let key = try vectorKey()
        let other = try BitwardenFixtures.userKey()
        let sealed = try EncString.encrypt("secret", key: key)
        XCTAssertThrowsError(try sealed.decrypt(key: other))
    }

    func testTypeZeroIsRejectedByName() throws {
        let key = try vectorKey()
        // Same bytes as the recorded fixture, relabelled as the MAC-less type.
        let legacy = try EncString.parse("0.AAECAwQFBgcICQoLDA0ODw==|jTy7gpypFURKBlYUcqNcVmyyv75FJVem2Nyjk6BpYKU=")
        XCTAssertEqual(legacy.type, .aesCbc256_B64)
        XCTAssertThrowsError(try legacy.decrypt(key: key)) { error in
            guard case VaultSyncError.crypto(let detail) = error else {
                return XCTFail("expected a crypto error, got \(error)")
            }
            XCTAssertTrue(detail.contains("type 0"), detail)
            XCTAssertTrue(detail.contains("AES-256-CBC without a MAC"), detail)
        }
    }

    func testTypeSixIsRejectedByName() throws {
        let key = try vectorKey()
        let rsa = try EncString.parse("6.AAECAwQFBgcICQoLDA0ODw==|jTy7gpypFURKBlYUcqNcVmyyv75FJVem2Nyjk6BpYKU=|yHl5XIMSOJRsTrkw57LOESNsklwC2J1ehqYgJoR6/5g=")
        XCTAssertEqual(rsa.type, .rsa2048_OaepSha1_HmacSha256_B64)
        XCTAssertThrowsError(try rsa.decrypt(key: key)) { error in
            guard case VaultSyncError.crypto(let detail) = error else {
                return XCTFail("expected a crypto error, got \(error)")
            }
            XCTAssertTrue(detail.contains("type 6"), detail)
            XCTAssertTrue(detail.contains("RSA-2048"), detail)
        }
    }

    func testStructurallyInvalidStringsAreNil() {
        XCTAssertNil(EncString(""))
        XCTAssertNil(EncString("not an encstring"))
        XCTAssertNil(EncString("2."))
        XCTAssertNil(EncString("2.onlyonepart"))
        XCTAssertNil(EncString("2.a|b|c|d"))
        XCTAssertNil(EncString("99.AAECAwQFBgcICQoLDA0ODw==|AA==|AA=="))
        XCTAssertNil(EncString("2.!!!notbase64!!!|AA==|AA=="))
    }

    func testParseErrorNamesTheField() {
        XCTAssertThrowsError(try EncString.parse("garbage", field: "hosts note")) { error in
            XCTAssertTrue("\(error)".contains("hosts note"), "\(error)")
        }
    }

    func testShortMACIsRejected() throws {
        let key = try vectorKey()
        let sealed = try EncString.encrypt("x", key: key)
        let truncated = EncString(
            type: .aesCbc256_HmacSha256_B64,
            iv: sealed.iv,
            ciphertext: sealed.ciphertext,
            mac: sealed.mac?.prefix(16)
        )
        XCTAssertThrowsError(try truncated.decrypt(key: key)) { error in
            XCTAssertTrue("\(error)".contains("HMAC tag"), "\(error)")
        }
    }

    func testUnwrapUserKeyFromTheRecordedVault() throws {
        // The account key in the recorded /api/sync fixture, opened with the
        // stretched master key for password "test" at 600 000 iterations —
        // which is what the live vault.lan prelogin reports.
        let masterKey = try BitwardenCrypto.masterKey(
            password: "test",
            email: "test@bitwarden.com",
            kdf: .pbkdf2(iterations: 600_000)
        )
        let stretched = BitwardenCrypto.stretch(masterKey: masterKey)
        let sync = try BitwardenJSON.decoder.decode(
            BitwardenSyncResponse.self,
            from: Data(BitwardenFixtures.syncJSON.utf8)
        )
        let protectedKey = try XCTUnwrap(sync.profile?.key)
        let userKey = try BitwardenCrypto.unwrapUserKey(
            protectedKey: protectedKey,
            stretchedMasterKey: stretched
        )
        XCTAssertEqual(userKey.concatenated.base64EncodedString(), BitwardenFixtures.userKeyBase64)
    }

    func testUnwrapWithTheWrongPasswordFails() throws {
        let masterKey = try BitwardenCrypto.masterKey(
            password: "not the password",
            email: "test@bitwarden.com",
            kdf: .pbkdf2(iterations: 600_000)
        )
        let sync = try BitwardenJSON.decoder.decode(
            BitwardenSyncResponse.self,
            from: Data(BitwardenFixtures.syncJSON.utf8)
        )
        let protectedKey = try XCTUnwrap(sync.profile?.key)
        XCTAssertThrowsError(
            try BitwardenCrypto.unwrapUserKey(
                protectedKey: protectedKey,
                stretchedMasterKey: BitwardenCrypto.stretch(masterKey: masterKey)
            )
        )
    }
}

// MARK: - Wire decoding

final class BitwardenWireTests: XCTestCase {
    func testPreloginFixtureDecodes() throws {
        let prelogin = try BitwardenJSON.decoder.decode(
            BitwardenPrelogin.self,
            from: Data(BitwardenFixtures.preloginJSON.utf8)
        )
        XCTAssertEqual(prelogin.kdf, 0)
        XCTAssertEqual(prelogin.kdfIterations, 600_000)
        XCTAssertNil(prelogin.kdfMemory)
        XCTAssertEqual(try prelogin.kdfDescriptor(), .pbkdf2(iterations: 600_000))
    }

    func testPreloginArgon2Decodes() throws {
        let prelogin = try BitwardenJSON.decoder.decode(
            BitwardenPrelogin.self,
            from: Data(BitwardenFixtures.preloginArgon2JSON.utf8)
        )
        XCTAssertEqual(
            try prelogin.kdfDescriptor(),
            .argon2id(iterations: 3, memoryMiB: 64, parallelism: 4)
        )
    }

    func testUnknownKDFIsNamed() {
        let json = Data(#"{"kdf":7,"kdfIterations":1}"#.utf8)
        XCTAssertThrowsError(
            try BitwardenJSON.decoder.decode(BitwardenPrelogin.self, from: json).kdfDescriptor()
        ) { error in
            XCTAssertTrue("\(error)".contains("KDF type 7"), "\(error)")
        }
    }

    func testMixedCasingDecodes() throws {
        // A real token response mixes OAuth snake_case with Bitwarden's
        // PascalCase in one object.
        let token = try BitwardenJSON.decoder.decode(
            BitwardenTokenResponse.self,
            from: Data(BitwardenFixtures.tokenJSON.utf8)
        )
        XCTAssertEqual(token.accessToken, "fixture-access-token")
        XCTAssertEqual(token.refreshToken, "fixture-refresh-token")
        XCTAssertEqual(token.expiresIn, 3600)
        XCTAssertEqual(token.kdf, 0)
        XCTAssertEqual(token.kdfIterations, 600_000)
        XCTAssertNotNil(token.key)
    }

    func testKeyNormalisation() {
        XCTAssertEqual(BitwardenJSON.normalisedKey("access_token"), "accessToken")
        XCTAssertEqual(BitwardenJSON.normalisedKey("Key"), "key")
        XCTAssertEqual(BitwardenJSON.normalisedKey("KdfIterations"), "kdfIterations")
        XCTAssertEqual(BitwardenJSON.normalisedKey("kdfIterations"), "kdfIterations")
        XCTAssertEqual(BitwardenJSON.normalisedKey("TwoFactorProviders2"), "twoFactorProviders2")
    }

    func testEndpointsForSelfHosted() throws {
        let endpoints = try BitwardenEndpoints(serverURL: XCTUnwrap(URL(string: "https://vault.lan/")))
        XCTAssertEqual(endpoints.identity.absoluteString, "https://vault.lan/identity")
        XCTAssertEqual(endpoints.api.absoluteString, "https://vault.lan/api")
        XCTAssertEqual(endpoints.host, "vault.lan")
    }

    func testEndpointsForBitwardenCloudSplitHosts() throws {
        let endpoints = try BitwardenEndpoints(serverURL: XCTUnwrap(URL(string: "https://vault.bitwarden.com")))
        XCTAssertEqual(endpoints.identity.absoluteString, "https://identity.bitwarden.com")
        XCTAssertEqual(endpoints.api.absoluteString, "https://api.bitwarden.com")
    }

    func testEndpointsRejectNonHTTPURLs() throws {
        XCTAssertThrowsError(try BitwardenEndpoints(serverURL: XCTUnwrap(URL(string: "ftp://vault.lan"))))
    }

    func testFormEncodingEscapesBase64Characters() {
        // A "+" in a form body decodes as a space, and "+" is one of base64's
        // 64 characters — so an unescaped master password hash silently
        // becomes the wrong hash roughly half the time.
        let encoded = BitwardenAPIClient.formURLEncoded([
            "password": "/fLMc6m0bwpU1bYko8NY/gl/+SaxfSGGQc6arJoDOaE=",
            "grant_type": "password",
        ])
        XCTAssertTrue(encoded.contains("%2B"), encoded)
        XCTAssertTrue(encoded.contains("%2F"), encoded)
        XCTAssertTrue(encoded.contains("%3D"), encoded)
        XCTAssertFalse(encoded.contains("+"), encoded)
    }

    func testLenientDateParsing() {
        // Bitwarden sends seven fractional digits; ISO8601DateFormatter accepts three.
        XCTAssertNotNil(BitwardenDate.parse("2026-09-14T12:00:00.0000000Z"))
        XCTAssertNotNil(BitwardenDate.parse("2026-09-14T12:00:00.000Z"))
        XCTAssertNotNil(BitwardenDate.parse("2026-09-14T12:00:00Z"))
        XCTAssertNil(BitwardenDate.parse(nil))
        XCTAssertNil(BitwardenDate.parse("not a date"))
        XCTAssertEqual(
            BitwardenDate.parse("2026-09-14T12:00:00.0000000Z"),
            BitwardenDate.parse("2026-09-14T12:00:00Z")
        )
    }

    func testDatesTruncateDownToMilliseconds() throws {
        // The vault stores ISO-8601 with three fractional digits, so a `Date`
        // does not survive a round trip bit for bit. Truncation must round
        // *down*: `VaultSyncMerge` keeps the newer snapshot, and a pulled
        // snapshot that rounded *up* could outrank the local edit it came from.
        struct Box: Codable { var when: Date }
        let precise = Date(timeIntervalSince1970: 1_772_000_000.123_456_7)
        let data = try GhosttyJSON.encoder.encode(Box(when: precise))
        let decoded = try GhosttyJSON.decoder.decode(Box.self, from: data)

        XCTAssertLessThanOrEqual(decoded.when, precise)
        XCTAssertEqual(decoded.when.timeIntervalSince1970, precise.timeIntervalSince1970, accuracy: 0.001)
        // Idempotent from then on.
        let again = try GhosttyJSON.decoder.decode(
            Box.self,
            from: try GhosttyJSON.encoder.encode(decoded)
        )
        XCTAssertEqual(again.when, decoded.when)
    }

    func testStableIdentityIDIsDeterministicAndDistinct() {
        let a = BitwardenSyncProvider.stableIdentityID(forCipherID: "11111111-2222-3333-4444-555555555555")
        let b = BitwardenSyncProvider.stableIdentityID(forCipherID: "11111111-2222-3333-4444-555555555555")
        let c = BitwardenSyncProvider.stableIdentityID(forCipherID: "different")
        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
    }

    func testKeyTypeFromPublicKeyLineNeverResolvesToSecureEnclave() {
        XCTAssertEqual(BitwardenSyncProvider.keyType(forPublicKeyLine: BitwardenFixtures.publicKeyLine1), .ed25519)
        // A key that arrived over the network cannot be in this device's Enclave.
        XCTAssertEqual(
            BitwardenSyncProvider.keyType(forPublicKeyLine: "ecdsa-sha2-nistp256 AAAA... c"),
            .p256
        )
        XCTAssertNil(BitwardenSyncProvider.keyType(forPublicKeyLine: "ssh-rsa AAAA... c"))
    }
}

// MARK: - Provider

final class BitwardenSyncProviderTests: XCTestCase {
    private static let serverURL = URL(string: "https://vault.lan")

    @MainActor
    private func makeProvider(
        transport: StubBitwardenTransport,
        keychain: InMemoryKeychain
    ) -> BitwardenSyncProvider {
        BitwardenSyncProvider(keychain: keychain, makeClient: { configuration in
            try BitwardenAPIClient(configuration: configuration, transport: transport)
        })
    }

    @MainActor
    private func connected(
        transport: StubBitwardenTransport,
        keychain: InMemoryKeychain
    ) async throws -> BitwardenSyncProvider {
        let provider = makeProvider(transport: transport, keychain: keychain)
        try await provider.connect(.bitwardenPassword(
            serverURL: try XCTUnwrap(Self.serverURL),
            email: "test@bitwarden.com",
            masterPassword: "test",
            totp: nil
        ))
        return provider
    }

    // MARK: Connect

    @MainActor
    func testConnectLabelsTheAccountAndPersistsToTheKeychain() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        let provider = try await connected(transport: transport, keychain: keychain)

        XCTAssertTrue(provider.status.isConnected)
        XCTAssertEqual(provider.status.accountLabel, "test@bitwarden.com · vault.lan")
        XCTAssertFalse(provider.status.lastResultWasError)

        XCTAssertTrue(keychain.contains(account: BitwardenSyncProvider.keychainAccount))
        let options = try XCTUnwrap(keychain.storedOptions[BitwardenSyncProvider.keychainAccount])
        guard case .whenUnlockedThisDeviceOnly = options.accessibility else {
            return XCTFail("the session blob holds the account's user key; it must be device-only")
        }
        XCTAssertFalse(options.synchronizable, "key material must not replicate through iCloud")

        // It must really be the user key, not a placeholder.
        let blob = try XCTUnwrap(try keychain.get(account: BitwardenSyncProvider.keychainAccount, prompt: nil))
        let session = try JSONDecoder().decode(BitwardenPersistedSession.self, from: blob)
        XCTAssertEqual(session.userKey.base64EncodedString(), BitwardenFixtures.userKeyBase64)
        XCTAssertEqual(session.refreshToken, "fixture-refresh-token")
    }

    @MainActor
    func testConnectSendsAHashNotThePassword() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        _ = try await connected(transport: transport, keychain: keychain)

        let tokenRequest = try XCTUnwrap(transport.exchanges.first { $0.path.hasSuffix("/connect/token") })
        let body = try XCTUnwrap(String(data: try XCTUnwrap(tokenRequest.body), encoding: .utf8))
        XCTAssertTrue(body.contains("grant_type=password"), body)
        XCTAssertTrue(body.contains("scope=api%20offline_access"), body)
        XCTAssertFalse(body.contains("password=test&"), "the master password must never be sent")
        XCTAssertFalse(body.hasSuffix("password=test"), "the master password must never be sent")
    }

    @MainActor
    func testTwoFactorRequiredIsADistinctError() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(
            token: BitwardenFixtures.twoFactorJSON,
            tokenStatus: 400
        )
        let provider = makeProvider(transport: transport, keychain: keychain)

        do {
            try await provider.connect(.bitwardenPassword(
                serverURL: try XCTUnwrap(Self.serverURL),
                email: "test@bitwarden.com",
                masterPassword: "test",
                totp: nil
            ))
            XCTFail("expected a two-factor error")
        } catch let error as BitwardenAuthError {
            XCTAssertEqual(error, .twoFactorRequired(providers: ["0"]))
            XCTAssertTrue(error.supportsTOTP)
        }

        XCTAssertFalse(provider.status.isConnected)
        XCTAssertTrue(provider.status.lastResultWasError)
        XCTAssertFalse(keychain.contains(account: BitwardenSyncProvider.keychainAccount))
    }

    @MainActor
    func testTOTPIsSentWhenSupplied() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        let provider = makeProvider(transport: transport, keychain: keychain)
        try await provider.connect(.bitwardenPassword(
            serverURL: try XCTUnwrap(Self.serverURL),
            email: "test@bitwarden.com",
            masterPassword: "test",
            totp: " 123456 "
        ))
        let tokenRequest = try XCTUnwrap(transport.exchanges.first { $0.path.hasSuffix("/connect/token") })
        let body = try XCTUnwrap(String(data: try XCTUnwrap(tokenRequest.body), encoding: .utf8))
        XCTAssertTrue(body.contains("twoFactorToken=123456"), body)
        XCTAssertTrue(body.contains("twoFactorProvider=0"), body)
    }

    @MainActor
    func testUnsupportedCredentialsAreRejected() async {
        let provider = makeProvider(transport: StubBitwardenTransport.vault(), keychain: InMemoryKeychain())
        do {
            try await provider.connect(.bundlePassphrase("nope"))
            XCTFail("expected a rejection")
        } catch let error as VaultSyncError {
            guard case .unsupportedCredentials = error else {
                return XCTFail("expected unsupportedCredentials, got \(error)")
            }
        } catch {
            XCTFail("expected a VaultSyncError, got \(error)")
        }
    }

    @MainActor
    func testRestoringASessionNeedsNoNetwork() async throws {
        let keychain = InMemoryKeychain()
        _ = try await connected(transport: StubBitwardenTransport.vault(), keychain: keychain)

        let offline = StubBitwardenTransport.vault()
        offline.refusesAllRequests = true
        let restored = makeProvider(transport: offline, keychain: keychain)

        XCTAssertTrue(restored.status.isConnected)
        XCTAssertEqual(restored.status.accountLabel, "test@bitwarden.com · vault.lan")
        XCTAssertTrue(offline.exchanges.isEmpty)
    }

    @MainActor
    func testARestoredSessionPullsWithoutSigningInAgain() async throws {
        let keychain = InMemoryKeychain()
        _ = try await connected(transport: StubBitwardenTransport.vault(), keychain: keychain)

        // A server that refuses to issue tokens at all: the restored access
        // token must be in place before the first request goes out, not
        // adopted asynchronously afterwards.
        let vaultOnly = StubBitwardenTransport { exchange in
            guard exchange.path.hasSuffix("/api/sync") else {
                throw VaultSyncError.server("Signing in again should not have been necessary.")
            }
            return (200, Data(BitwardenFixtures.syncJSON.utf8))
        }
        let restored = makeProvider(transport: vaultOnly, keychain: keychain)
        let pulled = try await restored.pull()
        let snapshot = try XCTUnwrap(pulled)
        XCTAssertEqual(snapshot.identities.count, 1)
        XCTAssertEqual(snapshot.hosts.count, 1)

        let sync = try XCTUnwrap(vaultOnly.exchanges.first)
        XCTAssertEqual(
            sync.path, "/api/sync",
            "the very first request after a restore must already be authenticated"
        )
    }

    @MainActor
    func testDisconnectRemovesTheStoredKeyMaterial() async throws {
        let keychain = InMemoryKeychain()
        let provider = try await connected(transport: StubBitwardenTransport.vault(), keychain: keychain)
        await provider.disconnect()

        XCTAssertFalse(provider.status.isConnected)
        XCTAssertNil(provider.status.accountLabel)
        XCTAssertFalse(keychain.contains(account: BitwardenSyncProvider.keychainAccount))
    }

    @MainActor
    func testOperationsBeforeConnectFail() async {
        let provider = makeProvider(transport: StubBitwardenTransport.vault(), keychain: InMemoryKeychain())
        do {
            _ = try await provider.pull()
            XCTFail("expected notConnected")
        } catch let error as VaultSyncError {
            guard case .notConnected = error else { return XCTFail("got \(error)") }
        } catch {
            XCTFail("got \(error)")
        }
    }

    // MARK: Pull

    @MainActor
    func testPullDecodesTheRecordedVault() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        let provider = try await connected(transport: transport, keychain: keychain)

        let pulled = try await provider.pull()
        let snapshot = try XCTUnwrap(pulled)

        // Identities — the type-1 login cipher must be ignored entirely.
        XCTAssertEqual(snapshot.identities.count, 1)
        let synced = try XCTUnwrap(snapshot.identities.first)
        XCTAssertEqual(synced.identity.id, BitwardenFixtures.identityUUID)
        XCTAssertEqual(synced.identity.name, "work laptop")
        XCTAssertEqual(synced.identity.keyType, .ed25519)
        XCTAssertEqual(synced.identity.publicKeyLine, BitwardenFixtures.publicKeyLine1)
        XCTAssertEqual(synced.identity.fingerprint, BitwardenFixtures.fingerprint1)
        XCTAssertFalse(synced.identity.isSecureEnclave)
        XCTAssertTrue(synced.identity.syncsToICloud, "metadata must survive the round trip")
        XCTAssertFalse(synced.deviceOnly)
        XCTAssertTrue(synced.canAuthenticateElsewhere)
        XCTAssertEqual(synced.privateKeyPEM, BitwardenFixtures.privateKeyPEM1)

        // The PEM that came out of the vault must be a key we can actually use.
        let parsed = try OpenSSHKeyFile.parse(pem: try XCTUnwrap(synced.privateKeyPEM))
        XCTAssertEqual(parsed.material.keyType, .ed25519)
        XCTAssertEqual(parsed.material.fingerprint, BitwardenFixtures.fingerprint1)
        XCTAssertEqual(parsed.comment, "andy@sagan")

        // Hosts, out of the secure note.
        XCTAssertEqual(snapshot.hosts.count, 1)
        let host = try XCTUnwrap(snapshot.hosts.first)
        XCTAssertEqual(host.id, BitwardenFixtures.hostUUID)
        XCTAssertEqual(host.alias, "noether")
        XCTAssertEqual(host.hostname, "10.0.0.81")
        XCTAssertEqual(host.port, 22)
        XCTAssertEqual(host.username, "andy")
        XCTAssertEqual(host.identityID, BitwardenFixtures.identityUUID)
        XCTAssertEqual(host.group, "Homelab")
        XCTAssertEqual(host.tags, ["homelab", "agents"])
        XCTAssertNil(host.colorHex)

        XCTAssertEqual(snapshot.knownHosts.count, 1)
        let pinned = try XCTUnwrap(snapshot.knownHosts.first)
        XCTAssertEqual(pinned.id, "10.0.0.81:22")
        XCTAssertEqual(pinned.keyType, "ssh-ed25519")
        XCTAssertEqual(pinned.fingerprint, BitwardenFixtures.fingerprint1)

        XCTAssertEqual(snapshot.updatedAt, BitwardenDate.parse("2026-03-04T05:06:07Z"))
        XCTAssertNotNil(provider.status.lastSync)
        XCTAssertFalse(provider.status.lastResultWasError)
        XCTAssertEqual(provider.status.lastResult, "Pulled 1 key, 1 host, 1 pinned.")
    }

    @MainActor
    func testPullReturnsNilForAnEmptyVault() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncEmptyJSON)
        let provider = try await connected(transport: transport, keychain: keychain)

        let snapshot = try await provider.pull()
        XCTAssertNil(snapshot, "neither the hosts note nor any SSH key exists yet")
        XCTAssertFalse(provider.status.lastResultWasError)
        XCTAssertEqual(provider.status.lastResult, "Nothing stored in this vault yet.")
    }

    @MainActor
    func testPullSynthesisesAStableIdentityForAForeignKey() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncForeignKeyJSON)
        let provider = try await connected(transport: transport, keychain: keychain)

        let pulled = try await provider.pull()
        let snapshot = try XCTUnwrap(pulled)
        XCTAssertEqual(snapshot.identities.count, 1)
        let synced = try XCTUnwrap(snapshot.identities.first)
        XCTAssertEqual(synced.identity.name, "made in the Bitwarden app")
        XCTAssertEqual(synced.identity.keyType, .ed25519, "derived from the public key line")
        XCTAssertEqual(
            synced.identity.id,
            BitwardenSyncProvider.stableIdentityID(forCipherID: "cccccccc-dddd-eeee-ffff-000000000000"),
            "a key with no Ghostty metadata must still get the same id on every pull"
        )
        XCTAssertTrue(snapshot.hosts.isEmpty)
    }

    // MARK: Push

    @MainActor
    func testPushSkipsSecureEnclaveKeysAndSaysSo() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        let provider = try await connected(transport: transport, keychain: keychain)
        let userKey = try BitwardenFixtures.userKey()

        let existing = SyncedIdentity(
            identity: Identity(
                id: try XCTUnwrap(BitwardenFixtures.identityUUID),
                name: "work laptop",
                keyType: .ed25519,
                publicKeyLine: BitwardenFixtures.publicKeyLine1,
                fingerprint: BitwardenFixtures.fingerprint1
            ),
            privateKeyPEM: BitwardenFixtures.privateKeyPEM1,
            deviceOnly: false
        )
        let fresh = SyncedIdentity(
            identity: Identity(
                name: "faraday",
                keyType: .ed25519,
                publicKeyLine: BitwardenFixtures.publicKeyLine2,
                fingerprint: BitwardenFixtures.fingerprint2
            ),
            privateKeyPEM: BitwardenFixtures.privateKeyPEM2,
            deviceOnly: false
        )
        let enclave = SyncedIdentity(
            identity: Identity(
                name: "phone key",
                keyType: .secureEnclaveP256,
                publicKeyLine: "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= phone",
                fingerprint: "SHA256:enclaveenclaveenclaveenclaveenclave1",
                isSecureEnclave: true
            ),
            privateKeyPEM: nil,
            deviceOnly: true
        )

        try await provider.push(VaultSnapshot(
            identities: [existing, fresh, enclave],
            hosts: [Host(alias: "noether", hostname: "10.0.0.81", username: "andy")],
            knownHosts: [],
            updatedAt: Date()
        ))

        let writes = transport.cipherWrites
        // 2 SSH keys (one update, one create) + the hosts note update.
        XCTAssertEqual(writes.count, 3)

        var names: [String] = []
        for write in writes {
            let json = try XCTUnwrap(
                try JSONSerialization.jsonObject(with: try XCTUnwrap(write.body)) as? [String: Any]
            )
            let name = try XCTUnwrap(json["name"] as? String)
            names.append(try EncString.parse(name).decryptToString(key: userKey))
        }
        XCTAssertEqual(Set(names), ["work laptop", "faraday", BitwardenSyncProvider.hostsNoteName])
        XCTAssertFalse(names.contains("phone key"), "a Secure Enclave key has no exportable half")

        // The existing key is updated in place; only the new one is created.
        let updates = writes.filter { $0.method == "PUT" }
        let creates = writes.filter { $0.method == "POST" }
        XCTAssertEqual(creates.count, 1)
        XCTAssertEqual(updates.count, 2)
        XCTAssertTrue(updates.contains { $0.path.hasSuffix("/api/ciphers/11111111-2222-3333-4444-555555555555") })
        XCTAssertTrue(updates.contains { $0.path.hasSuffix("/api/ciphers/66666666-7777-8888-9999-aaaaaaaaaaaa") })
        XCTAssertTrue(transport.cipherDeletes.isEmpty)

        XCTAssertFalse(provider.status.lastResultWasError)
        XCTAssertEqual(provider.status.lastResult, "Pushed 2 keys, 1 host. 1 device-only key not synced.")
    }

    @MainActor
    func testPushedCipherIsAType5SSHKeyWithEverythingEncrypted() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncEmptyJSON)
        let provider = try await connected(transport: transport, keychain: keychain)
        let userKey = try BitwardenFixtures.userKey()

        let identity = Identity(
            name: "work laptop",
            keyType: .ed25519,
            publicKeyLine: BitwardenFixtures.publicKeyLine1,
            fingerprint: BitwardenFixtures.fingerprint1,
            createdAt: try XCTUnwrap(BitwardenDate.parse("2026-01-02T03:04:05Z")),
            requiresBiometrics: true,
            syncsToICloud: true
        )
        try await provider.push(VaultSnapshot(
            identities: [SyncedIdentity(
                identity: identity,
                privateKeyPEM: BitwardenFixtures.privateKeyPEM1,
                deviceOnly: false
            )],
            hosts: [],
            knownHosts: [],
            updatedAt: Date()
        ))

        let keyWrite = try XCTUnwrap(transport.cipherWrites.first { write in
            guard let body = write.body,
                  let json = try? JSONSerialization.jsonObject(with: body) as? [String: Any]
            else { return false }
            return json["type"] as? Int == 5
        })
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(keyWrite.body)) as? [String: Any]
        )
        let sshKey = try XCTUnwrap(json["sshKey"] as? [String: Any])

        // Every field on the wire is an EncString, never plaintext.
        for field in ["privateKey", "publicKey", "keyFingerprint"] {
            let value = try XCTUnwrap(sshKey[field] as? String)
            XCTAssertTrue(value.hasPrefix("2."), "\(field) must be a type-2 EncString")
        }
        XCTAssertEqual(
            try EncString.parse(try XCTUnwrap(sshKey["privateKey"] as? String)).decryptToString(key: userKey),
            BitwardenFixtures.privateKeyPEM1
        )
        XCTAssertEqual(
            try EncString.parse(try XCTUnwrap(sshKey["publicKey"] as? String)).decryptToString(key: userKey),
            BitwardenFixtures.publicKeyLine1
        )

        // The metadata Bitwarden has nowhere to put rides in the notes.
        let notes = try EncString.parse(try XCTUnwrap(json["notes"] as? String)).decrypt(key: userKey)
        let note = try GhosttyJSON.decoder.decode(GhosttyIdentityNote.self, from: notes)
        XCTAssertEqual(note.id, identity.id)
        XCTAssertEqual(note.keyType, .ed25519)
        XCTAssertTrue(note.requiresBiometrics)
        XCTAssertTrue(note.syncsToICloud)
        XCTAssertEqual(note.createdAt, identity.createdAt)
        XCTAssertTrue(note.isOurs)
    }

    @MainActor
    func testHostsNoteIsASecureNoteWithTheExactName() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncEmptyJSON)
        let provider = try await connected(transport: transport, keychain: keychain)
        let userKey = try BitwardenFixtures.userKey()

        let host = Host(alias: "pi-a", hostname: "10.0.0.41", username: "andy", group: "Homelab")
        // An explicit `firstSeen` rather than the default `Date()`: the vault
        // stores ISO-8601 to the millisecond, so a date with sub-millisecond
        // precision does not survive the round trip. See `testDatesTruncate`.
        let pinned = KnownHost(
            hostname: "10.0.0.41",
            port: 22,
            keyType: "ssh-ed25519",
            fingerprint: BitwardenFixtures.fingerprint1,
            publicKeyLine: BitwardenFixtures.publicKeyLine1,
            firstSeen: try XCTUnwrap(BitwardenDate.parse("2026-04-05T06:07:08.250Z"))
        )
        let updatedAt = try XCTUnwrap(BitwardenDate.parse("2026-05-06T07:08:09Z"))
        try await provider.push(VaultSnapshot(
            identities: [],
            hosts: [host],
            knownHosts: [pinned],
            updatedAt: updatedAt
        ))

        let write = try XCTUnwrap(transport.cipherWrites.first)
        XCTAssertEqual(write.method, "POST", "no note exists yet, so it is created")
        let json = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: try XCTUnwrap(write.body)) as? [String: Any]
        )
        XCTAssertEqual(json["type"] as? Int, 2)
        XCTAssertNotNil(json["secureNote"])
        XCTAssertEqual(
            try EncString.parse(try XCTUnwrap(json["name"] as? String)).decryptToString(key: userKey),
            "Ghostty iOS hosts"
        )

        let notes = try EncString.parse(try XCTUnwrap(json["notes"] as? String)).decrypt(key: userKey)
        let note = try GhosttyJSON.decoder.decode(GhosttyHostsNote.self, from: notes)
        XCTAssertEqual(note.hosts, [host])
        XCTAssertEqual(note.knownHosts, [pinned])
        XCTAssertEqual(note.updatedAt, updatedAt)
    }

    @MainActor
    func testPushThenPullRoundTripsASnapshot() async throws {
        // Push into an empty vault, feed what was written back as the next
        // /api/sync, and require the snapshot to survive unchanged.
        let keychain = InMemoryKeychain()
        let recorder = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncEmptyJSON)
        let provider = try await connected(transport: recorder, keychain: keychain)

        let identity = Identity(
            name: "work laptop",
            keyType: .ed25519,
            publicKeyLine: BitwardenFixtures.publicKeyLine1,
            fingerprint: BitwardenFixtures.fingerprint1,
            createdAt: try XCTUnwrap(BitwardenDate.parse("2026-01-02T03:04:05Z")),
            requiresBiometrics: true,
            syncsToICloud: true
        )
        let original = VaultSnapshot(
            identities: [SyncedIdentity(
                identity: identity,
                privateKeyPEM: BitwardenFixtures.privateKeyPEM1,
                deviceOnly: false
            )],
            hosts: [Host(alias: "noether", hostname: "10.0.0.81", username: "andy", group: "Homelab")],
            knownHosts: [KnownHost(
                hostname: "10.0.0.81",
                port: 22,
                keyType: "ssh-ed25519",
                fingerprint: BitwardenFixtures.fingerprint1,
                publicKeyLine: BitwardenFixtures.publicKeyLine1,
                firstSeen: try XCTUnwrap(BitwardenDate.parse("2026-02-03T04:05:06Z"))
            )],
            updatedAt: try XCTUnwrap(BitwardenDate.parse("2026-03-04T05:06:07Z"))
        )
        try await provider.push(original)

        // Rebuild an /api/sync body out of exactly what was written.
        var ciphers: [[String: Any]] = []
        for (index, write) in recorder.cipherWrites.enumerated() {
            var cipher = try XCTUnwrap(
                try JSONSerialization.jsonObject(with: try XCTUnwrap(write.body)) as? [String: Any]
            )
            cipher["id"] = "replayed-\(index)"
            cipher["object"] = "cipherDetails"
            ciphers.append(cipher)
        }
        var replay = try XCTUnwrap(
            try JSONSerialization.jsonObject(with: Data(BitwardenFixtures.syncEmptyJSON.utf8)) as? [String: Any]
        )
        replay["ciphers"] = ciphers
        let replayJSON = try XCTUnwrap(
            String(data: try JSONSerialization.data(withJSONObject: replay), encoding: .utf8)
        )

        let second = StubBitwardenTransport.vault(sync: replayJSON)
        let reader = try await connected(transport: second, keychain: InMemoryKeychain())
        let replayed = try await reader.pull()
        let pulled = try XCTUnwrap(replayed)

        XCTAssertEqual(pulled.identities, original.identities)
        XCTAssertEqual(pulled.hosts, original.hosts)
        XCTAssertEqual(pulled.knownHosts, original.knownHosts)
        XCTAssertEqual(pulled.updatedAt, original.updatedAt)
    }

    @MainActor
    func testPushDeletesItsOwnOrphansOnly() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault()
        let provider = try await connected(transport: transport, keychain: keychain)

        // The recorded vault's SSH key carries our metadata and is absent from
        // this snapshot, so it is ours to remove.
        try await provider.push(VaultSnapshot(identities: [], hosts: [], knownHosts: [], updatedAt: Date()))

        XCTAssertEqual(transport.cipherDeletes.count, 1)
        XCTAssertTrue(
            try XCTUnwrap(transport.cipherDeletes.first).path
                .hasSuffix("/api/ciphers/11111111-2222-3333-4444-555555555555")
        )
    }

    @MainActor
    func testPushNeverDeletesAKeyItDidNotCreate() async throws {
        let keychain = InMemoryKeychain()
        let transport = StubBitwardenTransport.vault(sync: BitwardenFixtures.syncForeignKeyJSON)
        let provider = try await connected(transport: transport, keychain: keychain)

        try await provider.push(VaultSnapshot(identities: [], hosts: [], knownHosts: [], updatedAt: Date()))

        XCTAssertTrue(
            transport.cipherDeletes.isEmpty,
            "an SSH key made in the Bitwarden app is not ours to delete"
        )
    }
}
