// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Candidate self-seal for the ARES v2.8 winner package. A candidate seals its
/// 32-byte winner secret σ to its OWN X25519 key, producing an exactly-80-byte
/// package: `ephemeral_pk(32) ‖ ciphertext(32) ‖ Poly1305 tag(16)`. The server
/// bit-encodes the 80 bytes, fuses them homomorphically, and delivers the
/// winner's fused package; the winning candidate re-derives the key and opens σ.
///
/// The 12-byte nonce is *derived* from the ephemeral + recipient public keys and
/// not transmitted (the ephemeral key is single-use, so a deterministic nonce is
/// safe) — that is what keeps the package at 80 bytes, matching the server's
/// `DefaultWinnerPackageBytes`. (The skeleton's `ChaChaPoly.combined` shipped a
/// 12-byte nonce inline → 92 bytes, which the server rejects.)
public enum CandidateSeal {
    public static let packageBytes = 80
    private static let salt = Data("fheya-candidate-sealed-v2.8".utf8)

    public enum SealError: Error, Equatable { case badLength(Int) }

    /// Seal `sigma` (32 bytes) to `recipientPublicKey` (the candidate's own X25519
    /// public key). Returns the 80-byte package.
    public static func seal(sigma: Data,
                            to recipientPublicKey: Curve25519.KeyAgreement.PublicKey) throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephPub = ephemeral.publicKey.rawRepresentation
        let shared = try ephemeral.sharedSecretFromKeyAgreement(with: recipientPublicKey)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: Data(), outputByteCount: 32)
        let nonce = try ChaChaPoly.Nonce(
            data: deriveNonce(ephPub: ephPub, recipient: recipientPublicKey.rawRepresentation))
        let box = try ChaChaPoly.seal(sigma, using: key, nonce: nonce)
        return ephPub + box.ciphertext + box.tag   // 32 + 32 + 16 = 80
    }

    /// Open an 80-byte package with the candidate's own X25519 private key.
    public static func open(_ package: Data,
                            with recipientPrivateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        let pkg = Data(package)
        guard pkg.count == packageBytes else { throw SealError.badLength(pkg.count) }
        let ephPub = pkg.subdata(in: 0..<32)
        let ciphertext = pkg.subdata(in: 32..<64)
        let tag = pkg.subdata(in: 64..<80)
        let ephPublic = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPub)
        let shared = try recipientPrivateKey.sharedSecretFromKeyAgreement(with: ephPublic)
        let key = shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: salt,
                                                 sharedInfo: Data(), outputByteCount: 32)
        let nonce = try ChaChaPoly.Nonce(
            data: deriveNonce(ephPub: ephPub, recipient: recipientPrivateKey.publicKey.rawRepresentation))
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
        return try ChaChaPoly.open(box, using: key)
    }

    static func deriveNonce(ephPub: Data, recipient: Data) -> Data {
        Data(Data(SHA256.hash(data: ephPub + recipient)).prefix(12))
    }
}
