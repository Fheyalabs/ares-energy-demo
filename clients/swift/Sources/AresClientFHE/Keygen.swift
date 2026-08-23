// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public struct KeyPairShare {
    public let publicKey: PublicKey
    public let secretKey: SecretKeyShare
}

extension CryptoContext {
    public func keyGenFirst() throws -> KeyPairShare {
        var pk: UnsafeMutableRawPointer?
        var sk: UnsafeMutableRawPointer?
        let rc = KeyGenFirst(raw, &pk, &sk)
        guard rc == 0, let pk, let sk else { throw FHEError.keygenFailed }
        return KeyPairShare(publicKey: PublicKey(pk), secretKey: SecretKeyShare(sk))
    }

    public func keyGenNext(prev: PublicKey) throws -> KeyPairShare {
        var pk: UnsafeMutableRawPointer?
        var sk: UnsafeMutableRawPointer?
        let rc = KeyGenNext(raw, prev.raw, &pk, &sk)
        guard rc == 0, let pk, let sk else { throw FHEError.keygenFailed }
        return KeyPairShare(publicKey: PublicKey(pk), secretKey: SecretKeyShare(sk))
    }

    /// Combine all parties' public keys into a single joint key.
    public func multiAddPublicKeys(_ keys: [PublicKey]) throws -> PublicKey {
        var ptrs: [UnsafeMutableRawPointer?] = keys.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = ptrs.withUnsafeMutableBufferPointer { buf in
            MultiAddPublicKeys(raw, buf.baseAddress, Int32(keys.count), &out)
        }
        guard rc == 0, let out else { throw FHEError.keygenFailed }
        return PublicKey(out)
    }

    /// Single-party keygen (not threshold). Generates a keypair and installs the
    /// eval-mult key on the context so EvalMult ops work. The caller gets back
    /// (publicKey, secretKey). Used by the rideshare rider — no multi-party rounds.
    public func singleKeyGen() throws -> KeyPairShare {
        let kp = try keyGenFirst()
        let rc = SingleKeyEvalMultKeyGen(raw, kp.secretKey.raw)
        guard rc == 0 else { throw FHEError.keygenFailed }
        return kp
    }
}
