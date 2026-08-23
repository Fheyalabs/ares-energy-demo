// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

// SAFETY: Handle lifetime is safe even if the `CryptoContext` that produced a
// handle is released first. OpenFHE key/ciphertext types are internally
// shared_ptr-backed, so each `ARESPublicKey`/`ARESCiphertext`/etc. holds its own
// reference to the underlying C++ key material; `FreeCryptoContext` does not free
// material still referenced by a live handle. (If the bridge ever moves to raw
// ownership, handles must hold a strong `CryptoContext` reference instead.)
public final class PublicKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreePublicKey(raw) }
}

public final class SecretKeyShare {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeSecretKeyShare(raw) }
}

public final class Ciphertext {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeCiphertext(raw) }
}

public final class EvalMultKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeEvalMultKey(raw) }
}

public final class RotKey {
    let raw: UnsafeMutableRawPointer
    init(_ raw: UnsafeMutableRawPointer) { self.raw = raw }
    deinit { FreeRotKey(raw) }
}
