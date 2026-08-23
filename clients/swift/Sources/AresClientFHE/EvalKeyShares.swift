// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {
    public func genEvalMultKeyShare(_ sk: SecretKeyShare) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        let rc = GenEvalMultKeyShare(raw, sk.raw, &out)
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return EvalMultKey(out)
    }

    public func genRotKeyShare(_ sk: SecretKeyShare) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        let rc = GenRotKeyShare(raw, sk.raw, &out)
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return RotKey(out)
    }
}
