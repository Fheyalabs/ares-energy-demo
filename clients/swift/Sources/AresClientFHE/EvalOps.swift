// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {
    public func evalAdd(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalAdd(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalSub(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalSub(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalMult(_ a: Ciphertext, _ b: Ciphertext) throws -> Ciphertext {
        guard let h = EvalMult(raw, a.raw, b.raw) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalMultConst(_ ct: Ciphertext, _ scalar: Double) throws -> Ciphertext {
        guard let h = EvalMultConst(raw, ct.raw, scalar) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalSum(_ ct: Ciphertext, batchSize: Int) throws -> Ciphertext {
        guard let h = EvalSum(raw, ct.raw, Int32(batchSize)) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    public func evalChebyshevSign(_ ct: Ciphertext, degree: Int) throws -> Ciphertext {
        guard let h = EvalChebyshevSign(raw, ct.raw, Int32(degree)) else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    /// p(x) = Σ coefficients[i]·x^i, ascending order (coefficients[0] = constant term).
    public func evalPolynomial(_ ct: Ciphertext, coefficients: [Double]) throws -> Ciphertext {
        var coeffs = coefficients
        let h: UnsafeMutableRawPointer? = coeffs.withUnsafeMutableBufferPointer { buf in
            EvalPolynomial(raw, ct.raw, buf.baseAddress, Int32(buf.count))
        }
        guard let h else { throw FHEError.evalFailed }
        return Ciphertext(h)
    }

    /// For each i: mask[i] = ∏_{j≠i} p(cts[i] − cts[j]); p ≈ step on [-1,1].
    /// Returns one mask ciphertext per input (winner ≈ 1, losers ≈ 0).
    public func evalArgmax(_ cts: [Ciphertext], sharpeningCoefficients: [Double]) throws -> [Ciphertext] {
        var ctPtrs: [UnsafeMutableRawPointer?] = cts.map { $0.raw }
        var coeffs = sharpeningCoefficients
        let nCts = Int32(cts.count)
        let nCoeffs = Int32(coeffs.count)
        var outMasks = [UnsafeMutableRawPointer?](repeating: nil, count: cts.count)
        let rc = ctPtrs.withUnsafeMutableBufferPointer { cb in
            coeffs.withUnsafeMutableBufferPointer { sb in
                outMasks.withUnsafeMutableBufferPointer { ob in
                    EvalArgmax(raw, cb.baseAddress, nCts, sb.baseAddress, nCoeffs, ob.baseAddress)
                }
            }
        }
        guard rc == 0 else { throw FHEError.evalFailed }
        return try outMasks.map { ptr in
            guard let ptr else { throw FHEError.evalFailed }
            return Ciphertext(ptr)
        }
    }
}
