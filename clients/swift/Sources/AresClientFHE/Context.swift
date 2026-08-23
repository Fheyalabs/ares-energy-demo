// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

public final class CryptoContext {
    let raw: UnsafeMutableRawPointer

    public init(ringDim: UInt32, scalingFactor: Double, depth: UInt32,
                batchSize: UInt32 = 0,
                minimalRotationKeys: Bool = false,
                evalSumOnlyRotationKeys: Bool = false,
                profileDim: Int = 0,
                payloadSlotCount: Int = 0) throws {
        guard let h = CreateCKKSContext(ringDim, scalingFactor, depth, batchSize) else {
            throw FHEError.contextCreationFailed
        }
        self.raw = h
        // Dimension-parameterized rotation keys: generate only the
        // ceil(log2(profileDim)) sum + ceil(log2(payloadSlotCount)) broadcast keys
        // instead of the full ring/2 batch. Load-bearing for fitting 2^16/depth-23
        // multiparty keygen in memory. Default off preserves full-batch behaviour for
        // existing callers (auction / voting / boundcheck).
        if minimalRotationKeys {
            SetMinimalRotationKeys(h, Int32(profileDim), Int32(payloadSlotCount))
        } else if evalSumOnlyRotationKeys {
            // Chunked-union fusion: only the replicating EvalSumKeyGen fold set (no
            // broadcast at-index keys). The context MUST be built with
            // batchSize = next_pow2(profileDim) so EvalSumKeyGen emits the profile_dim fold.
            SetEvalSumOnlyRotationKeys(h, Int32(profileDim))
        }
    }
    public init(ringDim: UInt32, multiplicativeDepth: UInt32,
                plaintextModulus: UInt64,
                batchSize: UInt32 = 0) throws {
        guard let h = CreateBFVContext(ringDim, multiplicativeDepth, plaintextModulus, batchSize) else {
            throw FHEError.contextCreationFailed
        }
        self.raw = h
    }
    deinit { FreeCryptoContext(raw) }

    public static func openFHEContextCount() -> Int {
        Int(OpenFHEContextCount())
    }

    /// Releases process-global OpenFHE context state at a quiescent boundary.
    /// Callers must not retain a CryptoContext when invoking this method.
    public static func releaseOpenFHEGlobalContexts() {
        ReleaseAllOpenFHEContexts()
    }
}

public typealias BFVCryptoContext = CryptoContext
