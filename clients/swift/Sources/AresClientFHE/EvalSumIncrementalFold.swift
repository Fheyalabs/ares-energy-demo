// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

/// Folds eval-sum (rotation) key shares into a live accumulator one at a time, so a
/// caller can generate a participant share, fold it, drop it, and move on — peak
/// resident key material is the accumulator plus the single share being folded,
/// rather than all N shares held at once (the `combineEvalSumKeys` path). The
/// combined key is byte-identical to the all-at-once combine.
///
/// This is the opt-in memory optimization for large rings (2^16 / depth 23), where N
/// resident eval-sum key maps would otherwise dominate RSS. It mirrors the Go
/// `cgo.EvalSumIncrementalFold` (start → fold → finalize) and reuses the caller's
/// shared `CryptoContext` (the "WithContext" form — no extra ~3 GB context per call).
///
/// Usage:
/// ```
/// let base = try ctx.evalSumKeyGenLead(secretKeys[0])
/// let fold = try EvalSumIncrementalFold(context: ctx, leadBase: base)
/// for i in 1..<n {
///     let share = try ctx.evalSumKeyShare(secretKeys[i], base: base, ownPK: pubKeys[i])
///     try fold.fold(publicKey: pubKeys[i], share: share)   // share drops → ARC frees it
/// }
/// let evalSum = try fold.finalize()
/// ```
public final class EvalSumIncrementalFold {
    private let context: CryptoContext
    private var accumulator: RotKey?

    /// Seed the accumulator with the lead party's eval-sum base key
    /// (`evalSumKeyGenLead`). The base is cloned, not consumed — the caller keeps
    /// ownership of `leadBase` (it is also each participant's `base:`).
    public init(context: CryptoContext, leadBase: RotKey) throws {
        self.context = context
        guard let a = EvalSumCombineStart(leadBase.raw) else {
            throw FHEError.evalKeyFailed
        }
        self.accumulator = RotKey(a)
    }

    /// Fold one non-lead participant's eval-sum share into the accumulator. Drop the
    /// `share` afterwards so ARC frees its key material before the next fold — that is
    /// what bounds peak RSS to accumulator + one share.
    public func fold(publicKey: PublicKey, share: RotKey) throws {
        guard let accumulator else { throw FHEError.foldAlreadyFinalized }
        guard EvalSumCombineFold(context.raw, accumulator.raw, publicKey.raw, share.raw) == 0 else {
            throw FHEError.evalKeyFailed
        }
    }

    /// Return the combined joint eval-sum key. The fold is consumed; calling `fold`
    /// after `finalize` throws `foldAlreadyFinalized`.
    public func finalize() throws -> RotKey {
        guard let a = accumulator else { throw FHEError.foldAlreadyFinalized }
        accumulator = nil
        return a
    }
}
