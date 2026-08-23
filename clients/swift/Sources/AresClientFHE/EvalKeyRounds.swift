// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge
import Foundation

extension CryptoContext {

    // MARK: – Eval-mult-key 2-round protocol

    public func evalMultKeyGenLead(_ sk: SecretKeyShare) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeyGenLead(raw, sk.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func evalMultKeySwitchShare(_ sk: SecretKeyShare, base: EvalMultKey) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeySwitchShare(raw, sk.raw, base.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func combineEvalMultSwitchShares(_ pks: [PublicKey], _ shares: [EvalMultKey]) throws -> EvalMultKey {
        guard pks.count >= shares.count else { throw FHEError.evalKeyFailed }
        var pkPtrs: [UnsafeMutableRawPointer?] = pks.map { $0.raw }
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = pkPtrs.withUnsafeMutableBufferPointer { pb in
            shPtrs.withUnsafeMutableBufferPointer { sb in
                CombineEvalMultSwitchShares(raw, pb.baseAddress, sb.baseAddress,
                                           Int32(shares.count), &out)
            }
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return EvalMultKey(out)
    }

    public func evalMultKeyFinalShare(_ sk: SecretKeyShare, joined: EvalMultKey,
                                      finalPK: PublicKey) throws -> EvalMultKey {
        var out: UnsafeMutableRawPointer?
        guard EvalMultKeyFinalShare(raw, sk.raw, joined.raw, finalPK.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return EvalMultKey(out)
    }

    public func combineEvalMultFinalShares(_ finalPK: PublicKey,
                                           _ shares: [EvalMultKey]) throws -> EvalMultKey {
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = shPtrs.withUnsafeMutableBufferPointer { sb in
            CombineEvalMultFinalShares(raw, finalPK.raw, sb.baseAddress,
                                      Int32(shares.count), &out)
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return EvalMultKey(out)
    }

    public func insertEvalMultKey(_ key: EvalMultKey) throws {
        guard InsertEvalMultKey(raw, key.raw) == 0 else { throw FHEError.evalKeyFailed }
    }

    // MARK: – Eval-sum (rotation) key protocol

    public func evalSumKeyGenLead(_ sk: SecretKeyShare) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard EvalSumKeyGenLead(raw, sk.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func evalSumKeyShare(_ sk: SecretKeyShare, base: RotKey,
                                ownPK: PublicKey) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard EvalSumKeyShare(raw, sk.raw, base.raw, ownPK.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func combineEvalSumKeys(_ pks: [PublicKey], _ shares: [RotKey]) throws -> RotKey {
        guard pks.count >= shares.count else { throw FHEError.evalKeyFailed }
        var pkPtrs: [UnsafeMutableRawPointer?] = pks.map { $0.raw }
        var shPtrs: [UnsafeMutableRawPointer?] = shares.map { $0.raw }
        var out: UnsafeMutableRawPointer?
        let rc = pkPtrs.withUnsafeMutableBufferPointer { pb in
            shPtrs.withUnsafeMutableBufferPointer { sb in
                CombineEvalSumKeys(raw, pb.baseAddress, sb.baseAddress,
                                   Int32(shares.count), &out)
            }
        }
        guard rc == 0, let out else { throw FHEError.evalKeyFailed }
        return RotKey(out)
    }

    public func insertEvalSumKey(_ key: RotKey) throws {
        guard InsertEvalSumKey(raw, key.raw) == 0 else { throw FHEError.evalKeyFailed }
    }

    // MARK: – Streamed (per-index, merged into accumulator) eval-sum keygen

    public func streamedEvalSumKeyGenLead(_ sk: SecretKeyShare) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard StreamedEvalSumKeyGenLead(raw, sk.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func streamedEvalSumKeyShare(_ sk: SecretKeyShare, base: RotKey,
                                        ownPK: PublicKey) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard StreamedEvalSumKeyShare(raw, sk.raw, base.raw, ownPK.raw, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    // MARK: – Per-index (never-merged) eval-sum keygen

    /// Generate the lead's per-index eval-sum key as a RotKey handle (no serialize→deserialize
    /// roundtrip). Use `serializeAVectors` / `serializeBVectors` on the result for upload.
    public func generatePerIndexEvalSumKey(for sk: SecretKeyShare, index: Int32) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard GeneratePerIndexEvalSumKey(raw, sk.raw, index, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    /// Generate a party's per-index eval-sum share as a RotKey handle (no roundtrip).
    /// Use `serializeBVectors` on the result for b-only upload.
    public func generatePerIndexEvalSumShare(for sk: SecretKeyShare,
                                             singleIndexBase: RotKey,
                                             ownPK: PublicKey,
                                             index: Int32) throws -> RotKey {
        var out: UnsafeMutableRawPointer?
        guard GeneratePerIndexEvalSumShare(raw, sk.raw, singleIndexBase.raw, ownPK.raw, index, &out) == 0, let out else {
            throw FHEError.evalKeyFailed
        }
        return RotKey(out)
    }

    public func generatePerIndexEvalSumKeyData(for sk: SecretKeyShare, index: Int32) throws -> Data {
        let key = try generatePerIndexEvalSumKey(for: sk, index: index)
        return try serialize(key)
    }

    public func generatePerIndexEvalSumShareData(for sk: SecretKeyShare,
                                                 singleIndexBase: RotKey,
                                                 ownPK: PublicKey,
                                                 index: Int32) throws -> Data {
        let key = try generatePerIndexEvalSumShare(for: sk, singleIndexBase: singleIndexBase, ownPK: ownPK, index: index)
        return try serialize(key)
    }

    public func minimalRotationIndices() -> [Int32] {
        var count: Int32 = 0
        guard GetMinimalRotationIndices(raw, nil, &count) == 0, count > 0 else { return [] }
        var buf = [Int32](repeating: 0, count: Int(count))
        guard buf.withUnsafeMutableBufferPointer({ ptr in
            GetMinimalRotationIndices(raw, ptr.baseAddress, &count)
        }) == 0 else { return [] }
        return Array(buf.prefix(Int(count)))
    }

    public func generatePerIndexEvalSumKeys(for sk: SecretKeyShare) throws -> [(Int32, String)] {
        let indices = minimalRotationIndices()
        var result: [(Int32, String)] = []
        result.reserveCapacity(indices.count)
        for idx in indices {
            let key = try generatePerIndexEvalSumKey(for: sk, index: idx)
            let b64 = try serialize(key).base64EncodedString()
            result.append((idx, b64))
        }
        return result
    }

    public func generatePerIndexEvalSumShares(for sk: SecretKeyShare,
                                              baseKeysByIndex: [(Int32, String)],
                                              ownPK: PublicKey) throws -> [(Int32, String)] {
        var result: [(Int32, String)] = []
        result.reserveCapacity(baseKeysByIndex.count)
        for (idx, base64) in baseKeysByIndex {
            guard let data = Data(base64Encoded: base64) else {
                throw FHEError.deserializeFailed
            }
            let base = try deserializeRotKey(data)
            let share = try generatePerIndexEvalSumShare(for: sk,
                                                         singleIndexBase: base,
                                                         ownPK: ownPK,
                                                         index: idx)
            let b64 = try serialize(share).base64EncodedString()
            result.append((idx, b64))
        }
        return result
    }
}
