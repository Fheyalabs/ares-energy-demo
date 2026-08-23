// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

extension CryptoContext {
    public func partialDecrypt(_ ct: Ciphertext, with sk: SecretKeyShare) throws -> Ciphertext {
        var out: UnsafeMutableRawPointer?
        let rc = MultiDecMain(raw, ct.raw, sk.raw, &out)
        guard rc == 0, let out else { throw FHEError.decryptFailed }
        return Ciphertext(out)
    }

    public func fuse(_ partials: [Ciphertext], slotCapacity: Int) throws -> [Double] {
        var ptrs: [UnsafeMutableRawPointer?] = partials.map { $0.raw }
        var out = [Double](repeating: 0, count: slotCapacity)
        var n = Int32(slotCapacity)
        let rc = ptrs.withUnsafeMutableBufferPointer { pbuf in
            out.withUnsafeMutableBufferPointer { obuf in
                MultiDecFusion(raw, pbuf.baseAddress, Int32(partials.count), obuf.baseAddress, &n)
            }
        }
        guard rc == 0 else { throw FHEError.decryptFailed }
        return Array(out.prefix(Int(n)))
    }

    public func fuseInt(_ partials: [Ciphertext], slotCapacity: Int) throws -> [Int64] {
        var ptrs: [UnsafeMutableRawPointer?] = partials.map { $0.raw }
        var out = [Int64](repeating: 0, count: slotCapacity)
        var n = Int32(slotCapacity)
        let rc = ptrs.withUnsafeMutableBufferPointer { pbuf in
            out.withUnsafeMutableBufferPointer { obuf in
                MultiDecFusionPackedInt(raw, pbuf.baseAddress, Int32(partials.count), obuf.baseAddress, &n)
            }
        }
        guard rc == 0 else { throw FHEError.decryptFailed }
        return Array(out.prefix(Int(n)))
    }

    public func decryptSingle(_ ct: Ciphertext, with sk: SecretKeyShare, slots: Int) throws -> [Double] {
        var out = [Double](repeating: 0, count: slots)
        var n = Int32(slots)
        let rc = out.withUnsafeMutableBufferPointer { obuf in
            DecryptSingle(raw, ct.raw, sk.raw, obuf.baseAddress, &n)
        }
        guard rc == 0 else { throw FHEError.decryptFailed }
        return Array(out.prefix(Int(n)))
    }
}
