// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge
import Foundation

extension CryptoContext {
    public func encrypt(values: [Double], under pk: PublicKey) throws -> Ciphertext {
        var vals = values
        let h: UnsafeMutableRawPointer? = vals.withUnsafeMutableBufferPointer { buf in
            Encrypt(raw, pk.raw, buf.baseAddress, Int32(buf.count))
        }
        guard let h else { throw FHEError.encryptFailed }
        return Ciphertext(h)
    }

    public func encrypt(intValues: [Int64], under pk: PublicKey) throws -> Ciphertext {
        var vals = intValues
        let h: UnsafeMutableRawPointer? = vals.withUnsafeMutableBufferPointer { buf in
            EncryptPackedInt(raw, pk.raw, buf.baseAddress, Int32(buf.count))
        }
        guard let h else { throw FHEError.encryptFailed }
        return Ciphertext(h)
    }

    /// Encrypt an exact sequence of MSB-first payload chunks. The bridge owns
    /// bit packing so Swift and Kotlin emit identical ciphertext slot layouts.
    public func encryptPayloadChunks(
        payload: Data,
        publicKey: PublicKey,
        chunkSize: Int
    ) throws -> [Data] {
        guard !payload.isEmpty, chunkSize > 0 else { throw FHEError.encryptFailed }
        let (payloadBits, overflow) = payload.count.multipliedReportingOverflow(by: 8)
        guard !overflow, payloadBits % chunkSize == 0 else { throw FHEError.encryptFailed }

        return try stride(from: 0, to: payloadBits, by: chunkSize).map { bitOffset in
            var serialized: UnsafeMutablePointer<UInt8>?
            var serializedLength = 0
            let result = payload.withUnsafeBytes { bytes in
                EncryptSerializedPayloadChunk(
                    raw,
                    publicKey.raw,
                    bytes.bindMemory(to: UInt8.self).baseAddress,
                    payload.count,
                    bitOffset,
                    chunkSize,
                    &serialized,
                    &serializedLength
                )
            }
            guard result == 0, serialized != nil, serializedLength > 0 else {
                if let serialized { free(serialized) }
                throw FHEError.encryptFailed
            }
            return copyAndFree(serialized, serializedLength)
        }
    }

    /// Encrypt one scalar into every batch slot for a later local encrypted
    /// distance computation.
    public func encryptRepeatedScalar(_ value: Double, publicKey: PublicKey) throws -> Data {
        var serialized: UnsafeMutablePointer<UInt8>?
        var serializedLength = 0
        guard EncryptSerializedRepeatedScalarCKKS(
            raw, publicKey.raw, value, &serialized, &serializedLength
        ) == 0, serialized != nil, serializedLength > 0 else {
            if let serialized { free(serialized) }
            throw FHEError.encryptFailed
        }
        return copyAndFree(serialized, serializedLength)
    }

    /// Derive a serialized encrypted squared distance from two encrypted origin
    /// scalars and two local scalar values. The local values are never serialized.
    public func encryptedSquaredDistance(
        originFirst: Data,
        originSecond: Data,
        localFirst: Double,
        localSecond: Double
    ) throws -> Data {
        guard !originFirst.isEmpty, !originSecond.isEmpty else { throw FHEError.encryptFailed }
        let firstLength = originFirst.count
        let secondLength = originSecond.count
        var serialized: UnsafeMutablePointer<UInt8>?
        var serializedLength = 0
        let result = originFirst.withUnsafeBytes { firstBytes in
            originSecond.withUnsafeBytes { secondBytes in
                ComputeSerializedSquaredDistanceCKKS(
                    raw,
                    firstBytes.bindMemory(to: UInt8.self).baseAddress,
                    firstLength,
                    secondBytes.bindMemory(to: UInt8.self).baseAddress,
                    secondLength,
                    localFirst,
                    localSecond,
                    &serialized,
                    &serializedLength
                )
            }
        }
        guard result == 0, serialized != nil, serializedLength > 0 else {
            if let serialized { free(serialized) }
            throw FHEError.encryptFailed
        }
        return copyAndFree(serialized, serializedLength)
    }

    /// Encrypt one exact integer scalar into every BFV batch slot for a later
    /// local encrypted-distance computation.
    public func encryptRepeatedScalarBFV(_ value: Int64, publicKey: PublicKey) throws -> Data {
        var serialized: UnsafeMutablePointer<UInt8>?
        var serializedLength = 0
        guard EncryptSerializedRepeatedScalarBFV(
            raw, publicKey.raw, value, &serialized, &serializedLength
        ) == 0, serialized != nil, serializedLength > 0 else {
            if let serialized { free(serialized) }
            throw FHEError.encryptFailed
        }
        return copyAndFree(serialized, serializedLength)
    }

    /// Derive an exact packed-integer BFV squared distance from serialized
    /// encrypted origin scalars. The local values are never serialized.
    public func encryptedSquaredDistanceBFV(
        originFirst: Data,
        originSecond: Data,
        localFirst: Int64,
        localSecond: Int64
    ) throws -> Data {
        guard !originFirst.isEmpty, !originSecond.isEmpty else { throw FHEError.encryptFailed }
        let firstLength = originFirst.count
        let secondLength = originSecond.count
        var serialized: UnsafeMutablePointer<UInt8>?
        var serializedLength = 0
        let result = originFirst.withUnsafeBytes { firstBytes in
            originSecond.withUnsafeBytes { secondBytes in
                ComputeSerializedSquaredDistanceBFV(
                    raw,
                    firstBytes.bindMemory(to: UInt8.self).baseAddress,
                    firstLength,
                    secondBytes.bindMemory(to: UInt8.self).baseAddress,
                    secondLength,
                    localFirst,
                    localSecond,
                    &serialized,
                    &serializedLength
                )
            }
        }
        guard result == 0, serialized != nil, serializedLength > 0 else {
            if let serialized { free(serialized) }
            throw FHEError.encryptFailed
        }
        return copyAndFree(serialized, serializedLength)
    }
}
