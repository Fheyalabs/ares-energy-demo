// SPDX-License-Identifier: Apache-2.0

import COpenFHEBridge

/// Bridge call failure. `.contextMismatch` is reserved for future programmatic
/// signalling; deserialization failures (including context/version skew) surface
/// as `.deserializeFailed` (the bridge logs the mismatch case).
public enum FHEError: Error, Equatable {
    case contextCreationFailed
    case keygenFailed
    case evalKeyFailed
    case foldAlreadyFinalized
    case encryptFailed
    case decryptFailed
    case evalFailed
    case serializationFailed
    case deserializeFailed
    case contextMismatch
    case versionUnavailable
}
