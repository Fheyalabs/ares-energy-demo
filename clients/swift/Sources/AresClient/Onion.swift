import Foundation
import Crypto

public enum OnionError: Error, Equatable {
    case selfIndexOutOfRange(Int, Int)
    case selfMemoUnmatched
    case malformedLayer
}

public enum Onion {
    private static let hkdfInfo = Data("ares_onion_v1".utf8)

    private static func eciesEncrypt(recipientPub: Data, plaintext: Data) throws -> Data {
        let eph = Curve25519.KeyAgreement.PrivateKey()
        let recipient = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipientPub)
        let shared = try eph.sharedSecretFromKeyAgreement(with: recipient)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: hkdfInfo, outputByteCount: 32)
        let nonce = AES.GCM.Nonce() // 12 random bytes
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: nonce)
        var out = eph.publicKey.rawRepresentation     // 32
        out.append(Data(nonce))                        // 12
        out.append(sealed.ciphertext)                  // ct
        out.append(sealed.tag)                         // 16
        return out
    }

    private static func eciesDecrypt(recipientSk: Data, layer: Data) throws -> Data {
        guard layer.count >= 32 + 12 + 16 else { throw OnionError.malformedLayer }
        // Use layer.startIndex/endIndex (not 0-based): Data subdata slices carry
        // a non-zero startIndex, so offset arithmetic must be relative to base.
        let base = layer.startIndex
        let ephPub = layer.subdata(in: base ..< base + 32)
        let nonceData = layer.subdata(in: base + 32 ..< base + 44)
        let tag = layer.subdata(in: layer.endIndex - 16 ..< layer.endIndex)
        let ct = layer.subdata(in: base + 44 ..< layer.endIndex - 16)
        let sk = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: recipientSk)
        let eph = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPub)
        let shared = try sk.sharedSecretFromKeyAgreement(with: eph)
        let key = shared.hkdfDerivedSymmetricKey(
            using: SHA256.self, salt: Data(), sharedInfo: hkdfInfo, outputByteCount: 32)
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: nonceData), ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: key)
    }

    /// SC-2: wrap payload in peerPubs.count ECIES layers including self at selfIndex
    /// (reverse peel order). selfMemo = ciphertext immediately after the builder's own
    /// layer is applied — used to recognise its own item on peel.
    public static func build(payload: Data, peerPubs: [Data], selfIndex: Int) throws -> (onion: Data, selfMemo: Data) {
        guard selfIndex >= 0 && selfIndex < peerPubs.count else {
            throw OnionError.selfIndexOutOfRange(selfIndex, peerPubs.count)
        }
        var data = payload
        var selfMemo: Data?
        var i = peerPubs.count - 1
        while i >= 0 {
            data = try eciesEncrypt(recipientPub: peerPubs[i], plaintext: data)
            if i == selfIndex { selfMemo = data }
            i -= 1
        }
        return (data, selfMemo!)
    }

    /// Peel one layer from every onion; identify own item by exact byte-match against
    /// selfMemo. Throws if selfMemo is non-nil and no item matches.
    public static func peelBatch(mySk: Data, selfMemo: Data?, onions: [Data]) throws -> (peeled: [Data], ownIndex: Int) {
        var peeled: [Data] = []
        var ownIndex = -1
        for (i, o) in onions.enumerated() {
            if let memo = selfMemo, o == memo { ownIndex = i }
            peeled.append(try eciesDecrypt(recipientSk: mySk, layer: o))
        }
        if selfMemo != nil && ownIndex < 0 { throw OnionError.selfMemoUnmatched }
        return (peeled, ownIndex)
    }
}
