import Foundation
import Crypto

/// SC-10 lineage DAGNode in the hex/snake_case v2 wire form.
public struct DAGNode: Codable, Equatable, Sendable {
    public var hash: String
    public var sessionID: String
    public var phaseID: String
    public var role: String
    public var parents: [String]
    public var parentRoles: [String]
    public var payloadHash: String
    public var createdAt: String
    public var producer: String
    public var signature: String
    public var algorithm: String

    enum CodingKeys: String, CodingKey {
        case hash
        case sessionID = "session_id"
        case phaseID = "phase_id"
        case role
        case parents
        case parentRoles = "parent_roles"
        case payloadHash = "payload_hash"
        case createdAt = "created_at"
        case producer
        case signature
        case algorithm
    }
}

public enum LineageError: Error, Equatable {
    case badParentHex(String)
    case parentNot32Bytes(String, Int)
    case badSeed
}

public enum Lineage {
    /// Build an SC-10 slot-submission DAGNode. Deterministic fields (producer,
    /// payload_hash, node_hash) and the signed message reproduce Go/Python
    /// byte-for-byte; the Ed25519 signature is valid but randomized (swift-crypto
    /// Curve25519.Signing is non-deterministic) — interop relies on verification,
    /// not byte-equality. created_at is excluded from node_hash / signing_msg.
    public static func buildSlotNode(
        sessionID: String,
        payloadBytes: Data,
        ed25519Seed: Data? = nil,
        parentsHex: [String] = [],
        phaseID: String = "anon-g-verify",
        role: String = "slot-submission"
    ) throws -> (node: DAGNode, sk: Data, pk: Data) {
        let sid = Data(sessionID.utf8)
        let phase = Data(phaseID.utf8)
        let roleD = Data(role.utf8)

        let payloadHash = Data(SHA256.hash(data: payloadBytes))

        var parents: [Data] = []
        for ph in parentsHex {
            guard let pb = ByteUtil.fromHex(ph) else { throw LineageError.badParentHex(ph) }
            guard pb.count == 32 else { throw LineageError.parentNot32Bytes(ph, pb.count) }
            parents.append(pb)
        }
        parents.sort { $0.lexicographicallyPrecedes($1) }

        var nh = Data()
        nh.append(ByteUtil.lp(sid))
        nh.append(ByteUtil.lp(phase))
        nh.append(ByteUtil.lp(roleD))
        nh.append(ByteUtil.lp(payloadHash))
        nh.append(ByteUtil.u32be(UInt32(parents.count)))
        for p in parents { nh.append(p) }
        let nodeHash = Data(SHA256.hash(data: nh))

        var signingMsg = Data()
        signingMsg.append(nodeHash)
        signingMsg.append(ByteUtil.lp(sid))
        signingMsg.append(ByteUtil.lp(phase))
        signingMsg.append(ByteUtil.lp(roleD))

        let priv: Curve25519.Signing.PrivateKey
        if let seed = ed25519Seed {
            do { priv = try Curve25519.Signing.PrivateKey(rawRepresentation: seed) }
            catch { throw LineageError.badSeed }
        } else {
            priv = Curve25519.Signing.PrivateKey()
        }
        let pk = priv.publicKey.rawRepresentation
        let sk = priv.rawRepresentation
        let sig = try priv.signature(for: signingMsg)

        let iso = ISO8601DateFormatter()
        iso.formatOptions = [.withInternetDateTime]
        let node = DAGNode(
            hash: ByteUtil.hex(nodeHash),
            sessionID: sessionID,
            phaseID: phaseID,
            role: role,
            parents: parents.map { ByteUtil.hex($0) },   // sorted lowercase hex, matching Go's wire order
            parentRoles: [],
            payloadHash: ByteUtil.hex(payloadHash),
            createdAt: iso.string(from: Date()),
            producer: ByteUtil.hex(pk),
            signature: ByteUtil.hex(Data(sig)),
            algorithm: "ed25519"
        )
        return (node, sk, pk)
    }
}
