// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Registers a participant via the server's `POST /v2/register` so its device key
/// is on file — required before any signed protocol message (`verifySignedPayload`
/// rejects unregistered senders). All key fields are hex; `credential_blob` is the
/// minted invite (see ``InviteCredential``). The response carries `ws_auth_token`
/// (HMAC of the pseudonym) and the initial brownie.
/// Mirrors internal/transport/handlers_session.go `Register`.
public struct RegistrationClient {
    private let baseURL: String

    public init(serverURL: String) {
        self.baseURL = serverURL.hasSuffix("/") ? String(serverURL.dropLast()) : serverURL
    }

    public struct Result {
        public let wsAuthToken: String?
        public let brownie: Int
    }

    public func register(matchPseudonym: String, lkPubHex: String, devicePKHex: String,
                         nullifier: String, city: String, credentialBlob: Data) async throws -> Result {
        guard let url = URL(string: "\(baseURL)/v2/register") else {
            throw TransportError.dialFailed("\(baseURL)/v2/register")
        }
        let body: [String: String] = [
            "match_pseudonym": matchPseudonym,
            "lk_pub": lkPubHex,
            "device_pk": devicePKHex,
            "nullifier": nullifier,
            "city": city,
            "credential_blob": String(data: credentialBlob, encoding: .utf8) ?? "",
        ]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            throw TransportError.http(code, String(data: data, encoding: .utf8) ?? "")
        }
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return Result(wsAuthToken: obj?["ws_auth_token"] as? String,
                      brownie: obj?["brownie"] as? Int ?? 0)
    }
}
