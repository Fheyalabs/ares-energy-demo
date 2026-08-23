// SPDX-License-Identifier: Apache-2.0

import Foundation

/// Thin client for the server's manual queue launcher.
///
/// In development this is the real session creation path: enqueue enough
/// registered participants for a city and the server emits `session_invitation`
/// over websocket with the generated session id and OpenFHE contract.
public struct QueueClient: Sendable {
    private let baseURL: String

    public init(serverURL: String) {
        self.baseURL = serverURL.hasSuffix("/") ? String(serverURL.dropLast()) : serverURL
    }

    public struct EnqueueResult: Sendable {
        public let position: Int
        public let sessionID: String?
    }

    public func enqueue(pseudonym: String, city: String) async throws -> EnqueueResult {
        guard let url = URL(string: "\(baseURL)/v2/queue") else {
            throw TransportError.dialFailed("\(baseURL)/v2/queue")
        }
        let body = ["pseudonym": pseudonym, "city": city]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])

        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else {
            throw TransportError.http(code, String(decoding: data, as: UTF8.self))
        }
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return EnqueueResult(
            position: obj?["position"] as? Int ?? 0,
            sessionID: obj?["session_id"] as? String)
    }

    /// Test/debug direct launch (`POST /debug/launch`) that bypasses the scheduler's
    /// pool floor, so a small e2e run forms a session immediately rather than
    /// waiting for production-scale queue pressure. Returns the server-generated
    /// session id (the same id then arrives in `session_invitation`).
    public func launch(participants: [String], city: String,
                       openFHEContract: [String: Any]? = nil) async throws -> String {
        guard let url = URL(string: "\(baseURL)/debug/launch") else {
            throw TransportError.dialFailed("\(baseURL)/debug/launch")
        }
        var body: [String: Any] = ["city": city, "participants": participants]
        if let openFHEContract {
            body["openfhe_contract"] = openFHEContract
        }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 201 else {
            throw TransportError.http(code, String(decoding: data, as: UTF8.self))
        }
        let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any]
        return obj?["session_id"] as? String ?? ""
    }
}
