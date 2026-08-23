import Foundation

public struct AdminClient: Sendable {
    public let serverURL: String
    public init(serverURL: String) {
        self.serverURL = serverURL.hasSuffix("/") ? String(serverURL.dropLast()) : serverURL
    }

    static func encodeStartBody(sessionID: String, participants: [String],
                                attrs: [String: String]) throws -> Data {
        var body: [String: Any] = ["session_id": sessionID, "participants": participants]
        if !attrs.isEmpty { body["attrs"] = attrs }
        return try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    }

    public func health() async throws {
        let url = URL(string: "\(serverURL)/admin/health")!
        let (_, resp) = try await URLSession.shared.data(from: url)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 200 else { throw TransportError.http(code, "health") }
    }

    public func waitForHealth(timeout: TimeInterval = 15) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if (try? await health()) != nil { return }
            try await Task.sleep(nanoseconds: 200_000_000)
        }
        throw TransportError.timeout("server health")
    }

    public func startSession(sessionID: String, participants: [String],
                             attrs: [String: String] = [:]) async throws {
        var req = URLRequest(url: URL(string: "\(serverURL)/admin/sessions")!)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try Self.encodeStartBody(sessionID: sessionID, participants: participants, attrs: attrs)
        let (data, resp) = try await URLSession.shared.data(for: req)
        let code = (resp as? HTTPURLResponse)?.statusCode ?? 0
        guard code == 201 else { throw TransportError.http(code, String(decoding: data, as: UTF8.self)) }
    }

    public func getState(sessionID: String) async throws -> String {
        let url = URL(string: "\(serverURL)/admin/sessions/\(sessionID)")!
        let (data, _) = try await URLSession.shared.data(from: url)
        let obj = (try JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
        return obj["state"] as? String ?? ""
    }

    public func pollUntilTerminal(sessionID: String, terminal: String,
                                  tries: Int = 40, interval: TimeInterval = 0.5) async throws -> String {
        var last = ""
        for _ in 0..<tries {
            last = (try? await getState(sessionID: sessionID)) ?? last
            if last.isEmpty || last == terminal { return last }
            try await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
        }
        return last
    }
}
