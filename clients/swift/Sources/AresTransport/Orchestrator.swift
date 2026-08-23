import Foundation

/// Connect N participants serially (clear per-participant failures); close all.
public enum Orchestrator {
    public static func connectAll(serverURL: String, pseudonyms: [String], sessionID: String,
                                  authSecret: String, timeout: TimeInterval = 60) async throws -> [Session] {
        var sessions: [Session] = []
        for p in pseudonyms {
            sessions.append(try await Session.connect(serverURL: serverURL, pseudonym: p,
                sessionID: sessionID, authSecret: authSecret, defaultTimeout: timeout))
        }
        return sessions
    }

    public static func closeAll(_ sessions: [Session]) async {
        for s in sessions { await s.close() }
    }
}
