import Foundation
import Crypto
import AresClient

public enum TransportError: Error, Equatable {
    case dialFailed(String)
    case timeout(String)
    case closed(String)
    case http(Int, String)
}

public actor Session {
    public let pseudonym: String
    public let sessionID: String
    private var activeSessionID: String
    private let serverURL: String
    private let task: URLSessionWebSocketTask
    private var inbox: [InboundFrame] = []
    private var waiters: [(id: UUID, cont: CheckedContinuation<InboundFrame, any Error>)] = []
    private var closed = false
    private var closeError: TransportError?
    private let defaultTimeout: TimeInterval

    public nonisolated static func deriveAuthToken(secret: String, pseudonym: String) -> String {
        let mac = HMAC<SHA256>.authenticationCode(
            for: Data(pseudonym.utf8), using: SymmetricKey(data: Data(secret.utf8)))
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    private init(pseudonym: String, sessionID: String, serverURL: String,
                 task: URLSessionWebSocketTask, defaultTimeout: TimeInterval) {
        self.pseudonym = pseudonym; self.sessionID = sessionID; self.activeSessionID = sessionID
        self.serverURL = serverURL; self.task = task; self.defaultTimeout = defaultTimeout
    }

    // MARK: - Test-only surface (no-socket construction)
    // A real URLSessionWebSocketTask cannot be stubbed cheaply, so we expose a
    // package-internal init that skips the socket and two thin wrappers that let
    // @testable tests drive `deliver`/`receiveAny` without a network connection.
    // The public API surface is unchanged — this init is intentionally internal.
    #if DEBUG
    init(_testPseudonym: String) {
        self.pseudonym = _testPseudonym
        self.sessionID = "test"
        self.activeSessionID = "test"
        self.serverURL = ""
        // URLSession.shared.webSocketTask(with:) is the only public factory;
        // we create a dummy task to a local URL — it will never be resumed.
        self.task = URLSession.shared.webSocketTask(with: URL(string: "ws://127.0.0.1:0")!)
        self.defaultTimeout = 30
    }

    // Directly enqueue a frame into inbox (bypasses the socket loop).
    func _testEnqueue(_ frame: InboundFrame) {
        deliver(frame)
    }

    // Attempt a receiveAny with `timeout` seconds; returns true if a frame was
    // received, false if it timed out.  Does NOT throw — safe for XCTest.
    func _testTakeWithTimeout(_ timeout: TimeInterval) async -> Bool {
        do {
            _ = try await receiveAny(timeout: timeout)
            return true
        } catch {
            return false
        }
    }
    #endif

    public static func connect(serverURL: String, pseudonym: String, sessionID: String,
                               authSecret: String = "", authToken: String = "",
                               headers: [String: String] = [:],
                               resumeAfter: Int? = nil,
                               replayCursor: WSReplayCursor? = nil,
                               defaultTimeout: TimeInterval = 30) async throws -> Session {
        let request = try webSocketRequest(
            serverURL: serverURL,
            pseudonym: pseudonym,
            authSecret: authSecret,
            authToken: authToken,
            headers: headers,
            resumeAfter: resumeAfter,
            replayCursor: replayCursor
        )
        let task = URLSession.shared.webSocketTask(with: request)
        task.maximumMessageSize = 64 * 1024 * 1024
        task.resume()
        let base = serverURL.hasSuffix("/") ? String(serverURL.dropLast()) : serverURL
        let s = Session(pseudonym: pseudonym, sessionID: sessionID, serverURL: base,
                        task: task, defaultTimeout: defaultTimeout)
        await s.startReceiveLoop()
        return s
    }

    static func webSocketRequest(serverURL: String, pseudonym: String,
                                 authSecret: String = "", authToken: String = "",
                                 headers: [String: String] = [:],
                                 resumeAfter: Int? = nil,
                                 replayCursor: WSReplayCursor? = nil) throws -> URLRequest {
        guard var comps = URLComponents(string: serverURL) else { throw TransportError.dialFailed(serverURL) }
        comps.scheme = (comps.scheme == "https") ? "wss" : "ws"
        comps.path = "/v2/ws"
        var items = [URLQueryItem(name: "pseudonym", value: pseudonym)]
        if !authToken.isEmpty {
            items.append(URLQueryItem(name: "auth", value: authToken))
        } else if !authSecret.isEmpty {
            items.append(URLQueryItem(name: "auth", value: deriveAuthToken(secret: authSecret, pseudonym: pseudonym)))
        }
        if resumeAfter != nil, replayCursor != nil {
            throw TransportError.dialFailed("conflicting resume cursors")
        }
        if let replayCursor {
            items.append(URLQueryItem(name: "resume_after", value: String(replayCursor.sequence)))
        } else if let resumeAfter {
            guard resumeAfter >= 0 else { throw TransportError.dialFailed("negative resume cursor") }
            items.append(URLQueryItem(name: "resume_after", value: String(resumeAfter)))
        }
        comps.queryItems = items
        guard let url = comps.url else { throw TransportError.dialFailed(serverURL) }
        var request = URLRequest(url: url)
        for (name, value) in headers {
            request.setValue(value, forHTTPHeaderField: name)
        }
        return request
    }

    /// Update the session id used for outbound frames and admin-state polling.
    /// This supports queue-created sessions where the websocket is opened before
    /// the server-generated session id arrives in `session_invitation`.
    public func updateSessionID(_ sessionID: String) {
        activeSessionID = sessionID
    }

    private func startReceiveLoop() {
        let t = task
        Task { [weak self] in
            while true {
                guard let self else { break }
                let keepGoing = await self.receiveOne(from: t)
                if !keepGoing { break }
            }
        }
    }

    private func receiveOne(from wsTask: URLSessionWebSocketTask) async -> Bool {
        do {
            let msg = try await wsTask.receive()
            let data: Data
            switch msg {
            case .data(let d): data = d
            case .string(let str): data = Data(str.utf8)
            @unknown default: return !closed
            }
            if let frame = try? WSFrame.decodeInbound(data) { deliver(frame) }
            return !closed
        } catch {
            let transportError = TransportError.closed("\(pseudonym): \(error)")
            closed = true
            closeError = transportError
            failWaiters(transportError)
            return false
        }
    }

    private func deliver(_ frame: InboundFrame) {
        if !waiters.isEmpty {
            let w = waiters.removeFirst()
            w.cont.resume(returning: frame)
        } else {
            inbox.append(frame)
        }
    }

    private func failWaiters(_ err: any Error) {
        let ws = waiters
        waiters.removeAll()
        for w in ws { w.cont.resume(throwing: err) }
    }

    public func send(_ type: String, payloadJSON: Data? = nil, lineage: DAGNode? = nil, seq: Int = 0) async throws {
        if closed { throw TransportError.closed(pseudonym) }
        let frame = try WSFrame.encodeOutbound(type: type, sessionID: activeSessionID, seq: seq,
                                               payloadJSON: payloadJSON, lineage: lineage)
        try await task.send(.data(frame))
    }

    /// Send a device-signed protocol message. `fields` are the top-level
    /// (key, exact-JSON-value) pairs; the wire label is the message `type`
    /// (matches the server's `signedEventLabels`). See ``SignedPayload``.
    public func sendSigned(_ type: String, fields: [SignedPayload.Field],
                           identity: DeviceIdentity, seq: Int = 0) async throws {
        let wire = try SignedPayload.signed(label: type, sessionID: activeSessionID,
                                            fields: fields, identity: identity)
        try await send(type, payloadJSON: wire, seq: seq)
    }

    private func nextFrame(id: UUID) async throws -> InboundFrame {
        if !inbox.isEmpty { return inbox.removeFirst() }
        return try await withCheckedThrowingContinuation { cont in
            waiters.append((id: id, cont: cont))
        }
    }

    // Remove a waiter by id and resume its continuation with CancellationError so
    // the associated `nextFrame` task can unwind.  A CheckedContinuation that is
    // never resumed causes the waiting task to hang indefinitely (task cancellation
    // does not fire withCheckedThrowingContinuation), so we must always resume.
    private func removeWaiter(id: UUID) {
        if let idx = waiters.firstIndex(where: { $0.id == id }) {
            let w = waiters.remove(at: idx)
            w.cont.resume(throwing: CancellationError())
        }
    }

    public func receiveAny(timeout: TimeInterval? = nil) async throws -> InboundFrame {
        if let closeError {
            throw closeError
        }
        if closed {
            throw TransportError.closed(pseudonym)
        }
        if !inbox.isEmpty { return inbox.removeFirst() }
        let t = timeout ?? defaultTimeout
        let id = UUID()
        return try await withThrowingTaskGroup(of: InboundFrame.self) { group in
            group.addTask { try await self.nextFrame(id: id) }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(t * 1_000_000_000))
                throw TransportError.timeout("\(self.pseudonym): receiveAny")
            }
            do {
                let r = try await group.next()!
                group.cancelAll()
                return r
            } catch {
                group.cancelAll()
                self.removeWaiter(id: id)
                throw error
            }
        }
    }

    public func expect(_ type: String, timeout: TimeInterval? = nil) async throws -> InboundFrame {
        let deadline = Date().addingTimeInterval(timeout ?? defaultTimeout)
        var unmatched: [InboundFrame] = []
        while true {
            let remaining = deadline.timeIntervalSinceNow
            if remaining <= 0 {
                inbox.insert(contentsOf: unmatched, at: 0)
                throw TransportError.timeout("\(pseudonym): expect \(type)")
            }
            do {
                let f = try await receiveAny(timeout: remaining)
                if f.type == type {
                    inbox.insert(contentsOf: unmatched, at: 0)
                    return f
                }
                unmatched.append(f)
            } catch TransportError.timeout {
                inbox.insert(contentsOf: unmatched, at: 0)
                throw TransportError.timeout("\(pseudonym): expect \(type)")
            } catch {
                inbox.insert(contentsOf: unmatched, at: 0)
                throw error
            }
        }
    }

    public func awaitPhase(_ targetState: String, timeout: TimeInterval = 30) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        let sessionID = activeSessionID
        let url = URL(string: "\(serverURL)/admin/sessions/\(sessionID)")!
        while Date() < deadline {
            if let (data, resp) = try? await URLSession.shared.data(from: url),
               (resp as? HTTPURLResponse)?.statusCode == 200,
               let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               obj["state"] as? String == targetState {
                return
            }
            try await Task.sleep(nanoseconds: 100_000_000)
        }
        throw TransportError.timeout("\(pseudonym): awaitPhase \(targetState)")
    }

    public func close() {
        closed = true
        if closeError == nil {
            closeError = TransportError.closed(pseudonym)
        }
        task.cancel(with: .goingAway, reason: nil)
        failWaiters(closeError ?? TransportError.closed(pseudonym))
    }
}
