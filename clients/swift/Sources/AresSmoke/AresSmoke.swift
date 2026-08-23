// SPDX-License-Identifier: Apache-2.0

import Foundation

func arg(_ name: String, _ def: String? = nil) -> String? {
    let a = CommandLine.arguments
    if let i = a.firstIndex(of: name), i + 1 < a.count { return a[i + 1] }
    return def
}

@main
struct AresSmokeEntry {
    static func main() async {
        let sub = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""
        let server = arg("--server", ProcessInfo.processInfo.environment["ARES_SERVER"] ?? "http://localhost:8000")!
        let participants = Int(arg("--participants", "3")!) ?? 3
        let authSecret = arg("--auth-secret", ProcessInfo.processInfo.environment["ARES_WS_SECRET"] ?? "")!
        let sessionID = arg("--session-id", "\(sub)-\(Int(Date().timeIntervalSince1970))")!
        let mode = arg("--mode", "inbound") ?? "inbound"

        let code: Int32
        do {
            switch sub {
            case "auction":
                code = Int32(try await AuctionFlow.run(serverURL: server, participants: participants,
                    authSecret: authSecret, sessionID: sessionID))
            case "voting":
                code = Int32(try await VotingFlow.run(serverURL: server, participants: participants,
                    authSecret: authSecret, sessionID: sessionID))
            case "boundcheck":
                code = Int32(try await BoundCheckFlow.run(serverURL: server, participants: participants,
                    authSecret: authSecret, sessionID: sessionID, mode: mode))
            default:
                FileHandle.standardError.write(Data("usage: AresSmoke {auction|voting|boundcheck} --server URL --participants N\n".utf8))
                code = 2
            }
        } catch {
            FileHandle.standardError.write(Data("error: \(error)\n".utf8))
            code = 1
        }
        exit(code)
    }
}
