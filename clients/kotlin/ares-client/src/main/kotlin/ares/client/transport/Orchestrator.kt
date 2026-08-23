// SPDX-License-Identifier: Apache-2.0

package ares.client.transport

/**
 * Utility that connects and disconnects multiple [Session] instances.
 *
 * Mirrors Swift [Orchestrator] semantics. Sessions are opened serially so that
 * individual failures are attributed to their pseudonym.
 */
object Orchestrator {
    /**
     * Open one [Session] per pseudonym in [pseudonyms], all joining [sessionID].
     *
     * @param serverURL   base server URL passed to [Session.connect]
     * @param pseudonyms  ordered list of participant pseudonyms
     * @param sessionID   ARES session identifier shared by all participants
     * @param authSecret  shared HMAC secret; empty string disables auth
     * @return list of connected sessions in the same order as [pseudonyms]
     */
    fun connectAll(
        serverURL: String,
        pseudonyms: List<String>,
        sessionID: String,
        authSecret: String,
    ): List<Session> = pseudonyms.map { Session.connect(serverURL, it, sessionID, authSecret) }

    /**
     * Close all sessions, swallowing individual errors so that a single failure
     * does not prevent the remaining sessions from being cleaned up.
     */
    fun closeAll(sessions: List<Session>) {
        sessions.forEach { runCatching { it.close() } }
    }
}
