// SPDX-License-Identifier: Apache-2.0

package ares.client.transport

import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

/**
 * Thin REST wrapper for the ARES admin API.
 *
 * Mirrors Swift [AdminClient] semantics. All calls are synchronous and safe to
 * invoke from any thread.
 *
 * Endpoints used:
 *  - `GET  /admin/health`            → 200 on healthy
 *  - `POST /admin/sessions`          → 201 on success
 *  - `GET  /admin/sessions/{id}`     → `{"state":"..."}` JSON
 *
 * @param serverURL  base server URL, e.g. `http://localhost:8080` (trailing
 *                   slash is stripped automatically)
 */
class AdminClient(serverURL: String) {
    private val base    = serverURL.trimEnd('/')
    private val http    = OkHttpClient()
    private val stateRe = Regex("\"state\"\\s*:\\s*\"([^\"]*)\"")
    private val jsonMT  = "application/json".toMediaType()

    /**
     * Check whether the server is healthy (HTTP 200 on `/admin/health`).
     *
     * @return true if the server replied 200, false otherwise
     */
    fun health(): Boolean =
        runCatching {
            http.newCall(Request.Builder().url("$base/admin/health").build())
                .execute().use { it.isSuccessful }
        }.getOrDefault(false)

    /**
     * Block until the server reports healthy or [timeoutMs] elapses.
     *
     * Polls every 200 ms.
     *
     * @throws TransportException if the server does not become healthy in time
     */
    fun waitForHealth(timeoutMs: Long = 15_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (health()) return
            Thread.sleep(200)
        }
        throw TransportException("AdminClient: server health timeout after ${timeoutMs}ms")
    }

    /**
     * Create a new ARES session via `POST /admin/sessions`.
     *
     * Request body: `{"session_id":<id>,"participants":[...],"attrs":{...}}`.
     * The `attrs` object is omitted when empty.
     *
     * @throws TransportException if the server does not return HTTP 201
     */
    fun startSession(
        sessionID: String,
        participants: List<String>,
        attrs: Map<String, String> = emptyMap(),
    ) {
        val sb = StringBuilder()
        sb.append("{\"session_id\":\"$sessionID\",\"participants\":[")
        sb.append(participants.joinToString(",") { "\"$it\"" })
        sb.append("]")
        if (attrs.isNotEmpty()) {
            sb.append(",\"attrs\":{")
            sb.append(attrs.entries.joinToString(",") { "\"${it.key}\":\"${it.value}\"" })
            sb.append("}")
        }
        sb.append("}")
        val body = sb.toString().toRequestBody(jsonMT)
        http.newCall(
            Request.Builder().url("$base/admin/sessions").post(body).build()
        ).execute().use { resp ->
            if (resp.code != 201) {
                throw TransportException(
                    "startSession: HTTP ${resp.code}: ${resp.body?.string()}"
                )
            }
        }
    }

    /**
     * Fetch the current state of session [sessionID] from `GET /admin/sessions/{id}`.
     *
     * @return state string (e.g. `"anon_gossip"`), or empty string on any error
     */
    fun getState(sessionID: String): String =
        runCatching {
            http.newCall(
                Request.Builder().url("$base/admin/sessions/$sessionID").build()
            ).execute().use { resp ->
                if (!resp.isSuccessful) return ""
                stateRe.find(resp.body?.string() ?: "")?.groupValues?.get(1) ?: ""
            }
        }.getOrDefault("")

    /**
     * Poll until the session reaches [terminal] state or [tries] is exhausted.
     *
     * @param terminal   target terminal state string
     * @param tries      maximum number of polling attempts (default 40)
     * @param intervalMs sleep between attempts in milliseconds (default 500)
     * @return last observed state (may not equal [terminal] if polling exhausted)
     */
    fun pollUntilTerminal(
        sessionID: String,
        terminal: String,
        tries: Int = 40,
        intervalMs: Long = 500,
    ): String {
        var last = ""
        repeat(tries) {
            last = runCatching { getState(sessionID) }.getOrDefault(last)
            if (last.isEmpty() || last == terminal) return last
            Thread.sleep(intervalMs)
        }
        return last
    }
}
