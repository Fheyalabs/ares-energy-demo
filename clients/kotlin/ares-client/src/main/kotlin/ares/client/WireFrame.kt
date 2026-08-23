// SPDX-License-Identifier: Apache-2.0

package ares.client

/**
 * v2 WebSocket outbound frame codec.
 *
 * Outbound JSON layout (stable field order, no extra whitespace):
 *   {"type":…,"session_id":…,"seq":N,"payload":<inlined verbatim>,"version":"2","lineage":{…}}
 *
 * Rules:
 *  - `payload` is omitted when null.
 *  - `version` and `lineage` are both omitted when lineage is null (v1 frame).
 *  - `lineage` is present (and `version` = "2") when a [DAGNode] is supplied.
 *
 * DAGNode wire JSON uses snake_case keys to match the Go `pkg/ares/lineage` json tags.
 */
object WireFrame {

    private fun esc(s: String): String =
        "\"" + s.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    /**
     * Encode an outbound WebSocket frame.
     *
     * @param type       message type string, e.g. `"vote.ballot"`
     * @param sessionID  session identifier
     * @param seq        monotonically increasing sequence number
     * @param payloadJson  raw payload JSON bytes, inlined verbatim (or null to omit)
     * @param lineage    optional SC-10 lineage node; non-null triggers v2 frame
     * @return UTF-8 encoded JSON frame bytes
     */
    fun encodeOutbound(
        type: String,
        sessionID: String,
        seq: Int,
        payloadJson: ByteArray?,
        lineage: DAGNode?,
    ): ByteArray {
        val parts = ArrayList<String>()
        parts.add("\"type\":${esc(type)}")
        parts.add("\"session_id\":${esc(sessionID)}")
        parts.add("\"seq\":$seq")
        if (payloadJson != null) {
            parts.add("\"payload\":${String(payloadJson, Charsets.UTF_8)}")
        }
        if (lineage != null) {
            parts.add("\"version\":\"2\"")
            parts.add("\"lineage\":${encodeNode(lineage)}")
        }
        return ("{" + parts.joinToString(",") + "}").toByteArray(Charsets.UTF_8)
    }

    /**
     * Encode a [DAGNode] to its v2 wire JSON object string.
     *
     * Key order and names mirror the Go `dagNodeJSON` struct tags exactly:
     * hash, session_id, phase_id, role, parents, parent_roles,
     * payload_hash, created_at, producer, signature, algorithm.
     */
    fun encodeNode(n: DAGNode): String {
        fun arr(xs: List<String>) = "[" + xs.joinToString(",") { esc(it) } + "]"
        return "{" + listOf(
            "\"hash\":${esc(n.hash)}",
            "\"session_id\":${esc(n.sessionId)}",
            "\"phase_id\":${esc(n.phaseId)}",
            "\"role\":${esc(n.role)}",
            "\"parents\":${arr(n.parents)}",
            "\"parent_roles\":${arr(n.parentRoles)}",
            "\"payload_hash\":${esc(n.payloadHash)}",
            "\"created_at\":${esc(n.createdAt)}",
            "\"producer\":${esc(n.producer)}",
            "\"signature\":${esc(n.signature)}",
            "\"algorithm\":${esc(n.algorithm)}",
        ).joinToString(",") + "}"
    }
}
