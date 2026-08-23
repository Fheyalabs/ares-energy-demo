// SPDX-License-Identifier: Apache-2.0

package ares.client.transport

import ares.client.DAGNode
import ares.client.Signing
import ares.client.WireFrame
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit

/** A client-owned, durably persisted position in a recipient's server outbox. */
data class WSReplayCursor(val sequence: Long) {
    init {
        require(sequence >= 0) { "replay cursor must be non-negative" }
    }
}

/** A single inbound WebSocket frame with decoded routing fields and exact bytes. */
class InboundFrame(
    val type: String,
    val sessionId: String,
    val seq: Long,
    val raw: ByteArray
)

/** Signals a transport-level error (dial failure, send failure, timeout, etc.). */
class TransportException(msg: String) : RuntimeException(msg)

/**
 * OkHttp WebSocket session — v2 ARES wire protocol.
 *
 * Mirrors Swift [Session] and Python [session.Session] semantics:
 *  - WS URL: `ws(s)://host/v2/ws?pseudonym=<p>&auth=<hmac>`
 *  - Auth token: `HMAC-SHA256(authSecret, pseudonym)` hex (omitted if secret is empty)
 *  - Outbound frames encoded by [WireFrame.encodeOutbound]
 *  - Inbound frames are buffered in an unlimited channel; [receiveAny] / [expect]
 *    drain the channel with optional timeouts
 *
 * All blocking methods use [runBlocking] with [withTimeoutOrNull] so they can be
 * called safely from plain (non-coroutine) JVM threads.
 */
class Session private constructor(
    /** Participant pseudonym. */
    val pseudonym: String,
    /** ARES session identifier. */
    val sessionID: String,
    private val serverURL: String,
    private val ws: WebSocket,
    private val inbox: Channel<InboundFrame>,
) {
    companion object {
        private val typeRe = Regex("\"type\"\\s*:\\s*\"([^\"]*)\"")
        private val sidRe  = Regex("\"session_id\"\\s*:\\s*\"([^\"]*)\"")
        private val seqRe  = Regex("\"seq\"\\s*:\\s*(-?\\d+)")

        /**
         * Open a WebSocket connection to [serverURL] as participant [pseudonym].
         *
         * @param serverURL   base server URL, e.g. `http://localhost:8080`
         * @param pseudonym   participant pseudonym
         * @param sessionID   ARES session identifier (embedded in outbound frames)
         * @param authSecret  shared HMAC secret; empty string skips auth query param
         * @throws TransportException if OkHttp immediately rejects the request
         */
        fun connect(
            serverURL: String,
            pseudonym: String,
            sessionID: String,
            authSecret: String = "",
            replayCursor: WSReplayCursor? = null,
        ): Session {
            val url = webSocketURL(serverURL, pseudonym, authSecret, replayCursor)
            val trimmed = serverURL.trimEnd('/')
            val client = OkHttpClient.Builder()
                .readTimeout(0, TimeUnit.MILLISECONDS)
                .pingInterval(20, TimeUnit.SECONDS)
                .build()
            val inbox = Channel<InboundFrame>(Channel.UNLIMITED)
            val listener = object : WebSocketListener() {
                override fun onMessage(webSocket: WebSocket, text: String)  { deliver(text.encodeToByteArray()) }
                override fun onMessage(webSocket: WebSocket, bytes: ByteString) { deliver(bytes.toByteArray()) }
                private fun deliver(raw: ByteArray) { inbox.trySend(decodeInbound(raw)) }
            }
            val ws = client.newWebSocket(Request.Builder().url(url).build(), listener)
            return Session(pseudonym, sessionID, trimmed, ws, inbox)
        }

        internal fun webSocketURL(
            serverURL: String,
            pseudonym: String,
            authSecret: String = "",
            replayCursor: WSReplayCursor? = null,
        ): String {
            val trimmed = serverURL.trimEnd('/')
            val scheme = if (trimmed.startsWith("https")) "wss" else "ws"
            val host = trimmed.removePrefix("https://").removePrefix("http://")
            var url = "$scheme://$host/v2/ws?pseudonym=$pseudonym"
            if (authSecret.isNotEmpty()) {
                url += "&auth=${Signing.authToken(authSecret, pseudonym)}"
            }
            replayCursor?.let { url += "&resume_after=${it.sequence}" }
            return url
        }

        internal fun decodeInbound(raw: ByteArray): InboundFrame {
            val text = raw.decodeToString()
            val type = typeRe.find(text)?.groupValues?.get(1) ?: ""
            val sessionID = sidRe.find(text)?.groupValues?.get(1) ?: ""
            val sequence = seqRe.find(text)?.groupValues?.get(1)?.toLongOrNull() ?: 0L
            return InboundFrame(type, sessionID, sequence, raw.copyOf())
        }
    }

    /**
     * Encode and send one outbound WebSocket frame.
     *
     * @param type        message type string, e.g. `"vote.ballot"`
     * @param payloadJson raw payload JSON bytes to inline (or null to omit)
     * @param lineage     optional SC-10 lineage node; non-null triggers v2 frame
     * @param seq         monotonically increasing sequence number (default 0)
     * @throws TransportException if OkHttp reports the send failed
     */
    fun send(
        type: String,
        payloadJson: ByteArray? = null,
        lineage: DAGNode? = null,
        seq: Int = 0,
    ) {
        val frame = WireFrame.encodeOutbound(type, sessionID, seq, payloadJson, lineage)
        if (!ws.send(frame.toByteString())) {
            throw TransportException("$pseudonym: ws send failed for type=$type")
        }
    }

    /** Sends a previously validated, canonical wire frame without re-encoding it. */
    fun sendRaw(frame: ByteArray) {
        require(frame.isNotEmpty()) { "raw websocket frame is required" }
        if (!ws.send(frame.toByteString())) {
            throw TransportException("$pseudonym: raw ws send failed")
        }
    }

    /**
     * Wait for the next inbound frame (any type).
     *
     * @param timeoutMs maximum wait in milliseconds (default 30 000)
     * @throws TransportException on timeout
     */
    fun receiveAny(timeoutMs: Long = 30_000): InboundFrame = runBlocking {
        withTimeoutOrNull(timeoutMs) { inbox.receive() }
            ?: throw TransportException("$pseudonym: receiveAny timeout after ${timeoutMs}ms")
    }

    /**
     * Wait for the next inbound frame whose `type` equals [type], discarding
     * frames of other types encountered along the way.
     *
     * @param type      expected frame type
     * @param timeoutMs deadline from now in milliseconds (default 30 000)
     * @throws TransportException if the deadline passes without a matching frame
     */
    fun expect(type: String, timeoutMs: Long = 30_000): InboundFrame {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (true) {
            val remaining = deadline - System.currentTimeMillis()
            if (remaining <= 0) throw TransportException("$pseudonym: expect \"$type\" timeout")
            val f = receiveAny(remaining)
            if (f.type == type) return f
        }
    }

    /**
     * Poll the admin REST endpoint until the session reaches [targetState].
     *
     * Uses [AdminClient.getState] on a 100 ms interval.
     *
     * @param targetState  desired session state string, e.g. `"anon_gossip"`
     * @param timeoutMs    overall deadline in milliseconds (default 30 000)
     * @throws TransportException on timeout
     */
    fun awaitPhase(targetState: String, timeoutMs: Long = 30_000) {
        val deadline = System.currentTimeMillis() + timeoutMs
        val admin = AdminClient(serverURL)
        while (System.currentTimeMillis() < deadline) {
            if (admin.getState(sessionID) == targetState) return
            Thread.sleep(100)
        }
        throw TransportException("$pseudonym: awaitPhase \"$targetState\" timeout after ${timeoutMs}ms")
    }

    /** Close the underlying WebSocket and the inbound channel. */
    fun close() {
        runCatching { ws.close(1000, "bye") }
        inbox.close()
    }
}
