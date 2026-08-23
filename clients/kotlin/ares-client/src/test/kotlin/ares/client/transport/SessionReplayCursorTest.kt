// SPDX-License-Identifier: Apache-2.0

package ares.client.transport

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class SessionReplayCursorTest {
    @Test fun replayCursorRejectsNegativeSequence() {
        assertFailsWith<IllegalArgumentException> { WSReplayCursor(-1) }
    }

    @Test fun typedReplayCursorBuildsExactResumeAfterURL() {
        val url = Session.webSocketURL(
            serverURL = "https://api.example.test/base",
            pseudonym = "bidder-00",
            authSecret = "",
            replayCursor = WSReplayCursor(9_223_372_036_854_775L)
        )

        assertEquals(
            "wss://api.example.test/base/v2/ws?pseudonym=bidder-00&resume_after=9223372036854775",
            url
        )
    }

    @Test fun inboundFramePreservesPositiveServerSequence() {
        val raw = "{ \"type\": \"session.invitation\", \"session_id\": \"s1\", \"seq\": 17, \"payload\": {\"frame\":\"////\"} }".encodeToByteArray()
        val frame = Session.decodeInbound(raw)

        assertEquals(17, frame.seq)
        assertContentEquals(raw, frame.raw)
    }
}
