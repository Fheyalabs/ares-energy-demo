// SPDX-License-Identifier: Apache-2.0

package ares.smoke

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets

internal fun strictUTF8(raw: ByteArray): String = try {
    StandardCharsets.UTF_8
        .newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(raw))
        .toString()
} catch (error: java.nio.charset.CharacterCodingException) {
    throw IllegalArgumentException("raw transport frame is not valid UTF-8", error)
}
