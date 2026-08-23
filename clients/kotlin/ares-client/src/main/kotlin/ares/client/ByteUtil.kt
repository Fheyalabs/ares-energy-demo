package ares.client

object ByteUtil {
    fun u32be(n: Int): ByteArray =
        byteArrayOf((n ushr 24).toByte(), (n ushr 16).toByte(), (n ushr 8).toByte(), n.toByte())

    fun lp(b: ByteArray): ByteArray = u32be(b.size) + b

    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append("%02x".format(x.toInt() and 0xff))
        return sb.toString()
    }

    fun fromHex(s: String): ByteArray? {
        if (s.length % 2 != 0) return null
        val out = ByteArray(s.length / 2)
        var i = 0
        while (i < s.length) {
            val v = s.substring(i, i + 2).toIntOrNull(16) ?: return null
            out[i / 2] = v.toByte(); i += 2
        }
        return out
    }
}
