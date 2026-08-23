// SPDX-License-Identifier: Apache-2.0
package ares.smoke

import kotlin.system.exitProcess

fun main(argv: Array<String>) {
    fun arg(name: String, def: String?): String? {
        val i = argv.indexOf(name)
        return if (i >= 0 && i + 1 < argv.size) argv[i + 1] else def
    }
    val sub    = argv.firstOrNull() ?: ""
    val server = arg("--server", System.getenv("ARES_SERVER") ?: "http://localhost:8000")!!
    val n      = (arg("--participants", "3") ?: "3").toInt()
    val secret = arg("--auth-secret", System.getenv("ARES_WS_SECRET") ?: "")!!
    val sid    = arg("--session-id", "$sub-${System.currentTimeMillis() / 1000}")!!
    val mode   = arg("--mode", "inbound") ?: "inbound"
    val code   = try {
        when (sub) {
            "voting" -> VotingFlow.run(server, n, secret, sid)
            "auction" -> AuctionFlow.run(server, n, secret, sid)
            "boundcheck" -> BoundCheckFlow.run(server, n, secret, sid, mode)
            else -> {
                System.err.println("usage: ares-smoke {voting|auction|boundcheck} --server URL --participants N")
                2
            }
        }
    } catch (e: Exception) {
        System.err.println("error: $e")
        1
    }
    exitProcess(code)
}
