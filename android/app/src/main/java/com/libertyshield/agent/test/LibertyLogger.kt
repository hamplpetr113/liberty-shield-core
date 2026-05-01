package com.libertyshield.agent.test

import android.util.Log

/**
 * Sprint 208 — Diagnostic logger for the Liberty Shield test harness.
 *
 * Every message is prefixed with LIBERTY_TEST so it can be grepped from adb logcat:
 *   adb logcat -s LIBERTY_TEST
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
object LibertyLogger {

    private const val TAG = "LIBERTY_TEST"

    fun init(result: Boolean, detail: String = "") =
        log("INIT", if (result) "OK" else "FAIL", detail)

    fun start(result: Boolean, detail: String = "") =
        log("START", if (result) "OK" else "FAIL", detail)

    fun stop(result: Boolean, detail: String = "") =
        log("STOP", if (result) "OK" else "FAIL", detail)

    fun udpBind(port: Int, result: Boolean, detail: String = "") =
        log("UDP_BIND", "port=$port result=${if (result) "OK" else "FAIL"}", detail)

    fun udpSend(bytes: Int, peer: String, result: Boolean) =
        log("UDP_SEND", "bytes=$bytes to=$peer result=${if (result) "OK" else "FAIL"}")

    fun udpRecv(bytes: Int, from: String) =
        log("UDP_RECV", "bytes=$bytes from=$from")

    fun ingest(bytes: Int, result: Boolean) =
        log("INGEST", "bytes=$bytes result=${if (result) "OK" else "FAIL"}")

    fun poll(result: String) =
        log("POLL", result)

    fun tick(n: Int, result: Boolean) =
        log("TICK", "n=$n result=${if (result) "OK" else "FAIL"}")

    fun ping(seqNo: Int) = log("PING_SEND", "seq=$seqNo")

    fun pong(seqNo: Int) = log("PONG_RECV", "seq=$seqNo")

    fun error(where_: String, msg: String) =
        Log.e(TAG, "[$where_] ERROR: $msg")

    fun status(label: String) = log("STATUS", label)

    private fun log(event: String, msg: String, detail: String = "") {
        val line = if (detail.isNotEmpty()) "[$event] $msg — $detail" else "[$event] $msg"
        Log.i(TAG, line)
    }
}
