package com.libertyshield.agent

import android.content.Context
import android.net.ConnectivityManager
import android.util.Log
import android.net.NetworkCapabilities
import com.libertyshield.agent.models.SensorEvent
import com.libertyshield.agent.vpn.VpnStats
import kotlinx.coroutines.*
import java.net.HttpURLConnection
import java.net.URL
import java.util.ArrayDeque

class GatewayClient(
    private val context: Context,
    private val gatewayUrl: String,
    private val deviceId: String,
) {
    private val queue = ArrayDeque<String>()
    private var lastQueueOverflowLogMs = 0L
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    init {
        scope.launch { sendLoop() }
    }

    fun enqueue(event: SensorEvent) {
        synchronized(queue) {
            if (queue.size >= MAX_QUEUE_SIZE) {
                VpnStats.gwQueueRejected.incrementAndGet()
                val now = System.currentTimeMillis()
                if (now - lastQueueOverflowLogMs >= OVERFLOW_LOG_INTERVAL_MS) {
                    lastQueueOverflowLogMs = now
                    Log.w(TAG, "Gateway queue cap ($MAX_QUEUE_SIZE) reached — dropping telemetry event")
                }
                return
            }
            queue.addLast(event.toJson(deviceId))
        }
    }

    private suspend fun sendLoop() {
        var backoffMs = 2_000L
        while (scope.isActive) {
            val item = synchronized(queue) { queue.peekFirst() }
            if (item != null && isOnline()) {
                if (post(item)) {
                    VpnStats.gwPostOk.incrementAndGet()
                    synchronized(queue) { queue.pollFirst() }
                    backoffMs = 2_000L
                } else {
                    VpnStats.gwPostFail.incrementAndGet()
                    delay(backoffMs)
                    backoffMs = (backoffMs * 2).coerceAtMost(60_000L)
                }
            } else {
                delay(backoffMs)
            }
        }
    }

    private fun post(json: String): Boolean = runCatching {
        val conn = URL(gatewayUrl).openConnection() as HttpURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 5_000
        conn.readTimeout = 5_000
        conn.outputStream.use { it.write(json.toByteArray()) }
        conn.responseCode in 200..299
    }.getOrDefault(false)

    private fun isOnline(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    fun shutdown() = scope.cancel()

    companion object {
        private const val TAG = "GatewayClient"
        private const val MAX_QUEUE_SIZE = 2048
        private const val OVERFLOW_LOG_INTERVAL_MS = 10_000L
    }
}
