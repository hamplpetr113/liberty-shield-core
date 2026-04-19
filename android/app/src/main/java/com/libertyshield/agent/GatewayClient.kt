package com.libertyshield.agent

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import com.libertyshield.agent.models.SensorEvent
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
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    init {
        scope.launch { sendLoop() }
    }

    fun enqueue(event: SensorEvent) {
        synchronized(queue) { queue.addLast(event.toJson(deviceId)) }
    }

    private suspend fun sendLoop() {
        var backoffMs = 2_000L
        while (scope.isActive) {
            val item = synchronized(queue) { queue.peekFirst() }
            if (item != null && isOnline()) {
                if (post(item)) {
                    synchronized(queue) { queue.pollFirst() }
                    backoffMs = 2_000L
                } else {
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
}
