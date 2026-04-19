package com.libertyshield.agent.monitors

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import com.libertyshield.agent.GatewayClient
import com.libertyshield.agent.models.SensorEvent

// Detects network availability changes via ConnectivityManager.NetworkCallback.
// Note: this reports transport-layer changes (wifi/cellular), NOT per-connection
// remote IPs or ports. Real per-app network attribution requires a VpnService.
class NetworkMonitor(
    private val context: Context,
    private val client: GatewayClient,
) {
    private val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            val transport = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)     -> "wifi"
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
                else -> "other"
            }
            client.enqueue(SensorEvent.NetworkConnection(
                remoteIp   = "transport:$transport",
                remotePort = 0,
                pid        = null,
            ))
        }
    }

    fun start() {
        val req = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        cm.registerNetworkCallback(req, callback)
    }

    fun stop() = runCatching { cm.unregisterNetworkCallback(callback) }
}
