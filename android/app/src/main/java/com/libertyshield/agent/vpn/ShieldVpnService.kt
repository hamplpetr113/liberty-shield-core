package com.libertyshield.agent.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.libertyshield.agent.BuildConfig
import com.libertyshield.agent.GatewayClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

class ShieldVpnService : VpnService() {

    // ── Runtime state ─────────────────────────────────────────────────────────

    private enum class VpnState { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

    @Volatile private var vpnState: VpnState = VpnState.STOPPED

    /** Log every state change; warn (and skip) on duplicate transitions. */
    private fun transition(to: VpnState) {
        val from = vpnState
        if (from == to) {
            Log.w(TAG, "VPN state already $to — duplicate transition ignored")
            return
        }
        vpnState = to
        Log.i(TAG, "VPN [$from → $to]")
    }

    // ── Fields ────────────────────────────────────────────────────────────────

    private var tun: android.os.ParcelFileDescriptor? = null
    private var forwarder: PacketForwarder? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var client: GatewayClient

    // ── Service lifecycle ─────────────────────────────────────────────────────

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { stopVpn(); START_NOT_STICKY }
            else        -> { startVpn(); START_STICKY }
        }
    }

    override fun onBind(intent: android.content.Intent?): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by system")
        stopVpn()
        super.onRevoke()
    }

    /** Safety net: system-initiated destroy must clean up even if ACTION_STOP was never sent. */
    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // ── VPN start / stop ──────────────────────────────────────────────────────

    private fun startVpn() {
        if (vpnState != VpnState.STOPPED) {
            Log.w(TAG, "startVpn() called in state $vpnState — ignoring duplicate start")
            return
        }
        transition(VpnState.STARTING)
        startAsForeground()

        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        client = GatewayClient(
            context    = this,
            gatewayUrl = BuildConfig.GATEWAY_URL,
            deviceId   = deviceId,
        )

        tun = Builder()
            .setSession("Liberty Shield")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setMtu(1500)
            .addDisallowedApplication(packageName)
            .establish()
            ?: run {
                Log.e(TAG, "VPN establish() returned null — permission missing or revoked")
                transition(VpnState.FAILED)
                stopSelf()
                return
            }

        Log.i(TAG, "TUN interface established")

        val tunFd = tun!!
        val fwd = PacketForwarder(this@ShieldVpnService, FileOutputStream(tunFd.fileDescriptor))
        forwarder = fwd
        scope.launch {
            try {
                PacketReader(
                    stream    = FileInputStream(tunFd.fileDescriptor),
                    forwarder = fwd,
                    parser    = PacketParser(),
                    tracker   = ConnectionTracker(this@ShieldVpnService),
                    client    = client,
                ).run()
                Log.i(TAG, "PacketReader exited cleanly")
            } catch (e: IOException) {
                Log.w(TAG, "PacketReader exited: ${e.message}")
            }
        }
        startHeartbeat()
        transition(VpnState.RUNNING)
    }

    private fun stopVpn() {
        if (vpnState == VpnState.STOPPED || vpnState == VpnState.STOPPING) {
            Log.w(TAG, "stopVpn() called in state $vpnState — ignoring")
            return
        }
        transition(VpnState.STOPPING)
        // Close the TUN fd first so PacketReader.run()'s blocking stream.read() throws
        // IOException immediately and the coroutine exits before we cancel the scope.
        tun?.close()
        tun = null
        forwarder?.shutdown()
        forwarder = null
        scope.cancel()
        if (::client.isInitialized) client.shutdown()
        transition(VpnState.STOPPED)
        stopSelf()
    }

    // ── Heartbeat ─────────────────────────────────────────────────────────────

    private fun startHeartbeat() {
        scope.launch {
            while (isActive) {
                delay(HEARTBEAT_MS)
                Log.i(TAG, "heartbeat state=$vpnState ${VpnStats.summary()}")
            }
        }
    }

    // ── Foreground notification ───────────────────────────────────────────────

    private fun startAsForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Liberty Shield VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Liberty Shield")
            .setContentText("Network telemetry active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(NOTIF_ID, notification)
    }

    companion object {
        const val ACTION_START   = "com.libertyshield.agent.VPN_START"
        const val ACTION_STOP    = "com.libertyshield.agent.VPN_STOP"
        private const val TAG          = "ShieldVpnService"
        private const val NOTIF_ID     = 2
        private const val CHANNEL_ID   = "liberty_shield_vpn_channel"
        private const val HEARTBEAT_MS = 5_000L
    }
}
