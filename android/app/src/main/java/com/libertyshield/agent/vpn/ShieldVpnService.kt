package com.libertyshield.agent.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.libertyshield.agent.GatewayClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

class ShieldVpnService : VpnService() {

    companion object {
        const val ACTION_START = "com.libertyshield.agent.VPN_START"
        const val ACTION_STOP  = "com.libertyshield.agent.VPN_STOP"
        private const val TAG  = "ShieldVpnService"
        private const val NOTIF_ID = 2
        private const val CHANNEL_ID = "liberty_shield_vpn_channel"
    }

    private var tun: android.os.ParcelFileDescriptor? = null
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var client: GatewayClient

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

    private fun startVpn() {
        Log.i(TAG, "VPN telemetry starting")
        startAsForeground()

        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
        client = GatewayClient(
            context    = this,
            gatewayUrl = "http://10.0.2.2:8080/sensor/event",
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
                Log.e(TAG, "establish() returned null — VPN permission missing or revoked")
                stopSelf()
                return
            }

        Log.i(TAG, "TUN interface established")

        val tunFd = tun!!
        scope.launch {
            try {
                PacketReader(
                    stream    = FileInputStream(tunFd.fileDescriptor),
                    forwarder = PacketForwarder(this@ShieldVpnService, FileOutputStream(tunFd.fileDescriptor)),
                    parser    = PacketParser(),
                    tracker   = ConnectionTracker(this@ShieldVpnService),
                    client    = client,
                ).run()
            } catch (e: IOException) {
                Log.w(TAG, "PacketReader exited: ${e.message}")
            }
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "VPN telemetry stopping")
        scope.cancel()
        tun?.close()
        tun = null
        if (::client.isInitialized) client.shutdown()
        stopSelf()
    }

    private fun startAsForeground() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Liberty Shield VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val notification = androidx.core.app.NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Liberty Shield")
            .setContentText("Network telemetry active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(NOTIF_ID, notification)
    }
}
