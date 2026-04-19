package com.libertyshield.agent

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import androidx.core.app.NotificationCompat
import android.net.VpnService
import com.libertyshield.agent.monitors.AppMonitor
import com.libertyshield.agent.monitors.SensorMonitor
import com.libertyshield.agent.vpn.ShieldVpnService

class ShieldService : Service() {

    private lateinit var client: GatewayClient
    private lateinit var appMonitor: AppMonitor
    private lateinit var sensorMonitor: SensorMonitor

    override fun onCreate() {
        super.onCreate()
        startAsForeground()

        val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)

        client = GatewayClient(
            context    = this,
            gatewayUrl = "http://10.0.2.2:8080/sensor/event",  // 10.0.2.2 = emulator host loopback
            deviceId   = deviceId,
        )

        appMonitor    = AppMonitor(this, client)
        sensorMonitor = SensorMonitor(this, client)

        appMonitor.start()
        sensorMonitor.start()
        startVpnTelemetry()
    }

    override fun onDestroy() {
        sensorMonitor.stop()
        appMonitor.stop()
        stopService(Intent(this, ShieldVpnService::class.java))
        client.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startVpnTelemetry() {
        if (VpnService.prepare(this) != null) {
            // Permission not yet granted — start VpnPermissionActivity to show the system dialog.
            val i = Intent(this, VpnPermissionActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            startActivity(i)
        } else {
            val i = Intent(this, ShieldVpnService::class.java)
                .setAction(ShieldVpnService.ACTION_START)
            startService(i)
        }
    }

    private fun startAsForeground() {
        val channelId = "liberty_shield_channel"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "Liberty Shield",
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(this, channelId)
            .setContentTitle("Liberty Shield")
            .setContentText("Telemetry active")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .build()
        startForeground(1, notification)
    }
}
