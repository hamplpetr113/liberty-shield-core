package com.libertyshield.agent

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.provider.Settings
import androidx.core.app.NotificationCompat
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
            gatewayUrl = BuildConfig.GATEWAY_URL,
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
        startService(Intent(this, ShieldVpnService::class.java)
            .setAction(ShieldVpnService.ACTION_STOP))
        client.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startVpnTelemetry() {
        // VPN consent is obtained by LauncherActivity before this service starts.
        // ShieldVpnService.startVpn() handles revoked permission via FAILED state.
        startForegroundService(Intent(this, ShieldVpnService::class.java)
            .setAction(ShieldVpnService.ACTION_START))
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(1, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(1, notification)
        }
    }
}
