package com.libertyshield.agent.test

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import com.libertyshield.agent.ffi.RuntimeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * Sprint 209 — Foreground service wrapper for the two-phone test harness.
 *
 * Keeps [TestModeController] alive while the test runs.  Shows a persistent
 * notification with a "Stop" action so the test can be terminated without
 * unlocking the phone.
 *
 * The notification title and body explicitly call out TEST MODE so this cannot
 * be confused with a production service.
 *
 * Lifecycle:
 *   startService(TestModeService.startIntent(ctx, config))  →  onStartCommand
 *   ACTION_STOP intent or stopSelf()                        →  onDestroy
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
class TestModeService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var controller: TestModeController? = null

    companion object {
        const val ACTION_STOP = "com.libertyshield.agent.test.ACTION_STOP"
        private const val CHANNEL_ID = "liberty_test_channel"
        private const val NOTIF_ID = 9001

        /** Build a start intent carrying the peer configuration as extras. */
        fun startIntent(ctx: Context, config: PeerConfig): Intent =
            Intent(ctx, TestModeService::class.java).apply {
                putExtra("local_seed", config.localNodeSeed.toInt())
                putExtra("peer_seed", config.peerNodeSeed.toInt())
                putExtra("local_port", config.localUdpPort)
                putExtra("peer_ip", config.peerIp)
                putExtra("peer_port", config.peerUdpPort)
            }
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        val config = configFromIntent(intent)
        if (config == null) {
            LibertyLogger.error("TestModeService", "missing config in start intent")
            stopSelf()
            return START_NOT_STICKY
        }
        startForeground(NOTIF_ID, buildNotification())
        val ctrl = TestModeController(RuntimeBridge(), config)
        controller = ctrl
        scope.launch {
            val ok = ctrl.start()
            LibertyLogger.start(ok, "TestModeService")
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        controller?.stop()
        controller = null
        scope.cancel()
        LibertyLogger.stop(true, "TestModeService")
        super.onDestroy()
    }

    private fun configFromIntent(intent: Intent?): PeerConfig? {
        intent ?: return null
        val peerIp = intent.getStringExtra("peer_ip") ?: return null
        return PeerConfig(
            localNodeSeed = intent.getIntExtra("local_seed", 0x0A).toByte(),
            peerNodeSeed = intent.getIntExtra("peer_seed", 0x0B).toByte(),
            localUdpPort = intent.getIntExtra("local_port", 9000),
            peerIp = peerIp,
            peerUdpPort = intent.getIntExtra("peer_port", 9001),
        )
    }

    private fun buildNotification(): Notification {
        createChannel()
        val stopPi = PendingIntent.getService(
            this, 0,
            Intent(this, TestModeService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("[TEST MODE] Liberty Shield")
            .setContentText("NOT FOR PRODUCTION — test harness active")
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .addAction(
                Notification.Action.Builder(
                    null, "Stop", stopPi
                ).build()
            )
            .setOngoing(true)
            .build()
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            if (nm.getNotificationChannel(CHANNEL_ID) == null) {
                nm.createNotificationChannel(
                    NotificationChannel(CHANNEL_ID, "Liberty Test Mode", NotificationManager.IMPORTANCE_LOW)
                )
            }
        }
    }
}
