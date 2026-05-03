package com.libertyshield.agent.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.FileInputStream
import java.io.FileOutputStream

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
    private var scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private lateinit var client: GatewayClient

    // ── Service lifecycle ─────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate")
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> { recordStopReason("ACTION_STOP"); stopVpn(); START_NOT_STICKY }
            else        -> {
                startVpn()
                // If VPN failed to establish, don't let Android restart us into an infinite loop.
                if (vpnState == VpnState.FAILED) START_NOT_STICKY else START_STICKY
            }
        }
    }

    override fun onBind(intent: android.content.Intent?): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by system")
        recordStopReason("SYSTEM_REVOKE")
        stopVpn()
        super.onRevoke()
    }

    /** Safety net: system-initiated destroy must clean up even if ACTION_STOP was never sent. */
    override fun onDestroy() {
        Log.i(TAG, "onDestroy vpnState=$vpnState")
        if (vpnState != VpnState.STOPPED && vpnState != VpnState.STOPPING) {
            recordStopReason("ON_DESTROY state=$vpnState")
        }
        stopVpn()
        super.onDestroy()
    }

    // ── Shutdown diagnostics ──────────────────────────────────────────────────

    private fun recordStopReason(reason: String, error: Throwable? = null) {
        VpnStats.vpnLastStopReason.set(reason)
        VpnStats.vpnStopCount.incrementAndGet()
        VpnStats.vpnLastStopTimestampMs.set(System.currentTimeMillis())
        if (error != null) {
            VpnStats.vpnLastExceptionClass.set(error.javaClass.simpleName)
            VpnStats.vpnLastExceptionMessage.set(error.message ?: "")
        }
        Log.w("VPN_STOP", "reason=$reason state=$vpnState error=${error?.javaClass?.simpleName}: ${error?.message}", error)
    }

    // ── VPN start / stop ──────────────────────────────────────────────────────

    private fun startVpn() {
        if (vpnState != VpnState.STOPPED) {
            Log.w(TAG, "startVpn() called in state $vpnState — ignoring duplicate start")
            return
        }
        transition(VpnState.STARTING)
        // Fresh scope on every start — the previous scope was cancelled by stopVpn() and
        // launching into a cancelled scope throws JobCancellationException, which made the
        // PacketReader silently never run while the TUN was up (no internet, ERR_NETWORK_CHANGED).
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        try {
            Log.i(TAG, "step 1: startForeground")
            startAsForeground()

            Log.i(TAG, "step 2: init GatewayClient")
            val deviceId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
            client = GatewayClient(
                context    = this,
                gatewayUrl = BuildConfig.GATEWAY_URL,
                deviceId   = deviceId,
            )

            Log.i(TAG, "step 3: Builder.establish()")
            tun = Builder()
                .setSession("Liberty Shield")
                .addAddress("10.0.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")
                .setMtu(1500)
                .addDisallowedApplication(packageName)
                .establish()
                ?: run {
                    Log.e(TAG, "establish() returned null — permission revoked or another VPN is active")
                    recordStopReason("ESTABLISH_NULL")
                    cleanupAbortedStart()
                    transition(VpnState.FAILED)
                    stopSelf()
                    return
                }

            Log.i(TAG, "step 4: TUN established fd=${tun!!.fd}, starting relay")
            VpnStats.vpnEstablished.set(true)
            VpnStats.tunFdValid.set(true)
            VpnStats.vpnStartTimestampMs.set(System.currentTimeMillis())
            val tunFd = tun!!
            val fwd = PacketForwarder(this@ShieldVpnService, FileOutputStream(tunFd.fileDescriptor))
            forwarder = fwd
            // Transition to RUNNING before launching the coroutine so the PacketReader's
            // while-guard always sees RUNNING on first check. Launching first and transitioning
            // after was a race: the IO thread could evaluate (vpnState == RUNNING) while the
            // main thread had not yet called transition(), causing the relay to silently never
            // start while the TUN was up — resulting in broken internet with counters stuck at 0.
            transition(VpnState.RUNNING)
            scope.launch {
                var restarts = 0
                while (isActive && vpnState == VpnState.RUNNING) {
                    if (restarts > 0) Log.w(TAG, "PacketReader restarting (attempt $restarts of $MAX_READER_RESTARTS)")
                    try {
                        VpnStats.packetReaderRunning.set(true)
                        PacketReader(
                            stream    = FileInputStream(tunFd.fileDescriptor),
                            forwarder = fwd,
                            parser    = PacketParser(),
                            tracker   = ConnectionTracker(this@ShieldVpnService),
                            client    = client,
                        ).run()
                        VpnStats.packetReaderRunning.set(false)
                        recordStopReason("PACKET_READER_EOF")
                        Log.i(TAG, "PacketReader exited cleanly")
                        break  // clean exit (TUN closed or EOF) — do not restart
                    } catch (e: CancellationException) {
                        VpnStats.packetReaderRunning.set(false)
                        throw e   // scope is cancelling — propagate, don't treat as a crash
                    } catch (e: Exception) {
                        VpnStats.packetReaderRunning.set(false)
                        recordStopReason("PACKET_READER_CRASH attempt=$restarts", e)
                        Log.e("VPN_CRASH", "Packet loop crashed", e)
                        restarts++
                        VpnStats.packetReaderRestarts.set(restarts.toLong())
                        if (restarts > MAX_READER_RESTARTS || vpnState != VpnState.RUNNING) break
                        val backoff = minOf(RESTART_DELAY_MS * restarts, MAX_RESTART_DELAY_MS)
                        Log.w(TAG, "Restarting PacketReader in ${backoff}ms")
                        delay(backoff)
                    }
                }
                if (vpnState == VpnState.RUNNING) {
                    Log.w(TAG, "PacketReader permanently exited while VPN running — stopping VPN")
                    recordStopReason(if (restarts > MAX_READER_RESTARTS) "PACKET_READER_MAX_RESTARTS" else "PACKET_READER_PERMANENT_EXIT")
                    stopVpn()
                }
            }
            startHeartbeat()
        } catch (e: Exception) {
            Log.e(TAG, "startVpn() failed: ${e::class.java.simpleName}: ${e.message}", e)
            recordStopReason("START_EXCEPTION", e)
            cleanupAbortedStart()
            transition(VpnState.FAILED)
            stopSelf()
        }
    }

    /**
     * Tear down resources after [startVpn] fails before a healthy RUNNING session.
     * Safe to call when [vpnState] is STARTING or from the establish()-null branch.
     */
    private fun cleanupAbortedStart() {
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(Service.STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
        forwarder?.shutdown()
        forwarder = null
        runCatching { tun?.close() }
        tun = null
        scope.cancel()
        if (::client.isInitialized) client.shutdown()
    }

    private fun stopVpn() {
        // Idempotent / safe from RUNNING, STARTING, or FAILED — only a settled STOP or
        // in-progress STOPPING is ignored.
        if (vpnState == VpnState.STOPPED || vpnState == VpnState.STOPPING) {
            Log.w(TAG, "stopVpn() called in state $vpnState — ignoring")
            return
        }
        transition(VpnState.STOPPING)
        VpnStats.vpnEstablished.set(false)
        VpnStats.tunFdValid.set(false)
        VpnStats.packetReaderRunning.set(false)
        VpnStats.vpnStartTimestampMs.set(0L)
        // Close the TUN fd first so PacketReader.run()'s blocking stream.read() throws
        // IOException immediately and the coroutine exits before we cancel the scope.
        runCatching { tun?.close() }
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
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(NOTIF_ID, notification, android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } else {
            startForeground(NOTIF_ID, notification)
        }
    }

    companion object {
        const val ACTION_START   = "com.libertyshield.agent.VPN_START"
        const val ACTION_STOP    = "com.libertyshield.agent.VPN_STOP"
        private const val TAG                  = "ShieldVpnService"
        private const val NOTIF_ID             = 2
        private const val CHANNEL_ID           = "liberty_shield_vpn_channel"
        private const val HEARTBEAT_MS         = 5_000L
        private const val MAX_READER_RESTARTS  = 5
        private const val RESTART_DELAY_MS     = 500L    // base backoff; multiplied by attempt number
        private const val MAX_RESTART_DELAY_MS = 5_000L  // caps backoff at 5 s
    }
}
