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
import com.libertyshield.agent.tunnel.HelloFrameBuilder
import com.libertyshield.agent.tunnel.TunnelClient
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
import java.io.IOException

class ShieldVpnService : VpnService() {

    // ── Runtime state ─────────────────────────────────────────────────────────

    private enum class VpnState { STOPPED, STARTING, RUNNING, STOPPING, FAILED }

    @Volatile private var vpnState: VpnState = VpnState.STOPPED

    // Set true only on explicit user/system stop (ACTION_STOP, onRevoke).
    // Used to suppress full-VPN recovery when PacketReader exits during a deliberate shutdown.
    @Volatile private var userRequestedStop = false

    // Rate-limit guard for full VPN re-establishments.
    private val fullRecoveryLock       = Any()
    private val fullRecoveryTimestamps = mutableListOf<Long>()

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
    private var heartbeatJob: kotlinx.coroutines.Job? = null

    // ── Service lifecycle ─────────────────────────────────────────────────────

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "onCreate")
    }

    override fun onStartCommand(intent: android.content.Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                userRequestedStop = true
                recordStopReason("ACTION_STOP")
                stopVpn()
                START_NOT_STICKY
            }
            else -> {
                userRequestedStop = false
                startVpn()
                // If VPN failed to establish, don't let Android restart us into an infinite loop.
                if (vpnState == VpnState.FAILED) START_NOT_STICKY else START_STICKY
            }
        }
    }

    override fun onBind(intent: android.content.Intent?): IBinder? = super.onBind(intent)

    override fun onRevoke() {
        Log.i(TAG, "VPN permission revoked by system")
        userRequestedStop = true
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
            launchPacketReader(fwd, tunFd)
            startHeartbeat()
            launchDebugHello()
        } catch (e: Exception) {
            Log.e(TAG, "startVpn() failed: ${e::class.java.simpleName}: ${e.message}", e)
            if (tun != null) {
                // TUN was already established — keep it alive and recover the runtime layer.
                recoverRuntimeSameTun("START_EXCEPTION", e)
            } else {
                recordStopReason("START_EXCEPTION", e)
                cleanupAbortedStart()
                transition(VpnState.FAILED)
                stopSelf()
            }
        }
    }

    // ── PacketReader supervisor loop ──────────────────────────────────────────

    /**
     * Launches the PacketReader supervisor coroutine on the service scope.
     *
     * Exit classification:
     *  - [CancellationException]: scope was cancelled (user stop or onDestroy) — do not recover.
     *  - [IOException]: TUN fd is invalid; the same-fd recovery path is useless.
     *    If the stop was user-requested, exit quietly. Otherwise trigger [recoverFullVpn].
     *  - Normal return (len < 0): TUN fd was closed. Same logic as IOException.
     *  - Other [Exception]: PacketReader internal crash; retry up to [MAX_READER_RESTARTS]
     *    on the same fd, then fall back to [recoverFullVpn].
     */
    private fun launchPacketReader(fwd: PacketForwarder, tunFd: android.os.ParcelFileDescriptor) {
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
                    // Normal return: TUN read returned -1 (fd closed). Expected during user stop;
                    // unexpected otherwise — TUN fd was closed by Android, so full re-establish.
                    if (userRequestedStop || vpnState != VpnState.RUNNING) {
                        Log.i(TAG, "PacketReader EOF — expected during stop (userStop=$userRequestedStop)")
                        break
                    }
                    Log.w(TAG, "PacketReader EOF — TUN fd closed unexpectedly; triggering full VPN re-establish")
                    recoverFullVpn("PACKET_READER_EOF")
                    break
                } catch (e: CancellationException) {
                    VpnStats.packetReaderRunning.set(false)
                    throw e
                } catch (e: IOException) {
                    // IOException means the TUN fd is invalid — reusing it in recoverRuntimeSameTun
                    // would fail immediately. Full re-establish is the only correct path.
                    VpnStats.packetReaderRunning.set(false)
                    if (userRequestedStop || vpnState != VpnState.RUNNING) {
                        Log.i(TAG, "PacketReader IOException during stop — not recovering (userStop=$userRequestedStop)")
                        break
                    }
                    recordStopReason("PACKET_READER_IO", e)
                    Log.w(TAG, "PacketReader IOException — triggering full VPN re-establish", e)
                    recoverFullVpn("PACKET_READER_IO", e)
                    break
                } catch (e: Exception) {
                    VpnStats.packetReaderRunning.set(false)
                    if (userRequestedStop || vpnState != VpnState.RUNNING) break
                    recordStopReason("PACKET_READER_CRASH attempt=$restarts", e)
                    Log.e("VPN_CRASH", "Packet loop crashed", e)
                    restarts++
                    VpnStats.packetReaderRestarts.addAndGet(1L)
                    if (restarts > MAX_READER_RESTARTS) {
                        Log.w(TAG, "PacketReader exceeded max restarts — triggering full VPN re-establish")
                        recoverFullVpn("PACKET_READER_MAX_CRASHES", e)
                        break
                    }
                    val backoff = minOf(RESTART_DELAY_MS * restarts, MAX_RESTART_DELAY_MS)
                    Log.w(TAG, "Restarting PacketReader in ${backoff}ms")
                    delay(backoff)
                }
            }
            VpnStats.packetReaderRunning.set(false)
        }
    }

    // ── Runtime self-healing ──────────────────────────────────────────────────

    /**
     * Recovers from a runtime failure WITHOUT touching the TUN fd.
     * Use only when the TUN fd is known to be alive (e.g. startVpn() exception after establish()).
     *
     * Sequence:
     *  1. Shut down the stale [PacketForwarder] (closes all TCP sessions).
     *  2. Create a fresh [PacketForwarder] on the same TUN file descriptor.
     *  3. After [RECOVERY_DELAY_MS], relaunch the PacketReader supervisor.
     *
     * Never calls [stopSelf] — the service and TUN stay alive.
     * For PacketReader EOF/IOException use [recoverFullVpn] instead.
     */
    private fun recoverRuntimeSameTun(reason: String, error: Throwable? = null) {
        if (vpnState != VpnState.RUNNING && vpnState != VpnState.STARTING) {
            Log.w(TAG, "recoverRuntimeSameTun: vpnState=$vpnState — skipping")
            return
        }
        val count = VpnStats.runtimeRecoveries.incrementAndGet()
        Log.w(TAG, "recoverRuntimeSameTun #$count reason=$reason error=${error?.javaClass?.simpleName}: ${error?.message}", error)
        if (error != null) {
            VpnStats.vpnLastExceptionClass.set(error.javaClass.simpleName)
            VpnStats.vpnLastExceptionMessage.set(error.message ?: "")
        }
        val tunFd = tun ?: run {
            Log.e(TAG, "recoverRuntimeSameTun: tun is null — cannot recover")
            recordStopReason("RECOVER_TUN_NULL")
            stopVpn()
            return
        }
        // If we arrived here from a startVpn exception before RUNNING was set, finish the transition.
        if (vpnState != VpnState.RUNNING) {
            VpnStats.vpnEstablished.set(true)
            VpnStats.tunFdValid.set(true)
            if (VpnStats.vpnStartTimestampMs.get() == 0L) VpnStats.vpnStartTimestampMs.set(System.currentTimeMillis())
            transition(VpnState.RUNNING)
        }
        forwarder?.shutdown()
        val newFwd = PacketForwarder(this@ShieldVpnService, FileOutputStream(tunFd.fileDescriptor))
        forwarder = newFwd
        scope.launch {
            delay(RECOVERY_DELAY_MS)
            if (isActive && vpnState == VpnState.RUNNING) {
                Log.i(TAG, "recoverRuntimeSameTun: relaunching PacketReader after ${RECOVERY_DELAY_MS}ms")
                launchPacketReader(newFwd, tunFd)
            }
        }
        startHeartbeat()  // no-op if already running; ensures heartbeat started on STARTING→RUNNING path
    }

    /**
     * Full VPN re-establishment after unexpected TUN fd loss (PacketReader EOF or IOException).
     *
     * Unlike [recoverRuntimeSameTun], this closes the stale TUN fd, cancels the old scope,
     * and calls [startVpn] — which calls Builder.establish() to get a fresh TUN fd.
     * The foreground service is kept alive throughout; [stopSelf] is never called here.
     *
     * Rate-limited to [MAX_FULL_RECOVERIES_PER_WINDOW] within [FULL_RECOVERY_WINDOW_MS].
     * If the limit is exceeded the service transitions to FAILED and calls stopSelf.
     *
     * Must not be called when [userRequestedStop] is true; callers are responsible for
     * checking this before calling.
     */
    private fun recoverFullVpn(reason: String, error: Throwable? = null) {
        if (userRequestedStop) {
            Log.i(TAG, "recoverFullVpn: userRequestedStop=true — skipping recovery")
            return
        }
        if (vpnState == VpnState.STOPPING || vpnState == VpnState.STOPPED) {
            Log.i(TAG, "recoverFullVpn: vpnState=$vpnState — already stopping, skipping")
            return
        }

        // Rate-limit guard: max MAX_FULL_RECOVERIES_PER_WINDOW attempts per FULL_RECOVERY_WINDOW_MS.
        val allowed = synchronized(fullRecoveryLock) {
            val now = System.currentTimeMillis()
            fullRecoveryTimestamps.removeAll { now - it > FULL_RECOVERY_WINDOW_MS }
            if (fullRecoveryTimestamps.size >= MAX_FULL_RECOVERIES_PER_WINDOW) {
                false
            } else {
                fullRecoveryTimestamps.add(now)
                true
            }
        }
        if (!allowed) {
            VpnStats.fullVpnRecoverySuppressed.incrementAndGet()
            recordStopReason("FULL_RECOVERY_LIMIT_EXCEEDED")
            Log.e(TAG, "Full VPN recovery limit ($MAX_FULL_RECOVERIES_PER_WINDOW in ${FULL_RECOVERY_WINDOW_MS}ms) exceeded — giving up")
            transition(VpnState.FAILED)
            stopSelf()
            return
        }

        val count = VpnStats.fullVpnRecoveries.incrementAndGet()
        Log.w(TAG, "recoverFullVpn #$count reason=$reason error=${error?.javaClass?.simpleName}: ${error?.message}", error)
        if (error != null) {
            VpnStats.vpnLastExceptionClass.set(error.javaClass.simpleName)
            VpnStats.vpnLastExceptionMessage.set(error.message ?: "")
        }

        // Mirror stopVpn() cleanup — no stopSelf().
        transition(VpnState.STOPPING)
        VpnStats.vpnEstablished.set(false)
        VpnStats.tunFdValid.set(false)
        VpnStats.packetReaderRunning.set(false)
        VpnStats.vpnStartTimestampMs.set(0L)
        runCatching { tun?.close() }
        tun = null
        forwarder?.shutdown()
        forwarder = null
        scope.cancel()
        // Fresh scope so startVpn() does not launch into a cancelled Job.
        scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
        transition(VpnState.STOPPED)

        scope.launch {
            delay(RECOVERY_DELAY_MS)
            if (!userRequestedStop) {
                Log.i(TAG, "recoverFullVpn: calling startVpn() after ${RECOVERY_DELAY_MS}ms")
                startVpn()
            } else {
                // User revoked/stopped during our recovery window — honour the stop.
                Log.i(TAG, "recoverFullVpn: userRequestedStop set during recovery delay — calling stopSelf()")
                stopSelf()
            }
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
        if (heartbeatJob?.isActive == true) return  // already running — don't spawn a duplicate
        heartbeatJob = scope.launch {
            while (isActive) {
                delay(HEARTBEAT_MS)
                Log.i(TAG, "heartbeat state=$vpnState ${VpnStats.summary()}")
            }
        }
    }

    // ── Debug authenticated Hello ─────────────────────────────────────────────

    /**
     * Fire-and-forget: sends one authenticated Hello frame to the exit node if
     * [BuildConfig.DEBUG_PSK_HEX] is non-empty. Runs on the IO dispatcher; any
     * failure is logged and swallowed — VPN startup is never affected.
     *
     * DEV ONLY — remove or gate behind a proper secret store before shipping production.
     */
    private fun launchDebugHello() {
        val pskHex = BuildConfig.DEBUG_PSK_HEX
        if (pskHex.isEmpty()) return
        scope.launch(kotlinx.coroutines.Dispatchers.IO) {
            runCatching {
                val psk = HelloFrameBuilder.parsePsk(pskHex)
                val sessionId = System.currentTimeMillis()
                TunnelClient.sendHello(psk, sessionId, sequence = 1L)
            }.onFailure { e ->
                Log.e(TAG, "debug hello failed: ${e.message}")
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
        private const val RECOVERY_DELAY_MS                = 2_000L  // pause before restarting after full recovery
        private const val FULL_RECOVERY_WINDOW_MS          = 60_000L  // sliding window for full-VPN recovery rate limit
        private const val MAX_FULL_RECOVERIES_PER_WINDOW   = 3        // max full re-establishes within the window
    }
}
