package com.libertyshield.agent.test

import com.libertyshield.agent.ffi.RuntimeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Sprint 206 — Orchestrates a two-phone test session.
 *
 * Responsibilities:
 *   - Initialise and start the Rust runtime via [RuntimeBridge].
 *   - Own and start [UdpBridge] for UDP transport.
 *   - Drive a periodic tick loop (1 s).
 *   - Handle test-level ping/pong protocol: auto-reply PONG to incoming PING.
 *   - Expose [hud] for UI status snapshots.
 *
 * Call [start] once, then [sendPing] to initiate round-trip tests.
 * Call [stop] to tear down all resources cleanly.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
class TestModeController(
    val bridge: RuntimeBridge,
    val config: PeerConfig,
) {
    val udpBridge = UdpBridge(bridge, config)
    val hud: RuntimeHud by lazy { RuntimeHud(bridge, udpBridge, config, this) }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val running = AtomicBoolean(false)
    private val pingSeqCounter = AtomicInteger(0)

    val pingsReceived = AtomicInteger(0)
    val pongsReceived = AtomicInteger(0)

    /** Initialise runtime, bind UDP socket, start tick loop. Returns false on first failure. */
    fun start(): Boolean {
        if (!bridge.init(config.localNodeId)) {
            LibertyLogger.init(false, "Rust init returned error")
            return false
        }
        LibertyLogger.init(true)

        if (!bridge.start()) {
            LibertyLogger.start(false, "Rust start returned error")
            return false
        }
        LibertyLogger.start(true)

        udpBridge.onPacketReceived = ::handlePacket
        if (!udpBridge.start(scope)) return false

        running.set(true)
        launchTickLoop()
        LibertyLogger.status("TestModeController running — local=${TestIdentity.shortHex(config.localNodeId)}")
        return true
    }

    /** Tear down in reverse order: UDP → Rust runtime. */
    fun stop() {
        running.set(false)
        udpBridge.stop()
        bridge.stop()
        scope.cancel()
        LibertyLogger.stop(true)
    }

    /** Build and send a PING to the peer. Sequence number auto-increments. */
    fun sendPing(): Boolean {
        val seq = pingSeqCounter.incrementAndGet()
        val packet = TestPacket.buildPing(seq, config.localNodeId)
        LibertyLogger.ping(seq)
        return udpBridge.sendRaw(packet)
    }

    // Called on the IO thread for every received datagram (after Rust ingest).
    private fun handlePacket(data: ByteArray) {
        when {
            TestPacket.isPing(data) -> {
                val seq = TestPacket.seqNo(data)
                pingsReceived.incrementAndGet()
                LibertyLogger.status("PING_RECV seq=$seq")
                val pong = TestPacket.buildPong(seq, config.localNodeId)
                udpBridge.sendRaw(pong)
                LibertyLogger.pong(seq)
            }
            TestPacket.isPong(data) -> {
                val seq = TestPacket.seqNo(data)
                pongsReceived.incrementAndGet()
                LibertyLogger.pong(seq)
            }
        }
    }

    private fun launchTickLoop() {
        scope.launch {
            var n = 0
            while (isActive) {
                delay(1_000)
                val ok = bridge.tick(1)
                LibertyLogger.tick(++n, ok)
            }
        }
    }
}
