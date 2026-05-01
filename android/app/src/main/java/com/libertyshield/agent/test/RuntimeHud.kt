package com.libertyshield.agent.test

import com.libertyshield.agent.ffi.RuntimeBridge

/**
 * Sprint 205 — Minimal debug HUD for the two-phone test.
 *
 * [snapshot] captures a point-in-time view of runtime state and packet counters.
 * [format] renders it as a multi-line string suitable for a TextView or logcat.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
data class HudSnapshot(
    val statusLabel: String,
    val isRunning: Boolean,
    val packetsSent: Long,
    val packetsReceived: Long,
    val sendErrors: Long,
    val ingestErrors: Long,
    val pingsReceived: Int,
    val pongsReceived: Int,
    val localNodeIdHex: String,
    val peerNodeIdHex: String,
)

class RuntimeHud(
    private val bridge: RuntimeBridge,
    private val udpBridge: UdpBridge,
    private val config: PeerConfig,
    private val controller: TestModeController? = null,
) {
    fun snapshot(): HudSnapshot = HudSnapshot(
        statusLabel = bridge.statusLabel(),
        isRunning = bridge.isRunning(),
        packetsSent = udpBridge.packetsSent.get(),
        packetsReceived = udpBridge.packetsReceived.get(),
        sendErrors = udpBridge.sendErrors.get(),
        ingestErrors = udpBridge.ingestErrors.get(),
        pingsReceived = controller?.pingsReceived?.get() ?: 0,
        pongsReceived = controller?.pongsReceived?.get() ?: 0,
        localNodeIdHex = TestIdentity.shortHex(config.localNodeId),
        peerNodeIdHex = TestIdentity.shortHex(config.peerNodeId),
    )

    fun format(s: HudSnapshot = snapshot()): String = buildString {
        appendLine("=== LIBERTY TEST HUD ===")
        appendLine("Status : ${s.statusLabel}${if (s.isRunning) " [OK]" else ""}")
        appendLine("Local  : ${s.localNodeIdHex}  Peer: ${s.peerNodeIdHex}")
        appendLine("Sent   : ${s.packetsSent}  Recv: ${s.packetsReceived}")
        appendLine("Ping RX: ${s.pingsReceived}  Pong RX: ${s.pongsReceived}")
        appendLine("Errors : send=${s.sendErrors}  ingest=${s.ingestErrors}")
        append("========================")
    }
}
