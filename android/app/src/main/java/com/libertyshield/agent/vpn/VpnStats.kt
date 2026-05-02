package com.libertyshield.agent.vpn

import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Process-wide, thread-safe counters for the VPN relay.
 * Incremented from PacketForwarder (UDP/TCP dispatch) and GatewayClient (HTTP posts).
 * Read by ShieldVpnService's heartbeat logger every 5 s and by RuntimeDashboardActivity every 1 s.
 */
object VpnStats {
    // ── VPN lifecycle state (set by ShieldVpnService) ─────────────────────────
    val vpnEstablished       = AtomicBoolean(false)  // Builder.establish() returned non-null
    val tunFdValid           = AtomicBoolean(false)  // TUN fd is currently open
    val packetReaderRunning  = AtomicBoolean(false)  // PacketReader.run() is executing
    val packetReaderRestarts = AtomicLong()           // cumulative restart count
    val vpnStartTimestampMs  = AtomicLong(0L)         // wall-clock ms when TUN was established

    // ── TCP session lifecycle ─────────────────────────────────────────────────
    val tcpSessionsActive  = AtomicLong()
    val tcpSessionsCreated = AtomicLong()
    val tcpSessionsClosed  = AtomicLong()
    val tcpPacketsIn       = AtomicLong()

    // ── TCP session queue health ──────────────────────────────────────────────
    val tcpQueueOverflows    = AtomicLong()
    val tcpQueueMaxDepth     = AtomicInteger()
    val tcpHighQueueEvents   = AtomicLong()   // times any session queue exceeded HIGH_QUEUE_THRESHOLD

    // ── TCP connect latency outliers ──────────────────────────────────────────
    val tcpSlowConnects = AtomicLong()

    // ── UDP relay (one-shot per request) ──────────────────────────────────────
    val udpRequestsSent     = AtomicLong()
    val udpResponsesRecv    = AtomicLong()
    val udpErrors           = AtomicLong()
    val udpConcurrencyDrops = AtomicLong()

    // ── DNS cache + latency (network-only, cache hits excluded) ───────────────
    val dnsCacheHits      = AtomicLong()
    val dnsTimeouts       = AtomicLong()
    val dnsTotalLatencyMs = AtomicLong()
    val dnsLatencyCount   = AtomicLong()

    // ── QUIC (UDP 443) ────────────────────────────────────────────────────────
    val quicDropped = AtomicLong()

    // ── PacketReader throughput ───────────────────────────────────────────────
    val packetReaderTotal = AtomicLong()
    private var snapshotPkts   = 0L
    private var snapshotTimeMs = System.currentTimeMillis()

    // ── Gateway HTTP posts ────────────────────────────────────────────────────
    val gwPostOk   = AtomicLong()
    val gwPostFail = AtomicLong()

    fun summary(): String = buildString {
        val dnsCount = dnsLatencyCount.get()
        val dnsAvgMs = if (dnsCount > 0) dnsTotalLatencyMs.get() / dnsCount else -1L

        val now     = System.currentTimeMillis()
        val elapsed = maxOf(1L, now - snapshotTimeMs)
        val pkts    = packetReaderTotal.get()
        val pktRate = (pkts - snapshotPkts) * 1000L / elapsed
        snapshotPkts   = pkts
        snapshotTimeMs = now

        append("vpnEstablished=").append(vpnEstablished.get())
        append(" tunFdValid=").append(tunFdValid.get())
        append(" readerRunning=").append(packetReaderRunning.get())
        append(" readerRestarts=").append(packetReaderRestarts.get())
        append(" activeTcpSessions=").append(tcpSessionsActive.get())
        append(" tcpCreated=").append(tcpSessionsCreated.get())
        append(" tcpClosed=").append(tcpSessionsClosed.get())
        append(" tcpSlowConn=").append(tcpSlowConnects.get())
        append(" tcpQueueOvf=").append(tcpQueueOverflows.get())
        append(" tcpQueueMaxD=").append(tcpQueueMaxDepth.get())
        append(" tcpHighQ=").append(tcpHighQueueEvents.get())
        append(" udpSent=").append(udpRequestsSent.get())
        append(" udpRecv=").append(udpResponsesRecv.get())
        append(" udpErr=").append(udpErrors.get())
        append(" udpDrop=").append(udpConcurrencyDrops.get())
        append(" dnsAvgMs=").append(if (dnsAvgMs >= 0) dnsAvgMs else "n/a")
        append(" dnsHit=").append(dnsCacheHits.get())
        append(" dnsTout=").append(dnsTimeouts.get())
        append(" packetReaderRate=${pktRate}/s")
        append(" gwOk=").append(gwPostOk.get())
        append(" gwFail=").append(gwPostFail.get())
    }
}
