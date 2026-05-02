package com.libertyshield.agent.vpn

import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * Process-wide, thread-safe counters for the VPN relay.
 * Incremented from PacketForwarder (UDP/TCP dispatch) and GatewayClient (HTTP posts).
 * Read by ShieldVpnService's heartbeat logger every 5 s.
 */
object VpnStats {
    // TCP session lifecycle
    val tcpSessionsActive  = AtomicLong()
    val tcpSessionsCreated = AtomicLong()
    val tcpSessionsClosed  = AtomicLong()
    val tcpPacketsIn       = AtomicLong()   // total packets delivered to session.handle()

    // UDP relay (one-shot per request)
    val udpRequestsSent      = AtomicLong()
    val udpResponsesRecv     = AtomicLong()
    val udpErrors            = AtomicLong()
    val udpConcurrencyDrops  = AtomicLong()   // dropped because semaphore was full (IO-thread guard)

    // DNS cache + latency (network-only, cache hits excluded)
    val dnsCacheHits      = AtomicLong()
    val dnsTimeouts       = AtomicLong()
    val dnsTotalLatencyMs = AtomicLong()   // sum of successful DNS round-trips
    val dnsLatencyCount   = AtomicLong()   // denominator for avg

    // QUIC (UDP 443) — not supported; packets are dropped so browsers fall back to TCP
    val quicDropped  = AtomicLong()

    // TCP session queue health
    val tcpQueueOverflows = AtomicLong()
    val tcpQueueMaxDepth  = AtomicInteger()   // approximate peak depth across all live sessions

    // TCP connect latency outliers
    val tcpSlowConnects = AtomicLong()   // connects that exceeded CONNECT_WARN_MS

    // PacketReader throughput (incremented per TUN read, used to compute recent pkt/s)
    val packetReaderTotal = AtomicLong()
    private var snapshotPkts  = 0L
    private var snapshotTimeMs = System.currentTimeMillis()

    // Gateway HTTP posts
    val gwPostOk   = AtomicLong()
    val gwPostFail = AtomicLong()

    fun summary(): String = buildString {
        val dnsCount = dnsLatencyCount.get()
        val dnsAvgMs = if (dnsCount > 0) dnsTotalLatencyMs.get() / dnsCount else -1L

        val now      = System.currentTimeMillis()
        val elapsed  = maxOf(1L, now - snapshotTimeMs)
        val pkts     = packetReaderTotal.get()
        val pktRate  = (pkts - snapshotPkts) * 1000L / elapsed
        snapshotPkts   = pkts
        snapshotTimeMs = now

        append("activeTcpSessions=").append(tcpSessionsActive.get())
        append(" tcpCreated=").append(tcpSessionsCreated.get())
        append(" tcpClosed=").append(tcpSessionsClosed.get())
        append(" tcpSlowConn=").append(tcpSlowConnects.get())
        append(" tcpQueueOvf=").append(tcpQueueOverflows.get())
        append(" tcpQueueMaxD=").append(tcpQueueMaxDepth.get())
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
