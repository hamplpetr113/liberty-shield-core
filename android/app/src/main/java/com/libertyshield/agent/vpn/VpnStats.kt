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
    val udpRequestsSent  = AtomicLong()
    val udpResponsesRecv = AtomicLong()
    val udpErrors        = AtomicLong()

    // DNS cache
    val dnsCacheHits = AtomicLong()
    val dnsTimeouts  = AtomicLong()

    // TCP session queue health
    val tcpQueueOverflows = AtomicLong()
    val tcpQueueMaxDepth  = AtomicInteger()   // approximate peak depth across all live sessions

    // Gateway HTTP posts
    val gwPostOk   = AtomicLong()
    val gwPostFail = AtomicLong()

    fun summary(): String = buildString {
        append("tcpSessions=").append(tcpSessionsActive.get())
        append(" tcpCreated=").append(tcpSessionsCreated.get())
        append(" tcpClosed=").append(tcpSessionsClosed.get())
        append(" tcpPkts=").append(tcpPacketsIn.get())
        append(" tcpQueueOvf=").append(tcpQueueOverflows.get())
        append(" tcpQueueMaxD=").append(tcpQueueMaxDepth.get())
        append(" udpSent=").append(udpRequestsSent.get())
        append(" udpRecv=").append(udpResponsesRecv.get())
        append(" udpErr=").append(udpErrors.get())
        append(" dnsHit=").append(dnsCacheHits.get())
        append(" dnsTout=").append(dnsTimeouts.get())
        append(" gwOk=").append(gwPostOk.get())
        append(" gwFail=").append(gwPostFail.get())
    }
}
