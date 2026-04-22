package com.libertyshield.agent.vpn

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

    // Gateway HTTP posts
    val gwPostOk   = AtomicLong()
    val gwPostFail = AtomicLong()

    fun summary(): String = buildString {
        append("tcpSessions=").append(tcpSessionsActive.get())
        append(" tcpCreated=").append(tcpSessionsCreated.get())
        append(" tcpClosed=").append(tcpSessionsClosed.get())
        append(" tcpPkts=").append(tcpPacketsIn.get())
        append(" udpSent=").append(udpRequestsSent.get())
        append(" udpRecv=").append(udpResponsesRecv.get())
        append(" udpErr=").append(udpErrors.get())
        append(" gwOk=").append(gwPostOk.get())
        append(" gwFail=").append(gwPostFail.get())
    }
}
