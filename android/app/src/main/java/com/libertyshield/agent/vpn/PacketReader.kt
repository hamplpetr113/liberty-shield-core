package com.libertyshield.agent.vpn

import com.libertyshield.agent.GatewayClient
import com.libertyshield.agent.models.SensorEvent
import java.io.FileInputStream
import java.io.IOException

class PacketReader(
    private val stream: FileInputStream,
    private val forwarder: PacketForwarder,
    private val parser: PacketParser,
    private val tracker: ConnectionTracker,
    private val client: GatewayClient,
) {
    private val buf = ByteArray(32_768)

    // Bounded LRU — access-ordered LinkedHashMap evicts oldest entry at MAX_CACHE.
    // Not thread-safe, but PacketReader runs on a single coroutine.
    private val emitted: MutableMap<String, Unit> =
        object : LinkedHashMap<String, Unit>(256, 0.75f, true) {
            override fun removeEldestEntry(eldest: Map.Entry<String, Unit>) = size > MAX_CACHE
        }

    private val rateLimiter = RateLimiter(maxPerWindow = 50)

    suspend fun run() {
        try {
            while (true) {
                val len = stream.read(buf)
                if (len < 0) break          // -1 = TUN fd closed, exit cleanly
                if (len == 0) continue      // EAGAIN on non-blocking fd — no packet yet
                val packet = parser.parse(buf, len) ?: continue
                emitTelemetry(packet)
                forwarder.forward(buf, len, packet)  // must forward to keep connectivity
            }
        } catch (_: IOException) {
            // TUN fd closed — VPN is stopping, exit cleanly
        }
    }

    private fun emitTelemetry(p: ParsedPacket) {
        if (!shouldEmit(p)) return
        if (!rateLimiter.tryAcquire()) return

        if (p.isIpv6) {
            client.enqueue(SensorEvent.Ipv6Connection)
            return
        }

        val key = "${p.dstIp}:${p.dstPort}"
        if (emitted.put(key, Unit) != null) return  // LRU hit — already reported this session

        val uid = tracker.ownerUidOf(p.protocol, p.srcPort)
        client.enqueue(SensorEvent.NetworkConnection(
            remoteIp   = p.dstIp,
            remotePort = p.dstPort,
            pid        = uid.takeIf { it >= 0 },
        ))
    }

    private fun shouldEmit(p: ParsedPacket): Boolean {
        if (p.isIpv6) return true
        return when (p.protocol) {
            PacketParser.PROTO_TCP -> (p.tcpFlags and TCP_SYN) != 0  // new connections only
            PacketParser.PROTO_UDP -> p.dstPort > 1_024              // skip DNS and well-known ports
            else                   -> false
        }
    }

    companion object {
        private const val TCP_SYN   = 0x02
        private const val MAX_CACHE = 1_024
    }
}
