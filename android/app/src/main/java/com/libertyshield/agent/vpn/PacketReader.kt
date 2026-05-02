package com.libertyshield.agent.vpn

import android.util.Log
import com.libertyshield.agent.GatewayClient
import com.libertyshield.agent.models.SensorEvent
import java.io.FileInputStream
import java.io.IOException
import kotlinx.coroutines.CancellationException

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
        Log.i(TAG, "PacketReader started — reading TUN")
        try {
            while (true) {
                val len = stream.read(buf)
                if (len < 0) { Log.i(TAG, "TUN read returned -1 — fd closed"); break }
                if (len == 0) continue      // EAGAIN on non-blocking fd — no packet yet
                try {
                    val packet = parser.parse(buf, len)
                    if (packet == null) {
                        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "TUN pkt ${len}B → parser returned null (too short/malformed)")
                        continue
                    }
                    if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                        val proto = if (packet.isIpv6) "IPv6" else when (packet.protocol) {
                            PacketParser.PROTO_TCP -> "TCP"
                            PacketParser.PROTO_UDP -> "UDP"
                            else -> "proto=${packet.protocol}"
                        }
                        Log.d(TAG, "TUN pkt ${len}B $proto ${packet.srcIp}:${packet.srcPort}→${packet.dstIp}:${packet.dstPort} flags=0x${packet.tcpFlags.toString(16)}")
                    }
                    emitTelemetry(packet)
                    forwarder.forward(buf, len, packet)
                } catch (e: CancellationException) {
                    throw e   // scope cancellation must not be swallowed by the per-packet guard
                } catch (e: Exception) {
                    Log.e("VPN_CRASH", "Packet loop crashed", e)
                    // continue the loop — one bad packet does not kill PacketReader
                }
            }
        } catch (_: IOException) {
            Log.i(TAG, "PacketReader exited via IOException — VPN stopping")
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
        private const val TAG                 = "PacketReader"
        private const val VERBOSE_PACKET_LOGS = false   // set true to trace every TUN read in debug builds
        private const val TCP_SYN             = 0x02
        private const val MAX_CACHE = 1_024
    }
}
