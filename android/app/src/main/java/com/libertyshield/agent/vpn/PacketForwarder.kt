package com.libertyshield.agent.vpn

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

class PacketForwarder(
    private val vpnService: VpnService,
    private val tunOut: FileOutputStream,
) {
    private val scope       = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val writeMutex  = Mutex()   // guards concurrent writes to the single tunOut fd
    private val tcpSessions = TcpSessionTable()
    private val dnsCache    = DnsCache()

    // buf is owned by the caller's read loop and will be overwritten on the next iteration.
    // TCP: each session owns a Channel<ByteArray> and a dedicated processing coroutine.
    // enqueue() returns instantly; the session coroutine drains packets in FIFO order.
    // This means a slow sock.connect() on one session cannot block DNS or other sessions.
    // FIFO is per-session (5-tuple), not global — the guarantee that matters for TCP.
    // UDP remains fire-and-forget (scope.launch) because UDP is connectionless.
    fun forward(buf: ByteArray, len: Int, packet: ParsedPacket) {
        if (packet.isIpv6) {
            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "DROP IPv6 (${len}B) — not relayed")
            return
        }
        when (packet.protocol) {
            PacketParser.PROTO_UDP -> {
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "DISPATCH UDP ${packet.srcIp}:${packet.srcPort}→${packet.dstIp}:${packet.dstPort} ${len}B")
                val packetBytes = buf.copyOf(len)
                scope.launch { forwardUdp(packetBytes, len, packet) }
            }
            PacketParser.PROTO_TCP -> {
                val ihl   = (buf[0].toInt() and 0x0F) * 4
                val flags = if (buf.size > ihl + 13) buf[ihl + 13].toInt() and 0xFF else 0
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "DISPATCH TCP ${packet.srcIp}:${packet.srcPort}→${packet.dstIp}:${packet.dstPort} flags=0x${flags.toString(16)} ${len}B")
                val packetBytes = buf.copyOf(len)
                dispatchTcp(packetBytes, packet)   // enqueues instantly — per-session FIFO
            }
            else -> { if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "DROP proto=${packet.protocol} (${len}B) — unhandled") }
        }
    }

    fun shutdown() {
        tcpSessions.closeAll()
        scope.cancel()
    }

    private suspend fun forwardUdp(buf: ByteArray, len: Int, packet: ParsedPacket) {
        val ihl          = (buf[0].toInt() and 0x0F) * 4
        val payloadStart = ihl + 8   // skip IP header + 8-byte UDP header
        val payloadLen   = len - payloadStart
        if (payloadLen <= 0) return

        val payload = buf.copyOfRange(payloadStart, len)
        val isDns   = packet.dstPort == 53

        // DNS cache fast path — serve from memory, skip network entirely
        if (isDns) {
            val cached = dnsCache.get(payload)
            if (cached != null) {
                VpnStats.dnsCacheHits.incrementAndGet()
                val response = buildIpv4UdpPacket(
                    srcIp   = packet.dstIp,
                    dstIp   = packet.srcIp,
                    srcPort = packet.dstPort,
                    dstPort = packet.srcPort,
                    payload = cached,
                )
                writeMutex.withLock { tunOut.write(response); tunOut.flush() }
                return
            }
        }

        try {
            DatagramSocket().use { socket ->
                if (!vpnService.protect(socket)) {
                    throw IOException("protect() failed for UDP ${packet.dstIp}:${packet.dstPort}")
                }
                // DNS gets a tighter timeout — a missed DNS reply causes visible page-load delay
                socket.soTimeout = if (isDns) DNS_TIMEOUT_MS else SOCKET_TIMEOUT_MS

                socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(packet.dstIp), packet.dstPort))
                VpnStats.udpRequestsSent.incrementAndGet()
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "UDP → ${packet.dstIp}:${packet.dstPort} (${payloadLen}B)")

                // Wait for one response (covers DNS and simple request-response protocols).
                // Multi-packet UDP flows (QUIC, video) need a persistent-socket relay — TODO next sprint.
                val respBuf   = ByteArray(MAX_UDP_PAYLOAD)
                val respDgram = DatagramPacket(respBuf, respBuf.size)
                try {
                    socket.receive(respDgram)
                    VpnStats.udpResponsesRecv.incrementAndGet()
                    val respPayload = respBuf.copyOf(respDgram.length)
                    if (isDns) dnsCache.put(payload, respPayload)
                    val response = buildIpv4UdpPacket(
                        srcIp   = packet.dstIp,   // server → app
                        dstIp   = packet.srcIp,
                        srcPort = packet.dstPort,
                        dstPort = packet.srcPort,
                        payload = respPayload,
                    )
                    writeMutex.withLock { tunOut.write(response); tunOut.flush() }
                    if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "UDP ← ${packet.dstIp}:${packet.dstPort} (${respDgram.length}B)")
                } catch (_: java.net.SocketTimeoutException) {
                    if (isDns) VpnStats.dnsTimeouts.incrementAndGet()
                    // Non-DNS timeout is fire-and-forget — not an error
                }
            }
        } catch (e: Exception) {
            VpnStats.udpErrors.incrementAndGet()
            Log.w(TAG, "UDP forward error ${packet.dstIp}:${packet.dstPort}: ${e.message}")
        }
    }

    private fun dispatchTcp(buf: ByteArray, packet: ParsedPacket) {
        val isSyn = packet.tcpFlags and TcpPacketBuilder.FLAG_SYN != 0 &&
                    packet.tcpFlags and TcpPacketBuilder.FLAG_ACK == 0
        val key = TcpSession.key(packet.srcIp, packet.srcPort, packet.dstIp, packet.dstPort)
        val session = tcpSessions.getOrCreate(key, isSyn) {
            VpnStats.tcpSessionsCreated.incrementAndGet()
            VpnStats.tcpSessionsActive.incrementAndGet()
            TcpSession(
                srcIp      = packet.srcIp,
                srcPort    = packet.srcPort,
                dstIp      = packet.dstIp,
                dstPort    = packet.dstPort,
                vpnService = vpnService,
                tunOut     = tunOut,
                writeMutex = writeMutex,
                scope      = scope,
                onClose    = {
                    tcpSessions.remove(key)
                    VpnStats.tcpSessionsActive.decrementAndGet()
                    VpnStats.tcpSessionsClosed.incrementAndGet()
                },
            )
        } ?: return
        VpnStats.tcpPacketsIn.incrementAndGet()
        session.enqueue(buf)   // returns immediately; session's own coroutine handles it
    }

    // Constructs a raw IPv4 + UDP packet to write back into the TUN fd.
    // UDP checksum is set to 0 (legal in IPv4; kernel accepts it from the TUN).
    private fun buildIpv4UdpPacket(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLen   = 8 + payload.size
        val totalLen = 20 + udpLen
        val out      = ByteArray(totalLen)

        out[0]  = 0x45.toByte()           // version=4, IHL=5 (20 bytes, no options)
        out[1]  = 0                        // DSCP/ECN
        out[2]  = (totalLen shr 8).toByte()
        out[3]  = totalLen.toByte()
        out[4]  = 0; out[5] = 0           // identification (fragmentation not used here)
        out[6]  = 0x40.toByte()           // flags: DF=1, MF=0
        out[7]  = 0                        // fragment offset
        out[8]  = 64                       // TTL
        out[9]  = 17                       // protocol: UDP
        out[10] = 0; out[11] = 0          // checksum placeholder
        writeIp(out, 12, srcIp)
        writeIp(out, 16, dstIp)
        val cksum = ipv4Checksum(out, 20)
        out[10] = (cksum shr 8).toByte()
        out[11] = cksum.toByte()

        out[20] = (srcPort shr 8).toByte(); out[21] = srcPort.toByte()
        out[22] = (dstPort shr 8).toByte(); out[23] = dstPort.toByte()
        out[24] = (udpLen shr 8).toByte(); out[25] = udpLen.toByte()
        out[26] = 0; out[27] = 0          // UDP checksum = 0 (optional in IPv4)

        payload.copyInto(out, 28)
        return out
    }

    private fun writeIp(buf: ByteArray, offset: Int, ip: String) {
        ip.split(".").forEachIndexed { i, octet -> buf[offset + i] = octet.toInt().toByte() }
    }

    // One's-complement checksum over the 20-byte IPv4 header (checksum field pre-zeroed).
    private fun ipv4Checksum(buf: ByteArray, headerLen: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLen - 1) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            i += 2
        }
        while (sum shr 16 != 0) sum = (sum and 0xFFFF) + (sum shr 16)
        return sum.inv() and 0xFFFF
    }

    companion object {
        private const val TAG                 = "PacketForwarder"
        private const val VERBOSE_PACKET_LOGS = false   // set true to trace every dispatch in debug builds
        private const val DNS_TIMEOUT_MS      = 800     // tighter timeout for DNS — a miss causes visible delay
        private const val SOCKET_TIMEOUT_MS   = 2_000   // general UDP timeout
        private const val MAX_UDP_PAYLOAD     = 65_507  // max UDP payload (65535 − 20 IP − 8 UDP)
    }
}
