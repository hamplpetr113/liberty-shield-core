package com.libertyshield.agent.vpn

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Semaphore
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

enum class WritePriority { CONTROL, DATA }

data class PacketWrite(
    val buffer: ByteArray,
    val length: Int,
    val fromPool: Boolean = false,
    val priority: WritePriority = WritePriority.DATA,
)

class PacketForwarder(
    private val vpnService: VpnService,
    private val tunOut: FileOutputStream,
) {
    private val scope         = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val tcpSessions   = TcpSessionTable()
    private val dnsCache      = DnsCache()
    // Caps concurrent blocking UDP coroutines to prevent Dispatchers.IO thread starvation.
    // Each forwardUdp() blocks an IO thread for up to SOCKET_TIMEOUT_MS (2 s). Without a
    // cap, a burst of QUIC/UDP traffic fills the 64-thread IO pool and starves TCP serverJobs.
    private val udpSemaphore  = Semaphore(MAX_UDP_CONCURRENT)

    // Two-tier TUN write queues.  Control (SYN-ACK, ACK, RST, FIN, UDP) is UNLIMITED so
    // handshake and DNS packets are never dropped under load — dropping control is fatal.
    // Data (server-response segments) is bounded at 2 048 to apply backpressure.
    private val tunWriteControlQueue = Channel<PacketWrite>(capacity = Channel.UNLIMITED)
    private val tunWriteDataQueue    = Channel<PacketWrite>(capacity = TUN_DATA_QUEUE_CAPACITY)

    init {
        // Priority writer: drain ALL pending control first (drainControlQueue), then
        // suspend on select{} waiting for either queue.  select{} prevents the writer
        // from blocking exclusively on the data queue while control packets accumulate.
        // This was the critical bug: receiveCatching(data) would block indefinitely
        // during the handshake phase (no data yet), starving SYN-ACK/ACK/DNS writes.
        scope.launch(Dispatchers.IO) {
            try {
                while (isActive) {
                    if (drainControlQueue()) continue

                    // Suspend until either queue produces a packet.  Both channels are
                    // registered so a control RST or SYN-ACK wakes the loop immediately
                    // even when no data is flowing.  null means both channels are closed.
                    val pkt = select<PacketWrite?> {
                        tunWriteControlQueue.onReceiveCatching { it.getOrNull() }
                        tunWriteDataQueue.onReceiveCatching    { it.getOrNull() }
                    } ?: break

                    writeAndRelease(pkt)
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "TUN writer crashed", e)
            } finally {
                // Drain any pool buffers stranded in the data queue after shutdown.
                var c = tunWriteDataQueue.tryReceive()
                while (c.isSuccess) {
                    val p = c.getOrThrow()
                    if (p.fromPool) PacketPool.release(p.buffer)
                    c = tunWriteDataQueue.tryReceive()
                }
                VpnStats.tunWriteControlDepth.set(0)
                VpnStats.tunWriteDataDepth.set(0)
            }
        }

        // Session reaper: every 5 s, close sessions that exceeded their expiry policy.
        scope.launch {
            delay(REAPER_INITIAL_DELAY_MS)
            while (isActive) {
                tcpSessions.pruneExpired()
                delay(REAPER_INTERVAL_MS)
            }
        }
    }

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
                scope.launch {
                    if (!udpSemaphore.tryAcquire()) {
                        VpnStats.udpConcurrencyDrops.incrementAndGet()
                        return@launch
                    }
                    try { forwardUdp(packetBytes, len, packet) }
                    finally { udpSemaphore.release() }
                }
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
        tunWriteControlQueue.close()
        tunWriteDataQueue.close()
        scope.cancel()
    }

    // Non-blocking drain: write every currently queued control packet, return true if
    // any were written.  Called at the top of the writer loop so control always has
    // priority over data without needing the writer to re-enter select each time.
    private fun drainControlQueue(): Boolean {
        var wrote = false
        while (true) {
            val ctrl = tunWriteControlQueue.tryReceive().getOrNull() ?: break
            writeAndRelease(ctrl)
            wrote = true
        }
        return wrote
    }

    private fun writeAndRelease(pkt: PacketWrite) {
        try {
            tunOut.write(pkt.buffer, 0, pkt.length)
            tunOut.flush()
        } finally {
            if (pkt.fromPool) PacketPool.release(pkt.buffer)
            when (pkt.priority) {
                WritePriority.CONTROL -> VpnStats.tunWriteControlDepth.decrementAndGet()
                WritePriority.DATA    -> VpnStats.tunWriteDataDepth.decrementAndGet()
            }
        }
    }

    // All non-data TUN writes (UDP, RST, session-cap reject) go through the UNLIMITED control
    // queue so they are never capacity-dropped.  A failure here means the channel was closed
    // (VPN shutdown in progress) — log and count it, but do not crash.
    private fun sendControl(pkt: ByteArray) {
        val pw = PacketWrite(pkt, pkt.size, priority = WritePriority.CONTROL)
        if (tunWriteControlQueue.trySend(pw).isSuccess) {
            val depth = VpnStats.tunWriteControlDepth.incrementAndGet()
            if (depth > VpnStats.tunWriteControlMaxDepth.get()) VpnStats.tunWriteControlMaxDepth.set(depth)
        } else {
            VpnStats.tunWriteControlDrops.incrementAndGet()
            Log.w(TAG, "CONTROL packet dropped — TUN control queue closed (shutdown in progress)")
        }
    }

    private suspend fun forwardUdp(buf: ByteArray, len: Int, packet: ParsedPacket) {
        val ihl          = (buf[0].toInt() and 0x0F) * 4
        val payloadStart = ihl + 8   // skip IP header + 8-byte UDP header
        val payloadLen   = len - payloadStart
        if (payloadLen <= 0) return

        val payload = buf.copyOfRange(payloadStart, len)
        val isDns   = packet.dstPort == 53

        // QUIC guard disabled — dropping UDP 443 caused Chrome to stall instead of falling back
        // to TCP immediately. Passing QUIC through the one-shot path for now so browsing is not
        // blocked. TODO: implement persistent UDP relay for QUIC/HTTP3.
        // if (packet.dstPort == QUIC_PORT) {
        //     val count = VpnStats.quicDropped.incrementAndGet()
        //     if (count == 1L) Log.w(TAG, "UDP 443 (QUIC/HTTP3) not supported — dropping; client should fall back to TCP")
        //     return
        // }

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
                sendControl(response)
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

                val dnsT0 = if (isDns) System.currentTimeMillis() else 0L
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
                    if (isDns) {
                        VpnStats.dnsTotalLatencyMs.addAndGet(System.currentTimeMillis() - dnsT0)
                        VpnStats.dnsLatencyCount.incrementAndGet()
                    }
                    val respPayload = respBuf.copyOf(respDgram.length)
                    if (isDns) dnsCache.put(payload, respPayload)
                    val response = buildIpv4UdpPacket(
                        srcIp   = packet.dstIp,   // server → app
                        dstIp   = packet.srcIp,
                        srcPort = packet.dstPort,
                        dstPort = packet.srcPort,
                        payload = respPayload,
                    )
                    sendControl(response)
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
                srcIp                = packet.srcIp,
                srcPort              = packet.srcPort,
                dstIp                = packet.dstIp,
                dstPort              = packet.dstPort,
                vpnService           = vpnService,
                tunWriteControlQueue = tunWriteControlQueue,
                tunWriteDataQueue    = tunWriteDataQueue,
                scope                = scope,
                onClose              = {
                    tcpSessions.remove(key)
                    VpnStats.tcpSessionsActive.decrementAndGet()
                    VpnStats.tcpSessionsClosed.incrementAndGet()
                },
            )
        }
        if (session == null) {
            // Session cap: new SYN rejected — RST|ACK to app. Non-SYN with no session: silent drop.
            if (isSyn) {
                val ack = tcpSynAckForRst(buf) ?: return
                val rst = TcpPacketBuilder.buildRst(
                    packet.dstIp, packet.srcIp, packet.dstPort, packet.srcPort,
                    0L, ack, ackFlag = true,
                )
                sendControl(rst)
            }
            return
        }
        VpnStats.tcpPacketsIn.incrementAndGet()
        session.enqueue(buf)   // returns immediately; session's own coroutine handles it
    }

    /** ACK for RST|ACK to a client SYN: client ISN + 1 (32-bit). Null if IPv4/TCP header not parseable. */
    private fun tcpSynAckForRst(buf: ByteArray): Long? {
        if (buf.size < 20) return null
        if ((buf[0].toInt() and 0xF0) shr 4 != 4) return null
        val ihl = (buf[0].toInt() and 0x0F) * 4
        if (ihl < 20 || buf.size < ihl + 8) return null
        val seq = readU32be(buf, ihl + 4)
        return (seq + 1) and 0xFFFF_FFFFL
    }

    private fun readU32be(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong() and 0xFF) shl 24) or
        ((buf[offset + 1].toLong() and 0xFF) shl 16) or
        ((buf[offset + 2].toLong() and 0xFF) shl 8) or
        (buf[offset + 3].toLong() and 0xFF)

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
        private const val TAG                        = "PacketForwarder"
        private const val VERBOSE_PACKET_LOGS        = false   // set true to trace every dispatch in debug builds
        private const val DNS_TIMEOUT_MS             = 800     // tighter timeout for DNS — a miss causes visible delay
        private const val SOCKET_TIMEOUT_MS          = 2_000   // general UDP timeout
        private const val QUIC_PORT                  = 443     // UDP 443 = QUIC/HTTP3 — not supported, always dropped
        private const val MAX_UDP_PAYLOAD            = 65_507  // max UDP payload (65535 − 20 IP − 8 UDP)
        private const val MAX_UDP_CONCURRENT         = 32      // cap blocking IO threads for UDP; excess packets dropped
        private const val TUN_DATA_QUEUE_CAPACITY    = 2_048   // TCP server-response data segments (bounded — backpressure)
        private const val REAPER_INITIAL_DELAY_MS    = 5_000L  // first prune after 5 s so sessions have time to establish
        private const val REAPER_INTERVAL_MS         = 5_000L  // prune interval
    }
}
