package com.libertyshield.agent.vpn

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.io.FileOutputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class TcpSession(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val vpnService: VpnService,
    private val tunOut: FileOutputStream,
    private val writeMutex: Mutex,
    private val scope: CoroutineScope,
    private val onClose: () -> Unit = {},
) {
    private enum class State { CLOSED, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED_FINAL }

    private val sessionMutex = Mutex()
    private var state: State = State.CLOSED
    private var server: Socket? = null
    private var serverOut: OutputStream? = null
    private var serverJob: Job? = null
    private var relaySeq: Long = 0L
    private var relayAck: Long = 0L

    // ── Point 3: TcpSession receives packet ───────────────────────────────────
    suspend fun handle(buf: ByteArray) {
        val seg = parseTcpSegment(buf) ?: return
        if (Log.isLoggable(TAG, Log.DEBUG)) {
            Log.d(TAG, "[3] PKT $srcIp:$srcPort→$dstIp:$dstPort " +
                "flags=${flagsStr(seg.flags)} seq=${seg.seq} ack=${seg.ack} " +
                "ipHdrLen=${seg.ipHdrLen} tcpHdrLen=${seg.tcpHdrLen} " +
                "payloadOffset=${seg.payloadOffset} payloadLen=${seg.payloadLen} state=$state")
        }
        sessionMutex.withLock {
            when (state) {
                State.CLOSED       -> handleClosed(seg)
                State.SYN_RECEIVED -> handleSynReceived(seg, buf)
                State.ESTABLISHED  -> handleEstablished(seg, buf)
                State.FIN_WAIT     -> teardown()
                State.CLOSED_FINAL -> Unit
            }
        }
    }

    fun close() {
        serverJob?.cancel()
        runCatching { server?.close() }
    }

    private data class TcpSegment(
        val flags: Int,
        val seq: Long,
        val ack: Long,
        val ipHdrLen: Int,
        val tcpHdrLen: Int,
        val payloadOffset: Int,
        val payloadLen: Int,
    )

    private fun parseTcpSegment(buf: ByteArray): TcpSegment? {
        val ihl = ipHdrLen(buf)
        if (buf.size < ihl + 20) return null
        val flags      = buf[ihl + 13].toInt() and 0xFF
        val seq        = readU32(buf, ihl + 4)
        val ack        = readU32(buf, ihl + 8)
        val tcpHdrLen  = ((buf[ihl + 12].toInt() and 0xFF) shr 4) * 4
        val totalLen   = readU16(buf, 2)
        val payloadLen = maxOf(0, totalLen - ihl - tcpHdrLen)
        return TcpSegment(flags, seq, ack, ihl, tcpHdrLen, ihl + tcpHdrLen, payloadLen)
    }

    // ── Point 4: payload extracted from client packet ─────────────────────────
    private fun extractPayload(buf: ByteArray, seg: TcpSegment): ByteArray {
        if (seg.payloadLen == 0) return ByteArray(0)
        val end = minOf(seg.payloadOffset + seg.payloadLen, buf.size)
        if (end <= seg.payloadOffset) return ByteArray(0)
        val payload = buf.copyOfRange(seg.payloadOffset, end)
        if (Log.isLoggable(TAG, Log.DEBUG)) {
            val preview = if (payload.isNotEmpty()) payloadPreview(payload) else "(empty)"
            Log.d(TAG, "[4] EXTRACT $srcIp:$srcPort→$dstIp:$dstPort " +
                "ipHdrLen=${seg.ipHdrLen} tcpHdrLen=${seg.tcpHdrLen} " +
                "payloadOffset=${seg.payloadOffset} payloadLen=${seg.payloadLen} " +
                "actualExtracted=${payload.size} bufSize=${buf.size} preview=$preview")
        }
        return payload
    }

    private fun ipHdrLen(buf: ByteArray): Int = (buf[0].toInt() and 0x0F) * 4

    private fun readU32(buf: ByteArray, offset: Int): Long =
        ((buf[offset].toLong()     and 0xFF) shl 24) or
        ((buf[offset + 1].toLong() and 0xFF) shl 16) or
        ((buf[offset + 2].toLong() and 0xFF) shl  8) or
        (buf[offset + 3].toLong()  and 0xFF)

    private fun readU16(buf: ByteArray, offset: Int): Int =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    private fun mask32(v: Long): Long = v and 0xFFFF_FFFFL

    /** Decode the first byte of payload to identify protocol type for logs. */
    private fun payloadPreview(data: ByteArray): String {
        val b0 = data[0].toInt() and 0xFF
        return when {
            b0 == 0x16 -> "TLS_RECORD(0x16)"   // TLS handshake/data record
            b0 == 0x15 -> "TLS_ALERT(0x15)"
            b0 == 0x14 -> "TLS_CCS(0x14)"      // ChangeCipherSpec
            data.size >= 4 && data.slice(0..2).map { it.toInt() and 0xFF } == listOf(0x47, 0x45, 0x54) -> "HTTP_GET"
            data.size >= 4 && data.slice(0..3).map { it.toInt() and 0xFF } == listOf(0x48, 0x54, 0x54, 0x50) -> "HTTP_RESP"
            else -> "0x${b0.toString(16)}"
        }
    }

    /** Human-readable TCP flags for structured logs. */
    private fun flagsStr(f: Int): String {
        val sb = StringBuilder()
        if (f and TcpPacketBuilder.FLAG_SYN != 0) sb.append("SYN|")
        if (f and TcpPacketBuilder.FLAG_ACK != 0) sb.append("ACK|")
        if (f and TcpPacketBuilder.FLAG_PSH != 0) sb.append("PSH|")
        if (f and TcpPacketBuilder.FLAG_FIN != 0) sb.append("FIN|")
        if (f and TcpPacketBuilder.FLAG_RST != 0) sb.append("RST|")
        return if (sb.isEmpty()) "0x${f.toString(16)}" else sb.toString().trimEnd('|')
    }

    private suspend fun handleClosed(seg: TcpSegment) {
        val isSyn = seg.flags and TcpPacketBuilder.FLAG_SYN != 0
        val isAck = seg.flags and TcpPacketBuilder.FLAG_ACK != 0
        val isRst = seg.flags and TcpPacketBuilder.FLAG_RST != 0
        when {
            isRst -> teardown()
            isSyn && !isAck -> onSyn(seg)
            isAck -> {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, seg.ack, 0L), "RST")
                teardown()
            }
            else -> {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, mask32(seg.seq + 1), ackFlag = true), "RST|ACK")
                teardown()
            }
        }
    }

    private suspend fun onSyn(seg: TcpSegment) {
        relaySeq = 0x1000_0000L
        relayAck = mask32(seg.seq + 1)
        try {
            val sock = Socket()
            // Socket() is lazy on Android — the kernel fd is not allocated until bind/connect.
            // protect() reads the fd; calling it before bind() returns false every time.
            sock.bind(InetSocketAddress(0))
            if (!vpnService.protect(sock)) {
                Log.w(TAG, "TCP protect() failed for $dstIp:$dstPort")
                sock.close()
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, relayAck, ackFlag = true), "RST|ACK")
                teardown()
                return
            }
            sock.tcpNoDelay = true    // disable Nagle — critical for TLS handshake latency
            sock.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
            server = sock
            serverOut = sock.getOutputStream()
            state = State.SYN_RECEIVED
            Log.d(TAG, "SYN_RECEIVED $srcIp:$srcPort→$dstIp:$dstPort relaySeq=$relaySeq relayAck=$relayAck")
            send(TcpPacketBuilder.buildSynAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "SYN|ACK")
            relaySeq = mask32(relaySeq + 1)
        } catch (e: Exception) {
            Log.w(TAG, "TCP connect failed $dstIp:$dstPort: ${e::class.java.simpleName}: ${e.message}")
            send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, relayAck, ackFlag = true), "RST|ACK")
            teardown()
        }
    }

    private suspend fun handleSynReceived(seg: TcpSegment, buf: ByteArray) {
        when {
            seg.flags and TcpPacketBuilder.FLAG_RST != 0 -> teardown()
            seg.flags and TcpPacketBuilder.FLAG_ACK != 0 -> {
                state = State.ESTABLISHED
                Log.d(TAG, "ESTABLISHED $srcIp:$srcPort→$dstIp:$dstPort payloadLen=${seg.payloadLen}")
                startServerReader()
                if (seg.payloadLen > 0) {
                    Log.d(TAG, "SYN_RECEIVED→ESTABLISHED piggybacked ${seg.payloadLen}B $srcIp:$srcPort→$dstIp:$dstPort")
                } else {
                    Log.d(TAG, "SYN_RECEIVED→ESTABLISHED pure ACK — awaiting ClientHello")
                }
                handleEstablished(seg, buf)
            }
        }
    }

    private suspend fun handleEstablished(seg: TcpSegment, buf: ByteArray) {
        when {
            seg.flags and TcpPacketBuilder.FLAG_RST != 0 -> {
                Log.d(TAG, "ESTABLISHED RST $srcIp:$srcPort→$dstIp:$dstPort")
                teardown()
            }
            seg.flags and TcpPacketBuilder.FLAG_FIN != 0 -> {
                Log.d(TAG, "ESTABLISHED FIN $srcIp:$srcPort→$dstIp:$dstPort")
                relayAck = mask32(seg.seq + 1)
                send(TcpPacketBuilder.buildFinAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "FIN|ACK")
                relaySeq = mask32(relaySeq + 1)
                teardown()
            }
            else -> {
                // ALL non-RST non-FIN packets reach here, including pure ACK and ACK+payload.
                // Payload is forwarded whenever payloadLen > 0, regardless of which flags are set.
                val payload = extractPayload(buf, seg)
                if (payload.isNotEmpty()) {
                    relayAck = mask32(seg.seq + payload.size)
                    Log.d(TAG, "c→s ${payload.size}B flags=${flagsStr(seg.flags)} seq=${seg.seq} " +
                        "newRelayAck=$relayAck $srcIp:$srcPort→$dstIp:$dstPort")
                    forwardToServer(payload)
                    send(TcpPacketBuilder.buildAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "ACK")
                } else {
                    Log.d(TAG, "c→s 0B pure-ACK flags=${flagsStr(seg.flags)} seq=${seg.seq} $srcIp:$srcPort→$dstIp:$dstPort")
                }
            }
        }
    }

    // ── Point 5: payload forwarded to server socket ───────────────────────────
    private fun forwardToServer(data: ByteArray) {
        try {
            val out = serverOut ?: run {
                Log.e(TAG, "[5] forwardToServer: serverOut null — dropping ${data.size}B $srcIp:$srcPort→$dstIp:$dstPort")
                return
            }
            Log.d(TAG, "[5] forwardToServer: writing ${data.size}B to $dstIp:$dstPort")
            out.write(data)
            out.flush()
            Log.d(TAG, "[5] forwardToServer: wrote ${data.size}B to $dstIp:$dstPort OK")
        } catch (e: Exception) {
            Log.w(TAG, "[5] forwardToServer: write failed ${data.size}B $dstIp:$dstPort: ${e.message}")
            teardown()
        }
    }

    private fun startServerReader() {
        val sock = server ?: return
        serverJob = scope.launch {
            try {
                val inp = sock.getInputStream()
                val readBuf = ByteArray(READ_BUFFER_SIZE)
                var n = 0
                while (isActive && inp.read(readBuf).also { n = it } != -1) {
                    // ── Point 6: bytes read from server socket ─────────────────
                    Log.d(TAG, "[6] server→relay read ${n}B from $dstIp:$dstPort")
                    // Split into MSS-sized chunks so every IP packet stays within the
                    // TUN MTU (1500).  A single inp.read() can return up to READ_BUFFER_SIZE
                    // bytes; building one oversized packet from that causes EMSGSIZE on the
                    // tunOut.write() and silently tears down the session.
                    var offset = 0
                    while (offset < n) {
                        val chunkLen = minOf(MSS, n - offset)
                        val chunk = readBuf.copyOfRange(offset, offset + chunkLen)
                        offset += chunkLen
                        sessionMutex.withLock {
                            if (state != State.ESTABLISHED) return@withLock
                            // ── Point 7: packet built back to TUN ─────────────
                            Log.d(TAG, "[7] BUILD DATA ${chunk.size}B $srcIp:$srcPort→$dstIp:$dstPort " +
                                "relaySeq=$relaySeq relayAck=$relayAck " +
                                "preview=${payloadPreview(chunk)}")
                            val pkt = TcpPacketBuilder.buildData(
                                dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck, chunk,
                            )
                            send(pkt, "PSH|ACK data=${chunk.size}B")
                            relaySeq = mask32(relaySeq + chunk.size)
                        }
                    }
                }
            } catch (_: Exception) { }
            sessionMutex.withLock { teardown() }
        }
    }

    // ── Point 8: packet written to TUN ────────────────────────────────────────
    private suspend fun send(pkt: ByteArray, desc: String = "?") {
        writeMutex.withLock {
            Log.d(TAG, "[8] TUN← ${pkt.size}B [$desc] $srcIp:$srcPort→$dstIp:$dstPort")
            tunOut.write(pkt)
            tunOut.flush()
        }
    }

    private fun teardown() {
        if (state == State.CLOSED_FINAL) return
        state = State.CLOSED_FINAL
        serverJob?.cancel()
        serverJob = null
        serverOut = null
        runCatching { server?.close() }
        server = null
        Log.d(TAG, "torn down $srcIp:$srcPort→$dstIp:$dstPort")
        onClose()
    }

    companion object {
        private const val TAG                = "TcpSession"
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val READ_BUFFER_SIZE   = 32_768
        private const val MSS                = 1_460  // MTU(1500) − IP(20) − TCP(20)

        fun key(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): String =
            "$srcIp:$srcPort->$dstIp:$dstPort"
    }
}
