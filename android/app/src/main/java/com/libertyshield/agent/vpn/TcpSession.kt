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
    private var serverJob: Job? = null
    private var relaySeq: Long = 0L
    private var relayAck: Long = 0L

    suspend fun handle(buf: ByteArray) {
        val seg = parseTcpSegment(buf) ?: return
        sessionMutex.withLock {
            when (state) {
                State.CLOSED       -> handleClosed(seg)
                State.SYN_RECEIVED -> handleSynReceived(seg)
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
        val payloadOffset: Int,
        val payloadLen: Int,
    )

    private fun parseTcpSegment(buf: ByteArray): TcpSegment? {
        val ihl = ipHdrLen(buf)
        if (buf.size < ihl + 20) return null
        val flags      = buf[ihl + 13].toInt() and 0xFF
        val seq        = readU32(buf, ihl + 4)
        val ack        = readU32(buf, ihl + 8)
        val dataOffset = ((buf[ihl + 12].toInt() and 0xFF) shr 4) * 4
        val totalLen   = readU16(buf, 2)
        val payloadLen = maxOf(0, totalLen - ihl - dataOffset)
        return TcpSegment(flags, seq, ack, ihl + dataOffset, payloadLen)
    }

    private fun extractPayload(buf: ByteArray): ByteArray {
        val seg = parseTcpSegment(buf) ?: return ByteArray(0)
        if (seg.payloadLen == 0) return ByteArray(0)
        return buf.copyOfRange(seg.payloadOffset, seg.payloadOffset + seg.payloadLen)
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

    private suspend fun handleClosed(seg: TcpSegment) {
        val isSyn = seg.flags and TcpPacketBuilder.FLAG_SYN != 0
        val isAck = seg.flags and TcpPacketBuilder.FLAG_ACK != 0
        val isRst = seg.flags and TcpPacketBuilder.FLAG_RST != 0
        when {
            isRst -> {
                teardown()
            }
            isSyn && !isAck -> {
                onSyn(seg)
            }
            isAck -> {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, seg.ack, 0L))
                teardown()
            }
            else -> {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, mask32(seg.seq + 1), ackFlag = true))
                teardown()
            }
        }
    }

    private suspend fun onSyn(seg: TcpSegment) {
        relaySeq = 0x1000_0000L
        relayAck = mask32(seg.seq + 1)
        try {
            val sock = Socket()
            if (!vpnService.protect(sock)) {
                sock.close()
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, relayAck, ackFlag = true))
                teardown()
                return
            }
            sock.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
            server = sock
            state = State.SYN_RECEIVED
            send(TcpPacketBuilder.buildSynAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck))
            relaySeq = mask32(relaySeq + 1)
        } catch (_: Exception) {
            send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, relayAck, ackFlag = true))
            teardown()
        }
    }

    private suspend fun handleSynReceived(seg: TcpSegment) {
        when {
            seg.flags and TcpPacketBuilder.FLAG_RST != 0 -> teardown()
            seg.flags and TcpPacketBuilder.FLAG_ACK != 0 -> {
                state = State.ESTABLISHED
                startServerReader()
            }
        }
    }

    private suspend fun handleEstablished(seg: TcpSegment, buf: ByteArray) {
        when {
            seg.flags and TcpPacketBuilder.FLAG_RST != 0 -> teardown()
            seg.flags and TcpPacketBuilder.FLAG_FIN != 0 -> {
                relayAck = mask32(seg.seq + 1)
                send(TcpPacketBuilder.buildFinAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck))
                relaySeq = mask32(relaySeq + 1)
                teardown()
            }
            else -> {
                val payload = extractPayload(buf)
                if (payload.isNotEmpty()) {
                    relayAck = mask32(seg.seq + payload.size)
                    forwardToServer(payload)
                    send(TcpPacketBuilder.buildAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck))
                }
            }
        }
    }

    private fun forwardToServer(data: ByteArray) {
        try {
            server?.getOutputStream()?.write(data)
        } catch (_: Exception) {
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
                    val chunk = readBuf.copyOf(n)
                    sessionMutex.withLock {
                        if (state != State.ESTABLISHED) return@withLock
                        val pkt = TcpPacketBuilder.buildData(
                            dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck, chunk,
                        )
                        send(pkt)
                        relaySeq = mask32(relaySeq + chunk.size)
                    }
                }
            } catch (_: Exception) { }
            sessionMutex.withLock { teardown() }
        }
    }

    private suspend fun send(pkt: ByteArray) {
        writeMutex.withLock {
            tunOut.write(pkt)
            tunOut.flush()
        }
    }

    private fun teardown() {
        state = State.CLOSED_FINAL
        serverJob?.cancel()
        serverJob = null
        runCatching { server?.close() }
        server = null
        Log.d(TAG, "torn down $srcIp:$srcPort->$dstIp:$dstPort")
        onClose()
    }

    companion object {
        private const val TAG                = "TcpSession"
        private const val CONNECT_TIMEOUT_MS = 5_000
        private const val READ_BUFFER_SIZE   = 4_096

        fun key(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): String =
            "$srcIp:$srcPort->$dstIp:$dstPort"
    }
}
