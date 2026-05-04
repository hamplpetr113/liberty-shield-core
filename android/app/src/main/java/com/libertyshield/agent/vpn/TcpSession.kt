package com.libertyshield.agent.vpn

import android.net.VpnService
import android.util.Log
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class TcpSession(
    private val srcIp: String,
    private val srcPort: Int,
    private val dstIp: String,
    private val dstPort: Int,
    private val vpnService: VpnService,
    private val tunWriteControlQueue: SendChannel<PacketWrite>,
    private val tunWriteDataQueue: SendChannel<PacketWrite>,
    private val scope: CoroutineScope,
    private val onClose: () -> Unit = {},
) {
    private enum class State { CLOSED, SYN_RECEIVED, ESTABLISHED, FIN_WAIT, CLOSED_FINAL }

    private val sessionMutex = Mutex()
    @Volatile private var state: State = State.CLOSED
    private var server: Socket? = null
    private var serverOut: OutputStream? = null
    private var serverJob: Job? = null
    private var relaySeq: Long = 0L
    private var relayAck: Long = 0L

    // Pre-parsed IP ints: avoid String.split() allocations in the packet-build hot path.
    // Parsed once at session construction; srcIp/dstIp strings remain for logging.
    private val srcIpInt: Int = ipToInt(srcIp)
    private val dstIpInt: Int = ipToInt(dstIp)

    // Latency diagnostics — written by onSyn(), read by startServerReader().
    // @Volatile: onSyn() runs in queueJob, startServerReader() runs in serverJob.
    @Volatile private var connectDoneMs: Long = 0L

    // Session reaper fields — written by queueJob/serverJob, read by reaper coroutine.
    val createdAtMs: Long = System.currentTimeMillis()
    @Volatile var lastActivityMs: Long = createdAtMs
    @Volatile var firstByteSeen: Boolean = false

    // Per-session FIFO queue. PacketReader enqueues instantly (never blocks).
    // A dedicated coroutine drains it, so each session is independent — a slow
    // sock.connect() on session A cannot delay DNS or a new session B.
    // Bounded at 256 so a stalled session cannot grow unbounded in memory;
    // on overflow we send RST and tear down rather than silently dropping packets.
    private val inQueue    = Channel<ByteArray>(capacity = 256)
    private var queueJob: Job? = null
    private val tornDown   = AtomicBoolean(false) // CAS guard — ensures teardown() body runs exactly once
    private val queueDepth = AtomicInteger(0)    // tracks enqueued-but-not-yet-handled count
    @Volatile private var highQueueLogged = false

    init {
        queueJob = scope.launch {
            for (pkt in inQueue) {
                handle(pkt)
            }
        }
    }

    fun enqueue(pkt: ByteArray) {
        if (state == State.CLOSED_FINAL) return   // session already torn down — discard
        val result = inQueue.trySend(pkt)
        if (result.isFailure) {
            VpnStats.tcpQueueOverflows.incrementAndGet()
            Log.w(TAG, "TCP session queue full — dropping packet and tearing down $srcIp:$srcPort→$dstIp:$dstPort")
            scope.launch {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck, ackFlag = true), "RST queue-full")
                teardown()
            }
        } else {
            lastActivityMs = System.currentTimeMillis()
            val depth = queueDepth.incrementAndGet()
            // Racy compare-and-set is intentional — both threads write valid peaks, last writer wins
            if (depth > VpnStats.tcpQueueMaxDepth.get()) VpnStats.tcpQueueMaxDepth.set(depth)
            if (depth > HIGH_QUEUE_THRESHOLD && !highQueueLogged) {
                highQueueLogged = true
                Log.w(TAG, "High TCP queue $srcIp:$srcPort→$dstIp:$dstPort depth=$depth")
                VpnStats.tcpHighQueueEvents.incrementAndGet()
            }
        }
    }

    // Returns null (not expired) or the expiry reason string.
    // Called by the reaper from a different thread — all fields read here are @Volatile.
    //
    // Do not apply a hard lifetime cap to ESTABLISHED sessions; long-lived streams (radio,
    // video, WebSocket, downloads) are valid TCP connections. Reap by no-first-byte or idle only.
    fun expiryReason(nowMs: Long): String? {
        if (state == State.CLOSED_FINAL) return "closed"
        if (!firstByteSeen && nowMs - createdAtMs >= NO_FIRST_BYTE_TIMEOUT_MS) return "no_first_byte"
        if (nowMs - lastActivityMs >= IDLE_SESSION_TIMEOUT_MS) return "idle"
        return null
    }

    fun isExpired(nowMs: Long): Boolean = expiryReason(nowMs) != null

    // Called by TcpSessionTable.pruneExpired() on the reaper thread.
    // Increments per-reason stats, sends a best-effort RST, then tears down.
    fun closeExpired(reason: String) {
        when (reason) {
            "no_first_byte" -> {
                VpnStats.tcpSessionsExpired.incrementAndGet()
                VpnStats.tcpSessionsExpiredNoFirstByte.incrementAndGet()
            }
            "idle" -> {
                VpnStats.tcpSessionsExpired.incrementAndGet()
                VpnStats.tcpSessionsExpiredIdle.incrementAndGet()
            }
            "lifetime" -> {
                VpnStats.tcpSessionsExpired.incrementAndGet()
                VpnStats.tcpSessionsExpiredLifetime.incrementAndGet()
            }
        }
        send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, 0L), "RST expired=$reason")
        teardown()
    }

    // ── Point 3: TcpSession receives packet ───────────────────────────────────
    // sessionMutex: state, relaySeq/relayAck, synthetic send(...). forwardToServer() must not
    // run under sessionMutex (blocking I/O); see processEstablishedSegment().
    private suspend fun handle(buf: ByteArray) {
        queueDepth.updateAndGet { maxOf(0, it - 1) }
        val seg = parseTcpSegment(buf) ?: return
        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
            Log.d(TAG, "[3] PKT $srcIp:$srcPort→$dstIp:$dstPort " +
                "flags=${flagsStr(seg.flags)} seq=${seg.seq} ack=${seg.ack} " +
                "ipHdrLen=${seg.ipHdrLen} tcpHdrLen=${seg.tcpHdrLen} " +
                "payloadOffset=${seg.payloadOffset} payloadLen=${seg.payloadLen} state=$state")
        }
        val isSyn = seg.flags and TcpPacketBuilder.FLAG_SYN != 0
        val isAck = seg.flags and TcpPacketBuilder.FLAG_ACK != 0
        if (isSyn && !isAck) {
            // onSyn() calls sock.connect() which is a blocking Java call (up to
            // CONNECT_TIMEOUT_MS). It must NOT run inside sessionMutex — holding the
            // mutex for 100 ms–5 s would freeze every concurrent serverJob that needs
            // sessionMutex to send data back through the TUN (deadlock-adjacent stall).
            // PacketReader is a single coroutine so no concurrent packet can arrive
            // for this session while we are here — the sequential guarantee is preserved.
            val shouldConnect = sessionMutex.withLock { state == State.CLOSED }
            if (shouldConnect) onSyn(seg)
            return
        }
        var establishedSegment: Pair<TcpSegment, ByteArray>? = null
        sessionMutex.withLock {
            when (state) {
                State.CLOSED -> {
                    handleClosed(seg)
                    return@handle
                }
                State.SYN_RECEIVED -> when {
                    seg.flags and TcpPacketBuilder.FLAG_RST != 0 -> {
                        teardown()
                        return@handle
                    }
                    seg.flags and TcpPacketBuilder.FLAG_ACK != 0 -> {
                        state = State.ESTABLISHED
                        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                            Log.d(TAG, "ESTABLISHED $srcIp:$srcPort→$dstIp:$dstPort payloadLen=${seg.payloadLen}")
                        }
                        startServerReader()
                        if (seg.payloadLen > 0) {
                            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                                Log.d(TAG, "SYN_RECEIVED→ESTABLISHED piggybacked ${seg.payloadLen}B $srcIp:$srcPort→$dstIp:$dstPort")
                            }
                        } else {
                            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                                Log.d(TAG, "SYN_RECEIVED→ESTABLISHED pure ACK — awaiting ClientHello")
                            }
                        }
                        establishedSegment = seg to buf
                    }
                    else -> return@handle
                }
                State.ESTABLISHED -> {
                    establishedSegment = seg to buf
                }
                State.FIN_WAIT -> {
                    teardown()
                    return@handle
                }
                State.CLOSED_FINAL -> return@handle
            }
        }

        establishedSegment?.let { (s, b) -> processEstablishedSegment(s, b) }
    }

    fun close() {
        inQueue.close()
        queueJob?.cancel()
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
        if (tcpHdrLen < 20) return null                       // reject corrupt data-offset field
        val payloadOffset = ihl + tcpHdrLen
        if (payloadOffset > buf.size) return null             // header claims more than we have
        val totalLen   = minOf(readU16(buf, 2), buf.size)     // clamp IP totalLen to actual buffer
        val payloadLen = maxOf(0, totalLen - ihl - tcpHdrLen)
        return TcpSegment(flags, seq, ack, ihl, tcpHdrLen, payloadOffset, payloadLen)
    }

    // ── Point 4: payload extracted from client packet ─────────────────────────
    private fun extractPayload(buf: ByteArray, seg: TcpSegment): ByteArray {
        if (seg.payloadLen == 0) return ByteArray(0)
        val end = minOf(seg.payloadOffset + seg.payloadLen, buf.size)
        if (end <= seg.payloadOffset) {
            Log.w(TAG, "[4] EXTRACT EMPTY payloadLen=${seg.payloadLen} payloadOffset=${seg.payloadOffset} bufSize=${buf.size} end=$end ipHdrLen=${seg.ipHdrLen} tcpHdrLen=${seg.tcpHdrLen} $srcIp:$srcPort→$dstIp:$dstPort")
            return ByteArray(0)
        }
        val payload = buf.copyOfRange(seg.payloadOffset, end)
        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
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
        // SYN is intercepted in handle() before the sessionMutex block and routed to
        // onSyn() outside the lock.  Only stale non-SYN packets reach here (spurious
        // ACK, RST, etc.) — send RST and tear down.
        val isAck = seg.flags and TcpPacketBuilder.FLAG_ACK != 0
        val isRst = seg.flags and TcpPacketBuilder.FLAG_RST != 0
        when {
            isRst -> teardown()
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

    // Called OUTSIDE sessionMutex (see handle()). sock.connect() is a blocking Java
    // call that occupies the calling IO thread for up to CONNECT_TIMEOUT_MS. Running
    // it inside the mutex would stall every concurrent serverJob that needs sessionMutex
    // to flush server-response data back through the TUN.
    //
    // Safety: PacketReader is a single coroutine — no other packet for this session
    // can arrive while we are here. The instance fields (relaySeq, relayAck, server,
    // serverOut, state) are therefore safe to write without the mutex in this phase.
    // The sessionMutex is acquired at the end only to update state and enqueue control packets.
    private suspend fun onSyn(seg: TcpSegment) {
        relaySeq = 0x1000_0000L
        relayAck = mask32(seg.seq + 1)

        // Socket() is lazy on Android — fd not allocated until bind/connect.
        // protect() needs the fd; call bind() first or protect() returns false.
        val sock = try {
            val s = Socket()
            s.bind(InetSocketAddress(0))
            if (!vpnService.protect(s)) {
                Log.w(TAG, "TCP protect() failed for $dstIp:$dstPort")
                s.close()
                null
            } else {
                s.tcpNoDelay = true    // disable Nagle — critical for TLS handshake latency
                val t0 = System.currentTimeMillis()
                s.connect(InetSocketAddress(dstIp, dstPort), CONNECT_TIMEOUT_MS)
                val elapsed = System.currentTimeMillis() - t0
                connectDoneMs = t0 + elapsed
                VpnStats.tcpConnectCount.incrementAndGet()
                VpnStats.tcpConnectTotalMs.addAndGet(elapsed)
                VpnStats.updateMax(VpnStats.tcpConnectMaxMs, elapsed)
                if (elapsed > CONNECT_WARN_MS) {
                    Log.w(TAG, "TCP slow connect ${elapsed}ms $dstIp:$dstPort")
                    VpnStats.tcpSlowConnects.incrementAndGet()
                }
                s
            }
        } catch (e: Exception) {
            Log.w(TAG, "TCP connect failed $dstIp:$dstPort: ${e::class.java.simpleName}: ${e.message}")
            VpnStats.tcpConnectFailures.incrementAndGet()
            null
        }

        sessionMutex.withLock {
            if (sock == null) {
                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, relayAck, ackFlag = true), "RST|ACK")
                teardown()
            } else {
                server = sock
                serverOut = sock.getOutputStream()
                state = State.SYN_RECEIVED
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "SYN_RECEIVED $srcIp:$srcPort→$dstIp:$dstPort relaySeq=$relaySeq relayAck=$relayAck")
                send(TcpPacketBuilder.buildSynAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "SYN|ACK")
                relaySeq = mask32(relaySeq + 1)
            }
        }
    }

    /**
     * ESTABLISHED (and first ACK after SYN_ACK) client→server processing.
     * Lock: relaySeq/relayAck and send(...) only under sessionMutex.
     * Unlock: forwardToServer() between retransmit check and new-data path, and on FIN payload.
     * ACK after new data: relayAck advances only after forwardToServer returns so serverJob
     * cannot snapshot an ACK number for bytes not yet written to the server socket.
     */
    private suspend fun processEstablishedSegment(seg: TcpSegment, buf: ByteArray) {
        sessionMutex.withLock {
            if (state != State.ESTABLISHED) return
            if (seg.flags and TcpPacketBuilder.FLAG_RST != 0) {
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                    Log.d(TAG, "ESTABLISHED RST $srcIp:$srcPort→$dstIp:$dstPort")
                }
                teardown()
                return
            }
        }

        if (seg.flags and TcpPacketBuilder.FLAG_FIN != 0) {
            val payload = extractPayload(buf, seg)
            if (payload.isNotEmpty()) {
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                    Log.d(TAG, "ESTABLISHED FIN piggybacked ${payload.size}B — forwarding before close $srcIp:$srcPort→$dstIp:$dstPort")
                }
                forwardToServer(payload)
            } else {
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                    Log.d(TAG, "ESTABLISHED FIN $srcIp:$srcPort→$dstIp:$dstPort")
                }
            }
            sessionMutex.withLock {
                if (state != State.ESTABLISHED) return
                relayAck = mask32(seg.seq + payload.size.toLong() + 1)
                send(TcpPacketBuilder.buildFinAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "FIN|ACK")
                relaySeq = mask32(relaySeq + 1)
                teardown()
            }
            return
        }

        val payload = extractPayload(buf, seg)
        if (payload.isNotEmpty()) {
            val nextSeq = mask32(seg.seq + payload.size)
            sessionMutex.withLock {
                if (state != State.ESTABLISHED) return
                if (seq32Covered(nextSeq, relayAck)) {
                    if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                        Log.d(TAG, "c→s RETRANSMIT ${payload.size}B seq=${seg.seq} covered by relayAck=$relayAck — skip $srcIp:$srcPort→$dstIp:$dstPort")
                    }
                    send(TcpPacketBuilder.buildAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "ACK retransmit")
                    return
                }
            }
            forwardToServer(payload)
            sessionMutex.withLock {
                if (state != State.ESTABLISHED) return
                relayAck = nextSeq
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                    Log.d(TAG, "c→s ${payload.size}B flags=${flagsStr(seg.flags)} seq=${seg.seq} " +
                        "newRelayAck=$relayAck $srcIp:$srcPort→$dstIp:$dstPort")
                }
                send(TcpPacketBuilder.buildAck(dstIp, srcIp, dstPort, srcPort, relaySeq, relayAck), "ACK")
            }
        } else {
            sessionMutex.withLock {
                if (state != State.ESTABLISHED) return
                if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
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
            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "[5] forwardToServer: writing ${data.size}B to $dstIp:$dstPort")
            out.write(data)
            out.flush()
            lastActivityMs = System.currentTimeMillis()
            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "[5] forwardToServer: wrote ${data.size}B to $dstIp:$dstPort OK")
        } catch (e: Exception) {
            Log.w(TAG, "[5] forwardToServer: write failed ${data.size}B $dstIp:$dstPort: ${e.message}")
            teardown()
        }
    }

    private fun startServerReader() {
        val sock = server ?: return
        serverJob = scope.launch {
            var firstByteReceived = false
            try {
                val inp     = sock.getInputStream()
                val readBuf = ByteArray(READ_BUFFER_SIZE)
                var n       = 0
                while (isActive && inp.read(readBuf).also { n = it } != -1) {
                    lastActivityMs = System.currentTimeMillis()
                    if (!firstByteReceived && n > 0) {
                        firstByteReceived = true
                        firstByteSeen = true
                        val fbLatency = System.currentTimeMillis() - connectDoneMs
                        VpnStats.tcpFirstByteCount.incrementAndGet()
                        VpnStats.tcpFirstByteTotalMs.addAndGet(fbLatency)
                        VpnStats.updateMax(VpnStats.tcpFirstByteMaxMs, fbLatency)
                    }
                    // ── Point 6: bytes read from server socket ─────────────────
                    if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "[6] server→relay read ${n}B from $dstIp:$dstPort")
                    // Split into MSS-sized chunks (MTU 1500 → MSS 1460).
                    //
                    // Three-phase strategy:
                    //   Phase 1 — one sessionMutex lock for the whole read: snapshot relayAck,
                    //             record (seq, len) for each chunk, advance relaySeq. No allocs.
                    //   Phase 2 — build IP/TCP packets into pool buffers outside every lock.
                    //   Phase 3 — trySend each chunk to tunWriteDataQueue (lock-free). Data queue
                    //             overflow triggers an RST and tears down the session (backpressure).
                    val numChunks = (n + MSS - 1) / MSS
                    val seqSnaps  = LongArray(numChunks)
                    val chunkLens = IntArray(numChunks)
                    var ackSnap   = 0L
                    var active    = false
                    sessionMutex.withLock {
                        if (state == State.ESTABLISHED) {
                            active  = true
                            ackSnap = relayAck
                            var off = 0
                            var i   = 0
                            while (off < n) {
                                val cl       = minOf(MSS, n - off)
                                seqSnaps[i]  = relaySeq
                                chunkLens[i] = cl
                                relaySeq     = mask32(relaySeq + cl)
                                off += cl
                                i++
                            }
                        }
                    }
                    if (!active) continue
                    waitForDataQueueCapacity()

                    // Phase 2: borrow pool buffers, build packets into them — zero per-packet allocation.
                    // chunkLens[i] starts as payload length; after buildDataInto it holds total pkt length.
                    // Nullable array: Phase 3 nulls each slot on successful enqueue so the finally
                    // block only releases buffers whose ownership did NOT transfer to the drain coroutine.
                    var backpressureTeardown = false
                    val bufs = arrayOfNulls<ByteArray>(numChunks)
                    try {
                        var off = 0
                        for (i in 0 until numChunks) {
                            val payloadLen = chunkLens[i]
                            val buf = PacketPool.acquire()
                            bufs[i] = buf
                            chunkLens[i] = TcpPacketBuilder.buildDataInto(
                                buf, dstIpInt, srcIpInt, dstPort, srcPort,
                                seqSnaps[i], ackSnap, readBuf, off, payloadLen,
                            )
                            if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) {
                                Log.d(TAG, "[7] BUILD DATA ${payloadLen}B $srcIp:$srcPort→$dstIp:$dstPort seq=${seqSnaps[i]} ack=$ackSnap")
                            }
                            off += payloadLen
                        }

                        // Phase 3: enqueue chunks to the data queue.  On overflow, send RST and
                        // tear down — backpressure forces the session to close rather than silently
                        // dropping data.  remaining bufs are released by the finally block below.
                        for (i in 0 until numChunks) {
                            val buf = bufs[i]!!
                            val pw = PacketWrite(buf, chunkLens[i], fromPool = true, priority = WritePriority.DATA)
                            if (tunWriteDataQueue.trySend(pw).isSuccess) {
                                val depth = VpnStats.tunWriteDataDepth.incrementAndGet()
                                if (depth > VpnStats.tunWriteDataMaxDepth.get()) VpnStats.tunWriteDataMaxDepth.set(depth)
                                bufs[i] = null  // ownership transferred — skip in finally
                            } else {
                                VpnStats.tunWriteDataDrops.incrementAndGet()
                                send(TcpPacketBuilder.buildRst(dstIp, srcIp, dstPort, srcPort, 0L, 0L), "RST data-queue-full")
                                backpressureTeardown = true
                                break
                            }
                        }
                    } finally {
                        for (buf in bufs) if (buf != null) PacketPool.release(buf)
                    }
                    if (backpressureTeardown) {
                        teardown()
                        break
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (_: Exception) {
            } finally {
                // finally guarantees teardown + stat update run on every exit path:
                // normal EOF, socket IOException, CancellationException, and scope cancel.
                if (!firstByteReceived && connectDoneMs > 0L) VpnStats.tcpSessionsNoFirstByte.incrementAndGet()
                // NonCancellable: if serverJob was cancelled externally, a plain suspend call
                // would throw CancellationException and skip teardown. Wrap so teardown always runs.
                withContext(NonCancellable) { sessionMutex.withLock { teardown() } }
            }
        }
    }

    // ── Point 8: packet written to TUN ────────────────────────────────────────
    // Sends control packets (SYN-ACK, ACK, RST, FIN-ACK) via the UNLIMITED control queue.
    // Drop only on closed channel (VPN shutdown); never dropped due to capacity.
    private fun send(pkt: ByteArray, desc: String = "?") {
        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "[8] TUN← ${pkt.size}B [$desc] $srcIp:$srcPort→$dstIp:$dstPort")
        val pw = PacketWrite(pkt, pkt.size, priority = WritePriority.CONTROL)
        if (tunWriteControlQueue.trySend(pw).isSuccess) {
            val depth = VpnStats.tunWriteControlDepth.incrementAndGet()
            if (depth > VpnStats.tunWriteControlMaxDepth.get()) VpnStats.tunWriteControlMaxDepth.set(depth)
        } else {
            VpnStats.tunWriteControlDrops.incrementAndGet()
        }
    }

    private fun teardown() {
        if (!tornDown.compareAndSet(false, true)) return
        state = State.CLOSED_FINAL
        inQueue.close()     // causes the for-loop in queueJob to exit naturally
        queueJob?.cancel()  // belt-and-suspenders: also cancel if it's still waiting
        queueJob = null
        serverJob?.cancel()
        serverJob = null
        serverOut = null
        runCatching { server?.close() }
        server = null
        if (VERBOSE_PACKET_LOGS && Log.isLoggable(TAG, Log.DEBUG)) Log.d(TAG, "torn down $srcIp:$srcPort→$dstIp:$dstPort")
        onClose()
    }

    // Suspends briefly if the data queue is congested, to avoid overwhelming the TUN writer.
    // Polls at DATA_QUEUE_BACKPRESSURE_DELAY_MS intervals until depth drops below the soft limit
    // or DATA_QUEUE_BACKPRESSURE_MAX_DELAY_MS has elapsed — whichever comes first.
    private suspend fun waitForDataQueueCapacity() {
        var waitedMs = 0L
        while (
            VpnStats.tunWriteDataDepth.get() > DATA_QUEUE_SOFT_LIMIT &&
            waitedMs < DATA_QUEUE_BACKPRESSURE_MAX_DELAY_MS
        ) {
            delay(DATA_QUEUE_BACKPRESSURE_DELAY_MS)
            waitedMs += DATA_QUEUE_BACKPRESSURE_DELAY_MS
        }
        if (waitedMs > 0) {
            VpnStats.tunDataBackpressureWaits.incrementAndGet()
            VpnStats.tunDataBackpressureMs.addAndGet(waitedMs)
        }
    }

    companion object {
        private const val TAG                    = "TcpSession"
        private const val VERBOSE_PACKET_LOGS    = false   // set true to trace every packet in debug builds
        private const val CONNECT_TIMEOUT_MS     = 2_500
        private const val CONNECT_WARN_MS        = 500     // log warning if TCP connect exceeds this
        private const val READ_BUFFER_SIZE       = 32_768   // 32 KB ≈ 23 MSS; limits per-read burst to reduce queue depth spikes
        private const val MSS                    = 1_460   // MTU(1500) − IP(20) − TCP(20)
        private const val DATA_QUEUE_SOFT_LIMIT           = 384    // start backpressure when data queue exceeds this depth
        private const val DATA_QUEUE_BACKPRESSURE_DELAY_MS   = 2L  // poll interval while waiting for queue to drain
        private const val DATA_QUEUE_BACKPRESSURE_MAX_DELAY_MS = 200L // hard cap: never wait more than 200 ms per read
        private const val HIGH_QUEUE_THRESHOLD   = 64     // warn and count when session queue exceeds this
        const val NO_FIRST_BYTE_TIMEOUT_MS       = 15_000L   // tear down if no server byte in 15 s
        const val IDLE_SESSION_TIMEOUT_MS        = 120_000L  // tear down after 2 min of no activity (streams may pause between chunks)

        fun key(srcIp: String, srcPort: Int, dstIp: String, dstPort: Int): String =
            "$srcIp:$srcPort->$dstIp:$dstPort"

        // Returns true when nextSeq falls within [relayAck-window, relayAck] in 32-bit circular
        // space, meaning those bytes were already forwarded. Used to detect client retransmits.
        private fun seq32Covered(nextSeq: Long, relayAck: Long): Boolean =
            ((relayAck - nextSeq) and 0xFFFF_FFFFL) < 0x8000_0000L

        /** Parses "a.b.c.d" into a packed 32-bit int once at session construction. */
        private fun ipToInt(ip: String): Int {
            val p = ip.split(".")
            return (p[0].toInt() shl 24) or (p[1].toInt() shl 16) or
                   (p[2].toInt() shl  8) or  p[3].toInt()
        }
    }
}
