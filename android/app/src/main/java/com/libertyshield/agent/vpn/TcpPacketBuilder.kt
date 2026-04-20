package com.libertyshield.agent.vpn

/**
 * Builds raw IPv4 + TCP packets for injection into the TUN file descriptor.
 *
 * Perspective: the relay impersonates the *remote server* replying to the *local app*.
 * All callers must therefore invert src/dst relative to the captured packet:
 *
 *   srcIp / srcPort  →  remote server  (original dstIp / dstPort)
 *   dstIp / dstPort  →  local app      (original srcIp / srcPort)
 *
 * Seq / ack semantics (RFC 793):
 *   seq  — sequence number of the first byte of payload in this segment,
 *           or the relay's ISN for SYN; or the relay's next-send-seq for
 *           control-only segments.
 *   ack  — the next byte the *sender* expects from the other side.
 *           Only meaningful when FLAG_ACK is set.
 *
 * This object is stateless.  TcpSession owns the seq/ack counters and is
 * responsible for advancing them after each call:
 *   • SYN-ACK sent  →  seq += 1    (SYN consumes one sequence number)
 *   • Data sent     →  seq += payload.size
 *   • FIN-ACK sent  →  seq += 1    (FIN consumes one sequence number)
 *   • Pure ACK sent →  seq unchanged
 */
object TcpPacketBuilder {

    // ── TCP flag bits ─────────────────────────────────────────────────────────
    const val FLAG_FIN: Int = 0x01
    const val FLAG_SYN: Int = 0x02
    const val FLAG_RST: Int = 0x04
    const val FLAG_PSH: Int = 0x08
    const val FLAG_ACK: Int = 0x10

    // Conservative fixed window advertised to the app.  No window-scaling option
    // in MVP — the app will cap its send rate accordingly, which is acceptable.
    private const val WINDOW_SIZE = 65535

    private const val IP_HEADER_LEN  = 20   // no IP options
    private const val TCP_HEADER_LEN = 20   // no TCP options

    // ── Public builders ───────────────────────────────────────────────────────

    /**
     * SYN-ACK — completes the three-way handshake.
     *
     *   seq = relay's ISN
     *   ack = appISN + 1  (the app's SYN counts as one byte)
     *
     * Caller must increment its seq by 1 after sending.
     */
    fun buildSynAck(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
    ): ByteArray = build(srcIp, dstIp, srcPort, dstPort, seq, ack, FLAG_SYN or FLAG_ACK)

    /**
     * Pure ACK — acknowledges data received from the app; carries no payload.
     *
     *   seq = relay's current send-seq (unchanged; no new data is being sent)
     *   ack = cumulative bytes received from app so far
     *
     * Caller does not advance seq after sending.
     */
    fun buildAck(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
    ): ByteArray = build(srcIp, dstIp, srcPort, dstPort, seq, ack, FLAG_ACK)

    /**
     * Data segment (PSH | ACK) — carries server response payload to the app.
     *
     *   seq = relay's current send-seq (first byte of this chunk in the stream)
     *   ack = last cumulative ack (bytes received from app; unchanged if no new app data)
     *
     * PSH tells the app's TCP stack to deliver the data immediately rather than
     * waiting to fill a larger buffer.
     *
     * Caller must increment its seq by payload.size after sending.
     */
    fun buildData(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
        payload: ByteArray,
    ): ByteArray = build(srcIp, dstIp, srcPort, dstPort, seq, ack, FLAG_PSH or FLAG_ACK, payload)

    /**
     * FIN-ACK — initiates or acknowledges graceful connection teardown.
     *
     *   seq = relay's current send-seq
     *   ack = last cumulative ack from app
     *
     * Caller must increment its seq by 1 after sending (FIN counts as one byte).
     */
    fun buildFinAck(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
    ): ByteArray = build(srcIp, dstIp, srcPort, dstPort, seq, ack, FLAG_FIN or FLAG_ACK)

    /**
     * RST — abruptly tears down the connection.
     *
     * [ackFlag = false]  Unsolicited reset (session not yet synchronised):
     *   seq = relay's current send-seq (or the ack field of the offending segment)
     *   ack = 0 (ACK flag not set; ack field is ignored by receiver)
     *
     * [ackFlag = true]  RST|ACK in response to a SYN (e.g. session table full):
     *   seq = 0
     *   ack = appISN + 1
     *
     * RFC 793 §3.4: use RST (no ACK) when not synchronised; RST|ACK when synchronised.
     */
    fun buildRst(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
        ackFlag: Boolean = false,
    ): ByteArray = build(
        srcIp, dstIp, srcPort, dstPort, seq, ack,
        if (ackFlag) FLAG_RST or FLAG_ACK else FLAG_RST,
    )

    // ── Core packet constructor ───────────────────────────────────────────────

    private fun build(
        srcIp: String, dstIp: String,
        srcPort: Int,  dstPort: Int,
        seq: Long,     ack: Long,
        flags: Int,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val tcpLen   = TCP_HEADER_LEN + payload.size
        val totalLen = IP_HEADER_LEN  + tcpLen
        val out      = ByteArray(totalLen)  // zero-initialised by JVM

        writeIpHeader(out, srcIp, dstIp, totalLen)
        writeTcpHeader(out, srcPort, dstPort, seq, ack, flags, payload)

        // TCP checksum must be computed after both headers and payload are in place,
        // with the checksum field still zero (guaranteed by zero-init above + no early write).
        val cksum = tcpChecksum(out, srcIp, dstIp, tcpLen)
        out[IP_HEADER_LEN + 16] = (cksum shr 8).toByte()
        out[IP_HEADER_LEN + 17] = cksum.toByte()

        return out
    }

    // ── IPv4 header (RFC 791) ─────────────────────────────────────────────────

    private fun writeIpHeader(out: ByteArray, srcIp: String, dstIp: String, totalLen: Int) {
        // Byte 0: version (4) in high nibble, IHL=5 (20 bytes, no options) in low nibble.
        out[0]  = 0x45.toByte()

        // Byte 1: DSCP + ECN — best-effort, no congestion marking.
        out[1]  = 0

        // Bytes 2-3: total packet length (IP header + TCP header + payload).
        out[2]  = (totalLen shr 8).toByte()
        out[3]  = totalLen.toByte()

        // Bytes 4-5: identification — 0; we never fragment (DF=1 below).
        out[4]  = 0
        out[5]  = 0

        // Bytes 6-7: flags + fragment offset.
        //   Bit 15 (reserved) = 0
        //   Bit 14 (DF)       = 1  — Don't Fragment
        //   Bit 13 (MF)       = 0  — no More Fragments
        //   Bits 12-0         = 0  — fragment offset = 0
        out[6]  = 0x40.toByte()
        out[7]  = 0

        // Byte 8: TTL — 64 is a conventional safe default.
        out[8]  = 64

        // Byte 9: protocol — 6 = TCP.
        out[9]  = 6

        // Bytes 10-11: IPv4 header checksum placeholder (filled after writeIpBytes).
        out[10] = 0
        out[11] = 0

        writeIpBytes(out, 12, srcIp)
        writeIpBytes(out, 16, dstIp)

        // IPv4 header checksum covers only the 20-byte IP header (not the TCP segment).
        val cksum = ipv4Checksum(out)
        out[10] = (cksum shr 8).toByte()
        out[11] = cksum.toByte()
    }

    // ── TCP header (RFC 793, no options) ─────────────────────────────────────

    private fun writeTcpHeader(
        out: ByteArray,
        srcPort: Int, dstPort: Int,
        seq: Long,    ack: Long,
        flags: Int,
        payload: ByteArray,
    ) {
        val b = IP_HEADER_LEN   // TCP header starts immediately after the IP header

        out[b + 0] = (srcPort shr 8).toByte()
        out[b + 1] = srcPort.toByte()
        out[b + 2] = (dstPort shr 8).toByte()
        out[b + 3] = dstPort.toByte()

        // Bytes 4-7: sequence number (big-endian, 32-bit).
        // seq is held as Long to survive 32-bit wrap-around without going negative.
        // Mask to 32 bits before writing so wrap-around is handled correctly.
        val seq32 = seq and 0xFFFF_FFFFL
        out[b + 4] = (seq32 shr 24).toByte()
        out[b + 5] = (seq32 shr 16).toByte()
        out[b + 6] = (seq32 shr  8).toByte()
        out[b + 7] = seq32.toByte()

        // Bytes 8-11: acknowledgment number (big-endian, 32-bit).
        // Meaningful only when FLAG_ACK is set in flags; zero otherwise.
        val ack32 = ack and 0xFFFF_FFFFL
        out[b +  8] = (ack32 shr 24).toByte()
        out[b +  9] = (ack32 shr 16).toByte()
        out[b + 10] = (ack32 shr  8).toByte()
        out[b + 11] = ack32.toByte()

        // Byte 12: data offset (high nibble) + reserved (low nibble).
        // Data offset = 5 means the TCP header is 5 × 4 = 20 bytes — no options.
        out[b + 12] = 0x50.toByte()

        // Byte 13: control flags (URG | ACK | PSH | RST | SYN | FIN in bits 5-0).
        out[b + 13] = flags.toByte()

        // Bytes 14-15: receive window size.
        out[b + 14] = (WINDOW_SIZE shr 8).toByte()
        out[b + 15] = WINDOW_SIZE.toByte()

        // Bytes 16-17: TCP checksum — left as zero here; filled by build() after
        // the full segment is assembled, because the checksum covers the payload too.

        // Bytes 18-19: urgent pointer — 0 (URG flag is never set by this relay).

        // Payload follows immediately after the 20-byte header.
        payload.copyInto(out, b + TCP_HEADER_LEN)
    }

    // ── Checksum helpers ──────────────────────────────────────────────────────

    /**
     * TCP checksum (RFC 793 §3.1).
     *
     * The sum is computed over three regions:
     *
     *   1. 12-byte pseudo-header:
     *        srcIp (4 bytes) | dstIp (4 bytes) | 0x00 | proto=6 | tcpLength (2 bytes)
     *      The pseudo-header is NOT transmitted; it binds the checksum to the IP
     *      addresses so that a mis-routed packet is detected.
     *
     *   2. TCP header (20 bytes), with checksum field pre-zeroed.
     *
     *   3. TCP payload.
     *
     * If the combined TCP segment length is odd, a single zero byte is appended
     * *conceptually* for the sum (the extra byte is never sent).  The lone byte is
     * treated as the HIGH byte of the final 16-bit word (i.e. shifted left by 8).
     *
     * IMPORTANT: srcIp / dstIp here must match the packet being built (relay→app),
     * not the original captured packet (app→relay).  Swapping them produces a wrong
     * checksum that the kernel silently drops.
     */
    private fun tcpChecksum(out: ByteArray, srcIp: String, dstIp: String, tcpLen: Int): Int {
        var sum = 0L

        // ── Pseudo-header ──
        sum += ipWordSum(srcIp)         // source IP as two 16-bit words
        sum += ipWordSum(dstIp)         // destination IP as two 16-bit words
        sum += 6L                       // zero byte (implicit) + protocol = TCP
        sum += tcpLen.toLong()          // TCP segment length (header + payload)

        // ── TCP header + payload ──
        val start = IP_HEADER_LEN
        val end   = start + tcpLen
        var i     = start
        while (i < end - 1) {
            // Read two bytes as one unsigned 16-bit big-endian word.
            // and 0xFF is mandatory: Kotlin bytes are signed; without it, values
            // above 0x7F sign-extend into the upper bits of the Int and corrupt the sum.
            sum += ((out[i].toInt() and 0xFF) shl 8 or (out[i + 1].toInt() and 0xFF)).toLong()
            i += 2
        }
        // Odd-length segment: pad the last byte on the right with a zero nibble.
        // The lone byte is the HIGH byte of the final word (shift left, not right).
        if (i < end) {
            sum += (out[i].toInt() and 0xFF).toLong() shl 8
        }

        return foldAndInvert(sum)
    }

    /**
     * IPv4 header checksum (RFC 791).
     * Covers only the 20-byte IP header; checksum bytes must be zero when called.
     */
    private fun ipv4Checksum(out: ByteArray): Int {
        var sum = 0L
        for (i in 0 until IP_HEADER_LEN step 2) {
            sum += ((out[i].toInt() and 0xFF) shl 8 or (out[i + 1].toInt() and 0xFF)).toLong()
        }
        return foldAndInvert(sum)
    }

    /**
     * Folds a running 32-bit (or wider) one's-complement sum into 16 bits, then
     * bitwise-inverts it to produce the final checksum value.
     */
    private fun foldAndInvert(sum: Long): Int {
        var s = sum
        while (s shr 16 != 0L) s = (s and 0xFFFFL) + (s shr 16)
        return (s.inv() and 0xFFFFL).toInt()
    }

    /**
     * Sums a dotted-decimal IPv4 address string as two unsigned 16-bit big-endian words.
     * "a.b.c.d" → (a<<8 | b) + (c<<8 | d).
     */
    private fun ipWordSum(ip: String): Long {
        val o = ip.split(".").map { it.toInt() and 0xFF }
        return ((o[0] shl 8) or o[1]).toLong() + ((o[2] shl 8) or o[3]).toLong()
    }

    /** Writes a dotted-decimal IPv4 string into buf at offset as four raw bytes. */
    private fun writeIpBytes(buf: ByteArray, offset: Int, ip: String) {
        ip.split(".").forEachIndexed { i, octet ->
            buf[offset + i] = (octet.toInt() and 0xFF).toByte()
        }
    }
}
