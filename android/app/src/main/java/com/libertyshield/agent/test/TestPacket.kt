package com.libertyshield.agent.test

/**
 * Sprint 207 — Test packet protocol for the two-phone ping/pong test.
 *
 * Wire format (all big-endian):
 *   [0]      magic byte: 0xAB
 *   [1]      type:  0x01 = TEST_PING, 0x02 = TEST_PONG
 *   [2..5]   sequence number (u32 big-endian)
 *   [6..37]  sender node ID (32 bytes)
 *   [38..53] padding zeros (16 bytes)
 *
 * Total: 54 bytes.  Well above the Rust ingest minimum (>= 4 bytes for malformed check).
 *
 * Path through Rust runtime:
 *   Android A → [ingest into Rust] → [Rust outbound queue] → UDP → Android B → [ingest into Rust]
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
object TestPacket {

    const val MAGIC: Byte = 0xAB.toByte()
    const val TYPE_PING: Byte = 0x01
    const val TYPE_PONG: Byte = 0x02
    const val PACKET_SIZE = 54

    fun buildPing(seqNo: Int, senderNodeId: ByteArray): ByteArray =
        build(TYPE_PING, seqNo, senderNodeId)

    fun buildPong(seqNo: Int, senderNodeId: ByteArray): ByteArray =
        build(TYPE_PONG, seqNo, senderNodeId)

    private fun build(type: Byte, seqNo: Int, senderNodeId: ByteArray): ByteArray {
        require(senderNodeId.size == 32) { "senderNodeId must be 32 bytes" }
        return ByteArray(PACKET_SIZE).also { p ->
            p[0] = MAGIC
            p[1] = type
            p[2] = (seqNo ushr 24).toByte()
            p[3] = (seqNo ushr 16).toByte()
            p[4] = (seqNo ushr 8).toByte()
            p[5] = seqNo.toByte()
            senderNodeId.copyInto(p, destinationOffset = 6)
            // bytes 38-53 remain zero (padding)
        }
    }

    /** Returns true if [data] looks like a test packet. */
    fun isTestPacket(data: ByteArray): Boolean =
        data.size >= PACKET_SIZE && data[0] == MAGIC

    /** Returns true if [data] is a PING packet. */
    fun isPing(data: ByteArray): Boolean = isTestPacket(data) && data[1] == TYPE_PING

    /** Returns true if [data] is a PONG packet. */
    fun isPong(data: ByteArray): Boolean = isTestPacket(data) && data[1] == TYPE_PONG

    /** Extract the sequence number from a test packet. */
    fun seqNo(data: ByteArray): Int =
        ((data[2].toInt() and 0xFF) shl 24) or
                ((data[3].toInt() and 0xFF) shl 16) or
                ((data[4].toInt() and 0xFF) shl 8) or
                (data[5].toInt() and 0xFF)

    /** Extract the sender node ID from a test packet. */
    fun senderNodeId(data: ByteArray): ByteArray = data.copyOfRange(6, 38)
}
