package com.libertyshield.agent.tunnel

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Builds wire-compatible authenticated Hello frames matching server/exit-node/src/packet.rs.
 *
 * Frame format (big-endian, 22-byte header + payload):
 *   version(1) | msg_type(1) | flags(2) | session_id(8) | sequence(8) | payload_len(2) | payload(N)
 *
 * Authenticated Hello payload layout:
 *   [32-byte HMAC-SHA256 token][original_payload]
 *
 * HMAC canonical message matches Rust auth.rs:
 *   session_id (8 BE) || sequence (8 BE) || msg_type (0x01) || original_payload
 *
 * No Android dependencies — pure Kotlin/JVM, fully unit-testable on the JVM.
 */
object HelloFrameBuilder {

    private const val VERSION_1: Byte = 0x01
    private const val MSG_HELLO: Byte = 0x01
    const val HMAC_LEN = 32
    const val HEADER_LEN = 22

    /**
     * Parse a 64-hex-character PSK string into 32 bytes.
     * Throws [IllegalArgumentException] on wrong length or non-hex input.
     */
    fun parsePsk(hex: String): ByteArray {
        require(hex.length == 64) {
            "PSK must be 64 hex characters (32 bytes); got ${hex.length}"
        }
        return ByteArray(32) { i ->
            val hi = hex[i * 2].digitToIntOrNull(16)
                ?: throw IllegalArgumentException("Non-hex character '${hex[i * 2]}' at position ${i * 2}")
            val lo = hex[i * 2 + 1].digitToIntOrNull(16)
                ?: throw IllegalArgumentException("Non-hex character '${hex[i * 2 + 1]}' at position ${i * 2 + 1}")
            ((hi shl 4) or lo).toByte()
        }
    }

    /**
     * Compute HMAC-SHA256 token for a Hello frame.
     * Canonical message: session_id (8 BE) || sequence (8 BE) || 0x01 || originalPayload
     */
    fun hmacToken(
        psk: ByteArray,
        sessionId: Long,
        sequence: Long,
        originalPayload: ByteArray,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(psk, "HmacSHA256"))
        mac.update(sessionId.toBeBytes())
        mac.update(sequence.toBeBytes())
        mac.update(byteArrayOf(MSG_HELLO))
        mac.update(originalPayload)
        return mac.doFinal()
    }

    /**
     * Build a complete authenticated Hello frame ready to send as a UDP payload.
     *
     * With the default [originalPayload] of "hello" and HMAC_LEN=32:
     *   frame_len = 22 + 32 + 5 = 59 bytes (matches v0.5.4 VPS-confirmed frame length)
     */
    fun buildHelloFrame(
        psk: ByteArray,
        sessionId: Long,
        sequence: Long,
        originalPayload: ByteArray = "hello".toByteArray(),
    ): ByteArray {
        val token = hmacToken(psk, sessionId, sequence, originalPayload)
        val payload = token + originalPayload
        val payloadLen = payload.size
        return ByteArray(HEADER_LEN + payloadLen).also { buf ->
            buf[0] = VERSION_1
            buf[1] = MSG_HELLO
            // buf[2], buf[3] = flags = 0x0000 (ByteArray initialises to 0)
            sessionId.toBeBytes().copyInto(buf, destinationOffset = 4)
            sequence.toBeBytes().copyInto(buf, destinationOffset = 12)
            buf[20] = (payloadLen ushr 8).toByte()
            buf[21] = payloadLen.toByte()
            payload.copyInto(buf, destinationOffset = HEADER_LEN)
        }
    }

    private fun Long.toBeBytes(): ByteArray = ByteArray(8) { i ->
        (this ushr (56 - i * 8)).toByte()
    }
}
