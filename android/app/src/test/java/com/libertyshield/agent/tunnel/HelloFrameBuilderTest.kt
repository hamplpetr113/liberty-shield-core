package com.libertyshield.agent.tunnel

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Test
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Pure JVM unit tests for HelloFrameBuilder — no Android dependencies.
 * Run with: ./gradlew :app:testDebugUnitTest
 */
class HelloFrameBuilderTest {

    // All-0xAA PSK — 32 bytes, encoded as 64 'a' chars
    private val validPskHex = "a".repeat(64)
    private val validPsk = ByteArray(32) { 0xAA.toByte() }

    // ── PSK parsing ───────────────────────────────────────────────────────────

    @Test
    fun parsePsk_valid64hex_returns32bytes() {
        val psk = HelloFrameBuilder.parsePsk(validPskHex)
        assertEquals(32, psk.size)
        assertEquals(0xAA.toByte(), psk[0])
        assertEquals(0xAA.toByte(), psk[31])
    }

    @Test
    fun parsePsk_allZeroes_returns32zeroBytes() {
        val psk = HelloFrameBuilder.parsePsk("0".repeat(64))
        assertArrayEquals(ByteArray(32), psk)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parsePsk_tooShort_throws() {
        HelloFrameBuilder.parsePsk("aabb")
    }

    @Test(expected = IllegalArgumentException::class)
    fun parsePsk_tooLong_throws() {
        HelloFrameBuilder.parsePsk("a".repeat(66))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parsePsk_nonHexCharacter_throws() {
        HelloFrameBuilder.parsePsk("z".repeat(64))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parsePsk_empty_throws() {
        HelloFrameBuilder.parsePsk("")
    }

    // ── HMAC token ────────────────────────────────────────────────────────────

    @Test
    fun hmacToken_isDeterministic() {
        val a = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        val b = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        assertArrayEquals(a, b)
    }

    @Test
    fun hmacToken_is32Bytes() {
        val token = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        assertEquals(HelloFrameBuilder.HMAC_LEN, token.size)
    }

    @Test
    fun hmacToken_changesWithSessionId() {
        val a = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        val b = HelloFrameBuilder.hmacToken(validPsk, 2L, 1L, "hello".toByteArray())
        assertFalse("HMAC must differ when session_id changes", a.contentEquals(b))
    }

    @Test
    fun hmacToken_changesWithSequence() {
        val a = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        val b = HelloFrameBuilder.hmacToken(validPsk, 1L, 2L, "hello".toByteArray())
        assertFalse("HMAC must differ when sequence changes", a.contentEquals(b))
    }

    @Test
    fun hmacToken_changesWithPayload() {
        val a = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        val b = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "world".toByteArray())
        assertFalse("HMAC must differ when payload changes", a.contentEquals(b))
    }

    @Test
    fun hmacToken_matchesReferenceComputation() {
        // Reference: compute using javax.crypto directly with the same canonical message as Rust auth.rs:
        //   session_id (8 BE) || sequence (8 BE) || 0x01 (Hello) || original_payload
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(validPsk, "HmacSHA256"))
        mac.update(42L.toBeBytes())
        mac.update(7L.toBeBytes())
        mac.update(byteArrayOf(0x01))
        mac.update("hello".toByteArray())
        val expected = mac.doFinal()

        val actual = HelloFrameBuilder.hmacToken(validPsk, 42L, 7L, "hello".toByteArray())
        assertArrayEquals("HMAC must match independent reference computation", expected, actual)
    }

    // ── Frame structure ───────────────────────────────────────────────────────

    @Test
    fun buildHelloFrame_hasExpectedLength() {
        // 22-byte header + 32-byte HMAC + 5-byte "hello" = 59 bytes
        // This matches the VPS-confirmed authenticated frame length from v0.5.4.
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        assertEquals(59, frame.size)
    }

    @Test
    fun buildHelloFrame_versionIs1() {
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        assertEquals(0x01.toByte(), frame[0])
    }

    @Test
    fun buildHelloFrame_msgTypeIsHello() {
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        assertEquals(0x01.toByte(), frame[1])
    }

    @Test
    fun buildHelloFrame_flagsAreZero() {
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        assertEquals(0x00.toByte(), frame[2])
        assertEquals(0x00.toByte(), frame[3])
    }

    @Test
    fun buildHelloFrame_sessionIdEncodedBigEndian() {
        val sessionId = 0x0102030405060708L
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, sessionId, 1L)
        assertEquals(0x01.toByte(), frame[4])
        assertEquals(0x08.toByte(), frame[11])
    }

    @Test
    fun buildHelloFrame_payloadStartsWith32ByteHmac() {
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        val expectedToken = HelloFrameBuilder.hmacToken(validPsk, 1L, 1L, "hello".toByteArray())
        // Payload starts at byte 22 (after 22-byte header)
        assertArrayEquals(expectedToken, frame.copyOfRange(22, 54))
    }

    @Test
    fun buildHelloFrame_payloadEndsWithOriginalPayload() {
        val frame = HelloFrameBuilder.buildHelloFrame(validPsk, 1L, 1L)
        // "hello" starts at byte 54 (22 header + 32 MAC)
        assertArrayEquals("hello".toByteArray(), frame.copyOfRange(54, 59))
    }

    @Test
    fun buildHelloFrame_nonNullForAllZeroPsk() {
        val zeroPsk = ByteArray(32)
        val frame = HelloFrameBuilder.buildHelloFrame(zeroPsk, 0L, 0L)
        assertNotNull(frame)
        assertEquals(59, frame.size)
    }

    // Helper — duplicated locally so the test has no dependency on HelloFrameBuilder internals
    private fun Long.toBeBytes(): ByteArray = ByteArray(8) { i -> (this ushr (56 - i * 8)).toByte() }
}
