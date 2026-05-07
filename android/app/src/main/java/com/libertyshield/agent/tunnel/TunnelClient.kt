package com.libertyshield.agent.tunnel

import android.util.Log
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Sends a single authenticated Hello UDP frame to the Liberty Shield exit node.
 *
 * Must be called from a background thread or IO coroutine — never the main thread.
 * The VPN service excludes the app's own traffic via addDisallowedApplication(), so
 * this socket bypasses the TUN and reaches the exit node directly. protect() is not needed.
 *
 * Never logs the PSK value or raw HMAC token.
 */
object TunnelClient {

    private const val TAG = "TunnelClient"

    const val EXIT_NODE_HOST = "89.221.214.211"
    const val EXIT_NODE_PORT = 51820

    data class HelloResult(
        val success: Boolean,
        val target: String,
        val frameLen: Int,
        val sessionId: Long,
        val sequence: Long,
        val authMode: String,
        val errorMessage: String? = null,
    )

    /**
     * Send one authenticated Hello datagram to the exit node.
     *
     * @param psk   32-byte PSK parsed from [HelloFrameBuilder.parsePsk]
     * @param sessionId  arbitrary u64 session identifier
     * @param sequence   frame sequence number (use 1 for the initial Hello)
     * @param host  target host (defaults to production exit node)
     * @param port  target UDP port (defaults to 51820)
     */
    fun sendHello(
        psk: ByteArray,
        sessionId: Long,
        sequence: Long = 1L,
        host: String = EXIT_NODE_HOST,
        port: Int = EXIT_NODE_PORT,
    ): HelloResult {
        val target = "$host:$port"
        return try {
            val frame = HelloFrameBuilder.buildHelloFrame(psk, sessionId, sequence)
            val addr = InetAddress.getByName(host)
            DatagramSocket().use { socket ->
                socket.send(DatagramPacket(frame, frame.size, addr, port))
            }
            Log.i(
                TAG,
                "hello sent target=$target frame_len=${frame.size} " +
                    "session=$sessionId seq=$sequence auth=HMAC-SHA256",
            )
            HelloResult(
                success = true,
                target = target,
                frameLen = frame.size,
                sessionId = sessionId,
                sequence = sequence,
                authMode = "HMAC-SHA256",
            )
        } catch (e: Exception) {
            Log.e(TAG, "hello send failed target=$target: ${e.message}")
            HelloResult(
                success = false,
                target = target,
                frameLen = 0,
                sessionId = sessionId,
                sequence = sequence,
                authMode = "HMAC-SHA256",
                errorMessage = e.message,
            )
        }
    }
}
