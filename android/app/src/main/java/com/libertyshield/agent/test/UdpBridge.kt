package com.libertyshield.agent.test

import com.libertyshield.agent.ffi.RuntimeBridge
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * Sprint 204 — UDP transport bridge connecting the Rust runtime to real network sockets.
 *
 * Responsibilities (transport only — zero routing or crypto logic here):
 *   1. Bind a UDP socket on [localPort].
 *   2. Drain the Rust outbound queue and send packets to the peer.
 *   3. Receive UDP datagrams and pass them to the Rust ingest function.
 *
 * All security-critical work happens inside the Rust runtime.
 * Kotlin only moves bytes between the socket and the FFI boundary.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
class UdpBridge(
    private val bridge: RuntimeBridge,
    private val config: PeerConfig,
) {
    private var socket: DatagramSocket? = null
    private var recvJob: Job? = null
    private var sendJob: Job? = null

    val packetsSent = AtomicLong(0)
    val packetsReceived = AtomicLong(0)
    val sendErrors = AtomicLong(0)
    val ingestErrors = AtomicLong(0)

    /** Bind the UDP socket and start the send/receive loops. */
    fun start(scope: CoroutineScope): Boolean {
        return try {
            val sock = DatagramSocket(config.localUdpPort)
            sock.soTimeout = 200  // ms — lets the receive loop check isActive
            socket = sock
            LibertyLogger.udpBind(config.localUdpPort, result = true)
            startReceiveLoop(scope, sock)
            startSendLoop(scope, sock)
            true
        } catch (e: Exception) {
            LibertyLogger.udpBind(config.localUdpPort, result = false, detail = e.message ?: "")
            LibertyLogger.error("UdpBridge", "bind failed: ${e.message}")
            false
        }
    }

    /** Close socket and cancel loops. */
    fun stop() {
        recvJob?.cancel()
        sendJob?.cancel()
        socket?.close()
        socket = null
    }

    /** Send [data] directly to the peer (bypasses Rust queue — for test pings). */
    fun sendRaw(data: ByteArray): Boolean {
        val sock = socket ?: return false
        return try {
            val peerAddr = InetAddress.getByName(config.peerIp)
            val pkt = DatagramPacket(data, data.size, peerAddr, config.peerUdpPort)
            sock.send(pkt)
            packetsSent.incrementAndGet()
            LibertyLogger.udpSend(data.size, "${config.peerIp}:${config.peerUdpPort}", true)
            true
        } catch (e: Exception) {
            sendErrors.incrementAndGet()
            LibertyLogger.udpSend(data.size, "${config.peerIp}:${config.peerUdpPort}", false)
            LibertyLogger.error("UdpBridge", "sendRaw failed: ${e.message}")
            false
        }
    }

    /**
     * Optional callback invoked on the IO thread for every received datagram.
     * Set before calling [start]. Used by TestModeController for ping/pong handling.
     */
    var onPacketReceived: ((ByteArray) -> Unit)? = null

    // Receive loop: read UDP datagrams, hand to Rust ingest.
    private fun startReceiveLoop(scope: CoroutineScope, sock: DatagramSocket) {
        recvJob = scope.launch(Dispatchers.IO) {
            val buf = ByteArray(65_536)
            val pkt = DatagramPacket(buf, buf.size)
            while (isActive && !sock.isClosed) {
                try {
                    sock.receive(pkt)
                    val data = pkt.data.copyOf(pkt.length)
                    val from = "${pkt.address.hostAddress}:${pkt.port}"
                    packetsReceived.incrementAndGet()
                    LibertyLogger.udpRecv(data.size, from)
                    val ok = bridge.ingest(data)
                    LibertyLogger.ingest(data.size, ok)
                    if (!ok) ingestErrors.incrementAndGet()
                    onPacketReceived?.invoke(data)
                } catch (_: java.net.SocketTimeoutException) {
                    // normal — loop continues to check isActive
                } catch (e: Exception) {
                    if (isActive) LibertyLogger.error("UdpBridge.recv", e.message ?: "")
                }
            }
        }
    }

    // Send loop: drain Rust outbound queue, send each packet to peer.
    private fun startSendLoop(scope: CoroutineScope, sock: DatagramSocket) {
        sendJob = scope.launch(Dispatchers.IO) {
            val peerAddr = InetAddress.getByName(config.peerIp)
            while (isActive && !sock.isClosed) {
                val outbound = bridge.pollSendIntent()
                if (outbound != null) {
                    try {
                        val dgram = DatagramPacket(outbound, outbound.size, peerAddr, config.peerUdpPort)
                        sock.send(dgram)
                        packetsSent.incrementAndGet()
                        LibertyLogger.udpSend(outbound.size, "${config.peerIp}:${config.peerUdpPort}", true)
                    } catch (e: Exception) {
                        sendErrors.incrementAndGet()
                        LibertyLogger.error("UdpBridge.send", e.message ?: "")
                    }
                } else {
                    // Queue empty — yield briefly before polling again.
                    kotlinx.coroutines.delay(10)
                }
            }
        }
    }
}
