package com.libertyshield.agent.ffi

/**
 * Sprint 201 — Safe Kotlin wrapper around the Rust FFI boundary.
 *
 * All security-critical logic (crypto, routing, replay, scheduling) remains
 * inside the Rust runtime.  This class is a thin pass-through.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
class RuntimeBridge {

    companion object {
        const val FFI_OK = 0
        const val ERR_WRONG_STATE = -1
        const val ERR_NOT_INIT = -2
        const val ERR_MALFORMED = -3
        const val ERR_NO_PACKET = -5
        const val ERR_BUFFER_TOO_SMALL = -6

        private const val POLL_BUF_SIZE = 65_536

        fun stateLabel(code: Int): String = when (code) {
            0 -> "New"
            1 -> "Configured"
            2 -> "Bootstrapping"
            3 -> "Running"
            4 -> "Degraded"
            5 -> "Stopped"
            ERR_NOT_INIT -> "Uninitialised"
            else -> "Unknown($code)"
        }
    }

    // Pre-allocated poll buffer — avoids a 64 KB allocation on every poll call.
    private val pollBuffer = ByteArray(POLL_BUF_SIZE)

    /**
     * Initialise the Rust runtime with the 32-byte [nodeId].
     * Must be called before [start].
     */
    fun init(nodeId: ByteArray): Boolean {
        require(nodeId.size == 32) { "nodeId must be exactly 32 bytes" }
        return LibertyNative.nativeInitNode(nodeId) == FFI_OK
    }

    /**
     * Bootstrap the node to Running state.
     * Must call [init] first.
     */
    fun start(): Boolean = LibertyNative.nativeStartNode() == FFI_OK

    /** Stop the runtime. */
    fun stop(): Boolean = LibertyNative.nativeStopNode() == FFI_OK

    /** Raw runtime state code (0–5) or negative error code. */
    fun statusCode(): Int = LibertyNative.nativeRuntimeStatus()

    /** Human-readable state label. */
    fun statusLabel(): String = stateLabel(statusCode())

    /** Returns true if the runtime is in Running state. */
    fun isRunning(): Boolean = statusCode() == 3

    /**
     * Ingest a raw packet (UDP payload from the real network) into the runtime.
     * Must be in Running state.
     */
    fun ingest(packet: ByteArray): Boolean =
        LibertyNative.nativeIngestPacket(packet) == FFI_OK

    /**
     * Poll for the next outbound packet the runtime wants to send.
     * Returns a copy of the packet bytes, or null if the queue is empty.
     *
     * Caller is responsible for transmitting the returned bytes to the peer.
     */
    fun pollSendIntent(): ByteArray? {
        val n = LibertyNative.nativePollSendIntent(pollBuffer)
        return if (n > 0) pollBuffer.copyOf(n) else null
    }

    /**
     * Advance the runtime epoch by [n] ticks.
     * Drive this from a background timer to keep protocol state fresh.
     */
    fun tick(n: Int = 1): Boolean = LibertyNative.nativeTickRuntime(n) == FFI_OK
}
