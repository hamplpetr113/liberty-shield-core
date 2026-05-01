package com.libertyshield.agent.ffi

/**
 * Sprint 201 — JNI declarations for the Liberty Shield Rust runtime.
 *
 * Loads libliberty_controlled_chaos.so (cross-compiled with android-ffi feature).
 * All methods are private raw JNI calls; use [RuntimeBridge] for safe access.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
internal object LibertyNative {

    init {
        System.loadLibrary("liberty_controlled_chaos")
    }

    /** Initialise the global runtime with a 32-byte node ID. Returns FFI_OK (0) or error code. */
    external fun nativeInitNode(nodeId: ByteArray): Int

    /** Bootstrap the node to Running state. Returns FFI_OK (0) or error code. */
    external fun nativeStartNode(): Int

    /** Stop the running node. Returns FFI_OK (0) or error code. */
    external fun nativeStopNode(): Int

    /** Current runtime state: 0=New 1=Configured 2=Bootstrapping 3=Running 4=Degraded 5=Stopped */
    external fun nativeRuntimeStatus(): Int

    /** Ingest a raw IP/UDP packet into the Rust runtime. Returns FFI_OK (0) or error code. */
    external fun nativeIngestPacket(data: ByteArray): Int

    /**
     * Fill [buf] with the next outbound packet.
     * Returns bytes written (>0) or a negative error code.
     * [buf] must be pre-allocated by the caller (recommend 65536 bytes).
     */
    external fun nativePollSendIntent(buf: ByteArray): Int

    /** Advance the runtime epoch by [n] ticks. Returns FFI_OK (0) or error code. */
    external fun nativeTickRuntime(n: Int): Int
}
