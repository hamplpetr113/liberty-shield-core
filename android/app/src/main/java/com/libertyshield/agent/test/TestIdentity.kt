package com.libertyshield.agent.test

/**
 * Sprint 202 — Deterministic test-mode node identity.
 *
 * THIS IS NOT A PRODUCTION IDENTITY.  Never use these IDs in a real deployment.
 * Test IDs are derived from a single seed byte so that two phones can be
 * configured without a real identity management system.
 *
 * Phone A: seed = 0x0A  →  nodeId = [0x0A, 0x0A, ... 0x0A]  (32 bytes)
 * Phone B: seed = 0x0B  →  nodeId = [0x0B, 0x0B, ... 0x0B]  (32 bytes)
 */
object TestIdentity {

    const val SEED_PHONE_A: Byte = 0x0A
    const val SEED_PHONE_B: Byte = 0x0B

    /**
     * Generate a 32-byte test node ID from a single seed byte.
     * All bytes are identical to the seed — trivially distinguishable,
     * never suitable for real use.
     */
    fun nodeIdFromSeed(seed: Byte): ByteArray = ByteArray(32) { seed }

    /** Pre-built Phone A test ID. */
    val PHONE_A_ID: ByteArray get() = nodeIdFromSeed(SEED_PHONE_A)

    /** Pre-built Phone B test ID. */
    val PHONE_B_ID: ByteArray get() = nodeIdFromSeed(SEED_PHONE_B)

    /** Hex string representation for display (first 4 bytes only). */
    fun shortHex(nodeId: ByteArray): String =
        nodeId.take(4).joinToString("") { "%02x".format(it) } + "..."
}
