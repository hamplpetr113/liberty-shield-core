package com.libertyshield.agent.vpn

/**
 * Thread-safe pool of reusable 1500-byte packet buffers.
 *
 * Acquiring a buffer from the pool and releasing it back after the TUN write
 * eliminates per-packet ByteArray allocations in the TCP relay hot path and
 * reduces GC pressure during sustained throughput.
 *
 * - acquire() returns a pooled buffer, or allocates a fresh one if the pool is empty.
 * - release() returns a buffer to the pool; excess buffers beyond POOL_SIZE are
 *   discarded so the pool never grows unbounded.
 * - PACKET_SIZE matches the TUN MTU (1500) so every valid IP packet fits.
 */
object PacketPool {

    private const val PACKET_SIZE = 1500
    private const val POOL_SIZE   = 512

    private val pool = ArrayDeque<ByteArray>(POOL_SIZE)

    init {
        repeat(POOL_SIZE) {
            pool.add(ByteArray(PACKET_SIZE))
        }
    }

    @Synchronized
    fun acquire(): ByteArray = pool.removeFirstOrNull() ?: ByteArray(PACKET_SIZE)

    @Synchronized
    fun release(buf: ByteArray) {
        if (pool.size < POOL_SIZE) pool.addLast(buf)
    }
}
