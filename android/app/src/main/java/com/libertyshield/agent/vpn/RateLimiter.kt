package com.libertyshield.agent.vpn

// Fixed-window rate limiter. Resets the counter at the start of each window.
// Thread-safe via @Synchronized.
class RateLimiter(
    private val maxPerWindow: Int,
    private val windowMs: Long = 60_000L,
) {
    private var windowStart = System.currentTimeMillis()
    private var count = 0

    @Synchronized
    fun tryAcquire(): Boolean {
        val now = System.currentTimeMillis()
        if (now - windowStart >= windowMs) {
            windowStart = now
            count = 0
        }
        return if (count < maxPerWindow) { count++; true } else false
    }
}
