package com.libertyshield.agent.vpn

/**
 * TTL-based in-memory cache for DNS (UDP port 53) responses.
 *
 * Key  : DNS question bytes with the 2-byte transaction ID zeroed out.
 *        Two queries for the same domain/type differ only in transaction ID — zeroing
 *        it makes them compare equal for cache purposes.
 *
 * Value: cloned response bytes.  On cache hit the first 2 bytes (transaction ID)
 *        are patched to match the incoming query before injection into the TUN,
 *        so the app sees a correctly echoed transaction ID per RFC 1035 §4.1.1.
 *
 * Thread-safe via @Synchronized — called concurrently from PacketForwarder IO coroutines.
 * LRU eviction at MAX_ENTRIES prevents unbounded memory growth.
 */
class DnsCache(private val ttlMs: Long = TTL_MS) {

    private data class Entry(val response: ByteArray, val expiresAt: Long)

    // Access-ordered LinkedHashMap → eldest entry = least recently used → auto-evicts at capacity
    private val cache = object : LinkedHashMap<String, Entry>(MAX_ENTRIES + 1, 0.75f, true) {
        override fun removeEldestEntry(eldest: Map.Entry<String, Entry>) = size > MAX_ENTRIES
    }

    /**
     * Returns a cloned cached response (transaction ID patched to match [query]) if a
     * non-expired entry exists, otherwise null.
     */
    @Synchronized
    fun get(query: ByteArray): ByteArray? {
        if (query.size < 4) return null
        val key = cacheKey(query)
        val entry = cache[key] ?: return null
        if (System.currentTimeMillis() > entry.expiresAt) {
            cache.remove(key)
            return null
        }
        val out = entry.response.copyOf()
        out[0] = query[0]   // patch transaction ID
        out[1] = query[1]
        return out
    }

    /**
     * Stores [response] if it is a valid, non-error DNS response.
     * Validation:
     *   - response.size >= 12 (minimum DNS message length)
     *   - QR bit (flags byte 2 bit 7) == 1  → it is a response, not a query
     *   - RCODE (low 4 bits of byte 3) == 0 → NOERROR; don't cache NXDOMAIN etc.
     */
    @Synchronized
    fun put(query: ByteArray, response: ByteArray) {
        if (query.size < 4 || response.size < 12) return
        val flags = ((response[2].toInt() and 0xFF) shl 8) or (response[3].toInt() and 0xFF)
        val isResponse = (flags and 0x8000) != 0
        val rcode      = flags and 0x000F
        if (!isResponse || rcode != 0) return
        cache[cacheKey(query)] = Entry(response.copyOf(), System.currentTimeMillis() + ttlMs)
    }

    /** Cache key = hex of query payload with bytes 0–1 (transaction ID) zeroed. */
    private fun cacheKey(query: ByteArray): String {
        val sb = StringBuilder(query.size * 2)
        sb.append("0000")
        for (i in 2 until query.size) {
            val b = query[i].toInt() and 0xFF
            if (b < 16) sb.append('0')
            sb.append(b.toString(16))
        }
        return sb.toString()
    }

    companion object {
        const val TTL_MS      = 45_000L  // 45-second TTL — covers a typical browser page-load burst
        const val MAX_ENTRIES = 256
    }
}
