package com.libertyshield.agent.vpn

import android.util.Log

class TcpSessionTable {
    private val sessions = HashMap<String, TcpSession>()
    private var lastSessionLimitLogMs = 0L

    @Synchronized
    fun getOrCreate(key: String, isSyn: Boolean, create: () -> TcpSession): TcpSession? {
        val existing = sessions[key]
        if (existing != null) return existing
        if (!isSyn) return null
        if (sessions.size >= MAX_TCP_SESSIONS) {
            VpnStats.tcpSessionsRejectedCap.incrementAndGet()
            val now = System.currentTimeMillis()
            if (now - lastSessionLimitLogMs >= OVERFLOW_LOG_INTERVAL_MS) {
                lastSessionLimitLogMs = now
                Log.w(TAG, "TCP session limit ($MAX_TCP_SESSIONS) reached — new SYNs rejected until sessions close")
            }
            return null
        }
        return create().also { sessions[key] = it }
    }

    @Synchronized
    fun remove(key: String) {
        sessions.remove(key)?.close()
    }

    @Synchronized
    fun closeAll() {
        sessions.values.forEach { it.close() }
        sessions.clear()
    }

    @Synchronized
    fun pruneExpired() {
        val nowMs = System.currentTimeMillis()
        val toExpire = mutableListOf<Triple<String, TcpSession, String>>()
        for ((key, session) in sessions) {
            val reason = session.expiryReason(nowMs) ?: continue
            toExpire.add(Triple(key, session, reason))
        }
        for ((key, session, reason) in toExpire) {
            sessions.remove(key)
            session.closeExpired(reason)  // calls teardown → onClose → remove (reentrant, no-op)
        }
    }

    companion object {
        private const val TAG = "TcpSessionTable"
        const val MAX_TCP_SESSIONS = 512
        private const val OVERFLOW_LOG_INTERVAL_MS = 10_000L
    }
}
