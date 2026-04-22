package com.libertyshield.agent.vpn

class TcpSessionTable {
    private val sessions = HashMap<String, TcpSession>()

    @Synchronized
    fun getOrCreate(key: String, isSyn: Boolean, create: () -> TcpSession): TcpSession? {
        val existing = sessions[key]
        if (existing != null) return existing
        if (!isSyn) return null
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
}
