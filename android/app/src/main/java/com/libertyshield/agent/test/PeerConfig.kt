package com.libertyshield.agent.test

import android.content.Context
import android.content.SharedPreferences

/**
 * Sprint 203 — Manual peer configuration for the two-phone test.
 *
 * No discovery protocol.  Both phones are configured manually with:
 *   - local UDP port to listen on
 *   - peer IP address
 *   - peer UDP port
 *   - which phone identity to use (A or B)
 *
 * Configuration is persisted in SharedPreferences so it survives app restarts.
 *
 * TEST MODE ONLY — NOT FOR PRODUCTION USE.
 */
data class PeerConfig(
    val localNodeSeed: Byte,
    val peerNodeSeed: Byte,
    val localUdpPort: Int,
    val peerIp: String,
    val peerUdpPort: Int,
) {
    val localNodeId: ByteArray get() = TestIdentity.nodeIdFromSeed(localNodeSeed)
    val peerNodeId: ByteArray get() = TestIdentity.nodeIdFromSeed(peerNodeSeed)

    companion object {
        /** Default config for Phone A — expects Phone B at 192.168.1.100:9001. */
        fun phoneADefaults() = PeerConfig(
            localNodeSeed = TestIdentity.SEED_PHONE_A,
            peerNodeSeed = TestIdentity.SEED_PHONE_B,
            localUdpPort = 9000,
            peerIp = "192.168.1.100",
            peerUdpPort = 9001,
        )

        /** Default config for Phone B — expects Phone A at 192.168.1.101:9000. */
        fun phoneBDefaults() = PeerConfig(
            localNodeSeed = TestIdentity.SEED_PHONE_B,
            peerNodeSeed = TestIdentity.SEED_PHONE_A,
            localUdpPort = 9001,
            peerIp = "192.168.1.101",
            peerUdpPort = 9000,
        )
    }
}

/** SharedPreferences-backed persistence for [PeerConfig]. */
class PeerConfigStore(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("liberty_test_peer_config", Context.MODE_PRIVATE)

    fun save(config: PeerConfig) {
        prefs.edit()
            .putInt("local_seed", config.localNodeSeed.toInt())
            .putInt("peer_seed", config.peerNodeSeed.toInt())
            .putInt("local_port", config.localUdpPort)
            .putString("peer_ip", config.peerIp)
            .putInt("peer_port", config.peerUdpPort)
            .apply()
    }

    fun load(): PeerConfig? {
        if (!prefs.contains("local_port")) return null
        return PeerConfig(
            localNodeSeed = prefs.getInt("local_seed", 0x0A).toByte(),
            peerNodeSeed = prefs.getInt("peer_seed", 0x0B).toByte(),
            localUdpPort = prefs.getInt("local_port", 9000),
            peerIp = prefs.getString("peer_ip", "192.168.1.100") ?: "192.168.1.100",
            peerUdpPort = prefs.getInt("peer_port", 9001),
        )
    }

    fun loadOrDefault(isPhoneA: Boolean): PeerConfig =
        load() ?: if (isPhoneA) PeerConfig.phoneADefaults() else PeerConfig.phoneBDefaults()
}
