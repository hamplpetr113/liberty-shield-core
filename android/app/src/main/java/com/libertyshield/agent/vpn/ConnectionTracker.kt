package com.libertyshield.agent.vpn

import android.content.Context
import android.os.Build

// Per-connection UID attribution.
//
// Android < 10:  /proc/net/tcp is world-readable; local-port lookup works.
// Android 10+:   /proc/net/ is restricted to system processes.
//                getConnectionOwnerUid() requires android.permission.NETWORK_STACK
//                (signature/system permission — unavailable to third-party APKs).
//                UID is returned as -1 (unknown) on these devices.
class ConnectionTracker(private val context: Context) {

    private val pm = context.packageManager

    fun ownerUidOf(protocol: Int, srcPort: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) return -1
        return procNetLookup(protocol, srcPort)
    }

    fun packageForUid(uid: Int): String? {
        if (uid < 0) return null
        return runCatching { pm.getPackagesForUid(uid)?.firstOrNull() }.getOrNull()
    }

    // Parse /proc/net/tcp or /proc/net/udp to find the UID owning the given local port.
    // Row format: "sl: local_hex_ip:local_hex_port remote ... uid ..."
    private fun procNetLookup(protocol: Int, srcPort: Int): Int {
        val path = when (protocol) {
            PacketParser.PROTO_TCP -> "/proc/net/tcp"
            PacketParser.PROTO_UDP -> "/proc/net/udp"
            else                   -> return -1
        }
        return runCatching {
            java.io.File(path).useLines { lines ->
                val hexPort = "%04X".format(srcPort)
                lines.drop(1).firstNotNullOfOrNull { line ->
                    val cols = line.trim().split(Regex("\\s+"))
                    if (cols.size > 7 && cols[1].endsWith(":$hexPort")) {
                        cols[7].toIntOrNull()
                    } else null
                } ?: -1
            }
        }.getOrDefault(-1)
    }
}
