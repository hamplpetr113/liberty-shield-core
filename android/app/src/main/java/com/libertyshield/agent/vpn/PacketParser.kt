package com.libertyshield.agent.vpn

data class ParsedPacket(
    val isIpv6: Boolean = false,
    val protocol: Int,
    val srcIp: String,
    val dstIp: String,
    val srcPort: Int,
    val dstPort: Int,
    val tcpFlags: Int = 0,
    val totalLength: Int,
)

class PacketParser {

    fun parse(buf: ByteArray, len: Int): ParsedPacket? {
        if (len < 20) return null
        val version = (buf[0].toInt() and 0xFF) shr 4
        if (version != 4) {
            // IPv6 packet — surface for detection, no deep parsing in this sprint
            return ParsedPacket(
                isIpv6 = true, protocol = 0,
                srcIp = "", dstIp = "",
                srcPort = 0, dstPort = 0, totalLength = len,
            )
        }

        val ihl      = (buf[0].toInt() and 0x0F) * 4
        val totalLen = minOf(((buf[2].toInt() and 0xFF) shl 8) or (buf[3].toInt() and 0xFF), len)
        val protocol = buf[9].toInt() and 0xFF
        val srcIp    = ipString(buf, 12)
        val dstIp    = ipString(buf, 16)

        var srcPort  = 0
        var dstPort  = 0
        var tcpFlags = 0
        if ((protocol == PROTO_TCP || protocol == PROTO_UDP) && len >= ihl + 4) {
            srcPort = portAt(buf, ihl)
            dstPort = portAt(buf, ihl + 2)
            if (protocol == PROTO_TCP && len >= ihl + 14) {
                tcpFlags = buf[ihl + 13].toInt() and 0xFF
            }
        }

        return ParsedPacket(
            protocol    = protocol,
            srcIp       = srcIp,
            dstIp       = dstIp,
            srcPort     = srcPort,
            dstPort     = dstPort,
            tcpFlags    = tcpFlags,
            totalLength = totalLen,
        )
    }

    private fun ipString(buf: ByteArray, offset: Int) =
        "%d.%d.%d.%d".format(
            buf[offset].toInt()     and 0xFF,
            buf[offset + 1].toInt() and 0xFF,
            buf[offset + 2].toInt() and 0xFF,
            buf[offset + 3].toInt() and 0xFF,
        )

    private fun portAt(buf: ByteArray, offset: Int) =
        ((buf[offset].toInt() and 0xFF) shl 8) or (buf[offset + 1].toInt() and 0xFF)

    companion object {
        const val PROTO_ICMP = 1
        const val PROTO_TCP  = 6
        const val PROTO_UDP  = 17
    }
}
