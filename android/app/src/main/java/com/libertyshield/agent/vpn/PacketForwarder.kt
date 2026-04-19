package com.libertyshield.agent.vpn

import android.net.VpnService
import java.io.FileOutputStream

// Forwards intercepted packets to their real destination through a protect()ed socket,
// then writes responses back to the TUN output stream.
//
// NOT implemented in this sprint. Without forwarding, all intercepted traffic is dropped
// and device network connectivity breaks for affected apps.
//
// Next steps:
//   TCP: per-connection relay using VpnService.protect(Socket)
//   UDP: stateless relay using VpnService.protect(DatagramSocket)
//   Both: write response packets back to tunOut so the originating app sees replies
class PacketForwarder(
    private val vpnService: VpnService,
    private val tunOut: FileOutputStream,
) {
    fun forward(buf: ByteArray, len: Int, packet: ParsedPacket) {
        // TODO: implement per-protocol relay
    }
}
