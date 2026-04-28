use std::net::{SocketAddr, UdpSocket};

use crate::noise_link::EncryptedCell;

use super::types::{PeerAddress, TransportError, UdpPacket};

/// Sends `EncryptedCell` datagrams over UDP.
///
/// Binds a local socket on construction; each call to `send` writes exactly
/// `WIRE_SIZE` (1482) bytes to the specified peer.
pub struct UdpSender {
    socket: UdpSocket,
}

impl UdpSender {
    /// Bind to `bind_addr` (e.g. `"0.0.0.0:0"` for an OS-assigned port).
    pub fn bind(bind_addr: &str) -> Result<Self, TransportError> {
        let socket =
            UdpSocket::bind(bind_addr).map_err(|e| TransportError::SocketBind(e.to_string()))?;
        Ok(Self { socket })
    }

    /// The local address this sender is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket
            .local_addr()
            .map_err(|e| TransportError::SocketIo(e.to_string()))
    }

    /// Serialise `cell` and send it as a single 1482-byte UDP datagram to `peer`.
    pub fn send(&self, cell: &EncryptedCell, peer: &PeerAddress) -> Result<(), TransportError> {
        let packet = UdpPacket::from_encrypted_cell(cell);
        self.socket
            .send_to(&packet.bytes, peer.inner())
            .map_err(|e| TransportError::SocketIo(e.to_string()))?;
        Ok(())
    }
}
