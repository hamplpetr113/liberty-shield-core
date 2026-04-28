use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::noise_link::EncryptedCell;

use super::types::{PeerAddress, TransportError, UdpPacket, WIRE_SIZE};

/// Receives `EncryptedCell` datagrams from a UDP socket.
///
/// Binds a local socket on construction. Datagrams that are not exactly
/// `WIRE_SIZE` (1482) bytes are rejected with `TransportError::TruncatedPacket`.
pub struct UdpReceiver {
    socket: UdpSocket,
}

impl UdpReceiver {
    /// Bind to `bind_addr` (e.g. `"0.0.0.0:4444"`).
    pub fn bind(bind_addr: &str) -> Result<Self, TransportError> {
        let socket =
            UdpSocket::bind(bind_addr).map_err(|e| TransportError::SocketBind(e.to_string()))?;
        Ok(Self { socket })
    }

    /// The local address this receiver is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.socket
            .local_addr()
            .map_err(|e| TransportError::SocketIo(e.to_string()))
    }

    /// Configure the socket as non-blocking.  In non-blocking mode `receive`
    /// returns `TransportError::WouldBlock` when no datagram is available.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), TransportError> {
        self.socket
            .set_nonblocking(nonblocking)
            .map_err(|e| TransportError::SocketIo(e.to_string()))
    }

    /// Set a read timeout (pass `None` for no timeout / blocking mode).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), TransportError> {
        self.socket
            .set_read_timeout(timeout)
            .map_err(|e| TransportError::SocketIo(e.to_string()))
    }

    /// Block until one datagram arrives, then deserialise it.
    ///
    /// Returns `(EncryptedCell, PeerAddress)` on success.
    /// Returns `TransportError::TruncatedPacket` if the datagram is not exactly
    /// `WIRE_SIZE` bytes.  Returns `TransportError::WouldBlock` when the socket
    /// is non-blocking and no datagram is ready.
    pub fn receive(&self) -> Result<(EncryptedCell, PeerAddress), TransportError> {
        let mut buf = [0u8; WIRE_SIZE];
        let (n, peer) = self.socket.recv_from(&mut buf).map_err(|e| {
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut
            {
                TransportError::WouldBlock
            } else {
                TransportError::SocketIo(e.to_string())
            }
        })?;

        if n != WIRE_SIZE {
            return Err(TransportError::TruncatedPacket {
                received: n,
                expected: WIRE_SIZE,
            });
        }

        let packet = UdpPacket { bytes: buf };
        Ok((packet.to_encrypted_cell(), PeerAddress::new(peer)))
    }
}
