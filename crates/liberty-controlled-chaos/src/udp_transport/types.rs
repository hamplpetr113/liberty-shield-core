use std::net::SocketAddr;

use crate::cell_encoder::CELL_SIZE;
use crate::noise_link::{ENCRYPTED_CELL_SIZE, EncryptedCell};

/// Exact size of every UDP datagram on the wire.
pub const WIRE_SIZE: usize = ENCRYPTED_CELL_SIZE; // 1482

/// Opaque peer address (wraps `std::net::SocketAddr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAddress(pub SocketAddr);

impl PeerAddress {
    pub fn new(addr: SocketAddr) -> Self {
        Self(addr)
    }
    pub fn inner(&self) -> SocketAddr {
        self.0
    }
}

impl std::fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Fixed-size UDP datagram: exactly `WIRE_SIZE` (1482) bytes.
///
/// Wire layout:
///   path_id(8 LE) | nonce(8 LE) | ciphertext(1450) | auth_tag(16)
pub struct UdpPacket {
    pub bytes: [u8; WIRE_SIZE],
}

impl UdpPacket {
    /// Serialise an `EncryptedCell` into the flat wire format.
    pub fn from_encrypted_cell(cell: &EncryptedCell) -> Self {
        let mut bytes = [0u8; WIRE_SIZE];
        bytes[0..8].copy_from_slice(&cell.path_id.to_le_bytes());
        bytes[8..16].copy_from_slice(&cell.nonce.to_le_bytes());
        bytes[16..16 + CELL_SIZE].copy_from_slice(&cell.ciphertext);
        bytes[16 + CELL_SIZE..WIRE_SIZE].copy_from_slice(&cell.auth_tag);
        Self { bytes }
    }

    /// Deserialise the wire bytes back into an `EncryptedCell`.
    pub fn to_encrypted_cell(&self) -> EncryptedCell {
        let path_id = u64::from_le_bytes(self.bytes[0..8].try_into().unwrap());
        let nonce = u64::from_le_bytes(self.bytes[8..16].try_into().unwrap());
        let ciphertext: [u8; CELL_SIZE] = self.bytes[16..16 + CELL_SIZE].try_into().unwrap();
        let auth_tag: [u8; 16] = self.bytes[16 + CELL_SIZE..WIRE_SIZE].try_into().unwrap();
        EncryptedCell {
            path_id,
            nonce,
            ciphertext,
            auth_tag,
        }
    }
}

/// Errors produced by the UDP transport layer.
#[derive(Debug)]
pub enum TransportError {
    /// Socket bind or configuration failed.
    SocketBind(String),
    /// Underlying I/O error (send or receive).
    SocketIo(String),
    /// Received datagram is shorter than `WIRE_SIZE`.
    TruncatedPacket { received: usize, expected: usize },
    /// Non-blocking socket had no data ready (`EWOULDBLOCK` / `EAGAIN`).
    WouldBlock,
}
