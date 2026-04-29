//! Wire-level types for the security state journal.

/// Entry type: session-layer replay window update (packet accepted after AEAD).
pub const ENTRY_SESSION_REPLAY_UPDATE: u8 = 1;
/// Entry type: rekey nonce seen by the responder.
pub const ENTRY_REKEY_NONCE_SEEN: u8 = 2;
/// Entry type: transport-layer packet seen (before AEAD decrypt).
pub const ENTRY_TRANSPORT_PACKET_SEEN: u8 = 3;

/// Fixed-size binary log entry (25 bytes on disk).
///
/// Layout (little-endian):
/// ```text
///  0        1        9        17       25
///  ┌────────┬────────────────┬────────────────┬────────────────┐
///  │  type  │   circuit_id   │    sequence    │   timestamp    │
///  │ 1 byte │  8 bytes LE    │  8 bytes LE    │  8 bytes LE    │
///  └────────┴────────────────┴────────────────┴────────────────┘
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityStateEntry {
    /// One of the `ENTRY_*` constants.
    pub entry_type: u8,
    /// Circuit identifier; `0` for global entries (e.g., rekey nonces).
    pub circuit_id: u64,
    /// Sequence number, packet ID, or nonce value (context-dependent).
    pub sequence: u64,
    /// Unix timestamp (seconds) when the entry was written.
    pub timestamp: u64,
}

impl SecurityStateEntry {
    /// Serialised size of one entry in bytes.
    pub const BYTE_SIZE: usize = 25;

    /// Serialise to a fixed-size byte array.
    pub fn to_bytes(self) -> [u8; Self::BYTE_SIZE] {
        let mut b = [0u8; Self::BYTE_SIZE];
        b[0] = self.entry_type;
        b[1..9].copy_from_slice(&self.circuit_id.to_le_bytes());
        b[9..17].copy_from_slice(&self.sequence.to_le_bytes());
        b[17..25].copy_from_slice(&self.timestamp.to_le_bytes());
        b
    }

    /// Deserialise from a fixed-size byte array.
    pub fn from_bytes(b: &[u8; Self::BYTE_SIZE]) -> Self {
        Self {
            entry_type: b[0],
            circuit_id: u64::from_le_bytes(b[1..9].try_into().unwrap()),
            sequence: u64::from_le_bytes(b[9..17].try_into().unwrap()),
            timestamp: u64::from_le_bytes(b[17..25].try_into().unwrap()),
        }
    }
}
