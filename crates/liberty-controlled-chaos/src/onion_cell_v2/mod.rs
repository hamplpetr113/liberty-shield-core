//! Onion cell v2 — fixed-size 1450-byte authenticated onion cell.
//!
//! Layout (bytes):
//! ```text
//! [0..2]   command   (u16 LE)
//! [2..10]  circuit_id (u64 LE)
//! [10..14] stream_id  (u32 LE)
//! [14..22] sequence   (u64 LE)
//! [22..54] header_mac ([u8;32]) — HMAC over header fields
//! [54..1418] payload  ([u8;1364])
//! [1418..1450] padding ([u8;32])
//! ```
//! Total: 1450 bytes.
//!
//! The `header_mac` is the HMAC-SHA256 of bytes [0..22] with the session key.

use crate::crypto::hmac_sha256;

// ---------------------------------------------------------------------------
// Command
// ---------------------------------------------------------------------------

pub const CMD_DATA: u16 = 1;
pub const CMD_RELAY: u16 = 2;
pub const CMD_DESTROY: u16 = 3;
pub const CMD_PADDING: u16 = 4;
pub const CMD_EXTEND: u16 = 5;

/// Total wire size of a v2 onion cell.
pub const CELL_SIZE: usize = 1450;
pub const PAYLOAD_SIZE: usize = 1364;
pub const HEADER_SIZE: usize = 22; // command(2)+circuit_id(8)+stream_id(4)+sequence(8)
pub const MAC_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// OnionCellV2
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OnionCellV2 {
    pub command: u16,
    pub circuit_id: u64,
    pub stream_id: u32,
    pub sequence: u64,
    pub header_mac: [u8; MAC_SIZE],
    pub payload: [u8; PAYLOAD_SIZE],
}

impl OnionCellV2 {
    /// Build a cell and compute `header_mac`.
    pub fn new(
        command: u16,
        circuit_id: u64,
        stream_id: u32,
        sequence: u64,
        payload: [u8; PAYLOAD_SIZE],
        session_key: &[u8; 32],
    ) -> Self {
        let mut cell = Self {
            command,
            circuit_id,
            stream_id,
            sequence,
            header_mac: [0u8; MAC_SIZE],
            payload,
        };
        cell.header_mac = cell.compute_mac(session_key);
        cell
    }

    fn header_bytes(&self) -> [u8; HEADER_SIZE] {
        let mut h = [0u8; HEADER_SIZE];
        h[0..2].copy_from_slice(&self.command.to_le_bytes());
        h[2..10].copy_from_slice(&self.circuit_id.to_le_bytes());
        h[10..14].copy_from_slice(&self.stream_id.to_le_bytes());
        h[14..22].copy_from_slice(&self.sequence.to_le_bytes());
        h
    }

    pub fn compute_mac(&self, session_key: &[u8; 32]) -> [u8; MAC_SIZE] {
        hmac_sha256(session_key, &self.header_bytes())
    }

    pub fn verify_mac(&self, session_key: &[u8; 32]) -> bool {
        self.compute_mac(session_key) == self.header_mac
    }

    /// Serialise to exactly `CELL_SIZE` bytes.
    pub fn to_bytes(&self) -> [u8; CELL_SIZE] {
        let mut buf = [0u8; CELL_SIZE];
        buf[0..2].copy_from_slice(&self.command.to_le_bytes());
        buf[2..10].copy_from_slice(&self.circuit_id.to_le_bytes());
        buf[10..14].copy_from_slice(&self.stream_id.to_le_bytes());
        buf[14..22].copy_from_slice(&self.sequence.to_le_bytes());
        buf[22..54].copy_from_slice(&self.header_mac);
        buf[54..1418].copy_from_slice(&self.payload);
        // bytes [1418..1450] remain zero (padding)
        buf
    }

    /// Deserialise from exactly `CELL_SIZE` bytes.
    pub fn from_bytes(buf: &[u8; CELL_SIZE]) -> Self {
        let command = u16::from_le_bytes(buf[0..2].try_into().unwrap());
        let circuit_id = u64::from_le_bytes(buf[2..10].try_into().unwrap());
        let stream_id = u32::from_le_bytes(buf[10..14].try_into().unwrap());
        let sequence = u64::from_le_bytes(buf[14..22].try_into().unwrap());
        let mut header_mac = [0u8; MAC_SIZE];
        header_mac.copy_from_slice(&buf[22..54]);
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&buf[54..1418]);
        Self {
            command,
            circuit_id,
            stream_id,
            sequence,
            header_mac,
            payload,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> [u8; 32] {
        [0xBBu8; 32]
    }

    fn empty_payload() -> [u8; PAYLOAD_SIZE] {
        [0u8; PAYLOAD_SIZE]
    }

    // OCV2_1: cell serialises to CELL_SIZE bytes.
    #[test]
    fn ocv2_1_cell_size() {
        let cell = OnionCellV2::new(CMD_DATA, 1, 0, 0, empty_payload(), &key());
        assert_eq!(cell.to_bytes().len(), CELL_SIZE);
    }

    // OCV2_2: round-trip serialisation preserves all fields.
    #[test]
    fn ocv2_2_roundtrip() {
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload[0] = 42;
        let cell = OnionCellV2::new(CMD_RELAY, 99, 7, 5, payload, &key());
        let bytes = cell.to_bytes();
        let cell2 = OnionCellV2::from_bytes(&bytes);
        assert_eq!(cell2.command, CMD_RELAY);
        assert_eq!(cell2.circuit_id, 99);
        assert_eq!(cell2.stream_id, 7);
        assert_eq!(cell2.sequence, 5);
        assert_eq!(cell2.payload[0], 42);
    }

    // OCV2_3: verify_mac returns true with correct key.
    #[test]
    fn ocv2_3_verify_mac_correct() {
        let cell = OnionCellV2::new(CMD_DATA, 1, 0, 0, empty_payload(), &key());
        assert!(cell.verify_mac(&key()));
    }

    // OCV2_4: verify_mac returns false with wrong key.
    #[test]
    fn ocv2_4_verify_mac_wrong_key() {
        let cell = OnionCellV2::new(CMD_DATA, 1, 0, 0, empty_payload(), &key());
        let wrong_key = [0xCCu8; 32];
        assert!(!cell.verify_mac(&wrong_key));
    }

    // OCV2_5: MAC changes when circuit_id changes.
    #[test]
    fn ocv2_5_mac_circuit_sensitive() {
        let c1 = OnionCellV2::new(CMD_DATA, 1, 0, 0, empty_payload(), &key());
        let c2 = OnionCellV2::new(CMD_DATA, 2, 0, 0, empty_payload(), &key());
        assert_ne!(c1.header_mac, c2.header_mac);
    }

    // OCV2_6: MAC changes when sequence changes.
    #[test]
    fn ocv2_6_mac_sequence_sensitive() {
        let c1 = OnionCellV2::new(CMD_DATA, 1, 0, 1, empty_payload(), &key());
        let c2 = OnionCellV2::new(CMD_DATA, 1, 0, 2, empty_payload(), &key());
        assert_ne!(c1.header_mac, c2.header_mac);
    }

    // OCV2_7: CMD_PADDING is a valid command.
    #[test]
    fn ocv2_7_padding_command() {
        let cell = OnionCellV2::new(CMD_PADDING, 0, 0, 0, empty_payload(), &key());
        assert_eq!(cell.command, CMD_PADDING);
    }

    // OCV2_8: payload survives round-trip unchanged.
    #[test]
    fn ocv2_8_payload_preserved() {
        let mut payload = [0xAAu8; PAYLOAD_SIZE];
        payload[1363] = 0xFF;
        let cell = OnionCellV2::new(CMD_DATA, 1, 0, 0, payload, &key());
        let cell2 = OnionCellV2::from_bytes(&cell.to_bytes());
        assert_eq!(cell2.payload, payload);
    }

    // OCV2_9: MAC of tampered bytes fails verification.
    #[test]
    fn ocv2_9_tampered_mac_fails() {
        let cell = OnionCellV2::new(CMD_DATA, 1, 0, 0, empty_payload(), &key());
        let mut bytes = cell.to_bytes();
        bytes[2] ^= 0xFF; // flip circuit_id byte
        let cell2 = OnionCellV2::from_bytes(&bytes);
        assert!(!cell2.verify_mac(&key()));
    }

    // OCV2_10: CELL_SIZE constant matches actual size.
    #[test]
    fn ocv2_10_cell_size_constant() {
        assert_eq!(CELL_SIZE, 1450);
        assert_eq!(PAYLOAD_SIZE, 1364);
    }
}
