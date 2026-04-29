//! `EncryptedRelayCell` — an authenticated, encrypted relay cell.
//!
//! Sits above `SessionKeys` (ChaCha20-Poly1305) and wraps a `RelayCellPlaintext`.
//!
//! Wire format of the sealed output:
//!   sequence(8 LE) | sealed_payload(plaintext_len + 16)
//!
//! The `sequence` field in the outer wire format matches the `sequence` inside
//! the plaintext, allowing the receiver to reconstruct the AEAD nonce without
//! a separate nonce field.

use crate::crypto::{SessionError, SessionKeys};

use super::errors::EncryptedRelayError;
use super::types::RelayCellPlaintext;

/// The outer wire representation of an encrypted relay cell.
///
/// Layout: `sequence(8)` ‖ `ciphertext_and_tag(N+16)`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedRelayCell {
    /// Outer sequence number (mirrors the inner plaintext sequence).
    pub sequence: u64,
    /// AEAD ciphertext ‖ 16-byte Poly1305 tag.
    pub ciphertext_and_tag: Vec<u8>,
}

impl EncryptedRelayCell {
    /// Seal a `RelayCellPlaintext` with `session`.
    ///
    /// AAD = circuit_id(8 LE) ‖ stream_id(8 LE): binds the cell to its logical
    /// context so a cell cannot be replayed on a different circuit or stream.
    pub fn seal(
        session: &mut SessionKeys,
        plaintext: &RelayCellPlaintext,
    ) -> Result<Self, EncryptedRelayError> {
        let encoded = plaintext.encode()?;
        let aad = build_aad(plaintext.circuit_id, plaintext.stream_id);
        let sequence = session.send_sequence();
        let sealed = session
            .encrypt_packet(&aad, &encoded)
            .map_err(|e| match e {
                SessionError::NonceExhausted => EncryptedRelayError::NonceExhausted,
                // AuthenticationFailed and ReplayDetected cannot arise from encrypt_packet,
                // but the match must be exhaustive.
                SessionError::AuthenticationFailed | SessionError::ReplayDetected => {
                    EncryptedRelayError::AuthenticationFailed
                }
            })?;
        Ok(Self {
            sequence,
            ciphertext_and_tag: sealed,
        })
    }

    /// Open an `EncryptedRelayCell` using the receiver's session.
    ///
    /// `circuit_id` and `stream_id` are passed by the caller (from the packet
    /// routing context) and used to reconstruct the AAD for verification.
    pub fn open(
        &self,
        session: &SessionKeys,
        circuit_id: u64,
        stream_id: u64,
    ) -> Result<RelayCellPlaintext, EncryptedRelayError> {
        let aad = build_aad(circuit_id, stream_id);
        let plain = session
            .decrypt_packet(&aad, self.sequence, &self.ciphertext_and_tag)
            .map_err(|_| EncryptedRelayError::AuthenticationFailed)?;
        RelayCellPlaintext::decode(&plain)
    }

    /// Serialise the encrypted cell to wire bytes.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.ciphertext_and_tag.len());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.extend_from_slice(&self.ciphertext_and_tag);
        buf
    }

    /// Deserialise from wire bytes (inverse of `to_wire`).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, EncryptedRelayError> {
        if bytes.len() < 8 + 16 {
            // 8 sequence bytes + at least 16 bytes tag
            return Err(EncryptedRelayError::BufferTooShort);
        }
        let sequence = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let ciphertext_and_tag = bytes[8..].to_vec();
        Ok(Self {
            sequence,
            ciphertext_and_tag,
        })
    }
}

/// Build the AEAD additional data: circuit_id(8 LE) ‖ stream_id(8 LE).
fn build_aad(circuit_id: u64, stream_id: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(16);
    aad.extend_from_slice(&circuit_id.to_le_bytes());
    aad.extend_from_slice(&stream_id.to_le_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::super::types::RelayCellCommand;
    use super::*;
    use crate::crypto::SessionKeys;

    fn symmetric_session() -> SessionKeys {
        SessionKeys::new([0xABu8; 32], [0xABu8; 32])
    }

    fn make_cell(circuit: u64, stream: u64, seq: u64) -> RelayCellPlaintext {
        RelayCellPlaintext::new(
            circuit,
            stream,
            RelayCellCommand::Data,
            seq,
            b"test payload".to_vec(),
        )
    }

    // ER1: seal then open recovers plaintext
    #[test]
    fn er1_roundtrip() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let cell = make_cell(1, 2, 0);
        let enc = EncryptedRelayCell::seal(&mut sender, &cell).unwrap();
        let dec = enc.open(&receiver, 1, 2).unwrap();
        assert_eq!(dec, cell);
    }

    // ER2: wrong circuit_id → authentication failure
    #[test]
    fn er2_wrong_circuit_id() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let enc = EncryptedRelayCell::seal(&mut sender, &make_cell(1, 2, 0)).unwrap();
        assert_eq!(
            enc.open(&receiver, 99, 2).unwrap_err(),
            EncryptedRelayError::AuthenticationFailed
        );
    }

    // ER3: wrong stream_id → authentication failure
    #[test]
    fn er3_wrong_stream_id() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let enc = EncryptedRelayCell::seal(&mut sender, &make_cell(1, 2, 0)).unwrap();
        assert_eq!(
            enc.open(&receiver, 1, 99).unwrap_err(),
            EncryptedRelayError::AuthenticationFailed
        );
    }

    // ER4: tampered ciphertext rejected
    #[test]
    fn er4_tampered_ciphertext() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let mut enc = EncryptedRelayCell::seal(&mut sender, &make_cell(1, 1, 0)).unwrap();
        enc.ciphertext_and_tag[0] ^= 0xFF;
        assert_eq!(
            enc.open(&receiver, 1, 1).unwrap_err(),
            EncryptedRelayError::AuthenticationFailed
        );
    }

    // ER5: sequence mismatch (wrong sequence for nonce) → authentication failure
    #[test]
    fn er5_wrong_sequence() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let enc = EncryptedRelayCell::seal(&mut sender, &make_cell(1, 1, 0)).unwrap();
        // Tamper with the outer sequence
        let tampered = EncryptedRelayCell {
            sequence: 99,
            ciphertext_and_tag: enc.ciphertext_and_tag.clone(),
        };
        assert_eq!(
            tampered.open(&receiver, 1, 1).unwrap_err(),
            EncryptedRelayError::AuthenticationFailed
        );
    }

    // ER6: wire roundtrip preserves all fields
    #[test]
    fn er6_wire_roundtrip() {
        let mut session = symmetric_session();
        let original = EncryptedRelayCell::seal(&mut session, &make_cell(3, 4, 0)).unwrap();
        let wire = original.to_wire();
        let recovered = EncryptedRelayCell::from_wire(&wire).unwrap();
        assert_eq!(recovered, original);
    }

    // ER7: from_wire rejects short buffers
    #[test]
    fn er7_short_wire_rejected() {
        let err = EncryptedRelayCell::from_wire(&[0u8; 10]).unwrap_err();
        assert_eq!(err, EncryptedRelayError::BufferTooShort);
    }

    // ER8: multiple sequential cells succeed with advancing sequence
    #[test]
    fn er8_sequential_cells() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        for seq in 0u64..5 {
            let cell = make_cell(10, 20, seq);
            let enc = EncryptedRelayCell::seal(&mut sender, &cell).unwrap();
            assert_eq!(enc.sequence, seq);
            let dec = enc.open(&receiver, 10, 20).unwrap();
            assert_eq!(dec.sequence, seq);
        }
    }

    // ER9: Drop command round-trips correctly
    #[test]
    fn er9_drop_command() {
        let mut sender = symmetric_session();
        let receiver = symmetric_session();
        let cell = RelayCellPlaintext::new(1, 0, RelayCellCommand::Drop, 0, vec![]);
        let enc = EncryptedRelayCell::seal(&mut sender, &cell).unwrap();
        let dec = enc.open(&receiver, 1, 0).unwrap();
        assert_eq!(dec.command, RelayCellCommand::Drop);
    }

    // ER10: deterministic — same keys, same sequence, same plaintext → same wire bytes
    #[test]
    fn er10_deterministic() {
        let mut s1 = symmetric_session();
        let mut s2 = symmetric_session();
        let cell = make_cell(1, 2, 0);
        let enc1 = EncryptedRelayCell::seal(&mut s1, &cell).unwrap();
        let enc2 = EncryptedRelayCell::seal(&mut s2, &cell).unwrap();
        assert_eq!(enc1.to_wire(), enc2.to_wire());
    }
}
