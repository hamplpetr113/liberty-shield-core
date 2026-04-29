// NON-PRODUCTION: deterministic session seeding from numeric seeds.
// In production, keys would be derived via a real Noise XX handshake.
// Do NOT use these sessions outside of the loopback testnet.

use std::collections::HashMap;

use liberty_controlled_chaos::noise_link::{NoiseLinkEncoder, NoiseSession};

use crate::encrypted_udp_types::{EncryptedUdpError, EncryptedUdpNodeId};

/// Derive a 32-byte key from an 8-byte seed by repeating the LE bytes four times.
/// NON-PRODUCTION: not a real KDF.
fn seed_to_key(seed: u64) -> [u8; 32] {
    let bytes = seed.to_le_bytes();
    let mut key = [0u8; 32];
    for chunk in key.chunks_mut(8) {
        chunk.copy_from_slice(&bytes);
    }
    key
}

/// Per-peer session state for one direction of encrypted communication.
///
/// `send_encoder` holds the outbound `NoiseLinkEncoder` (nonce increments on each encode).
/// `recv_encoder` holds the inbound `NoiseLinkEncoder` (stateless decode; only recv_key matters).
///
/// NON-PRODUCTION: sessions are seeded deterministically, not negotiated via handshake.
#[derive(Debug)]
pub struct EncryptedPeerSession {
    pub peer_id: EncryptedUdpNodeId,
    pub send_encoder: NoiseLinkEncoder,
    pub recv_encoder: NoiseLinkEncoder,
    pub last_sent_sequence: u64,
    pub last_received_sequence: u64,
}

impl EncryptedPeerSession {
    /// Create a new peer session from deterministic seeds.
    ///
    /// `send_seed` derives the key used to encrypt outbound data to this peer.
    /// `recv_seed` derives the key used to authenticate/decrypt inbound data from this peer.
    ///
    /// For two nodes A and B to communicate correctly:
    ///   A.add_peer_session(B, send_seed=S, recv_seed=R)
    ///   B.add_peer_session(A, send_seed=R, recv_seed=S)
    /// (matching keys so AEAD tags verify)
    ///
    /// NON-PRODUCTION: real sessions use Noise XX ephemeral key exchange.
    pub fn new(peer_id: EncryptedUdpNodeId, send_seed: u64, recv_seed: u64) -> Self {
        let send_key = seed_to_key(send_seed);
        let recv_key = seed_to_key(recv_seed);
        // send_encoder: send_key for encryption, dummy recv_key (only encode is called)
        let send_session = NoiseSession::new(send_key, [0u8; 32]);
        // recv_encoder: dummy send_key, recv_key for authentication + decryption
        let recv_session = NoiseSession::new([0u8; 32], recv_key);
        Self {
            peer_id,
            send_encoder: NoiseLinkEncoder::new(send_session),
            recv_encoder: NoiseLinkEncoder::new(recv_session),
            last_sent_sequence: 0,
            last_received_sequence: 0,
        }
    }
}

/// Table of per-peer sessions keyed by `EncryptedUdpNodeId`.
#[derive(Debug)]
pub struct EncryptedPeerSessionTable {
    sessions: HashMap<u64, EncryptedPeerSession>,
}

impl EncryptedPeerSessionTable {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    /// Add a session for `peer_id`. Returns `Err(InvalidNode)` if already present.
    pub fn add_peer(
        &mut self,
        peer_id: EncryptedUdpNodeId,
        send_seed: u64,
        recv_seed: u64,
    ) -> Result<(), EncryptedUdpError> {
        if self.sessions.contains_key(&peer_id.0) {
            return Err(EncryptedUdpError::InvalidNode);
        }
        self.sessions.insert(
            peer_id.0,
            EncryptedPeerSession::new(peer_id, send_seed, recv_seed),
        );
        Ok(())
    }

    pub fn get_peer(&self, peer_id: EncryptedUdpNodeId) -> Option<&EncryptedPeerSession> {
        self.sessions.get(&peer_id.0)
    }

    pub fn get_peer_mut(
        &mut self,
        peer_id: EncryptedUdpNodeId,
    ) -> Option<&mut EncryptedPeerSession> {
        self.sessions.get_mut(&peer_id.0)
    }

    pub fn remove_peer(&mut self, peer_id: EncryptedUdpNodeId) {
        self.sessions.remove(&peer_id.0);
    }

    pub fn has_peer(&self, peer_id: EncryptedUdpNodeId) -> bool {
        self.sessions.contains_key(&peer_id.0)
    }

    pub fn peer_count(&self) -> usize {
        self.sessions.len()
    }
}

impl Default for EncryptedPeerSessionTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(id: u64) -> EncryptedUdpNodeId {
        EncryptedUdpNodeId(id)
    }

    // ST1: add peer succeeds and peer_count reflects it
    #[test]
    fn st1_add_peer() {
        let mut table = EncryptedPeerSessionTable::new();
        table.add_peer(peer(1), 100, 200).unwrap();
        assert_eq!(table.peer_count(), 1);
        assert!(table.has_peer(peer(1)));
    }

    // ST2: duplicate peer rejected
    #[test]
    fn st2_duplicate_peer_rejected() {
        let mut table = EncryptedPeerSessionTable::new();
        table.add_peer(peer(2), 100, 200).unwrap();
        assert_eq!(
            table.add_peer(peer(2), 300, 400).unwrap_err(),
            EncryptedUdpError::InvalidNode
        );
        assert_eq!(table.peer_count(), 1);
    }

    // ST3: unknown peer returns None
    #[test]
    fn st3_unknown_peer_rejected() {
        let table = EncryptedPeerSessionTable::new();
        assert!(table.get_peer(peer(99)).is_none());
    }

    // ST4: deterministic sessions — same seeds produce same first-nonce ciphertext
    #[test]
    fn st4_deterministic_sessions() {
        use crate::encrypted_cell_fixture::make_cell;
        let mut table_a = EncryptedPeerSessionTable::new();
        let mut table_b = EncryptedPeerSessionTable::new();
        table_a.add_peer(peer(1), 0xAAAA, 0xBBBB).unwrap();
        table_b.add_peer(peer(1), 0xAAAA, 0xBBBB).unwrap();
        // Same seed → same send_key → same first encrypt result
        let payload = b"test";
        let cell_a = make_cell(payload, 1).unwrap();
        let cell_b = make_cell(payload, 1).unwrap();
        let enc_a = table_a
            .get_peer_mut(peer(1))
            .unwrap()
            .send_encoder
            .encode(cell_a);
        let enc_b = table_b
            .get_peer_mut(peer(1))
            .unwrap()
            .send_encoder
            .encode(cell_b);
        assert_eq!(enc_a.ciphertext, enc_b.ciphertext);
        assert_eq!(enc_a.auth_tag, enc_b.auth_tag);
    }

    // ST5: remove peer removes it from the table
    #[test]
    fn st5_remove_peer() {
        let mut table = EncryptedPeerSessionTable::new();
        table.add_peer(peer(5), 10, 20).unwrap();
        assert!(table.has_peer(peer(5)));
        table.remove_peer(peer(5));
        assert!(!table.has_peer(peer(5)));
        assert_eq!(table.peer_count(), 0);
    }
}
