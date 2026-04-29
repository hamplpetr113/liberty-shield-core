use crate::onion_crypto::{decrypt_layer, derive_layer_key, encrypt_layer};

/// Errors produced by the onion packet layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionPacketError {
    /// Attempt to unwrap a packet that has no remaining layers.
    NoLayersRemaining,
    /// The hop list provided to `wrap_layers` was empty.
    EmptyHopList,
}

/// A packet travelling through the onion network.
///
/// Each intermediate node calls `unwrap_layer` to peel its encryption layer
/// and obtain the inner packet addressed to the next hop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnionPacket {
    pub circuit_id: u64,
    /// Index of the hop that should process this packet next.
    pub hop_index: usize,
    /// Payload — may still have layers above this hop's layer.
    pub encrypted_payload: Vec<u8>,
}

impl OnionPacket {
    /// Create a new onion packet at a given hop.
    pub fn new(circuit_id: u64, hop_index: usize, encrypted_payload: Vec<u8>) -> Self {
        Self {
            circuit_id,
            hop_index,
            encrypted_payload,
        }
    }

    /// Wrap plaintext with one encryption layer for `node_id` at `hop_index`.
    /// Returns a new packet whose payload is the encrypted form.
    pub fn wrap_layer(self, node_id: u64) -> Self {
        let key = derive_layer_key(node_id, self.hop_index);
        let encrypted = encrypt_layer(&self.encrypted_payload, key);
        Self {
            circuit_id: self.circuit_id,
            hop_index: self.hop_index,
            encrypted_payload: encrypted,
        }
    }

    /// Peel one encryption layer using the key for `node_id` at the current
    /// `hop_index`. Returns the inner packet with `hop_index` incremented.
    ///
    /// Returns `Err(NoLayersRemaining)` if the payload is empty.
    pub fn unwrap_layer(self, node_id: u64) -> Result<Self, OnionPacketError> {
        if self.encrypted_payload.is_empty() {
            return Err(OnionPacketError::NoLayersRemaining);
        }
        let key = derive_layer_key(node_id, self.hop_index);
        let decrypted = decrypt_layer(&self.encrypted_payload, key);
        Ok(Self {
            circuit_id: self.circuit_id,
            hop_index: self.hop_index + 1,
            encrypted_payload: decrypted,
        })
    }
}

/// Build a fully wrapped onion packet from plaintext.
///
/// `hops` is an ordered list of node IDs from guard to exit.
/// The outermost layer belongs to `hops[0]`; wrapping is applied inside-out
/// so the guard node's layer is outermost.
pub fn wrap_layers(
    circuit_id: u64,
    plaintext: &[u8],
    hops: &[u64],
) -> Result<OnionPacket, OnionPacketError> {
    if hops.is_empty() {
        return Err(OnionPacketError::EmptyHopList);
    }
    // Start at the innermost layer (last hop, highest hop_index).
    let last = hops.len() - 1;
    let mut pkt = OnionPacket::new(circuit_id, last, plaintext.to_vec());

    // Wrap from the innermost hop outward so that hop 0 is the outermost layer.
    for (i, &node_id) in hops.iter().enumerate().rev() {
        pkt.hop_index = i;
        pkt = pkt.wrap_layer(node_id);
    }
    pkt.hop_index = 0;
    Ok(pkt)
}

/// Fully unwrap an onion packet through all hops, returning the plaintext.
///
/// `hops` must match the list used during `wrap_layers`.
pub fn unwrap_layers(mut pkt: OnionPacket, hops: &[u64]) -> Result<Vec<u8>, OnionPacketError> {
    for &node_id in hops {
        pkt = pkt.unwrap_layer(node_id)?;
    }
    Ok(pkt.encrypted_payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hops3() -> Vec<u64> {
        vec![10, 20, 30]
    }

    // OP1: wrap + unwrap roundtrip restores plaintext
    #[test]
    fn op1_wrap_unwrap_symmetry() {
        let plaintext = b"liberty shield test payload".to_vec();
        let pkt = wrap_layers(1, &plaintext, &hops3()).unwrap();
        let recovered = unwrap_layers(pkt, &hops3()).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // OP2: deterministic — same inputs produce identical wrapped packets
    #[test]
    fn op2_deterministic_onion_layering() {
        let plaintext = b"deterministic".to_vec();
        let pkt1 = wrap_layers(1, &plaintext, &hops3()).unwrap();
        let pkt2 = wrap_layers(1, &plaintext, &hops3()).unwrap();
        assert_eq!(pkt1, pkt2);
    }

    // OP3: packet size does not shrink after wrapping (XOR is size-preserving)
    #[test]
    fn op3_packet_size_invariant() {
        let plaintext = vec![0u8; 64];
        let pkt = wrap_layers(1, &plaintext, &hops3()).unwrap();
        assert_eq!(pkt.encrypted_payload.len(), plaintext.len());
    }

    // OP4: wrap changes bytes (outer layer is encrypted)
    #[test]
    fn op4_wrap_changes_bytes() {
        let plaintext = b"original".to_vec();
        let pkt = wrap_layers(1, &plaintext, &hops3()).unwrap();
        assert_ne!(pkt.encrypted_payload, plaintext);
    }

    // OP5: hop_index starts at 0 after wrapping
    #[test]
    fn op5_hop_index_starts_at_zero() {
        let pkt = wrap_layers(42, b"test", &hops3()).unwrap();
        assert_eq!(pkt.hop_index, 0);
    }

    // OP6: each unwrap_layer increments hop_index
    #[test]
    fn op6_unwrap_increments_hop_index() {
        let plaintext = b"hop tracking".to_vec();
        let pkt = wrap_layers(1, &plaintext, &hops3()).unwrap();
        let pkt1 = pkt.unwrap_layer(hops3()[0]).unwrap();
        assert_eq!(pkt1.hop_index, 1);
        let pkt2 = pkt1.unwrap_layer(hops3()[1]).unwrap();
        assert_eq!(pkt2.hop_index, 2);
    }

    // OP7: empty hop list returns error
    #[test]
    fn op7_empty_hop_list_error() {
        assert_eq!(
            wrap_layers(1, b"x", &[]).unwrap_err(),
            OnionPacketError::EmptyHopList
        );
    }

    // OP8: unwrap on empty payload returns error
    #[test]
    fn op8_unwrap_empty_payload_error() {
        let pkt = OnionPacket::new(1, 0, vec![]);
        assert_eq!(
            pkt.unwrap_layer(10).unwrap_err(),
            OnionPacketError::NoLayersRemaining
        );
    }

    // OP9: circuit_id is preserved across all operations
    #[test]
    fn op9_circuit_id_preserved() {
        let pkt = wrap_layers(99, b"cid", &hops3()).unwrap();
        assert_eq!(pkt.circuit_id, 99);
        let recovered_pkt = pkt.unwrap_layer(hops3()[0]).unwrap();
        assert_eq!(recovered_pkt.circuit_id, 99);
    }

    // OP10: single-hop wrap + unwrap
    #[test]
    fn op10_single_hop_roundtrip() {
        let plaintext = b"one hop".to_vec();
        let pkt = wrap_layers(1, &plaintext, &[55]).unwrap();
        let recovered = unwrap_layers(pkt, &[55]).unwrap();
        assert_eq!(recovered, plaintext);
    }
}
