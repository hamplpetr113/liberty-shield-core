//! `NodeDescriptor` — a node's public identity and network address.
//!
//! Different from `node_discovery::NodeDescriptor` which uses a numeric ID and
//! includes latency/reliability scoring.  This type uses the raw SHA-256 node_id
//! and a standard `SocketAddr`.

use std::net::SocketAddr;

use crate::crypto::sha256;

/// Public descriptor for one mesh node: cryptographic ID + network address.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeDescriptor {
    /// SHA-256 of `public_key` — the canonical 32-byte node identifier.
    pub node_id: [u8; 32],
    /// Long-term X25519 public key.
    pub public_key: [u8; 32],
    /// Network address used to reach this node.
    pub address: SocketAddr,
}

impl NodeDescriptor {
    /// Construct a descriptor from a public key and address.
    ///
    /// `node_id` is computed as `SHA-256(public_key)`.
    pub fn new(public_key: [u8; 32], address: SocketAddr) -> Self {
        let node_id = sha256(&public_key);
        Self {
            node_id,
            public_key,
            address,
        }
    }

    /// Return `true` if `node_id == SHA-256(public_key)`.
    pub fn is_valid(&self) -> bool {
        sha256(&self.public_key) == self.node_id
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;
    use crate::crypto::sha256;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    // MN1: NodeDescriptor::new sets node_id = SHA256(public_key).
    #[test]
    fn mn1_descriptor_node_id_derivation() {
        let pk = [0xABu8; 32];
        let d = NodeDescriptor::new(pk, addr(9000));
        assert_eq!(d.node_id, sha256(&pk));
        assert!(d.is_valid());
    }

    // MN2: is_valid rejects a descriptor with a tampered node_id.
    #[test]
    fn mn2_descriptor_invalid_node_id() {
        let pk = [0x42u8; 32];
        let mut d = NodeDescriptor::new(pk, addr(9001));
        d.node_id[0] ^= 0xFF;
        assert!(!d.is_valid());
    }

    // MN3: different public keys produce different node_ids.
    #[test]
    fn mn3_distinct_keys_distinct_ids() {
        let d1 = NodeDescriptor::new([0x01u8; 32], addr(9002));
        let d2 = NodeDescriptor::new([0x02u8; 32], addr(9002));
        assert_ne!(d1.node_id, d2.node_id);
    }
}
