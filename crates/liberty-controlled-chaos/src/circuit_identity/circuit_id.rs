//! `CircuitIdentity` — cryptographic binding between two nodes and a circuit.
//!
//! The circuit hash is `SHA-256(local_node_id || peer_node_id || nonce_le64)`.
//! The `circuit_id` is the first 8 bytes of the hash (little-endian u64).
//!
//! NON-PRODUCTION: the nonce should come from a CSPRNG in production.

use crate::crypto::sha256;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error returned when a circuit identity conflicts with an existing one.
#[derive(Debug, PartialEq)]
pub enum CollisionError {
    /// A circuit with this `circuit_id` is already registered.
    CircuitIdCollision(u64),
    /// A circuit with this `circuit_hash` is already registered
    /// (hash collision despite a different circuit_id — should never happen
    /// with good nonces but must be caught).
    CircuitHashCollision([u8; 32]),
}

impl std::fmt::Display for CollisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CollisionError::CircuitIdCollision(id) => {
                write!(f, "circuit_id {id} already registered")
            }
            CollisionError::CircuitHashCollision(_) => {
                write!(f, "circuit_hash already registered (nonce collision)")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitIdentity
// ---------------------------------------------------------------------------

/// Cryptographic identity for one circuit leg between two nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct CircuitIdentity {
    /// Derived u64 circuit identifier (first 8 bytes of `circuit_hash`, LE).
    pub circuit_id: u64,
    /// SHA-256 of `(local_node_id || peer_node_id || nonce_le64)`.
    pub circuit_hash: [u8; 32],
}

impl CircuitIdentity {
    /// Derive a `CircuitIdentity` from the two node IDs and a u64 nonce.
    ///
    /// `circuit_hash = SHA-256(local_node_id || peer_node_id || nonce.to_le_bytes())`
    /// `circuit_id   = u64::from_le_bytes(circuit_hash[0..8])`
    pub fn generate(local_node_id: &[u8; 32], peer_node_id: &[u8; 32], nonce: u64) -> Self {
        let mut input = [0u8; 72]; // 32 + 32 + 8
        input[0..32].copy_from_slice(local_node_id);
        input[32..64].copy_from_slice(peer_node_id);
        input[64..72].copy_from_slice(&nonce.to_le_bytes());
        let circuit_hash = sha256(&input);
        let circuit_id = u64::from_le_bytes(circuit_hash[0..8].try_into().unwrap());
        Self {
            circuit_id,
            circuit_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn node_a() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 0xAA;
        b
    }

    fn node_b() -> [u8; 32] {
        let mut b = [0u8; 32];
        b[0] = 0xBB;
        b
    }

    // CI1: circuit_hash = SHA256(local || peer || nonce).
    #[test]
    fn ci1_hash_derivation() {
        let mut input = [0u8; 72];
        input[0..32].copy_from_slice(&node_a());
        input[32..64].copy_from_slice(&node_b());
        input[64..72].copy_from_slice(&42u64.to_le_bytes());
        let expected_hash = sha256(&input);

        let id = CircuitIdentity::generate(&node_a(), &node_b(), 42);
        assert_eq!(id.circuit_hash, expected_hash);
    }

    // CI2: circuit_id = u64::from_le_bytes(circuit_hash[0..8]).
    #[test]
    fn ci2_circuit_id_from_hash() {
        let id = CircuitIdentity::generate(&node_a(), &node_b(), 1);
        let expected_id = u64::from_le_bytes(id.circuit_hash[0..8].try_into().unwrap());
        assert_eq!(id.circuit_id, expected_id);
    }

    // CI3: generate is deterministic.
    #[test]
    fn ci3_deterministic() {
        let a = CircuitIdentity::generate(&node_a(), &node_b(), 99);
        let b = CircuitIdentity::generate(&node_a(), &node_b(), 99);
        assert_eq!(a, b);
    }

    // CI4: different nonces produce different identities.
    #[test]
    fn ci4_nonce_changes_hash() {
        let a = CircuitIdentity::generate(&node_a(), &node_b(), 1);
        let b = CircuitIdentity::generate(&node_a(), &node_b(), 2);
        assert_ne!(a.circuit_hash, b.circuit_hash);
    }

    // CI5: node order matters — (A,B,n) ≠ (B,A,n).
    #[test]
    fn ci5_node_order_asymmetry() {
        let ab = CircuitIdentity::generate(&node_a(), &node_b(), 7);
        let ba = CircuitIdentity::generate(&node_b(), &node_a(), 7);
        assert_ne!(ab.circuit_hash, ba.circuit_hash);
    }

    // CI6: different node pairs produce different hashes.
    #[test]
    fn ci6_different_nodes_differ() {
        let mut node_c = [0u8; 32];
        node_c[0] = 0xCC;
        let ab = CircuitIdentity::generate(&node_a(), &node_b(), 0);
        let ac = CircuitIdentity::generate(&node_a(), &node_c, 0);
        assert_ne!(ab.circuit_hash, ac.circuit_hash);
    }
}
