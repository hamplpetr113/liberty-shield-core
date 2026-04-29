use std::collections::{HashMap, HashSet};

use crate::encrypted_circuit_path::{CircuitError, EncryptedCircuitPath};
use crate::encrypted_udp_types::EncryptedUdpNodeId;

/// A packet travelling along a circuit, carrying the payload and its position.
#[derive(Debug, Clone)]
pub struct CircuitPacket {
    pub circuit_id: u64,
    /// Which hop index this packet is currently at.
    pub hop_index: usize,
    /// Hash of the payload used for per-hop replay detection.
    pub payload_hash: u64,
    pub payload: Vec<u8>,
}

impl CircuitPacket {
    fn new(circuit_id: u64, hop_index: usize, payload: Vec<u8>) -> Self {
        let payload_hash = hash_payload(&payload);
        Self {
            circuit_id,
            hop_index,
            payload_hash,
            payload,
        }
    }
}

/// Simple non-cryptographic payload hash for replay detection.
fn hash_payload(payload: &[u8]) -> u64 {
    payload
        .iter()
        .enumerate()
        .fold(0xcbf29ce484222325u64, |h, (i, &b)| {
            h.wrapping_mul(0x100000001b3)
                .wrapping_add(b as u64)
                .wrapping_add(i as u64)
        })
}

/// Manages registered circuits and simulates hop-by-hop forwarding.
#[derive(Debug)]
pub struct EncryptedCircuitRuntime {
    circuits: HashMap<u64, EncryptedCircuitPath>,
    closed: HashSet<u64>,
    /// Per-circuit, per-hop replay table: (circuit_id, hop_index) → seen payload hashes.
    replay_table: HashMap<(u64, usize), HashSet<u64>>,
}

impl EncryptedCircuitRuntime {
    pub fn new() -> Self {
        Self {
            circuits: HashMap::new(),
            closed: HashSet::new(),
            replay_table: HashMap::new(),
        }
    }

    /// Register a new circuit path. Returns `Err` for invalid paths or duplicate IDs.
    pub fn register_circuit(&mut self, path: EncryptedCircuitPath) -> Result<(), CircuitError> {
        if self.circuits.contains_key(&path.circuit_id) || self.closed.contains(&path.circuit_id) {
            return Err(CircuitError::UnknownCircuit);
        }
        self.circuits.insert(path.circuit_id, path);
        Ok(())
    }

    /// Initiate a send from the origin of a circuit.
    /// Returns a `CircuitPacket` positioned at hop 0.
    pub fn send_on_circuit(
        &mut self,
        circuit_id: u64,
        payload: &[u8],
    ) -> Result<CircuitPacket, CircuitError> {
        if self.closed.contains(&circuit_id) {
            return Err(CircuitError::CircuitClosed);
        }
        let path = self
            .circuits
            .get(&circuit_id)
            .ok_or(CircuitError::UnknownCircuit)?;
        if path.is_expired() {
            return Err(CircuitError::TtlExpired);
        }
        let pkt = CircuitPacket::new(circuit_id, 0, payload.to_vec());
        self.check_replay(circuit_id, 0, pkt.payload_hash)?;
        Ok(pkt)
    }

    /// Forward a `CircuitPacket` to the next hop.
    /// Returns `Some(packet)` at the next hop, or `None` if at the final hop (delivered).
    pub fn forward_next(
        &mut self,
        pkt: CircuitPacket,
    ) -> Result<Option<CircuitPacket>, CircuitError> {
        if self.closed.contains(&pkt.circuit_id) {
            return Err(CircuitError::CircuitClosed);
        }
        let path = self
            .circuits
            .get(&pkt.circuit_id)
            .ok_or(CircuitError::UnknownCircuit)?;
        if path.is_expired() {
            return Err(CircuitError::TtlExpired);
        }
        let next_hop = pkt.hop_index + 1;
        if next_hop >= path.hops.len() {
            return Ok(None);
        }
        let next_pkt = CircuitPacket::new(pkt.circuit_id, next_hop, pkt.payload.clone());
        self.check_replay(pkt.circuit_id, next_hop, next_pkt.payload_hash)?;
        Ok(Some(next_pkt))
    }

    /// Close a circuit. Further sends and forwards on this circuit will fail.
    pub fn close_circuit(&mut self, circuit_id: u64) -> Result<(), CircuitError> {
        if self.closed.contains(&circuit_id) {
            return Err(CircuitError::CircuitClosed);
        }
        if !self.circuits.contains_key(&circuit_id) {
            return Err(CircuitError::UnknownCircuit);
        }
        self.circuits.remove(&circuit_id);
        self.closed.insert(circuit_id);
        Ok(())
    }

    /// Advance a circuit path's TTL by one tick.
    pub fn tick_ttl(&mut self, circuit_id: u64) -> Result<bool, CircuitError> {
        let path = self
            .circuits
            .get_mut(&circuit_id)
            .ok_or(CircuitError::UnknownCircuit)?;
        Ok(path.tick_ttl())
    }

    /// Number of currently registered (open) circuits.
    pub fn circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Return the node at `hop_index` within `circuit_id`.
    pub fn hop_node(
        &self,
        circuit_id: u64,
        hop_index: usize,
    ) -> Result<EncryptedUdpNodeId, CircuitError> {
        let path = self
            .circuits
            .get(&circuit_id)
            .ok_or(CircuitError::UnknownCircuit)?;
        path.hops
            .get(hop_index)
            .copied()
            .ok_or(CircuitError::UnknownCircuit)
    }

    fn check_replay(&mut self, circuit_id: u64, hop: usize, hash: u64) -> Result<(), CircuitError> {
        let seen = self.replay_table.entry((circuit_id, hop)).or_default();
        if !seen.insert(hash) {
            return Err(CircuitError::ReplayDetected);
        }
        Ok(())
    }
}

impl Default for EncryptedCircuitRuntime {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encrypted_circuit_path::CircuitError;

    fn ids(ns: &[u64]) -> Vec<EncryptedUdpNodeId> {
        ns.iter().map(|&n| EncryptedUdpNodeId(n)).collect()
    }

    fn make_path(circuit_id: u64, hops: &[u64], ttl: u32) -> EncryptedCircuitPath {
        EncryptedCircuitPath::new(circuit_id, ids(hops), ttl).unwrap()
    }

    // C1: register a 3-hop circuit
    #[test]
    fn c1_register_3_hop_circuit() {
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(make_path(1, &[1, 2, 3], 10)).unwrap();
        assert_eq!(rt.circuit_count(), 1);
    }

    // C2: single hop circuit rejected at path creation
    #[test]
    fn c2_reject_single_hop_circuit() {
        let err = EncryptedCircuitPath::new(1, ids(&[1]), 10).unwrap_err();
        assert_eq!(err, CircuitError::TooFewHops);
    }

    // C3: circuit with loop rejected at path creation
    #[test]
    fn c3_reject_circuit_loop() {
        let err = EncryptedCircuitPath::new(1, ids(&[1, 2, 1]), 10).unwrap_err();
        assert_eq!(err, CircuitError::LoopDetected);
    }

    // C4: payload forwarded across all hops
    #[test]
    fn c4_payload_forwarded_across_hops() {
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(make_path(1, &[1, 2, 3], 10)).unwrap();
        let pkt = rt.send_on_circuit(1, b"hello").unwrap();
        assert_eq!(pkt.hop_index, 0);
        let pkt = rt.forward_next(pkt).unwrap().unwrap();
        assert_eq!(pkt.hop_index, 1);
        let pkt = rt.forward_next(pkt).unwrap().unwrap();
        assert_eq!(pkt.hop_index, 2);
        let result = rt.forward_next(pkt).unwrap();
        assert!(result.is_none(), "packet delivered at final hop");
    }

    // C5: TTL expiration
    #[test]
    fn c5_ttl_expiration() {
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(make_path(1, &[1, 2, 3], 1)).unwrap();
        rt.tick_ttl(1).unwrap(); // ttl=1→0
        let err = rt.send_on_circuit(1, b"data").unwrap_err();
        assert_eq!(err, CircuitError::TtlExpired);
    }

    // C6: closed circuit rejected
    #[test]
    fn c6_closed_circuit_rejected() {
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(make_path(1, &[1, 2, 3], 10)).unwrap();
        rt.close_circuit(1).unwrap();
        assert_eq!(
            rt.send_on_circuit(1, b"data").unwrap_err(),
            CircuitError::CircuitClosed
        );
    }

    // C7: replay detection per hop
    #[test]
    fn c7_replay_detection() {
        let mut rt = EncryptedCircuitRuntime::new();
        rt.register_circuit(make_path(1, &[1, 2, 3], 10)).unwrap();
        rt.send_on_circuit(1, b"replay-me").unwrap(); // first send ok
        assert_eq!(
            rt.send_on_circuit(1, b"replay-me").unwrap_err(),
            CircuitError::ReplayDetected
        );
    }

    // C8: deterministic routing — same input always gives same hop sequence
    #[test]
    fn c8_deterministic_routing() {
        let run = |payload: &[u8]| -> Vec<usize> {
            let mut rt = EncryptedCircuitRuntime::new();
            rt.register_circuit(make_path(1, &[10, 20, 30], 100))
                .unwrap();
            let mut pkt = rt.send_on_circuit(1, payload).unwrap();
            let mut hops = vec![pkt.hop_index];
            loop {
                match rt.forward_next(pkt.clone()).unwrap() {
                    Some(next) => {
                        hops.push(next.hop_index);
                        pkt = next;
                    }
                    None => break,
                }
            }
            hops
        };
        assert_eq!(run(b"abc"), run(b"abc"));
        assert_eq!(run(b"abc"), vec![0, 1, 2]);
    }

    // C9: unknown circuit send rejected
    #[test]
    fn c9_unknown_circuit_rejected() {
        let mut rt = EncryptedCircuitRuntime::new();
        assert_eq!(
            rt.send_on_circuit(99, b"data").unwrap_err(),
            CircuitError::UnknownCircuit
        );
    }
}
