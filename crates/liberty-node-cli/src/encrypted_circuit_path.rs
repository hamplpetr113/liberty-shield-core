use crate::encrypted_udp_types::EncryptedUdpNodeId;

/// Errors produced by the circuit layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitError {
    /// Fewer than 3 hops in the path.
    TooFewHops,
    /// Circuit contains a repeated node (loop).
    LoopDetected,
    /// The circuit ID is not registered.
    UnknownCircuit,
    /// The circuit's TTL has reached zero.
    TtlExpired,
    /// A packet with the same payload was already seen on this hop (replay).
    ReplayDetected,
    /// Attempted to use a circuit that was explicitly closed.
    CircuitClosed,
}

/// A fixed hop sequence for one circuit.
///
/// Minimum 3 hops, no repeated nodes, TTL-limited.
#[derive(Debug, Clone)]
pub struct EncryptedCircuitPath {
    pub circuit_id: u64,
    pub hops: Vec<EncryptedUdpNodeId>,
    pub current_hop: usize,
    pub ttl: u32,
    pub max_hops: usize,
}

impl EncryptedCircuitPath {
    /// Create a new path. Returns `Err(TooFewHops)` if `hops.len() < 3`.
    /// Returns `Err(LoopDetected)` if any node ID appears more than once.
    pub fn new(
        circuit_id: u64,
        hops: Vec<EncryptedUdpNodeId>,
        ttl: u32,
    ) -> Result<Self, CircuitError> {
        if hops.len() < 3 {
            return Err(CircuitError::TooFewHops);
        }
        // Check for loops.
        let mut seen = std::collections::HashSet::new();
        for h in &hops {
            if !seen.insert(h.0) {
                return Err(CircuitError::LoopDetected);
            }
        }
        let max_hops = hops.len();
        Ok(Self {
            circuit_id,
            hops,
            current_hop: 0,
            ttl,
            max_hops,
        })
    }

    /// The node at the current hop position.
    pub fn current_node(&self) -> EncryptedUdpNodeId {
        self.hops[self.current_hop]
    }

    /// The next node in the path, or `None` if at the final hop.
    pub fn next_node(&self) -> Option<EncryptedUdpNodeId> {
        self.hops.get(self.current_hop + 1).copied()
    }

    /// Advance to the next hop. Returns `true` if there is a next hop.
    pub fn advance(&mut self) -> bool {
        if self.current_hop + 1 < self.hops.len() {
            self.current_hop += 1;
            true
        } else {
            false
        }
    }

    /// Whether the path has reached the final hop.
    pub fn is_complete(&self) -> bool {
        self.current_hop + 1 == self.hops.len()
    }

    /// Consume one TTL tick. Returns `true` if the circuit is still alive.
    pub fn tick_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
        }
        self.ttl > 0
    }

    /// Whether TTL has been exhausted.
    pub fn is_expired(&self) -> bool {
        self.ttl == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(ns: &[u64]) -> Vec<EncryptedUdpNodeId> {
        ns.iter().map(|&n| EncryptedUdpNodeId(n)).collect()
    }

    // CP1: 3-hop circuit created successfully
    #[test]
    fn cp1_three_hop_circuit_ok() {
        let path = EncryptedCircuitPath::new(1, ids(&[1, 2, 3]), 10).unwrap();
        assert_eq!(path.hops.len(), 3);
        assert_eq!(path.circuit_id, 1);
        assert_eq!(path.current_hop, 0);
        assert_eq!(path.ttl, 10);
    }

    // CP2: fewer than 3 hops rejected
    #[test]
    fn cp2_too_few_hops_rejected() {
        assert_eq!(
            EncryptedCircuitPath::new(1, ids(&[1, 2]), 10).unwrap_err(),
            CircuitError::TooFewHops
        );
        assert_eq!(
            EncryptedCircuitPath::new(1, ids(&[1]), 10).unwrap_err(),
            CircuitError::TooFewHops
        );
    }

    // CP3: loop in hops rejected
    #[test]
    fn cp3_loop_rejected() {
        assert_eq!(
            EncryptedCircuitPath::new(1, ids(&[1, 2, 1]), 10).unwrap_err(),
            CircuitError::LoopDetected
        );
    }

    // CP4: advance moves current_hop forward
    #[test]
    fn cp4_advance() {
        let mut path = EncryptedCircuitPath::new(1, ids(&[1, 2, 3]), 10).unwrap();
        assert_eq!(path.current_node(), EncryptedUdpNodeId(1));
        assert!(path.advance());
        assert_eq!(path.current_node(), EncryptedUdpNodeId(2));
        assert!(path.advance());
        assert_eq!(path.current_node(), EncryptedUdpNodeId(3));
        assert!(!path.advance(), "no hop beyond last");
    }

    // CP5: is_complete returns true at final hop
    #[test]
    fn cp5_is_complete() {
        let mut path = EncryptedCircuitPath::new(1, ids(&[1, 2, 3]), 10).unwrap();
        assert!(!path.is_complete());
        path.advance();
        assert!(!path.is_complete());
        path.advance();
        assert!(path.is_complete());
    }

    // CP6: TTL expiry
    #[test]
    fn cp6_ttl_expiry() {
        let mut path = EncryptedCircuitPath::new(1, ids(&[1, 2, 3]), 2).unwrap();
        assert!(!path.is_expired());
        assert!(path.tick_ttl()); // ttl 2→1, alive
        assert!(!path.tick_ttl()); // ttl 1→0, expired
        assert!(path.is_expired());
    }
}
