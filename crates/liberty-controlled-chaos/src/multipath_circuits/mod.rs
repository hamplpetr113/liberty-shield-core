//! Multipath routing — spreads traffic across multiple circuits.
//!
//! Strategy: `hash(packet_id) % circuit_count`.  This is deterministic (same
//! packet always maps to the same circuit) while spreading load evenly across
//! a large number of packets.
//!
//! When a circuit is removed, packets that previously mapped to it are
//! re-hashed over the remaining set (consistent hashing is NOT used; this is
//! a simple modular scheme).

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// RouteResult
// ---------------------------------------------------------------------------

/// The circuit selected for a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteResult {
    pub circuit_id: u64,
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultipathError {
    /// No circuits are available.
    NoCircuitsAvailable,
    /// Circuit_id is not in the active set.
    CircuitNotFound,
}

impl std::fmt::Display for MultipathError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MultipathError::NoCircuitsAvailable => write!(f, "no circuits available for routing"),
            MultipathError::CircuitNotFound => write!(f, "circuit not found"),
        }
    }
}

// ---------------------------------------------------------------------------
// MultipathRouter
// ---------------------------------------------------------------------------

/// Routes packets across multiple circuits using modular hashing.
pub struct MultipathRouter {
    active_circuits: VecDeque<u64>,
    /// Total packets routed (for statistics).
    packets_routed: u64,
}

impl MultipathRouter {
    pub fn new() -> Self {
        Self {
            active_circuits: VecDeque::new(),
            packets_routed: 0,
        }
    }

    /// Add a circuit to the active pool.  No-op if already present.
    pub fn add_circuit(&mut self, circuit_id: u64) {
        if !self.active_circuits.contains(&circuit_id) {
            self.active_circuits.push_back(circuit_id);
        }
    }

    /// Remove a circuit from the active pool.
    pub fn remove_circuit(&mut self, circuit_id: u64) -> Result<(), MultipathError> {
        let pos = self
            .active_circuits
            .iter()
            .position(|&c| c == circuit_id)
            .ok_or(MultipathError::CircuitNotFound)?;
        self.active_circuits.remove(pos);
        Ok(())
    }

    /// Select a path for `packet_id` using `hash(packet_id) % circuit_count`.
    pub fn select_path(&self, packet_id: u64) -> Result<RouteResult, MultipathError> {
        if self.active_circuits.is_empty() {
            return Err(MultipathError::NoCircuitsAvailable);
        }
        let idx = (packet_id % self.active_circuits.len() as u64) as usize;
        Ok(RouteResult {
            circuit_id: self.active_circuits[idx],
        })
    }

    /// Route a packet and increment the counter.
    pub fn route_packet(&mut self, packet_id: u64) -> Result<RouteResult, MultipathError> {
        let result = self.select_path(packet_id)?;
        self.packets_routed += 1;
        Ok(result)
    }

    /// Number of active circuits.
    pub fn circuit_count(&self) -> usize {
        self.active_circuits.len()
    }

    pub fn packets_routed(&self) -> u64 {
        self.packets_routed
    }

    pub fn is_empty(&self) -> bool {
        self.active_circuits.is_empty()
    }
}

impl Default for MultipathRouter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // MP1: single circuit — all packets route to it.
    #[test]
    fn mp1_single_circuit() {
        let mut r = MultipathRouter::new();
        r.add_circuit(42);
        assert_eq!(r.route_packet(0).unwrap().circuit_id, 42);
        assert_eq!(r.route_packet(99).unwrap().circuit_id, 42);
    }

    // MP2: two circuits — packets distribute across both.
    #[test]
    fn mp2_multiple_circuits() {
        let mut r = MultipathRouter::new();
        r.add_circuit(10);
        r.add_circuit(20);
        // packet_id=0 → 0%2=0 → circuit[0]=10
        assert_eq!(r.select_path(0).unwrap().circuit_id, 10);
        // packet_id=1 → 1%2=1 → circuit[1]=20
        assert_eq!(r.select_path(1).unwrap().circuit_id, 20);
    }

    // MP3: path distribution — 1000 packets across 4 circuits stays roughly fair.
    #[test]
    fn mp3_path_distribution() {
        let mut r = MultipathRouter::new();
        for cid in [1u64, 2, 3, 4] {
            r.add_circuit(cid);
        }
        let mut counts = [0u32; 4];
        for pkt in 0u64..1000 {
            let cid = r.select_path(pkt).unwrap().circuit_id;
            counts[(cid - 1) as usize] += 1;
        }
        // Each circuit should get exactly 250 packets (modular hash is perfectly uniform).
        for &c in &counts {
            assert_eq!(c, 250);
        }
    }

    // MP4: failover — removing a circuit means packets re-route over remaining ones.
    #[test]
    fn mp4_failover() {
        let mut r = MultipathRouter::new();
        r.add_circuit(1);
        r.add_circuit(2);
        r.remove_circuit(1).unwrap();
        // Only circuit 2 remains.
        assert_eq!(r.route_packet(0).unwrap().circuit_id, 2);
        assert_eq!(r.route_packet(1).unwrap().circuit_id, 2);
    }

    // MP5: load balancing — verify packets_routed counter increments.
    #[test]
    fn mp5_load_balancing() {
        let mut r = MultipathRouter::new();
        r.add_circuit(5);
        for i in 0u64..10 {
            r.route_packet(i).unwrap();
        }
        assert_eq!(r.packets_routed(), 10);
    }

    // MP6: circuit removal returns error for unknown id.
    #[test]
    fn mp6_circuit_removal() {
        let mut r = MultipathRouter::new();
        assert_eq!(
            r.remove_circuit(99).unwrap_err(),
            MultipathError::CircuitNotFound
        );
    }

    // MP7: circuit addition is idempotent (no duplicate).
    #[test]
    fn mp7_circuit_addition() {
        let mut r = MultipathRouter::new();
        r.add_circuit(1);
        r.add_circuit(1);
        assert_eq!(r.circuit_count(), 1);
    }

    // MP8: fairness — sequential packet ids spread evenly over 3 circuits.
    #[test]
    fn mp8_fairness() {
        let mut r = MultipathRouter::new();
        r.add_circuit(100);
        r.add_circuit(200);
        r.add_circuit(300);
        let mut seen = std::collections::HashSet::new();
        for pkt in 0u64..3 {
            seen.insert(r.select_path(pkt).unwrap().circuit_id);
        }
        assert_eq!(seen.len(), 3);
    }

    // MP9: high load — 10_000 packets all route without error.
    #[test]
    fn mp9_high_load() {
        let mut r = MultipathRouter::new();
        for cid in 1u64..=5 {
            r.add_circuit(cid);
        }
        for pkt in 0u64..10_000 {
            assert!(r.route_packet(pkt).is_ok());
        }
        assert_eq!(r.packets_routed(), 10_000);
    }

    // MP10: stability — no panics after repeated add/remove cycles.
    #[test]
    fn mp10_stability() {
        let mut r = MultipathRouter::new();
        for round in 0u64..20 {
            r.add_circuit(round);
            r.route_packet(round).ok();
            if round > 0 {
                r.remove_circuit(round - 1).ok();
            }
        }
        // Should still have at least one circuit.
        assert!(r.circuit_count() >= 1);
    }
}
