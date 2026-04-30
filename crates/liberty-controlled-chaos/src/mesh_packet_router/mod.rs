//! Mesh packet router — routes cells between neighboring nodes by circuit ID.
//!
//! `MeshPacketRouter` maintains a forwarding table: each circuit_id maps to a
//! next-hop `node_id`.  Unknown circuits are rejected, and a basic loop guard
//! prevents re-routing a packet back to its incoming hop.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// RouteEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub circuit_id: u64,
    /// Incoming hop node_id (where packets arrive from).
    pub ingress_node: [u8; 32],
    /// Outgoing hop node_id (where packets should be forwarded).
    pub egress_node: [u8; 32],
    pub packets_forwarded: u64,
    pub bytes_forwarded: u64,
}

// ---------------------------------------------------------------------------
// RouterError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterError {
    UnknownCircuit,
    LoopDetected,
    DuplicateRoute,
}

// ---------------------------------------------------------------------------
// MeshPacketRouter
// ---------------------------------------------------------------------------

pub struct MeshPacketRouter {
    routes: HashMap<u64, RouteEntry>,
    total_forwarded: u64,
    total_rejected: u64,
}

impl MeshPacketRouter {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            total_forwarded: 0,
            total_rejected: 0,
        }
    }

    /// Install a forwarding route for `circuit_id`.
    pub fn install_route(
        &mut self,
        circuit_id: u64,
        ingress_node: [u8; 32],
        egress_node: [u8; 32],
    ) -> Result<(), RouterError> {
        if self.routes.contains_key(&circuit_id) {
            return Err(RouterError::DuplicateRoute);
        }
        self.routes.insert(
            circuit_id,
            RouteEntry {
                circuit_id,
                ingress_node,
                egress_node,
                packets_forwarded: 0,
                bytes_forwarded: 0,
            },
        );
        Ok(())
    }

    /// Remove a route.
    pub fn remove_route(&mut self, circuit_id: u64) {
        self.routes.remove(&circuit_id);
    }

    /// Forward a packet on `circuit_id` arriving from `from_node`.
    ///
    /// Returns the egress `node_id` the packet should be sent to.
    pub fn forward(
        &mut self,
        circuit_id: u64,
        from_node: &[u8; 32],
        bytes: u64,
    ) -> Result<[u8; 32], RouterError> {
        let entry = self
            .routes
            .get_mut(&circuit_id)
            .ok_or(RouterError::UnknownCircuit)?;
        // Loop guard: reject if packet arrives from the egress side.
        if from_node == &entry.egress_node {
            self.total_rejected += 1;
            return Err(RouterError::LoopDetected);
        }
        entry.packets_forwarded += 1;
        entry.bytes_forwarded += bytes;
        self.total_forwarded += 1;
        Ok(entry.egress_node)
    }

    pub fn route(&self, circuit_id: u64) -> Option<&RouteEntry> {
        self.routes.get(&circuit_id)
    }

    pub fn route_count(&self) -> usize {
        self.routes.len()
    }

    pub fn total_forwarded(&self) -> u64 {
        self.total_forwarded
    }

    pub fn total_rejected(&self) -> u64 {
        self.total_rejected
    }
}

impl Default for MeshPacketRouter {
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

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // MPR1: install_route adds a route.
    #[test]
    fn mpr1_install_route() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        assert_eq!(r.route_count(), 1);
    }

    // MPR2: forward returns egress node.
    #[test]
    fn mpr2_forward_returns_egress() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        let egress = r.forward(1, &nid(1), 100).unwrap();
        assert_eq!(egress, nid(2));
    }

    // MPR3: forward on unknown circuit returns UnknownCircuit.
    #[test]
    fn mpr3_unknown_circuit() {
        let mut r = MeshPacketRouter::new();
        assert_eq!(r.forward(99, &nid(1), 0), Err(RouterError::UnknownCircuit));
    }

    // MPR4: loop detection rejects packet from egress side.
    #[test]
    fn mpr4_loop_detected() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        // Packet arriving from egress node (loop)
        assert_eq!(r.forward(1, &nid(2), 0), Err(RouterError::LoopDetected));
    }

    // MPR5: duplicate route returns DuplicateRoute.
    #[test]
    fn mpr5_duplicate_route() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        assert_eq!(
            r.install_route(1, nid(3), nid(4)),
            Err(RouterError::DuplicateRoute)
        );
    }

    // MPR6: remove_route removes the route.
    #[test]
    fn mpr6_remove_route() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        r.remove_route(1);
        assert_eq!(r.route_count(), 0);
    }

    // MPR7: total_forwarded increments on forward.
    #[test]
    fn mpr7_total_forwarded() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        r.forward(1, &nid(1), 50).unwrap();
        r.forward(1, &nid(1), 50).unwrap();
        assert_eq!(r.total_forwarded(), 2);
    }

    // MPR8: total_rejected increments on loop detection.
    #[test]
    fn mpr8_total_rejected() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        let _ = r.forward(1, &nid(2), 0);
        assert_eq!(r.total_rejected(), 1);
    }

    // MPR9: route entry tracks bytes.
    #[test]
    fn mpr9_bytes_tracked() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        r.forward(1, &nid(1), 200).unwrap();
        assert_eq!(r.route(1).unwrap().bytes_forwarded, 200);
    }

    // MPR10: multiple independent circuits.
    #[test]
    fn mpr10_multiple_circuits() {
        let mut r = MeshPacketRouter::new();
        r.install_route(1, nid(1), nid(2)).unwrap();
        r.install_route(2, nid(3), nid(4)).unwrap();
        assert_eq!(r.forward(1, &nid(1), 10).unwrap(), nid(2));
        assert_eq!(r.forward(2, &nid(3), 10).unwrap(), nid(4));
    }
}
