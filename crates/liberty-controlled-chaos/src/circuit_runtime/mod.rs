//! CircuitRuntime — manages active circuit lifecycles and routes cells.
//!
//! Sits above `OnionLayer` and `MeshRouter`:
//!   CircuitRuntime → OnionLayer → MeshRouter → UDPTransport
//!
//! Each registered `Circuit` gets a `RoutePath` derived from its relay hops.
//! `send_cell` advances the path by one hop on every call, returning the peer
//! address to which the (onion-encrypted) cell should be dispatched.
//!
//! No network I/O is performed here; no unsafe code.

mod circuit_table;
mod runtime;
mod types;

pub use circuit_table::ActiveCircuit;
pub use runtime::CircuitRuntime;
pub use types::{CircuitRuntimeError, CircuitState};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::cell_encoder::CELL_SIZE;
    use crate::circuit_builder::{CircuitBuilder, CircuitId, NodeDescriptor, NodeId};
    use crate::mesh_router::RoutingError;
    use crate::noise_link::EncryptedCell;
    use crate::udp_transport::PeerAddress;

    use super::*;

    fn peer(port: u16) -> PeerAddress {
        PeerAddress::new(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
    }

    fn node(id: u64, port: u16) -> NodeDescriptor {
        NodeDescriptor {
            node_id: NodeId(id),
            public_key: [id as u8; 32],
            peer_address: peer(port),
            latency_estimate: 100,
            reliability_score: 0.99,
        }
    }

    fn three_nodes() -> Vec<NodeDescriptor> {
        // Unsorted; CircuitBuilder sorts by NodeId → [1→1001, 2→2001, 3→3001]
        vec![node(3, 3001), node(1, 1001), node(2, 2001)]
    }

    fn make_runtime_with_circuit() -> (CircuitRuntime, CircuitId) {
        let circuit = CircuitBuilder::build_circuit(&three_nodes(), 3).unwrap();
        let cid = circuit.circuit_id;
        let mut rt = CircuitRuntime::new();
        rt.register_circuit(circuit, 0).unwrap();
        (rt, cid)
    }

    fn dummy_cell() -> EncryptedCell {
        EncryptedCell {
            path_id: 0,
            nonce: 0,
            ciphertext: [0u8; CELL_SIZE],
            auth_tag: [0u8; 16],
        }
    }

    // ── R1: register circuit ──────────────────────────────────────────────────

    #[test]
    fn r1_register_circuit() {
        let circuit = CircuitBuilder::build_circuit(&three_nodes(), 3).unwrap();
        let cid = circuit.circuit_id;
        let mut rt = CircuitRuntime::new();
        rt.register_circuit(circuit, 42_000).unwrap();

        let active = rt.get_active_circuit(cid).unwrap();
        assert_eq!(active.state, CircuitState::Active);
        assert_eq!(active.creation_timestamp, 42_000);
        assert_eq!(active.circuit.hop_count(), 3);
    }

    // ── R2: send cell through circuit ─────────────────────────────────────────

    #[test]
    fn r2_send_cell_returns_first_hop() {
        let (mut rt, cid) = make_runtime_with_circuit();
        let hop = rt.send_cell(cid, &dummy_cell()).unwrap();
        // After sorting by NodeId: [1→1001, 2→2001, 3→3001]; first hop = port 1001
        assert_eq!(hop, peer(1001));
    }

    // ── R3: reject unknown circuit ────────────────────────────────────────────

    #[test]
    fn r3_unknown_circuit_rejected() {
        let mut rt = CircuitRuntime::new();
        assert!(matches!(
            rt.send_cell(CircuitId(0xdeadbeef), &dummy_cell()),
            Err(CircuitRuntimeError::CircuitNotFound(CircuitId(0xdeadbeef)))
        ));
    }

    // ── R4: circuit close ─────────────────────────────────────────────────────

    #[test]
    fn r4_closed_circuit_rejects_send() {
        let (mut rt, cid) = make_runtime_with_circuit();
        rt.close_circuit(cid).unwrap();

        let active = rt.get_active_circuit(cid).unwrap();
        assert_eq!(active.state, CircuitState::Closed);

        assert!(matches!(
            rt.send_cell(cid, &dummy_cell()),
            Err(CircuitRuntimeError::CircuitNotActive(..))
        ));
    }

    // ── R5: deterministic routing through MeshRouter ──────────────────────────

    #[test]
    fn r5_deterministic_routing() {
        // Two independently constructed runtimes with identical circuit inputs
        // must produce the same hop sequence.
        let (mut rt_a, cid_a) = make_runtime_with_circuit();
        let (mut rt_b, cid_b) = make_runtime_with_circuit();

        // circuit_id is deterministic, so both must match
        assert_eq!(cid_a, cid_b);

        let hop_a1 = rt_a.send_cell(cid_a, &dummy_cell()).unwrap();
        let hop_b1 = rt_b.send_cell(cid_b, &dummy_cell()).unwrap();
        assert_eq!(hop_a1, hop_b1, "first hop must be identical");

        let hop_a2 = rt_a.send_cell(cid_a, &dummy_cell()).unwrap();
        let hop_b2 = rt_b.send_cell(cid_b, &dummy_cell()).unwrap();
        assert_eq!(hop_a2, hop_b2, "second hop must be identical");

        let hop_a3 = rt_a.send_cell(cid_a, &dummy_cell()).unwrap();
        let hop_b3 = rt_b.send_cell(cid_b, &dummy_cell()).unwrap();
        assert_eq!(hop_a3, hop_b3, "third hop must be identical");
    }

    // ── R6: duplicate circuit registration rejected ───────────────────────────

    #[test]
    fn r6_duplicate_registration_rejected() {
        let nodes = three_nodes();
        let c1 = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        let c2 = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        let cid = c1.circuit_id;

        let mut rt = CircuitRuntime::new();
        rt.register_circuit(c1, 0).unwrap();
        assert!(matches!(
            rt.register_circuit(c2, 0),
            Err(CircuitRuntimeError::CircuitAlreadyExists(id)) if id == cid
        ));
    }

    // ── R7: path exhaustion surfaces as RoutingFailed ─────────────────────────

    #[test]
    fn r7_path_exhaustion() {
        let circuit = CircuitBuilder::build_circuit(&three_nodes(), 3).unwrap();
        let cid = circuit.circuit_id;
        let mut rt = CircuitRuntime::new();
        // TTL = 3 hops * 1000 = 3000; exhaust all 3 hops many times is fine,
        // but exhaust hop-count (max_hops = 3) after 3 advances → RouteComplete.
        rt.register_circuit(circuit, 0).unwrap();
        let cell = dummy_cell();

        rt.send_cell(cid, &cell).unwrap(); // hop 0
        rt.send_cell(cid, &cell).unwrap(); // hop 1
        rt.send_cell(cid, &cell).unwrap(); // hop 2

        // path complete — next call surfaces RoutingFailed(RouteComplete)
        assert!(matches!(
            rt.send_cell(cid, &cell),
            Err(CircuitRuntimeError::RoutingFailed(
                RoutingError::RouteComplete(..)
            ))
        ));
    }

    // ── R8: close on unknown circuit returns error ────────────────────────────

    #[test]
    fn r8_close_unknown_circuit_rejected() {
        let mut rt = CircuitRuntime::new();
        assert!(matches!(
            rt.close_circuit(CircuitId(42)),
            Err(CircuitRuntimeError::CircuitNotFound(CircuitId(42)))
        ));
    }
}
