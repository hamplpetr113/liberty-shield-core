//! End-to-end mini testnet — in-memory hybrid network for integration testing.
//!
//! `TestNode` bundles all per-node state.  `TestNet` wires N nodes together
//! through their `RelayPipeline`s using the `CircuitEstablisher` /
//! `CircuitExtender` protocols, then relays encrypted cells in-process.
//!
//! No real UDP I/O is needed for the circuit and relay tests; `UdpLink` is
//! used in the dedicated TN_UDP test to confirm the transport layer works with
//! live sockets.
//!
//! NON-PRODUCTION: deterministic nonces, no concurrency hardening.

use crate::circuit_runtime::establish::CircuitEstablisher;
use crate::circuit_runtime::extend::CircuitExtender;
use crate::encrypted_relay::{PipelineResult, RelayCellCommand, RelayCellPlaintext, RelayPipeline};
use crate::node_identity::NodeIdentity;
use crate::resource_guard::{ResourceBudget, ResourceGuard};
use crate::transport::UdpLink;

// ---------------------------------------------------------------------------
// TestNode
// ---------------------------------------------------------------------------

/// One node in the mini testnet.
pub struct TestNode {
    pub identity: NodeIdentity,
    pub pipeline: RelayPipeline,
    pub resource_guard: ResourceGuard,
    /// Optional UDP socket — bound on construction if `bind_udp` is true.
    pub udp_link: Option<UdpLink>,
}

impl TestNode {
    /// Create a node without a UDP socket.
    pub fn new(seed: u8) -> Self {
        let identity = NodeIdentity::generate_from_seed([seed; 32]);
        Self {
            identity,
            pipeline: RelayPipeline::new(),
            resource_guard: ResourceGuard::new(ResourceBudget::default()),
            udp_link: None,
        }
    }

    /// Create a node with a loopback-bound UDP socket.
    pub fn with_udp(seed: u8) -> Self {
        let mut node = Self::new(seed);
        node.udp_link = Some(UdpLink::bind("127.0.0.1:0").expect("udp bind"));
        node
    }

    pub fn node_id(&self) -> [u8; 32] {
        self.identity.node_id
    }
}

// ---------------------------------------------------------------------------
// TestNet helpers
// ---------------------------------------------------------------------------

/// Establish a 2-node A→B circuit and register keys in both pipelines.
///
/// Returns `circuit_id`.
pub fn establish_ab(
    node_a: &mut TestNode,
    node_b: &mut TestNode,
    circuit_id: u64,
    nonce: u64,
) -> u64 {
    let mut est_a = CircuitEstablisher::new();
    let mut est_b = CircuitEstablisher::new();

    let create = est_a.initiate(circuit_id, nonce).unwrap();
    let (created, _, b_keys) = est_b.handle_create(&create).unwrap();
    let a_keys = est_a.handle_created(&created).unwrap();

    node_a
        .pipeline
        .register_circuit(circuit_id, a_keys.0, a_keys.1);
    node_b
        .pipeline
        .register_circuit(circuit_id, b_keys.0, b_keys.1);

    circuit_id
}

/// Extend from A's existing circuit (via B) to C, adding a new B→C leg.
///
/// Returns `new_circuit_id`.
pub fn extend_to_c(
    node_a: &mut TestNode,
    node_b: &mut TestNode,
    node_c: &mut TestNode,
    via_cid: u64,
    new_cid: u64,
    nonce: u64,
) -> u64 {
    let mut ext_a = CircuitExtender::new();
    let mut ext_b = CircuitExtender::new();

    let extend_msg = ext_a.prepare_extend(via_cid, new_cid, nonce).unwrap();
    let result = ext_b.handle_extend(&extend_msg).unwrap();
    let a_bc_keys = ext_a.handle_extended(&result.response).unwrap();

    node_a
        .pipeline
        .register_circuit(new_cid, a_bc_keys.0, a_bc_keys.1);
    node_b
        .pipeline
        .register_circuit(new_cid, result.forwarder_keys.0, result.forwarder_keys.1);
    node_c
        .pipeline
        .register_circuit(new_cid, result.target_keys.0, result.target_keys.1);

    new_cid
}

/// Relay one plaintext payload from A through B to C, return the decrypted payload at C.
pub fn relay_a_to_c(
    node_a: &mut TestNode,
    node_b: &mut TestNode,
    node_c: &mut TestNode,
    cid_ab: u64,
    cid_bc: u64,
    stream_id: u64,
    payload: Vec<u8>,
) -> Vec<u8> {
    let pt = RelayCellPlaintext::new(cid_ab, stream_id, RelayCellCommand::Data, 0, payload);
    let enc_ab = node_a.pipeline.send_cell(cid_ab, stream_id, pt).unwrap();

    let dec_b = match node_b.pipeline.receive_cell(cid_ab, stream_id, &enc_ab) {
        PipelineResult::Accepted(d) => d,
        other => panic!("B failed: {other:?}"),
    };

    let pt_bc =
        RelayCellPlaintext::new(cid_bc, stream_id, RelayCellCommand::Data, 0, dec_b.payload);
    let enc_bc = node_b.pipeline.send_cell(cid_bc, stream_id, pt_bc).unwrap();

    match node_c.pipeline.receive_cell(cid_bc, stream_id, &enc_bc) {
        PipelineResult::Accepted(d) => d.payload,
        other => panic!("C failed: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::directory_authority::{AuthorityIdentity, DirectoryConsensus};
    use crate::directory_client::DirectoryClient;
    use crate::node_descriptor::NodeDescriptor;
    use crate::node_identity::NodeIdentity;
    use crate::padding_scheduler::{PacketKind, PaddingScheduler, SchedulerConfig};
    use crate::path_selection::{CandidatePeer, PathSelector, PeerRole};
    use crate::resource_guard::ResourceError;

    // TN1: 3-node relay — payload arrives at C unchanged.
    #[test]
    fn tn1_three_node_relay() {
        let mut a = TestNode::new(0x01);
        let mut b = TestNode::new(0x02);
        let mut c = TestNode::new(0x03);

        establish_ab(&mut a, &mut b, 100, 1);
        extend_to_c(&mut a, &mut b, &mut c, 100, 200, 2);

        let payload = b"hello from A to C".to_vec();
        let received = relay_a_to_c(&mut a, &mut b, &mut c, 100, 200, 1, payload.clone());
        assert_eq!(received, payload);
    }

    // TN2: 5-node mesh — build multiple independent circuits.
    #[test]
    fn tn2_five_node_mesh() {
        let mut n0 = TestNode::new(0x01);
        let mut n1 = TestNode::new(0x02);
        let mut n2 = TestNode::new(0x03);
        let mut n3 = TestNode::new(0x04);
        let mut n4 = TestNode::new(0x05);

        // Circuit 1: n0 → n1 → n2
        establish_ab(&mut n0, &mut n1, 10, 11);
        extend_to_c(&mut n0, &mut n1, &mut n2, 10, 11, 12);

        // Circuit 2: n3 → n4 (2-hop only)
        establish_ab(&mut n3, &mut n4, 20, 21);

        // Relay on circuit 1.
        let msg1 = b"circuit1".to_vec();
        let recv1 = relay_a_to_c(&mut n0, &mut n1, &mut n2, 10, 11, 1, msg1.clone());
        assert_eq!(recv1, msg1);

        // Relay on circuit 2 (direct A→B, no C hop).
        let pt = RelayCellPlaintext::new(20, 1, RelayCellCommand::Data, 0, b"circuit2".to_vec());
        let enc = n3.pipeline.send_cell(20, 1, pt).unwrap();
        match n4.pipeline.receive_cell(20, 1, &enc) {
            PipelineResult::Accepted(d) => assert_eq!(d.payload, b"circuit2"),
            other => panic!("{other:?}"),
        }
    }

    // TN3: path selection integration — PathSelector picks 3 distinct roles.
    #[test]
    fn tn3_path_selection_integration() {
        let nodes: Vec<TestNode> = (0x01..=0x06).map(TestNode::new).collect();
        let candidates: Vec<CandidatePeer> = nodes
            .iter()
            .enumerate()
            .map(|(i, n)| CandidatePeer {
                node_id: n.node_id(),
                public_key: n.identity.public_key,
                role: [PeerRole::Guard, PeerRole::Relay, PeerRole::Exit][i % 3],
            })
            .collect();

        let sel = PathSelector::new();
        let path = sel.select(&candidates).unwrap();
        assert_eq!(path.guard.role, PeerRole::Guard);
        assert_eq!(path.relay.role, PeerRole::Relay);
        assert_eq!(path.exit.role, PeerRole::Exit);
        // No duplicate node_ids.
        assert_ne!(path.guard.node_id, path.relay.node_id);
        assert_ne!(path.guard.node_id, path.exit.node_id);
        assert_ne!(path.relay.node_id, path.exit.node_id);
    }

    // TN4: circuit establish — A and B share working session keys.
    #[test]
    fn tn4_circuit_establish() {
        let mut a = TestNode::new(0xAA);
        let mut b = TestNode::new(0xBB);
        establish_ab(&mut a, &mut b, 500, 50);

        let pt =
            RelayCellPlaintext::new(500, 1, RelayCellCommand::Data, 0, b"established".to_vec());
        let enc = a.pipeline.send_cell(500, 1, pt.clone()).unwrap();
        match b.pipeline.receive_cell(500, 1, &enc) {
            PipelineResult::Accepted(d) => assert_eq!(d.payload, b"established"),
            other => panic!("{other:?}"),
        }
    }

    // TN5: circuit extend — A can reach C through B with correct keys.
    #[test]
    fn tn5_circuit_extend() {
        let mut a = TestNode::new(0x10);
        let mut b = TestNode::new(0x11);
        let mut c = TestNode::new(0x12);

        establish_ab(&mut a, &mut b, 600, 60);
        extend_to_c(&mut a, &mut b, &mut c, 600, 601, 61);

        // A→C via circuit 601.
        let pt = RelayCellPlaintext::new(601, 1, RelayCellCommand::Data, 0, b"extended".to_vec());
        let enc = a.pipeline.send_cell(601, 1, pt).unwrap();
        let dec_b = match b.pipeline.receive_cell(601, 1, &enc) {
            PipelineResult::Accepted(d) => d,
            other => panic!("{other:?}"),
        };
        let pt_c =
            RelayCellPlaintext::new(601, 1, RelayCellCommand::Data, 0, dec_b.payload.clone());
        let enc_c = b.pipeline.send_cell(601, 1, pt_c).unwrap();
        match c.pipeline.receive_cell(601, 1, &enc_c) {
            PipelineResult::Accepted(d) => assert_eq!(d.payload, b"extended"),
            other => panic!("{other:?}"),
        }
    }

    // TN6: packet relay — 5 sequential cells traverse A→B→C.
    #[test]
    fn tn6_packet_relay() {
        let mut a = TestNode::new(0x20);
        let mut b = TestNode::new(0x21);
        let mut c = TestNode::new(0x22);

        establish_ab(&mut a, &mut b, 700, 70);
        extend_to_c(&mut a, &mut b, &mut c, 700, 701, 71);

        for seq in 0u64..5 {
            let payload = format!("cell-{seq}").into_bytes();
            let received = relay_a_to_c(&mut a, &mut b, &mut c, 700, 701, seq + 1, payload.clone());
            assert_eq!(received, payload);
        }
    }

    // TN7: padding scheduler active — schedule respects real_cap and cover_floor.
    #[test]
    fn tn7_padding_scheduler_active() {
        let sched = PaddingScheduler::new(SchedulerConfig::default_config(), [0x42u8; 32]);
        let entries = sched.schedule(1, 4, true);

        // control at slot 0.
        assert_eq!(entries[0].kind, PacketKind::Control);

        // real count ≤ real_cap (8).
        let real = entries
            .iter()
            .filter(|e| e.kind == PacketKind::Real)
            .count();
        assert!(real <= 8);

        // cover ≥ cover_floor (4).
        let cover = entries
            .iter()
            .filter(|e| e.kind == PacketKind::Cover)
            .count();
        assert!(cover >= 4);

        // total == slots_per_epoch (20).
        assert_eq!(entries.len(), 20);
    }

    // TN8: resource guard limits — adding too many circuits is rejected.
    #[test]
    fn tn8_resource_guard_limits() {
        let mut node = TestNode::new(0x30);
        // Default budget has max_circuits = 64.
        for _ in 0..64 {
            node.resource_guard.try_add_circuit().unwrap();
        }
        assert_eq!(
            node.resource_guard.try_add_circuit().unwrap_err(),
            ResourceError::CircuitLimitExceeded
        );
        // Release one slot.
        node.resource_guard.remove_circuit();
        assert!(node.resource_guard.try_add_circuit().is_ok());
    }

    // TN9: directory client integration — ingest consensus, build path.
    #[test]
    fn tn9_directory_client_integration() {
        use std::net::SocketAddr;

        let auth = AuthorityIdentity::new(NodeIdentity::generate_from_seed([0xF0u8; 32]));
        // Build a consensus with 16 descriptors to get role distribution.
        let mut builder = DirectoryConsensus::begin(&auth, 1, 0).unwrap();
        for seed in 0x10u8..0x20u8 {
            let pk = NodeIdentity::generate_from_seed([seed; 32]).public_key;
            let desc = NodeDescriptor::new(
                pk,
                format!("127.0.0.1:{}", 9000 + seed as u16)
                    .parse::<SocketAddr>()
                    .unwrap(),
            );
            builder.add_descriptor(auth.sign_descriptor(desc)).unwrap();
        }
        let consensus = builder.finalise(&auth);

        let mut dc = DirectoryClient::new(AuthorityIdentity::new(
            NodeIdentity::generate_from_seed([0xF0u8; 32]),
        ));
        dc.ingest_consensus(&consensus).unwrap();
        assert_eq!(dc.candidates().len(), 16);

        if !dc.guards().is_empty() && !dc.relays().is_empty() && !dc.exits().is_empty() {
            let path = dc.build_path().unwrap();
            assert_eq!(path.guard.role, PeerRole::Guard);
            assert_eq!(path.relay.role, PeerRole::Relay);
            assert_eq!(path.exit.role, PeerRole::Exit);
        }
    }

    // TN10: UDP link integration — testnet node can send/recv bytes.
    #[test]
    fn tn10_udp_link_integration() {
        let server = TestNode::with_udp(0x40);
        let client = TestNode::with_udp(0x41);

        let server_addr = server.udp_link.as_ref().unwrap().local_addr().unwrap();
        server
            .udp_link
            .as_ref()
            .unwrap()
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        client
            .udp_link
            .as_ref()
            .unwrap()
            .send(server_addr, b"testnet udp")
            .unwrap();

        let (payload, _) = server.udp_link.as_ref().unwrap().recv().unwrap();
        assert_eq!(payload, b"testnet udp");
    }
}
