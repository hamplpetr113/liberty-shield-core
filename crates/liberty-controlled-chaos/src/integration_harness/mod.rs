mod assertions;
mod fixtures;
mod pipeline;

#[cfg(test)]
mod tests {
    use crate::cell_encoder::CELL_SIZE;
    use crate::circuit_builder::CircuitBuilder;
    use crate::circuit_runtime::CircuitRuntime;
    use crate::guard_selection::GuardSelector;
    use crate::mesh_router::{MeshRouter, Route, RouteId, RoutingTable};
    use crate::noise_link::ENCRYPTED_CELL_SIZE;
    use crate::onion_layer::ONION_PACKET_SIZE;
    use crate::protocol_runtime::{ProtocolAction, ProtocolEvent, ProtocolRuntime};
    use crate::relay_protocol::{RelayCapabilities, RelayDescriptor, RelayNodeId};
    use crate::udp_transport::PeerAddress;

    use std::net::SocketAddr;

    use super::assertions::*;
    use super::fixtures::*;
    use super::pipeline::*;

    fn socket_peer(port: u16) -> PeerAddress {
        PeerAddress::new(format!("127.0.0.1:{port}").parse::<SocketAddr>().unwrap())
    }

    // ── I1: node discovery → guard selection → circuit build ─────────────────

    #[test]
    fn i1_nodes_to_guards_to_circuit() {
        let disc_nodes = discovery_nodes(5);
        let policy = guard_policy();
        let guards = GuardSelector::select_initial_guards(&disc_nodes, &policy, 3).unwrap();
        assert_eq!(guards.active_count(), 3);

        // Bridge discovery nodes to circuit_builder nodes.
        let cb_nodes = circuit_nodes(5);
        let circuit = CircuitBuilder::build_circuit(&cb_nodes, 3).unwrap();
        assert_eq!(circuit.hop_count(), 3);
        assert_eq!(circuit.onion_keys.len(), 3);
    }

    // ── I2: circuit → circuit_runtime → send_cell ────────────────────────────

    #[test]
    fn i2_circuit_to_runtime_to_send() {
        let cb_nodes = circuit_nodes(3);
        let circuit = CircuitBuilder::build_circuit(&cb_nodes, 3).unwrap();
        let circuit_id = circuit.circuit_id;

        let mut rt = CircuitRuntime::new();
        rt.register_circuit(circuit, 0).unwrap();

        // Build a minimal encrypted cell to pass to send_cell.
        let enc_cell = {
            use crate::cell_encoder::CELL_SIZE;
            use crate::noise_link::EncryptedCell;
            EncryptedCell {
                path_id: 1,
                nonce: 0,
                ciphertext: [0u8; CELL_SIZE],
                auth_tag: [0u8; 16],
            }
        };

        // send_cell advances the RoutePath and returns the first hop address.
        let peer = rt.send_cell(circuit_id, &enc_cell).unwrap();
        // The RoutePath for 3 hops should return a valid address.
        assert_ne!(peer, socket_peer(0));
    }

    // ── I3: replay protection — first cell is accepted ───────────────────────

    #[test]
    fn i3_replay_first_accepted() {
        use crate::circuit_builder::CircuitId;
        use crate::onion_cell_protocol::{OnionCell, OnionCellType, encode_cell};
        use crate::protocol_runtime::ProtocolEvent;

        let mut rt = ProtocolRuntime::new();
        let bytes = encode_cell(&OnionCell::new(
            CircuitId(100),
            OnionCellType::RelayData,
            vec![1, 2, 3, 4],
        ));
        let action = rt.handle_event(ProtocolEvent::CellReceived(bytes));
        assert_eq!(
            action,
            ProtocolAction::ForwardCell(crate::circuit_builder::CircuitId(100))
        );
    }

    // ── I4: replay protection — duplicate cell is dropped ────────────────────

    #[test]
    fn i4_replay_duplicate_dropped() {
        use crate::circuit_builder::CircuitId;
        use crate::onion_cell_protocol::{OnionCell, OnionCellType, encode_cell};

        let mut rt = ProtocolRuntime::new();
        let bytes = encode_cell(&OnionCell::new(
            CircuitId(101),
            OnionCellType::RelayData,
            vec![5, 6, 7, 8],
        ));
        rt.handle_event(ProtocolEvent::CellReceived(bytes.clone()));
        let action = rt.handle_event(ProtocolEvent::CellReceived(bytes));
        assert_eq!(action, ProtocolAction::DropCell);
    }

    // ── I5: CellEncoder output is always CELL_SIZE (1450) bytes ──────────────

    #[test]
    fn i5_cell_encoder_output_size() {
        let frame = make_stream_frame(1, 1, 200);
        let payload = vec![0xaau8; 200];
        let cell = encode_to_cell(frame, &payload);
        assert_cell_size(&cell);
        assert_eq!(CELL_SIZE, 1450);
    }

    // ── I6: NoiseLink output is always ENCRYPTED_CELL_SIZE (1482) bytes ──────

    #[test]
    fn i6_noiselink_output_size() {
        assert_encrypted_cell_wire_size();

        let frame = make_stream_frame(2, 2, 200);
        let payload = vec![0xbbu8; 200];
        let cell = encode_to_cell(frame, &payload);
        let enc = encrypt_cell(cell, noise_session());

        // Verify each field's contribution to the wire size.
        assert_eq!(enc.ciphertext.len(), CELL_SIZE);
        assert_eq!(enc.auth_tag.len(), 16);
        // path_id(8) + nonce(8) + ciphertext(1450) + auth_tag(16)
        assert_eq!(
            8 + 8 + enc.ciphertext.len() + enc.auth_tag.len(),
            ENCRYPTED_CELL_SIZE
        );
    }

    // ── I7: OnionLayer output constant is ONION_PACKET_SIZE (1507) bytes ─────

    #[test]
    fn i7_onion_layer_output_size() {
        assert_onion_packet_wire_size();
        assert_onion_packet_formula();

        let frame = make_stream_frame(3, 3, 200);
        let payload = vec![0xccu8; 200];
        let cell = encode_to_cell(frame, &payload);
        let enc = encrypt_cell(cell, noise_session());
        let keys = onion_keys(3);
        let packet = wrap_onion(&enc, &keys);

        // payload field must be ENCRYPTED_CELL_SIZE bytes.
        assert_eq!(packet.payload.len(), ENCRYPTED_CELL_SIZE);
        // outer_auth must be 16 bytes.
        assert_eq!(packet.outer_auth.len(), 16);
        // Validate the constant formula.
        assert_eq!(ONION_PACKET_SIZE, 1 + 8 + ENCRYPTED_CELL_SIZE + 16);
    }

    // ── I8: MeshRouter forward is deterministic ───────────────────────────────

    #[test]
    fn i8_mesh_router_deterministic() {
        use crate::noise_link::EncryptedCell;

        let build_router = || {
            let mut table = RoutingTable::new();
            table
                .add_route(Route {
                    route_id: RouteId(1),
                    next_hop: socket_peer(7001),
                    hop_count: 1,
                    latency_estimate: 100,
                    reliability_score: 0.95,
                })
                .unwrap();
            MeshRouter::new(table)
        };

        let dummy_cell = EncryptedCell {
            path_id: 0,
            nonce: 0,
            ciphertext: [0u8; CELL_SIZE],
            auth_tag: [0u8; 16],
        };

        let r1 = build_router();
        let r2 = build_router();

        let hop1 = r1.forward(&dummy_cell, RouteId(1)).unwrap();
        let hop2 = r2.forward(&dummy_cell, RouteId(1)).unwrap();
        assert_eq!(hop1, hop2, "same route must always yield same next-hop");
    }

    // ── I9: full outbound path produces constant-size packets at each stage ───

    #[test]
    fn i9_full_outbound_path_constant_size() {
        // StreamFrame → Cell(1450) → EncryptedCell(1482) → OnionPacket(payload=1482).
        let frame = make_stream_frame(4, 4, 128);
        let payload = vec![0xddu8; 128];

        let cell = encode_to_cell(frame, &payload);
        assert_eq!(cell.as_bytes().len(), CELL_SIZE, "stage 1: Cell = 1450");

        let enc = encrypt_cell(cell, noise_session());
        assert_eq!(
            enc.ciphertext.len(),
            CELL_SIZE,
            "stage 2: ciphertext = 1450"
        );

        let keys = onion_keys(3);
        let packet = wrap_onion(&enc, &keys);
        assert_eq!(
            packet.payload.len(),
            ENCRYPTED_CELL_SIZE,
            "stage 3: payload = 1482"
        );
    }

    // ── I10: payload is never inspected at any layer ──────────────────────────

    #[test]
    fn i10_payload_never_inspected() {
        // All-zero and all-ones payloads must produce the same structural output
        // (only the ciphertext and tag differ — but sizes are identical).
        let frame_a = make_stream_frame(10, 10, 64);
        let frame_b = make_stream_frame(10, 10, 64);
        let zeros = vec![0x00u8; 64];
        let ones = vec![0xffu8; 64];

        let cell_a = encode_to_cell(frame_a, &zeros);
        let cell_b = encode_to_cell(frame_b, &ones);

        // Both cells are the same size regardless of payload content.
        assert_eq!(cell_a.as_bytes().len(), cell_b.as_bytes().len());

        // After encryption, the encrypted cell sizes are identical.
        let enc_a = encrypt_cell(cell_a, noise_session());
        let enc_b = encrypt_cell(cell_b, noise_session());
        assert_eq!(enc_a.ciphertext.len(), enc_b.ciphertext.len());

        // MeshRouter never reads the payload — forwarding with different cells
        // returns the same routing decision.
        let mut table = RoutingTable::new();
        table
            .add_route(Route {
                route_id: RouteId(99),
                next_hop: socket_peer(8888),
                hop_count: 1,
                latency_estimate: 50,
                reliability_score: 0.99,
            })
            .unwrap();
        let router = MeshRouter::new(table);

        let hop_a = router.forward(&enc_a, RouteId(99)).unwrap();
        let hop_b = router.forward(&enc_b, RouteId(99)).unwrap();
        assert_eq!(hop_a, hop_b, "routing must not depend on payload content");
    }

    // ── I_relay: protocol runtime relay flow ──────────────────────────────────

    #[test]
    fn i_relay_full_handshake_flow() {
        let mut rt = ProtocolRuntime::new();

        let desc = RelayDescriptor {
            relay_id: RelayNodeId(1),
            public_key: [0u8; 32],
            peer_address: socket_peer(9100),
            reliability_score: 0.9,
            latency_estimate: 100,
            capabilities: RelayCapabilities {
                supports_onion: true,
                supports_cover: true,
                supports_rotation: true,
                supports_fragmentation: true,
            },
        };

        let action = rt.handle_event(ProtocolEvent::RelayConnected(desc));
        assert_eq!(action, ProtocolAction::NotifyRelay(RelayNodeId(1)));
        assert_eq!(rt.state().active_relays, 1);

        let action = rt.handle_event(ProtocolEvent::RelayHandshakeComplete(RelayNodeId(1)));
        assert_eq!(action, ProtocolAction::NotifyRelay(RelayNodeId(1)));
    }

    // ── I_circuit: circuit creation → extension → destruction ────────────────

    #[test]
    fn i_circuit_lifecycle() {
        use crate::circuit_builder::CircuitId;

        let mut rt = ProtocolRuntime::new();

        let action = rt.handle_event(ProtocolEvent::CircuitCreated(CircuitId(500)));
        assert_eq!(action, ProtocolAction::NoAction);
        assert_eq!(rt.state().active_circuits, 1);

        let action = rt.handle_event(ProtocolEvent::CircuitExtended(
            CircuitId(500),
            RelayNodeId(10),
        ));
        assert_eq!(action, ProtocolAction::NoAction);

        let action = rt.handle_event(ProtocolEvent::CircuitDestroyed(CircuitId(500)));
        assert_eq!(action, ProtocolAction::DestroyCircuit(CircuitId(500)));
        assert_eq!(rt.state().active_circuits, 0);
    }
}
