#[cfg(test)]
mod transport_invariants {
    use crate::cell_encoder::{CELL_SIZE, MAX_PAYLOAD};
    use crate::noise_link::ENCRYPTED_CELL_SIZE;
    use crate::onion_layer::ONION_PACKET_SIZE;

    #[test]
    fn cell_size_constant() {
        assert_eq!(CELL_SIZE, 1450);
    }

    #[test]
    fn encrypted_cell_size_constant() {
        assert_eq!(ENCRYPTED_CELL_SIZE, 1482);
    }

    #[test]
    fn onion_packet_size_constant() {
        assert_eq!(ONION_PACKET_SIZE, 1507);
    }

    #[test]
    fn encrypted_cell_size_formula() {
        // path_id(8) + nonce(8) + ciphertext(CELL_SIZE) + auth_tag(16)
        assert_eq!(ENCRYPTED_CELL_SIZE, 8 + 8 + CELL_SIZE + 16);
    }

    #[test]
    fn onion_packet_size_formula() {
        // layer_count(1) + nonce(8) + payload(ENCRYPTED_CELL_SIZE) + outer_auth(16)
        assert_eq!(ONION_PACKET_SIZE, 1 + 8 + ENCRYPTED_CELL_SIZE + 16);
    }

    #[test]
    fn wire_size_matches_encrypted_cell_size() {
        assert_eq!(ENCRYPTED_CELL_SIZE, 1482);
        assert_eq!(ONION_PACKET_SIZE, 1507);
    }

    #[test]
    fn max_payload_does_not_exceed_cell() {
        assert!(MAX_PAYLOAD < CELL_SIZE);
        assert_eq!(MAX_PAYLOAD, CELL_SIZE - 43); // 43-byte header
    }

    #[test]
    fn payload_len_zero_cell_still_fills_cell_size() {
        use crate::cell_encoder::CellEncoder;
        use crate::runtime_boundary::{
            ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef,
            RuntimeBoundaryValidator, RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
        };
        use crate::stream_mux::StreamMux;
        use std::collections::HashSet;

        // Build a frame with the minimum valid payload_ref size (64).
        let mut paths = HashSet::new();
        paths.insert(1u64);
        let v =
            RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
        let mut budget = ShadowBudgetTracker::new(1_000_000);
        let out = ControlledChaosOutput {
            path_id: 1,
            flow_id: 1,
            fragment_id: 1,
            scheduled_send_time: 0,
            shadow_flag: false,
            packet_class: PacketClass::Real,
            latency_deadline: u64::MAX,
            payload_ref: PayloadRef::new(1, 64).unwrap(),
        };
        let intent = match v.validate(out, 0, &mut budget) {
            RuntimeValidationResult::Accept(i) => i,
            RuntimeValidationResult::Reject(r) => panic!("{r:?}"),
        };
        let mut mux = StreamMux::with_defaults();
        mux.submit(intent, 0).unwrap();
        let (mut frames, _) = mux.drain_ready(u64::MAX);
        let frame = frames.remove(0);

        let mut enc = CellEncoder::new(0);
        let cell = enc.encode(frame, &[0u8; 64]).unwrap();
        assert_eq!(cell.as_bytes().len(), CELL_SIZE);
    }
}

#[cfg(test)]
mod routing_invariants {
    use crate::circuit_builder::{CircuitBuilder, CircuitId};
    use crate::circuit_runtime::CircuitRuntime;

    fn circuit_nodes(count: usize) -> Vec<crate::circuit_builder::NodeDescriptor> {
        use crate::circuit_builder::{NodeDescriptor, NodeId};
        use crate::udp_transport::PeerAddress;
        use std::net::SocketAddr;

        (1..=(count as u64))
            .map(|id| NodeDescriptor {
                node_id: NodeId(id),
                public_key: [id as u8; 32],
                peer_address: PeerAddress::new(
                    format!("127.0.0.1:{}", 9000 + id as u16)
                        .parse::<SocketAddr>()
                        .unwrap(),
                ),
                latency_estimate: 100,
                reliability_score: 0.95,
            })
            .collect()
    }

    #[test]
    fn no_duplicate_hops_in_circuit() {
        let nodes = circuit_nodes(5);
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        // Hop node IDs must be unique (builder enforces this via duplicate check).
        let ids: Vec<u64> = circuit.hops.iter().map(|n| n.node_id.0).collect();
        let unique: std::collections::HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "circuit hops must not revisit a node"
        );
    }

    #[test]
    fn closed_circuit_rejects_send() {
        use crate::cell_encoder::CELL_SIZE;
        use crate::noise_link::EncryptedCell;

        let nodes = circuit_nodes(3);
        let circuit = CircuitBuilder::build_circuit(&nodes, 3).unwrap();
        let circuit_id = circuit.circuit_id;

        let mut rt = CircuitRuntime::new();
        rt.register_circuit(circuit, 0).unwrap();
        rt.close_circuit(circuit_id).unwrap();

        let enc = EncryptedCell {
            path_id: 0,
            nonce: 0,
            ciphertext: [0u8; CELL_SIZE],
            auth_tag: [0u8; 16],
        };
        let result = rt.send_cell(circuit_id, &enc);
        assert!(
            result.is_err(),
            "send_cell on closed circuit must return error"
        );
    }

    #[test]
    fn destroyed_extension_cannot_extend() {
        use crate::protocol_runtime::{CircuitRuntimeAdapter, ProtocolRuntimeError};
        use crate::relay_protocol::RelayNodeId;

        let mut ca = CircuitRuntimeAdapter::new();
        ca.create_circuit(CircuitId(999)).unwrap();
        ca.destroy_circuit(CircuitId(999)).unwrap();
        let err = ca
            .extend_circuit(CircuitId(999), RelayNodeId(1))
            .unwrap_err();
        assert_eq!(err, ProtocolRuntimeError::InvalidState);
    }

    #[test]
    fn guard_list_has_no_duplicates() {
        use crate::guard_selection::{GuardPolicy, GuardSelector};
        use crate::node_discovery::{DiscoveryNodeId, NodeDescriptor};
        use crate::udp_transport::PeerAddress;
        use std::collections::HashSet;
        use std::net::SocketAddr;

        let nodes: Vec<NodeDescriptor> = (1u64..=5)
            .map(|id| NodeDescriptor {
                node_id: DiscoveryNodeId(id),
                public_key: [id as u8; 32],
                peer_address: PeerAddress::new(
                    format!("127.0.0.1:{}", 9000 + id as u16)
                        .parse::<SocketAddr>()
                        .unwrap(),
                ),
                latency_estimate: 100,
                reliability_score: 0.95,
                last_seen_timestamp: 1_000,
            })
            .collect();

        let policy = GuardPolicy {
            min_guards: 3,
            max_guards: 5,
            max_latency: 500_000,
            min_reliability: 0.5,
            max_failure_count: 10,
            stability_window: 3600,
        };
        let guards = GuardSelector::select_initial_guards(&nodes, &policy, 3).unwrap();
        let ids: Vec<u64> = guards.list_guards().iter().map(|g| g.node_id.0).collect();
        let unique: HashSet<u64> = ids.iter().copied().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "guard list must not contain duplicates"
        );
    }
}

#[cfg(test)]
mod security_invariants {
    use crate::circuit_builder::CircuitId;
    use crate::onion_cell_protocol::{OnionCell, OnionCellType, encode_cell};
    use crate::protocol_runtime::{ProtocolAction, ProtocolEvent, ProtocolRuntime};

    #[test]
    fn replay_rejects_duplicate_cell() {
        let mut rt = ProtocolRuntime::new();
        let bytes = encode_cell(&OnionCell::new(
            CircuitId(1000),
            OnionCellType::RelayData,
            vec![0xde, 0xad, 0xbe, 0xef],
        ));
        let first = rt.handle_event(ProtocolEvent::CellReceived(bytes.clone()));
        assert_eq!(
            first,
            ProtocolAction::ForwardCell(CircuitId(1000)),
            "first cell must be forwarded"
        );
        let second = rt.handle_event(ProtocolEvent::CellReceived(bytes));
        assert_eq!(
            second,
            ProtocolAction::DropCell,
            "duplicate cell must be dropped"
        );
    }

    #[test]
    fn wrong_noiselink_key_fails_decode() {
        use crate::cell_encoder::CELL_SIZE;
        use crate::cell_encoder::Cell;
        use crate::noise_link::{NoiseLinkEncoder, NoiseSession};

        let send_key = [0x11u8; 32];
        let recv_key = [0xAAu8; 32]; // wrong key
        let mut sender = NoiseLinkEncoder::new(NoiseSession::new(send_key, send_key));

        let cell = Cell::from_raw([0u8; CELL_SIZE]);
        let enc = sender.encode(cell);

        let mut receiver = NoiseLinkEncoder::new(NoiseSession::new(recv_key, recv_key));
        assert!(
            receiver.decode(enc).is_err(),
            "wrong recv key must cause authentication failure"
        );
    }

    #[test]
    fn wrong_onion_key_fails_peel() {
        use crate::cell_encoder::CELL_SIZE;
        use crate::noise_link::EncryptedCell;
        use crate::onion_layer::{LayerDecryptor, LayerEncryptor, OnionLayerKey};

        let correct_key = OnionLayerKey {
            bytes: [0x22u8; 32],
        };
        let wrong_key = OnionLayerKey {
            bytes: [0x33u8; 32],
        };

        let cell = EncryptedCell {
            path_id: 1,
            nonce: 0,
            ciphertext: [0u8; CELL_SIZE],
            auth_tag: [0u8; 16],
        };
        let packet = LayerEncryptor::wrap(&cell, &[correct_key]).unwrap();
        assert!(
            LayerDecryptor::peel(packet, &wrong_key).is_err(),
            "wrong onion key must fail peel"
        );
    }

    #[test]
    fn runtime_boundary_rejects_invalid_path() {
        use crate::runtime_boundary::{
            ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef,
            RuntimeBoundaryValidator, ShadowBudgetTracker, TunnelState,
        };
        use std::collections::HashSet;

        // Validator registered with path_id=1 only.
        let mut paths = HashSet::new();
        paths.insert(1u64);
        let v =
            RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
        let mut budget = ShadowBudgetTracker::new(1_000_000);

        // Submit an output with path_id=99 — not registered.
        let out = ControlledChaosOutput {
            path_id: 99,
            flow_id: 1,
            fragment_id: 1,
            scheduled_send_time: 0,
            shadow_flag: false,
            packet_class: PacketClass::Real,
            latency_deadline: u64::MAX,
            payload_ref: PayloadRef::new(1, 100).unwrap(),
        };
        let result = v.validate(out, 0, &mut budget);
        assert!(
            result.is_rejected(),
            "unknown path_id must be rejected by RuntimeBoundaryValidator"
        );
    }

    #[test]
    fn stream_mux_only_accepts_runtime_packet_intent() {
        // `StreamMux::submit` accepts only `RuntimePacketIntent` — a type whose
        // constructor is `pub(in crate::runtime_boundary)`.  The only way to
        // produce one is through `RuntimeBoundaryValidator::validate`, so this
        // test verifies the pipeline compiles and runs correctly.
        use crate::runtime_boundary::{
            ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef,
            RuntimeBoundaryValidator, RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
        };
        use crate::stream_mux::StreamMux;
        use std::collections::HashSet;

        let mut paths = HashSet::new();
        paths.insert(1u64);
        let v =
            RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
        let mut budget = ShadowBudgetTracker::new(1_000_000);
        let out = ControlledChaosOutput {
            path_id: 1,
            flow_id: 5,
            fragment_id: 5,
            scheduled_send_time: 0,
            shadow_flag: false,
            packet_class: PacketClass::Real,
            latency_deadline: u64::MAX,
            payload_ref: PayloadRef::new(5, 100).unwrap(),
        };
        let intent = match v.validate(out, 0, &mut budget) {
            RuntimeValidationResult::Accept(i) => i,
            RuntimeValidationResult::Reject(r) => panic!("{r:?}"),
        };
        let mut mux = StreamMux::with_defaults();
        assert!(
            mux.submit(intent, 0).is_ok(),
            "valid RuntimePacketIntent must be accepted by StreamMux"
        );
    }
}
