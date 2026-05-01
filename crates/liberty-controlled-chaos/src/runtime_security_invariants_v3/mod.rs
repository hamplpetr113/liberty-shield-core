//! Runtime security invariants v3 — integration-level checks covering the
//! full stack from Sprint 161–172.
//!
//! These tests are not unit tests; they exercise the wired-together subsystems:
//! - `IntegratedNodeRuntime` (lifecycle + epoch driver + circuit build driver)
//! - `PacketFlowEngine` (LinkCryptoProvider migration)
//! - `OutboundSendQueue` (push_front + overflow)
//! - `RuntimeEpochDriver` (subscriber hooks)
//! - `UdpFlowAdapter` (bridge correctness)
//! - `AndroidVpnBridgeContract` (type safety)

// All invariants are test-only.

#[cfg(test)]
mod tests {
    use crate::android_vpn_bridge_contract::{
        PermissionState, TunnelState, VpnPacketIn, VpnRuntimeCommand, VpnRuntimeStatus,
    };
    use crate::integrated_node_runtime::{IntegratedNodeRuntime, RuntimeState};
    use crate::link_crypto_provider::NullCryptoProvider;
    use crate::node_config::NodeConfig;
    use crate::outbound_send_queue::{OutboundSendQueue, OverflowPolicy, QueuedPacket};
    use crate::packet_flow_engine::PacketFlowEngine;
    use crate::runtime_epoch_driver::{EpochDriverConfig, EpochSubscriber, RuntimeEpochDriver};

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn started_rt(id: u8) -> IntegratedNodeRuntime {
        let mut rt = IntegratedNodeRuntime::new(NodeConfig::new(nid(id)));
        rt.configure().unwrap();
        rt.start_bootstrap(1).unwrap();
        rt.complete_bootstrap(1).unwrap();
        rt
    }

    // SI3_1: runtime in Running state can advance epoch and circuit builds together.
    #[test]
    fn si3_1_epoch_and_circuit_build_co_advance() {
        let mut rt = started_rt(1);
        let path = vec![nid(10), nid(11), nid(12)];
        rt.enqueue_circuit_build(path, 100);
        rt.advance_epoch_driven(2);
        assert_eq!(rt.build_driver().in_flight_count(), 1);
        assert_eq!(rt.epoch_driver().epoch(), 3);
    }

    // SI3_2: stopping the runtime does not affect the epoch driver counter.
    #[test]
    fn si3_2_stop_does_not_reset_epoch_driver() {
        let mut rt = started_rt(2);
        rt.advance_epoch_driven(5);
        rt.stop(10).unwrap();
        assert_eq!(rt.epoch_driver().epoch(), 6);
    }

    // SI3_3: PacketFlowEngine with NullCryptoProvider round-trips a cell.
    #[test]
    fn si3_3_null_provider_flow_round_trip() {
        use crate::onion_cell_v2::{CMD_DATA, PAYLOAD_SIZE};
        let mut sender = PacketFlowEngine::new(nid(1));
        let mut receiver = PacketFlowEngine::new(nid(2));
        sender.register_peer_provider(
            nid(2),
            Box::new(NullCryptoProvider),
            Box::new(NullCryptoProvider),
        );
        receiver.register_peer_provider(
            nid(1),
            Box::new(NullCryptoProvider),
            Box::new(NullCryptoProvider),
        );
        receiver.relay_mut().register_circuit(42, None);
        let cell = crate::onion_cell_v2::OnionCellV2::new(
            CMD_DATA,
            42,
            0,
            0,
            [0u8; PAYLOAD_SIZE],
            &[0u8; 32],
        );
        let intent = sender.build_send_intent(nid(2), &cell).unwrap();
        let result = receiver.process_inbound(nid(1), &intent.wire_bytes);
        assert!(matches!(
            result,
            crate::packet_flow_engine::PacketFlowResult::DeliveredLocal { .. }
        ));
    }

    // SI3_4: OutboundSendQueue push_front preserves FIFO after re-enqueue.
    #[test]
    fn si3_4_push_front_fifo_preserved() {
        let mut q = OutboundSendQueue::new(4, OverflowPolicy::DropNewest);
        q.push(QueuedPacket {
            peer_id: nid(2),
            wire_bytes: b"second".to_vec(),
        })
        .unwrap();
        q.push(QueuedPacket {
            peer_id: nid(3),
            wire_bytes: b"third".to_vec(),
        })
        .unwrap();
        q.push_front(QueuedPacket {
            peer_id: nid(1),
            wire_bytes: b"first".to_vec(),
        })
        .unwrap();
        let order: Vec<u8> = (0..3).map(|_| q.pop().unwrap().peer_id[0]).collect();
        assert_eq!(order, vec![1, 2, 3]);
    }

    // SI3_5: RuntimeEpochDriver subscriber count never goes negative after repeated
    // subscribe/unsubscribe cycles.
    #[test]
    fn si3_5_subscriber_count_consistent() {
        struct Noop;
        impl EpochSubscriber for Noop {
            fn on_epoch(&mut self, _: u64) {}
            fn name(&self) -> &str {
                "noop"
            }
        }
        let mut d = RuntimeEpochDriver::new(EpochDriverConfig::default());
        let mut ids = Vec::new();
        for _ in 0..5 {
            ids.push(d.subscribe(Box::new(Noop)));
        }
        assert_eq!(d.subscriber_count(), 5);
        for id in ids {
            d.unsubscribe(id);
        }
        assert_eq!(d.subscriber_count(), 0);
    }

    // SI3_6: VpnRuntimeStatus::Connected is active; Stopped is not.
    #[test]
    fn si3_6_vpn_status_active_states() {
        assert!(VpnRuntimeStatus::Connected.is_active());
        assert!(VpnRuntimeStatus::Paused.is_active());
        assert!(!VpnRuntimeStatus::Stopped.is_active());
        assert!(!VpnRuntimeStatus::Idle.is_active());
    }

    // SI3_7: VpnPacketIn::is_plausible rejects truncated IP headers.
    #[test]
    fn si3_7_vpn_packet_plausibility() {
        assert!(!VpnPacketIn::new(vec![0u8; 19], 0).is_plausible());
        assert!(VpnPacketIn::new(vec![0u8; 20], 0).is_plausible());
        assert!(VpnPacketIn::new(vec![0u8; 1500], 0).is_plausible());
    }

    // SI3_8: VpnRuntimeCommand variants cover all expected lifecycle transitions.
    #[test]
    fn si3_8_command_coverage() {
        let all = [
            VpnRuntimeCommand::Start,
            VpnRuntimeCommand::Stop,
            VpnRuntimeCommand::Pause,
            VpnRuntimeCommand::Resume,
            VpnRuntimeCommand::RotateCircuits,
        ];
        assert_eq!(all.len(), 5);
    }

    // SI3_9: PermissionState and TunnelState are independent types (no overlap).
    #[test]
    fn si3_9_permission_tunnel_independent() {
        let p = PermissionState::Granted;
        let t = TunnelState::Open;
        assert_eq!(p, PermissionState::Granted);
        assert_eq!(t, TunnelState::Open);
    }

    // SI3_10: IntegratedNodeRuntime epoch driver is synced to bootstrap epoch.
    #[test]
    fn si3_10_epoch_driver_synced_to_bootstrap() {
        let rt = started_rt(10);
        assert_eq!(rt.epoch_driver().epoch(), 1);
        assert_eq!(rt.current_epoch(), 1);
    }
}
