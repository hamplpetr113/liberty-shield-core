//! Packet flow engine — explicit inbound and outbound packet processing pipelines.
//!
//! **Inbound path:**
//! raw datagram → frame decode → session lookup → link decrypt → onion cell decode → relay decision
//!
//! **Outbound path:**
//! onion cell → link encrypt → frame encode → `SendIntent`
//!
//! ## Wire format for link frames (within a mesh frame payload)
//! ```text
//! [8 bytes: sequence u64 LE]
//! [32 bytes: auth_tag]
//! [N bytes: encrypted payload]
//! ```
//!
//! NON-PRODUCTION: link crypto is HMAC-SHA256 only (no confidentiality).

use std::collections::HashMap;

use crate::link_crypto_v2::{LinkCryptoError, LinkFrame, LinkSession};
use crate::mesh_packet_framer::{FrameError, MeshPacketFramer};
use crate::onion_cell_v2::{CELL_SIZE, OnionCellV2};
use crate::onion_relay_runtime::{DropReason as RelayDropReason, OnionRelayRuntime, RouteDecision};
use crate::outbound_send_queue::{OutboundSendQueue, OverflowPolicy, QueuedPacket};
use crate::policy_engine::{PolicyAction, PolicyEngine, PolicyRequest};

// ---------------------------------------------------------------------------
// SendIntent
// ---------------------------------------------------------------------------

/// Represents one UDP datagram that the runtime should send.
#[derive(Debug, Clone)]
pub struct SendIntent {
    /// Destination peer node ID.
    pub peer_id: [u8; 32],
    /// Fully encoded wire bytes (framed + link-encrypted).
    pub wire_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// PacketFlowResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketFlowResult {
    /// Cell should be forwarded to `next_hop`.
    RelayedTo { circuit_id: u64, next_hop: [u8; 32] },
    /// Cell is for this node (exit or local stream).
    DeliveredLocal { circuit_id: u64 },
    /// Cell was dropped.
    Dropped(FlowDropReason),
}

// ---------------------------------------------------------------------------
// FlowDropReason
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDropReason {
    /// No link session is registered for the sending peer.
    NoSession,
    /// Link-layer authentication tag mismatch.
    AuthFailed,
    /// Link-layer sequence replay detected.
    LinkReplay,
    /// Frame header was malformed or too short.
    MalformedFrame,
    /// Decrypted payload was not a valid onion cell.
    MalformedCell,
    /// Relay has no circuit with this ID.
    UnknownCircuit,
    /// Relay-layer sequence replay detected.
    CellReplay,
    /// Policy engine denied the packet.
    PolicyDenied,
    /// Next hop would be this node (loop).
    LoopDetected,
    /// Send session requires a rekey before more traffic.
    RekeyRequired,
}

// ---------------------------------------------------------------------------
// PacketFlowEngine
// ---------------------------------------------------------------------------

pub struct PacketFlowEngine {
    framer: MeshPacketFramer,
    /// Receive-direction link sessions keyed by sender peer ID.
    recv_sessions: HashMap<[u8; 32], LinkSession>,
    /// Send-direction link sessions keyed by recipient peer ID.
    send_sessions: HashMap<[u8; 32], LinkSession>,
    relay: OnionRelayRuntime,
    policy: PolicyEngine,
    /// Outbound queue for packets pending delivery to the network layer.
    outbound_queue: OutboundSendQueue,
    inbound_count: u64,
    outbound_count: u64,
    drop_count: u64,
}

impl PacketFlowEngine {
    /// Default outbound queue capacity.
    pub const DEFAULT_QUEUE_CAPACITY: usize = 256;

    pub fn new(local_id: [u8; 32]) -> Self {
        Self {
            framer: MeshPacketFramer::new(),
            recv_sessions: HashMap::new(),
            send_sessions: HashMap::new(),
            relay: OnionRelayRuntime::new(local_id),
            policy: PolicyEngine::new(),
            outbound_queue: OutboundSendQueue::new(
                Self::DEFAULT_QUEUE_CAPACITY,
                OverflowPolicy::DropOldest,
            ),
            inbound_count: 0,
            outbound_count: 0,
            drop_count: 0,
        }
    }

    /// Register symmetric link sessions for a peer.
    /// `send_key` / `send_recv_key` are used when we SEND to `peer_id`.
    /// `recv_key` / `recv_recv_key` are used when we RECEIVE from `peer_id`.
    pub fn register_peer_session(
        &mut self,
        peer_id: [u8; 32],
        send_key: [u8; 32],
        recv_key: [u8; 32],
    ) {
        self.send_sessions
            .insert(peer_id, LinkSession::new(send_key, recv_key, 0));
        self.recv_sessions
            .insert(peer_id, LinkSession::new(recv_key, send_key, 0));
    }

    // -----------------------------------------------------------------------
    // Inbound path
    // -----------------------------------------------------------------------

    /// Process one inbound datagram arriving from `from_peer`.
    ///
    /// Full pipeline: frame decode → policy gate → session lookup → link decrypt
    /// → onion cell parse → relay decision.
    pub fn process_inbound(&mut self, from_peer: [u8; 32], wire_bytes: &[u8]) -> PacketFlowResult {
        self.inbound_count += 1;

        // 1. Policy gate (peer admission).
        let policy_req = PolicyRequest::PeerAdmission {
            node_id: from_peer,
            trust_score: 0.5,
        };
        if self.policy.evaluate(&policy_req) == PolicyAction::Deny {
            self.drop_count += 1;
            return PacketFlowResult::Dropped(FlowDropReason::PolicyDenied);
        }

        // 2. Frame decode: strip length prefix.
        let inner = match self.framer.decode(wire_bytes) {
            Ok((payload, _)) => payload.to_vec(),
            Err(FrameError::Truncated | FrameError::ZeroLength | FrameError::TooLarge) => {
                self.drop_count += 1;
                return PacketFlowResult::Dropped(FlowDropReason::MalformedFrame);
            }
        };

        // 3. Deserialize LinkFrame: [8 seq][32 tag][payload]
        if inner.len() < 40 {
            self.drop_count += 1;
            return PacketFlowResult::Dropped(FlowDropReason::MalformedFrame);
        }
        let sequence = u64::from_le_bytes(inner[..8].try_into().unwrap());
        let auth_tag: [u8; 32] = inner[8..40].try_into().unwrap();
        let payload = inner[40..].to_vec();
        let link_frame = LinkFrame {
            sequence,
            payload,
            auth_tag,
        };

        // 4. Link decrypt.
        let recv_session = match self.recv_sessions.get_mut(&from_peer) {
            Some(s) => s,
            None => {
                self.drop_count += 1;
                return PacketFlowResult::Dropped(FlowDropReason::NoSession);
            }
        };
        let cell_bytes = match recv_session.open(link_frame) {
            Ok(b) => b,
            Err(LinkCryptoError::AuthenticationFailure) => {
                self.drop_count += 1;
                return PacketFlowResult::Dropped(FlowDropReason::AuthFailed);
            }
            Err(LinkCryptoError::ReplayDetected) => {
                self.drop_count += 1;
                return PacketFlowResult::Dropped(FlowDropReason::LinkReplay);
            }
            Err(LinkCryptoError::RekeyRequired) => {
                self.drop_count += 1;
                return PacketFlowResult::Dropped(FlowDropReason::RekeyRequired);
            }
        };

        // 5. Parse onion cell.
        if cell_bytes.len() != CELL_SIZE {
            self.drop_count += 1;
            return PacketFlowResult::Dropped(FlowDropReason::MalformedCell);
        }
        let cell_arr: [u8; CELL_SIZE] = cell_bytes.try_into().unwrap();
        let cell = OnionCellV2::from_bytes(&cell_arr);

        // 6. Relay decision.
        let decision = self.relay.process_inbound_cell(&cell);
        self.map_route_decision(decision)
    }

    /// Feed an already-decoded cell directly into the relay (bypasses link layer).
    /// Used for relay-level replay and policy tests.
    pub fn process_cell_direct(&mut self, cell: &OnionCellV2) -> PacketFlowResult {
        self.inbound_count += 1;
        let decision = self.relay.process_inbound_cell(cell);
        self.map_route_decision(decision)
    }

    fn map_route_decision(&mut self, decision: RouteDecision) -> PacketFlowResult {
        match decision {
            RouteDecision::LocalDelivery => PacketFlowResult::DeliveredLocal { circuit_id: 0 },
            RouteDecision::Forward(next_hop) => PacketFlowResult::RelayedTo {
                circuit_id: 0,
                next_hop,
            },
            RouteDecision::Drop(reason) => {
                self.drop_count += 1;
                PacketFlowResult::Dropped(match reason {
                    RelayDropReason::UnknownCircuit => FlowDropReason::UnknownCircuit,
                    RelayDropReason::ReplayDetected => FlowDropReason::CellReplay,
                    RelayDropReason::PolicyDenied => FlowDropReason::PolicyDenied,
                    RelayDropReason::LoopDetected => FlowDropReason::LoopDetected,
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Outbound path
    // -----------------------------------------------------------------------

    /// Build a `SendIntent` for an onion cell to be sent to `to_peer`.
    ///
    /// Pipeline: cell bytes → link encrypt → frame encode → `SendIntent`.
    pub fn build_send_intent(
        &mut self,
        to_peer: [u8; 32],
        cell: &OnionCellV2,
    ) -> Result<SendIntent, FlowDropReason> {
        // 1. Serialize cell.
        let cell_bytes = cell.to_bytes().to_vec();

        // 2. Link encrypt.
        let send_session = self
            .send_sessions
            .get_mut(&to_peer)
            .ok_or(FlowDropReason::NoSession)?;

        let frame = send_session.seal(cell_bytes).map_err(|e| match e {
            LinkCryptoError::RekeyRequired => FlowDropReason::RekeyRequired,
            _ => FlowDropReason::AuthFailed,
        })?;

        // 3. Serialize LinkFrame: [8 seq][32 tag][payload].
        let mut serialized = Vec::with_capacity(8 + 32 + frame.payload.len());
        serialized.extend_from_slice(&frame.sequence.to_le_bytes());
        serialized.extend_from_slice(&frame.auth_tag);
        serialized.extend_from_slice(&frame.payload);

        // 4. Frame encode.
        let wire_bytes = self
            .framer
            .encode(&serialized)
            .map_err(|_| FlowDropReason::MalformedFrame)?;

        self.outbound_count += 1;
        Ok(SendIntent {
            peer_id: to_peer,
            wire_bytes,
        })
    }

    /// Build a `SendIntent` and immediately enqueue it in the outbound queue.
    /// Returns `Ok(())` on success; errors from `build_send_intent` propagate.
    pub fn enqueue_send_intent(
        &mut self,
        to_peer: [u8; 32],
        cell: &OnionCellV2,
    ) -> Result<(), FlowDropReason> {
        let intent = self.build_send_intent(to_peer, cell)?;
        let queued = QueuedPacket {
            peer_id: intent.peer_id,
            wire_bytes: intent.wire_bytes,
        };
        // DropOldest policy — overflow is non-fatal; queue silently drops oldest.
        let _ = self.outbound_queue.push(queued);
        Ok(())
    }

    /// Poll one packet from the outbound queue. Returns `None` if empty.
    pub fn poll_outbound(&mut self) -> Option<QueuedPacket> {
        self.outbound_queue.pop().ok()
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn relay_mut(&mut self) -> &mut OnionRelayRuntime {
        &mut self.relay
    }
    pub fn policy_mut(&mut self) -> &mut PolicyEngine {
        &mut self.policy
    }
    pub fn outbound_queue(&self) -> &OutboundSendQueue {
        &self.outbound_queue
    }
    pub fn outbound_queue_mut(&mut self) -> &mut OutboundSendQueue {
        &mut self.outbound_queue
    }
    pub fn inbound_count(&self) -> u64 {
        self.inbound_count
    }
    pub fn outbound_count(&self) -> u64 {
        self.outbound_count
    }
    pub fn drop_count(&self) -> u64 {
        self.drop_count
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, PAYLOAD_SIZE};
    use crate::policy_engine::{PolicyAction, PolicyRule};

    fn lid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn make_cell(circuit_id: u64, seq: u64) -> OnionCellV2 {
        OnionCellV2::new(
            CMD_DATA,
            circuit_id,
            0,
            seq,
            [0u8; PAYLOAD_SIZE],
            &[0u8; 32],
        )
    }

    fn make_engine(local: u8) -> PacketFlowEngine {
        PacketFlowEngine::new(lid(local))
    }

    // PFE1: inbound missing session returns NoSession.
    #[test]
    fn pfe1_inbound_missing_session() {
        let mut engine = make_engine(1);
        // Construct minimal framed bytes (just enough to pass the frame decode).
        let fake_inner = vec![0u8; 50];
        let framed = {
            let len = fake_inner.len() as u32;
            let mut v = len.to_le_bytes().to_vec();
            v.extend_from_slice(&fake_inner);
            v
        };
        let result = engine.process_inbound(lid(9), &framed);
        assert_eq!(result, PacketFlowResult::Dropped(FlowDropReason::NoSession));
    }

    // PFE2: inbound replay rejected at relay layer.
    #[test]
    fn pfe2_inbound_relay_replay() {
        let mut engine = make_engine(2);
        // Register a local-delivery circuit (no next hop).
        engine.relay_mut().register_circuit(42, None);

        let cell = make_cell(42, 0);
        // First: delivered.
        let r1 = engine.process_cell_direct(&cell);
        assert_eq!(r1, PacketFlowResult::DeliveredLocal { circuit_id: 0 });
        // Second: same sequence → replay.
        let r2 = engine.process_cell_direct(&cell);
        assert_eq!(r2, PacketFlowResult::Dropped(FlowDropReason::CellReplay));
    }

    // PFE3: outbound creates non-empty send intent.
    #[test]
    fn pfe3_outbound_send_intent() {
        let mut engine = make_engine(3);
        engine.register_peer_session(lid(9), lid(0xAA), lid(0xBB));

        let cell = make_cell(1, 0);
        let intent = engine.build_send_intent(lid(9), &cell).unwrap();
        assert_eq!(intent.peer_id, lid(9));
        assert!(!intent.wire_bytes.is_empty());
    }

    // PFE4: policy denied packet returns PolicyDenied.
    #[test]
    fn pfe4_policy_denied() {
        let mut engine = make_engine(4);
        // Deny all peers with trust < 1.1 (effectively all).
        engine.policy_mut().add_rule(PolicyRule {
            name: "deny-untrusted".into(),
            action: PolicyAction::Deny,
            min_trust: 1.1,
            denied_classes: Vec::new(),
            max_privacy_mode: 0,
        });

        let fake_inner = vec![0u8; 50];
        let framed = {
            let len = fake_inner.len() as u32;
            let mut v = len.to_le_bytes().to_vec();
            v.extend_from_slice(&fake_inner);
            v
        };
        let result = engine.process_inbound(lid(9), &framed);
        assert_eq!(
            result,
            PacketFlowResult::Dropped(FlowDropReason::PolicyDenied)
        );
    }

    // PFE5: malformed frame (too short) returns MalformedFrame.
    #[test]
    fn pfe5_malformed_frame() {
        let mut engine = make_engine(5);
        let result = engine.process_inbound(lid(9), &[0u8; 2]);
        assert_eq!(
            result,
            PacketFlowResult::Dropped(FlowDropReason::MalformedFrame)
        );
    }

    // PFE6: enqueue_send_intent places item in outbound queue.
    #[test]
    fn pfe6_enqueue_creates_queue_item() {
        let mut engine = make_engine(6);
        engine.register_peer_session(lid(9), lid(0xAA), lid(0xBB));

        let cell = make_cell(1, 0);
        engine.enqueue_send_intent(lid(9), &cell).unwrap();
        assert_eq!(engine.outbound_queue().len(), 1);
    }

    // PFE7: poll_outbound returns enqueued item.
    #[test]
    fn pfe7_poll_returns_item() {
        let mut engine = make_engine(7);
        engine.register_peer_session(lid(9), lid(0xAA), lid(0xBB));

        let cell = make_cell(1, 0);
        engine.enqueue_send_intent(lid(9), &cell).unwrap();
        let pkt = engine.poll_outbound().expect("should have packet");
        assert_eq!(pkt.peer_id, lid(9));
        assert!(!pkt.wire_bytes.is_empty());
    }

    // PFE8: poll_outbound on empty queue returns None.
    #[test]
    fn pfe8_poll_empty_returns_none() {
        let mut engine = make_engine(8);
        assert!(engine.poll_outbound().is_none());
    }

    // PFE9: outbound queue drops oldest on overflow (DropOldest policy).
    #[test]
    fn pfe9_queue_overflow_drops_oldest() {
        let mut engine = make_engine(9);
        engine.register_peer_session(lid(10), lid(0xAA), lid(0xBB));
        // Overfill the queue beyond DEFAULT_QUEUE_CAPACITY.
        for seq in 0u64..PacketFlowEngine::DEFAULT_QUEUE_CAPACITY as u64 + 2 {
            let cell = make_cell(1, seq);
            engine.enqueue_send_intent(lid(10), &cell).unwrap();
        }
        assert_eq!(
            engine.outbound_queue().len(),
            PacketFlowEngine::DEFAULT_QUEUE_CAPACITY
        );
        assert!(engine.outbound_queue().dropped_count() > 0);
    }

    // PFE10: peer destination preserved through enqueue/poll.
    #[test]
    fn pfe10_peer_destination_preserved() {
        let mut engine = make_engine(10);
        engine.register_peer_session(lid(0xAB), lid(0xAA), lid(0xBB));
        let cell = make_cell(5, 0);
        engine.enqueue_send_intent(lid(0xAB), &cell).unwrap();
        let pkt = engine.poll_outbound().unwrap();
        assert_eq!(pkt.peer_id, lid(0xAB));
    }
}
