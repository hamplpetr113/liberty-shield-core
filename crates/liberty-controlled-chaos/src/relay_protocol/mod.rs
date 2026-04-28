//! RelayProtocol — relay connection state machine and handshake types.
//!
//! No network I/O; no randomness; all state is caller-driven.

mod errors;
mod types;

pub use errors::RelayProtocolError;
pub use types::{
    RelayCapabilities, RelayConnectionState, RelayDescriptor, RelayHandshakeRequest,
    RelayHandshakeResponse, RelayNodeId, RelayProtocolHandler,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::udp_transport::PeerAddress;

    use super::*;

    fn addr() -> PeerAddress {
        PeerAddress::new("127.0.0.1:9000".parse::<SocketAddr>().unwrap())
    }

    fn full_caps() -> RelayCapabilities {
        RelayCapabilities {
            supports_onion: true,
            supports_cover: true,
            supports_rotation: true,
            supports_fragmentation: true,
        }
    }

    fn partial_caps() -> RelayCapabilities {
        RelayCapabilities {
            supports_onion: true,
            supports_cover: false,
            supports_rotation: false,
            supports_fragmentation: false,
        }
    }

    fn descriptor(id: u64, caps: RelayCapabilities) -> RelayDescriptor {
        RelayDescriptor {
            relay_id: RelayNodeId(id),
            public_key: [0u8; 32],
            peer_address: addr(),
            reliability_score: 0.95,
            latency_estimate: 50,
            capabilities: caps,
        }
    }

    fn response(id: u64, accepted: bool, caps: RelayCapabilities) -> RelayHandshakeResponse {
        RelayHandshakeResponse {
            relay_id: RelayNodeId(id),
            relay_pubkey: [1u8; 32],
            accepted,
            negotiated_capabilities: caps,
        }
    }

    // ── rp1: handshake accept ─────────────────────────────────────────────────

    #[test]
    fn rp1_handshake_accept() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(1, full_caps())).unwrap();
        h.begin_handshake(RelayNodeId(1), [0u8; 32], full_caps())
            .unwrap();
        h.complete_handshake(RelayNodeId(1), response(1, true, full_caps()))
            .unwrap();
        assert_eq!(
            h.get_state(RelayNodeId(1)),
            Some(RelayConnectionState::Established)
        );
    }

    // ── rp2: handshake reject ─────────────────────────────────────────────────

    #[test]
    fn rp2_handshake_reject() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(2, full_caps())).unwrap();
        h.begin_handshake(RelayNodeId(2), [0u8; 32], full_caps())
            .unwrap();
        let err = h
            .complete_handshake(RelayNodeId(2), response(2, false, full_caps()))
            .unwrap_err();
        assert_eq!(err, RelayProtocolError::HandshakeRejected);
    }

    // ── rp3: capability mismatch ──────────────────────────────────────────────

    #[test]
    fn rp3_capability_mismatch() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(3, full_caps())).unwrap();
        // Request full caps, but relay returns only partial negotiated caps
        // while claiming accepted=true — this is a protocol violation.
        h.begin_handshake(RelayNodeId(3), [0u8; 32], full_caps())
            .unwrap();
        let err = h
            .complete_handshake(
                RelayNodeId(3),
                response(3, true, partial_caps()), // accepted but missing caps
            )
            .unwrap_err();
        assert_eq!(err, RelayProtocolError::CapabilityMismatch);
    }

    // ── rp4: state transition Init → Handshaking → Established → Closed ──────

    #[test]
    fn rp4_state_transition() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(4, full_caps())).unwrap();
        assert_eq!(
            h.get_state(RelayNodeId(4)),
            Some(RelayConnectionState::Init)
        );

        h.begin_handshake(RelayNodeId(4), [0u8; 32], full_caps())
            .unwrap();
        assert_eq!(
            h.get_state(RelayNodeId(4)),
            Some(RelayConnectionState::Handshaking)
        );

        h.complete_handshake(RelayNodeId(4), response(4, true, full_caps()))
            .unwrap();
        assert_eq!(
            h.get_state(RelayNodeId(4)),
            Some(RelayConnectionState::Established)
        );

        h.close(RelayNodeId(4)).unwrap();
        assert_eq!(
            h.get_state(RelayNodeId(4)),
            Some(RelayConnectionState::Closed)
        );
    }

    // ── rp5: duplicate relay rejected ────────────────────────────────────────

    #[test]
    fn rp5_duplicate_relay_rejected() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(5, full_caps())).unwrap();
        let err = h.register_relay(descriptor(5, full_caps())).unwrap_err();
        assert_eq!(err, RelayProtocolError::DuplicateRelay);
    }

    // ── rp6: begin_handshake wrong state ─────────────────────────────────────

    #[test]
    fn rp6_begin_handshake_invalid_state() {
        let mut h = RelayProtocolHandler::new();
        h.register_relay(descriptor(6, full_caps())).unwrap();
        h.begin_handshake(RelayNodeId(6), [0u8; 32], full_caps())
            .unwrap();
        // Already Handshaking — second begin is invalid.
        let err = h
            .begin_handshake(RelayNodeId(6), [0u8; 32], full_caps())
            .unwrap_err();
        assert_eq!(err, RelayProtocolError::InvalidState);
    }

    // ── rp7: relay not found ──────────────────────────────────────────────────

    #[test]
    fn rp7_relay_not_found() {
        let mut h = RelayProtocolHandler::new();
        let err = h.close(RelayNodeId(99)).unwrap_err();
        assert_eq!(err, RelayProtocolError::RelayNotFound);
    }
}
