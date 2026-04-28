use std::collections::HashMap;

use crate::udp_transport::PeerAddress;

use super::errors::RelayProtocolError;

/// Identifies a relay node in the mesh protocol layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RelayNodeId(pub u64);

/// Capabilities a relay may advertise or a client may request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayCapabilities {
    pub supports_onion: bool,
    pub supports_cover: bool,
    pub supports_rotation: bool,
    pub supports_fragmentation: bool,
}

impl RelayCapabilities {
    /// Returns `true` if every capability set in `required` is also set here.
    pub fn satisfies(&self, required: &RelayCapabilities) -> bool {
        (!required.supports_onion || self.supports_onion)
            && (!required.supports_cover || self.supports_cover)
            && (!required.supports_rotation || self.supports_rotation)
            && (!required.supports_fragmentation || self.supports_fragmentation)
    }

    /// Intersection: only keep capabilities both sides support.
    pub fn negotiate(&self, other: &RelayCapabilities) -> RelayCapabilities {
        RelayCapabilities {
            supports_onion: self.supports_onion && other.supports_onion,
            supports_cover: self.supports_cover && other.supports_cover,
            supports_rotation: self.supports_rotation && other.supports_rotation,
            supports_fragmentation: self.supports_fragmentation && other.supports_fragmentation,
        }
    }
}

/// Static descriptor for a relay node.
#[derive(Debug, Clone)]
pub struct RelayDescriptor {
    pub relay_id: RelayNodeId,
    pub public_key: [u8; 32],
    pub peer_address: PeerAddress,
    pub reliability_score: f64,
    pub latency_estimate: u64,
    pub capabilities: RelayCapabilities,
}

/// Sent by a client to initiate a handshake with a relay.
#[derive(Debug, Clone)]
pub struct RelayHandshakeRequest {
    pub client_pubkey: [u8; 32],
    pub requested_capabilities: RelayCapabilities,
}

/// Sent by the relay in response to a handshake request.
#[derive(Debug, Clone)]
pub struct RelayHandshakeResponse {
    pub relay_id: RelayNodeId,
    pub relay_pubkey: [u8; 32],
    pub accepted: bool,
    pub negotiated_capabilities: RelayCapabilities,
}

/// Connection state for a single relay link.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayConnectionState {
    Init,
    Handshaking,
    Established,
    Closed,
}

// ── Protocol handler ──────────────────────────────────────────────────────────

struct RelayEntry {
    #[allow(dead_code)]
    descriptor: RelayDescriptor,
    state: RelayConnectionState,
    /// Capabilities requested during `begin_handshake`, cleared on completion.
    pending_caps: Option<RelayCapabilities>,
}

/// Manages relay registrations and the per-relay handshake state machine.
///
/// No network I/O; all state transitions are deterministic.
pub struct RelayProtocolHandler {
    relays: HashMap<u64, RelayEntry>,
}

impl RelayProtocolHandler {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
        }
    }

    /// Register a relay in `Init` state.  Error: `DuplicateRelay`.
    pub fn register_relay(&mut self, desc: RelayDescriptor) -> Result<(), RelayProtocolError> {
        let id = desc.relay_id.0;
        if self.relays.contains_key(&id) {
            return Err(RelayProtocolError::DuplicateRelay);
        }
        self.relays.insert(
            id,
            RelayEntry {
                descriptor: desc,
                state: RelayConnectionState::Init,
                pending_caps: None,
            },
        );
        Ok(())
    }

    /// Transition `Init → Handshaking` and return the request to send.
    pub fn begin_handshake(
        &mut self,
        relay_id: RelayNodeId,
        client_pubkey: [u8; 32],
        requested_caps: RelayCapabilities,
    ) -> Result<RelayHandshakeRequest, RelayProtocolError> {
        let entry = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(RelayProtocolError::RelayNotFound)?;

        if entry.state != RelayConnectionState::Init {
            return Err(RelayProtocolError::InvalidState);
        }
        entry.state = RelayConnectionState::Handshaking;
        entry.pending_caps = Some(requested_caps);

        Ok(RelayHandshakeRequest {
            client_pubkey,
            requested_capabilities: requested_caps,
        })
    }

    /// Transition `Handshaking → Established` using the relay's response.
    ///
    /// Returns:
    /// - `HandshakeRejected` if `response.accepted == false`.
    /// - `CapabilityMismatch` if negotiated caps don't satisfy the original
    ///   requested caps.
    /// - `InvalidState` if the relay is not in `Handshaking` state.
    pub fn complete_handshake(
        &mut self,
        relay_id: RelayNodeId,
        response: RelayHandshakeResponse,
    ) -> Result<(), RelayProtocolError> {
        let entry = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(RelayProtocolError::RelayNotFound)?;

        if entry.state != RelayConnectionState::Handshaking {
            return Err(RelayProtocolError::InvalidState);
        }
        if !response.accepted {
            return Err(RelayProtocolError::HandshakeRejected);
        }
        if let Some(req) = entry.pending_caps
            && !response.negotiated_capabilities.satisfies(&req)
        {
            return Err(RelayProtocolError::CapabilityMismatch);
        }
        entry.state = RelayConnectionState::Established;
        entry.pending_caps = None;
        Ok(())
    }

    /// Transition any state → `Closed`.
    pub fn close(&mut self, relay_id: RelayNodeId) -> Result<(), RelayProtocolError> {
        let entry = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(RelayProtocolError::RelayNotFound)?;
        entry.state = RelayConnectionState::Closed;
        Ok(())
    }

    /// Return the current connection state for a relay, if registered.
    pub fn get_state(&self, relay_id: RelayNodeId) -> Option<RelayConnectionState> {
        self.relays.get(&relay_id.0).map(|e| e.state)
    }
}

impl Default for RelayProtocolHandler {
    fn default() -> Self {
        Self::new()
    }
}
