use std::collections::HashMap;

use crate::relay_protocol::{RelayConnectionState, RelayDescriptor, RelayNodeId};

use super::errors::ProtocolRuntimeError;

/// Bridges the relay protocol state machine into the integration runtime.
///
/// Tracks per-relay `RelayConnectionState`; no network I/O.
pub struct RelayRuntime {
    relays: HashMap<u64, RelayConnectionState>,
}

impl RelayRuntime {
    pub fn new() -> Self {
        Self {
            relays: HashMap::new(),
        }
    }

    /// Register a relay in `Init` state.  Error: `InvalidState` if duplicate.
    pub fn register_relay(&mut self, desc: RelayDescriptor) -> Result<(), ProtocolRuntimeError> {
        if self.relays.contains_key(&desc.relay_id.0) {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        self.relays
            .insert(desc.relay_id.0, RelayConnectionState::Init);
        Ok(())
    }

    /// Transition `Init → Handshaking`.
    pub fn begin_handshake(&mut self, relay_id: RelayNodeId) -> Result<(), ProtocolRuntimeError> {
        let state = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(ProtocolRuntimeError::RelayNotEstablished)?;
        if *state != RelayConnectionState::Init {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        *state = RelayConnectionState::Handshaking;
        Ok(())
    }

    /// Transition `Handshaking → Established`.
    pub fn complete_handshake(
        &mut self,
        relay_id: RelayNodeId,
    ) -> Result<(), ProtocolRuntimeError> {
        let state = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(ProtocolRuntimeError::RelayNotEstablished)?;
        if *state != RelayConnectionState::Handshaking {
            return Err(ProtocolRuntimeError::InvalidState);
        }
        *state = RelayConnectionState::Established;
        Ok(())
    }

    /// Transition any state → `Closed`.
    pub fn close_relay(&mut self, relay_id: RelayNodeId) -> Result<(), ProtocolRuntimeError> {
        let state = self
            .relays
            .get_mut(&relay_id.0)
            .ok_or(ProtocolRuntimeError::RelayNotEstablished)?;
        *state = RelayConnectionState::Closed;
        Ok(())
    }

    /// Return `true` if the relay is in `Established` state.
    pub fn is_established(&self, relay_id: RelayNodeId) -> bool {
        matches!(
            self.relays.get(&relay_id.0),
            Some(RelayConnectionState::Established)
        )
    }
}

impl Default for RelayRuntime {
    fn default() -> Self {
        Self::new()
    }
}
