use crate::onion_layer::OnionLayerKey;
use crate::udp_transport::PeerAddress;

use super::types::{CircuitError, CircuitId, NodeDescriptor};

/// A fully-built N-hop circuit with one `OnionLayerKey` per hop.
pub struct Circuit {
    pub circuit_id: CircuitId,
    /// Ordered relay hops, guard first.
    pub hops: Vec<NodeDescriptor>,
    /// Per-hop onion keys, aligned with `hops` by index.
    pub onion_keys: Vec<OnionLayerKey>,
}

impl Circuit {
    pub(super) fn new(
        circuit_id: CircuitId,
        hops: Vec<NodeDescriptor>,
        onion_keys: Vec<OnionLayerKey>,
    ) -> Self {
        Self {
            circuit_id,
            hops,
            onion_keys,
        }
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    /// Returns the guard (entry) node's `PeerAddress`, or an error if the circuit is empty.
    pub fn first_hop(&self) -> Result<&PeerAddress, CircuitError> {
        self.hops
            .first()
            .map(|n| &n.peer_address)
            .ok_or(CircuitError::NotEnoughNodes)
    }

    /// Returns the exit node's `PeerAddress`, or an error if the circuit is empty.
    pub fn last_hop(&self) -> Result<&PeerAddress, CircuitError> {
        self.hops
            .last()
            .map(|n| &n.peer_address)
            .ok_or(CircuitError::NotEnoughNodes)
    }
}
