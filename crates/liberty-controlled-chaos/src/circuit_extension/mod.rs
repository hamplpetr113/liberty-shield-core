//! CircuitExtension — circuit hop extension protocol and state machine.
//!
//! Sits between the relay protocol and the circuit runtime:
//!   CircuitExtensionManager → CircuitRuntime → OnionLayer → ...
//!
//! No network I/O; no randomness; all transitions are deterministic.

mod builder;
mod state;
mod types;

pub use builder::CircuitExtensionManager;
pub use state::CircuitExtensionState;
pub use types::{
    CircuitDestroy, CircuitExtendRequest, CircuitExtendResponse, DestroyReason, ExtensionError,
};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use crate::circuit_builder::CircuitId;
    use crate::relay_protocol::RelayNodeId;
    use crate::udp_transport::PeerAddress;

    use super::*;

    fn addr() -> PeerAddress {
        PeerAddress::new("127.0.0.1:9001".parse::<SocketAddr>().unwrap())
    }

    // ── ce1: extend request success ───────────────────────────────────────────

    #[test]
    fn ce1_extend_request_success() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(1)).unwrap();

        m.request_extend(CircuitId(1), RelayNodeId(10), addr())
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(1)),
            Some(CircuitExtensionState::Extending)
        );

        m.complete_extend(CircuitId(1), RelayNodeId(10), true)
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(1)),
            Some(CircuitExtensionState::Active)
        );
    }

    // ── ce2: duplicate relay rejected ─────────────────────────────────────────

    #[test]
    fn ce2_duplicate_relay_rejected() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(2)).unwrap();

        // First extend to relay 20 succeeds.
        m.request_extend(CircuitId(2), RelayNodeId(20), addr())
            .unwrap();
        m.complete_extend(CircuitId(2), RelayNodeId(20), true)
            .unwrap();

        // Second extend to the same relay must fail.
        let err = m
            .request_extend(CircuitId(2), RelayNodeId(20), addr())
            .unwrap_err();
        assert_eq!(err, ExtensionError::DuplicateRelay);
    }

    // ── ce3: destroy transition ───────────────────────────────────────────────

    #[test]
    fn ce3_destroy_transition() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(3)).unwrap();
        m.destroy_circuit(CircuitId(3), DestroyReason::Manual)
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(3)),
            Some(CircuitExtensionState::Destroyed)
        );
    }

    #[test]
    fn ce3_extend_after_destroy_rejected() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(4)).unwrap();
        m.destroy_circuit(CircuitId(4), DestroyReason::Failure)
            .unwrap();
        let err = m
            .request_extend(CircuitId(4), RelayNodeId(30), addr())
            .unwrap_err();
        assert_eq!(err, ExtensionError::CircuitDestroyed);
    }

    // ── ce4: full state progression ───────────────────────────────────────────

    #[test]
    fn ce4_state_progression() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(5)).unwrap();
        assert_eq!(
            m.get_state(CircuitId(5)),
            Some(CircuitExtensionState::Building)
        );

        m.request_extend(CircuitId(5), RelayNodeId(50), addr())
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(5)),
            Some(CircuitExtensionState::Extending)
        );

        m.complete_extend(CircuitId(5), RelayNodeId(50), true)
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(5)),
            Some(CircuitExtensionState::Active)
        );

        m.destroy_circuit(CircuitId(5), DestroyReason::Timeout)
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(5)),
            Some(CircuitExtensionState::Destroyed)
        );
    }

    // ── ce5: failed extend reverts to Building ────────────────────────────────

    #[test]
    fn ce5_failed_extend_reverts_to_building() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(6)).unwrap();
        m.request_extend(CircuitId(6), RelayNodeId(60), addr())
            .unwrap();
        m.complete_extend(CircuitId(6), RelayNodeId(60), false)
            .unwrap();
        assert_eq!(
            m.get_state(CircuitId(6)),
            Some(CircuitExtensionState::Building)
        );
    }

    // ── ce6: duplicate circuit registration rejected ──────────────────────────

    #[test]
    fn ce6_duplicate_registration_rejected() {
        let mut m = CircuitExtensionManager::new();
        m.register_circuit(CircuitId(7)).unwrap();
        let err = m.register_circuit(CircuitId(7)).unwrap_err();
        assert_eq!(err, ExtensionError::CircuitAlreadyRegistered);
    }
}
