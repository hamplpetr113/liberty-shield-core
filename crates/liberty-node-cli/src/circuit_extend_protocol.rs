use crate::circuit_extend_state::{CircuitExtendState, ExtendRequest, ExtendResponse, ExtendState};

/// Convenience: build an accepted `ExtendResponse` with a deterministic circuit ID.
pub fn make_ok_response(seed: u64) -> ExtendResponse {
    ExtendResponse {
        accepted: true,
        reason: "ok".to_string(),
        next_circuit_id: seed.wrapping_mul(0x9e3779b97f4a7c15).wrapping_add(1),
    }
}

/// Errors produced by the circuit extension protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendError {
    /// Cannot extend a circuit that is already Closed.
    CircuitClosed,
    /// The target node is already a hop in this circuit.
    DuplicateHop,
    /// Cannot start a new extend while one is already in flight.
    ExtendInProgress,
    /// No extend is pending; spurious response received.
    NoPendingExtend,
    /// Circuit has not reached at least 3 hops after all extensions.
    TooFewHops,
    /// Circuit is not in the correct state for this operation.
    InvalidState,
}

/// Manages the circuit-extension lifecycle for one circuit.
pub struct CircuitExtendProtocol {
    pub state: CircuitExtendState,
    /// Counter used to generate deterministic circuit IDs for sub-circuits.
    next_sub_id: u64,
}

impl CircuitExtendProtocol {
    pub fn new(circuit_id: u64, origin_node: u64) -> Self {
        Self {
            state: CircuitExtendState::new(circuit_id, origin_node),
            next_sub_id: circuit_id.wrapping_mul(0x9e3779b97f4a7c15),
        }
    }

    /// Deterministic sub-circuit ID derived from the parent circuit and a counter.
    fn next_id(&mut self) -> u64 {
        self.next_sub_id = self
            .next_sub_id
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.next_sub_id
    }

    /// Begin extending the circuit to `target_node`.
    ///
    /// Returns the `ExtendRequest` to be sent to the current last hop.
    pub fn begin_extend(
        &mut self,
        target_node: u64,
        next_hop: u64,
    ) -> Result<ExtendRequest, ExtendError> {
        match self.state.state {
            ExtendState::Closed => return Err(ExtendError::CircuitClosed),
            ExtendState::Extending => return Err(ExtendError::ExtendInProgress),
            _ => {}
        }
        if self.state.contains_node(target_node) {
            return Err(ExtendError::DuplicateHop);
        }
        // Deterministic key material derived from circuit_id + target
        let key_seed = self.state.circuit_id.wrapping_add(target_node);
        let onion_key_material = key_seed.to_le_bytes().to_vec();

        self.state.begin_extending(target_node);
        Ok(ExtendRequest {
            target_node,
            next_hop,
            onion_key_material,
        })
    }

    /// Handle an incoming extend request (called at the node receiving the request).
    ///
    /// Returns an `ExtendResponse` to send back to the initiator.
    pub fn handle_extend_request(
        &mut self,
        req: &ExtendRequest,
    ) -> Result<ExtendResponse, ExtendError> {
        if self.state.state == ExtendState::Closed {
            return Err(ExtendError::CircuitClosed);
        }
        if self.state.contains_node(req.target_node) {
            let resp = ExtendResponse {
                accepted: false,
                reason: "duplicate hop".to_string(),
                next_circuit_id: 0,
            };
            return Ok(resp);
        }
        let next_id = self.next_id();
        Ok(ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: next_id,
        })
    }

    /// Handle the response to a previously issued extend request.
    pub fn handle_extend_response(&mut self, resp: &ExtendResponse) -> Result<(), ExtendError> {
        if self.state.pending_target.is_none() {
            return Err(ExtendError::NoPendingExtend);
        }
        let target = self.state.pending_target.unwrap();
        if resp.accepted {
            self.state.confirm_extended(target);
        } else {
            self.state.fail();
        }
        Ok(())
    }

    /// Returns true if the circuit has been extended at least once and is not Failed/Closed.
    pub fn is_extended(&self) -> bool {
        self.state.state == ExtendState::Extended
    }

    /// Returns true once the circuit has ≥ 3 hops and is in Extended state.
    pub fn is_ready(&self) -> bool {
        self.is_extended() && self.state.hop_count() >= 3
    }

    pub fn close(&mut self) {
        self.state.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(circuit_id: u64, origin: u64) -> CircuitExtendProtocol {
        CircuitExtendProtocol::new(circuit_id, origin)
    }

    // CE1: begin_extend returns an ExtendRequest with correct target
    #[test]
    fn ce1_begin_extend() {
        let mut p = proto(1, 10);
        let req = p.begin_extend(20, 20).unwrap();
        assert_eq!(req.target_node, 20);
        assert_eq!(p.state.state, ExtendState::Extending);
    }

    // CE2: handle_extend_request accepts a valid extend
    #[test]
    fn ce2_accept_extend() {
        let mut p = proto(1, 10);
        let req = p.begin_extend(20, 20).unwrap();
        // Simulate the receiving side
        let mut receiver = proto(2, 10);
        let resp = receiver.handle_extend_request(&req).unwrap();
        assert!(resp.accepted);
        assert_eq!(resp.reason, "ok");
        assert_ne!(resp.next_circuit_id, 0);
    }

    // CE3: duplicate hop rejected
    #[test]
    fn ce3_reject_duplicate_hop() {
        let mut p = proto(1, 10);
        let req = p.begin_extend(20, 20).unwrap();
        let resp = ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: 999,
        };
        p.handle_extend_response(&resp).unwrap();
        // Now try to extend to node 20 again — should fail
        assert_eq!(
            p.begin_extend(20, 20).unwrap_err(),
            ExtendError::DuplicateHop
        );
    }

    // CE4: cannot extend a closed circuit
    #[test]
    fn ce4_reject_closed_circuit() {
        let mut p = proto(1, 10);
        p.close();
        assert_eq!(
            p.begin_extend(20, 20).unwrap_err(),
            ExtendError::CircuitClosed
        );
    }

    // CE5: deterministic circuit IDs — same seed produces same sequence
    #[test]
    fn ce5_deterministic_circuit_id() {
        let req = ExtendRequest {
            target_node: 20,
            next_hop: 20,
            onion_key_material: vec![1, 2, 3, 4, 5, 6, 7, 8],
        };
        let mut p1 = proto(42, 10);
        let mut p2 = proto(42, 10);
        let resp1 = p1.handle_extend_request(&req).unwrap();
        let resp2 = p2.handle_extend_request(&req).unwrap();
        assert_eq!(resp1.next_circuit_id, resp2.next_circuit_id);
    }

    // CE6: full 3-hop extension succeeds
    #[test]
    fn ce6_three_hop_extension_success() {
        let mut p = proto(1, 10);
        // Extend to node 20
        p.begin_extend(20, 20).unwrap();
        p.handle_extend_response(&ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: 2,
        })
        .unwrap();
        assert_eq!(p.state.hop_count(), 2);

        // Extend to node 30
        p.begin_extend(30, 30).unwrap();
        p.handle_extend_response(&ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: 3,
        })
        .unwrap();
        assert_eq!(p.state.hop_count(), 3);
        assert!(p.is_ready());
    }

    // CE7: rejected response puts circuit into Failed state
    #[test]
    fn ce7_failed_extension_state() {
        let mut p = proto(1, 10);
        p.begin_extend(20, 20).unwrap();
        p.handle_extend_response(&ExtendResponse {
            accepted: false,
            reason: "refused".to_string(),
            next_circuit_id: 0,
        })
        .unwrap();
        assert_eq!(p.state.state, ExtendState::Failed);
        assert!(!p.is_extended());
    }

    // CE8: response with accepted=true completes the extension
    #[test]
    fn ce8_response_completes_extension() {
        let mut p = proto(1, 10);
        p.begin_extend(20, 20).unwrap();
        p.handle_extend_response(&ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: 77,
        })
        .unwrap();
        assert_eq!(p.state.state, ExtendState::Extended);
        assert!(p.is_extended());
        assert!(p.state.contains_node(20));
    }

    // CE9: spurious response without pending extend returns error
    #[test]
    fn ce9_spurious_response_rejected() {
        let mut p = proto(1, 10);
        let resp = ExtendResponse {
            accepted: true,
            reason: "ok".to_string(),
            next_circuit_id: 5,
        };
        assert_eq!(
            p.handle_extend_response(&resp).unwrap_err(),
            ExtendError::NoPendingExtend
        );
    }

    // CE10: extend-in-progress prevents second extend
    #[test]
    fn ce10_extend_in_progress_rejected() {
        let mut p = proto(1, 10);
        p.begin_extend(20, 20).unwrap();
        assert_eq!(
            p.begin_extend(30, 30).unwrap_err(),
            ExtendError::ExtendInProgress
        );
    }
}
