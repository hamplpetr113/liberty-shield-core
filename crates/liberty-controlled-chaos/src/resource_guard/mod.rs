//! Resource guard — budget enforcement for circuits, peers, handshakes, and bandwidth.
//!
//! `ResourceGuard` tracks current usage against a `ResourceBudget` and rejects
//! operations that would exceed any limit.  Call `reset_epoch()` once per epoch
//! to clear the byte counter.

// ---------------------------------------------------------------------------
// Budget
// ---------------------------------------------------------------------------

/// Hard limits for one node's resource consumption.
#[derive(Debug, Clone)]
pub struct ResourceBudget {
    /// Maximum number of simultaneously open circuits.
    pub max_circuits: u32,
    /// Maximum number of simultaneously tracked peers.
    pub max_peers: u32,
    /// Maximum number of in-flight (pending) handshakes.
    pub max_pending_handshakes: u32,
    /// Maximum bytes that may be forwarded in one epoch.
    pub max_bytes_per_epoch: u64,
}

impl ResourceBudget {
    /// Reasonable defaults for a test node.
    pub fn default_budget() -> Self {
        Self {
            max_circuits: 64,
            max_peers: 256,
            max_pending_handshakes: 16,
            max_bytes_per_epoch: 10 * 1024 * 1024, // 10 MiB
        }
    }
}

impl Default for ResourceBudget {
    fn default() -> Self {
        Self::default_budget()
    }
}

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// Adding another circuit would exceed `max_circuits`.
    CircuitLimitExceeded,
    /// Adding another peer would exceed `max_peers`.
    PeerLimitExceeded,
    /// Starting another handshake would exceed `max_pending_handshakes`.
    HandshakeLimitExceeded,
    /// The byte count would exceed `max_bytes_per_epoch`.
    ByteLimitExceeded,
}

impl std::fmt::Display for ResourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResourceError::CircuitLimitExceeded => write!(f, "circuit limit exceeded"),
            ResourceError::PeerLimitExceeded => write!(f, "peer limit exceeded"),
            ResourceError::HandshakeLimitExceeded => write!(f, "handshake limit exceeded"),
            ResourceError::ByteLimitExceeded => write!(f, "byte limit exceeded for this epoch"),
        }
    }
}

// ---------------------------------------------------------------------------
// ResourceGuard
// ---------------------------------------------------------------------------

/// Tracks resource consumption and enforces a `ResourceBudget`.
pub struct ResourceGuard {
    budget: ResourceBudget,
    circuits: u32,
    peers: u32,
    pending_handshakes: u32,
    bytes_this_epoch: u64,
}

impl ResourceGuard {
    /// Create a guard with the given budget and zero usage.
    pub fn new(budget: ResourceBudget) -> Self {
        Self {
            budget,
            circuits: 0,
            peers: 0,
            pending_handshakes: 0,
            bytes_this_epoch: 0,
        }
    }

    // ── Circuits ──────────────────────────────────────────────────────────────

    /// Attempt to register one new circuit.
    pub fn try_add_circuit(&mut self) -> Result<(), ResourceError> {
        if self.circuits >= self.budget.max_circuits {
            return Err(ResourceError::CircuitLimitExceeded);
        }
        self.circuits += 1;
        Ok(())
    }

    /// Release one circuit slot.
    pub fn remove_circuit(&mut self) {
        self.circuits = self.circuits.saturating_sub(1);
    }

    /// Current circuit count.
    pub fn circuit_count(&self) -> u32 {
        self.circuits
    }

    // ── Peers ─────────────────────────────────────────────────────────────────

    /// Attempt to register one new peer.
    pub fn try_add_peer(&mut self) -> Result<(), ResourceError> {
        if self.peers >= self.budget.max_peers {
            return Err(ResourceError::PeerLimitExceeded);
        }
        self.peers += 1;
        Ok(())
    }

    /// Release one peer slot.
    pub fn remove_peer(&mut self) {
        self.peers = self.peers.saturating_sub(1);
    }

    /// Current peer count.
    pub fn peer_count(&self) -> u32 {
        self.peers
    }

    // ── Handshakes ────────────────────────────────────────────────────────────

    /// Attempt to start one new pending handshake.
    pub fn try_add_handshake(&mut self) -> Result<(), ResourceError> {
        if self.pending_handshakes >= self.budget.max_pending_handshakes {
            return Err(ResourceError::HandshakeLimitExceeded);
        }
        self.pending_handshakes += 1;
        Ok(())
    }

    /// Mark one pending handshake as completed (or failed), freeing the slot.
    pub fn complete_handshake(&mut self) {
        self.pending_handshakes = self.pending_handshakes.saturating_sub(1);
    }

    /// Current pending handshake count.
    pub fn handshake_count(&self) -> u32 {
        self.pending_handshakes
    }

    // ── Bytes ─────────────────────────────────────────────────────────────────

    /// Attempt to consume `n` bytes from the epoch budget.
    pub fn try_consume_bytes(&mut self, n: u64) -> Result<(), ResourceError> {
        let new_total = self.bytes_this_epoch.saturating_add(n);
        if new_total > self.budget.max_bytes_per_epoch {
            return Err(ResourceError::ByteLimitExceeded);
        }
        self.bytes_this_epoch = new_total;
        Ok(())
    }

    /// Bytes consumed so far this epoch.
    pub fn bytes_this_epoch(&self) -> u64 {
        self.bytes_this_epoch
    }

    // ── Epoch reset ───────────────────────────────────────────────────────────

    /// Reset the per-epoch byte counter.  Call once at the start of each epoch.
    pub fn reset_epoch(&mut self) {
        self.bytes_this_epoch = 0;
    }

    // ── Budget access ─────────────────────────────────────────────────────────

    /// Read-only reference to the budget.
    pub fn budget(&self) -> &ResourceBudget {
        &self.budget
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn small_budget() -> ResourceBudget {
        ResourceBudget {
            max_circuits: 3,
            max_peers: 4,
            max_pending_handshakes: 2,
            max_bytes_per_epoch: 1000,
        }
    }

    // RG1: circuits up to limit accepted, over limit rejected.
    #[test]
    fn rg1_circuit_limit() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_add_circuit().unwrap();
        g.try_add_circuit().unwrap();
        g.try_add_circuit().unwrap();
        assert_eq!(
            g.try_add_circuit().unwrap_err(),
            ResourceError::CircuitLimitExceeded
        );
    }

    // RG2: remove_circuit frees a slot.
    #[test]
    fn rg2_remove_circuit_frees() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_add_circuit().unwrap();
        g.try_add_circuit().unwrap();
        g.try_add_circuit().unwrap();
        g.remove_circuit();
        assert!(g.try_add_circuit().is_ok());
    }

    // RG3: peers up to limit accepted, over limit rejected.
    #[test]
    fn rg3_peer_limit() {
        let mut g = ResourceGuard::new(small_budget());
        for _ in 0..4 {
            g.try_add_peer().unwrap();
        }
        assert_eq!(
            g.try_add_peer().unwrap_err(),
            ResourceError::PeerLimitExceeded
        );
    }

    // RG4: remove_peer frees a slot.
    #[test]
    fn rg4_remove_peer_frees() {
        let mut g = ResourceGuard::new(small_budget());
        for _ in 0..4 {
            g.try_add_peer().unwrap();
        }
        g.remove_peer();
        assert!(g.try_add_peer().is_ok());
    }

    // RG5: handshakes up to limit accepted, over limit rejected.
    #[test]
    fn rg5_handshake_limit() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_add_handshake().unwrap();
        g.try_add_handshake().unwrap();
        assert_eq!(
            g.try_add_handshake().unwrap_err(),
            ResourceError::HandshakeLimitExceeded
        );
    }

    // RG6: complete_handshake frees a slot.
    #[test]
    fn rg6_complete_handshake_frees() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_add_handshake().unwrap();
        g.try_add_handshake().unwrap();
        g.complete_handshake();
        assert!(g.try_add_handshake().is_ok());
    }

    // RG7: byte budget enforced correctly.
    #[test]
    fn rg7_byte_budget() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_consume_bytes(500).unwrap();
        g.try_consume_bytes(499).unwrap();
        assert_eq!(
            g.try_consume_bytes(2).unwrap_err(),
            ResourceError::ByteLimitExceeded
        );
    }

    // RG8: reset_epoch clears byte counter.
    #[test]
    fn rg8_reset_epoch_clears_bytes() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_consume_bytes(999).unwrap();
        g.reset_epoch();
        assert_eq!(g.bytes_this_epoch(), 0);
        g.try_consume_bytes(1000).unwrap();
    }

    // RG9: remove beyond zero does not underflow (saturating sub).
    #[test]
    fn rg9_remove_below_zero_saturates() {
        let mut g = ResourceGuard::new(small_budget());
        g.remove_circuit(); // already 0
        g.remove_peer();
        g.complete_handshake();
        assert_eq!(g.circuit_count(), 0);
        assert_eq!(g.peer_count(), 0);
        assert_eq!(g.handshake_count(), 0);
    }

    // RG10: all resources can be used up to their limits simultaneously.
    #[test]
    fn rg10_all_limits_simultaneously() {
        let mut g = ResourceGuard::new(small_budget());
        for _ in 0..3 {
            g.try_add_circuit().unwrap();
        }
        for _ in 0..4 {
            g.try_add_peer().unwrap();
        }
        for _ in 0..2 {
            g.try_add_handshake().unwrap();
        }
        g.try_consume_bytes(1000).unwrap();

        assert_eq!(
            g.try_add_circuit().unwrap_err(),
            ResourceError::CircuitLimitExceeded
        );
        assert_eq!(
            g.try_add_peer().unwrap_err(),
            ResourceError::PeerLimitExceeded
        );
        assert_eq!(
            g.try_add_handshake().unwrap_err(),
            ResourceError::HandshakeLimitExceeded
        );
        assert_eq!(
            g.try_consume_bytes(1).unwrap_err(),
            ResourceError::ByteLimitExceeded
        );
    }

    // RG11: counters track correctly across add/remove cycles.
    #[test]
    fn rg11_counter_tracking() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_add_circuit().unwrap();
        g.try_add_circuit().unwrap();
        assert_eq!(g.circuit_count(), 2);
        g.remove_circuit();
        assert_eq!(g.circuit_count(), 1);

        g.try_add_peer().unwrap();
        assert_eq!(g.peer_count(), 1);
        g.remove_peer();
        assert_eq!(g.peer_count(), 0);
    }

    // RG12: byte budget accumulates across multiple try_consume_bytes calls.
    #[test]
    fn rg12_bytes_accumulate() {
        let mut g = ResourceGuard::new(small_budget());
        g.try_consume_bytes(100).unwrap();
        g.try_consume_bytes(200).unwrap();
        assert_eq!(g.bytes_this_epoch(), 300);
    }
}
