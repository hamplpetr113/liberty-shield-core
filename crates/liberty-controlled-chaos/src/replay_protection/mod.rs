//! ReplayProtection — per-circuit sliding-window replay detection.
//!
//! No network I/O; no randomness; all state is caller-driven.

mod detector;
mod types;
mod window;

pub use detector::ReplayDetector;
pub use types::{CellNonce, ReplayError};
pub use window::ReplayWindow;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    // ── rw1: duplicate nonce rejected ─────────────────────────────────────────

    #[test]
    fn rw1_duplicate_nonce_rejected() {
        let mut w = ReplayWindow::new(64);
        w.check_and_record(CellNonce(5)).unwrap();
        let err = w.check_and_record(CellNonce(5)).unwrap_err();
        assert_eq!(err, ReplayError::DuplicateNonce);
    }

    // ── rw2: increasing nonce accepted ────────────────────────────────────────

    #[test]
    fn rw2_increasing_nonce_accepted() {
        let mut w = ReplayWindow::new(64);
        for n in 0u64..10 {
            w.check_and_record(CellNonce(n)).unwrap();
        }
        assert_eq!(w.last_nonce, 9);
    }

    // ── rw3: old nonce rejected ───────────────────────────────────────────────

    #[test]
    fn rw3_old_nonce_rejected() {
        let mut w = ReplayWindow::new(64);
        // Advance the window to nonce 100.
        w.check_and_record(CellNonce(100)).unwrap();
        // Nonce 35 is below floor (100 - 64 = 36) → WindowExpired.
        let err = w.check_and_record(CellNonce(35)).unwrap_err();
        assert_eq!(err, ReplayError::WindowExpired);
    }

    #[test]
    fn rw3_nonce_at_floor_accepted() {
        let mut w = ReplayWindow::new(64);
        w.check_and_record(CellNonce(100)).unwrap();
        // Nonce exactly at floor (100 - 64 = 36) is within window.
        w.check_and_record(CellNonce(36)).unwrap();
    }

    // ── rw4: per-circuit isolation ────────────────────────────────────────────

    #[test]
    fn rw4_per_circuit_isolation() {
        let mut det = ReplayDetector::new();
        // Same nonce on two different circuits must both succeed.
        det.check_cell(CircuitId(1), CellNonce(42)).unwrap();
        det.check_cell(CircuitId(2), CellNonce(42)).unwrap();

        // Second use of nonce 42 on circuit 1 must fail.
        let err = det.check_cell(CircuitId(1), CellNonce(42)).unwrap_err();
        assert_eq!(err, ReplayError::DuplicateNonce);

        // Circuit 2 still has its own state; nonce 42 is already recorded there too.
        let err2 = det.check_cell(CircuitId(2), CellNonce(42)).unwrap_err();
        assert_eq!(err2, ReplayError::DuplicateNonce);
    }

    // ── rw5: register / remove ────────────────────────────────────────────────

    #[test]
    fn rw5_register_and_remove() {
        let mut det = ReplayDetector::new();
        det.register_circuit(CircuitId(10));
        det.check_cell(CircuitId(10), CellNonce(1)).unwrap();
        det.remove_circuit(CircuitId(10));
        // After removal, a new window is created lazily — nonce 1 is now fresh.
        det.check_cell(CircuitId(10), CellNonce(1)).unwrap();
    }

    // ── rw6: window pruning keeps seen_nonces bounded ─────────────────────────

    #[test]
    fn rw6_window_pruning() {
        let mut w = ReplayWindow::new(4);
        for n in 0u64..20 {
            w.check_and_record(CellNonce(n)).unwrap();
        }
        // After advancing to 19, floor = 19 - 4 = 15.
        // Only nonces >= 15 should remain: [15, 16, 17, 18, 19].
        assert!(w.seen_nonces.len() <= 5);
        assert!(w.seen_nonces.iter().all(|&x| x >= 15));
    }
}
