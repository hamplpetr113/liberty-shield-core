//! Extended replay-protection tests covering additional edge cases,
//! out-of-order acceptance, multi-circuit stress, and boundary conditions.

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;
    use crate::replay_protection::{CellNonce, ReplayDetector, ReplayError, ReplayWindow};

    // RW7: out-of-order nonces within window are accepted
    #[test]
    fn rw7_out_of_order_within_window() {
        let mut w = ReplayWindow::new(64);
        // Accept 100, then 50 (50 > 100 - 64 = 36 → valid)
        w.check_and_record(CellNonce(100)).unwrap();
        w.check_and_record(CellNonce(50)).unwrap();
        w.check_and_record(CellNonce(80)).unwrap();
        assert_eq!(w.last_nonce, 100);
    }

    // RW8: nonce exactly at the window floor is accepted
    #[test]
    fn rw8_nonce_at_floor() {
        let mut w = ReplayWindow::new(10);
        w.check_and_record(CellNonce(20)).unwrap(); // floor = 20 - 10 = 10
        w.check_and_record(CellNonce(10)).unwrap(); // exactly at floor
    }

    // RW9: nonce one below floor is rejected
    #[test]
    fn rw9_nonce_below_floor() {
        let mut w = ReplayWindow::new(10);
        w.check_and_record(CellNonce(20)).unwrap(); // floor = 10
        let err = w.check_and_record(CellNonce(9)).unwrap_err();
        assert_eq!(err, ReplayError::WindowExpired);
    }

    // RW10: window advances when a higher nonce arrives
    #[test]
    fn rw10_window_advances() {
        let mut w = ReplayWindow::new(4);
        for n in [0u64, 1, 2, 3] {
            w.check_and_record(CellNonce(n)).unwrap();
        }
        assert_eq!(w.last_nonce, 3);
        // Now accept a nonce beyond the original set
        w.check_and_record(CellNonce(100)).unwrap();
        assert_eq!(w.last_nonce, 100);
        // Old nonces should now be expired
        let err = w.check_and_record(CellNonce(0)).unwrap_err();
        assert_eq!(err, ReplayError::WindowExpired);
    }

    // RW11: replay detector handles many circuits independently
    #[test]
    fn rw11_many_circuits() {
        let mut det = ReplayDetector::new();
        // Register 50 circuits and send nonce 0 on each
        for cid in 0u64..50 {
            det.check_cell(CircuitId(cid), CellNonce(0)).unwrap();
        }
        // Replay on circuit 0 must fail, but circuit 1 is fresh for nonce 1
        assert_eq!(
            det.check_cell(CircuitId(0), CellNonce(0)).unwrap_err(),
            ReplayError::DuplicateNonce
        );
        det.check_cell(CircuitId(0), CellNonce(1)).unwrap();
    }

    // RW12: seen_nonces bounded after high-nonce jump
    #[test]
    fn rw12_seen_nonces_bounded_after_jump() {
        let mut w = ReplayWindow::new(8);
        // Fill the window
        for n in 0u64..8 {
            w.check_and_record(CellNonce(n)).unwrap();
        }
        // Jump far ahead
        w.check_and_record(CellNonce(1000)).unwrap();
        // seen_nonces should contain only nonces >= 1000 - 8 = 992
        assert!(w.seen_nonces.iter().all(|&x| x >= 992));
        assert!(w.seen_nonces.len() <= 9); // at most 8 old + 1 new
    }

    // RW13: duplicate detection works for out-of-order nonces
    #[test]
    fn rw13_duplicate_out_of_order() {
        let mut w = ReplayWindow::new(64);
        w.check_and_record(CellNonce(50)).unwrap();
        w.check_and_record(CellNonce(100)).unwrap();
        w.check_and_record(CellNonce(75)).unwrap();
        // Replaying 75 should be rejected
        assert_eq!(
            w.check_and_record(CellNonce(75)).unwrap_err(),
            ReplayError::DuplicateNonce
        );
    }

    // RW14: zero-size window: only the last nonce is valid
    #[test]
    fn rw14_zero_window_size() {
        let mut w = ReplayWindow::new(0);
        w.check_and_record(CellNonce(5)).unwrap();
        // Nonce 5 again: duplicate
        assert_eq!(
            w.check_and_record(CellNonce(5)).unwrap_err(),
            ReplayError::DuplicateNonce
        );
        // Nonce 4 (below floor=5): expired (floor = 5 - 0 = 5)
        let err = w.check_and_record(CellNonce(4)).unwrap_err();
        assert_eq!(err, ReplayError::WindowExpired);
    }

    // RW15: dense sequential stream accepted cleanly
    #[test]
    fn rw15_dense_sequential_stream() {
        let mut w = ReplayWindow::new(128);
        for n in 0u64..256 {
            w.check_and_record(CellNonce(n)).unwrap();
        }
        assert_eq!(w.last_nonce, 255);
        // Nonce 0 should now be expired (floor = 255 - 128 = 127)
        assert_eq!(
            w.check_and_record(CellNonce(0)).unwrap_err(),
            ReplayError::WindowExpired
        );
    }

    // RW16: accept_nonce convenience alias works
    #[test]
    fn rw16_window_accepts_valid_sequence() {
        let mut det = ReplayDetector::new();
        let cid = CircuitId(99);
        for seq in 0u64..10 {
            det.check_cell(cid, CellNonce(seq)).unwrap();
        }
        // All must now be duplicates
        for seq in 0u64..10 {
            assert_eq!(
                det.check_cell(cid, CellNonce(seq)).unwrap_err(),
                ReplayError::DuplicateNonce,
                "nonce {seq} should be a duplicate"
            );
        }
    }

    // RW17: removing a circuit resets its window state
    #[test]
    fn rw17_circuit_removal_resets_state() {
        let mut det = ReplayDetector::new();
        let cid = CircuitId(7);
        det.register_circuit(cid);
        for n in 0u64..5 {
            det.check_cell(cid, CellNonce(n)).unwrap();
        }
        det.remove_circuit(cid);
        // After removal, all nonces should be fresh again
        for n in 0u64..5 {
            det.check_cell(cid, CellNonce(n)).unwrap();
        }
    }

    // RW18: large nonce jump does not overflow
    #[test]
    fn rw18_nonce_near_u64_max() {
        let mut w = ReplayWindow::new(64);
        let big = u64::MAX - 10;
        w.check_and_record(CellNonce(big)).unwrap();
        assert_eq!(w.last_nonce, big);
        // Duplicate check
        assert_eq!(
            w.check_and_record(CellNonce(big)).unwrap_err(),
            ReplayError::DuplicateNonce
        );
    }
}
