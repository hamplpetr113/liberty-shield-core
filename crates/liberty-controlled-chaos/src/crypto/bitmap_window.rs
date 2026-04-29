//! 128-packet bitmap sliding window for session-layer replay detection.
//!
//! `BitmapReplayWindow` uses a single `u128` as a bitfield: bit `k` is set when
//! the sequence number `max_seen - k` has been accepted.  The window covers the
//! 128 most-recent sequence numbers; anything older is rejected as `TooOld`.
//!
//! All operations are O(1) with no heap allocation.

/// Error returned by [`BitmapReplayWindow::check_and_record`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowError {
    /// Sequence was already seen (replay attempt).
    Replay,
    /// Sequence is more than 127 below `max_seen` (outside the window).
    TooOld,
}

/// Bitmap sliding-window replay guard.
///
/// Bit layout: bit `k` of `bitmap` corresponds to sequence `max_seen - k`.
/// Accepting a new sequence `seq > max_seen` shifts the bitmap left by
/// `seq - max_seen` (evicting old entries) and sets bit 0.
#[derive(Debug, Clone)]
pub struct BitmapReplayWindow {
    /// Highest sequence accepted so far; `None` before the first packet.
    max_seen: Option<u64>,
    /// Bitfield of seen sequences relative to `max_seen`.
    bitmap: u128,
}

impl Default for BitmapReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl BitmapReplayWindow {
    /// Create an empty window.
    pub fn new() -> Self {
        Self {
            max_seen: None,
            bitmap: 0,
        }
    }

    /// Check `seq` and, if valid, record it.
    ///
    /// Returns:
    /// - `Ok(())` on the first time this sequence is accepted.
    /// - `Err(WindowError::Replay)` if `seq` was already recorded.
    /// - `Err(WindowError::TooOld)` if `seq` is more than 127 behind `max_seen`.
    pub fn check_and_record(&mut self, seq: u64) -> Result<(), WindowError> {
        let Some(max) = self.max_seen else {
            // First packet ever: unconditionally accept.
            self.max_seen = Some(seq);
            self.bitmap = 1;
            return Ok(());
        };

        if seq > max {
            let shift = seq - max;
            // Shift existing bits toward higher offsets; set bit 0 for new max.
            self.bitmap = if shift >= 128 {
                1 // all prior entries have fallen out of the 128-packet window
            } else {
                (self.bitmap << shift) | 1
            };
            self.max_seen = Some(seq);
            Ok(())
        } else {
            let offset = max - seq;
            if offset >= 128 {
                return Err(WindowError::TooOld);
            }
            let mask = 1u128 << offset;
            if self.bitmap & mask != 0 {
                return Err(WindowError::Replay);
            }
            self.bitmap |= mask;
            Ok(())
        }
    }

    /// Return the highest sequence number accepted so far.
    pub fn max_seen(&self) -> Option<u64> {
        self.max_seen
    }

    /// Reset to the empty state (e.g., after a session rekey).
    pub fn reset(&mut self) {
        self.max_seen = None;
        self.bitmap = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SW1: first packet always accepted regardless of sequence value
    #[test]
    fn sw1_first_packet_accepted() {
        let mut w = BitmapReplayWindow::new();
        assert!(w.check_and_record(999).is_ok());
        assert_eq!(w.max_seen(), Some(999));
    }

    // SW2: duplicate sequence rejected as Replay
    #[test]
    fn sw2_duplicate_rejected() {
        let mut w = BitmapReplayWindow::new();
        w.check_and_record(5).unwrap();
        assert_eq!(w.check_and_record(5).unwrap_err(), WindowError::Replay);
    }

    // SW3: sequence more than 127 behind max_seen is TooOld
    #[test]
    fn sw3_too_old_rejected() {
        let mut w = BitmapReplayWindow::new();
        w.check_and_record(200).unwrap();
        // 200 - 128 = 72; sequence 72 is exactly at the boundary (offset=128) → TooOld
        assert_eq!(w.check_and_record(72).unwrap_err(), WindowError::TooOld);
        // sequence 73 has offset=127 → still within window → accepted
        assert!(w.check_and_record(73).is_ok());
    }

    // SW4: out-of-order sequences within the 128-packet window are accepted
    #[test]
    fn sw4_out_of_order_within_window() {
        let mut w = BitmapReplayWindow::new();
        // Accept 100, then lower sequences within window.
        w.check_and_record(100).unwrap();
        w.check_and_record(50).unwrap(); // offset=50, within window
        w.check_and_record(99).unwrap(); // offset=1, within window
        // Re-submitting any of them is a Replay.
        assert_eq!(w.check_and_record(99).unwrap_err(), WindowError::Replay);
        assert_eq!(w.check_and_record(50).unwrap_err(), WindowError::Replay);
    }

    // SW5: large forward jump evicts entire prior window
    #[test]
    fn sw5_large_forward_jump_clears_window() {
        let mut w = BitmapReplayWindow::new();
        w.check_and_record(0).unwrap();
        w.check_and_record(1).unwrap();
        // Jump 200 ahead — prior entries are all evicted.
        w.check_and_record(200).unwrap();
        // Sequence 1 is now 199 behind max_seen=200 → TooOld.
        assert_eq!(w.check_and_record(1).unwrap_err(), WindowError::TooOld);
        // Sequence 73 is 127 behind 200 → still in window → accepted.
        assert!(w.check_and_record(73).is_ok());
    }

    // SW6: reset clears all state
    #[test]
    fn sw6_reset_clears_state() {
        let mut w = BitmapReplayWindow::new();
        w.check_and_record(42).unwrap();
        w.reset();
        assert_eq!(w.max_seen(), None);
        // After reset, sequence 42 is fresh again.
        assert!(w.check_and_record(42).is_ok());
    }
}
