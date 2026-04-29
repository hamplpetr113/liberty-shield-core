//! Simple AIMD congestion controller.
//!
//! Additive increase on ACK (+1 per ACK), multiplicative decrease on loss
//! (window /= 2).  The send window is capped at `max_window`.  A packet
//! can be sent only if inflight < window.
//!
//! RTT is a running EWMA: rtt = 0.875 * rtt + 0.125 * sample.

// ---------------------------------------------------------------------------
// CongestionController
// ---------------------------------------------------------------------------

/// AIMD congestion controller for a single flow.
pub struct CongestionController {
    /// Current send window (packets).
    send_window: u32,
    /// Hard cap on the window.
    max_window: u32,
    /// Smoothed RTT estimate in milliseconds.
    rtt_estimate_ms: f64,
    /// Number of packets currently in flight (sent, not yet ACKed or lost).
    inflight_packets: u32,
}

impl CongestionController {
    /// Create a controller with `initial_window` and `max_window`.
    pub fn new(initial_window: u32, max_window: u32) -> Self {
        assert!(initial_window >= 1, "initial window must be at least 1");
        assert!(
            max_window >= initial_window,
            "max_window must be >= initial_window"
        );
        Self {
            send_window: initial_window,
            max_window,
            rtt_estimate_ms: 100.0,
            inflight_packets: 0,
        }
    }

    /// Returns `true` if sending another packet is allowed.
    pub fn can_send(&self) -> bool {
        self.inflight_packets < self.send_window
    }

    /// Record that a packet was sent.
    pub fn on_packet_sent(&mut self) {
        self.inflight_packets = self.inflight_packets.saturating_add(1);
    }

    /// Record an ACK with an RTT sample (ms).  Additive increase: window += 1.
    pub fn on_ack(&mut self, rtt_ms: f64) {
        self.inflight_packets = self.inflight_packets.saturating_sub(1);
        // EWMA update.
        self.rtt_estimate_ms = 0.875 * self.rtt_estimate_ms + 0.125 * rtt_ms;
        // AIMD increase.
        self.send_window = self.send_window.saturating_add(1).min(self.max_window);
    }

    /// Record a loss event.  Multiplicative decrease: window /= 2 (min 1).
    pub fn on_loss(&mut self) {
        self.inflight_packets = self.inflight_packets.saturating_sub(1);
        self.send_window = (self.send_window / 2).max(1);
    }

    /// Re-evaluate window after external changes (no-op in this simple model).
    pub fn update_window(&mut self) {
        self.send_window = self.send_window.min(self.max_window);
    }

    // Accessors -----------------------------------------------------------------

    pub fn send_window(&self) -> u32 {
        self.send_window
    }

    pub fn max_window(&self) -> u32 {
        self.max_window
    }

    pub fn rtt_estimate_ms(&self) -> f64 {
        self.rtt_estimate_ms
    }

    pub fn inflight_packets(&self) -> u32 {
        self.inflight_packets
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ctrl() -> CongestionController {
        CongestionController::new(4, 64)
    }

    // CC1: initial window is set correctly.
    #[test]
    fn cc1_initial_window() {
        let c = ctrl();
        assert_eq!(c.send_window(), 4);
        assert_eq!(c.max_window(), 64);
        assert_eq!(c.inflight_packets(), 0);
    }

    // CC2: can_send returns true when inflight < window.
    #[test]
    fn cc2_send_allowed() {
        let c = ctrl();
        assert!(c.can_send());
    }

    // CC3: can_send returns false when window is full.
    #[test]
    fn cc3_send_blocked() {
        let mut c = CongestionController::new(1, 64);
        c.on_packet_sent();
        assert!(!c.can_send());
    }

    // CC4: on_ack increases window by 1 per ACK.
    #[test]
    fn cc4_ack_increases_window() {
        let mut c = ctrl();
        c.on_packet_sent();
        let w_before = c.send_window();
        c.on_ack(50.0);
        assert_eq!(c.send_window(), w_before + 1);
    }

    // CC5: on_loss halves the window.
    #[test]
    fn cc5_loss_halves_window() {
        let mut c = CongestionController::new(8, 64);
        c.on_packet_sent();
        c.on_loss();
        assert_eq!(c.send_window(), 4);
    }

    // CC6: RTT estimate is updated on ACK.
    #[test]
    fn cc6_rtt_update() {
        let mut c = ctrl();
        c.on_packet_sent();
        c.on_ack(200.0);
        // After one sample: 0.875*100 + 0.125*200 = 112.5
        assert!((c.rtt_estimate_ms() - 112.5).abs() < 0.01);
    }

    // CC7: inflight tracks multiple in-flight packets.
    #[test]
    fn cc7_multiple_inflight() {
        let mut c = ctrl();
        c.on_packet_sent();
        c.on_packet_sent();
        assert_eq!(c.inflight_packets(), 2);
        c.on_ack(10.0);
        assert_eq!(c.inflight_packets(), 1);
    }

    // CC8: window is capped at max_window.
    #[test]
    fn cc8_window_cap() {
        let mut c = CongestionController::new(63, 64);
        c.on_packet_sent();
        c.on_ack(10.0);
        assert_eq!(c.send_window(), 64);
        // Another ACK must not exceed max.
        c.on_packet_sent();
        c.on_ack(10.0);
        assert_eq!(c.send_window(), 64);
    }

    // CC9: burst send followed by bulk ACK converges.
    #[test]
    fn cc9_burst_send() {
        let mut c = CongestionController::new(4, 64);
        for _ in 0..4 {
            c.on_packet_sent();
        }
        assert!(!c.can_send());
        for _ in 0..4 {
            c.on_ack(20.0);
        }
        assert!(c.can_send());
        assert!(c.send_window() > 4);
    }

    // CC10: repeated loss converges toward window = 1.
    #[test]
    fn cc10_fairness() {
        let mut c = CongestionController::new(64, 128);
        for _ in 0..10 {
            c.on_packet_sent();
            c.on_loss();
        }
        assert!(c.send_window() <= 4);
    }
}
