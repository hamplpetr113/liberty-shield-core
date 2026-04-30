//! Network telemetry — per-epoch metrics snapshots and latency histograms.
//!
//! `NetworkTelemetry` accumulates packet/byte counts and RTT samples across
//! each epoch.  Calling `collect_snapshot()` freezes the current counters into
//! a `TelemetrySnapshot`; `advance_epoch()` atomically stores the snapshot and
//! resets per-epoch counters for the new epoch.
//!
//! Latency is bucketed into four ranges:
//! - `under_10ms`  : rtt < 10 ms
//! - `ms_10_to_50` : 10 ≤ rtt < 50 ms
//! - `ms_50_to_100`: 50 ≤ rtt < 100 ms
//! - `over_100ms`  : rtt ≥ 100 ms

use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// LatencyHistogram
// ---------------------------------------------------------------------------

/// RTT distribution across four coarse buckets.
#[derive(Debug, Clone, Default)]
pub struct LatencyHistogram {
    pub under_10ms: u64,
    pub ms_10_to_50: u64,
    pub ms_50_to_100: u64,
    pub over_100ms: u64,
}

impl LatencyHistogram {
    pub fn record(&mut self, rtt_ms: f64) {
        if rtt_ms < 10.0 {
            self.under_10ms += 1;
        } else if rtt_ms < 50.0 {
            self.ms_10_to_50 += 1;
        } else if rtt_ms < 100.0 {
            self.ms_50_to_100 += 1;
        } else {
            self.over_100ms += 1;
        }
    }

    pub fn total(&self) -> u64 {
        self.under_10ms + self.ms_10_to_50 + self.ms_50_to_100 + self.over_100ms
    }

    /// Rough mean based on bucket midpoints.
    pub fn mean_estimate_ms(&self) -> f64 {
        let t = self.total();
        if t == 0 {
            return 0.0;
        }
        let sum = self.under_10ms as f64 * 5.0
            + self.ms_10_to_50 as f64 * 30.0
            + self.ms_50_to_100 as f64 * 75.0
            + self.over_100ms as f64 * 150.0;
        sum / t as f64
    }
}

// ---------------------------------------------------------------------------
// TelemetrySnapshot
// ---------------------------------------------------------------------------

/// Immutable point-in-time metrics snapshot.
#[derive(Debug, Clone)]
pub struct TelemetrySnapshot {
    pub epoch: u64,
    pub circuits_active: u64,
    pub peer_count: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub latency_histogram: LatencyHistogram,
}

// ---------------------------------------------------------------------------
// NetworkTelemetry
// ---------------------------------------------------------------------------

/// Accumulates metrics and produces epoch snapshots.
pub struct NetworkTelemetry {
    current_epoch: u64,
    circuits_active: u64,
    peer_count: u64,
    packets_sent: u64,
    packets_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    latency_histogram: LatencyHistogram,
    snapshots: VecDeque<TelemetrySnapshot>,
    max_snapshots: usize,
}

impl NetworkTelemetry {
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            current_epoch: 0,
            circuits_active: 0,
            peer_count: 0,
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            latency_histogram: LatencyHistogram::default(),
            snapshots: VecDeque::new(),
            max_snapshots,
        }
    }

    pub fn record_packet_sent(&mut self, bytes: u64) {
        self.packets_sent += 1;
        self.bytes_sent += bytes;
    }

    pub fn record_packet_received(&mut self, bytes: u64) {
        self.packets_received += 1;
        self.bytes_received += bytes;
    }

    pub fn record_rtt(&mut self, rtt_ms: f64) {
        self.latency_histogram.record(rtt_ms);
    }

    pub fn set_circuits_active(&mut self, n: u64) {
        self.circuits_active = n;
    }

    pub fn set_peer_count(&mut self, n: u64) {
        self.peer_count = n;
    }

    /// Return a snapshot of current counters without modifying state.
    pub fn collect_snapshot(&self) -> TelemetrySnapshot {
        TelemetrySnapshot {
            epoch: self.current_epoch,
            circuits_active: self.circuits_active,
            peer_count: self.peer_count,
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            bytes_sent: self.bytes_sent,
            bytes_received: self.bytes_received,
            latency_histogram: self.latency_histogram.clone(),
        }
    }

    /// Freeze current epoch counters as a snapshot, then reset for the next epoch.
    pub fn advance_epoch(&mut self) {
        let snap = self.collect_snapshot();
        if self.snapshots.len() >= self.max_snapshots {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back(snap);
        self.current_epoch += 1;
        self.packets_sent = 0;
        self.packets_received = 0;
        self.bytes_sent = 0;
        self.bytes_received = 0;
        self.latency_histogram = LatencyHistogram::default();
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    /// Last `n` snapshots (oldest first).
    pub fn recent_snapshots(&self, n: usize) -> impl Iterator<Item = &TelemetrySnapshot> {
        let start = self.snapshots.len().saturating_sub(n);
        self.snapshots.range(start..)
    }

    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tele() -> NetworkTelemetry {
        NetworkTelemetry::new(10)
    }

    // NT1: collect_snapshot captures current counters.
    #[test]
    fn nt1_collect_snapshot() {
        let mut t = tele();
        t.record_packet_sent(100);
        t.record_packet_received(200);
        let snap = t.collect_snapshot();
        assert_eq!(snap.packets_sent, 1);
        assert_eq!(snap.packets_received, 1);
        assert_eq!(snap.bytes_sent, 100);
        assert_eq!(snap.bytes_received, 200);
    }

    // NT2: advance_epoch resets per-epoch counters.
    #[test]
    fn nt2_advance_epoch_resets() {
        let mut t = tele();
        t.record_packet_sent(50);
        t.advance_epoch();
        let snap = t.collect_snapshot();
        assert_eq!(snap.packets_sent, 0);
        assert_eq!(snap.epoch, 1);
    }

    // NT3: advance_epoch stores snapshot.
    #[test]
    fn nt3_advance_stores_snapshot() {
        let mut t = tele();
        t.record_packet_sent(10);
        t.advance_epoch();
        assert_eq!(t.snapshot_count(), 1);
    }

    // NT4: latency histogram buckets are correct.
    #[test]
    fn nt4_latency_histogram_buckets() {
        let mut t = tele();
        t.record_rtt(5.0); // under_10ms
        t.record_rtt(20.0); // 10-50
        t.record_rtt(70.0); // 50-100
        t.record_rtt(200.0); // over_100
        let snap = t.collect_snapshot();
        assert_eq!(snap.latency_histogram.under_10ms, 1);
        assert_eq!(snap.latency_histogram.ms_10_to_50, 1);
        assert_eq!(snap.latency_histogram.ms_50_to_100, 1);
        assert_eq!(snap.latency_histogram.over_100ms, 1);
    }

    // NT5: histogram total matches sample count.
    #[test]
    fn nt5_histogram_total() {
        let mut h = LatencyHistogram::default();
        for ms in [1.0, 15.0, 60.0, 120.0] {
            h.record(ms);
        }
        assert_eq!(h.total(), 4);
    }

    // NT6: mean_estimate on empty histogram returns 0.
    #[test]
    fn nt6_mean_estimate_empty() {
        let h = LatencyHistogram::default();
        assert_eq!(h.mean_estimate_ms(), 0.0);
    }

    // NT7: mean_estimate for all-fast traffic is < 10 ms.
    #[test]
    fn nt7_mean_fast_traffic() {
        let mut h = LatencyHistogram::default();
        h.record(1.0);
        h.record(2.0);
        assert!(h.mean_estimate_ms() < 10.0);
    }

    // NT8: snapshot rolling window respects max_snapshots.
    #[test]
    fn nt8_rolling_window() {
        let mut t = NetworkTelemetry::new(3);
        for _ in 0..5 {
            t.advance_epoch();
        }
        assert_eq!(t.snapshot_count(), 3);
    }

    // NT9: set_circuits_active and set_peer_count reflected in snapshot.
    #[test]
    fn nt9_gauges_in_snapshot() {
        let mut t = tele();
        t.set_circuits_active(7);
        t.set_peer_count(12);
        let snap = t.collect_snapshot();
        assert_eq!(snap.circuits_active, 7);
        assert_eq!(snap.peer_count, 12);
    }

    // NT10: current_epoch advances on each advance_epoch call.
    #[test]
    fn nt10_epoch_counter() {
        let mut t = tele();
        assert_eq!(t.current_epoch(), 0);
        t.advance_epoch();
        t.advance_epoch();
        assert_eq!(t.current_epoch(), 2);
    }

    // NT11: recent_snapshots yields at most n entries.
    #[test]
    fn nt11_recent_snapshots() {
        let mut t = tele();
        for _ in 0..5 {
            t.advance_epoch();
        }
        assert_eq!(t.recent_snapshots(3).count(), 3);
    }

    // NT12: latency histogram resets after advance_epoch.
    #[test]
    fn nt12_histogram_reset() {
        let mut t = tele();
        t.record_rtt(5.0);
        t.advance_epoch();
        let snap = t.collect_snapshot();
        assert_eq!(snap.latency_histogram.total(), 0);
    }

    // NT14: snapshot stored by advance_epoch captures pre-reset epoch number.
    #[test]
    fn nt14_snapshot_epoch_matches() {
        let mut t = tele();
        t.advance_epoch(); // stores snapshot with epoch=0
        let snap = t.recent_snapshots(1).next().unwrap();
        assert_eq!(snap.epoch, 0);
        assert_eq!(t.current_epoch(), 1);
    }

    // NT13: bytes_sent and bytes_received accumulate correctly.
    #[test]
    fn nt13_byte_counters() {
        let mut t = tele();
        t.record_packet_sent(512);
        t.record_packet_sent(256);
        t.record_packet_received(1024);
        let snap = t.collect_snapshot();
        assert_eq!(snap.bytes_sent, 768);
        assert_eq!(snap.bytes_received, 1024);
        assert_eq!(snap.packets_sent, 2);
        assert_eq!(snap.packets_received, 1);
    }
}
