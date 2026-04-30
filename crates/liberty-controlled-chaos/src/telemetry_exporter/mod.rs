//! Telemetry exporter — produces privacy-safe metric snapshots that can be
//! forwarded to monitoring systems without leaking identifying information.
//!
//! Secrets (session keys, node IDs, peer IPs) are never included.  All peer
//! references are replaced with opaque 8-byte handles derived from a salt.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// TelemetryField
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum TelemetryField {
    Counter(u64),
    Gauge(f64),
    Label(String),
}

// ---------------------------------------------------------------------------
// TelemetrySnapshot
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ExportSnapshot {
    pub epoch: u64,
    pub fields: HashMap<String, TelemetryField>,
}

impl ExportSnapshot {
    pub fn new(epoch: u64) -> Self {
        Self {
            epoch,
            fields: HashMap::new(),
        }
    }

    pub fn set_counter(&mut self, key: &str, value: u64) {
        self.fields
            .insert(key.into(), TelemetryField::Counter(value));
    }

    pub fn set_gauge(&mut self, key: &str, value: f64) {
        self.fields.insert(key.into(), TelemetryField::Gauge(value));
    }

    pub fn set_label(&mut self, key: &str, value: &str) {
        self.fields
            .insert(key.into(), TelemetryField::Label(value.into()));
    }

    pub fn get_counter(&self, key: &str) -> Option<u64> {
        match self.fields.get(key) {
            Some(TelemetryField::Counter(v)) => Some(*v),
            _ => None,
        }
    }

    pub fn get_gauge(&self, key: &str) -> Option<f64> {
        match self.fields.get(key) {
            Some(TelemetryField::Gauge(v)) => Some(*v),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// TelemetryExporter
// ---------------------------------------------------------------------------

pub struct TelemetryExporter {
    /// Salt used to anonymise node IDs in exported data.
    anonymise_salt: [u8; 8],
    snapshots: Vec<ExportSnapshot>,
    max_snapshots: usize,
    exports_produced: u64,
}

impl TelemetryExporter {
    pub fn new(anonymise_salt: [u8; 8], max_snapshots: usize) -> Self {
        Self {
            anonymise_salt,
            snapshots: Vec::new(),
            max_snapshots,
            exports_produced: 0,
        }
    }

    /// Anonymise a 32-byte node ID to an 8-byte opaque handle.
    pub fn anonymise_node_id(&self, node_id: &[u8; 32]) -> u64 {
        // FNV-1a 64-bit, seeded with the salt.
        let seed = u64::from_le_bytes(self.anonymise_salt);
        let mut v: u64 = 0xcbf2_9ce4_8422_2325u64 ^ seed;
        for &b in node_id.iter() {
            v ^= b as u64;
            v = v.wrapping_mul(0x0000_0100_0000_01b3);
        }
        v
    }

    /// Record a snapshot.  Oldest entries are evicted when capacity is exceeded.
    pub fn push_snapshot(&mut self, snap: ExportSnapshot) {
        if self.snapshots.len() >= self.max_snapshots {
            self.snapshots.remove(0);
        }
        self.snapshots.push(snap);
        self.exports_produced += 1;
    }

    /// Build a summary snapshot from raw counters.
    pub fn build_snapshot(
        &self,
        epoch: u64,
        circuits_active: u64,
        peers_connected: u64,
        bytes_forwarded: u64,
        cover_ratio: f64,
    ) -> ExportSnapshot {
        let mut snap = ExportSnapshot::new(epoch);
        snap.set_counter("circuits_active", circuits_active);
        snap.set_counter("peers_connected", peers_connected);
        snap.set_counter("bytes_forwarded", bytes_forwarded);
        snap.set_gauge("cover_ratio", cover_ratio);
        snap.set_label("version", "alpha");
        snap
    }

    pub fn snapshots(&self) -> &[ExportSnapshot] {
        &self.snapshots
    }

    pub fn exports_produced(&self) -> u64 {
        self.exports_produced
    }

    pub fn latest(&self) -> Option<&ExportSnapshot> {
        self.snapshots.last()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn exporter() -> TelemetryExporter {
        TelemetryExporter::new([1, 2, 3, 4, 5, 6, 7, 8], 10)
    }

    // TE1: build_snapshot produces expected fields.
    #[test]
    fn te1_build_snapshot_fields() {
        let e = exporter();
        let s = e.build_snapshot(5, 3, 2, 1000, 0.1);
        assert_eq!(s.get_counter("circuits_active"), Some(3));
        assert_eq!(s.get_counter("peers_connected"), Some(2));
    }

    // TE2: push_snapshot increments exports_produced.
    #[test]
    fn te2_exports_produced() {
        let mut e = exporter();
        let s = e.build_snapshot(1, 0, 0, 0, 0.0);
        e.push_snapshot(s);
        assert_eq!(e.exports_produced(), 1);
    }

    // TE3: latest returns most recent snapshot.
    #[test]
    fn te3_latest() {
        let mut e = exporter();
        e.push_snapshot(e.build_snapshot(1, 0, 0, 0, 0.0));
        e.push_snapshot(e.build_snapshot(2, 5, 3, 100, 0.2));
        assert_eq!(e.latest().unwrap().epoch, 2);
    }

    // TE4: max_snapshots evicts oldest.
    #[test]
    fn te4_max_snapshots_evicts() {
        let mut e = TelemetryExporter::new([0; 8], 2);
        e.push_snapshot(e.build_snapshot(1, 0, 0, 0, 0.0));
        e.push_snapshot(e.build_snapshot(2, 0, 0, 0, 0.0));
        e.push_snapshot(e.build_snapshot(3, 0, 0, 0, 0.0));
        assert_eq!(e.snapshots().len(), 2);
        assert_eq!(e.snapshots()[0].epoch, 2);
    }

    // TE5: anonymise_node_id is deterministic.
    #[test]
    fn te5_anonymise_deterministic() {
        let e = exporter();
        let nid = [42u8; 32];
        assert_eq!(e.anonymise_node_id(&nid), e.anonymise_node_id(&nid));
    }

    // TE6: different node IDs produce different handles.
    #[test]
    fn te6_anonymise_different_ids() {
        let e = exporter();
        let a = e.anonymise_node_id(&[1u8; 32]);
        let b = e.anonymise_node_id(&[2u8; 32]);
        assert_ne!(a, b);
    }

    // TE7: cover_ratio gauge is stored.
    #[test]
    fn te7_cover_ratio_gauge() {
        let e = exporter();
        let s = e.build_snapshot(1, 0, 0, 0, 0.25);
        assert!((s.get_gauge("cover_ratio").unwrap() - 0.25).abs() < 1e-9);
    }

    // TE8: set_label stores string value.
    #[test]
    fn te8_set_label() {
        let mut s = ExportSnapshot::new(1);
        s.set_label("status", "ok");
        assert!(matches!(s.fields.get("status"), Some(TelemetryField::Label(v)) if v == "ok"));
    }

    // TE9: get_counter returns None for missing key.
    #[test]
    fn te9_missing_counter() {
        let s = ExportSnapshot::new(1);
        assert_eq!(s.get_counter("missing"), None);
    }

    // TE10: snapshots() returns all retained snapshots.
    #[test]
    fn te10_snapshots_slice() {
        let mut e = exporter();
        for i in 0..5 {
            e.push_snapshot(e.build_snapshot(i, 0, 0, 0, 0.0));
        }
        assert_eq!(e.snapshots().len(), 5);
    }
}
