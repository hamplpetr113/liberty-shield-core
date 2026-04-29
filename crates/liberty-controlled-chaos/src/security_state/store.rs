//! Append-only binary journal for persistent security state.
//!
//! `SecurityStateStore` writes fixed-size 25-byte entries to a log file.
//! On restart, `load_all` replays the log to reconstruct in-memory state.
//!
//! **Crash safety:** entries are fixed-size; if the file length is not a
//! multiple of `SecurityStateEntry::BYTE_SIZE`, the trailing partial entry
//! is silently discarded during `load_all`.
//!
//! **Durability:** writes reach the OS page cache but are not `fsync`'d per
//! call.  Call `sync()` periodically for stronger durability guarantees.
//! This is a NON-PRODUCTION implementation.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::BitmapReplayWindow;
use crate::onion::RekeyNonceStore;
use crate::transport::TransportReplayFilter;

use super::types::{
    ENTRY_REKEY_NONCE_SEEN, ENTRY_SESSION_REPLAY_UPDATE, ENTRY_TRANSPORT_PACKET_SEEN,
    SecurityStateEntry,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from `SecurityStateStore` operations.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying I/O failure.
    Io(std::io::Error),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "security state I/O error: {e}"),
        }
    }
}

impl From<std::io::Error> for StoreError {
    fn from(e: std::io::Error) -> Self {
        StoreError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Append-only log of security state events.
///
/// One `SecurityStateStore` corresponds to one on-disk log file.  Multiple
/// components (relay pipeline, rekey handler) can share a single store
/// instance.
pub struct SecurityStateStore {
    path: PathBuf,
    file: File,
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

impl SecurityStateStore {
    /// Open (or create) the log at `path` for appending.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }

    /// Append a raw entry to the log.
    fn append(&mut self, entry: SecurityStateEntry) -> Result<(), StoreError> {
        self.file.write_all(&entry.to_bytes())?;
        Ok(())
    }

    /// Record that `sequence` on `circuit_id` was fully accepted by the
    /// session layer (after AEAD authentication).
    pub fn record_packet(&mut self, circuit_id: u64, sequence: u64) -> Result<(), StoreError> {
        self.append(SecurityStateEntry {
            entry_type: ENTRY_SESSION_REPLAY_UPDATE,
            circuit_id,
            sequence,
            timestamp: now_secs(),
        })
    }

    /// Record that a rekey request nonce `nonce` was processed by the
    /// responder.  `circuit_id` is stored as 0 (nonces are global).
    pub fn record_rekey_nonce(&mut self, nonce: u64) -> Result<(), StoreError> {
        self.append(SecurityStateEntry {
            entry_type: ENTRY_REKEY_NONCE_SEEN,
            circuit_id: 0,
            sequence: nonce,
            timestamp: now_secs(),
        })
    }

    /// Record that `sequence` on `circuit_id` was seen by the transport-layer
    /// filter (before AEAD decryption).
    pub fn record_transport_packet(
        &mut self,
        circuit_id: u64,
        sequence: u64,
    ) -> Result<(), StoreError> {
        self.append(SecurityStateEntry {
            entry_type: ENTRY_TRANSPORT_PACKET_SEEN,
            circuit_id,
            sequence,
            timestamp: now_secs(),
        })
    }

    /// Flush all pending writes to the OS (does not call `fsync`).
    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.file.flush()?;
        Ok(())
    }

    /// Request the OS to durably write the file to disk (`fsync`).
    pub fn sync(&self) -> Result<(), StoreError> {
        self.file.sync_data()?;
        Ok(())
    }

    /// Path of the backing log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read all valid entries from `path`.
    ///
    /// If the file does not exist, returns an empty `Vec`.
    /// Trailing bytes that do not form a complete entry are discarded
    /// (crash-safe partial-write recovery).
    pub fn load_all(path: impl AsRef<Path>) -> Result<Vec<SecurityStateEntry>, StoreError> {
        let mut file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(StoreError::Io(e)),
        };
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        let n = data.len() / SecurityStateEntry::BYTE_SIZE;
        let entries = (0..n)
            .map(|i| {
                let start = i * SecurityStateEntry::BYTE_SIZE;
                let chunk: &[u8; SecurityStateEntry::BYTE_SIZE] = data
                    [start..start + SecurityStateEntry::BYTE_SIZE]
                    .try_into()
                    .unwrap();
                SecurityStateEntry::from_bytes(chunk)
            })
            .collect();
        Ok(entries)
    }
}

// ---------------------------------------------------------------------------
// Startup restore helpers
// ---------------------------------------------------------------------------

/// Reconstruct a `BitmapReplayWindow` for `circuit_id` from a set of log entries.
///
/// Filters `ENTRY_SESSION_REPLAY_UPDATE` entries matching `circuit_id` and
/// replays them into a fresh window.  Entries that fall outside the 128-packet
/// window are silently discarded (they are too old to matter for replay protection).
pub fn restore_replay_window(
    entries: &[SecurityStateEntry],
    circuit_id: u64,
) -> BitmapReplayWindow {
    let mut window = BitmapReplayWindow::new();
    for e in entries {
        if e.entry_type == ENTRY_SESSION_REPLAY_UPDATE && e.circuit_id == circuit_id {
            let _ = window.check_and_record(e.sequence);
        }
    }
    window
}

/// Reconstruct a `RekeyNonceStore` with `max_size` capacity from log entries.
///
/// Filters `ENTRY_REKEY_NONCE_SEEN` entries and replays them.  If the log
/// contains more entries than `max_size`, the store's own eviction policy
/// (smallest-first) applies.
pub fn restore_nonce_store(entries: &[SecurityStateEntry], max_size: usize) -> RekeyNonceStore {
    let mut store = RekeyNonceStore::new(max_size);
    for e in entries {
        if e.entry_type == ENTRY_REKEY_NONCE_SEEN {
            store.check_and_record(e.sequence);
        }
    }
    store
}

/// Reconstruct a `TransportReplayFilter` for `circuit_id` from log entries.
///
/// Filters `ENTRY_TRANSPORT_PACKET_SEEN` entries matching `circuit_id` and
/// replays them into a fresh filter with the given `capacity`.
pub fn restore_transport_filter(
    entries: &[SecurityStateEntry],
    circuit_id: u64,
    capacity: usize,
) -> TransportReplayFilter {
    let mut filter = TransportReplayFilter::new(capacity);
    for e in entries {
        if e.entry_type == ENTRY_TRANSPORT_PACKET_SEEN && e.circuit_id == circuit_id {
            filter.check_and_record(e.sequence);
        }
    }
    filter
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;

    use super::*;
    use crate::security_state::types::{
        ENTRY_REKEY_NONCE_SEEN, ENTRY_SESSION_REPLAY_UPDATE, ENTRY_TRANSPORT_PACKET_SEEN,
    };

    fn test_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("liberty_shield_ss_{name}.log"));
        p
    }

    fn cleanup(p: &Path) {
        let _ = std::fs::remove_file(p);
    }

    // SS1: write several entries; load_all reads them back correctly
    #[test]
    fn ss1_log_write_read() {
        let path = test_path("ss1");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_packet(1, 42).unwrap();
        store.record_rekey_nonce(99).unwrap();
        store.record_transport_packet(1, 42).unwrap();
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].entry_type, ENTRY_SESSION_REPLAY_UPDATE);
        assert_eq!(entries[0].circuit_id, 1);
        assert_eq!(entries[0].sequence, 42);
        assert_eq!(entries[1].entry_type, ENTRY_REKEY_NONCE_SEEN);
        assert_eq!(entries[1].circuit_id, 0);
        assert_eq!(entries[1].sequence, 99);
        assert_eq!(entries[2].entry_type, ENTRY_TRANSPORT_PACKET_SEEN);
        assert_eq!(entries[2].circuit_id, 1);
        assert_eq!(entries[2].sequence, 42);

        cleanup(&path);
    }

    // SS2: restored replay window recognises previously-seen sequences
    #[test]
    fn ss2_replay_state_restore() {
        let path = test_path("ss2");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_packet(7, 100).unwrap();
        store.record_packet(7, 50).unwrap();
        store.record_packet(7, 99).unwrap();
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        let mut window = restore_replay_window(&entries, 7);

        assert_eq!(window.max_seen(), Some(100));
        // Previously-seen sequences are rejected as replays.
        assert!(window.check_and_record(100).is_err());
        assert!(window.check_and_record(50).is_err());
        assert!(window.check_and_record(99).is_err());
        // A fresh sequence is accepted.
        assert!(window.check_and_record(101).is_ok());

        cleanup(&path);
    }

    // SS3: restored nonce store rejects previously-processed nonces
    #[test]
    fn ss3_rekey_nonce_persistence() {
        let path = test_path("ss3");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_rekey_nonce(111).unwrap();
        store.record_rekey_nonce(222).unwrap();
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        let mut nstore = restore_nonce_store(&entries, 1000);

        assert!(!nstore.check_and_record(111)); // replay
        assert!(!nstore.check_and_record(222)); // replay
        assert!(nstore.check_and_record(333)); // fresh

        cleanup(&path);
    }

    // SS4: partial entry written during simulated crash is discarded on restore
    #[test]
    fn ss4_crash_recovery() {
        let path = test_path("ss4");
        cleanup(&path);

        // Write two complete entries.
        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_packet(1, 10).unwrap();
        store.record_packet(1, 20).unwrap();
        drop(store);

        // Simulate a crash by appending a partial entry (12 bytes < 25).
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0x01u8; 12]).unwrap();
        drop(file);

        // load_all must discard the partial entry and return only the 2 complete ones.
        let entries = SecurityStateStore::load_all(&path).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].sequence, 10);
        assert_eq!(entries[1].sequence, 20);

        cleanup(&path);
    }

    // SS5: load_all on non-existent file returns empty vec
    #[test]
    fn ss5_missing_file_returns_empty() {
        let path = test_path("ss5_nonexistent_xyz");
        cleanup(&path);
        let entries = SecurityStateStore::load_all(&path).unwrap();
        assert!(entries.is_empty());
    }

    // SS6: restore_replay_window ignores entries for other circuits
    #[test]
    fn ss6_restore_isolates_by_circuit() {
        let path = test_path("ss6");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_packet(1, 10).unwrap();
        store.record_packet(2, 20).unwrap(); // different circuit
        store.record_packet(1, 11).unwrap();
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        let mut w1 = restore_replay_window(&entries, 1);
        let mut w2 = restore_replay_window(&entries, 2);

        // Circuit 1 saw 10 and 11.
        assert!(w1.check_and_record(10).is_err()); // replay
        assert!(w1.check_and_record(11).is_err()); // replay
        assert!(w1.check_and_record(20).is_ok()); // fresh for circuit 1

        // Circuit 2 saw only 20.
        assert!(w2.check_and_record(20).is_err()); // replay
        assert!(w2.check_and_record(10).is_ok()); // fresh for circuit 2

        cleanup(&path);
    }

    // SS7: restore_nonce_store with capacity less than log entries evicts oldest
    #[test]
    fn ss7_nonce_restore_respects_capacity() {
        let path = test_path("ss7");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        for n in 1u64..=10 {
            store.record_rekey_nonce(n).unwrap();
        }
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        // Capacity 5; only 5 nonces should survive.
        let nstore = restore_nonce_store(&entries, 5);
        assert_eq!(nstore.len(), 5);

        cleanup(&path);
    }

    // SS8: restore_transport_filter restores correct filter state
    #[test]
    fn ss8_transport_filter_restore() {
        let path = test_path("ss8");
        cleanup(&path);

        let mut store = SecurityStateStore::open(&path).unwrap();
        store.record_transport_packet(3, 100).unwrap();
        store.record_transport_packet(3, 200).unwrap();
        drop(store);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        let mut filter = restore_transport_filter(&entries, 3, 4096);

        // Both sequences were seen — duplicates rejected.
        assert!(!filter.check_and_record(100));
        assert!(!filter.check_and_record(200));
        // A fresh sequence is accepted.
        assert!(filter.check_and_record(300));

        cleanup(&path);
    }

    // SS9: SecurityStateEntry round-trips through to_bytes / from_bytes
    #[test]
    fn ss9_entry_serialisation_roundtrip() {
        let e = SecurityStateEntry {
            entry_type: ENTRY_SESSION_REPLAY_UPDATE,
            circuit_id: 0xDEAD_BEEF_0102_0304,
            sequence: 0xCAFE_BABE_DEAD_1234,
            timestamp: 1_700_000_000,
        };
        let bytes = e.to_bytes();
        let e2 = SecurityStateEntry::from_bytes(&bytes);
        assert_eq!(e, e2);
    }

    // SS10: appending to an existing log extends it without corruption
    #[test]
    fn ss10_append_to_existing_log() {
        let path = test_path("ss10");
        cleanup(&path);

        // First session.
        let mut s1 = SecurityStateStore::open(&path).unwrap();
        s1.record_packet(1, 1).unwrap();
        s1.record_packet(1, 2).unwrap();
        drop(s1);

        // Second session appends to the same file.
        let mut s2 = SecurityStateStore::open(&path).unwrap();
        s2.record_packet(1, 3).unwrap();
        drop(s2);

        let entries = SecurityStateStore::load_all(&path).unwrap();
        assert_eq!(entries.len(), 3);
        let seqs: Vec<u64> = entries.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3]);

        cleanup(&path);
    }
}
