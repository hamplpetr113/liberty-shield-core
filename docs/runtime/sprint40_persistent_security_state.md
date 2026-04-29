# Sprint 40 — Persistent Security State

**NON-PRODUCTION IMPLEMENTATION**

Sprint 40 adds an append-only binary journal that survives node restart,
ensuring that replay protection and rekey nonce deduplication cannot be
bypassed by restarting the process.

---

## Problem

Before Sprint 40, all security state was held in memory:

| Component | State lost on restart |
|---|---|
| `BitmapReplayWindow` | Window cleared → old sequences accepted again |
| `RekeyNonceStore` | Nonces forgotten → replayed rekey requests accepted |
| `TransportReplayFilter` | Filter cleared → transport duplicates accepted |

An adversary who can force a node restart could replay captured packets.

---

## Solution: `SecurityStateStore`

A fixed-record append-only journal at `security_state/`.

### File format

`security_state.log` — sequence of fixed-size 25-byte entries:

```
 0        1        9        17       25
 ┌────────┬────────────────┬────────────────┬────────────────┐
 │  type  │   circuit_id   │    sequence    │   timestamp    │
 │ 1 byte │  8 bytes LE    │  8 bytes LE    │  8 bytes LE    │
 └────────┴────────────────┴────────────────┴────────────────┘
```

### Entry types

| Constant | Value | Meaning |
|---|---|---|
| `ENTRY_SESSION_REPLAY_UPDATE` | 1 | Packet accepted after AEAD decrypt |
| `ENTRY_REKEY_NONCE_SEEN` | 2 | Rekey nonce processed by responder |
| `ENTRY_TRANSPORT_PACKET_SEEN` | 3 | Packet accepted by transport filter |

### Crash safety

Entry size is fixed (25 bytes).  `load_all` computes
`file_length / 25` to find the number of complete entries and silently
discards any trailing partial entry — the result of an in-flight write
at the moment of a crash.

---

## Components Added

### Phase 1 — `security_state/` module

| File | Contents |
|---|---|
| `security_state/types.rs` | `SecurityStateEntry` (25-byte layout), entry type constants |
| `security_state/store.rs` | `SecurityStateStore`, `StoreError`, restore helper functions |
| `security_state/mod.rs` | Public API re-exports |

**`SecurityStateStore` API:**

| Method | Description |
|---|---|
| `open(path)` | Open or create the log for appending |
| `record_packet(circuit_id, seq)` | Write `SESSION_REPLAY_UPDATE` entry |
| `record_rekey_nonce(nonce)` | Write `REKEY_NONCE_SEEN` entry |
| `record_transport_packet(circuit_id, seq)` | Write `TRANSPORT_PACKET_SEEN` entry |
| `load_all(path)` | Read all valid entries; handles missing file and partial writes |
| `flush()` | Flush to OS buffer |
| `sync()` | `fsync` for durable write |

### Phase 2 — `BitmapReplayWindow` snapshot support

New types in `crypto/bitmap_window.rs`:

```rust
pub struct ReplayWindowSnapshot { pub max_seen: u64, pub bitmap: u128 }
```

New methods:

| Method | Description |
|---|---|
| `snapshot() -> Option<ReplayWindowSnapshot>` | Capture current state; `None` if empty |
| `restore(snap: ReplayWindowSnapshot)` | Overwrite state from snapshot |

### Phase 3 — Rekey nonce persistence

`restore_nonce_store(entries, max_size) -> RekeyNonceStore` reconstructs
the `RekeyNonceStore` from log entries on startup.  If the log contains
more entries than `max_size`, the store's own smallest-first eviction
policy applies during restore.

### Phase 4 — Transport replay persistence

`restore_transport_filter(entries, circuit_id, capacity) -> TransportReplayFilter`
reconstructs the `TransportReplayFilter` for one circuit from
`TRANSPORT_PACKET_SEEN` entries.  Bounded to 4096 entries per circuit in
production configurations.

### Phase 5 — `RelayPipeline` integration

`RelayPipeline` now has an optional `SecurityStateStore`:

```rust
RelayPipeline::new()                         // no persistence
RelayPipeline::with_security_state(store)    // with persistence
```

On each `receive_cell` call:
1. Transport filter check → writes `TRANSPORT_PACKET_SEEN` if passed
2. Sequence window check (existing)
3. AEAD decrypt → writes `SESSION_REPLAY_UPDATE` if accepted

New method `record_rekey_nonce(nonce)` for callers to persist rekey events.

### Phase 6 — Startup restore pattern

```rust
// Load all persisted entries.
let entries = SecurityStateStore::load_all("security_state.log")?;

// Reconstruct per-circuit state.
let window  = restore_replay_window(&entries, circuit_id);
let nonces  = restore_nonce_store(&entries, 10_000);
let filter  = restore_transport_filter(&entries, circuit_id, 4096);

// Open for appending going forward.
let store   = SecurityStateStore::open("security_state.log")?;
let pipeline = RelayPipeline::with_security_state(store);
```

---

## Security Guarantees

| Guarantee | Status |
|---|---|
| Replay sequences rejected across restart | ✓ (SESSION_REPLAY_UPDATE) |
| Rekey nonce replay across restart blocked | ✓ (REKEY_NONCE_SEEN) |
| Transport duplicate rejection across restart | ✓ (TRANSPORT_PACKET_SEEN) |
| Crash-safe partial-write recovery | ✓ (fixed record size) |
| Append-only journal (no entry overwrite) | ✓ |

---

## Limitations (NON-PRODUCTION)

- **No `fsync` per write.** OS crash may lose last few entries.  Call
  `store.sync()` periodically; default is OS-buffer-level durability only.
- **Unbounded log growth.** No compaction or rotation is implemented.  In
  production, logs should be rotated and old entries pruned.
- **No file locking.** Multiple writers to the same log can corrupt it.
  One store per process is the expected usage.
- **Sequence numbers only — no timestamps for eviction.** The
  `RekeyNonceStore` evicts the numerically smallest nonce, not the
  oldest.  Production should use time-based eviction.
- **Transport filter uses raw sequence as key.** Different circuits with
  the same sequence number are tracked independently — no cross-circuit
  collision — but a production system should use a `(circuit_id, seq)`
  composite key at the transport layer.

---

## Test Coverage (Sprint 40 additions)

| File | Tests | Prefix |
|---|---|---|
| `crypto/bitmap_window.rs` | 2 | SW7–SW8 |
| `security_state/store.rs` | 10 | SS1–SS10 |
| `encrypted_relay/pipeline.rs` | 1 | RP7 |
| **Subtotal** | **13** | |

**Workspace totals after Sprint 40:**

| Crate | Tests |
|---|---|
| `liberty-controlled-chaos` | 489 |
| `liberty-node-cli` | 407 |
| `liberty-shield` | 7 |
| doctests | 1 |
| **Total** | **904** |
