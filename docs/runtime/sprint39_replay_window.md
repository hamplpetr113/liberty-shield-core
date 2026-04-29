# Sprint 39 — Replay Window and Session Lifecycle Hardening

**NON-PRODUCTION IMPLEMENTATION**

Sprint 39 adds four defensive layers to protect long-running onion circuits against
replay attacks, state confusion, and unbounded memory growth.

---

## Phase 1 — Bitmap Sliding Replay Window (`crypto/bitmap_window.rs`)

### Motivation

`decrypt_packet_in_order` (Sprint 38) enforces strictly-increasing sequences,
rejecting any out-of-order delivery.  Real networks reorder packets; a session
layer needs a window that accepts late-arriving packets within a reasonable range
while still blocking true replays.

### Design

```
bitmap: u128   (bit k = sequence max_seen - k was accepted)
max_seen: Option<u64>
```

**Window size:** 128 packets (one `u128`).  
**Lookup:** O(1) — a shift and a bit-test.  
**Memory:** 24 bytes per session (no heap).

When `seq > max_seen`:  
- shift = `seq − max_seen`  
- `bitmap = (bitmap << shift) | 1` — old entries slide right; new max occupies bit 0.  
- If shift ≥ 128, the entire prior window is evicted: `bitmap = 1`.

When `seq ≤ max_seen`:  
- `offset = max_seen − seq`  
- offset ≥ 128 → `TooOld`  
- bit at `offset` already set → `Replay`  
- otherwise: set the bit and accept.

### Integration into `SessionKeys`

New method:

```rust
pub fn decrypt_packet_with_window(
    &mut self,
    aad: &[u8],
    sequence: u64,
    ciphertext_and_tag: &[u8],
) -> Result<Vec<u8>, SessionError>
```

Maps both `WindowError::Replay` and `WindowError::TooOld` to
`SessionError::ReplayDetected`.  The window is reset by `rotate()` /
`rotate_keys()` / `complete_rekey()`.

### Tests (SW1–SW6 in `bitmap_window.rs`)

| Test | Scenario |
|---|---|
| SW1 | First packet always accepted |
| SW2 | Duplicate → `Replay` |
| SW3 | Sequence 128+ behind max → `TooOld`; sequence 127 behind → accepted |
| SW4 | Out-of-order within window accepted; re-submission rejected |
| SW5 | Large forward jump (≥128) clears prior window |
| SW6 | `reset()` clears state; previously-seen sequence is fresh again |

---

## Phase 2 — Persistent Rekey Nonce Store (`onion/rekey_guard.rs`)

### Motivation

The Sprint 38 `RekeyGuard` uses an unbounded `HashSet`.  Under a slow-replay
attack, an adversary can inflate memory indefinitely by sending unique nonces.

### Design

```rust
pub struct RekeyNonceStore {
    seen: BTreeSet<u64>,
    max_size: usize,
}
```

`check_and_record(nonce)` evicts the **numerically smallest** entry when the
set is full.  This is a conservative policy: real nonces are random, so the
evicted entry is also the least likely to be replayed against.

### Tests (RG1–RG3 in `rekey_guard.rs`)

| Test | Scenario |
|---|---|
| RG1 | Fresh nonce accepted; duplicate rejected |
| RG2 | Eviction removes smallest entry; re-inserted entries cause new evictions |
| RG3 | Zero-capacity store: every insert succeeds once (no eviction loop) |

---

## Phase 3 — Session Lifecycle State (`crypto/session_keys.rs`)

### Motivation

Code that triggers a rekey needs to signal "do not start a new rekey while one
is in progress" without adding external state.  An expired session should be
identifiable without inspecting the sequence number.

### Design

```rust
pub enum SessionState { Active, Rekeying, Expired }
```

Added to `SessionKeys`:

| Method | Description |
|---|---|
| `state() -> SessionState` | Current state |
| `is_usable() -> bool` | `true` when `Active` or `Rekeying` |
| `begin_rekey()` | `Active → Rekeying` |
| `complete_rekey(new_send, new_recv)` | Calls `rotate()`, then `Rekeying → Active` |
| `expire()` | Any → `Expired` |

`rotate()` and `rotate_keys()` do **not** change the state; they are low-level
key-material operations.  State transitions are the caller's responsibility.

### Tests (SL1–SL3 in `session_keys.rs`)

| Test | Scenario |
|---|---|
| SL1 | Initial state is `Active`; `is_usable()` true |
| SL2 | `begin_rekey()` → `Rekeying`; `expire()` → `Expired`; `is_usable()` false |
| SL3 | `complete_rekey()` resets keys, resets sequence, returns to `Active` |

---

## Phase 4 — Transport Replay Filter (`transport/replay_filter.rs`)

### Motivation

The AEAD-level replay protection requires key material to detect replays.  A
transport-layer filter rejects obvious duplicates before AEAD decryption,
reducing CPU usage under replay floods.

### Design

```rust
pub struct TransportReplayFilter {
    capacity: usize,
    seen: HashSet<u64>,
    order: VecDeque<u64>,
}
```

LRU-style eviction: when the set is full, the entry inserted furthest in the
past is removed.  Packet IDs (e.g., sequence numbers or composite keys) are
`u64`.

`RelayPipeline` now maintains a `HashMap<u64, TransportReplayFilter>` (one per
circuit, capacity 512) and checks the filter **before** the `ReplayDetector`
window and before AEAD decryption.

### Tests (TR1–TR3 in `replay_filter.rs`)

| Test | Scenario |
|---|---|
| TR1 | Fresh IDs accepted; duplicates rejected |
| TR2 | Eviction at capacity removes oldest entry |
| TR3 | Zero-capacity filter: no eviction loop; behaves correctly |

---

## Test Coverage Summary (Sprint 39 additions)

| Module | New Tests | Prefix |
|---|---|---|
| `crypto/bitmap_window` | 6 | SW1–SW6 |
| `onion/rekey_guard` | 3 | RG1–RG3 |
| `crypto/session_keys` | 6 | DW1–DW3, SL1–SL3 |
| `transport/replay_filter` | 3 | TR1–TR3 |
| **Subtotal** | **18** | |

**Workspace totals after Sprint 39:**

| Crate | Tests |
|---|---|
| `liberty-controlled-chaos` | 476 |
| `liberty-node-cli` | 407 |
| `liberty-shield` | 7 |
| doctests | 1 |
| **Total** | **891** |

---

## Security Notes

- `BitmapReplayWindow` is in-memory; it does not survive process restart.
- `RekeyNonceStore` uses numeric-order eviction; production use should prefer
  time-based eviction with a nonce timestamp.
- `TransportReplayFilter` is keyed by raw sequence number; a production
  implementation should key by `(circuit_id, sequence)` to avoid cross-circuit
  collisions.
- All implementations are **NON-PRODUCTION**: for architectural validation only.
