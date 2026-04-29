# Session Checkpoint — Sprint 37: X25519 Key Exchange

**Date:** 2026-04-29  
**Branch:** main  
**Tests:** 860 passing (445 liberty-controlled-chaos, 407 liberty-node-cli, 7 liberty-shield, 1 doctest)  
**Clippy:** clean (`-D warnings`)

---

## What Was Built

| Phase | File | Change |
|---|---|---|
| 1 | `crypto/x25519.rs` | RFC 7748 X25519 from scratch (14 tests X1–X14) |
| 2 | `crypto/mod.rs` | Export X25519 public API symbols |
| 3 | `onion/handshake.rs` | Replace XOR DH with real X25519 (13 tests HS1–HS13) |
| 4 | `crypto/session_keys.rs` | Add `requires_rotation()` + `remaining_packets()` (3 new tests SK11–SK13) |
| 5 | `docs/runtime/x25519_key_exchange_sprint37.md` | Architecture doc |

---

## Key Design Decisions

1. **Canonical field reduction in `fe_reduce`**: Without a final conditional
   subtraction of p, `fe_sub(a, a)` produces `[p]` rather than `[0, …, 0]`.
   This caused `x25519(k, [0; 32])` to return a non-zero result, failing the
   low-order-point test.  Added a branchless detection (`above` flag) and
   subtraction at the end of every `fe_reduce` call.

2. **Private keys in `HopHandshakeParams`**: The struct now holds
   `initiator_private`/`responder_private` (X25519 private keys) instead of
   pre-computed "public keys".  Public keys are derived internally via
   `x25519_basepoint`, matching the real Diffie-Hellman protocol flow.

3. **Same-private-key no longer WeakSecret**: In the XOR scheme, equal inputs
   produced zero (trivially detectable).  X25519 with equal private keys gives
   `x25519(k, basepoint(k))` which is a valid non-zero shared secret — HS4 was
   updated to assert success.  `WeakSecret` now only fires for all-zero X25519
   output (genuine low-order public input).

4. **Rotation threshold at 87.5 %**: `requires_rotation()` fires at
   `(MAX_SEQUENCE / 8) * 7`.  This leaves 12.5 % headroom (~562 billion
   packets) for in-flight messages during renegotiation.

---

## Test Delta vs Sprint 36

| Module | Sprint 36 | Sprint 37 | Delta |
|---|---|---|---|
| `crypto/x25519` | — | 14 | +14 |
| `onion/handshake` | 10 | 13 | +3 |
| `crypto/session_keys` | 10 | 13 | +3 |
| **Workspace total** | **840** | **860** | **+20** |

---

## Commit

Staged files:
- `crates/liberty-controlled-chaos/src/crypto/x25519.rs`
- `crates/liberty-controlled-chaos/src/crypto/mod.rs`
- `crates/liberty-controlled-chaos/src/crypto/session_keys.rs`
- `crates/liberty-controlled-chaos/src/onion/handshake.rs`
- `docs/runtime/x25519_key_exchange_sprint37.md`
- `docs/runtime/session_checkpoint_sprint37_x25519.md`

Message: `Sprint 37: add X25519 key exchange foundation`

---

## Next Sprint Suggestions

- Add constant-time guarantees to field arithmetic (particularly `fe_mul` and
  the ladder) — currently safe only for determinism, not side-channel
  resistance.
- Implement NTor handshake (RFC 8840) which adds forward secrecy via
  per-session ephemeral keys and uses the node's long-term identity key.
- Wire `requires_rotation()` into the relay pipeline to trigger automatic
  session renegotiation before nonce exhaustion.
