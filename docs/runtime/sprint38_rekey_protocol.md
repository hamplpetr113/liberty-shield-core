# Sprint 38 — Session Rekey Protocol and Crypto Hardening

**NON-PRODUCTION IMPLEMENTATION**

Sprint 38 extends the cryptographic session layer with forward-secret session
renegotiation, stricter replay detection, ephemeral keypair support, and
nonce-exhaustion guardrails.

---

## Overview

Long-running onion circuits need a way to refresh session keys without
tearing down the circuit.  Sprint 38 introduces:

1. **Automatic key rotation** — `SessionKeys` gains `rotate_keys()` and
   `decrypt_packet_in_order()` for the protocol layer to enforce forward
   secrecy and reject replays.
2. **Rekey handshake** — a one-round X25519 ephemeral DH exchange produces
   fresh `SessionKeys` independent of the original session material.
3. **Ephemeral keypair** — `EphemeralKeypair` / `generate_ephemeral_from_seed` /
   `derive_ephemeral_shared` as forward-secrecy building blocks.

---

## Session Rotation (`crypto/session_keys.rs`)

### New API

| Method | Description |
|---|---|
| `rotate_keys(new_send, new_recv)` | Replace keys; reset `send_sequence` and `last_recv_sequence` |
| `decrypt_packet_in_order(aad, seq, ct)` | Decrypt and enforce strictly-increasing sequence numbers |
| `requires_rotation() -> bool` | True when `send_sequence ≥ 87.5 % × MAX_SEQUENCE` |
| `remaining_packets() -> u64` | Packets remaining before `NonceExhausted` |

### New Error Variant

```rust
SessionError::ReplayDetected
```

Returned by `decrypt_packet_in_order` when `sequence <= last_recv_sequence`.
The plain `decrypt_packet` remains unchanged (`&self`, no order tracking).

### Rotation Threshold

```
rotation threshold = (MAX_SEQUENCE / 8) × 7
                   = 246290604621823   (≈ 87.5 % of 2^48 − 1)
remaining at trigger = ≈ 35 trillion packets
```

This leaves 12.5 % headroom for packets in-flight during renegotiation.

---

## Rekey Protocol (`onion/rekey.rs`)

### Message Flow

```
Initiator                              Responder
  │                                        │
  │─ RekeyRequest { initiator_pub, nonce }─►│
  │                                        │  RekeyGuard::check_and_record(nonce)
  │                                        │  eph_shared = x25519(resp_priv, init_pub)
  │                                        │  (k_recv, k_send) = HKDF(shared, ctx)
  │◄─ RekeyResponse { responder_pub, nonce }│
  │                                        │
  │  eph_shared = x25519(init_priv, resp_pub)
  │  (k_send, k_recv) = HKDF(shared, ctx)
```

**DH symmetry:** `x25519(init_priv, resp_pub) == x25519(resp_priv, init_pub)` ✓

**Key mirroring:**
- Initiator session: `SessionKeys::new(k_send, k_recv)`
- Responder session: `SessionKeys::new(k_recv, k_send)`
- `init.send_key == resp.recv_key` ✓
- `init.recv_key == resp.send_key` ✓

### HKDF Context

```
context = "liberty-shield:rekey:" ‖ nonce(16 bytes)
```

Binding the nonce into the context ensures that even if the same ephemeral
keys were reused (they shouldn't be), the derived keys are unique per exchange.

### Structures

| Type | Role |
|---|---|
| `RekeyRequest` | Sent by initiator: `initiator_pub`, `nonce` |
| `RekeyResponse` | Sent by responder: `responder_pub`, `request_nonce` |
| `RekeyResult` | Holds new `SessionKeys` for one party |
| `RekeyInitiator` | Opaque state held by initiator between request and response |
| `RekeyGuard` | Anti-replay nonce tracker (HashSet) for the responder |

### Functions

| Function | Description |
|---|---|
| `initiate_rekey(seed, nonce)` | Build request + initiator state |
| `handle_rekey_request(guard, req, seed)` | Process request; return response + new session |
| `finalize_rekey(state, response)` | Verify nonce echo; derive initiator's new session |

---

## Ephemeral Keypair (`crypto/x25519.rs`)

```rust
pub struct EphemeralKeypair { pub public: [u8; 32], /* private: [u8; 32] */ }

pub fn generate_ephemeral_from_seed(seed: &[u8; 32]) -> EphemeralKeypair
pub fn derive_ephemeral_shared(our: &EphemeralKeypair, peer_pub: &[u8; 32]) -> [u8; 32]
```

In production, `seed` must come from a CSPRNG.  The private scalar is kept
opaque; the only way to use it is through `derive_ephemeral_shared`.

---

## Forward Secrecy Properties

- Each rekey exchange uses freshly generated ephemeral keys.
- Compromising the long-term circuit key **does not** compromise traffic
  protected by a prior rekey session (the ephemeral private keys are
  discarded after `finalize_rekey` / `handle_rekey_request` return).
- `is_zero_shared_secret` is checked after every DH to reject low-order
  public-key inputs.

---

## Security Notes

- **NON-PRODUCTION**: no formal side-channel audit.
- `RekeyGuard` is in-memory only; a relay restart resets its seen-nonce set.
  Production implementations must persist seen nonces or use timestamps with
  a tight validity window.
- The `decrypt_packet_in_order` strictly-increasing check rejects gaps.
  For protocols that tolerate reordering, use the underlying `decrypt_packet`
  with a sliding-window `ReplayDetector` instead.

---

## Test Coverage

| Suite | Tests | Range |
|---|---|---|
| `crypto/session_keys` | 19 | SK1–SK16, AE1–AE3 |
| `crypto/x25519` (ephemeral) | 3 | FS1–FS3 |
| `onion/rekey` | 4 | RK1–RK4 |
| **Sprint 38 new** | **13** | |
| **Workspace total** | **873** | |
