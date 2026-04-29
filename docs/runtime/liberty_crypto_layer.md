# Liberty Shield Crypto Layer

**Sprint 31-36 — NON-PRODUCTION IMPLEMENTATION**

This document describes the cryptographic architecture introduced in Sprint 31-36:
a zero-external-dependency crypto layer built from RFC-conformant primitives,
a fixed-size cell framing format, extended replay protection, encrypted relay
cells, a per-hop handshake framework, and large-scale simulation validation.

---

## Architecture Overview

```
Application data
      │
      ▼
 SessionKeys (send_key / recv_key / send_sequence)
      │  encrypt_packet / decrypt_packet
      ▼
 ChaCha20-Poly1305 AEAD  ←── HKDF-SHA256 key derivation
      │
      ▼
 EncryptedRelayCell (sequence ‖ ciphertext+tag)
      │  AAD = circuit_id(8 LE) ‖ stream_id(8 LE)
      ▼
 RelayPipeline
      │  replay-check first → ReplayDetector
      │  then decrypt
      ▼
 Fixed-size FramedCell  (512 bytes on wire)
      │  version(1) | payload_len(4 LE u32) | payload | zero-padding
      ▼
 Onion handshake layer
      │  per-hop HKDF key derivation
      ▼
 Wire / MeshSimulator
```

---

## Primitive Modules (`crates/liberty-controlled-chaos/src/crypto/`)

All primitives are implemented from scratch using only `std`. No external crates.

### SHA-256 (`sha256.rs`)

FIPS 180-4 compliant. Provides:

| Function | Description |
|---|---|
| `sha256(data) -> [u8; 32]` | Standard SHA-256 hash |
| `hmac_sha256(key, data) -> [u8; 32]` | HMAC-SHA256 (RFC 2104) |

Key details: 64-byte block size, big-endian word representation, 64 round constants.

### ChaCha20 (`chacha20.rs`)

RFC 8439 §2.1, 20-round variant. Provides:

| Function | Description |
|---|---|
| `chacha20_xor(key, nonce, counter, data)` | Encrypt/decrypt a byte slice |
| `chacha20_key_stream_block0(key, nonce)` | Generate keystream block at counter=0 (OTK derivation) |

State: 4-word constant ‖ 8-word key ‖ 1-word counter ‖ 3-word nonce. Each block = 20 rounds of quarter-round operations on a 16-word state.

### Poly1305 (`poly1305.rs`)

RFC 8439 §2.5, GF(2^130-5) authenticator. Provides:

| Function | Description |
|---|---|
| `poly1305_mac(key: &[u8; 32], data) -> [u8; 16]` | Compute authentication tag |
| `ct_eq_16(a, b) -> bool` | Constant-time 16-byte comparison |

Implementation: 5×26-bit limbs to avoid 64-bit overflow; clamp `r` per spec; little-endian serialization.

### ChaCha20-Poly1305 AEAD (`aead.rs`)

RFC 8439 §2.8. Provides:

| Function | Description |
|---|---|
| `aead_seal(key, nonce, aad, plaintext) -> Vec<u8>` | Encrypt and authenticate; returns ciphertext ‖ 16-byte tag |
| `aead_open(key, nonce, aad, ct_and_tag) -> Result<Vec<u8>, AeadError>` | Verify tag then decrypt |

MAC construction: `mac_data = aad ‖ pad(aad) ‖ ciphertext ‖ pad(ct) ‖ len(aad) as u64 LE ‖ len(ct) as u64 LE`. OTK = first 32 bytes of ChaCha20 block at counter=0; encryption starts at counter=1.

### HKDF-SHA256 (`hkdf.rs`)

RFC 5869. Provides:

| Function | Description |
|---|---|
| `hkdf_extract(salt, ikm) -> [u8; 32]` | Extract PRK = HMAC-SHA256(salt, ikm) |
| `hkdf_expand(prk, info, length) -> Vec<u8>` | Expand PRK to arbitrary length |
| `hkdf(salt, ikm, info, length) -> Vec<u8>` | Extract + expand combined |
| `derive_session_keys(shared_secret, context) -> ([u8; 32], [u8; 32])` | Derive send_key and recv_key |

`derive_session_keys` uses labels `b"liberty-shield:send:<ctx>"` and `b"liberty-shield:recv:<ctx>"`.

---

## Session Keys (`crypto/session_keys.rs`)

```rust
pub struct SessionKeys {
    send_key:      [u8; 32],
    recv_key:      [u8; 32],
    send_sequence: u64,      // monotonically increasing; errors at MAX_SEQUENCE
}
```

**Nonce construction** (`build_nonce`): 12-byte nonce = `[0, 0, 0, 0]` ‖ `sequence.to_le_bytes()`.

**Sequence limit**: `MAX_SEQUENCE = (1u64 << 48) - 1`. `encrypt_packet` returns `SessionKeyError::NonceExhausted` if exceeded.

**API**:

| Method | Description |
|---|---|
| `SessionKeys::new(send_key, recv_key)` | Construct with sequence=0 |
| `encrypt_packet(aad, plaintext) -> Result<Vec<u8>>` | AEAD seal; increments send_sequence |
| `decrypt_packet(aad, sequence, ct_and_tag) -> Result<Vec<u8>>` | AEAD open at given sequence; uses recv_key |
| `send_sequence() -> u64` | Current send counter |

Sequence is carried out-of-band (in `EncryptedRelayCell.sequence`) so the receiver can construct the correct nonce for decryption without maintaining a counter.

---

## Fixed Cell Framing (`proto/cell_frame.rs`)

Every cell on the wire is exactly **512 bytes**.

```
 0        1        5        5+payload_len   512
 ┌────────┬────────────────┬───────────────────┐
 │version │ payload_len    │ payload  │ padding │
 │ 1 byte │ 4 bytes LE u32 │ ≤507 B   │ zeros   │
 └────────┴────────────────┴───────────────────┘
```

| Constant | Value | Description |
|---|---|---|
| `CELL_FRAME_SIZE` | 512 | Total wire size in bytes |
| `HEADER_SIZE` | 5 | version + payload_len |
| `MAX_FRAME_PAYLOAD` | 507 | Maximum payload bytes per cell |
| `FRAME_VERSION` | `0x01` | Current wire version |

**API**:

| Function | Description |
|---|---|
| `frame_cell(payload) -> Result<FramedCell, FrameError>` | Encode; zero-pad to 512 bytes |
| `parse_cell(raw: &[u8; 512]) -> Result<FramedCell, FrameError>` | Decode; verify version and length |
| `parse_cell_slice(raw: &[u8]) -> Result<FramedCell, FrameError>` | Like above but accepts slice |

Padding bytes after `payload_len` **must** be zero on send; receiver ignores them.

---

## Replay Protection (`replay_protection/`)

The existing `ReplayWindow` / `ReplayDetector` from Sprint 24 was extended with 12 additional edge-case tests (RW7–RW18) in `extended_tests.rs`:

| Test | Scenario |
|---|---|
| RW7 | Out-of-order nonces within window accepted |
| RW8 | Nonce exactly at window floor accepted |
| RW9 | Nonce one below floor rejected (`WindowExpired`) |
| RW10 | Window advances on high-nonce arrival; old nonces expire |
| RW11 | 50 independent circuits tracked; per-circuit isolation |
| RW12 | `seen_nonces` bounded after large forward jump |
| RW13 | Duplicate detection for out-of-order nonces |
| RW14 | Zero-size window: only last nonce valid |
| RW15 | Dense sequential stream (0–255, window=128) accepted cleanly |
| RW16 | All 10 sequential nonces become duplicates after first pass |
| RW17 | `remove_circuit` resets window state |
| RW18 | Nonce near `u64::MAX` accepted without overflow |

---

## Encrypted Relay Cells (`encrypted_relay/`)

### `EncryptedRelayCell` (`cell.rs`)

Wire format: `sequence(8 LE) ‖ ciphertext_and_tag`

AAD = `circuit_id.to_le_bytes() ‖ stream_id.to_le_bytes()` (16 bytes total)

| Method | Description |
|---|---|
| `EncryptedRelayCell::seal(session, circuit_id, stream_id, plaintext)` | Encrypt using session send_key |
| `open(&self, session, circuit_id, stream_id)` | Decrypt using session recv_key at stored sequence |
| `to_wire() -> Vec<u8>` | Serialize to bytes |
| `from_wire(bytes) -> Result<Self>` | Deserialize |

### `RelayPipeline` (`pipeline.rs`)

Combines per-circuit `SessionKeys` + `ReplayDetector`. Receive path:

1. Look up session by `circuit_id`; return `NoSession` if absent
2. Replay-check `cell.sequence` against `ReplayDetector`; return `ReplayRejected` if duplicate/expired
3. Decrypt; return `AuthFailed` on MAC failure
4. Record nonce in replay window
5. Return `Accepted(plaintext)`

The replay check happens **before** decryption (fail-fast, avoids AEAD work on replays).

### `RelayCellCommand` (`types.rs`)

| Tag | Variant | Description |
|---|---|---|
| 1 | `Data` | Stream payload |
| 2 | `Begin` | Open stream |
| 3 | `End` | Close stream |
| 4 | `Connected` | Stream established |
| 5 | `Extend` | Extend circuit |
| 6 | `Extended` | Circuit extended |
| 7 | `Padding` | Cover traffic |

---

## Onion Handshake (`onion/handshake.rs`)

**NON-PRODUCTION**: Placeholder DH = XOR of two 32-byte "public keys". Structurally identical to X25519; real DH can replace `derive_shared` without changing the API.

### Key derivation per hop

```
shared_secret[i] = initiator_key[i] ^ responder_key[i]
context          = circuit_id(8 LE) ‖ hop_index(1)
prk              = HKDF-Extract(salt="liberty-shield-v1", ikm=shared_secret)
(init_send, init_recv) = derive_session_keys(prk, context)
initiator_session = SessionKeys::new(init_send, init_recv)
responder_session = SessionKeys::new(init_recv, init_send)
```

`initiator_session.send_key == responder_session.recv_key` — what the initiator sends, the responder can decrypt.

### API

| Function | Description |
|---|---|
| `complete_handshake(params) -> Result<HandshakeResult>` | Derive keys for one hop |
| `generate_public_key(secret_seed) -> HopPublicKey` | Deterministic "public key" from seed |
| `build_circuit_keys(circuit_id, init_secs, resp_secs)` | Build all hop keys for a circuit |

`WeakSecret` is returned when `shared_secret` is all-zero (XOR of identical keys).

---

## Large-Scale Simulation Tests (`mesh_simulator/large_scale_tests.rs`)

15 tests (LS1–LS15) exercise the full stack at scale:

| Test | Scenario |
|---|---|
| LS1 | 50-node topology role distribution (5 guard, 40 relay, 5 exit) |
| LS2 | 50-node, 100 packets — zero drop |
| LS3 | 100-node, 500 packets — zero drop |
| LS4 | 200-circuit build; each circuit exactly 3 hops |
| LS5 | 1000 unique nonces — zero replay rejections |
| LS6 | Replay injection on 10 circuits — all 10 detected |
| LS7 | Cover traffic on 200 circuits — packets generated |
| LS8 | 5000-packet burst; 15000 forwards (5000 × 3 hops) |
| LS9 | All role types present in 50-node network |
| LS10 | Average path length = 3.0 across 2000 packets |
| LS11 | 10 scheduler rounds — cumulative counts correct |
| LS12 | Circuit-unique nonces accepted on each circuit |
| LS13 | Forward count = packets × 3 hops |
| LS14 | Deterministic topology reproducible across two constructions |
| LS15 | Fresh simulator starts with all-zero metrics |

---

## Security Notes

- All crypto is **NON-PRODUCTION**: intended for architectural validation, not deployment.
- No constant-time guarantees beyond `ct_eq_16` for tag comparison.
- No side-channel mitigations in SHA-256 or ChaCha20 implementation.
- Nonce space: 2^48 packets per session (`MAX_SEQUENCE`); `requires_rotation()` fires at 87.5 %.
- `decrypt_packet_in_order` enforces strictly-increasing sequences; the basic `decrypt_packet`
  does not track order — pair it with `ReplayDetector` for sliding-window protection.
- `RekeyGuard` nonce set is in-memory only; persisted storage is required for production.

---

## Sprint 37 — X25519 Key Exchange

Replaced XOR placeholder DH with RFC 7748 X25519.  See
`docs/runtime/x25519_key_exchange_sprint37.md` for full details.

---

## Sprint 38 — Session Rekey Protocol

Added session renegotiation and crypto hardening.  See
`docs/runtime/sprint38_rekey_protocol.md` for full details.

New modules: `onion/rekey.rs`, `EphemeralKeypair` in `crypto/x25519.rs`.

New `SessionKeys` API: `rotate_keys`, `decrypt_packet_in_order`,
`SessionError::ReplayDetected`.

---

## Sprint 39 — Replay Window and Session Lifecycle Hardening

Added bitmap sliding replay window, persistent rekey nonce store, session
lifecycle state machine, and transport-layer replay filter.  See
`docs/runtime/sprint39_replay_window.md` for full details.

New modules: `crypto/bitmap_window.rs`, `onion/rekey_guard.rs`,
`transport/replay_filter.rs`.

New `SessionKeys` API: `decrypt_packet_with_window`, `state()`, `is_usable()`,
`begin_rekey()`, `complete_rekey()`, `expire()`, `SessionState` enum.

New `BitmapReplayWindow` exported from `crypto`: O(1) 128-packet window.

`RelayPipeline` now integrates `TransportReplayFilter` (capacity 512) as a
fast first-pass duplicate check before AEAD decryption.

---

## Test Coverage Summary

| Module | Tests |
|---|---|
| `crypto/sha256` | 7 (SH1–SH7) |
| `crypto/chacha20` | 6 (CC1–CC6) |
| `crypto/poly1305` | 6 (PL1–PL6) |
| `crypto/aead` | 10 (AE1–AE10) |
| `crypto/hkdf` | 7 (HK1–HK7) |
| `crypto/bitmap_window` | 6 (SW1–SW6) |
| `crypto/session_keys` | 25 (SK1–SK16, AE1–AE3, DW1–DW3, SL1–SL3) |
| `proto/cell_frame` | 11 (CF1–CF11) |
| `replay_protection` (extended) | 12 (RW7–RW18) |
| `encrypted_relay/cell` | 10 (ER1–ER10) |
| `encrypted_relay/pipeline` | 6 (RP1–RP6) |
| `onion/handshake` | 13 (HS1–HS13) |
| `onion/rekey` | 4 (RK1–RK4) |
| `onion/rekey_guard` | 3 (RG1–RG3) |
| `crypto/x25519` (ephemeral) | 3 (FS1–FS3) |
| `mesh_simulator` (large-scale) | 15 (LS1–LS15) |
| `transport/replay_filter` | 3 (TR1–TR3) |
| **Total (Sprint 31-39)** | **147** |
