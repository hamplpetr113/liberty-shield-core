# X25519 Key Exchange — Sprint 37

**NON-PRODUCTION IMPLEMENTATION**

Sprint 37 replaces the XOR placeholder DH in the onion handshake layer with
a fully conformant X25519 (RFC 7748) implementation, adds nonce-exhaustion
rotation signals to `SessionKeys`, and extends the canonical field-element
reduction to ensure correct handling of low-order public-key inputs.

---

## Motivation

Sprint 35 established the HKDF-based per-hop handshake structure, but left
`derive_shared` as a bitwise XOR of two 32-byte "public keys".  That approach:

- Produces an all-zero shared secret whenever both parties choose the same key.
- Provides no Diffie-Hellman security properties.
- Would fail all standard key-exchange test vectors.

Sprint 37 closes this gap by implementing the full Montgomery-ladder X25519
function from RFC 7748 §5, integrating it into the onion handshake, and
adding session rotation signals.

---

## X25519 Implementation (`crypto/x25519.rs`)

### Field Arithmetic — GF(2^255 − 19)

Five `u64` limbs in radix-2^51:

```
value = h[0] + h[1]·2^51 + h[2]·2^102 + h[3]·2^153 + h[4]·2^204
```

| Function | Description |
|---|---|
| `fe_from_bytes(b)` | Unpack 32 little-endian bytes; clears unused high bit |
| `fe_to_bytes(h)` | Pack to canonical 32-byte LE; conditional subtract of p |
| `fe_add(a, b)` | Addition with carry propagation |
| `fe_sub(a, b)` | Subtraction; adds 2p before subtracting to stay non-negative |
| `fe_mul(a, b)` | Schoolbook multiplication using u128 accumulators; two-pass carry |
| `fe_sq(a)` | `fe_mul(a, a)` |
| `fe_reduce(h)` | Two carry passes + canonical subtraction of p if h ≥ p |
| `fe_cswap(a, b, swap)` | Branchless conditional swap |
| `fe_invert(a)` | a^(p−2) via standard addition chain |

**Canonical reduction in `fe_reduce`:** After the two carry passes all limbs
are in `[0, 2^51)`.  Without an explicit final subtraction, `fe_sub(a, a)`
produces the limb vector `[p]` (a non-canonical encoding of 0), which causes
`x25519(k, 0)` to return a non-zero result.  The conditional subtraction:

```
h ≥ p  ⟺  h[4..1] == MASK51  and  h[0] ≥ 2^51-19
```

is detected and applied branchlessly:

```rust
let above = ((h[0].wrapping_add(19)) >> 51)
    & ((h[1].wrapping_add(1)) >> 51)
    ...
    & ((h[4].wrapping_add(1)) >> 51);
h[0] -= above * (MASK51 - 18);  // subtract p[0]
h[1..5] -= above * MASK51;      // subtract p[1..4]
```

### Montgomery Ladder

RFC 7748 §5 algorithm, iterating bits 254..=0 of the clamped scalar.
Uses `fe_cswap` for data-independent swap.

```
x_2, z_2  = 1, 0   (point at infinity)
x_3, z_3  = u, 1   (input point)
for bit in 254..=0:
    conditional_swap(bit)
    differential_add_and_double(x_2, z_2, x_3, z_3, x_1)
return x_2 * inverse(z_2)
```

When u = 0 (low-order 2-torsion point): z_2 becomes 0 after the first
iteration because `x_1 = 0` makes `z_3 = x_1 * (...)  = 0`.  After all
iterations, `fe_invert(0) = 0` (0^(p−2) = 0 mod p) and the final product
`x_2 * 0 = 0`, producing the all-zero shared secret.

### Public API

| Symbol | Description |
|---|---|
| `X25519PrivateKey` | `[u8; 32]` type alias |
| `X25519PublicKey` | `[u8; 32]` type alias |
| `X25519SharedSecret` | `[u8; 32]` type alias |
| `X25519_BASEPOINT` | Basepoint u = 9 |
| `clamp_scalar(k)` | RFC 7748 clamping: byte 0 &= 248, byte 31 &= 127, byte 31 \|= 64 |
| `x25519(priv, pub)` | Clamped scalar × u-coordinate |
| `x25519_basepoint(priv)` | x25519(priv, BASEPOINT) |
| `is_zero_shared_secret(s)` | True if s is all-zero (low-order point warning) |

---

## Onion Handshake (`onion/handshake.rs`)

### API Changes

`HopHandshakeParams` now carries X25519 **private** keys; public keys are
derived internally:

```rust
// Before (Sprint 35):
pub struct HopHandshakeParams {
    pub initiator_key: HopPublicKey,   // XOR'd together
    pub responder_key: HopPublicKey,
}

// After (Sprint 37):
pub struct HopHandshakeParams {
    pub initiator_private: HopPrivateKey,  // [u8; 32]
    pub responder_private: HopPrivateKey,  // [u8; 32]
}
```

### Key Derivation per Hop

```
resp_pub       = x25519_basepoint(responder_private)
shared_secret  = x25519(initiator_private, resp_pub)
             ≡  x25519(responder_private, initiator_pub)  (DH symmetry)
context        = circuit_id(8 LE) ‖ hop_index(1)
prk            = HKDF-Extract("liberty-shield-v1", shared_secret)
(send, recv)   = derive_session_keys(prk, context)
initiator_session = SessionKeys::new(send, recv)
responder_session = SessionKeys::new(recv, send)
```

### Behaviour Changes from Sprint 35

| Scenario | Sprint 35 (XOR) | Sprint 37 (X25519) |
|---|---|---|
| `initiator_private == responder_private` | `WeakSecret` (XOR → zero) | Succeeds (DH is non-zero) |
| All-zero public key input | N/A (keys were public) | `WeakSecret` |
| generate_public_key | HKDF of seed | `x25519_basepoint(private_key)` |

---

## Session Keys Rotation Signals (`crypto/session_keys.rs`)

Two new methods provide proactive rotation signalling before nonce space
exhaustion:

```rust
pub fn requires_rotation(&self) -> bool;
pub fn remaining_packets(&self) -> u64;
```

`requires_rotation()` returns `true` when `send_sequence ≥ 87.5 % × MAX_SEQUENCE`
(7/8 of `(2^48 − 1)`), leaving 12.5 % of the nonce space as a safety margin
for in-flight messages during renegotiation.

`remaining_packets()` returns `MAX_SEQUENCE − send_sequence`, saturating at 0.

---

## Test Coverage

| Module | Tests | Range |
|---|---|---|
| `crypto/x25519` | 14 | X1–X14 |
| `onion/handshake` | 13 | HS1–HS13 |
| `crypto/session_keys` | 13 | SK1–SK13 |
| **Sprint 37 total** | **40** | |
| **Workspace total** | **860** | |

### Key Vectors (RFC 7748 §6.1)

Alice private key (first 4 bytes): `77 07 6d 0a …`
Alice public key (first 4 bytes): `85 20 f0 09 …`
Bob private key (first 4 bytes): `5d ab 08 7e …`
Bob public key (first 4 bytes): `de 9e db 7d …`
Shared secret (first 4 bytes): `4a 5d 9d 5b …`

---

## Security Notes

- **NON-PRODUCTION**: no formal side-channel audit has been performed on the
  Montgomery ladder or field arithmetic.
- No constant-time guarantees beyond `fe_cswap` (branchless) and `ct_eq_16`
  (Poly1305 tag comparison).
- `is_zero_shared_secret` should be checked after every `x25519` call in
  production to reject low-order-point attacks.
