# Liberty Controlled Chaos — Security Audit (Sprint 12)

**Date:** 2026-04-28
**Crate:** `liberty-controlled-chaos` v0.1.0
**Audit scope:** All modules implemented through Sprint 12.

---

## 1. Scope

This document covers the security posture of every module in the
`liberty-controlled-chaos` crate as of Sprint 12.  The audit is a
**design-level review only** — it does not constitute a penetration test
or formal verification.

---

## 2. Implemented Layers

| Layer | Module | Status |
|---|---|---|
| Runtime boundary | `runtime_boundary` | Implemented |
| Stream multiplexer | `stream_mux` | Implemented |
| Cell encoder | `cell_encoder` | Implemented |
| Noise link (AEAD) | `noise_link` | NON-PRODUCTION placeholder |
| Onion layer | `onion_layer` | NON-PRODUCTION placeholder |
| Circuit builder | `circuit_builder` | Implemented |
| Circuit runtime | `circuit_runtime` | Implemented |
| Mesh router | `mesh_router` | Implemented |
| UDP transport | `udp_transport` | Implemented |
| Node discovery | `node_discovery` | Implemented |
| Guard selection | `guard_selection` | Implemented |
| Relay protocol | `relay_protocol` | Implemented |
| Circuit extension | `circuit_extension` | Implemented |
| Onion cell protocol | `onion_cell_protocol` | Implemented |
| Replay protection | `replay_protection` | Implemented |
| Protocol runtime | `protocol_runtime` | Implemented |
| Route shadower | `route_shadower` | Implemented |
| Path fragmenter | `path_fragmenter` | Implemented |
| Cover traffic | `cover_traffic` | Implemented |
| Anti-correlation scheduler | `anti_correlation_scheduler` | Implemented |
| Multi-circuit distributor | `multi_circuit_distributor` | Implemented |
| Circuit rotation | `circuit_rotation` | Implemented |
| Transmitter / ShadowSync | `transmitter` | Implemented |
| Integration harness | `integration_harness` | Implemented (test-only) |
| Invariant tests | `invariant_tests` | Implemented (test-only) |

---

## 3. Trust Boundaries

```
External caller
    │
    ▼
RuntimeBoundaryValidator  ◄── V1-V6 checks (kill switch, tunnel state,
    │                          path registration, deadline, payload ref,
    │                          shadow budget)
    ▼
StreamMux (RuntimePacketIntent only — forged intents compile-rejected)
    │
    ▼
CellEncoder (payload bytes copied verbatim; never interpreted)
    │
    ▼
NoiseLinkEncoder (AEAD encrypt — NON-PRODUCTION cipher)
    │
    ▼
LayerEncryptor (onion wrap — NON-PRODUCTION cipher)
    │
    ▼
MeshRouter (routing decision from metadata only; payload never read)
    │
    ▼
UDPTransport (wire egress — outside crate scope)
```

The `RuntimePacketIntent` type enforces the boundary at compile time:
its constructor is `pub(in crate::runtime_boundary)`, so no code outside
the `runtime_boundary` module tree can produce one without going through
`RuntimeBoundaryValidator::validate()`.

---

## 4. NON-PRODUCTION Crypto Warnings

**Both `noise_link` and `onion_layer` use placeholder cryptography:**

- **Cipher:** ChaCha8-XOR keystream (reduced-round ChaCha; not ChaCha20).
- **MAC:** SipHash-2-4-128 (a keyed hash, not an AEAD MAC).

These constructions are **deterministic and key-dependent** but provide
**no formal security guarantees**.  They are intentionally labelled
`NON-PRODUCTION` throughout the source.

### Required replacements before any real networking

| Current | Replace with |
|---|---|
| `noise_link` ChaCha8-XOR + SipHash | `chacha20poly1305` crate (ChaCha20-Poly1305, RFC 8439) |
| `onion_layer` XOR keystream + SipHash | Full onion encryption (e.g. `aes-gcm` or `chacha20poly1305` per hop) |
| Key derivation (XOR mix) | HKDF (RFC 5869) |

---

## 5. Replay Protection Status

`ReplayWindow` in `replay_protection` tracks seen nonces in a sliding
window.  The `CellPipeline` in `protocol_runtime` derives a u64 nonce
from incoming raw bytes using FNV-1a (inline) and passes it to
`ReplayDetector`.

**Strengths:**
- Duplicate raw bytes are rejected on second receipt.
- Window-expired nonces (below `last_nonce - window_size`) are rejected.

**Limitations:**
- FNV-1a is not collision-resistant; an adversary who can craft colliding
  byte sequences could inject a cell that bypasses replay detection.
- Window size is fixed at construction; no dynamic tuning.
- Nonce derivation must be replaced with a cryptographically strong
  method (e.g. the nonce from the authenticated AEAD tag) before
  production use.

---

## 6. Timing and Correlation Protections

| Protection | Module | Status |
|---|---|---|
| Cover traffic generation | `cover_traffic` | Deterministic intents; real scheduling needed |
| Anti-correlation scheduling | `anti_correlation_scheduler` | Real/cover interleaving implemented |
| Traffic shadowing | `route_shadower` | Probability-based shadow decisions implemented |
| Path fragmentation | `path_fragmenter` | Multi-path split implemented |
| Circuit rotation | `circuit_rotation` | Age/failure/guard-degradation triggers implemented |

All timing values (`epoch_start_us`, `now_us`, deadlines) are
caller-supplied; the crate never reads system time.  This makes all
timing logic deterministic and testable but means the caller is
responsible for providing accurate timestamps.

---

## 7. Known Limitations

1. **No key exchange:** Session keys are provided by the caller.  No
   Noise or DH handshake is implemented; key material must be established
   out-of-band.

2. **No certificate / identity verification:** `RelayDescriptor.public_key`
   is trusted as-is; no PKI or web-of-trust validation occurs.

3. **No padding at the transport layer:** `UDPTransport` sends cells
   at their encoded size (`CELL_SIZE = 1450`), which is already fixed.
   IP fragmentation and MTU clamping are not handled.

4. **Single-node guard set bypass:** An adversary controlling all guard
   candidates (e.g. in a local test) can trivially build a single-node
   circuit.  Production deployments require a trusted, well-distributed
   guard list.

5. **FNV-1a nonce collision:** See §5.

6. **No secret erasure:** Key material in `NoiseSession` and
   `OnionLayerKey` is not explicitly zeroed on drop.  Use `zeroize` crate
   in production.

---

## 8. Required Hardening Before Real Networking

- [ ] Replace `noise_link` cipher+MAC with `chacha20poly1305` (RFC 8439).
- [ ] Replace `onion_layer` cipher+MAC with a production-grade AEAD.
- [ ] Replace key derivation XOR mix with HKDF (RFC 5869).
- [ ] Replace FNV-1a nonce derivation with AEAD-derived or sequence nonce.
- [ ] Add `zeroize` to all key-bearing types.
- [ ] Implement a DH or Noise protocol handshake for session establishment.
- [ ] Add certificate / public-key verification for relay identities.
- [ ] Audit all `pub(crate)` constructors for forge-ability.
- [ ] Replace `#[allow(dead_code)]` guards with real usage or removal.

---

## 9. Recommended Next Sprint

**Sprint 13 — Production Crypto Integration:**

1. Replace `noise_link` with `chacha20poly1305` crate.
2. Replace `onion_layer` MAC with the same AEAD.
3. Integrate HKDF key derivation for per-hop keys.
4. Add `zeroize` to `NoiseSession` and `OnionLayerKey`.
5. All existing tests must continue to pass with the new primitives.
