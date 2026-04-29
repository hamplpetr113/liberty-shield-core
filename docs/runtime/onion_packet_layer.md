# Onion Packet Layer — Sprint 24

## Overview

Sprint 24 adds a layered onion packet abstraction on top of the existing
encrypted circuit and peer directory infrastructure.

**NON-PRODUCTION**: The crypto is deterministic XOR. Real AEAD replaces it
in a later sprint.

## Files

| File | Purpose |
|------|---------|
| `onion_crypto.rs` | Deterministic key derivation + encrypt/decrypt |
| `onion_packet.rs` | `OnionPacket` type: `wrap_layer`, `unwrap_layer`, `wrap_layers`, `unwrap_layers` |

## Crypto (onion_crypto.rs)

Key derivation uses FNV-style mixing:

```
key = FNV_mix(node_id) ⊕ FNV_mix(hop_index)
```

Functions:
- `derive_layer_key(node_id, hop_index) → [u8; 8]`
- `encrypt_layer(payload, key) → Vec<u8>`  — XOR each byte with repeating key
- `decrypt_layer(payload, key) → Vec<u8>`  — identical to encrypt (XOR inverse)

## Packet Format (onion_packet.rs)

```
OnionPacket
  circuit_id: u64
  hop_index:  usize   // index of the next hop to process this packet
  encrypted_payload: Vec<u8>
```

### Wrapping (client side)

`wrap_layers(circuit_id, plaintext, hops)` applies layers inside-out:

```
pkt = plaintext
for node_id in hops.rev():
    pkt = wrap_layer(pkt, node_id)    // XOR with key(node_id, hop_index)
pkt.hop_index = 0
```

Result: outermost layer belongs to `hops[0]` (the guard).

### Unwrapping (each hop)

`unwrap_layer(node_id)` peels one layer:
- Decrypts payload with `key(node_id, current_hop_index)`
- Increments `hop_index`

`unwrap_layers(pkt, hops)` drives a full decryption sequence, returning
the final plaintext.

### Size invariant

XOR is size-preserving — `encrypted_payload.len()` equals `plaintext.len()`
at every hop.

## Tests (OC1–OC6, OP1–OP10)

- OC1: encrypt → decrypt roundtrip
- OC2: deterministic key derivation
- OC3: different inputs → different keys
- OC4: wrong key does not restore plaintext
- OP1: wrap + unwrap roundtrip
- OP2: deterministic wrapping
- OP3: size invariant
- OP5: hop_index starts at 0
- OP6: each unwrap increments hop_index
