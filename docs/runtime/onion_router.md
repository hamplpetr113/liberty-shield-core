# Onion Router — Sprint 24

## Overview

Sprint 24 adds `OnionRouter`, which drives onion packets through a registered
circuit by decrypting one layer per hop and determining when delivery occurs.

## File

`onion_router.rs` — `OnionRouter`, `ProcessResult`, `OnionRouterError`

## Design

`OnionRouter` combines:
- `EncryptedCircuitRuntime` for TTL and registration tracking
- A `circuit_hops` map (`circuit_id → Vec<u64>`) for the ordered node IDs

### Packet lifecycle

```
client:  build_packet(circuit_id, plaintext)
           → wrap_layers(plaintext, [guard, relay, exit])
           → OnionPacket { hop_index: 0, encrypted_payload: ... }

guard:   process_packet(pkt)
           → unwrap guard's layer → hop_index: 1
           → ProcessResult::Forward(inner_pkt)

relay:   process_packet(pkt)
           → unwrap relay's layer → hop_index: 2
           → ProcessResult::Forward(inner_pkt)

exit:    process_packet(pkt)
           → unwrap exit's layer → hop_index: 3 (beyond last)
           → ProcessResult::Delivered(plaintext)
```

## API

```rust
router.register_circuit(circuit_id, hop_node_ids)  // must be ≥ 3 hops
router.build_packet(circuit_id, plaintext)          // returns wrapped OnionPacket
router.process_packet(pkt)                          // returns Forward or Delivered
router.circuit_count()                              // number of registered circuits
```

## ProcessResult

```rust
pub enum ProcessResult {
    Forward(OnionPacket),   // inner packet for the next hop
    Delivered(Vec<u8>),     // final plaintext at exit hop
}
```

## Error Types

| Error | Cause |
|-------|-------|
| `UnknownCircuit` | circuit_id not registered |
| `CryptoError` | `OnionPacketError` from unwrap_layer |
| `CircuitError` | underlying circuit runtime error |

## CLI Commands

| Command | Description |
|---------|-------------|
| `onion-circuit-build --nodes N` | Build a 3-hop circuit from N peers |
| `onion-send --nodes N --payload P` | Wrap and route payload through circuit |
| `onion-simulate --nodes N --rounds R` | Simulate R round-trips through the circuit |

## Tests (OR1–OR7)

- OR1: packet moves hop-by-hop (hop_index increments)
- OR2: each hop removes exactly one layer (payload bytes change)
- OR3: final hop delivers original plaintext
- OR4: unknown circuit returns `UnknownCircuit`
- OR5: fewer than 3 hops rejected at registration
- OR6: circuit count reflects registered circuits
- OR7: 4-hop end-to-end simulation

## Security Constraints

- No public sockets — OnionRouter is purely in-memory
- No `0.0.0.0` binds anywhere in the onion layer
- All node IDs and keys are deterministic (loopback testnet)
