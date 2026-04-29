# Encrypted Multi-Hop Circuits — Sprint 21

## Overview

Sprint 21 adds an abstract circuit routing layer on top of the encrypted UDP stack.
Circuits are fixed hop sequences with TTL and per-hop replay protection. No new UDP
sockets are required — circuits operate over the existing `EncryptedUdpNode` sessions.

## Files

| File | Purpose |
|------|---------|
| `encrypted_circuit_path.rs` | `EncryptedCircuitPath`: fixed hop sequence, TTL, loop detection |
| `encrypted_circuit_runtime.rs` | `EncryptedCircuitRuntime`: register/send/forward/close circuits |

## Circuit Lifecycle

```
register_circuit(path)   → circuit ID registered, TTL starts counting
send_on_circuit(id, payload) → CircuitPacket at hop 0
forward_next(pkt)        → CircuitPacket at hop+1, or None (delivered)
close_circuit(id)        → circuit removed, further use returns CircuitClosed
tick_ttl(id)             → decrements TTL; returns false when TTL=0
```

## Constraints

- Minimum 3 hops (guard + relay + exit model)
- No repeated node IDs (loop detection via `HashSet`)
- TTL: each `tick_ttl` call decrements; `is_expired()` true when TTL reaches 0
- Replay detection: FNV-style hash of payload per `(circuit_id, hop_index)` key

## Packet Forwarding

`forward_next` returns:
- `Ok(Some(pkt))` — packet advanced to the next hop
- `Ok(None)` — packet has reached the final hop (delivered)
- `Err(TtlExpired)` — TTL has reached zero
- `Err(CircuitClosed)` — circuit was explicitly closed
- `Err(ReplayDetected)` — duplicate payload at this hop

## Tests (CP1–CP6, C1–C9)

- C4: 3-hop circuit requires 3 `forward_next` calls before delivery
- C7: replay of same payload at hop 0 detected
- C8: deterministic routing — same payload always yields same hop sequence
- C5: TTL=1 → one tick expires the circuit
