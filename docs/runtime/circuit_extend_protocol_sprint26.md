# Sprint 26 — Circuit Extend Protocol

## Purpose

Manages the lifecycle of extending a circuit by one hop at a time. Enforces state-machine invariants, prevents duplicate hops, and generates deterministic sub-circuit IDs.

## State Machine

```
Created ──begin_extend──► Extending ──confirm──► Extended
                               │
                               └──fail──► Failed
Any state ──close──► Closed
```

| State      | Meaning                                       |
|-----------|-----------------------------------------------|
| Created   | Circuit exists, no extension started          |
| Extending | Extend request sent, awaiting response        |
| Extended  | At least one hop successfully added           |
| Failed    | Last extension attempt was rejected           |
| Closed    | Circuit torn down; no further operations      |

## API (`CircuitExtendProtocol`)

| Method                   | Description                                          |
|--------------------------|------------------------------------------------------|
| `begin_extend(target, next_hop)` | Emit `ExtendRequest`, enter Extending state |
| `handle_extend_request(req)`     | Receive an extend at the relay side          |
| `handle_extend_response(resp)`   | Process accepted/rejected response           |
| `is_extended()`                  | True when state == Extended                  |
| `is_ready()`                     | True when Extended AND hop_count ≥ 3         |
| `close()`                        | Move to Closed                               |

## Error Variants

- `CircuitClosed` — cannot extend a closed circuit
- `DuplicateHop` — target already in the circuit
- `ExtendInProgress` — prior extend not yet resolved
- `NoPendingExtend` — spurious response received
- `TooFewHops` — circuit not yet at minimum hop count
- `InvalidState` — operation not valid in current state

## Sub-Circuit ID Generation

Sub-circuit IDs are derived deterministically using an LCG seeded from the parent circuit ID:

```
next = prev * 6364136223846793005 + 1442695040888963407  (all wrapping_*)
```

## Modules

- `crates/liberty-node-cli/src/circuit_extend_state.rs` — state machine + structs
- `crates/liberty-node-cli/src/circuit_extend_protocol.rs` — protocol driver + 10 tests (CE1–CE10)
