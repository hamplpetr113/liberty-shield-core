# Circuit Builder + Guard Selection — Sprint 24

## Overview

Sprint 24 adds deterministic circuit construction and guard selection on top
of the `PeerDirectory` infrastructure from Sprint 22.

## Files

| File | Purpose |
|------|---------|
| `guard_selection.rs` | `select_guard()` — deterministic guard selection |
| `circuit_builder.rs` | `CircuitBuilder::build_circuit()` — 3-hop minimum circuit |

## Guard Selection (guard_selection.rs)

Algorithm:
1. Sort all candidates by `node_id` ascending.
2. Return the first candidate whose `role == PeerRole::Guard`.

```rust
pub fn select_guard(candidates: &[PeerDescriptor]) -> Result<&PeerDescriptor, GuardSelectionError>
```

**Error**: `NoGuardAvailable` if no candidate has the Guard role.

## Circuit Builder (circuit_builder.rs)

Rules enforced:
- Minimum 3 hops
- No duplicate node IDs
- `hops[0]` must be a Guard
- `hops[last]` must be an Exit
- Middle hops prefer Relay nodes; fall back to any unused node if none available

```rust
pub struct BuiltCircuit {
    pub hops: Vec<PeerDirectoryNodeId>,  // [guard, relay..., exit]
}

CircuitBuilder::build_circuit(peers: &[PeerDescriptor]) -> Result<BuiltCircuit, CircuitBuildError>
```

### Algorithm

```
1. guard = select_guard(peers)           // lowest node_id Guard
2. exit  = min(exits, excl. guard)      // lowest node_id Exit ≠ guard
3. relay = first unused Relay           // fallback: first unused node
4. hops  = [guard, relay, exit]
5. validate no duplicates
```

## Error Types

| Error | Cause |
|-------|-------|
| `TooFewHops` | fewer than 3 distinct peers |
| `NoGuard` | no Guard in candidate set |
| `NoExit` | no Exit available (excluding guard) |
| `DuplicateNode` | path contains repeated node ID |

## Tests (GS1–GS6, CB1–CB8)

- GS1: deterministic — same set always returns the same guard
- GS2: selected node always has Guard role
- GS3: lowest node_id Guard is chosen
- CB1: valid 3-hop circuit [Guard, Relay, Exit]
- CB5: no duplicate nodes in output
- CB6: deterministic — same input → same circuit
- CB7/CB8: first hop is Guard, last hop is Exit
