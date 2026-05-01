# Sprint 27 — Path Selection Engine

## Purpose

Selects a deterministic, role-aware, duplicate-free circuit path from a pool of `PeerDescriptor` candidates. Paths are ordered `[guard, middle…, exit]`.

## Role Assignment (deterministic from node_id)

| `node_id % 3` | Role    |
|---------------|---------|
| 0             | Guard   |
| 1             | Relay   |
| 2             | Exit    |

## Selection Algorithm

1. **Guard**: lowest `node_id` Guard not in `avoid_recent_nodes`.
2. **Exit**: lowest `node_id` Exit not already used and not in `avoid_recent_nodes`.
3. **Middle(s)**: lowest `node_id` Relay not already used (one per required middle hop).
4. Final deduplication check; returns `InsufficientNodes` if any duplicates slipped through.

`prefer_high_reliability` breaks ties by port descending; `prefer_low_latency` breaks ties by port ascending (proxy metrics — real latency data arrives in a later sprint).

## Policy Fields (`PathSelectionPolicy`)

| Field                  | Default | Meaning                                   |
|------------------------|---------|-------------------------------------------|
| `min_hops`             | 3       | Minimum circuit length (guard+mid+exit)   |
| `prefer_low_latency`   | false   | Prefer lower port as latency proxy        |
| `prefer_high_reliability` | false | Prefer higher port as reliability proxy |
| `require_distinct_roles` | true  | Enforce Guard/Relay/Exit role separation  |
| `avoid_recent_nodes`   | empty   | Node IDs to deprioritize                  |

## Error Variants

- `InsufficientNodes` — not enough distinct nodes
- `NoGuard` — no Guard-role node available
- `NoExit` — no Exit-role node available (excluding used nodes)
- `NoRelay` — no Relay-role node available (excluding used nodes)

## Module

- `crates/liberty-node-cli/src/path_selection.rs` — selector + 10 tests (PS1–PS10)
