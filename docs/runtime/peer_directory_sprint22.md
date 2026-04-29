# Peer Directory — Sprint 22

## Overview

Sprint 22 adds a local peer directory that tracks node descriptors with Guard/Relay/Exit roles.
All lookups are deterministic and in-memory. No network access.

## File

`peer_directory.rs` — `PeerDirectory`, `PeerDescriptor`, `PeerRole`, `DirectoryError`

## Role Model

Roles are assigned by `node_id % 3`:

| node_id % 3 | Role |
|-------------|------|
| 0 | Guard |
| 1 | Relay |
| 2 | Exit |

`PeerDescriptor::deterministic(id, base_port)` produces a reproducible descriptor with
`address = "127.0.0.1"` and `port = base_port + id`.

## API

```rust
dir.register_node(desc)   // Err(DuplicateNodeId) if already present
dir.remove_node(id)       // Err(NodeNotFound) if absent
dir.list_nodes()          // sorted by node_id for deterministic output
dir.lookup_node(id)       // Option<&PeerDescriptor>
dir.assign_roles(&ids)    // re-assign roles by position (0→Guard, 1→Relay, 2→Exit)
dir.node_count()
```

## CLI Command

`directory-status --node-count N` creates a directory with N nodes and reports role counts.

## Tests (D1–D8)

- D3: `list_nodes` returns sorted order regardless of insertion order
- D5: `deterministic` produces same descriptor for same inputs
- D6: `assign_roles` overrides role by position
- D7: duplicate node ID rejected
