# Session Checkpoint — Sprint 16: Local Multi-Node Dry-Run Cluster

## Sprint Goal

Replace single-node CLI simulation with a fully deterministic multi-node `LocalCluster`
that spans 5–250 logical nodes, wires them into role-based topologies, and routes packets
through the existing `MeshSimulator` — all without real sockets, randomness, or system time.

## Completed Phases

### Phase 1 — cluster_types.rs
Defines all core cluster primitives: `ClusterNodeId`, `ClusterNodeRole`, `ClusterNodeStatus`,
`ClusterNodeConfig`, `ClusterNodeSnapshot`, `ClusterError`. `ClusterNodeConfig::validate()`
mirrors the three-rule validation in `NodeConfig`. Tests CT1–CT4.

### Phase 2 — cluster_manager.rs
`LocalCluster` owns parallel `Vec<NodeService>` + `Vec<ClusterNodeConfig>` vectors and an
`Option<MeshSimulator>`. Uses `MeshSimulator` directly (not `NodeRuntime`) for fine-grained
`send_payload` / `tick_cover_traffic` / `metrics` access. `start_all()` creates the simulator
with `circuit_count = (node_count / 5).max(1)`. Tests CM1–CM10.

### Phase 3 — cluster_topology.rs
`ClusterTopologyProfile` enum (Tiny / Small / Medium / Large) with `role_counts()` and
`parse_profile()`. `build_cluster_configs()` and `build_cluster_configs_with_count()` assign
sequential IDs from 1 and ports from BASE_PORT=39000. Tests TB1–TB6.

### Phase 4 — cluster_peering.rs
`wire_full_mesh` and `wire_role_based_mesh`. Full-mesh silently discards `TableFull` so
`max_peers` is enforced naturally. Role-based wiring uses `matches!()` for pair filtering.
Tests PW1–PW6.

### Phase 5 — cluster_packet_flow.rs
`send_cluster_payload` and `send_cluster_cover_tick`. Imports wire-size constants directly
from `liberty-controlled-chaos` (CELL_SIZE=1450, ENCRYPTED_CELL_SIZE=1482, ONION=1507).
Tests PF1–PF6.

### Phase 6 — CLI commands (args.rs, output.rs, lib.rs)
Added `ClusterStart`, `ClusterStatus`, `ClusterRun`, `ClusterTopology`, `ClusterPeers`
command variants. Output functions in `output.rs`. CLI tests CLI-C1–C7.

### Phase 7 — cluster_metrics.rs
`ClusterMetrics::from_cluster()` aggregates running/stopped counts from snapshots and packet
counters from `sim_metrics()`. Tests MT1–MT5.

### Phase 8 — Documentation
`docs/runtime/local_multi_node_cluster_sprint16.md` — architecture, role table, lifecycle,
wiring strategies, CLI commands, wire-size constants, limitations, next sprint.

### Phase 9 — Hardening tests (H1–H10)
Edge-case coverage: double-start rejection, stop-before-start safety, mid-run node removal,
zero-node topology, max_peers enforcement, valid JSON for all cluster commands, snapshot sort
order, zero-round runs, large profile creation, medium profile determinism.

### Phase 10 — Final validation
- `cargo fmt -p liberty-node-cli` — clean
- `cargo test -p liberty-node-cli` — **90/90 passed**
- `cargo test --workspace` — all workspace tests pass
- `cargo clippy -p liberty-node-cli -p liberty-controlled-chaos -- -D warnings` — clean

## Bug Fixed During Validation

`lib.rs` had a stale import `use cluster_types::{ClusterNodeRole, ClusterTopologyProfile as _ClusterTopologyProfile}`.
`ClusterTopologyProfile` lives in `cluster_topology`, not `cluster_types`. Also removed
unused `ClusterMetrics` import and `cluster_metrics_json` from output imports. Moved
`ClusterTopologyProfile`, `ClusterNodeRole`, and `build_cluster_configs_with_count` into the
`#[cfg(test)]` module where they are actually used. Added `#[derive(Debug)]` to
`ClusterPacketResult` (required by `unwrap_err()` in PF2/PF3 tests).

## Test Count

| Module                  | Tests |
|-------------------------|-------|
| cluster_types           | CT1–CT4 (4) |
| cluster_manager         | CM1–CM10 (10) |
| cluster_topology        | TB1–TB6 (6) |
| cluster_peering         | PW1–PW6 (6) |
| cluster_packet_flow     | PF1–PF6 (6) |
| cluster_metrics         | MT1–MT5 (5) |
| lib (CLI cluster)       | CLI-C1–C7 (7) |
| lib (hardening)         | H1–H10 (10) |
| Sprint 14/15 legacy     | N1–N10, CLI1–CLI5, node_service_state_as_str (16) |
| Sprint 15 modules       | config, identity, node_service, peer_table, runtime_state (~20) |
| **Total**               | **90** |

## Key Design Decisions

1. `MeshSimulator` held directly in `LocalCluster` — gives access to `send_payload()` and
   `tick_cover_traffic()` without routing through `NodeRuntime`'s bulk-only interface.
2. Parallel `Vec<NodeService>` + `Vec<ClusterNodeConfig>` — deterministic insertion order,
   O(n) lookup acceptable at cluster sizes ≤ 250 nodes.
3. `circuit_count = (node_count / 5).max(1)` — scales naturally, always at least 1 circuit.
4. `snapshots()` sorts by `node_id` — deterministic output regardless of insertion order.
5. `wire_full_mesh` silently drops `TableFull` — natural max_peers enforcement, no error noise.

## Files Created / Modified

### New files
- `crates/liberty-node-cli/src/cluster_types.rs`
- `crates/liberty-node-cli/src/cluster_manager.rs`
- `crates/liberty-node-cli/src/cluster_topology.rs`
- `crates/liberty-node-cli/src/cluster_peering.rs`
- `crates/liberty-node-cli/src/cluster_packet_flow.rs`
- `crates/liberty-node-cli/src/cluster_metrics.rs`
- `docs/runtime/local_multi_node_cluster_sprint16.md`

### Modified files
- `crates/liberty-node-cli/src/args.rs`
- `crates/liberty-node-cli/src/output.rs`
- `crates/liberty-node-cli/src/lib.rs`

## Next Sprint

**Sprint 17 — Controlled Local UDP Testnet**: bind real loopback UDP sockets per node,
implement `connect_to_peer()` over UDP, route actual Noise-encrypted packets between
`NodeService` instances. Foundation: `LocalCluster` topology profiles and wiring layer
from Sprint 16.
