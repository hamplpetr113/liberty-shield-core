# Local Multi-Node Dry-Run Cluster — Sprint 16

## Purpose

Sprint 16 moves Liberty Shield from single-node CLI simulation to a fully deterministic
multi-node local dry-run cluster. The goal is to exercise the complete guard → relay → exit
packet path across multiple logical nodes without opening any real sockets or touching the
network. All state is in-process; all output is deterministic given the same inputs.

## Architecture

```
LocalCluster
├── Vec<NodeService>          — per-node lifecycle (start / stop / snapshot)
├── Vec<ClusterNodeConfig>    — parallel config vector (same index = same node)
├── Option<MeshSimulator>     — cluster-level deterministic packet engine
└── running: bool             — single flag gates run/send operations
```

`LocalCluster` owns a `MeshSimulator` directly rather than delegating through `NodeRuntime`.
This gives fine-grained access to `send_payload()`, `tick_cover_traffic()`, and `metrics()`
without going through the bulk-simulation path that `NodeRuntime::run_rounds()` provides.

## Node Roles

| Role    | Responsibility                              | Default max_peers |
|---------|---------------------------------------------|-------------------|
| Client  | Originates traffic; connects to guards only | 16                |
| Guard   | First hop; connects clients to relay layer  | 64                |
| Relay   | Middle hop; connects guard ↔ exit           | 128               |
| Exit    | Final hop; connects relay layer outward     | 64                |

Role ratios per profile:

| Profile | Nodes | Clients | Guards | Relays | Exits |
|---------|-------|---------|--------|--------|-------|
| tiny    | 5     | 1       | 1      | 2      | 1     |
| small   | 20    | 2       | 3      | 12     | 3     |
| medium  | 100   | 5       | 10     | 75     | 10    |
| large   | 250   | 10      | 25     | 190    | 25    |

## LocalCluster Lifecycle

```
LocalCluster::new()
  → add_node(cfg) × N           validates config, creates NodeService
  → start_all()                 starts all services, creates MeshSimulator
      circuit_count = (N / 5).max(1)
  → run_rounds(n)               runs n simulation ticks via MeshSimulator
  → stop_all()                  stops services in reverse insertion order
```

`start_all()` is idempotent-guarded: calling it twice returns `ClusterAlreadyRunning`.
`stop_all()` is always safe to call regardless of running state.

## Peer Wiring

Two wiring strategies are available:

- **`wire_full_mesh`** — every node connects to every other node (up to `max_peers`).
  `TableFull` errors are silently discarded, so `max_peers` is enforced naturally.

- **`wire_role_based_mesh`** — connects only role-appropriate pairs:
  - Client → Guard
  - Guard → Relay
  - Relay ↔ Relay (bidirectional)
  - Relay → Exit
  - Exit → Relay (bidirectional)

The CLI cluster commands do not call either wiring function explicitly; wiring is internal
to the NodeService peer tables and does not affect `MeshSimulator` packet routing, which
operates on its own circuit model.

## Dry-Run Packet Flow

Every packet traverses exactly 3 hops (guard → relay → exit):

```
send_payload(bytes)
  → MeshSimulator selects circuits[0]
  → guard hop → relay hop → exit hop
  → PacketFlowResult { hops: [guard, relay, exit], delivered: true }
```

Invariant: `packets_forwarded = 3 × packets_sent` for all profiles.

Cover traffic is generated via `tick_cover_traffic(epoch_us)` and tracked separately in
`MeshMetrics::cover_packets`.

Wire-size constants (from `liberty-controlled-chaos`):

| Constant              | Value  | Description                    |
|-----------------------|--------|--------------------------------|
| `CELL_SIZE`           | 1450 B | Unencrypted payload cell       |
| `ENCRYPTED_CELL_SIZE` | 1482 B | Cell after Noise encryption    |
| `ONION_PACKET_SIZE`   | 1507 B | Layered onion-wrapped packet   |

## CLI Commands

| Command                                      | Output                                      |
|----------------------------------------------|---------------------------------------------|
| `liberty-node cluster-start --profile tiny`  | `{"command":"cluster-start","nodes":5,...}` |
| `liberty-node cluster-status --profile tiny` | node list with role/status/peer_count       |
| `liberty-node cluster-run --profile tiny --rounds 100` | packet counts for the run         |
| `liberty-node cluster-topology --profile tiny` | role counts breakdown                     |
| `liberty-node cluster-peers --profile tiny`  | per-node peer counts                        |

All commands accept `--profile tiny|small|medium|large`. Unknown profiles return
`{"error":"unknown profile: <name>"}`.

## Why Real UDP Remains Disabled

`allow_real_udp = false` on every `ClusterNodeConfig`. This is enforced at two levels:

1. `ClusterNodeConfig::validate()` — rejects any config with `allow_real_udp && simulation_mode`
2. `NodeService::start()` — refuses to bind a real socket in non-simulation mode

Sprint 16 is a local dry-run sprint. No packets leave the process. Real UDP is reserved for
Sprint 17 (Controlled Local UDP Testnet) where nodes will bind real loopback sockets under a
controlled test harness.

## Current Limitations

- **No real peering**: `NodeService` peer tables are populated separately from
  `MeshSimulator` circuit selection. The simulator uses its own random-circuit model.
- **Single-circuit routing**: `send_payload()` always uses `circuits[0]`; multi-path load
  balancing is not yet implemented.
- **No failure injection**: node failure, packet loss, and latency simulation are planned
  for a future sprint.
- **No persistence**: cluster state is entirely in-memory; there is no save/restore.

## Next Sprint Recommendation

**Sprint 17 — Controlled Local UDP Testnet**: bind real UDP sockets on loopback addresses
(127.0.0.x), wire nodes via `NodeService::connect_to_peer()`, and route actual encrypted
Noise packets between processes. The `LocalCluster` wiring layer and `ClusterTopologyProfile`
from Sprint 16 provide the foundation.
