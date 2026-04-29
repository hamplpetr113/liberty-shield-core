# Sprint 15 — Liberty Node Runtime Foundation

## 1. Purpose

Sprint 15 moves Liberty Shield from a simulation-only CLI toward a real node runtime foundation. It adds configuration, deterministic identity derivation, a peer table, and a node service lifecycle — all while keeping every network behaviour safely controlled, testable, and offline. This sprint establishes the structural foundation that future sprints will extend with real cryptography and actual UDP transport.

**This is NOT yet a public network node.** No sockets are opened, no external servers are contacted, and all simulated behaviour is deterministic and in-process.

## 2. What Was Implemented

New files added to `crates/liberty-node-cli/src/`:

| File | Purpose |
|------|---------|
| `config.rs` | `NodeConfig` with validation; `ConfigError` |
| `identity.rs` | `NodeIdentity` placeholder derivation |
| `peer_table.rs` | `PeerTable` with sorted peer management |
| `runtime_state.rs` | `NodeServiceState` enum; `NodeRuntimeSnapshot` |
| `node_service.rs` | `NodeService` lifecycle orchestrator |

Updated files:

| File | Change |
|------|--------|
| `args.rs` | Added `start`, `status`, `peers` subcommands |
| `output.rs` | Added `start_json`, `status_json`, `peers_json`, `service_error_json` |
| `lib.rs` | Wired new commands into `execute()`; added CLI1–CLI5 tests |

## 3. Why Real UDP Remains Disabled

`allow_real_udp` is present in `NodeConfig` to model the configuration surface, but `NodeService::start()` returns `ServiceError::RealUdpNotAllowed` whenever it is `true`. This is intentional:

- The Noise handshake has not yet been wired to a real socket
- Production cryptographic keys (X25519 / Ed25519) have not been implemented
- The peer discovery protocol is not yet defined
- Opening real sockets in a test binary would break the determinism guarantee

Real UDP will be enabled in a future sprint, guarded behind a feature flag, and tested with loopback sockets only.

## 4. Simulation Mode

When `simulation_mode = true` (the default), the node uses `MeshSimulator` for all packet routing:

```
NodeService::bootstrap_simulation(node_count, circuits)
    → creates NodeRuntime::new(node_count)
    → builds circuits

NodeService::start()
    → does NOT open sockets (simulation_mode only)
    → transitions state: Created → Running

NodeService::run_simulation_rounds(rounds)
    → delegates to NodeRuntime::run_rounds(rounds)
    → updates packets_simulated and packets_forwarded counters
    → returns Err(NotStarted) if called before start()
```

All packet counts and path metrics are deterministic and reproducible across runs.

## 5. NodeConfig

```
NodeConfig {
    node_name: String          // default: "liberty-node-local"
    node_id: u64               // default: 1
    bind_address: String       // default: "127.0.0.1"
    bind_port: u16             // default: 39000
    max_peers: usize           // default: 64
    simulation_mode: bool      // default: true
    allow_real_udp: bool       // default: false
}
```

Validation rejects: `bind_port == 0`, `max_peers == 0`, and `allow_real_udp && simulation_mode` (conflicting modes).

## 6. NodeIdentity — NON-PRODUCTION Placeholder Warning

**WARNING: `NodeIdentity` keys are NOT real cryptographic keys.**

Both `public_key` and `private_key_placeholder` are derived deterministically from `node_id` using integer arithmetic only. They have no cryptographic security properties and MUST NOT be used in any production or network-facing context.

Real key generation (X25519 for key exchange, Ed25519 for signing) is deferred to a future sprint alongside the `chacha20poly1305` + HKDF integration recommended in the Sprint 12 security audit.

## 7. PeerTable

`PeerTable` stores `PeerInfo` entries sorted by `peer_id` for deterministic iteration. It enforces:

- **No duplicates** — `add_peer` returns `DuplicatePeer` if the ID already exists
- **Capacity limit** — `add_peer` returns `TableFull` when `max_peers` is reached
- **Deterministic ordering** — `list_peers()` always returns entries sorted by `peer_id`

The table supports `mark_connected` / `mark_disconnected` for tracking live peer state without any network I/O.

## 8. NodeService Lifecycle

```
Created
  ↓ new(config)
  ↓ bootstrap_simulation(node_count, circuits)   [optional]
Configured
  ↓ start()
Running
  ↓ run_simulation_rounds(n)                     [repeatable]
  ↓ stop()
Stopped
```

Additional states (`IdentityReady`, `PeersReady`, `Error`) are defined for future phases when real handshaking and peer discovery are introduced.

`stop()` transitions directly to `Stopped` from any state; it is always safe to call.

## 9. CLI Commands

| Command | Description | Example output |
|---------|-------------|----------------|
| `liberty-node start` | Start node in simulation mode | `{"command":"start","state":"Running","simulation_mode":true,"node_id":1}` |
| `liberty-node status` | Current node state (fresh) | `{"command":"status","state":"Created","simulation_mode":true,...}` |
| `liberty-node peers` | List known peers | `{"command":"peers","peers":[]}` |
| `liberty-node run` | Run simulation rounds | `{"metrics":{...}}` |
| `liberty-node topology` | Print topology | `{"node_count":100,...}` |
| `liberty-node bench` | Benchmark with timing | `{"elapsed_us":...,"throughput_packets_per_sec":...}` |

All commands output valid JSON. Errors are reported as `{"error": "<message>"}`.

## 10. Next Sprint Recommendation

Sprint 16 candidates, in order of risk:

1. **Production crypto** — replace placeholder identity with real X25519 / Ed25519 keys using `ring` or `ed25519-dalek`; add HKDF key derivation; integrate `chacha20poly1305` for cell encryption. Required before any real networking.

2. **Config file loading** — add `NodeConfig::from_file(path)` parsing a TOML config; add `--config` flag to the CLI. Low risk, high usability.

3. **Loopback UDP integration** — enable `allow_real_udp` behind a feature flag; wire `UdpTransport` to a loopback socket pair; test with two local node instances communicating on `127.0.0.1`.

Production crypto (option 1) is the highest-priority blocker. Real networking without it would send plaintext.
