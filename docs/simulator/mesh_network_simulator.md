# Mesh Network Simulator

## 1. Purpose

The Mesh Network Simulator provides a deterministic, in-process simulation of the Liberty Shield protocol stack. It enables fast, repeatable testing of onion routing, replay protection, cover traffic, and mesh topology without real network I/O, OS threads, or cryptographic overhead. All state is caller-driven; there is no randomness, no system clock dependency, and no external side effects.

## 2. Simulator Architecture

```
MeshSimulator
├── MeshTopology          — static node graph (guards, relays, exits, links)
├── HashMap<u64, SimNodeState>  — per-node forward/drop/cover counters + replay detector
├── CircuitRuntime        — registered circuit_builder::Circuit objects
├── MeshRouter            — deterministic next-hop lookups via RoutingTable
├── MeshMetrics           — aggregate simulation statistics
└── Vec<SimCircuit>       — active simulated routes (circuit_id + route node IDs)
```

`MeshSimulator::new(node_count)` wires all components from a single integer. No builder pattern, no configuration files.

## 3. Packet Flow Model

Every call to `send_payload` or `send_on_circuit` executes the following pipeline:

```
PacketFlowEngine::make_cell(circuit_id, nonce, payload)
    → EncryptedCell { path_id, nonce, ciphertext[1450], auth_tag[16] }
    → 1482 bytes on wire (constant regardless of payload length)

For each node_id in circuit.route:
    SimNodeState.replay_detector.check_cell(CircuitId, CellNonce)
        Ok(())             → record_forward; HopResult { accepted: true }
        Err(DuplicateNonce)→ record_drop;    HopResult { accepted: false, ReplayDetected }
        Err(WindowExpired) → record_drop;    HopResult { accepted: false, ReplayWindowExpired }
    NodeNotFound           →                 HopResult { accepted: false, NodeNotFound }
    If !accepted: delivered = false; break

If delivered: metrics.record_delivery(hop_count)
```

Packet size is always `ENCRYPTED_CELL_SIZE = 1482` bytes. Payload content never affects routing decisions.

## 4. Node Roles

| Role  | Count (100-node topology) | ID range  | Function                          |
|-------|--------------------------|-----------|-----------------------------------|
| Guard | 10                       | 1–10      | Entry point; client connects here |
| Relay | 80                       | 11–90     | Mid-path forwarding               |
| Exit  | 10                       | 91–100    | Final hop; reaches destination    |

Every circuit is exactly 3 hops: Guard → Relay → Exit. Circuit `i` selects `guard[i % 10]`, `relay[i % 80]`, `exit[i % 10]`.

Links are directed: each guard links to one relay (`guard[g] → relay[g % relays]`), each relay links to one exit (`relay[r] → exit[r % exits]`). A 100-node topology has 90 links (10 guard→relay + 80 relay→exit).

## 5. Deterministic Simulation Rules

- **No randomness.** `generate_deterministic(node_count)` uses only integer arithmetic.
- **No system time.** Epoch arguments (`tick_cover_traffic(epoch)`) are caller-supplied integers.
- **Monotonic nonces.** `send_payload` increments an internal counter; nonces never repeat across calls, so replay detection never fires unless the caller explicitly reuses a nonce via `send_on_circuit`.
- **Stable circuit IDs.** Circuit `i` always has `circuit_id = i + 1`.
- **Node IDs are stable.** Guards occupy IDs `1..=guard_count`, relays `guard_count+1..=guard+relay`, exits `relay+1..=total`.
- **Peer addresses.** Each node's address is `127.0.0.1:{9000 + node_id}`.

## 6. What Is Simulated

- Mesh topology (guards, relays, exits, directed links)
- 3-hop onion circuit construction and registration
- Per-node replay detection with sliding window (via `ReplayDetector`)
- Per-node packet forwarding, drop, and cover-traffic counters
- Cover traffic generation via `CoverTrafficGenerator::generate_epoch`
- Aggregate metrics: packets sent/forwarded/dropped, replay rejections, cover packets, average path length
- Constant wire-size cells (1482 bytes) regardless of payload
- Circuit-ID preservation end-to-end

## 7. What Is Not Real Networking

- No UDP or TCP sockets. `PeerAddress` values are stored but never connected.
- No real encryption. `PacketFlowEngine::make_cell` fills `ciphertext` with the payload (zero-padded) and derives a deterministic `auth_tag` from `(circuit_id, nonce)` — no Noise protocol, no ChaCha20, no Poly1305.
- No actual onion layering. `CircuitBuilder` is invoked to test registration paths; the simulation routes by node ID, not by decrypting onion layers.
- No concurrency. All state is single-threaded; there are no async tasks, channels, or mutexes.
- No clock. Replay window expiry is driven by nonce distance, not wall time.
- No network failure injection. Every reachable node always forwards unless replay is detected.

## 8. Next Step: CLI Node

The mesh simulator is the foundation for a CLI-driven node harness. The recommended next component is a `cli_node` binary that:

1. Accepts `--node-count N` and `--circuits C` arguments.
2. Constructs a `MeshSimulator` and runs a configurable number of rounds.
3. Prints per-hop statistics and final `MeshMetrics` as structured JSON.
4. Serves as the basis for fuzz targets and property-based tests against the full simulator API.

This keeps the simulation layer pure (no I/O) while providing a human-readable entry point for manual validation and CI smoke tests.
