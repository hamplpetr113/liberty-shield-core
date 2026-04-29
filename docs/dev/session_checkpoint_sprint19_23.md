# Session Checkpoint — Sprints 19–23

## Baseline

Sprint 18 complete: 201/201 tests, `EncryptedCell` over loopback UDP, NON-PRODUCTION crypto.

## Sprint 19 — Noise Handshake State Machine

**New modules**: `handshake_types`, `handshake_message`, `handshake_state`, `handshake_manager`

3-message in-memory handshake (ClientHello → ServerHello → ClientFinish).
Deterministic nonces from node IDs. Seed symmetry: `A.send == B.recv`.
Tests: HT1–HT3, HM1–HM3, HS1–HS10, H1–H9 (34 new tests).

## Sprint 20 — Integrate Handshake into UDP Layer

**Modified**: `encrypted_udp_types.rs`, `encrypted_udp_node.rs`, `encrypted_udp_cluster.rs`

- `EncryptedUdpError::HandshakeError` variant added
- `EncryptedUdpNode`: `begin_handshake`, `poll_handshake`, `is_session_established`
  — `poll_handshake` auto-installs peer session on `Established`
- `EncryptedUdpCluster`: `handshake_ring()`, `handshake_full_mesh()`
Tests: I1–I7 (7 new tests).

## Sprint 21 — Encrypted Multi-Hop Circuits

**New modules**: `encrypted_circuit_path`, `encrypted_circuit_runtime`

Min 3 hops, loop detection, TTL-limited, per-hop FNV replay detection.
`forward_next` returns `None` only after the packet passes the last hop.
Tests: CP1–CP6, C1–C9 (15 new tests).

## Sprint 22 — Peer Directory

**New module**: `peer_directory`

Guard/Relay/Exit roles by `node_id % 3`. Deterministic descriptors, sorted listing.
Tests: D1–D8 (8 new tests).

## Sprint 23 — Cover Traffic

**New module**: `cover_traffic_engine`

`ENCRYPTED_CELL_SIZE`-byte cover packets via the full `make_encrypted_cell` pipeline.
Deterministic seed, interleaved mixing with real packets.
Tests: CT1–CT7 (7 new tests).

## CLI Extensions

5 new commands: `handshake-ring`, `circuit-run`, `circuit-status`,
`directory-status`, `cover-traffic-run`.

Tests: CLI-S1–CLI-S8, S1–S8 (16 new tests).

## Final State

- **Total tests**: 601 (315 in `liberty-controlled-chaos`, 279 in `liberty-node-cli`, 7 in main)
- **Clippy**: clean with `-D warnings`
- **`cargo fmt`**: applied
- **Commit**: not made (per standing instruction)

## Key Invariants

1. All UDP sockets bind to `127.0.0.1` only — `PublicBindRejected` enforced at config level
2. `HandshakeError` from session before handshake (`SessionNotFound`)
3. Circuits require ≥ 3 hops, no repeated nodes, TTL countdown
4. Cover packets are exactly `ENCRYPTED_CELL_SIZE` bytes — indistinguishable from data cells
5. All JSON output free of `0.0.0.0`
