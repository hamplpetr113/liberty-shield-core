# Session Checkpoint — Sprint 17: Controlled Local UDP Testnet

## Sprint Goal

Introduce real UDP socket binding to Liberty Shield for the first time, using only
`127.0.0.1` loopback addresses. Prove the packet codec and socket wiring work correctly
before encrypted packet flow is introduced. Keep the default runtime simulation-only;
real UDP is strictly opt-in.

## Completed Phases

### Phase 1 — udp_testnet_types.rs
`UdpTestnetMode` (Disabled default / LoopbackOnly), `UdpTestnetNodeId`, `UdpTestnetPacketKind`
(Probe/Data/Cover/Shutdown), `UdpTestnetError` (9 variants), `UdpTestnetNodeConfig` with
5-rule validation. Tests UT1–UT5.

### Phase 2 — udp_testnet_packet.rs
`UdpTestnetPacket` with `encode_packet` / `decode_packet`. 27-byte big-endian wire header:
source_node(8) + target_node(8) + kind(1) + sequence(8) + payload_len(2). Tests PK1–PK5.

### Phase 3 — udp_loopback_socket.rs
`UdpLoopbackSocket` wrapping `std::net::UdpSocket`. `bind()` checks address == "127.0.0.1".
`send_to()` checks `IpAddr::is_loopback()` before any syscall. `try_recv()` handles
`WouldBlock`/`TimedOut` as `Ok(None)`. Non-blocking always. Tests SO1–SO5.

### Phase 4 — udp_testnet_node.rs
`UdpTestnetNode` with sequence counter, per-node packet counters, and `poll_once()`.
`poll_once()` swallows `PacketDecodeFailed` as a dropped packet (increments dropped,
returns `Ok(None)`). Tests UN1–UN6.

### Phase 5 — udp_testnet_cluster.rs
`UdpTestnetCluster` with ring topology. `send_probe_ring()` and `send_data_round()` use
pre-collected snapshots to avoid borrow conflicts. `poll_all()` drains each node's buffer
completely. Tests UC1–UC6.

### Phase 6 — CLI commands (args.rs, output.rs, lib.rs)
4 new commands: `udp-testnet-start`, `udp-testnet-probe`, `udp-testnet-data`,
`udp-testnet-status`. Poll loop up to 200 iterations after send (loopback delivers in <1
iteration in practice). Tests CLI-UDP1–CLI-UDP6.

### Phase 7 — Safety gate tests (SG1–SG8)
8 automated safety tests in lib.rs covering all constraint enforcement layers. SG4 uses
a real bound socket to verify non-loopback `send_to` is rejected at the socket layer.

### Phase 8 — Documentation
`docs/runtime/controlled_udp_testnet_sprint17.md` — safety model, loopback-only rationale,
real vs non-production inventory, CLI command table, security gates table, Sprint 18 plan.

### Phase 9 — Final validation
- `cargo fmt -p liberty-node-cli` — clean
- `cargo test -p liberty-node-cli` — **137/137 passed**
- `cargo test --workspace` — all workspace tests pass
- `cargo clippy -p liberty-node-cli -p liberty-controlled-chaos -- -D warnings` — clean

## Bugs Fixed During Validation

1. `UdpTestnetMode` manual `Default` impl rejected by `clippy::derivable_impls` — replaced
   with `#[derive(Default)]` + `#[default]` on `Disabled` variant.
2. `UdpLoopbackSocket`, `UdpTestnetNode`, `UdpTestnetCluster` missing `#[derive(Debug)]`
   required by `unwrap_err()` in tests — added to all three.

## Test Count

| Module / area | Tests |
|---|---|
| udp_testnet_types | UT1–UT5 (5) |
| udp_testnet_packet | PK1–PK5 (5) |
| udp_loopback_socket | SO1–SO5 (5) |
| udp_testnet_node | UN1–UN6 (6) |
| udp_testnet_cluster | UC1–UC6 (6) |
| lib (CLI UDP) | CLI-UDP1–6 (6) |
| lib (safety gates) | SG1–SG8 (8) |
| Sprint 16 legacy | 96 (unchanged) |
| **Total** | **137** |

## Key Design Decisions

1. `bind_address` enforced in both `validate()` and `bind()` — defense in depth; callers
   who skip `validate()` still can't bind a public address.
2. `send_to` checks `IpAddr::is_loopback()` (true for all `127.x.x.x`) — no hardcoded
   `"127.0.0.1"` string check at the socket layer.
3. `try_recv()` handles both `WouldBlock` and `TimedOut` — portable across Linux/Windows.
4. `poll_all()` uses `while let Ok(Some(_)) = node.poll_once()` — drains the full OS
   buffer per node in one call, avoiding partial receive issues.
5. `send_probe_ring()` collects snapshots into a `Vec` first — avoids borrow conflict
   between `iter()` (immutable) and indexed `[i]` (mutable) in the same loop.
6. CLI poll loop runs up to 200 iterations — loopback delivers in <1 iteration in practice,
   but extra budget is free (non-blocking) and provides buffer for loaded CI machines.

## Files Created

- `crates/liberty-node-cli/src/udp_testnet_types.rs`
- `crates/liberty-node-cli/src/udp_testnet_packet.rs`
- `crates/liberty-node-cli/src/udp_loopback_socket.rs`
- `crates/liberty-node-cli/src/udp_testnet_node.rs`
- `crates/liberty-node-cli/src/udp_testnet_cluster.rs`
- `docs/runtime/controlled_udp_testnet_sprint17.md`

## Files Modified

- `crates/liberty-node-cli/src/args.rs` (+4 commands)
- `crates/liberty-node-cli/src/output.rs` (+5 output functions)
- `crates/liberty-node-cli/src/lib.rs` (+5 modules, +4 execute arms, +14 tests)

## What Remains Non-Production

- No encryption (plaintext packets over loopback)
- No Noise handshake
- No replay protection on this path
- NodeIdentity keys are deterministic test vectors
- No peer discovery
- No rate limiting

## Next Sprint

**Sprint 18 — Encrypted UDP Packet Flow**: wire `NoiseChannel` handshake between
`UdpTestnetNode` peers, route `EncryptedCell` objects through `UdpLoopbackSocket`,
connect `ReplayFilter` to `poll_encrypted()`. Plan at:
`docs/runtime/sprint18_encrypted_udp_packet_flow_plan.md`
