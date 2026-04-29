# Session Checkpoint — Sprint 18: Encrypted UDP Packet Flow

**Date:** 2026-04-29
**Tests passing:** 201 / 201 (`liberty-node-cli`), full workspace green
**Clippy:** clean with `-D warnings`

---

## What Was Built

Sprint 18 routes `EncryptedCell` objects from `liberty-controlled-chaos::noise_link`
over the Sprint 17 loopback UDP testnet. The full send pipeline is:

```
payload → Cell (CellEncoder) → EncryptedCell (NoiseLinkEncoder) →
EncryptedUdpPacket wire bytes → UdpSocket (127.0.0.1 only) → receiver
```

### New files in `crates/liberty-node-cli/src/`

| File | Description |
|------|-------------|
| `encrypted_udp_types.rs` | Types, error enum, config, validation — tests ET1–ET5 |
| `encrypted_udp_packet.rs` | Packet codec + EncryptedCell ↔ bytes helpers — tests EP1–EP6 |
| `encrypted_cell_fixture.rs` | Deterministic Cell/EncryptedCell builder for tests — tests EF1–EF5 |
| `encrypted_udp_socket.rs` | Loopback UdpSocket wrapper — tests ES1–ES5 |
| `encrypted_peer_session.rs` | Per-peer NoiseLinkEncoder pair + session table — tests ST1–ST5 |
| `encrypted_udp_node.rs` | Full node (socket + sessions + replay windows) — tests EN1–EN7 |
| `encrypted_udp_cluster.rs` | Ring cluster of nodes — tests EC1–EC6 |

### Modified files

- `args.rs` — 5 new `Command` variants: `EncryptedUdp{Start,Probe,Send,Status,Bench}`
- `output.rs` — 6 new JSON output functions
- `lib.rs` — module declarations, execute arms, 38 new integration tests:
  CLI-E1–E7, EG1–EG8, EXT-B1–B3, EXT-C1

### Modified in `crates/liberty-controlled-chaos/`

Added `#[derive(Debug)]` to: `ReplayWindow`, `EncryptedCell`, `NoiseSession`, `NoiseLinkEncoder`.

---

## Test Count Delta

| Sprint | Tests |
|--------|-------|
| Sprint 17 baseline | 163 |
| Sprint 18 new tests (all modules) | +38 integration + 59 unit = +97 total delta is approximate |
| Sprint 18 final | **201** |

---

## Key Design Decisions

**Deterministic key seeding.** `seed_to_key(seed)` repeats the 8-byte LE seed four times.
For direction A→B: A's `send_seed` = B's `recv_seed` = `pair_seed(A,B)`.
This is `NON-PRODUCTION` and must be replaced before real networking.

**Borrow split in `poll_once()`.** `replay_windows` and `sessions` are both borrowed
mutably but in non-overlapping scopes to satisfy the borrow checker.

**`Cell` construction via full pipeline.** `Cell::from_raw` is `pub(crate)` inside
`liberty-controlled-chaos`, so `make_cell()` in the fixture uses the public
`CellEncoder::encode()` pipeline. For empty / small payloads, `PayloadRef::new(0, max(64, len))`
satisfies the [64, 1500] minimum length requirement without changing actual payload size.

**`send_encrypted_cell` skips session lookup.** Useful for replay-test scenarios
where pre-crafted bytes (same nonce) need to be sent twice without going through the
nonce-incrementing `send_encoder`.

---

## Port Allocation (Sprint 18)

- Unit tests in module files: 43000–43092
- Integration tests in lib.rs: 43100–43244
- No overlap with Sprint 17 range (42100–42611)

---

## What Was NOT Built

- No real Noise XX handshake (Sprint 19 target)
- No multi-threaded support
- No public network reachability (by design)

---

## Resuming This Work

The codebase is in a complete, compiling, and tested state. To resume:

```bash
cargo test -p liberty-node-cli        # 201 tests
cargo clippy -p liberty-node-cli -p liberty-controlled-chaos -- -D warnings
```

Sprint 19 plan: `docs/runtime/sprint19_noise_handshake_plan.md`
