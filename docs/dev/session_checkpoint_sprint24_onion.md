# Session Checkpoint — Sprint 24: Onion Routing Layer

## Baseline

Sprint 23 complete: 601/601 tests, handshake + circuits + peer directory + cover traffic.

## Sprint 24 — Onion Routing + Circuit Building

### New modules (crates/liberty-node-cli/src/)

| Module | Purpose |
|--------|---------|
| `onion_crypto.rs` | Deterministic XOR layer crypto — `derive_layer_key`, `encrypt_layer`, `decrypt_layer` |
| `onion_packet.rs` | `OnionPacket` — `wrap_layer`, `unwrap_layer`, `wrap_layers`, `unwrap_layers` |
| `guard_selection.rs` | `select_guard` — deterministic guard node selection by lowest node_id |
| `circuit_builder.rs` | `CircuitBuilder::build_circuit` — 3-hop minimum, Guard→Relay→Exit, no duplicates |
| `onion_router.rs` | `OnionRouter` — `register_circuit`, `build_packet`, `process_packet` |

### CLI extensions

Three new commands added to `args.rs`, `output.rs`, and `lib.rs`:

| Command | Description |
|---------|-------------|
| `onion-circuit-build --nodes N` | Build deterministic 3-hop circuit from N peers |
| `onion-send --nodes N --payload P` | Wrap payload, route through all hops, report delivery |
| `onion-simulate --nodes N --rounds R` | Run R full-trip simulations, report delivered count |

### Tests added

- OC1–OC6: crypto tests (6)
- OP1–OP10: packet layer tests (10)
- GS1–GS6: guard selection tests (6)
- CB1–CB8: circuit builder tests (8)
- OR1–OR7: onion router tests (7)
- OR-CLI1–OR-CLI9, OR-SEC1: CLI integration tests (10)

**Total new tests: 47**

### Final state

- **Total tests**: 648 (326 in `liberty-node-cli`, 315 in `liberty-controlled-chaos`, 7 in main)
- **Clippy**: clean with `-D warnings`
- **`cargo fmt`**: applied

### Key invariants

1. All crypto is NON-PRODUCTION deterministic XOR — no randomness
2. No public sockets, no `0.0.0.0` binds anywhere
3. `wrap_layers` + `unwrap_layers` are strict inverses (XOR symmetry)
4. Circuit always has guard at `hops[0]`, exit at `hops[last]`
5. `OnionRouter::process_packet` returns `Delivered` only at the final hop
6. Packet size is invariant across all layers (XOR is length-preserving)
