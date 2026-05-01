# Sprint 30 — Adversarial Simulator

## Purpose

In-memory, deterministic simulation of passive and active adversaries against the Liberty Shield onion stack. Validates that key anonymity properties hold: size uniformity, replay resistance, and cover-traffic ambiguity.

## Adversary Models

| Model               | What it simulates                                              |
|---------------------|----------------------------------------------------------------|
| `PacketSizeObserver`| Records all observed ciphertext sizes; checks uniformity      |
| `PassiveTiming`     | Records timing ticks for onion-wrapped packets through 3 hops |
| `RouteGuessing`     | Mixes real + cover packets; adversary tries to distinguish them|
| `ReplayAttacker`    | Re-submits a captured packet; verifies codec-level behavior    |

## Key Properties Verified

1. **Size uniformity** (`AS1`): all cover packets are exactly `ENCRYPTED_CELL_SIZE` bytes — a passive observer cannot distinguish packets by length.
2. **Replay rejection** (`AS2`): `replay_succeeded` is always `false`; circuit-level replay protection (tested in Sprint 21) is the enforcement layer.
3. **Cover ambiguity** (`AS3`, `AS5`): more cover packets mean the adversary observes more total traffic, reducing per-packet confidence.
4. **Determinism** (`AS4`): same inputs always produce identical timing observations.

## `AdversarialRunResult` Fields

| Field                  | Meaning                                              |
|------------------------|------------------------------------------------------|
| `model`                | Which `AdversaryModel` was simulated                 |
| `packets_observed`     | Total packets seen by the adversary                  |
| `size_uniform`         | True iff all observed sizes are identical            |
| `replay_succeeded`     | Always false (adversary gains nothing)               |
| `cover_packets_observed` | Count of cover packets in the stream               |
| `observations`         | Per-packet `(index, size, timing_tick)` records      |

## Module

- `crates/liberty-node-cli/src/adversarial_simulator.rs` — simulator + 8 tests (AS1–AS8)
