# Sprint 29 — Traffic Scheduler

## Purpose

Epoch-based packet scheduler that mixes real data, cover traffic, padding, and control messages. Enforces per-epoch rate limits and guarantees minimum cover traffic to prevent traffic-analysis correlation.

## Packet Kinds

| Kind      | Priority | Description                                       |
|-----------|----------|---------------------------------------------------|
| Control   | 1 (first)| Network control messages; always drained first    |
| Real      | 2        | Application data; capped at `max_real_per_epoch`  |
| Cover     | 3        | Indistinguishable cover traffic; min guaranteed   |
| Padding   | 4 (last) | Filler when all other queues empty; conditional   |

## Drain Order (per epoch)

1. Drain all Control packets.
2. Drain up to `max_real_per_epoch` Real packets.
3. Drain at least `min_cover_per_epoch` Cover packets; remainder appended after Real.
4. If all queues are empty and `padding_floor > 0`, emit `padding_floor` Padding packets.

## Policy Fields (`SchedulerPolicy`)

| Field               | Default | Meaning                                 |
|---------------------|---------|-----------------------------------------|
| `epoch_ms`          | 100     | Epoch duration in milliseconds          |
| `max_real_per_epoch`| 10      | Hard cap on real packets per epoch      |
| `min_cover_per_epoch`| 2      | Minimum cover packets guaranteed        |
| `padding_floor`     | 1       | Padding packets when queues are empty   |
| `deterministic_seed`| 0       | Seed for any deterministic mixing       |

## Invariants

- `SEC29`: scheduler never exceeds `max_real_per_epoch` real packets in a single epoch's output.
- Cover packets are always present if any were enqueued (min guarantee).
- Epoch counter increments after each `drain_epoch()` call.

## Module

- `crates/liberty-node-cli/src/traffic_scheduler.rs` — scheduler + 10 tests (TS1–TS10)
