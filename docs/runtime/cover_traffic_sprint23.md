# Cover Traffic Engine — Sprint 23

## Overview

Sprint 23 adds a deterministic cover traffic generator for the loopback testnet.
Cover packets are exactly `ENCRYPTED_CELL_SIZE` bytes — indistinguishable in size
from genuine encrypted data cells.

**NON-PRODUCTION**: In production, nonces must be randomly generated per packet.

## File

`cover_traffic_engine.rs` — `CoverTrafficEngine`, `CoverPacket`, `CoverOrReal`

## Packet Generation

Each packet is produced by:
1. Deriving a per-packet seed: `seed * K1 + node_id + counter`
2. Building a 64-byte deterministic dummy payload via `build_dummy_payload`
3. Calling `make_encrypted_cell(payload, pkt_seed)` → real `EncryptedCell` pipeline
4. Serialising to `ENCRYPTED_CELL_SIZE` bytes: `path_id | nonce | ciphertext | auth_tag`

Fallback: if `make_encrypted_cell` fails, a zeroed buffer of `ENCRYPTED_CELL_SIZE` is used.

## Scheduling

`schedule_cover_traffic(n)` pre-computes `n` tick offsets in `[1, 100]` from the seed.
`schedule()` returns the current tick schedule.

## Mixing

`mix_cover_and_real_packets(real, cover_count)` interleaves real and cover packets:
- Starts with real packets, alternates with cover packets
- Drains all packets regardless of imbalance (uses `is_empty()` sentinel, not counters)
- Returns `Vec<CoverOrReal>` with `real.len() + cover_count` entries

## CLI Command

`cover-traffic-run --node-id N --seed S --count C` generates C packets and reports
whether all are `ENCRYPTED_CELL_SIZE` bytes.

## Tests (CT1–CT7)

- CT1: packet size is exactly `ENCRYPTED_CELL_SIZE`
- CT5: same seed and node_id reproduce identical byte sequences
- CT4: mix returns correct count with correct real/cover ratio
- CT7: sequence counter increments monotonically
