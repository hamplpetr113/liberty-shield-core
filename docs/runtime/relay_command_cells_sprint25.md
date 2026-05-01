# Sprint 25 — Relay Command Cells

## Purpose

The relay cell layer provides a typed, wire-encoded unit of circuit communication. Each cell carries a command tag, sequence number, circuit/stream IDs, and an opaque payload. Uniform wire encoding means all cells are indistinguishable by length to a passive observer.

## Wire Format (27-byte header)

```
Offset  Size  Field
     0     8  circuit_id   (u64 LE)
     8     8  stream_id    (u64 LE)
    16     1  command tag  (u8)
    17     8  sequence     (u64 LE)
    25     2  payload_len  (u16 LE)
    27     N  payload      (up to MAX_RELAY_PAYLOAD = 498 bytes)
```

Total max cell size: 525 bytes.

## Command Tags

| Tag | Variant         | Purpose                              |
|-----|----------------|--------------------------------------|
|   1 | `RelayData`     | Carry application data               |
|   2 | `RelayEnd`      | Signal stream teardown               |
|   3 | `RelayConnected`| Confirm stream established           |
|   4 | `RelaySendMe`   | Flow-control credit acknowledgement  |
|   5 | `RelayExtend`   | Request next-hop circuit extension   |
|   6 | `RelayExtended` | Confirm circuit extension            |
|   7 | `RelayDrop`     | Cover / padding cell (discarded)     |

## Key Constraints

- `MAX_RELAY_PAYLOAD = 498` bytes; payloads exceeding this return `PayloadTooLarge`.
- Unknown command tags produce `UnknownCommand(u8)`.
- Buffers shorter than the header produce `BufferTooShort`.
- Declared `payload_len` beyond remaining bytes produces `TruncatedPayload`.

## Modules

- `crates/liberty-node-cli/src/relay_cell.rs` — types
- `crates/liberty-node-cli/src/relay_cell_codec.rs` — encode/decode + 12 tests (RC1–RC12)
