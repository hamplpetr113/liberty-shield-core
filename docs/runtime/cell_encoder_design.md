# CellEncoder Design — Sprint 7 Phase 4

**Version:** 1.0
**Status:** Design — no implementation yet.
**Scope:** The CellEncoder layer that sits between `StreamMux` and `NoiseLink`.

---

## 1. Purpose

`StreamMux` emits `StreamFrame` values that carry sequenced, prioritised metadata and an opaque `PayloadRef` handle. `NoiseLink` expects fixed-size transport cells that can be encrypted and forwarded without knowledge of stream structure.

`CellEncoder` bridges these two concerns. Its responsibilities are:

**Cell construction.** Convert each `StreamFrame` into a fixed-size `Cell` (1450 bytes) by serialising the frame header fields and padding the payload region to the constant cell size. `NoiseLink` always receives cells of exactly 1450 bytes regardless of actual payload length.

**Constant-size enforcement.** All cells emitted by `CellEncoder` are the same size. This prevents traffic-analysis attacks that would otherwise allow an observer to infer payload sizes from ciphertext length.

**Payload opacity.** `CellEncoder` treats `PayloadRef` as an opaque handle. It copies the encrypted payload bytes into the cell's payload region without inspecting, transforming, or logging their content. The payload is already encrypted before it reaches `CellEncoder`.

**Stream metadata preservation.** The `stream_id`, `sequence_number`, `path_id`, `fragment_id`, and `payload_length` fields from the `StreamFrame` are serialised verbatim into the cell header. `NoiseLink` and the far-end decoder use these fields for replay detection and stream reassembly.

The invariant `CellEncoder` upholds: every `Cell` emitted corresponds to exactly one `StreamFrame`. No cell may be produced without a `StreamFrame` input.

---

## 2. Cell Format

Each cell is exactly **1450 bytes**.

### 2.1 Header (43 bytes)

| Field | Type | Size | Description |
|---|---|---|---|
| `version` | `u8` | 1 byte | Cell format version. Current value: `0x01`. |
| `flags` | `u8` | 1 byte | Bitmask. Bit 0: `is_cover` (shadow/cover cell). Bit 1: `is_reset` (StreamReset cell). Bits 2–7: reserved, must be zero. |
| `stream_id` | `u64` | 8 bytes | Forwarded from `StreamFrame.stream_id`. Little-endian. |
| `sequence_number` | `u64` | 8 bytes | Forwarded from `StreamFrame.sequence_number`. Little-endian. |
| `path_id` | `u64` | 8 bytes | Forwarded from `StreamFrame.path_id`. Little-endian. |
| `fragment_id` | `u64` | 8 bytes | Forwarded from `StreamFrame.fragment_id`. Little-endian. |
| `payload_length` | `u16` | 2 bytes | Actual payload byte count in the payload region (before padding). Little-endian. Range: `[0, 1407]`. |

Total header size: 1 + 1 + 8 + 8 + 8 + 8 + 2 = **43 bytes**.

### 2.2 Payload Region (variable, up to 1407 bytes)

The `payload_length` bytes immediately following the header contain the encrypted payload, copied verbatim from the caller-managed buffer pool via `PayloadRef`. `CellEncoder` never reads these bytes for any purpose other than copying.

### 2.3 Padding Region (constant-fill to 1450 bytes)

The remaining `1450 - 43 - payload_length` bytes are filled with padding. Padding bytes must be indistinguishable from ciphertext to an observer. The padding source is a PRNG seeded per-session; the exact PRNG is specified at implementation time (ChaCha8 is the expected choice, consistent with other Liberty Shield components).

For `StreamReset` cells (`flags & 0x02 != 0`), `payload_length` is `0` and the entire payload+padding region (1407 bytes) is padding.

---

## 3. Encoder Responsibilities

### 3.1 StreamFrame → Cell conversion

For each `StreamFrame` received from `StreamMux`:

1. Serialise the header fields into a 43-byte header buffer (all multi-byte fields little-endian).
2. Set `flags` based on `StreamFrame.frame_kind`:
   - `Data` or `BurstHead` → `flags = 0x00`
   - `Cover` → `flags = 0x01`
   - `StreamReset` → `flags = 0x02`
3. Copy `payload_length` bytes from the buffer pool at `payload_ref.pool_index()` into the payload region. For `StreamReset` frames (`payload_ref = None`), skip this step.
4. Fill the remainder of the 1450-byte cell with padding bytes from the session PRNG.
5. Return the completed `Cell`.

### 3.2 Constant cell size enforcement

`CellEncoder` must reject any `StreamFrame` whose `payload_ref.length()` exceeds 1407 bytes (the maximum payload capacity of a cell). Such frames are returned as `CellEncoderError::PayloadTooLarge`. This is a defence-in-depth check; `PayloadRef::new()` already enforces a maximum of 1500 bytes, but 1407 is the tighter limit imposed by the cell format.

### 3.3 Payload opacity

`CellEncoder` copies payload bytes but must not:
- Inspect payload content for any purpose.
- Log or emit payload bytes.
- Apply any transformation to payload bytes.
- Hold a reference to the buffer pool beyond the scope of a single `encode()` call.

### 3.4 Stream ordering preservation

`CellEncoder` encodes frames in the order they are submitted. It does not reorder frames. Ordering guarantees are upheld by `StreamMux`; `CellEncoder` preserves them by encoding one cell per call without internal buffering.

---

## 4. Security Constraints

`CellEncoder` must never:

- **Vary cell size by payload length.** All cells are exactly 1450 bytes. An observer seeing variable-length ciphertext could infer payload sizes.
- **Open sockets or import networking crates.** `CellEncoder` is a pure transformation layer.
- **Use `unsafe` Rust.** No raw pointer arithmetic, no `unsafe` blocks.
- **Inspect payload bytes.** The payload is opaque encrypted data. `CellEncoder` copies it without reading.
- **Emit a cell without a `StreamFrame` input.** There is no `encode_raw` or equivalent method.
- **Reuse padding across cells.** Each cell's padding region must be freshly generated from the session PRNG.

**Compile-time enforcement:**

- `CellEncoder::encode` accepts `StreamFrame` by value (consuming it), enforcing one-frame-one-cell at the type level.
- `Cell` must not expose a raw `*const u8` payload pointer.
- No `unsafe` block is permitted anywhere in the `cell_encoder` module.

---

## 5. Rust Module Plan

```
crates/liberty-controlled-chaos/src/cell_encoder/
    mod.rs      — module declarations, public re-exports
    types.rs    — Cell, CellHeader, CellFlags, CellEncoderError
    encoder.rs  — CellEncoder, encode(), padding PRNG wiring
```

### 5.1 `types.rs`

```
/// Fixed-size transport cell: exactly 1450 bytes.
struct Cell {
    data: [u8; 1450],
}

impl Cell {
    fn header(&self) -> CellHeader  // parsed view of the first 43 bytes
    fn payload_bytes(&self) -> &[u8]  // slice of length header.payload_length
    fn as_bytes(&self) -> &[u8; 1450]  // the full cell for NoiseLink
}

struct CellHeader {
    version: u8,
    flags: u8,
    stream_id: u64,
    sequence_number: u64,
    path_id: u64,
    fragment_id: u64,
    payload_length: u16,
}

enum CellEncoderError {
    PayloadTooLarge { length: u16, max: u16 },
    PayloadRefInvalid,
}
```

### 5.2 `encoder.rs`

```
struct CellEncoder {
    // Session PRNG for padding generation.
    // Fields determined at implementation time.
}

impl CellEncoder {
    fn new(session_seed: u64) -> Self;

    /// Convert one StreamFrame into one Cell.
    /// Consumes the StreamFrame (one frame → one cell).
    fn encode(
        &mut self,
        frame: StreamFrame,
        payload_buf: &[u8],  // caller resolves PayloadRef → &[u8] before calling
    ) -> Result<Cell, CellEncoderError>;
}
```

---

## 6. Tests Required Before Implementation

| ID | Test name | What it asserts |
|---|---|---|
| E1 | `constant_cell_size` | Every `Cell` returned by `encode()` is exactly 1450 bytes regardless of payload length. |
| E2 | `payload_length_validated` | A `StreamFrame` with `payload_ref.length() > 1407` returns `Err(PayloadTooLarge)`. |
| E3 | `deterministic_header_encoding` | Two calls with the same `StreamFrame` fields produce cells with identical header bytes. |
| E4 | `payload_bytes_preserved` | The payload region of the encoded cell contains the input payload bytes verbatim. |
| E5 | `padding_fills_remainder` | `cell.as_bytes()[43 + payload_length ..]` has length `1450 - 43 - payload_length`. |
| E6 | `stream_reset_cell_has_zero_payload` | A `StreamReset` frame produces a cell with `payload_length = 0` and `flags & 0x02 != 0`. |
| E7 | `cover_cell_flags_set` | A `Cover` frame produces a cell with `flags & 0x01 != 0`. |
| E8 | `stream_metadata_preserved` | `stream_id`, `sequence_number`, `path_id`, `fragment_id` in the decoded header match the input `StreamFrame` fields. |
| E9 | `no_networking_dependencies` | `cargo tree -p liberty-controlled-chaos` does not contain `tokio`, `mio`, or `socket2`. |
