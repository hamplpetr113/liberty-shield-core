# StreamMux Design — Sprint 7 Phase 2

**Version:** 1.0  
**Status:** Design — no implementation yet.  
**Scope:** The StreamMux layer that sits between `RuntimeBoundaryValidator` and `CellEncoder`.

---

## 1. Purpose

`RuntimeBoundaryValidator` answers a single question per packet: *is this intent safe to transmit?* It knows nothing about ordering, grouping, or flow structure. `CellEncoder` answers a single question per frame: *how do I frame and encrypt this payload?* It knows nothing about where a frame sits relative to other frames in a flow.

`StreamMux` exists to bridge these two concerns. Its responsibilities are:

**Stream identity.** A flow traversing multiple paths produces traffic on multiple logical streams. `StreamMux` assigns a stable, deterministic `stream_id` to each (flow, path, class) triple and maintains the boundary between real and shadow traffic at the stream level. `CellEncoder` and `NoiseLink` see only frames on a stream, never the original `flow_id`.

**Sequencing.** Every frame emitted from `StreamMux` carries a monotonically increasing `sequence_number` scoped to its stream. This gives `CellEncoder` and the far-end decoder enough information to detect gaps, detect replays, and reconstruct ordering without exposing the raw `flow_id` to lower layers.

**Queue management.** The validated intents arriving from `RuntimeBoundaryValidator` carry absolute deadlines. `StreamMux` is responsible for holding frames that arrive before their `scheduled_send_time` is reached and for expiring frames that miss their `latency_deadline` before they can be handed to `CellEncoder`.

**Priority separation.** Real frames must never be delayed or dropped in favour of shadow/cover frames. `StreamMux` maintains separate queues per stream class and drains real frames before shadow/cover frames in every scheduling pass.

**The invariant `StreamMux` upholds at all times:** `CellEncoder` may only receive a `StreamFrame` that originated from a `RuntimePacketIntent`. There is no path to produce a `StreamFrame` without a validated intent.

---

## 2. Inputs

`StreamMux` accepts only `RuntimePacketIntent` values. It never accepts `ControlledChaosOutput` directly; the type system enforces this because `RuntimePacketIntent` cannot be constructed outside `RuntimeBoundaryValidator`.

The fields `StreamMux` reads from each intent:

| Field | Type | How `StreamMux` uses it |
|---|---|---|
| `flow_id` | `u64` | Combined with `path_id` and `packet_class` to derive `stream_id`. |
| `path_id` | `u64` | Combined with `flow_id` and `packet_class` to derive `stream_id`. Also used to route the resulting `StreamFrame` to the correct path-level queue. |
| `packet_class` | `PacketClass` | Determines which sub-queue the frame enters (`Real` vs. `Shadow`/`Cover`). Controls drop policy on failure. |
| `payload_ref` | `PayloadRef` | Passed through to `StreamFrame` unchanged. `StreamMux` never reads or modifies payload bytes. |
| `latency_deadline` | `u64` (μs) | Frame is expired and dropped if `now_us > latency_deadline` at dequeue time. |
| `shadow_flag` | `bool` | Cross-checked against `packet_class` during frame construction; mismatch is treated as an internal error. |
| `fragment_id` | `u64` | Preserved in `StreamFrame` to allow downstream replay detection alongside `sequence_number`. |
| `scheduled_send_time` | `u64` (μs) | Frame is not eligible for dequeue until `now_us >= scheduled_send_time`. |

`StreamMux` must not read `payload_ref` contents. It treats `PayloadRef` as an opaque handle.

---

## 3. Outputs

`StreamMux` emits `StreamFrame` values to `CellEncoder`. A `StreamFrame` contains all metadata `CellEncoder` needs; `CellEncoder` never needs to query `StreamMux` state.

### 3.1 `StreamFrame` fields

| Field | Type | Description |
|---|---|---|
| `stream_id` | `StreamId` | Stable identifier for the (flow, path, class) triple. Opaque to `CellEncoder`. |
| `sequence_number` | `u64` | Monotonically increasing per stream. Never reused. |
| `path_id` | `u64` | Forwarded from intent; used by the transport layer to select the outbound path. |
| `packet_class` | `PacketClass` | Forwarded from intent; used by `CellEncoder` to decide padding strategy. |
| `payload_ref` | `PayloadRef` | The encrypted payload handle from the original intent. Unmodified. |
| `deadline_us` | `u64` | Forwarded `latency_deadline`; `CellEncoder` drops the frame if it misses this. |
| `frame_kind` | `StreamFrameKind` | Semantic classification: `Data`, `BurstHead`, `Cover`, `StreamReset`. |
| `fragment_id` | `u64` | Forwarded from intent for replay detection. |

### 3.2 `StreamFrameKind`

| Variant | When emitted |
|---|---|
| `Data` | Normal real-packet frame. |
| `BurstHead` | First frame of a burst sequence (`shadow_flag == false`, intent's burst-head marker set). |
| `Cover` | Shadow or cover-class intent. |
| `StreamReset` | Emitted when a stream is reset (path down, session expiry). Carries no payload. |

---

## 4. Stream ID Model

### 4.1 Derivation

`stream_id` is derived deterministically from a 3-tuple: `(flow_id, path_id, stream_class)`.

```
stream_class := Real   when packet_class == PacketClass::Real
stream_class := Shadow when packet_class == PacketClass::Shadow || PacketClass::Cover
```

The derivation uses SipHash-1-3 (the same primitive used in `PacketDispatcher`) with fixed non-secret keys. The input is the three components packed into a fixed-width byte representation:

```
stream_id_bits = SipHash-1-3(flow_id || path_id || stream_class_byte)
```

This gives a 64-bit `StreamId` that is:

- **Deterministic**: the same inputs always produce the same `stream_id`.
- **Stable**: adding or removing other flows does not change the `stream_id` of an existing flow.
- **Collision-resistant**: the hash space is 2⁶⁴; with the bounded number of simultaneous flows in a Liberty Shield session (expected < 1000), collisions are negligible.

### 4.2 Real vs. shadow stream separation

Real and shadow traffic for the same `flow_id` and `path_id` are assigned to **different** streams by virtue of the `stream_class` byte in the hash input. This means:

- Real stream for flow 42, path 1: `stream_id = H(42, 1, 0x00)`
- Shadow stream for flow 42, path 1: `stream_id = H(42, 1, 0x01)`

A `CellEncoder` receiving frames on a shadow stream never knows the real-stream identity of the originating flow. The association is held only by `StreamMux`.

### 4.3 Collision handling

In the event of a hash collision (two distinct 3-tuples produce the same `stream_id`), `StreamMux` detects this at stream-creation time by checking whether the new 3-tuple matches the existing stream's recorded 3-tuple. On mismatch:

- The newer stream is assigned a new `stream_id` by XOR-ing with a per-session salt and re-deriving.
- A warning event is recorded in `StreamMux` internal state.
- If a collision cannot be resolved within 3 attempts, `StreamMux` returns `StreamMuxError::StreamIdExhausted` and the intent is rejected.

In practice, with a 64-bit hash and fewer than 10 000 simultaneous streams, the expected number of collisions per lifetime of a VPN session is < 10⁻¹⁰.

---

## 5. Sequencing Model

### 5.1 Per-stream monotonic counter

Each `StreamState` maintains a `next_seq: u64` counter. Every frame dequeued from `StreamMux` receives the current value as its `sequence_number`, then `next_seq` is incremented.

**Invariants:**
- Sequence numbers are assigned at dequeue time (not enqueue time), because frames may be dropped between enqueue and dequeue (deadline expiry, queue overflow). Gaps in `sequence_number` therefore signal dropped frames, not reordering.
- Sequence numbers are **never reused** on a given stream within a session. Even after a stream reset, the counter resumes from the last-assigned value + 1. Only a full session teardown resets counters to zero.
- There is no distinction between real and shadow sequence namespaces within a stream — each stream has exactly one counter.

### 5.2 Wraparound

`sequence_number` is `u64`. At `u64::MAX`, the next value wraps to `u64::MAX` and the stream is forced into `StreamReset` state. A `StreamFrame { frame_kind: StreamReset }` is emitted, the stream is removed from `StreamMux`, and the 3-tuple is eligible for re-registration with a new `StreamState` (counter reset to 0). The probability of reaching `u64::MAX` in a realistic session is negligible (≈ 10²⁰ frames per stream per session needed).

### 5.3 Replay prevention

`CellEncoder` and the far-end decoder use `(stream_id, sequence_number)` pairs for replay detection. `StreamMux` upholds replay safety by guaranteeing that no `sequence_number` is emitted twice on the same `stream_id` within a session. The `fragment_id` forwarded from the intent provides a secondary replay check at the application layer.

---

## 6. Queueing

### 6.1 Per-stream queue structure

Each `StreamState` holds two queues:

```
real_queue:   BinaryHeap<StreamEntry> ordered by ascending latency_deadline
shadow_queue: BinaryHeap<StreamEntry> ordered by ascending latency_deadline
```

Real and shadow traffic are strictly separated. `StreamMux::drain_ready(now_us)` always exhausts all ready real frames from all streams before returning any shadow frames, mirroring the invariant from `FragmentQueue`.

### 6.2 Queue depth limits

| Queue | Maximum depth |
|---|---|
| `real_queue` per stream | Unbounded (real frames must never be silently dropped before CellEncoder sees them). |
| `shadow_queue` per stream | `max_shadow_depth`, calculated as `max(4, 2 × cover_bandwidth_kbps × latency_guard_ms / 8000)` — same formula as `FragmentQueue`. |

When `shadow_queue` is at capacity and a new shadow frame arrives, the oldest shadow frame (smallest deadline) is evicted and the new frame is inserted. The eviction count is tracked in `StreamMuxStats`.

### 6.3 Deadline expiration at dequeue

When `drain_ready(now_us)` inspects a frame, it first checks:

```
if now_us > frame.latency_deadline → expire the frame
```

Expired real frames produce a `StreamMuxError::DeadlineMissed` event (caller must surface to forwarder). Expired shadow frames are dropped silently with no event. Neither kind of expired frame increments `next_seq` — sequence numbers are only assigned to frames actually handed to `CellEncoder`.

### 6.4 Scheduled send time

Frames with `scheduled_send_time > now_us` are not eligible for dequeue even if they are at the head of the queue. `drain_ready` skips such frames without removing them. This preserves the Controlled Chaos Engine's timing intent while allowing the scheduler to call `drain_ready` at any frequency.

---

## 7. Backpressure

### 7.1 Real frame queue pressure

The `real_queue` is unbounded in depth. If the queue grows beyond a configurable `real_queue_warn_depth` (default: 256 frames), `StreamMux` emits a `StreamMuxError::RealQueuePressure { stream_id, depth }` warning. This is advisory only; frames continue to be accepted.

If `real_queue` exceeds `real_queue_hard_limit` (default: 1024 frames), `StreamMux` returns `StreamMuxError::RealQueueFull { stream_id }` for the new frame. The caller (the VPN forwarder) receives an explicit error and must decide whether to drop or back-pressure the upstream source.

**Real frames are never silently dropped.** Any situation that would cause a real frame to be lost must produce an explicit error return.

### 7.2 Shadow/cover queue overflow

When `shadow_queue` is full, the oldest shadow frame is evicted and the count is incremented in `StreamMuxStats::shadow_frames_evicted`. No error is returned; the caller is not notified.

### 7.3 Invalid stream

If a `RuntimePacketIntent` arrives for a `stream_id` that `StreamMux` cannot find and cannot create (e.g., path is no longer registered), `StreamMux` returns `StreamMuxError::InvalidStream { path_id }` and emits a `PlanInvalidationEvent` with `reason: PathDown { path_id }`. This mirrors the behaviour of `RuntimeBoundaryValidator` for V3 failures.

---

## 8. Security Constraints

`StreamMux` must never:

- **Inspect payload contents.** `PayloadRef` is forwarded as an opaque handle from `RuntimePacketIntent` to `StreamFrame`. `StreamMux` never dereferences it, reads from it, or writes to it.
- **Open sockets.** `StreamMux` is pure in-memory state. It has no dependency on networking crates.
- **Bypass `RuntimeBoundaryValidator`.** The only way to enqueue a frame is via `StreamMux::submit(intent: RuntimePacketIntent, ...)`. The type signature enforces this — there is no `StreamMux::submit_raw` or equivalent.
- **Create `RuntimePacketIntent`.** `StreamMux` consumes intents; it never produces them. The private constructor on `RuntimePacketIntent` makes this impossible at the type level.
- **Modify payload bytes.** `StreamMux` may modify `StreamFrame` metadata fields (assigning `stream_id`, `sequence_number`, `frame_kind`). It must not modify `payload_ref`.
- **Override KillSwitch, FirewallController, or TunnelState.** These are enforced by `RuntimeBoundaryValidator` before the intent reaches `StreamMux`. `StreamMux` holds no reference to these state objects and cannot query them.
- **Emit a `StreamFrame` without consuming a `RuntimePacketIntent`.** The `StreamFrame` produced from a `RuntimePacketIntent` must be the only output of a successful `submit` call; no additional frames may be generated per intent.

**Compile-time enforcement:**

- `StreamMux` must not import any networking crate.
- `StreamFrame` must not contain a raw `*const u8` or `*mut u8` payload pointer.
- `StreamMux::submit` must accept `RuntimePacketIntent` by value (consuming it), not by reference. This prevents a single intent from producing multiple frames.

---

## 9. Failure Behavior

### 9.1 Stream reset

A stream reset is triggered by:
- The path associated with the stream going down (`PathEvent::PathDown`).
- The session expiring.
- `sequence_number` reaching `u64::MAX`.

On reset, `StreamMux`:
1. Drains all real frames from the stream's `real_queue` and returns them as `StreamMuxError::StreamReset { stream_id, drained_real_frames }`. The caller re-submits or surfaces these to the forwarder.
2. Discards all shadow frames silently.
3. Emits a `StreamFrame { frame_kind: StreamReset, sequence_number: next_seq }` to `CellEncoder` as notification.
4. Removes the `StreamState` from the active stream map.
5. Records the 3-tuple in a `recently_reset` set for a configurable cooldown period to prevent immediate re-registration of a resetting stream.

### 9.2 Path invalidation

When `StreamMux` receives a `PathEvent::PathDown { path_id }`, it:
1. Finds all streams associated with `path_id`.
2. Initiates stream reset for each (§9.1).
3. Emits a `PlanInvalidationEvent { reason: PathDown { path_id }, affected_path: Some(path_id), current_stats: <last known> }` to the caller.

The caller is responsible for invoking `build_fragment_plan` with updated candidates. `StreamMux` does not self-replan.

### 9.3 Expired deadline

As described in §6.3: expired real frames produce `StreamMuxError::DeadlineMissed`; expired shadow frames are dropped silently. In neither case is `sequence_number` incremented.

### 9.4 Queue overflow

As described in §7: real queue overflow produces `StreamMuxError::RealQueueFull`; shadow queue overflow silently evicts the oldest shadow frame.

### 9.5 Replay prevention

If two intents with the same `fragment_id` are submitted to the same stream, the duplicate is rejected with `StreamMuxError::DuplicateFragment { stream_id, fragment_id }`. A small fixed-size sliding window (default: 256 entries) tracks recently seen `fragment_id` values per stream. Entries outside the window are assumed non-duplicate (the window size is tunable).

---

## 10. Rust Interface Proposal

The following types define the StreamMux interface. These are **type proposals only** — no implementation exists yet.

```
/// Stable identifier for a (flow_id, path_id, stream_class) triple.
/// Derived deterministically via SipHash-1-3 over the triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct StreamId(u64);

/// Classification of a StreamFrame for CellEncoder.
#[derive(Debug, Clone, PartialEq, Eq)]
enum StreamFrameKind {
    Data,
    BurstHead,
    Cover,
    StreamReset,
}

/// The output unit of StreamMux; the input unit of CellEncoder.
/// Contains only metadata and an opaque PayloadRef — no plaintext bytes.
struct StreamFrame {
    stream_id:       StreamId,
    sequence_number: u64,
    path_id:         u64,
    packet_class:    PacketClass,
    payload_ref:     PayloadRef,
    deadline_us:     u64,
    frame_kind:      StreamFrameKind,
    fragment_id:     u64,
}

/// Per-stream live state.  One instance per active (flow_id, path_id, class) triple.
struct StreamState {
    stream_id:     StreamId,
    flow_id:       u64,
    path_id:       u64,
    next_seq:      u64,
    // real_queue and shadow_queue are internal; not exposed.
}

/// Error variants returned by StreamMux operations.
#[derive(Debug)]
enum StreamMuxError {
    InvalidStream       { path_id: u64 },
    RealQueueFull       { stream_id: StreamId },
    RealQueuePressure   { stream_id: StreamId, depth: usize },
    DeadlineMissed      { stream_id: StreamId, late_by_us: u64 },
    StreamReset         { stream_id: StreamId, drained_real_frames: Vec<StreamFrame> },
    DuplicateFragment   { stream_id: StreamId, fragment_id: u64 },
    StreamIdExhausted,
}

/// Aggregate stats snapshot.
struct StreamMuxStats {
    active_stream_count:    usize,
    real_frames_enqueued:   u64,
    shadow_frames_evicted:  u64,
    real_frames_expired:    u64,
    shadow_frames_expired:  u64,
}

/// The mux itself.  No internal clock; callers pass `now_us` to drain_ready.
/// No networking imports.  No unsafe.
struct StreamMux {
    // Internal fields determined at implementation time.
    // Must be Send + Sync.
}

impl StreamMux {
    fn new(
        real_queue_hard_limit: usize,
        max_shadow_depth: usize,
        replay_window: usize,
    ) -> Self;

    /// Accept a validated intent and enqueue it on the appropriate stream.
    /// Consumes the intent (one intent → at most one frame).
    /// Returns Ok(()) on success or Err(StreamMuxError) on failure.
    /// Real packet failures always return Err; shadow packet failures may be
    /// absorbed internally (eviction) or returned (queue full).
    fn submit(
        &mut self,
        intent: RuntimePacketIntent,
        now_us: u64,
    ) -> Result<(), StreamMuxError>;

    /// Drain all frames whose scheduled_send_time ≤ now_us and
    /// latency_deadline ≥ now_us, in priority order (real before shadow).
    /// Expired frames are removed and handled per §9.3.
    fn drain_ready(&mut self, now_us: u64) -> Vec<StreamFrame>;

    /// Notify StreamMux that a path has gone down.  Triggers stream reset
    /// for all streams on that path (§9.2).
    fn on_path_down(
        &mut self,
        path_id: u64,
    ) -> (Vec<StreamMuxError>, Vec<PlanInvalidationEvent>);

    /// Return current statistics snapshot.
    fn stats(&self) -> StreamMuxStats;
}
```

**Design constraints for Sprint 7 Phase 2 implementors:**

- `StreamMux` must be `Send + Sync`. All fields must satisfy these bounds without `unsafe`.
- `StreamFrame` must not contain any field that exposes a raw pointer or OS handle.
- `StreamMux::submit` takes `RuntimePacketIntent` by value to enforce the one-intent-one-frame rule at the type level.
- `drain_ready` returns `Vec<StreamFrame>` rather than an iterator to avoid borrow-checker entanglement with `StreamMux`'s internal queues. If allocation overhead is a concern, a `drain_into(buf: &mut Vec<StreamFrame>)` variant may be added.
- The replay window uses a `VecDeque` or fixed-size ring buffer per stream — not a `HashSet` — to bound per-stream memory usage.
- No `unsafe` block is permitted anywhere in the `stream_mux` module.

---

## 11. Tests Required Before Implementation

The following tests must be written and pass before any StreamMux code is considered complete. All tests are pure in-memory; no sockets, no Android APIs.

| ID | Test name | What it asserts |
|---|---|---|
| M1 | `same_flow_path_gives_same_stream_id` | Submitting two intents with identical `flow_id`, `path_id`, and `packet_class` produces `StreamFrame` values with the same `stream_id`. |
| M2 | `real_and_shadow_streams_are_distinct` | Same `flow_id` and `path_id`, but `packet_class = Real` vs. `packet_class = Shadow`, produce frames with different `stream_id` values. |
| M3 | `sequence_numbers_monotonic` | Submitting N intents on the same stream produces frames with `sequence_number` 0, 1, 2, …, N-1 (in drain order). |
| M4 | `real_queue_overflow_returns_error` | When `real_queue` is at `real_queue_hard_limit`, submitting one more real intent returns `Err(RealQueueFull)`. |
| M5 | `shadow_queue_overflow_evicts_silently` | When `shadow_queue` is full, submitting one more shadow intent succeeds; the oldest shadow frame is evicted; no error is returned. |
| M6 | `expired_real_deadline_returns_error` | A real frame whose `latency_deadline < now_us` at dequeue time produces `StreamMuxError::DeadlineMissed`. No `sequence_number` is assigned. |
| M7 | `expired_shadow_deadline_drops_silently` | A shadow frame whose `latency_deadline < now_us` at dequeue time is dropped; no error is returned; `sequence_number` is not incremented. |
| M8 | `payload_ref_not_modified` | `StreamFrame.payload_ref.pool_index()` and `StreamFrame.payload_ref.length()` match the values in the original `RuntimePacketIntent`. |
| M9 | `no_frame_accepted_without_intent` | `StreamMux` has no public method that accepts anything other than `RuntimePacketIntent`. Verified by attempting to compile a caller that bypasses `submit(intent: RuntimePacketIntent, ...)` — the code must not compile. (Compile-fail test using `trybuild` or a static assertion.) |
| M10 | `stream_reset_drains_real_frames` | After `on_path_down(path_id)`, all previously enqueued real frames for that path are returned in the error result, not silently dropped. |
| M11 | `replay_detection_rejects_duplicate_fragment_id` | Submitting two intents with the same `fragment_id` on the same stream produces `Err(DuplicateFragment)` for the second. |
| M12 | `scheduled_send_time_respected` | A frame with `scheduled_send_time = now_us + 10_000` is not returned by `drain_ready(now_us)` but is returned by `drain_ready(now_us + 10_000)`. |

---

## 12. Sprint 7 Phase 2 Readiness Checklist

All items must be satisfied before the StreamMux implementation is considered complete and Sprint 7 Phase 3 (`CellEncoder`) may begin.

### Code readiness

- [ ] `crates/liberty-controlled-chaos/src/stream_mux/mod.rs` exists and declares all public types (`StreamId`, `StreamFrame`, `StreamFrameKind`, `StreamState`, `StreamMux`, `StreamMuxError`, `StreamMuxStats`).
- [ ] `StreamMux::submit` accepts `RuntimePacketIntent` by value — confirmed by type signature, not just convention.
- [ ] `StreamMux` has no dependency on any networking crate (verified by a `cargo tree` audit test analogous to B6 in the Runtime Boundary Contract).
- [ ] All 12 tests M1–M12 pass.
- [ ] All 89 existing `liberty-controlled-chaos` tests still pass after `stream_mux` is integrated into `lib.rs`.
- [ ] Zero clippy warnings under `-D warnings`.
- [ ] No `unsafe` blocks anywhere in `stream_mux`.

### Architecture readiness

- [ ] `CellEncoder` input type is specified (types only; no implementation) and accepts `StreamFrame` rather than `ControlledChaosOutput` or `RuntimePacketIntent` directly.
- [ ] The `PayloadRef` buffer pool release protocol is defined: confirm that `StreamMux` neither allocates nor frees buffers — it only forwards handles.
- [ ] `StreamMuxStats` is wired into the `TransmitterStats` aggregate so that `shadow_frames_evicted` and `real_frames_expired` are observable at the session level.

### Security readiness

- [ ] Code review confirms that no path through `StreamMux` reads `PayloadRef` contents.
- [ ] Code review confirms that `StreamFrame` cannot be constructed outside `stream_mux::mod` (analogous to `RuntimePacketIntent` enforcing its private constructor).
- [ ] The replay window size is documented and agreed upon (default: 256 entries per stream).

### Documentation readiness

- [ ] This document (`stream_mux_design.md`) has been reviewed and all open questions resolved.
- [ ] The `stream_id` derivation function is documented with its exact byte layout (field ordering, endianness) so that future implementations are bit-for-bit compatible.
- [ ] The connection between `StreamId` and `flow_id` is documented as internal-only: no external component (CellEncoder, NoiseLink, UDPTransport) may use `StreamId` to infer `flow_id`.
