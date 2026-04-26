# Liberty Shield — Sprint 6 Phase 3: Transmitter / ShadowSync Layer

**Version:** 0.1  
**Status:** Design (pre-implementation)  
**Date:** 2026-04-26  
**Depends on:** `route_shadower.rs` (Phase 1), `path_fragmenter.rs` (Phase 2)

---

## 1. Module Purpose

The Transmitter is the execution layer between the deterministic planning modules
(RouteShadower + PathFragmenter) and the packet I/O boundary. It accepts a
`FragmentPlan` and a stream of real packets, then produces a scheduled mix of
real and synthetic cover transmissions across multiple paths.

The Transmitter has two distinct responsibilities:

**Dispatch** — route real packets to the paths and bandwidth budgets specified
by the `FragmentPlan`, enforcing `latency_guard_ms` as an absolute deadline.

**ShadowSync** — generate cover traffic whose statistical fingerprint matches
the real flow closely enough that a passive observer cannot determine which
path carries real packets and which carries cover.

The Transmitter does NOT make policy decisions. It does not decide whether to
shadow, how many paths to use, or how much bandwidth to allocate — those
decisions are made upstream by RouteShadower and PathFragmenter. The Transmitter
only executes the plan it receives.

---

## 2. Position in the Pipeline

```
[ Real Packet Stream ]
        │
        ▼
┌───────────────────────────────────────────────────────┐
│                      Transmitter                       │
│                                                        │
│  ┌──────────────┐   ┌──────────────────────────────┐  │
│  │ FragmentQueue│   │      ShadowSyncEngine        │  │
│  │  (per path)  │◄──│  statistical flow mirror     │  │
│  └──────┬───────┘   └──────────────────────────────┘  │
│         │                          │                   │
│  ┌──────▼───────┐   ┌──────────────▼─────────────┐   │
│  │PacketDispatcher   │     TimingController       │   │
│  │ real routing │   │  deadline + jitter mgmt    │   │
│  └──────┬───────┘   └──────────────┬─────────────┘   │
│         └──────────────────────────┘                   │
│                      │                                  │
│         ┌────────────▼────────────┐                    │
│         │   PathHealthMonitor    │                    │
│         │  path quality signals  │                    │
│         └────────────────────────┘                    │
└───────────────────────┬───────────────────────────────┘
                        │
             ┌──────────┼──────────┐
             ▼          ▼          ▼
          Path 0     Path 1     Path N
       (VPN/Mesh adapter — out of scope this sprint)
```

Inputs come from three sources:
- `PathFragmenter` → `FragmentPlan`
- Real packet stream → `PacketSource` trait
- Path state feedback → `PathHealthMonitor`

Output is a stream of `ScheduledPacket` values consumed by the downstream
adapter (VPN or mesh layer).

---

## 3. Inputs

### 3.1 FragmentPlan

The output of `path_fragmenter::build_fragment_plan`. Carries:

| Field | Used by |
|-------|---------|
| `allocations: Vec<PathAllocation>` | PacketDispatcher (routing weights), ShadowSyncEngine (per-path budgets) |
| `total_cover_bandwidth_kbps: u32` | TimingController (aggregate rate cap) |
| `effective_shadow_paths: u8` | ShadowSyncEngine (concurrency limit) |
| `degraded: bool` | PacketDispatcher (skip cover generation when fully degraded) |
| `degradation_reason` | PathHealthMonitor (log context) |

`PathAllocation` per-path fields used by the Transmitter:

| Field | Used by |
|-------|---------|
| `path_id: u64` | FragmentQueue key, ScheduledPacket routing tag |
| `weight: f32` | ShadowSyncEngine (proportional cover distribution) |
| `cover_bandwidth_kbps: u32` | TimingController (per-path token bucket size) |

If `FragmentPlan.allocations` is empty (shadow_probability == 0.0 or all paths
gated out), the Transmitter operates in **pass-through mode**: all real packets
are forwarded immediately with no cover generation. See §7.1.

### 3.2 Packet Stream

A stream of `RealPacket` values arriving from the VPN/mesh adapter. Each
carries:

| Field | Type | Notes |
|-------|------|-------|
| `payload_size_bytes` | `u16` | Used by ShadowSyncEngine for size-distribution tracking |
| `arrival_timestamp_us` | `u64` | Microsecond wall-clock; used for IAT tracking |
| `flow_id` | `u64` | Identifies the originating flow (for per-flow state) |

The Transmitter does not inspect packet contents. `flow_id` is treated as
opaque; it is used only to maintain per-flow statistical state in
ShadowSyncEngine.

### 3.3 Path State

`PathHealthMonitor` receives out-of-band signals (RTT samples, loss events,
path-down notifications) from the underlying adapter. These feed back into
the Transmitter's internal path state but do NOT override the `FragmentPlan`
within a single plan epoch — they trigger a **plan invalidation event**
that propagates upward to PathFragmenter for recomputation.

### 3.4 Timing Scheduler

A monotonic clock reference provided at construction time via a `Clock` trait.
The `TimingController` uses this exclusively — it never calls wall-clock APIs
directly — so tests can inject a controlled clock.

---

## 4. Outputs

### 4.1 Scheduled Packet Transmissions

```
ScheduledPacket {
    path_id:            u64,
    flow_type:          FlowType,    // Real | Shadow
    payload:            PacketPayload,
    deadline_us:        u64,         // absolute microsecond timestamp
    sequence_id:        u64,         // per-path monotonic counter
}

enum FlowType { Real, Shadow }
```

Consumers (VPN/mesh adapters) are expected to send `ScheduledPacket` by
`deadline_us`. If they cannot, they must return a `DeadlineMissed` error so
the Transmitter can update its congestion model. The Transmitter does not
retry on deadline miss — a missed deadline means the real packet was sent
late but still sent; cover packets on deadline miss are dropped silently.

### 4.2 Shadow Packet Generation Schedule

The `ShadowSyncEngine` produces `ShadowSchedule` values consumed internally
by the `PacketDispatcher`. They are not directly exposed to callers but are
included here for clarity:

```
ShadowSchedule {
    path_id:       u64,
    slots:         Vec<ShadowSlot>,
    epoch_start_us: u64,
}

ShadowSlot {
    offset_us:     u32,    // relative to epoch_start_us
    size_bytes:    u16,    // from size-distribution model
    is_burst_head: bool,   // marks first packet in a burst replica
}
```

`ShadowSchedule` covers a fixed lookahead window (default: 2 × `latency_guard_ms`).
The engine regenerates the schedule whenever the real flow's statistical model
shifts significantly (change detection threshold: δ_IAT > 20% or δ_size > 15%).

### 4.3 Plan Invalidation Events

When PathHealthMonitor detects a path has degraded below operational threshold,
the Transmitter emits a `PlanInvalidationEvent`:

```
PlanInvalidationEvent {
    reason:       InvalidationReason,
    affected_path: Option<u64>,    // None = all paths
    current_stats: PathStats,
}

enum InvalidationReason {
    PathDown { path_id: u64 },
    LatencyExceeded { path_id: u64, observed_rtt_ms: u32 },
    BandwidthShrunk { path_id: u64, available_kbps: u32 },
    AllPathsDegraded,
}
```

The caller (OrchestratorLoop or VPN service) handles this event by calling
`build_fragment_plan` again and calling `Transmitter::update_plan`.

---

## 5. Components

### 5.1 PacketDispatcher

**Role:** Assigns each incoming real packet to a path and enqueues it. Also
consumes `ShadowSchedule` from ShadowSyncEngine and enqueues cover packets.

**Path assignment for real packets** uses weighted deterministic hashing:

```
path_index = weighted_select(
    weights   = [alloc.weight for alloc in plan.allocations],
    key       = hash64(packet.flow_id XOR packet.sequence_counter),
)
```

The XOR with `sequence_counter` (a per-flow monotonic counter maintained by
the dispatcher) ensures consecutive packets from the same flow distribute
across paths according to the weight vector, while remaining deterministic
for a given (flow_id, counter) pair. The hash function is SipHash-1-3
(fast, non-cryptographic, deterministic).

**Shadow packet injection:** After enqueuing a real packet, the dispatcher
checks whether ShadowSyncEngine has a pending `ShadowSlot` due within the
current lookahead window. If yes, it constructs a cover `ScheduledPacket` and
enqueues it on the designated shadow path. Shadow slots are consumed in order;
unused slots expire silently.

**Separation invariant:** A shadow packet and the real packet it mimics are
NEVER enqueued on the same path in the same scheduling window. If the shadow
path assignment collides with the real packet's path, the shadow is moved to
the next-highest-weight path. If no alternative path exists, the shadow slot
is dropped.

### 5.2 ShadowSyncEngine

**Role:** Maintains a per-flow statistical model of the real traffic and
generates synthetic `ShadowSchedule` values that match that model.

The engine tracks four statistical dimensions per flow:

| Dimension | Model | Update mechanism |
|-----------|-------|-----------------|
| Inter-arrival time (IAT) | EWMA + variance (α=0.125) | On every packet arrival |
| Packet size | 8-bucket histogram (log₂ scale, 64–1500 bytes) | On every packet arrival |
| Burst state | 2-state FSM: BURST / IDLE | IAT < burst_threshold_us → BURST; IAT > idle_threshold_us → IDLE |
| Path weight | From FragmentPlan.allocations[i].weight | On plan update |

**Burst detection thresholds** (configurable, default values):
- `burst_threshold_us`: 500 μs — IAT below this = same burst
- `idle_threshold_us`: 5000 μs — IAT above this = new idle period

**Shadow generation algorithm:**

```
When real packet arrives (size S, IAT T):
  1. Update EWMA_IAT, EWMA_IAT_var, size_histogram
  2. Transition burst FSM if threshold crossed
  3. Decide whether to emit shadow this epoch:
       emit_shadow = (plan.effective_shadow_paths > 0)
                 AND (plan.degraded == false)
                 AND (flow is not hard-excluded — see §7.1)
  4. If emit_shadow:
       shadow_iat    = EWMA_IAT + jitter_sample()         // §6.3
       shadow_size   = sample_from_histogram(size_histogram)
       shadow_offset = clamp(shadow_iat, 0, latency_guard_us)
       append ShadowSlot { offset_us: shadow_offset,
                           size_bytes: shadow_size,
                           is_burst_head: just_entered_BURST }
  5. Flush ShadowSchedule to PacketDispatcher if lookahead window filled
     or burst state changed
```

**Phase offset:** Shadow slots are offset from the real packet's departure
time by `EWMA_IAT / 2` (half-interval phase offset). This ensures shadow
and real inter-arrival distributions are similar in aggregate but their
individual phase alignment is mismatched, preventing cross-correlation by
observers who can see both paths simultaneously.

**Model reset:** The per-flow model resets when a flow has been idle for
more than `idle_timeout_s` (default 30 s). This prevents stale models from
generating inappropriate cover traffic.

### 5.3 TimingController

**Role:** Controls packet departure timing, enforces `latency_guard_ms`, and
injects bounded jitter.

**Per-path token bucket:**

Each path in the `FragmentPlan` has a token bucket:

```
TokenBucket {
    capacity_bits:     cover_bandwidth_kbps * 1000 * latency_guard_ms / 1000,
    refill_rate_bps:   cover_bandwidth_kbps * 1000,
    tokens:            u64,    // current token count in bits
    last_refill_us:    u64,
}
```

A cover packet of `size_bytes` may only depart when
`tokens >= size_bytes * 8`. If the bucket is empty, the cover packet is
deferred. Deferral is capped at `latency_guard_ms` — a cover packet deferred
past this deadline is dropped (not the real packet, which is never rate-limited).

Real packets are never token-bucket-limited. Only cover packets are subject
to the per-path budget.

**Departure scheduling (per-path queue):**

```
Priority (highest first):
  P1: Real packet with deadline ≤ now + 0.2 × latency_guard_ms
      (imminent deadline — preempts everything)
  P2: Real packet (any deadline)
  P3: Cover packet with deadline ≤ now + 0.5 × latency_guard_ms
      (half deadline — still time to send)
  P4: Cover packet (any deadline)
```

This priority order guarantees real packets are never delayed by cover traffic
on a congested path.

**Jitter injection** is described in §6.3.

### 5.4 FragmentQueue

**Role:** Per-path priority queues holding `ScheduledPacket` values awaiting
transmission.

One `FragmentQueue` instance per `path_id` in `plan.allocations`. Each queue
is a min-heap keyed on `deadline_us`.

Invariants:
- Maximum depth: `2 × (cover_bandwidth_kbps × latency_guard_ms / 8000)` packets
  (two latency windows of cover packets). Real packets are not depth-limited.
- On queue overflow (cover packets only): oldest cover packets are evicted.
  Real packets are never evicted.
- The queue is drained in `deadline_us` order by the downstream adapter.

Queue depth is reported to PathHealthMonitor as a congestion signal.

### 5.5 PathHealthMonitor

**Role:** Tracks path quality and emits `PlanInvalidationEvent` when a path
degrades below operational thresholds.

Monitors three per-path signals:

| Signal | Source | Threshold |
|--------|--------|-----------|
| RTT | Adapter-supplied RTT samples | `observed_rtt_ms > 2 × CandidatePath.measured_rtt_ms` |
| Loss rate | Adapter-supplied ACK/NACK | `loss_pct > 10%` over a 5-second window |
| Available bandwidth | Adapter bandwidth estimate | `available_kbps < 0.5 × FragmentPlan.allocations[i].cover_bandwidth_kbps` |

The monitor uses a **hysteresis guard**: a path must exceed a threshold for
at least 3 consecutive measurement intervals (default: 1 s each) before
emitting a `PlanInvalidationEvent`. This prevents thrashing on transient
congestion.

PathHealthMonitor does NOT modify the `FragmentPlan` itself. It only emits
events; the caller decides when and whether to recompute the plan.

---

## 6. ShadowSync Model

### 6.1 Threat Model Assumption

The adversary is a passive observer with access to one or more network paths.
The adversary:
- Can observe packet sizes, inter-arrival times, and path identifiers.
- Cannot observe payload contents (encrypted).
- Attempts to determine which path carries real traffic and which carries
  cover traffic by statistical analysis.

The ShadowSync objective is to make this determination computationally
infeasible within a reasonable observation window (minutes to hours).

### 6.2 Packet Timing

Real flow inter-arrival times are tracked with EWMA (α=0.125). Shadow flows
are generated at IAT drawn from a Gaussian approximation:

```
shadow_iat_us ~ N(EWMA_IAT, EWMA_IAT_var^0.5)
```

The Gaussian is truncated to [EWMA_IAT × 0.5, EWMA_IAT × 2.0] to prevent
physically implausible values. Values outside this range are clamped.

The controlled randomness source for jitter is a per-session ChaCha8 PRNG
seeded from a session key established at VPN session initiation (not wall-clock
time). This prevents timing oracle attacks against the jitter source.

### 6.3 Jitter Injection Rules

Jitter is applied to cover packets only. Real packets are dispatched as
soon as their token bucket allows, with no artificial delay.

```
jitter_us = prng.next_bounded(JITTER_MAX_US)

where:
  JITTER_MAX_US = min(
      EWMA_IAT × JITTER_IAT_RATIO,    // proportional to flow rate
      latency_guard_us × JITTER_DEADLINE_FRACTION,
  )

Constants (configurable):
  JITTER_IAT_RATIO:           0.20   // ≤20% of mean IAT
  JITTER_DEADLINE_FRACTION:   0.15   // ≤15% of latency_guard_ms
```

The `latency_guard_us × JITTER_DEADLINE_FRACTION` cap guarantees that jitter
never causes a cover packet to exceed its deadline.

Jitter is applied at enqueue time (added to `ShadowSlot.offset_us`), not at
departure time. This means `deadline_us` already accounts for jitter when
the adapter receives the packet.

### 6.4 Burst Shape Matching

The burst FSM transitions (§5.2) drive shadow burst replication:

```
IDLE → BURST transition in real flow:
  Shadow engine emits a burst-head ShadowSlot (is_burst_head = true)
  after a random phase offset drawn from [0, EWMA_IAT × 3].
  Subsequent shadow slots in the burst are spaced at real-burst IAT ± jitter.

BURST → IDLE transition:
  Shadow engine emits a final burst slot, then enters an idle shadow period
  whose duration is sampled from the real idle duration distribution.
```

The random phase offset for burst replication is critical: if shadow burst
onset were synchronised to real burst onset, a cross-path observer could
use burst timing as a correlation signal. The phase randomisation decorrelates
burst onset timestamps.

### 6.5 Packet Size Distribution

The 8-bucket histogram covers:
```
Bucket 0: [0,   64)   bytes
Bucket 1: [64,  128)  bytes
Bucket 2: [128, 256)  bytes
Bucket 3: [256, 512)  bytes
Bucket 4: [512, 768)  bytes
Bucket 5: [768, 1024) bytes
Bucket 6: [1024,1280) bytes
Bucket 7: [1280,1500] bytes
```

Histogram counts are updated on every real packet arrival. Shadow packet sizes
are sampled by:
1. Select bucket with probability proportional to count.
2. Sample uniform within the bucket's byte range.
3. Clamp to [64, 1500] (minimum cover packet size avoids trivial size-zero
   fingerprinting; maximum is standard MTU minus headers).

The histogram is weighted toward recent history using an EWMA-like decay:
each bucket count decays by factor (1 - 1/N) per packet, where N=32.

### 6.6 Path Usage Ratios

Cover traffic is distributed across paths according to `PathAllocation.weight`
(from FragmentPlan), which is already proportional to `reliability_score`.
This ensures that the relative bandwidth usage across paths for cover traffic
mirrors the relative usage that a real multi-path flow would show.

Divergence between real-path weights and cover-path weights is avoided by
design: both draw from the same `FragmentPlan.allocations`.

---

## 7. Scheduling Algorithm

### 7.1 Pass-Through Mode (No Shadow)

Entry conditions:
- `FragmentPlan.allocations` is empty, OR
- `FragmentPlan.effective_shadow_paths == 0`, OR
- The flow's `ShadowDecision.shadow_probability == 0.0` (Banking/Login sentinel)

In pass-through mode:
- All real packets are enqueued on path 0 (primary path) with
  `deadline_us = now + latency_guard_us`.
- No cover packets are generated.
- ShadowSyncEngine is not updated (avoids accumulating stale models).
- The mode is transparent to the adapter.

The `shadow_probability == 0.0` check is performed by the Transmitter as a
second-line guard. RouteShadower is the primary enforcer (it sets probability
to 0.0 for Banking/Login), and PathFragmenter propagates this by returning an
empty `allocations` list. The Transmitter checks explicitly to be defensive
against future callers that might construct `FragmentPlan` values directly.

### 7.2 Normal Dispatch Loop

```
On real packet arrival (P):
  1. Update ShadowSyncEngine(P)
  2. if pass_through_mode: forward_real(P, path=primary); return

  3. path = weighted_dispatch(P.flow_id, P.seq)
  4. deadline = now_us + latency_guard_us
  5. enqueue ScheduledPacket { path, Real, P.payload, deadline } into FragmentQueue[path]

  6. shadows = ShadowSyncEngine.drain_pending_slots(now_us)
  7. for each slot in shadows:
       shadow_path = shadow_path_for(slot, excluded=path)
       if token_bucket[shadow_path].try_consume(slot.size_bytes):
         enqueue ScheduledPacket { shadow_path, Shadow, synthetic_payload(slot.size_bytes),
                                   now_us + slot.offset_us } into FragmentQueue[shadow_path]
       else:
         // Token bucket empty — drop shadow slot silently
         metrics.shadow_slots_dropped += 1
```

### 7.3 Plan Update

When the caller calls `Transmitter::update_plan(new_plan: FragmentPlan)`:

1. Drain all cover packets from all `FragmentQueue` instances (real packets
   are preserved).
2. Remove `FragmentQueue` and `TokenBucket` instances for paths no longer
   in `new_plan.allocations`.
3. Create `FragmentQueue` and `TokenBucket` for new paths.
4. Update ShadowSyncEngine path weights from new `allocations`.
5. Recompute `pass_through_mode` flag.

Plan updates do not reset per-flow statistical models in ShadowSyncEngine —
the flow model is independent of the plan.

### 7.4 Queue Fairness

Under congestion (token bucket depleted), cover packets compete with each
other by deadline. Fairness across paths is not a Transmitter concern — the
`FragmentPlan` has already encoded the fair bandwidth allocation via
`cover_bandwidth_kbps` per path. The Transmitter enforces those budgets via
token buckets; the plan enforces fairness.

---

## 8. Determinism Boundaries

| Component | Deterministic? | Randomness source | Notes |
|-----------|---------------|-------------------|-------|
| PacketDispatcher — path assignment | Yes | None | SipHash of (flow_id XOR seq) |
| ShadowSyncEngine — statistical model update | Yes | None | Pure arithmetic on inputs |
| ShadowSyncEngine — shadow IAT generation | No | Session ChaCha8 PRNG | Seeded from session key; reproducible given same seed |
| ShadowSyncEngine — burst phase offset | No | Session ChaCha8 PRNG | Same seed constraint |
| ShadowSyncEngine — size bucket sampling | No | Session ChaCha8 PRNG | Same seed constraint |
| TimingController — token bucket | Yes | None | Deterministic given clock |
| TimingController — jitter | No | Session ChaCha8 PRNG | Bounded by §6.3 constraints |
| FragmentQueue — dispatch order | Yes | None | Min-heap on deadline_us |
| PathHealthMonitor — threshold evaluation | Yes | None | Arithmetic on samples |

**Session ChaCha8 PRNG:**

All non-deterministic outputs use a single per-session ChaCha8 PRNG instance.
The seed is a 32-byte value derived from the VPN session key via HKDF-SHA256
with label `"liberty-shield-transmitter-rng-v1"`. This means:

- The PRNG output is not predictable by an observer who does not know the
  session key.
- The same session replayed with the same packets produces identical jitter
  values (reproducible in tests by injecting a known seed).
- There is no dependence on wall-clock time for jitter decisions, preventing
  timing oracle attacks.

The PRNG is advanced in a single linear sequence; there are no parallel
instances. This keeps the state simple and avoids split-seed problems.

---

## 9. Security Constraints

### 9.1 Banking and Login Traffic — Hard Exclusion

**Rule:** No cover traffic is EVER generated for flows carrying Banking or
Login traffic.

**Enforcement chain:**
1. `RouteShadower.apply_hard_exclusion` sets `shadow_probability = 0.0`.
2. `PathFragmenter.build_fragment_plan` returns `allocations: []` when
   `shadow_probability == 0.0`.
3. `Transmitter`: if `allocations` is empty, operate in pass-through mode
   (§7.1). Additionally, check `shadow_probability == 0.0` directly from the
   `ShadowDecision` passed alongside the plan.

If any component fails to enforce this rule, the Transmitter's explicit
check is the last line of defence. A violation of this rule is logged as
a CRITICAL security event and the session is placed in permanent pass-through
mode until the plan is reloaded.

**Rationale:** Banking and Login flows are the highest-value correlation
targets. Generating cover traffic for them creates a statistical oracle:
an observer who knows the rule can infer session type by the presence or
absence of cover traffic. No cover is safer.

### 9.2 latency_guard_ms as a Hard Limit

`latency_guard_ms` from `ShadowDecision` is the absolute upper bound on
scheduling delay introduced by the Transmitter. It governs:

- `deadline_us` for all `ScheduledPacket` values.
- The maximum deferral time for cover packets (§5.3).
- The jitter cap (§6.3).
- The ShadowSchedule lookahead window (§4.2).

Real packets are NEVER delayed past `latency_guard_ms`. If a real packet
cannot be dispatched within this window (e.g., all path queues are full due
to cover packets), cover packets are evicted from the queue to make room
(reverse-priority: lowest-priority cover packets evicted first).

### 9.3 Packet Loss Recovery

The Transmitter does not implement retransmission. Loss recovery is the
responsibility of the transport layer (TCP or application-level ARQ above
the VPN adapter). The Transmitter's contribution to loss resilience is:

- Real packets are dispatched on healthy paths (as determined by
  PathHealthMonitor). If a path's loss rate exceeds 10%, a plan invalidation
  event is emitted and the caller may move traffic to another path.
- Cover packets on a degraded path are dropped silently. Cover loss does not
  trigger plan recomputation.

### 9.4 Replay Protection Considerations

Cover packets must not be replayable as real packets. Requirements:

- Cover packets carry a `FlowType::Shadow` tag in their header (format
  defined by the adapter, out of scope for this sprint).
- The adapter layer must drop incoming packets tagged as Shadow.
- Cover packet payloads are synthetic (random bytes from the PRNG, not
  derived from real payload content).
- Cover packets carry sequence IDs from a per-path counter space that is
  separate from the real packet counter space. Overlap between the two
  namespaces is prevented by using even sequence IDs for real and odd
  sequence IDs for cover (or an equivalent tagging scheme defined by the
  adapter interface).

The replay protection design is advisory at this phase; the final scheme is
defined with the adapter interface (Sprint 7 scope).

---

## 10. Failure Handling

### 10.1 Path Degradation

When PathHealthMonitor detects a path degrading (RTT, loss, or bandwidth
threshold — §5.5):

```
1. If affected_path is in FragmentPlan.allocations:
   a. Suppress cover traffic on affected_path immediately (drain its
      FragmentQueue shadow entries; retain real entries).
   b. Emit PlanInvalidationEvent { reason: LatencyExceeded | BandwidthShrunk,
                                   affected_path }.
   c. Continue dispatching real packets on affected_path until the caller
      provides an updated plan. Do NOT unilaterally reroute real packets —
      that is PathFragmenter's responsibility.

2. If all paths degrade simultaneously:
   a. Emit PlanInvalidationEvent { reason: AllPathsDegraded }.
   b. Enter pass-through mode on primary path (path with lowest path_id
      in current allocations).
   c. Real packets continue to be dispatched; cover is fully suppressed.
```

### 10.2 Path Removal

When PathHealthMonitor emits `PathDown { path_id }`:

```
1. Drain FragmentQueue[path_id] — all cover entries dropped, real entries
   redistributed to the next-best path (highest remaining weight in
   allocations, excluding the downed path).
2. Remove TokenBucket[path_id].
3. Emit PlanInvalidationEvent { reason: PathDown, affected_path: path_id }.
4. Update internal path set; do not attempt to schedule onto path_id until
   a new FragmentPlan is received that includes it.
```

Real packet redistribution in step 1 uses the same `weighted_dispatch`
function as normal dispatch, evaluated against the surviving paths only.
This redistribution is temporary — the authoritative reallocation happens
when PathFragmenter produces a new plan.

### 10.3 Shadow Flow Suppression

Cover generation is suppressed (without emitting a plan invalidation event)
in these conditions:

| Condition | Action |
|-----------|--------|
| Token bucket empty | Drop shadow slot; no deferral beyond deadline |
| `FragmentQueue[shadow_path]` at cover capacity | Drop shadow slot |
| `plan.degraded == true` | Suppress all cover generation |
| Burst phase offset expired without real burst | Discard pending burst shadow |
| `PathHealthMonitor` reports path loss > 10% | Suppress cover on that path |

Suppression is transient. Cover generation resumes automatically when the
condition clears (bucket refills, queue drains, etc.).

### 10.4 ShadowSyncEngine Model Staleness

If a flow has been idle for `idle_timeout_s` (default 30 s), its statistical
model is reset. On the next arrival:
- The size histogram is initialised to a uniform distribution (equal weight
  across all 8 buckets).
- EWMA_IAT is initialised to the first observed IAT.
- The burst FSM starts in IDLE state.

This prevents a flow that resumes after a long pause from generating cover
traffic calibrated to stale statistics.

---

## 11. Interfaces

### 11.1 Transmitter Public Interface

```rust
pub struct TransmitterConfig {
    pub latency_guard_ms:  u32,
    pub idle_timeout_s:    u32,     // default 30
    pub burst_threshold_us: u32,    // default 500
    pub idle_threshold_us:  u32,    // default 5000
    pub jitter_iat_ratio:   f32,    // default 0.20
}

pub struct Transmitter { /* opaque */ }

impl Transmitter {
    pub fn new(
        plan:   FragmentPlan,
        decision: ShadowDecision,  // for hard-exclusion guard
        config: TransmitterConfig,
        clock:  Arc<dyn Clock>,
        rng_seed: [u8; 32],
    ) -> Self;

    /// Replace the active plan. Drains cover queues; preserves real queues
    /// and per-flow statistical models.
    pub fn update_plan(&mut self, plan: FragmentPlan, decision: ShadowDecision);

    /// Feed one real packet into the dispatcher. Returns scheduled packets
    /// ready for immediate dispatch (deadline within current tick).
    pub fn push_packet(&mut self, packet: RealPacket) -> Vec<ScheduledPacket>;

    /// Drain all packets whose deadline_us ≤ now. Called by the adapter
    /// on each scheduler tick.
    pub fn drain_ready(&mut self, now_us: u64) -> Vec<ScheduledPacket>;

    /// Notify of an adapter-level path event (RTT sample, loss, bandwidth).
    pub fn report_path_event(&mut self, event: PathEvent) -> Option<PlanInvalidationEvent>;

    /// Current per-path queue depths and token bucket fill levels.
    pub fn stats(&self) -> TransmitterStats;
}
```

### 11.2 Clock Trait

```rust
pub trait Clock: Send + Sync {
    fn now_us(&self) -> u64;    // monotonic microseconds
}
```

Production implementation: wraps `std::time::Instant`. Test implementation:
manually-advanced counter.

### 11.3 PacketSource Trait (adapter → Transmitter)

```rust
pub struct RealPacket {
    pub flow_id:               u64,
    pub payload_size_bytes:    u16,
    pub arrival_timestamp_us:  u64,
    pub payload:               PacketPayload,
}

// PacketPayload is opaque bytes — defined by the adapter layer.
// The Transmitter does not inspect or copy payload bytes (zero-copy design).
pub struct PacketPayload(/* adapter-defined */);
```

### 11.4 PacketSink Trait (Transmitter → adapter)

```rust
pub trait PacketSink: Send {
    fn send(&mut self, packet: ScheduledPacket) -> Result<(), SendError>;
}

pub enum SendError {
    DeadlineMissed { path_id: u64, late_by_us: u64 },
    PathUnavailable { path_id: u64 },
    QueueFull { path_id: u64 },
}
```

Errors from `PacketSink` are forwarded to PathHealthMonitor as path events.

### 11.5 PathEvent (adapter → PathHealthMonitor)

```rust
pub enum PathEvent {
    RttSample    { path_id: u64, rtt_ms: u32 },
    PacketLost   { path_id: u64 },
    PacketAcked  { path_id: u64 },
    BandwidthEstimate { path_id: u64, available_kbps: u32 },
    PathDown     { path_id: u64 },
    PathRestored { path_id: u64, rtt_ms: u32, available_kbps: u32 },
}
```

### 11.6 Relationship to PathFragmenter

```
PathFragmenter::build_fragment_plan(decision, candidates, real_flow_kbps)
        │
        │  FragmentPlan
        ▼
Transmitter::new(plan, decision, config, clock, rng_seed)
        │
        ├── push_packet(real_packet)   ──► Vec<ScheduledPacket>
        │
        ├── drain_ready(now_us)        ──► Vec<ScheduledPacket>
        │
        ├── report_path_event(event)   ──► Option<PlanInvalidationEvent>
        │        │
        │        │ PlanInvalidationEvent
        │        ▼
        │   caller calls build_fragment_plan() again
        │        │
        │        │ new FragmentPlan
        │        ▼
        └── update_plan(new_plan, new_decision)
```

PathFragmenter is called by the Transmitter's caller — the Transmitter itself
has no reference to PathFragmenter. This inversion of control keeps the
dependency graph acyclic and allows each component to be tested independently.

---

## 12. Testing Strategy

### 12.1 Unit Tests — ShadowSyncEngine

| # | Test | Assertion |
|---|------|-----------|
| U1 | `iat_model_converges` | After 50 packets at constant IAT, EWMA_IAT within 5% of true IAT |
| U2 | `size_histogram_uniform_seed` | 1000 samples from uniform histogram produce ≤15% deviation per bucket |
| U3 | `burst_fsm_enters_burst` | Two packets 100 μs apart → FSM state = BURST |
| U4 | `burst_fsm_enters_idle` | Single packet after 10 ms gap → FSM state = IDLE |
| U5 | `stale_model_resets_on_timeout` | No packets for idle_timeout_s; next packet reinitialises EWMA |
| U6 | `jitter_bounded_by_deadline_fraction` | 10 000 jitter samples all ≤ latency_guard_us × JITTER_DEADLINE_FRACTION |
| U7 | `phase_offset_decorrelates_burst_onset` | Shadow burst start timestamp differs from real burst start |

### 12.2 Unit Tests — PacketDispatcher

| # | Test | Assertion |
|---|------|-----------|
| U8 | `real_packet_assigned_to_valid_path` | Returned `path_id` is in `plan.allocations` |
| U9 | `weight_distribution_approximated` | 10 000 packets → per-path count within 5% of weight × total |
| U10 | `shadow_excluded_from_real_path` | Shadow path ≠ real packet path (when alternatives exist) |
| U11 | `no_shadow_when_pass_through` | allocations empty → zero shadow packets emitted |
| U12 | `shadow_probability_zero_blocks_shadow` | ShadowDecision.shadow_probability == 0.0 → zero shadows |

### 12.3 Unit Tests — TimingController

| # | Test | Assertion |
|---|------|-----------|
| U13 | `real_packet_never_delayed_past_guard` | Real packet deadline = arrival + latency_guard_us, always |
| U14 | `cover_dropped_on_empty_bucket` | Token bucket at 0 → shadow slot silently dropped |
| U15 | `real_preempts_cover_in_queue` | Real packet with deadline < cover deadline dispatched first |
| U16 | `token_bucket_refills_over_time` | Advance clock; bucket refills proportionally to rate |

### 12.4 Unit Tests — PathHealthMonitor

| # | Test | Assertion |
|---|------|-----------|
| U17 | `single_rtt_spike_no_invalidation` | One RTT sample over threshold → no event (hysteresis) |
| U18 | `three_rtt_spikes_emits_event` | Three consecutive → PlanInvalidationEvent emitted |
| U19 | `path_down_immediate_event` | PathDown event → immediate PlanInvalidationEvent, no hysteresis |
| U20 | `cover_suppressed_on_high_loss` | Loss rate > 10% → shadow packets drop to zero on that path |

### 12.5 Integration / Simulation Tests

| # | Test | Assertion |
|---|------|-----------|
| S1 | `statistical_similarity_iat` | KS-test on IAT distributions of real vs shadow flows: p > 0.05 |
| S2 | `statistical_similarity_sizes` | χ² test on size histograms: p > 0.05 |
| S3 | `plan_update_preserves_real_queue` | update_plan() → real packets not dropped |
| S4 | `path_down_redistributes_real` | PathDown → real packets rerouted; no packet loss |
| S5 | `full_degradation_pass_through` | All paths degrade → real packets still dispatched |
| S6 | `banking_flow_zero_cover_under_load` | Banking flow + high correlation + hostile network → zero shadow packets |
| S7 | `determinism_with_fixed_seed` | Same packet stream + same seed → bit-identical ScheduledPacket output |
| S8 | `latency_guard_enforced_under_cover_load` | Heavy cover load → real packets still dispatched within latency_guard_ms |

### 12.6 Property-Based Tests

Two properties to verify with automated input generation:

**P1 — No real packet dropped:** For any sequence of `RealPacket` inputs and
any valid `FragmentPlan`, `drain_ready` eventually returns each real packet
exactly once before `now_us > arrival_timestamp_us + latency_guard_us * 2`.

**P2 — Cover never on primary path during same window:** For any window of
`latency_guard_us` duration, no `path_id` appears in both a `Real` and
`Shadow` `ScheduledPacket` simultaneously when alternative paths are available.

---

## 13. Out of Scope for this Sprint

- Actual packet I/O (network socket writes, TUN adapter integration)
- OS-specific platform code
- Cryptographic session key derivation (HKDF call — placeholder `rng_seed` parameter)
- Replay protection header format (defined with Sprint 7 adapter interface)
- Multi-session coordination (one Transmitter instance per VPN session)
- Metrics export / telemetry

---

## 14. Module File Layout

```
crates/liberty-controlled-chaos/src/
├── transmitter/
│   ├── mod.rs              ← public interface, Transmitter struct
│   ├── dispatcher.rs       ← PacketDispatcher
│   ├── shadow_sync.rs      ← ShadowSyncEngine
│   ├── timing.rs           ← TimingController, TokenBucket
│   ├── queue.rs            ← FragmentQueue
│   ├── health_monitor.rs   ← PathHealthMonitor
│   └── types.rs            ← RealPacket, ScheduledPacket, FlowType, PathEvent, …
```

`lib.rs` will gain:
```rust
pub mod transmitter;
pub use transmitter::{
    Transmitter, TransmitterConfig,
    RealPacket, ScheduledPacket, FlowType,
    PathEvent, PlanInvalidationEvent,
    Clock,
};
```

---

## 15. Acceptance Criteria

| Criterion | Requirement |
|-----------|-------------|
| Banking/Login hard exclusion | Zero shadow packets when `shadow_probability == 0.0`, independently of FragmentPlan content |
| latency_guard_ms never exceeded | All `ScheduledPacket.deadline_us ≤ arrival_us + latency_guard_us` for real packets |
| Cover traffic bounded by plan budget | Per-path cover bandwidth does not exceed `cover_bandwidth_kbps` over any 1-second window |
| Real packets not dropped on cover congestion | Token bucket depletion or queue overflow only drops cover packets |
| Statistical IAT similarity | KS-test p > 0.05 on real vs shadow IAT distributions over 500-packet window |
| Plan update is non-disruptive | update_plan() completes in O(paths) time; real queue contents preserved |
| Deterministic dispatch | Same (flow_id, seq, plan) always selects the same path |
| PRNG reproducibility | Same seed + same packet stream → identical shadow schedule |
| Path failure isolation | Single path down does not interrupt real traffic on other paths |
