//! StreamMux — sequencing, queueing, and stream-identity layer between
//! `RuntimeBoundaryValidator` and `CellEncoder`.

use std::collections::{HashMap, VecDeque};

use super::queues::{RealEntry, ShadowEntry, StreamQueue};
use super::types::{StreamFrame, StreamFrameKind, StreamId, StreamMuxError, StreamMuxStats};
use crate::runtime_boundary::{PacketClass, RuntimePacketIntent};
use crate::transmitter::{InvalidationReason, PathStats, PlanInvalidationEvent};

// ── SipHash-1-3 over 17 bytes ─────────────────────────────────────────────────
// Input layout: flow_id (8 LE bytes) || path_id (8 LE bytes) || class_byte (1 byte)

const SIPHASH_K0: u64 = 0x0706_0504_0302_0100;
const SIPHASH_K1: u64 = 0x0f0e_0d0c_0b0a_0908;

macro_rules! sip_round {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13);
        $v1 ^= $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17);
        $v1 ^= $v2;
        $v2 = $v2.rotate_left(32);
    };
}

fn siphash13_stream(flow_id: u64, path_id: u64, class_byte: u8) -> u64 {
    let mut v0 = SIPHASH_K0 ^ 0x736f_6d65_7073_6575u64;
    let mut v1 = SIPHASH_K1 ^ 0x646f_7261_6e64_6f6du64;
    let mut v2 = SIPHASH_K0 ^ 0x6c79_6765_6e65_7261u64;
    let mut v3 = SIPHASH_K1 ^ 0x7465_6462_7974_6573u64;

    // Block 0: flow_id little-endian.
    let m0 = flow_id.to_le();
    v3 ^= m0;
    sip_round!(v0, v1, v2, v3);
    v0 ^= m0;

    // Block 1: path_id little-endian.
    let m1 = path_id.to_le();
    v3 ^= m1;
    sip_round!(v0, v1, v2, v3);
    v0 ^= m1;

    // Final block: 1 remaining byte + (length=17 mod 256) packed into high byte.
    let m2 = ((17u64 & 0xff) << 56) | (class_byte as u64);
    v3 ^= m2;
    sip_round!(v0, v1, v2, v3);
    v0 ^= m2;

    v2 ^= 0xff;
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);
    sip_round!(v0, v1, v2, v3);

    v0 ^ v1 ^ v2 ^ v3
}

// ── StreamState ───────────────────────────────────────────────────────────────

struct StreamState {
    stream_id: StreamId,
    flow_id: u64,
    path_id: u64,
    is_shadow: bool,
    next_seq: u64,
    queue: StreamQueue,
    replay_win: VecDeque<u64>,
}

impl StreamState {
    fn new(
        stream_id: StreamId,
        flow_id: u64,
        path_id: u64,
        is_shadow: bool,
        max_shadow_depth: usize,
        replay_window_size: usize,
    ) -> Self {
        Self {
            stream_id,
            flow_id,
            path_id,
            is_shadow,
            next_seq: 0,
            queue: StreamQueue::new(max_shadow_depth),
            replay_win: VecDeque::with_capacity(replay_window_size),
        }
    }

    fn assign_seq(&mut self) -> u64 {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        seq
    }
}

// ── StreamMux ─────────────────────────────────────────────────────────────────

/// Sequencing, queueing, and stream-identity layer.
///
/// Accepts `RuntimePacketIntent` values and emits `StreamFrame` values.
/// No networking dependencies; no unsafe; no payload inspection.
pub struct StreamMux {
    streams: HashMap<StreamId, StreamState>,
    /// path_id → stream_ids using that path (for on_path_down lookup).
    path_index: HashMap<u64, Vec<StreamId>>,
    real_queue_hard: usize,
    real_queue_warn: usize,
    max_shadow_depth: usize,
    replay_window_size: usize,
    /// XOR salt for collision resolution; per-session constant.
    collision_salt: u64,
    stats: StreamMuxStats,
}

impl StreamMux {
    pub fn new(
        real_queue_hard_limit: usize,
        real_queue_warn_depth: usize,
        max_shadow_depth: usize,
        replay_window_size: usize,
        collision_salt: u64,
    ) -> Self {
        Self {
            streams: HashMap::new(),
            path_index: HashMap::new(),
            real_queue_hard: real_queue_hard_limit,
            real_queue_warn: real_queue_warn_depth,
            max_shadow_depth,
            replay_window_size,
            collision_salt,
            stats: StreamMuxStats::default(),
        }
    }

    /// Convenience constructor with design-doc defaults.
    pub fn with_defaults() -> Self {
        Self::new(1024, 256, 32, 256, 0xdead_beef_cafe_1234)
    }

    // ── stream_id derivation ──────────────────────────────────────────────────

    fn derive_stream_id(
        &self,
        flow_id: u64,
        path_id: u64,
        class_byte: u8,
    ) -> Result<StreamId, StreamMuxError> {
        let mut candidate = StreamId(siphash13_stream(flow_id, path_id, class_byte));

        for attempt in 0u64..3 {
            match self.streams.get(&candidate) {
                None => return Ok(candidate),
                Some(existing)
                    if existing.flow_id == flow_id
                        && existing.path_id == path_id
                        && existing.is_shadow == (class_byte == 0x01) =>
                {
                    return Ok(candidate); // same triple reuses existing slot
                }
                Some(_) => {
                    // Hash collision: different triple. Re-derive with salt.
                    candidate = StreamId(candidate.0 ^ self.collision_salt ^ (attempt + 1));
                }
            }
        }
        Err(StreamMuxError::StreamIdExhausted)
    }

    fn get_or_create_stream(
        &mut self,
        flow_id: u64,
        path_id: u64,
        is_shadow: bool,
    ) -> Result<StreamId, StreamMuxError> {
        let class_byte: u8 = if is_shadow { 0x01 } else { 0x00 };
        let stream_id = self.derive_stream_id(flow_id, path_id, class_byte)?;

        if !self.streams.contains_key(&stream_id) {
            let state = StreamState::new(
                stream_id,
                flow_id,
                path_id,
                is_shadow,
                self.max_shadow_depth,
                self.replay_window_size,
            );
            self.streams.insert(stream_id, state);
            self.path_index.entry(path_id).or_default().push(stream_id);
            self.stats.active_stream_count = self.streams.len();
        }
        Ok(stream_id)
    }

    // ── replay window ─────────────────────────────────────────────────────────

    fn check_replay(replay_win: &mut VecDeque<u64>, fragment_id: u64, window_size: usize) -> bool {
        if replay_win.contains(&fragment_id) {
            return false;
        }
        if replay_win.len() >= window_size {
            replay_win.pop_front();
        }
        replay_win.push_back(fragment_id);
        true
    }

    // ── submit ────────────────────────────────────────────────────────────────

    /// Accept a validated intent and enqueue it on the appropriate stream.
    /// Consumes the intent (one intent → at most one enqueued entry).
    pub fn submit(
        &mut self,
        intent: RuntimePacketIntent,
        _now_us: u64,
    ) -> Result<(), StreamMuxError> {
        let flow_id = intent.flow_id();
        let path_id = intent.path_id();
        let fragment_id = intent.fragment_id();
        let is_shadow = intent.packet_class().is_shadow_or_cover();
        let scheduled_send_time = intent.scheduled_send_time();
        let latency_deadline = intent.latency_deadline();
        let shadow_flag = intent.inner().shadow_flag;
        let payload_ref = intent.payload_ref().clone();

        let stream_id = self.get_or_create_stream(flow_id, path_id, is_shadow)?;

        // Borrow stream state; collect replay window answer before other &mut borrows.
        let window_size = self.replay_window_size;
        let real_hard = self.real_queue_hard;
        let real_warn = self.real_queue_warn;

        let state = self.streams.get_mut(&stream_id).unwrap();

        if !Self::check_replay(&mut state.replay_win, fragment_id, window_size) {
            return Err(StreamMuxError::DuplicateFragment {
                stream_id,
                fragment_id,
            });
        }

        if is_shadow {
            let evicted = {
                let state = self.streams.get_mut(&stream_id).unwrap();
                state.queue.push_shadow(ShadowEntry {
                    scheduled_send_time,
                    latency_deadline,
                    fragment_id,
                    payload_ref,
                })
            };
            self.stats.shadow_frames_evicted += evicted;
        } else {
            let above_warn = {
                let state = self.streams.get_mut(&stream_id).unwrap();
                let depth = state.queue.real_len();
                if depth >= real_hard {
                    return Err(StreamMuxError::RealQueueFull { stream_id });
                }
                let above_warn = depth >= real_warn;
                state.queue.push_real(RealEntry {
                    scheduled_send_time,
                    latency_deadline,
                    fragment_id,
                    payload_ref,
                    shadow_flag,
                });
                above_warn
            };
            self.stats.real_frames_enqueued += 1;
            if above_warn {
                self.stats.real_queue_pressure_events += 1;
            }
        }
        Ok(())
    }

    // ── drain_ready ───────────────────────────────────────────────────────────

    /// Drain all frames ready for dispatch (`scheduled_send_time <= now_us`),
    /// real traffic before shadow across all streams.
    /// Expired real frames appear as `DeadlineMissed` in the error vec.
    pub fn drain_ready(&mut self, now_us: u64) -> (Vec<StreamFrame>, Vec<StreamMuxError>) {
        let mut out_frames = Vec::new();
        let mut out_errors = Vec::new();

        let stream_ids: Vec<StreamId> = self.streams.keys().copied().collect();

        // ── real frames first ─────────────────────────────────────────────────
        for sid in &stream_ids {
            let (new_frames, new_errors) = {
                let state = match self.streams.get_mut(sid) {
                    Some(s) => s,
                    None => continue,
                };
                let (ready, expired) = state.queue.drain_ready_real(now_us);
                let mut frames: Vec<StreamFrame> = Vec::with_capacity(ready.len());
                for entry in ready {
                    let seq = state.assign_seq();
                    let kind = if entry.shadow_flag {
                        StreamFrameKind::BurstHead
                    } else {
                        StreamFrameKind::Data
                    };
                    frames.push(StreamFrame {
                        stream_id: state.stream_id,
                        sequence_number: seq,
                        path_id: state.path_id,
                        packet_class: PacketClass::Real,
                        payload_ref: Some(entry.payload_ref),
                        deadline_us: entry.latency_deadline,
                        frame_kind: kind,
                        fragment_id: entry.fragment_id,
                    });
                }
                let mut errors: Vec<StreamMuxError> = Vec::with_capacity(expired.len());
                for entry in expired {
                    errors.push(StreamMuxError::DeadlineMissed {
                        stream_id: *sid,
                        late_by_us: now_us.saturating_sub(entry.latency_deadline),
                    });
                }
                (frames, errors)
            };
            let expired_count = new_errors.len() as u64;
            out_frames.extend(new_frames);
            out_errors.extend(new_errors);
            self.stats.real_frames_expired += expired_count;
        }

        // ── shadow frames second ───────────────────────────────────────────────
        for sid in &stream_ids {
            let (new_frames, expired_count) = {
                let state = match self.streams.get_mut(sid) {
                    Some(s) => s,
                    None => continue,
                };
                let (ready, expired_count) = state.queue.drain_ready_shadow(now_us);
                let mut frames: Vec<StreamFrame> = Vec::with_capacity(ready.len());
                for entry in ready {
                    let seq = state.assign_seq();
                    frames.push(StreamFrame {
                        stream_id: state.stream_id,
                        sequence_number: seq,
                        path_id: state.path_id,
                        packet_class: PacketClass::Shadow,
                        payload_ref: Some(entry.payload_ref),
                        deadline_us: entry.latency_deadline,
                        frame_kind: StreamFrameKind::Cover,
                        fragment_id: entry.fragment_id,
                    });
                }
                (frames, expired_count)
            };
            out_frames.extend(new_frames);
            self.stats.shadow_frames_expired += expired_count;
        }

        (out_frames, out_errors)
    }

    // ── on_path_down ──────────────────────────────────────────────────────────

    /// Notify StreamMux that a path has gone down. Resets all streams on that
    /// path and returns drained real frames plus a `PlanInvalidationEvent`.
    pub fn on_path_down(
        &mut self,
        path_id: u64,
    ) -> (Vec<StreamMuxError>, Vec<PlanInvalidationEvent>) {
        let mut mux_errors = Vec::new();
        let mut invalidations = Vec::new();

        let affected = self.path_index.remove(&path_id).unwrap_or_default();
        if affected.is_empty() {
            return (mux_errors, invalidations);
        }

        for sid in affected {
            let mut state = match self.streams.remove(&sid) {
                Some(s) => s,
                None => continue,
            };

            // Drain all real frames and surface them to the caller.
            let real_entries = state.queue.drain_all_real();
            let drained = real_entries
                .into_iter()
                .map(|e| StreamFrame {
                    stream_id: sid,
                    sequence_number: 0, // not assigned: stream is being torn down
                    path_id,
                    packet_class: PacketClass::Real,
                    payload_ref: Some(e.payload_ref),
                    deadline_us: e.latency_deadline,
                    frame_kind: StreamFrameKind::Data,
                    fragment_id: e.fragment_id,
                })
                .collect();

            mux_errors.push(StreamMuxError::StreamReset {
                stream_id: sid,
                drained_real_frames: drained,
            });
        }

        self.stats.active_stream_count = self.streams.len();

        invalidations.push(PlanInvalidationEvent {
            reason: InvalidationReason::PathDown { path_id },
            affected_path: Some(path_id),
            current_stats: PathStats {
                path_id,
                rtt_ms: 0,
                loss_pct: 0.0,
                available_kbps: 0,
            },
        });

        (mux_errors, invalidations)
    }

    pub fn stats(&self) -> StreamMuxStats {
        let mut s = self.stats.clone();
        s.active_stream_count = self.streams.len();
        s
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_boundary::{
        ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef, RuntimeBoundaryValidator,
        RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
    };
    use std::collections::HashSet;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_mux() -> StreamMux {
        StreamMux::new(8, 4, 8, 256, 0xabcd_1234_5678_ef01)
    }

    fn make_intent(
        flow_id: u64,
        path_id: u64,
        class: PacketClass,
        fragment_id: u64,
        scheduled_send_time: u64,
        deadline: u64,
    ) -> RuntimePacketIntent {
        let mut paths = HashSet::new();
        paths.insert(path_id);
        let v =
            RuntimeBoundaryValidator::new(KillSwitchState::Inactive, TunnelState::TunnelUp, paths);
        let mut b = ShadowBudgetTracker::new(1_000_000);
        let shadow_flag = class == PacketClass::Shadow;
        let out = ControlledChaosOutput {
            path_id,
            flow_id,
            fragment_id,
            scheduled_send_time,
            shadow_flag,
            packet_class: class,
            latency_deadline: deadline,
            payload_ref: PayloadRef::new((fragment_id % u32::MAX as u64) as u32, 200).unwrap(),
        };
        match v.validate(out, scheduled_send_time, &mut b) {
            RuntimeValidationResult::Accept(i) => i,
            RuntimeValidationResult::Reject(r) => panic!("make_intent rejected: {r:?}"),
        }
    }

    const NOW: u64 = 1_000_000;
    const FUTURE: u64 = NOW + 100_000;

    // ── M1: same triple → same stream_id ─────────────────────────────────────

    #[test]
    fn m1_same_flow_path_gives_same_stream_id() {
        let mut mux = make_mux();
        let i1 = make_intent(42, 1, PacketClass::Real, 1, NOW, FUTURE);
        let i2 = make_intent(42, 1, PacketClass::Real, 2, NOW, FUTURE);
        mux.submit(i1, NOW).unwrap();
        mux.submit(i2, NOW).unwrap();
        let (frames, _) = mux.drain_ready(FUTURE);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].stream_id, frames[1].stream_id);
    }

    // ── M2: real vs shadow → different stream_id ──────────────────────────────

    #[test]
    fn m2_real_and_shadow_streams_are_distinct() {
        let mut mux = make_mux();
        let ir = make_intent(42, 1, PacketClass::Real, 1, NOW, FUTURE);
        let is_ = make_intent(42, 1, PacketClass::Shadow, 2, NOW, FUTURE);
        mux.submit(ir, NOW).unwrap();
        mux.submit(is_, NOW).unwrap();
        let (frames, _) = mux.drain_ready(FUTURE);
        // Real frames drain before shadow; both should be present.
        assert_eq!(frames.len(), 2);
        let real_sid = frames
            .iter()
            .find(|f| f.packet_class == PacketClass::Real)
            .map(|f| f.stream_id);
        let shadow_sid = frames
            .iter()
            .find(|f| f.packet_class == PacketClass::Shadow)
            .map(|f| f.stream_id);
        assert_ne!(
            real_sid, shadow_sid,
            "real and shadow must have distinct stream_ids"
        );
    }

    // ── M3: monotonic sequence numbers ───────────────────────────────────────

    #[test]
    fn m3_sequence_numbers_monotonic() {
        let mut mux = make_mux();
        for frag in 0u64..5 {
            let i = make_intent(1, 1, PacketClass::Real, frag, NOW, FUTURE);
            mux.submit(i, NOW).unwrap();
        }
        let (frames, _) = mux.drain_ready(FUTURE);
        assert_eq!(frames.len(), 5);
        for (idx, frame) in frames.iter().enumerate() {
            assert_eq!(
                frame.sequence_number, idx as u64,
                "seq must be 0..N-1 in drain order"
            );
        }
    }

    // ── M4: real queue hard limit ─────────────────────────────────────────────

    #[test]
    fn m4_real_queue_overflow_returns_error() {
        let mut mux = StreamMux::new(4, 2, 8, 256, 0);
        for frag in 0u64..4 {
            let i = make_intent(1, 1, PacketClass::Real, frag, NOW, FUTURE);
            mux.submit(i, NOW).unwrap();
        }
        let i = make_intent(1, 1, PacketClass::Real, 99, NOW, FUTURE);
        let result = mux.submit(i, NOW);
        assert!(
            matches!(result, Err(StreamMuxError::RealQueueFull { .. })),
            "expected RealQueueFull, got {result:?}"
        );
    }

    // ── M5: shadow queue overflow evicts silently ─────────────────────────────

    #[test]
    fn m5_shadow_queue_overflow_evicts_silently() {
        let mut mux = StreamMux::new(1024, 512, 4, 256, 0);
        for frag in 0u64..5 {
            let i = make_intent(1, 1, PacketClass::Shadow, frag, NOW, FUTURE);
            assert!(
                mux.submit(i, NOW).is_ok(),
                "shadow submit must always be Ok"
            );
        }
        assert_eq!(mux.stats().shadow_frames_evicted, 1);
    }

    // ── M6: expired real deadline → DeadlineMissed ───────────────────────────

    #[test]
    fn m6_expired_real_deadline_returns_error() {
        let mut mux = make_mux();
        let i = make_intent(1, 1, PacketClass::Real, 1, NOW, NOW + 1);
        mux.submit(i, NOW).unwrap();
        let (frames, errors) = mux.drain_ready(NOW + 1_000);
        assert!(frames.is_empty(), "expired frame must not appear in output");
        assert_eq!(errors.len(), 1);
        assert!(
            matches!(errors[0], StreamMuxError::DeadlineMissed { .. }),
            "expected DeadlineMissed"
        );
    }

    // ── M7: expired shadow deadline → silent drop ─────────────────────────────

    #[test]
    fn m7_expired_shadow_deadline_drops_silently() {
        let mut mux = make_mux();
        let i = make_intent(1, 1, PacketClass::Shadow, 1, NOW, NOW + 1);
        mux.submit(i, NOW).unwrap();
        let (frames, errors) = mux.drain_ready(NOW + 1_000);
        assert!(
            frames.is_empty(),
            "expired shadow must not appear in output"
        );
        assert!(errors.is_empty(), "expired shadow must produce no errors");
    }

    // ── M8: payload_ref passes through unmodified ─────────────────────────────

    #[test]
    fn m8_payload_ref_not_modified() {
        let mut mux = make_mux();
        let i = make_intent(1, 1, PacketClass::Real, 7, NOW, FUTURE);
        let orig_index = i.payload_ref().pool_index();
        let orig_len = i.payload_ref().length();
        mux.submit(i, NOW).unwrap();
        let (frames, _) = mux.drain_ready(FUTURE);
        assert_eq!(frames.len(), 1);
        let pr = frames[0].payload_ref.as_ref().unwrap();
        assert_eq!(pr.pool_index(), orig_index);
        assert_eq!(pr.length(), orig_len);
    }

    // ── M9: API-level enforcement — submit only accepts RuntimePacketIntent ───

    #[test]
    fn m9_no_frame_without_intent() {
        // Compile-time guarantee: StreamMux::submit(&mut self, RuntimePacketIntent, u64).
        // There is no submit_raw / submit_output method. This test confirms the
        // method exists and only works with a RuntimePacketIntent.
        let mut mux = make_mux();
        let i = make_intent(1, 1, PacketClass::Real, 1, NOW, FUTURE);
        assert!(mux.submit(i, NOW).is_ok());
    }

    // ── M10: on_path_down drains real frames ──────────────────────────────────

    #[test]
    fn m10_stream_reset_drains_real_frames() {
        let mut mux = make_mux();
        for frag in 0u64..3 {
            // scheduled far in future so they won't be drained by drain_ready
            let i = make_intent(
                1,
                1,
                PacketClass::Real,
                frag,
                FUTURE + 1_000,
                FUTURE + 2_000,
            );
            mux.submit(i, NOW).unwrap();
        }
        let (errors, _inv) = mux.on_path_down(1);
        let reset = errors.iter().find_map(|e| {
            if let StreamMuxError::StreamReset {
                drained_real_frames,
                ..
            } = e
            {
                Some(drained_real_frames)
            } else {
                None
            }
        });
        assert!(reset.is_some(), "StreamReset must be returned");
        assert_eq!(reset.unwrap().len(), 3, "all 3 real frames must be drained");
    }

    // ── M11: replay detection ─────────────────────────────────────────────────

    #[test]
    fn m11_replay_detection_rejects_duplicate_fragment_id() {
        let mut mux = make_mux();
        let i1 = make_intent(1, 1, PacketClass::Real, 99, NOW, FUTURE);
        let i2 = make_intent(1, 1, PacketClass::Real, 99, NOW, FUTURE);
        mux.submit(i1, NOW).unwrap();
        let result = mux.submit(i2, NOW);
        assert!(
            matches!(
                result,
                Err(StreamMuxError::DuplicateFragment {
                    fragment_id: 99,
                    ..
                })
            ),
            "duplicate fragment_id must be rejected; got {result:?}"
        );
    }

    // ── M12: scheduled_send_time respected ───────────────────────────────────

    #[test]
    fn m12_scheduled_send_time_respected() {
        let mut mux = make_mux();
        let send_at = NOW + 10_000;
        let i = make_intent(1, 1, PacketClass::Real, 1, send_at, FUTURE);
        mux.submit(i, NOW).unwrap();

        let (frames, _) = mux.drain_ready(NOW);
        assert!(
            frames.is_empty(),
            "frame must not be dequeued before scheduled_send_time"
        );

        let (frames, _) = mux.drain_ready(send_at);
        assert_eq!(
            frames.len(),
            1,
            "frame must be dequeued at scheduled_send_time"
        );
    }

    // ── warn threshold is advisory: no error returned ─────────────────────────

    #[test]
    fn warn_threshold_does_not_reject_real_frames() {
        // warn=2, hard=8
        let mut mux = StreamMux::new(8, 2, 8, 256, 0);
        // Enqueue past warn threshold — all must succeed.
        for frag in 0u64..5 {
            let i = make_intent(1, 1, PacketClass::Real, frag, NOW, FUTURE);
            assert!(
                mux.submit(i, NOW).is_ok(),
                "real frames must be accepted past warn threshold"
            );
        }
        assert!(
            mux.stats().real_queue_pressure_events > 0,
            "pressure events must be counted"
        );
    }
}
