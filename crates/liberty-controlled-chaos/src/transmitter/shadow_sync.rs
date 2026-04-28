//! ShadowSyncEngine — statistical flow mirroring and cover-slot generation.
//! Also contains the ChaCha8 PRNG used throughout the Transmitter.

use std::collections::HashMap;

use super::types::ShadowSlot;

// ── ChaCha8 PRNG ──────────────────────────────────────────────────────────────

pub struct ChaCha8Rng {
    state: [u32; 16],
    buffer: [u32; 16],
    pos: usize,
}

impl ChaCha8Rng {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut key = [0u32; 8];
        for (i, chunk) in seed.chunks_exact(4).enumerate() {
            key[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
        let mut state = [0u32; 16];
        // "expand 32-byte k"
        state[0] = 0x6170_7865;
        state[1] = 0x3320_646e;
        state[2] = 0x7962_2d32;
        state[3] = 0x6b20_6574;
        state[4..12].copy_from_slice(&key);
        // state[12..16] = 0  (counter + nonce)
        Self {
            state,
            buffer: [0u32; 16],
            pos: 16,
        }
    }

    fn chacha_block(s: &mut [u32; 16]) {
        macro_rules! qr {
            ($a:expr, $b:expr, $c:expr, $d:expr) => {
                s[$a] = s[$a].wrapping_add(s[$b]);
                s[$d] ^= s[$a];
                s[$d] = s[$d].rotate_left(16);
                s[$c] = s[$c].wrapping_add(s[$d]);
                s[$b] ^= s[$c];
                s[$b] = s[$b].rotate_left(12);
                s[$a] = s[$a].wrapping_add(s[$b]);
                s[$d] ^= s[$a];
                s[$d] = s[$d].rotate_left(8);
                s[$c] = s[$c].wrapping_add(s[$d]);
                s[$b] ^= s[$c];
                s[$b] = s[$b].rotate_left(7);
            };
        }
        // 8 rounds = 4 double-rounds
        for _ in 0..4 {
            qr!(0, 4, 8, 12);
            qr!(1, 5, 9, 13);
            qr!(2, 6, 10, 14);
            qr!(3, 7, 11, 15);
            qr!(0, 5, 10, 15);
            qr!(1, 6, 11, 12);
            qr!(2, 7, 8, 13);
            qr!(3, 4, 9, 14);
        }
    }

    fn refill(&mut self) {
        let mut x = self.state;
        Self::chacha_block(&mut x);
        for (i, xi) in x.iter().enumerate() {
            self.buffer[i] = xi.wrapping_add(self.state[i]);
        }
        self.state[12] = self.state[12].wrapping_add(1);
        if self.state[12] == 0 {
            self.state[13] = self.state[13].wrapping_add(1);
        }
        self.pos = 0;
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.pos >= 16 {
            self.refill();
        }
        let v = self.buffer[self.pos];
        self.pos += 1;
        v
    }

    pub fn next_u64(&mut self) -> u64 {
        let lo = self.next_u32() as u64;
        let hi = self.next_u32() as u64;
        (hi << 32) | lo
    }

    /// Uniform sample in `[0, max)`.  Returns 0 when `max ≤ 1`.
    pub fn next_bounded(&mut self, max: u64) -> u64 {
        if max <= 1 {
            return 0;
        }
        let threshold = max.wrapping_neg() % max;
        loop {
            let r = self.next_u64();
            if r >= threshold {
                return r % max;
            }
        }
    }

    /// Sample from N(mean, std_dev), truncated to [mean*0.5, mean*2.0].
    /// Falls back to `mean` if all rejection attempts fail (extremely rare).
    pub fn sample_gaussian_truncated(&mut self, mean: f64, std_dev: f64) -> f64 {
        if mean <= 0.0 {
            return 0.0;
        }
        let lo = mean * 0.5;
        let hi = mean * 2.0;
        for _ in 0..32 {
            let u1 = (self.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 2.0);
            let u2 = (self.next_u64() as f64 + 1.0) / (u64::MAX as f64 + 2.0);
            let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
            let sample = mean + std_dev * z;
            if sample >= lo && sample <= hi {
                return sample;
            }
        }
        mean
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next_u32().to_le_bytes();
            let rem = (buf.len() - i).min(4);
            buf[i..i + rem].copy_from_slice(&v[..rem]);
            i += rem;
        }
    }
}

// ── Burst FSM ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BurstState {
    Idle,
    Burst,
}

// ── Size histogram ────────────────────────────────────────────────────────────

/// Bucket boundaries: (inclusive_low, exclusive_high).  Bucket 7 is inclusive
/// on both ends [1280, 1500].
const BUCKET_BOUNDS: [(u16, u16); 8] = [
    (0, 64),
    (64, 128),
    (128, 256),
    (256, 512),
    (512, 768),
    (768, 1024),
    (1024, 1280),
    (1280, 1501), // upper bound 1501 so "< hi" covers 1500
];

const HISTOGRAM_DECAY: f64 = 31.0 / 32.0;

fn size_bucket(bytes: u16) -> usize {
    let b = bytes.min(1500);
    match b {
        0..=63 => 0,
        64..=127 => 1,
        128..=255 => 2,
        256..=511 => 3,
        512..=767 => 4,
        768..=1023 => 5,
        1024..=1279 => 6,
        _ => 7,
    }
}

// ── Per-flow statistical model ────────────────────────────────────────────────

const EWMA_ALPHA: f64 = 0.125;

pub struct FlowModel {
    pub ewma_iat_us: f64,
    pub ewma_iat_var_us2: f64,
    pub size_histogram: [f64; 8],
    pub burst_state: BurstState,
    pub last_arrival_us: u64,
    pub initialised: bool,
}

impl FlowModel {
    fn new_uniform() -> Self {
        Self {
            ewma_iat_us: 0.0,
            ewma_iat_var_us2: 0.0,
            size_histogram: [1.0; 8],
            burst_state: BurstState::Idle,
            last_arrival_us: 0,
            initialised: false,
        }
    }

    /// Update model with a new packet.  Returns `true` if burst FSM just
    /// transitioned IDLE → BURST.
    fn update(
        &mut self,
        arrival_us: u64,
        size_bytes: u16,
        burst_threshold_us: u32,
        idle_threshold_us: u32,
    ) -> bool {
        // Decay histogram then increment the matching bucket.
        for w in self.size_histogram.iter_mut() {
            *w *= HISTOGRAM_DECAY;
        }
        self.size_histogram[size_bucket(size_bytes)] += 1.0;

        if !self.initialised {
            self.ewma_iat_us = 1_000.0;
            self.ewma_iat_var_us2 = 100.0;
            self.last_arrival_us = arrival_us;
            self.initialised = true;
            return false;
        }

        let iat = arrival_us.saturating_sub(self.last_arrival_us) as f64;
        self.last_arrival_us = arrival_us;

        let dev = iat - self.ewma_iat_us;
        self.ewma_iat_us = (1.0 - EWMA_ALPHA) * self.ewma_iat_us + EWMA_ALPHA * iat;
        self.ewma_iat_var_us2 = (1.0 - EWMA_ALPHA) * self.ewma_iat_var_us2 + EWMA_ALPHA * dev * dev;

        let prev = self.burst_state.clone();
        if iat < burst_threshold_us as f64 {
            self.burst_state = BurstState::Burst;
        } else if iat > idle_threshold_us as f64 {
            self.burst_state = BurstState::Idle;
        }
        prev == BurstState::Idle && self.burst_state == BurstState::Burst
    }
}

// ── ShadowSyncEngine ──────────────────────────────────────────────────────────

const JITTER_DEADLINE_FRACTION: f64 = 0.15;

pub struct ShadowSyncEngine {
    flows: HashMap<u64, FlowModel>,
    pending_slots: Vec<ShadowSlot>,
    rng: ChaCha8Rng,
    latency_guard_us: u64,
    burst_threshold_us: u32,
    idle_threshold_us: u32,
    idle_timeout_us: u64,
    jitter_iat_ratio: f64,
}

impl ShadowSyncEngine {
    pub fn new(
        latency_guard_ms: u32,
        idle_timeout_s: u32,
        burst_threshold_us: u32,
        idle_threshold_us: u32,
        jitter_iat_ratio: f32,
        rng_seed: &[u8; 32],
    ) -> Self {
        Self {
            flows: HashMap::new(),
            pending_slots: Vec::new(),
            rng: ChaCha8Rng::from_seed(rng_seed),
            latency_guard_us: latency_guard_ms as u64 * 1_000,
            burst_threshold_us,
            idle_threshold_us,
            idle_timeout_us: idle_timeout_s as u64 * 1_000_000,
            jitter_iat_ratio: jitter_iat_ratio as f64,
        }
    }

    /// Process one real packet arrival.  Emits shadow slots when `shadow_enabled`.
    pub fn update_packet(
        &mut self,
        flow_id: u64,
        size_bytes: u16,
        arrival_us: u64,
        shadow_enabled: bool,
    ) {
        // Extract model state in an explicit scope so the &mut FlowModel borrow
        // on self.flows is released before any &mut self method calls below.
        let (just_entered_burst, ewma_iat, std_dev) = {
            let model = self
                .flows
                .entry(flow_id)
                .or_insert_with(FlowModel::new_uniform);
            if model.initialised
                && arrival_us.saturating_sub(model.last_arrival_us) > self.idle_timeout_us
            {
                *model = FlowModel::new_uniform();
            }
            let jeb = model.update(
                arrival_us,
                size_bytes,
                self.burst_threshold_us,
                self.idle_threshold_us,
            );
            let ewma = model.ewma_iat_us.max(1.0);
            let sd = model.ewma_iat_var_us2.sqrt();
            (jeb, ewma, sd)
        };

        if !shadow_enabled {
            return;
        }

        // Compute jitter bound (§6.3).
        let jitter_max_us = (ewma_iat * self.jitter_iat_ratio)
            .min(self.latency_guard_us as f64 * JITTER_DEADLINE_FRACTION)
            .max(0.0) as u64;

        let jitter_us = if jitter_max_us > 0 {
            self.rng.next_bounded(jitter_max_us)
        } else {
            0
        };

        // Shadow IAT: Gaussian-truncated to [0.5×ewma, 2.0×ewma], plus jitter.
        let shadow_iat = self.rng.sample_gaussian_truncated(ewma_iat, std_dev);
        let raw_offset = shadow_iat + jitter_us as f64;
        let offset_us = raw_offset.min(self.latency_guard_us as f64).max(0.0) as u32;

        let shadow_size = self.sample_size(flow_id);

        let mut slot = ShadowSlot {
            offset_us,
            size_bytes: shadow_size,
            is_burst_head: just_entered_burst,
        };

        // Burst-head phase randomisation (§6.4): shift onset by [0, EWMA_IAT×3].
        if just_entered_burst {
            let phase_max = (ewma_iat * 3.0) as u64;
            let phase = if phase_max > 0 {
                self.rng.next_bounded(phase_max)
            } else {
                0
            };
            slot.offset_us =
                ((slot.offset_us as u64).saturating_add(phase)).min(self.latency_guard_us) as u32;
        }

        self.pending_slots.push(slot);
    }

    /// Sample a packet size from `flow_id`'s histogram.
    fn sample_size(&mut self, flow_id: u64) -> u16 {
        // Borrow flow immutably just to read histogram, then use rng.
        let histogram = self
            .flows
            .get(&flow_id)
            .map(|m| m.size_histogram)
            .unwrap_or([1.0; 8]);

        let total: f64 = histogram.iter().sum();
        if total <= 0.0 {
            return 256;
        }

        let r = (self.rng.next_u64() as f64 / u64::MAX as f64) * total;
        let mut cum = 0.0;
        for (i, &count) in histogram.iter().enumerate() {
            cum += count;
            if r <= cum {
                let (lo, hi) = BUCKET_BOUNDS[i];
                let range = (hi - lo).max(1) as u64;
                let offset = self.rng.next_bounded(range) as u16;
                return (lo + offset).clamp(64, 1500);
            }
        }
        512
    }

    /// Take all pending shadow slots.
    pub fn drain_pending_slots(&mut self) -> Vec<ShadowSlot> {
        std::mem::take(&mut self.pending_slots)
    }

    /// Generate `size` bytes of synthetic cover payload.
    pub fn synthetic_payload(&mut self, size: u16) -> Vec<u8> {
        let mut buf = vec![0u8; size as usize];
        self.rng.fill_bytes(&mut buf);
        buf
    }

    /// Expose EWMA IAT for a flow (used in tests).
    #[cfg(test)]
    pub fn ewma_iat_us(&self, flow_id: u64) -> Option<f64> {
        self.flows.get(&flow_id).map(|m| m.ewma_iat_us)
    }

    /// Expose burst state for a flow (used in tests).
    #[cfg(test)]
    pub fn burst_state(&self, flow_id: u64) -> Option<BurstState> {
        self.flows.get(&flow_id).map(|m| m.burst_state.clone())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> ShadowSyncEngine {
        ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &[0u8; 32])
    }

    // U1 — EWMA converges within 5% of true IAT after 50 packets.
    #[test]
    fn u1_iat_model_converges() {
        let mut engine = make_engine();
        let true_iat_us = 1_000u64;
        let flow = 1u64;
        let mut t = 0u64;
        for _ in 0..50 {
            t += true_iat_us;
            engine.update_packet(flow, 512, t, false);
        }
        let ewma = engine.ewma_iat_us(flow).unwrap();
        let error = (ewma - true_iat_us as f64).abs() / true_iat_us as f64;
        assert!(
            error < 0.05,
            "EWMA {ewma:.1} deviates >5% from {true_iat_us}"
        );
    }

    // U2 — 1000 samples from steady-state histogram stay within ±20% per active bucket.
    // Bucket 0 ([0, 63]) is excluded: sample_size clamps output to ≥ 64, so all
    // bucket-0 samples land in bucket 1.  We cycle through buckets 1-7 for ~100
    // rounds to reach EWMA steady state before asserting uniformity.
    #[test]
    fn u2_size_histogram_uniform_seed() {
        let mut engine = make_engine();
        let flow = 2u64;
        let mut t = 0u64;
        for _ in 0..100u16 {
            for b in 1u16..8 {
                t += 5_000;
                let size = BUCKET_BOUNDS[b as usize].0 + 1;
                engine.update_packet(flow, size, t, false);
            }
        }

        let n = 10_000usize;
        let mut counts = [0usize; 8];
        for _ in 0..n {
            let s = engine.sample_size(flow);
            counts[size_bucket(s)] += 1;
        }
        // Only buckets 1-7 are reachable; expected count per bucket ≈ n/7 ≈ 1429.
        let expected = n as f64 / 7.0;
        for i in 1usize..8 {
            let c = counts[i];
            let dev = (c as f64 - expected).abs() / expected;
            assert!(
                dev < 0.20,
                "bucket {i}: count {c} deviates {dev:.2} > 0.20 from expected {expected:.0}"
            );
        }
    }

    // U3 — Two packets 100 μs apart → FSM = Burst.
    #[test]
    fn u3_burst_fsm_enters_burst() {
        let mut engine = make_engine();
        let flow = 3u64;
        engine.update_packet(flow, 512, 1_000, false);
        engine.update_packet(flow, 512, 1_100, false); // IAT=100 < 500 threshold
        assert_eq!(engine.burst_state(flow), Some(BurstState::Burst));
    }

    // U4 — Single packet after 10 ms gap → FSM = Idle.
    #[test]
    fn u4_burst_fsm_enters_idle() {
        let mut engine = make_engine();
        let flow = 4u64;
        engine.update_packet(flow, 512, 1_000, false);
        // Force into Burst first.
        engine.update_packet(flow, 512, 1_100, false);
        assert_eq!(engine.burst_state(flow), Some(BurstState::Burst));
        // Now send after 10 ms gap (> 5000 idle_threshold).
        engine.update_packet(flow, 512, 1_100 + 10_000, false);
        assert_eq!(engine.burst_state(flow), Some(BurstState::Idle));
    }

    // U5 — No packets for idle_timeout_s; next packet resets EWMA.
    #[test]
    fn u5_stale_model_resets_on_timeout() {
        let mut engine = make_engine();
        let flow = 5u64;
        let iat = 100u64;
        let mut t = 0u64;
        // Warm up to a stable EWMA ≈ 100 μs.
        for _ in 0..50 {
            t += iat;
            engine.update_packet(flow, 512, t, false);
        }
        let ewma_before = engine.ewma_iat_us(flow).unwrap();
        assert!(
            (ewma_before - 100.0).abs() < 10.0,
            "pre-reset ewma {ewma_before}"
        );

        // Advance time by > idle_timeout_s (30 s).
        t += 31_000_000;
        engine.update_packet(flow, 512, t, false);
        // Model resets; EWMA is re-initialised to 1000 μs default.
        let ewma_after = engine.ewma_iat_us(flow).unwrap();
        assert!(
            (ewma_after - 1_000.0).abs() < 1.0,
            "post-reset ewma {ewma_after} should be ~1000"
        );
    }

    // U6 — 10 000 jitter samples all ≤ latency_guard_us × JITTER_DEADLINE_FRACTION.
    #[test]
    fn u6_jitter_bounded_by_deadline_fraction() {
        let latency_guard_ms = 80u32;
        let latency_guard_us = latency_guard_ms as u64 * 1_000;
        let cap = (latency_guard_us as f64 * JITTER_DEADLINE_FRACTION) as u64;
        let mut engine = ShadowSyncEngine::new(latency_guard_ms, 30, 500, 5000, 0.20, &[42u8; 32]);
        let max = cap.max(1);
        for _ in 0..10_000 {
            let j = engine.rng.next_bounded(max);
            assert!(j < max, "jitter {j} exceeded cap {cap}");
        }
    }

    // U7 — Shadow burst onset differs from real burst onset.
    #[test]
    fn u7_phase_offset_decorrelates_burst_onset() {
        let mut engine = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &[7u8; 32]);
        let flow = 7u64;
        // Warm up in idle state.
        let mut t = 0u64;
        for _ in 0..5 {
            t += 10_000;
            engine.update_packet(flow, 512, t, false);
        }
        let real_burst_onset = t + 200; // IAT=200 < 500 → BURST
        engine.update_packet(flow, 512, real_burst_onset, true);
        let slots = engine.drain_pending_slots();
        assert!(!slots.is_empty(), "expected at least one shadow slot");
        let burst_head = slots.iter().find(|s| s.is_burst_head);
        assert!(burst_head.is_some(), "no burst-head slot");
        let head_offset = burst_head.unwrap().offset_us;
        assert!(
            head_offset <= 80_000,
            "burst-head offset {head_offset} exceeds latency_guard_us"
        );
    }

    // S1 — Burst-head slot has phase offset applied and stays within latency_guard_us.
    #[test]
    fn shadow_timing_phase_offset_from_real_burst_onset() {
        let mut engine = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &[0xABu8; 32]);
        let flow = 10u64;
        let mut t = 0u64;
        for _ in 0..10 {
            t += 10_000;
            engine.update_packet(flow, 512, t, false);
        }
        t += 200; // IAT=200 < 500 → enters BURST
        engine.update_packet(flow, 512, t, true);
        let slots = engine.drain_pending_slots();
        let burst_head = slots.iter().find(|s| s.is_burst_head);
        assert!(
            burst_head.is_some(),
            "expected burst-head slot after idle→burst transition"
        );
        let offset = burst_head.unwrap().offset_us;
        assert!(
            offset as u64 <= 80_000,
            "burst-head offset {offset} exceeds latency_guard_us 80_000"
        );
    }

    // S2 — Same session seed produces identical shadow plans.
    #[test]
    fn same_session_seed_gives_same_shadow_plan() {
        let seed = [0x42u8; 32];
        let flow = 20u64;
        let mut engine_a = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &seed);
        let mut engine_b = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &seed);
        let mut t = 0u64;
        for _ in 0..15 {
            t += 1_000;
            engine_a.update_packet(flow, 512, t, true);
            engine_b.update_packet(flow, 512, t, true);
        }
        let slots_a = engine_a.drain_pending_slots();
        let slots_b = engine_b.drain_pending_slots();
        assert_eq!(
            slots_a.len(),
            slots_b.len(),
            "slot count differs between same-seed engines"
        );
        for (i, (a, b)) in slots_a.iter().zip(slots_b.iter()).enumerate() {
            assert_eq!(a.offset_us, b.offset_us, "slot {i} offset_us differs");
            assert_eq!(a.size_bytes, b.size_bytes, "slot {i} size_bytes differs");
            assert_eq!(
                a.is_burst_head, b.is_burst_head,
                "slot {i} is_burst_head differs"
            );
        }
    }

    // S3 — Different session seeds produce different shadow plans.
    #[test]
    fn different_session_seed_gives_different_shadow_plan() {
        let flow = 30u64;
        let mut engine_a = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &[0x11u8; 32]);
        let mut engine_b = ShadowSyncEngine::new(80, 30, 500, 5000, 0.20, &[0x22u8; 32]);
        let mut t = 0u64;
        for _ in 0..20 {
            t += 1_000;
            engine_a.update_packet(flow, 512, t, true);
            engine_b.update_packet(flow, 512, t, true);
        }
        let slots_a = engine_a.drain_pending_slots();
        let slots_b = engine_b.drain_pending_slots();
        let any_differ = slots_a.len() != slots_b.len()
            || slots_a
                .iter()
                .zip(slots_b.iter())
                .any(|(a, b)| a.offset_us != b.offset_us || a.size_bytes != b.size_bytes);
        assert!(
            any_differ,
            "different seeds produced identical shadow plans"
        );
    }

    // S4 — offset_us never exceeds u32::MAX (no underflow via saturating arithmetic).
    #[test]
    fn shadow_never_schedules_before_real_burst() {
        let mut engine = make_engine();
        let flow = 40u64;
        let mut t = 0u64;
        for _ in 0..100 {
            t += 300;
            engine.update_packet(flow, 512, t, true);
        }
        let slots = engine.drain_pending_slots();
        assert!(!slots.is_empty(), "expected shadow slots");
        for slot in &slots {
            // offset_us is u32; saturating arithmetic guarantees no wraparound.
            assert!(
                slot.offset_us as u64 <= u32::MAX as u64,
                "offset_us overflowed: {}",
                slot.offset_us
            );
        }
    }

    // S5 — All shadow slot offsets respect the configured latency_guard_us.
    #[test]
    fn latency_guard_respected() {
        let latency_guard_ms = 80u32;
        let guard_us = latency_guard_ms as u64 * 1_000;
        let mut engine =
            ShadowSyncEngine::new(latency_guard_ms, 30, 500, 5000, 0.20, &[0xFFu8; 32]);
        let flow = 50u64;
        let mut t = 0u64;
        for _ in 0..200 {
            t += 300;
            engine.update_packet(flow, 512, t, true);
        }
        let slots = engine.drain_pending_slots();
        assert!(!slots.is_empty(), "expected shadow slots");
        for slot in &slots {
            assert!(
                slot.offset_us as u64 <= guard_us,
                "slot offset {} exceeds latency_guard_us {}",
                slot.offset_us,
                guard_us
            );
        }
    }

    // S6 — No input packets → drain returns empty vec.
    #[test]
    fn empty_real_burst_returns_empty_shadow_plan() {
        let mut engine = make_engine();
        let slots = engine.drain_pending_slots();
        assert!(
            slots.is_empty(),
            "expected no slots when no packets were processed"
        );
    }

    // S7 — shadow_enabled=false → no slots (Banking/Login pass-through).
    #[test]
    fn banking_login_passthrough_no_shadow_plan() {
        let mut engine = make_engine();
        let flow = 60u64;
        let mut t = 0u64;
        for _ in 0..20 {
            t += 300;
            engine.update_packet(flow, 512, t, false);
        }
        let slots = engine.drain_pending_slots();
        assert!(
            slots.is_empty(),
            "shadow_enabled=false must produce no shadow slots; got {}",
            slots.len()
        );
    }
}
