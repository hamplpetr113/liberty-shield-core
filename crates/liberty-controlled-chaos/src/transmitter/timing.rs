//! TimingController and per-path TokenBucket for cover-traffic rate enforcement.

// ── TokenBucket ───────────────────────────────────────────────────────────────

pub struct TokenBucket {
    capacity_bits: u64,
    refill_rate_bps: u64,
    tokens: u64,
    last_refill_us: u64,
}

impl TokenBucket {
    /// `cover_bandwidth_kbps`: per-path cover budget.
    /// `latency_guard_ms`: sets bucket capacity to one guard window of cover data.
    pub fn new(cover_bandwidth_kbps: u32, latency_guard_ms: u32, now_us: u64) -> Self {
        let refill_rate_bps = cover_bandwidth_kbps as u64 * 1_000;
        // capacity = rate × window = kbps×1000 × latency_guard_ms/1000 bits
        let capacity_bits = cover_bandwidth_kbps as u64 * latency_guard_ms as u64;
        Self {
            capacity_bits,
            refill_rate_bps,
            tokens: capacity_bits, // start full
            last_refill_us: now_us,
        }
    }

    /// Refill tokens based on elapsed time since last call.
    pub fn refill(&mut self, now_us: u64) {
        if now_us <= self.last_refill_us {
            return;
        }
        let elapsed_us = now_us - self.last_refill_us;
        // new_tokens = refill_rate_bps × elapsed_us / 1_000_000
        let new_tokens = (self.refill_rate_bps.saturating_mul(elapsed_us)) / 1_000_000;
        self.tokens = (self.tokens.saturating_add(new_tokens)).min(self.capacity_bits);
        self.last_refill_us = now_us;
    }

    /// Attempt to consume `size_bytes × 8` bits.  Returns `true` on success.
    pub fn try_consume(&mut self, size_bytes: u16) -> bool {
        let bits = size_bytes as u64 * 8;
        if self.tokens >= bits {
            self.tokens -= bits;
            true
        } else {
            false
        }
    }

    pub fn fill_bits(&self) -> u64 {
        self.tokens
    }

    /// Drain the bucket to simulate empty state (used in tests).
    #[cfg(test)]
    pub fn drain_all(&mut self) {
        self.tokens = 0;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // U13 — cover_bandwidth=100kbps, latency=80ms → capacity=8000 bits.
    //        Consuming 1000-byte packet (8000 bits) empties bucket exactly.
    #[test]
    fn u14_cover_dropped_on_empty_bucket() {
        let mut bucket = TokenBucket::new(100, 80, 0);
        bucket.drain_all();
        assert!(!bucket.try_consume(512), "should fail when bucket is empty");
    }

    // U16 — Token bucket refills proportionally to rate.
    #[test]
    fn u16_token_bucket_refills_over_time() {
        let mut bucket = TokenBucket::new(100, 80, 0);
        bucket.drain_all();
        assert_eq!(bucket.fill_bits(), 0);

        // Advance 10 ms → should gain 100kbps × 0.01s = 1000 bits.
        bucket.refill(10_000);
        let gained = bucket.fill_bits();
        // 100_000 bps × 10_000 μs / 1_000_000 = 1_000 bits
        assert_eq!(gained, 1_000, "expected 1000 bits, got {gained}");
    }

    #[test]
    fn bucket_does_not_exceed_capacity() {
        let bw = 100u32;
        let guard = 80u32;
        let cap = bw as u64 * guard as u64; // 8000 bits
        let mut bucket = TokenBucket::new(bw, guard, 0);
        bucket.drain_all();
        // Refill more than capacity.
        bucket.refill(1_000_000_000); // 1000 s
        assert_eq!(bucket.fill_bits(), cap);
    }

    #[test]
    fn consume_exactly_available() {
        let mut bucket = TokenBucket::new(100, 80, 0);
        bucket.drain_all();
        bucket.refill(10_000); // +1000 bits
        // 125 bytes = 1000 bits: should succeed exactly.
        assert!(bucket.try_consume(125));
        assert_eq!(bucket.fill_bits(), 0);
        assert!(!bucket.try_consume(1)); // now empty
    }
}
