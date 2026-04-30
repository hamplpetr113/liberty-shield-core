//! Circuit rate limiter — token-bucket rate limiting per circuit.
//!
//! Each circuit has an independent token bucket that refills at a configurable
//! rate per epoch.  Byte-level granularity.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// RateLimitError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitError {
    CircuitNotFound,
    BudgetExhausted,
}

// ---------------------------------------------------------------------------
// BucketConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub struct BucketConfig {
    /// Maximum token capacity.
    pub capacity: u64,
    /// Tokens added per epoch tick.
    pub refill_per_epoch: u64,
}

impl Default for BucketConfig {
    fn default() -> Self {
        Self {
            capacity: 65536,
            refill_per_epoch: 8192,
        }
    }
}

// ---------------------------------------------------------------------------
// TokenBucket
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct TokenBucket {
    tokens: u64,
    config: BucketConfig,
    total_consumed: u64,
    total_rejected: u64,
}

impl TokenBucket {
    fn new(config: BucketConfig) -> Self {
        Self {
            tokens: config.capacity,
            config,
            total_consumed: 0,
            total_rejected: 0,
        }
    }

    fn try_consume(&mut self, bytes: u64) -> bool {
        if self.tokens >= bytes {
            self.tokens -= bytes;
            self.total_consumed += bytes;
            true
        } else {
            self.total_rejected += bytes;
            false
        }
    }

    fn refill(&mut self) {
        self.tokens = (self.tokens + self.config.refill_per_epoch).min(self.config.capacity);
    }
}

// ---------------------------------------------------------------------------
// CircuitRateLimiter
// ---------------------------------------------------------------------------

pub struct CircuitRateLimiter {
    default_config: BucketConfig,
    buckets: HashMap<u64, TokenBucket>,
    global_consumed: u64,
    global_rejected: u64,
}

impl CircuitRateLimiter {
    pub fn new(default_config: BucketConfig) -> Self {
        Self {
            default_config,
            buckets: HashMap::new(),
            global_consumed: 0,
            global_rejected: 0,
        }
    }

    pub fn register_circuit(&mut self, circuit_id: u64) {
        self.buckets
            .entry(circuit_id)
            .or_insert_with(|| TokenBucket::new(self.default_config));
    }

    pub fn register_circuit_with_config(&mut self, circuit_id: u64, config: BucketConfig) {
        self.buckets.insert(circuit_id, TokenBucket::new(config));
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) {
        self.buckets.remove(&circuit_id);
    }

    /// Attempt to consume `bytes` from `circuit_id`'s bucket.
    pub fn try_consume(&mut self, circuit_id: u64, bytes: u64) -> Result<(), RateLimitError> {
        let bucket = self
            .buckets
            .get_mut(&circuit_id)
            .ok_or(RateLimitError::CircuitNotFound)?;
        if bucket.try_consume(bytes) {
            self.global_consumed += bytes;
            Ok(())
        } else {
            self.global_rejected += bytes;
            Err(RateLimitError::BudgetExhausted)
        }
    }

    /// Refill all buckets (call once per epoch).
    pub fn tick_epoch(&mut self) {
        for b in self.buckets.values_mut() {
            b.refill();
        }
    }

    pub fn available_tokens(&self, circuit_id: u64) -> Option<u64> {
        self.buckets.get(&circuit_id).map(|b| b.tokens)
    }

    pub fn global_consumed(&self) -> u64 {
        self.global_consumed
    }

    pub fn global_rejected(&self) -> u64 {
        self.global_rejected
    }

    pub fn circuit_count(&self) -> usize {
        self.buckets.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter() -> CircuitRateLimiter {
        CircuitRateLimiter::new(BucketConfig {
            capacity: 1000,
            refill_per_epoch: 200,
        })
    }

    // CRL1: registered circuit starts full.
    #[test]
    fn crl1_full_on_register() {
        let mut r = limiter();
        r.register_circuit(1);
        assert_eq!(r.available_tokens(1), Some(1000));
    }

    // CRL2: consume within budget succeeds.
    #[test]
    fn crl2_consume_ok() {
        let mut r = limiter();
        r.register_circuit(1);
        assert!(r.try_consume(1, 500).is_ok());
        assert_eq!(r.available_tokens(1), Some(500));
    }

    // CRL3: consume beyond budget returns BudgetExhausted.
    #[test]
    fn crl3_budget_exhausted() {
        let mut r = limiter();
        r.register_circuit(1);
        assert_eq!(r.try_consume(1, 1001), Err(RateLimitError::BudgetExhausted));
    }

    // CRL4: unknown circuit returns CircuitNotFound.
    #[test]
    fn crl4_not_found() {
        let mut r = limiter();
        assert_eq!(r.try_consume(99, 1), Err(RateLimitError::CircuitNotFound));
    }

    // CRL5: tick_epoch refills tokens up to capacity.
    #[test]
    fn crl5_refill() {
        let mut r = limiter();
        r.register_circuit(1);
        r.try_consume(1, 1000).unwrap();
        assert_eq!(r.available_tokens(1), Some(0));
        r.tick_epoch();
        assert_eq!(r.available_tokens(1), Some(200));
    }

    // CRL6: refill does not exceed capacity.
    #[test]
    fn crl6_refill_capped() {
        let mut r = limiter();
        r.register_circuit(1);
        r.tick_epoch(); // tokens already full
        assert_eq!(r.available_tokens(1), Some(1000));
    }

    // CRL7: global_consumed accumulates.
    #[test]
    fn crl7_global_consumed() {
        let mut r = limiter();
        r.register_circuit(1);
        r.try_consume(1, 100).unwrap();
        r.try_consume(1, 200).unwrap();
        assert_eq!(r.global_consumed(), 300);
    }

    // CRL8: global_rejected accumulates on failures.
    #[test]
    fn crl8_global_rejected() {
        let mut r = limiter();
        r.register_circuit(1);
        r.try_consume(1, 1000).unwrap();
        r.try_consume(1, 500).unwrap_err();
        assert_eq!(r.global_rejected(), 500);
    }

    // CRL9: remove_circuit makes circuit not found.
    #[test]
    fn crl9_remove() {
        let mut r = limiter();
        r.register_circuit(1);
        r.remove_circuit(1);
        assert_eq!(r.try_consume(1, 1), Err(RateLimitError::CircuitNotFound));
    }

    // CRL10: custom config per circuit is respected.
    #[test]
    fn crl10_custom_config() {
        let mut r = limiter();
        r.register_circuit_with_config(
            1,
            BucketConfig {
                capacity: 50,
                refill_per_epoch: 10,
            },
        );
        assert_eq!(r.try_consume(1, 51), Err(RateLimitError::BudgetExhausted));
        assert!(r.try_consume(1, 50).is_ok());
    }
}
