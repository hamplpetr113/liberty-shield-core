//! Runtime epoch driver — deterministic, tick-driven epoch clock for tests
//! and production alike.
//!
//! `RuntimeEpochDriver` owns the authoritative epoch counter.  Callers
//! advance time by calling `tick()` (one epoch) or `tick_by(n)`.  A
//! monotonic guard prevents the epoch from going backwards.
//!
//! Subscribers implement `EpochSubscriber` and are notified on every tick.
//! This decouples epoch-sensitive subsystems (key rotation, directory refresh,
//! circuit rotation) from the clock implementation.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// EpochSubscriber trait
// ---------------------------------------------------------------------------

pub trait EpochSubscriber: Send {
    /// Called after every epoch advance.  `new_epoch` is the epoch that just
    /// became current.
    fn on_epoch(&mut self, new_epoch: u64);
    /// Human-readable name for diagnostics.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// SubscriberId
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SubscriberId(u64);

// ---------------------------------------------------------------------------
// EpochDriverConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EpochDriverConfig {
    /// Starting epoch (default 0).
    pub initial_epoch: u64,
    /// If true, `tick()` panics if the resulting epoch would wrap u64.
    /// Always true in production; can be false in fuzz/chaos tests.
    pub strict_monotone: bool,
}

impl Default for EpochDriverConfig {
    fn default() -> Self {
        Self {
            initial_epoch: 0,
            strict_monotone: true,
        }
    }
}

// ---------------------------------------------------------------------------
// EpochDriverMetrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct EpochDriverMetrics {
    pub total_ticks: u64,
    pub total_subscriber_calls: u64,
}

// ---------------------------------------------------------------------------
// RuntimeEpochDriver
// ---------------------------------------------------------------------------

pub struct RuntimeEpochDriver {
    epoch: u64,
    config: EpochDriverConfig,
    next_id: u64,
    subscribers: HashMap<u64, Box<dyn EpochSubscriber>>,
    metrics: EpochDriverMetrics,
}

impl RuntimeEpochDriver {
    pub fn new(config: EpochDriverConfig) -> Self {
        Self {
            epoch: config.initial_epoch,
            config,
            next_id: 0,
            subscribers: HashMap::new(),
            metrics: EpochDriverMetrics::default(),
        }
    }

    /// Returns the current epoch without advancing.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Attach a subscriber; returns its handle.
    pub fn subscribe(&mut self, sub: Box<dyn EpochSubscriber>) -> SubscriberId {
        let id = self.next_id;
        self.next_id += 1;
        self.subscribers.insert(id, sub);
        SubscriberId(id)
    }

    /// Detach a subscriber by handle.  Returns true if it was present.
    pub fn unsubscribe(&mut self, id: SubscriberId) -> bool {
        self.subscribers.remove(&id.0).is_some()
    }

    /// Advance by exactly one epoch, notifying all subscribers.
    pub fn tick(&mut self) {
        self.tick_by(1);
    }

    /// Advance by `n` epochs, notifying subscribers after each step.
    pub fn tick_by(&mut self, n: u64) {
        for _ in 0..n {
            if self.config.strict_monotone {
                self.epoch = self
                    .epoch
                    .checked_add(1)
                    .expect("epoch overflow with strict_monotone=true");
            } else {
                self.epoch = self.epoch.wrapping_add(1);
            }
            self.metrics.total_ticks += 1;
            // Notify all subscribers in insertion order (HashMap iteration is
            // non-deterministic; that's acceptable — subscribers must be
            // independent of ordering).
            for sub in self.subscribers.values_mut() {
                sub.on_epoch(self.epoch);
                self.metrics.total_subscriber_calls += 1;
            }
        }
    }

    pub fn metrics(&self) -> &EpochDriverMetrics {
        &self.metrics
    }

    pub fn subscriber_count(&self) -> usize {
        self.subscribers.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct NullSubscriber {
        name: String,
    }

    impl NullSubscriber {
        fn new(name: &str) -> Self {
            Self { name: name.into() }
        }
    }

    impl EpochSubscriber for NullSubscriber {
        fn on_epoch(&mut self, _new_epoch: u64) {}
        fn name(&self) -> &str {
            &self.name
        }
    }

    fn driver() -> RuntimeEpochDriver {
        RuntimeEpochDriver::new(EpochDriverConfig::default())
    }

    // RED1: initial epoch matches config.
    #[test]
    fn red1_initial_epoch() {
        let d = driver();
        assert_eq!(d.epoch(), 0);
    }

    // RED2: tick advances epoch by one.
    #[test]
    fn red2_tick_advances_one() {
        let mut d = driver();
        d.tick();
        assert_eq!(d.epoch(), 1);
    }

    // RED3: tick_by(n) advances by n.
    #[test]
    fn red3_tick_by_n() {
        let mut d = driver();
        d.tick_by(7);
        assert_eq!(d.epoch(), 7);
    }

    // RED4: subscriber receives epoch on tick — verified via metrics.
    #[test]
    fn red4_subscriber_notified() {
        let mut d = driver();
        d.subscribe(Box::new(NullSubscriber::new("s1")));
        d.tick();
        assert_eq!(d.metrics().total_subscriber_calls, 1);
        assert_eq!(d.epoch(), 1);
    }

    // RED5: multiple ticks — subscriber called each time.
    #[test]
    fn red5_subscriber_called_each_tick() {
        let mut d = driver();
        d.subscribe(Box::new(NullSubscriber::new("s")));
        d.tick_by(5);
        assert_eq!(d.metrics().total_subscriber_calls, 5);
    }

    // RED6: two subscribers — both called per tick.
    #[test]
    fn red6_two_subscribers_both_called() {
        let mut d = driver();
        d.subscribe(Box::new(NullSubscriber::new("a")));
        d.subscribe(Box::new(NullSubscriber::new("b")));
        d.tick_by(3);
        assert_eq!(d.metrics().total_subscriber_calls, 6);
    }

    // RED7: unsubscribe removes subscriber.
    #[test]
    fn red7_unsubscribe() {
        let mut d = driver();
        let id = d.subscribe(Box::new(NullSubscriber::new("s")));
        assert!(d.unsubscribe(id));
        d.tick_by(4);
        assert_eq!(d.metrics().total_subscriber_calls, 0);
    }

    // RED8: unsubscribe unknown id returns false.
    #[test]
    fn red8_unsubscribe_unknown() {
        let mut d = driver();
        assert!(!d.unsubscribe(SubscriberId(99)));
    }

    // RED9: subscriber_count reflects live subscribers.
    #[test]
    fn red9_subscriber_count() {
        let mut d = driver();
        assert_eq!(d.subscriber_count(), 0);
        let id = d.subscribe(Box::new(NullSubscriber::new("s")));
        assert_eq!(d.subscriber_count(), 1);
        d.unsubscribe(id);
        assert_eq!(d.subscriber_count(), 0);
    }

    // RED10: custom initial_epoch respected.
    #[test]
    fn red10_custom_initial_epoch() {
        let mut d = RuntimeEpochDriver::new(EpochDriverConfig {
            initial_epoch: 100,
            strict_monotone: true,
        });
        assert_eq!(d.epoch(), 100);
        d.tick();
        assert_eq!(d.epoch(), 101);
    }
}
