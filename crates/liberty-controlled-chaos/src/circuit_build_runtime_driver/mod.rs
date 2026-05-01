//! Circuit build runtime driver — manages the lifecycle of pending circuit builds.
//!
//! `CircuitBuildRuntimeDriver` wraps `CircuitBuilderRuntime` and adds:
//! - A work queue of pending build requests (`BuildRequest`)
//! - Per-epoch timeout enforcement: circuits that have been pending for more
//!   than `timeout_epochs` are aborted and recorded as failures
//! - A completion log: finished circuit IDs and their final paths
//! - Metrics: total started, completed, timed-out, failed

use crate::circuit_builder_runtime::CircuitBuilderRuntime;
use std::collections::VecDeque;

// ---------------------------------------------------------------------------
// BuildRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BuildRequest {
    pub circuit_id: u64,
    /// Ordered node IDs for the intended path (guard, relay, exit).
    pub path: Vec<[u8; 32]>,
    /// Epoch at which the build was enqueued.
    pub queued_at_epoch: u64,
}

// ---------------------------------------------------------------------------
// CompletedBuild
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CompletedBuild {
    pub circuit_id: u64,
    pub path: Vec<[u8; 32]>,
    pub completed_at_epoch: u64,
}

// ---------------------------------------------------------------------------
// DriverConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DriverConfig {
    /// Max in-flight concurrent builds.
    pub max_concurrent: usize,
    /// Epochs after which a pending build is timed out.
    pub timeout_epochs: u64,
    /// Max retries forwarded to CircuitBuilderRuntime.
    pub max_retries: u32,
}

impl Default for DriverConfig {
    fn default() -> Self {
        Self {
            max_concurrent: 8,
            timeout_epochs: 10,
            max_retries: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// DriverMetrics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct DriverMetrics {
    pub total_started: u64,
    pub total_completed: u64,
    pub total_timed_out: u64,
    pub total_failed: u64,
}

// ---------------------------------------------------------------------------
// CircuitBuildRuntimeDriver
// ---------------------------------------------------------------------------

pub struct CircuitBuildRuntimeDriver {
    config: DriverConfig,
    builder: CircuitBuilderRuntime,
    /// Circuits waiting to be started (queued but not yet in-flight).
    pending_queue: VecDeque<BuildRequest>,
    /// Circuits currently in-flight: circuit_id → (path, queued_at_epoch).
    in_flight: std::collections::HashMap<u64, (Vec<[u8; 32]>, u64)>,
    completed: Vec<CompletedBuild>,
    metrics: DriverMetrics,
}

impl CircuitBuildRuntimeDriver {
    pub fn new(config: DriverConfig) -> Self {
        let max_retries = config.max_retries;
        Self {
            config,
            builder: CircuitBuilderRuntime::new(max_retries),
            pending_queue: VecDeque::new(),
            in_flight: std::collections::HashMap::new(),
            completed: Vec::new(),
            metrics: DriverMetrics::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Enqueue
    // -----------------------------------------------------------------------

    /// Enqueue a build request.  Returns false and discards if the queue
    /// already has `max_concurrent` in-flight builds.
    pub fn enqueue(&mut self, req: BuildRequest) -> bool {
        if self.in_flight.len() >= self.config.max_concurrent {
            return false;
        }
        self.pending_queue.push_back(req);
        true
    }

    // -----------------------------------------------------------------------
    // Tick
    // -----------------------------------------------------------------------

    /// Advance one epoch: start queued builds, time out stale in-flight builds.
    pub fn tick(&mut self, current_epoch: u64) {
        // Start any queued builds up to max_concurrent.
        while self.in_flight.len() < self.config.max_concurrent {
            match self.pending_queue.pop_front() {
                None => break,
                Some(req) => {
                    let guard = req.path.first().copied().unwrap_or([0u8; 32]);
                    let relay = req.path.get(1).copied().unwrap_or([0u8; 32]);
                    let exit = req.path.get(2).copied().unwrap_or([0u8; 32]);
                    self.builder
                        .start_build(req.circuit_id, guard, relay, exit, current_epoch);
                    // advance Pending → Building so complete() is valid later
                    let _ = self.builder.advance(req.circuit_id);
                    self.in_flight
                        .insert(req.circuit_id, (req.path.clone(), req.queued_at_epoch));
                    self.metrics.total_started += 1;
                }
            }
        }

        // Time out stale builds.
        let timeout = self.config.timeout_epochs;
        let timed_out: Vec<u64> = self
            .in_flight
            .iter()
            .filter(|(_, (_, queued_at))| {
                current_epoch.saturating_sub(*queued_at) >= timeout
            })
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            self.in_flight.remove(&id);
            let _ = self.builder.remove(id);
            self.metrics.total_timed_out += 1;
        }
    }

    // -----------------------------------------------------------------------
    // Complete
    // -----------------------------------------------------------------------

    /// Mark a build as successfully completed.
    /// Returns false if the circuit was not in-flight.
    pub fn complete(&mut self, circuit_id: u64, epoch: u64) -> bool {
        match self.in_flight.remove(&circuit_id) {
            None => false,
            Some((path, _)) => {
                let _ = self.builder.complete(circuit_id, epoch);
                self.completed.push(CompletedBuild {
                    circuit_id,
                    path,
                    completed_at_epoch: epoch,
                });
                self.metrics.total_completed += 1;
                true
            }
        }
    }

    // -----------------------------------------------------------------------
    // Failure
    // -----------------------------------------------------------------------

    /// Record a build failure; removes from in-flight.
    pub fn record_failure(&mut self, circuit_id: u64) -> bool {
        match self.in_flight.remove(&circuit_id) {
            None => false,
            Some(_) => {
                let _ = self.builder.record_failure(circuit_id);
                let _ = self.builder.remove(circuit_id);
                self.metrics.total_failed += 1;
                true
            }
        }
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn in_flight_count(&self) -> usize {
        self.in_flight.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_queue.len()
    }

    pub fn completed_builds(&self) -> &[CompletedBuild] {
        &self.completed
    }

    pub fn metrics(&self) -> &DriverMetrics {
        &self.metrics
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn req(id: u64, epoch: u64) -> BuildRequest {
        BuildRequest {
            circuit_id: id,
            path: vec![peer(1), peer(2), peer(3)],
            queued_at_epoch: epoch,
        }
    }

    fn driver() -> CircuitBuildRuntimeDriver {
        CircuitBuildRuntimeDriver::new(DriverConfig::default())
    }

    // CBD1: enqueue adds to pending.
    #[test]
    fn cbd1_enqueue_pending() {
        let mut d = driver();
        assert!(d.enqueue(req(1, 0)));
        assert_eq!(d.pending_count(), 1);
    }

    // CBD2: tick starts pending builds up to max_concurrent.
    #[test]
    fn cbd2_tick_starts_builds() {
        let mut d = driver();
        d.enqueue(req(1, 0));
        d.enqueue(req(2, 0));
        d.tick(1);
        assert_eq!(d.in_flight_count(), 2);
        assert_eq!(d.pending_count(), 0);
        assert_eq!(d.metrics().total_started, 2);
    }

    // CBD3: max_concurrent prevents starting more builds than allowed.
    #[test]
    fn cbd3_max_concurrent_respected() {
        let mut d = CircuitBuildRuntimeDriver::new(DriverConfig {
            max_concurrent: 2,
            ..DriverConfig::default()
        });
        for i in 0..5 {
            d.enqueue(req(i, 0));
        }
        d.tick(1);
        assert_eq!(d.in_flight_count(), 2);
        assert_eq!(d.pending_count(), 3);
    }

    // CBD4: complete removes from in-flight and records completion.
    #[test]
    fn cbd4_complete_records() {
        let mut d = driver();
        d.enqueue(req(10, 0));
        d.tick(1);
        assert!(d.complete(10, 2));
        assert_eq!(d.in_flight_count(), 0);
        assert_eq!(d.completed_builds().len(), 1);
        assert_eq!(d.completed_builds()[0].circuit_id, 10);
        assert_eq!(d.metrics().total_completed, 1);
    }

    // CBD5: complete on unknown id returns false.
    #[test]
    fn cbd5_complete_unknown_returns_false() {
        let mut d = driver();
        assert!(!d.complete(99, 1));
    }

    // CBD6: timeout removes stale in-flight builds.
    #[test]
    fn cbd6_timeout_removes_stale() {
        let mut d = CircuitBuildRuntimeDriver::new(DriverConfig {
            timeout_epochs: 5,
            ..DriverConfig::default()
        });
        d.enqueue(req(1, 0));
        d.tick(1); // starts it, in-flight since epoch 0
        assert_eq!(d.in_flight_count(), 1);
        d.tick(6); // epoch 6 - 0 >= 5 → timed out
        assert_eq!(d.in_flight_count(), 0);
        assert_eq!(d.metrics().total_timed_out, 1);
    }

    // CBD7: record_failure removes from in-flight and increments counter.
    #[test]
    fn cbd7_failure_recorded() {
        let mut d = driver();
        d.enqueue(req(20, 0));
        d.tick(1);
        assert!(d.record_failure(20));
        assert_eq!(d.in_flight_count(), 0);
        assert_eq!(d.metrics().total_failed, 1);
    }

    // CBD8: record_failure on unknown id returns false.
    #[test]
    fn cbd8_failure_unknown_returns_false() {
        let mut d = driver();
        assert!(!d.record_failure(99));
    }

    // CBD9: enqueue rejected when at max_concurrent with no room.
    #[test]
    fn cbd9_enqueue_at_capacity_rejected() {
        let mut d = CircuitBuildRuntimeDriver::new(DriverConfig {
            max_concurrent: 1,
            ..DriverConfig::default()
        });
        d.enqueue(req(1, 0));
        d.tick(1); // in-flight = 1 = max
        assert!(!d.enqueue(req(2, 0)));
    }

    // CBD10: metrics track all counters across multiple operations.
    #[test]
    fn cbd10_metrics_accurate() {
        let mut d = driver();
        d.enqueue(req(1, 0));
        d.enqueue(req(2, 0));
        d.tick(1);
        d.complete(1, 2);
        d.record_failure(2);
        let m = d.metrics();
        assert_eq!(m.total_started, 2);
        assert_eq!(m.total_completed, 1);
        assert_eq!(m.total_failed, 1);
        assert_eq!(m.total_timed_out, 0);
    }
}
