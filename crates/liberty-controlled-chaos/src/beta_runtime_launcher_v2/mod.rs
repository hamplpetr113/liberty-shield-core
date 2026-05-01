//! Beta runtime launcher v2 — wraps `IntegratedNodeRuntime` + `PacketFlowEngine`
//! + `RuntimeEpochDriver` into a single launch sequence.
//!
//! Differences from v1:
//! - Owns the epoch driver; callers drive time via `tick()`.
//! - Owns a `PacketFlowEngine` alongside the node runtime.
//! - `launch()` bootstraps the node, syncs the epoch driver, and returns a
//!   `BetaRuntimeV2` handle for ongoing operation.
//! - Configurable peer session registration.

use crate::integrated_node_runtime::{IntegratedNodeRuntime, RuntimeError, RuntimeState};
use crate::node_config::NodeConfig;
use crate::packet_flow_engine::PacketFlowEngine;
use crate::runtime_epoch_driver::{EpochDriverConfig, RuntimeEpochDriver};

// ---------------------------------------------------------------------------
// LaunchConfig
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LaunchConfig {
    pub node_id: [u8; 32],
    pub initial_epoch: u64,
}

impl LaunchConfig {
    pub fn new(node_id: [u8; 32]) -> Self {
        Self {
            node_id,
            initial_epoch: 1,
        }
    }

    pub fn with_initial_epoch(mut self, epoch: u64) -> Self {
        self.initial_epoch = epoch;
        self
    }
}

// ---------------------------------------------------------------------------
// LaunchError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    /// Node lifecycle error during launch.
    Runtime(String),
    /// Already launched.
    AlreadyLaunched,
}

// ---------------------------------------------------------------------------
// BetaRuntimeV2 — handle returned by a successful launch
// ---------------------------------------------------------------------------

pub struct BetaRuntimeV2 {
    pub rt: IntegratedNodeRuntime,
    pub flow: PacketFlowEngine,
    pub epoch_driver: RuntimeEpochDriver,
}

impl BetaRuntimeV2 {
    /// Advance the runtime by `n` epochs (ticks epoch driver + node subsystems).
    pub fn tick(&mut self, n: u64) {
        self.rt.advance_epoch_driven(n);
    }

    pub fn state(&self) -> RuntimeState {
        self.rt.state()
    }

    pub fn current_epoch(&self) -> u64 {
        self.rt.current_epoch()
    }

    pub fn stop(&mut self) -> Result<(), RuntimeError> {
        self.rt.stop(self.rt.current_epoch() + 1)
    }
}

// ---------------------------------------------------------------------------
// BetaRuntimeLauncherV2
// ---------------------------------------------------------------------------

pub struct BetaRuntimeLauncherV2 {
    config: LaunchConfig,
    launched: bool,
}

impl BetaRuntimeLauncherV2 {
    pub fn new(config: LaunchConfig) -> Self {
        Self {
            config,
            launched: false,
        }
    }

    /// Launch: configure, bootstrap, and return a `BetaRuntimeV2` handle.
    pub fn launch(&mut self) -> Result<BetaRuntimeV2, LaunchError> {
        if self.launched {
            return Err(LaunchError::AlreadyLaunched);
        }

        let epoch = self.config.initial_epoch;
        let mut rt = IntegratedNodeRuntime::new(NodeConfig::new(self.config.node_id));

        rt.configure()
            .map_err(|e| LaunchError::Runtime(format!("{e:?}")))?;
        rt.start_bootstrap(epoch)
            .map_err(|e| LaunchError::Runtime(format!("{e:?}")))?;
        rt.complete_bootstrap(epoch)
            .map_err(|e| LaunchError::Runtime(format!("{e:?}")))?;

        let flow = PacketFlowEngine::new(self.config.node_id);
        let epoch_driver = RuntimeEpochDriver::new(EpochDriverConfig {
            initial_epoch: epoch,
            strict_monotone: true,
        });

        self.launched = true;
        Ok(BetaRuntimeV2 {
            rt,
            flow,
            epoch_driver,
        })
    }

    pub fn is_launched(&self) -> bool {
        self.launched
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn launcher(id: u8) -> BetaRuntimeLauncherV2 {
        BetaRuntimeLauncherV2::new(LaunchConfig::new(nid(id)))
    }

    // BRV2_1: launch returns a handle in Running state.
    #[test]
    fn brv2_1_launch_running() {
        let mut l = launcher(1);
        let h = l.launch().unwrap();
        assert_eq!(h.state(), RuntimeState::Running);
    }

    // BRV2_2: double launch returns AlreadyLaunched.
    #[test]
    fn brv2_2_double_launch() {
        let mut l = launcher(2);
        l.launch().unwrap();
        let err = l.launch().err().unwrap();
        assert_eq!(err, LaunchError::AlreadyLaunched);
    }

    // BRV2_3: is_launched reflects state.
    #[test]
    fn brv2_3_is_launched() {
        let mut l = launcher(3);
        assert!(!l.is_launched());
        l.launch().unwrap();
        assert!(l.is_launched());
    }

    // BRV2_4: initial epoch is propagated to the handle.
    #[test]
    fn brv2_4_initial_epoch_propagated() {
        let mut l = BetaRuntimeLauncherV2::new(LaunchConfig::new(nid(4)).with_initial_epoch(10));
        let h = l.launch().unwrap();
        assert_eq!(h.current_epoch(), 10);
    }

    // BRV2_5: tick advances current_epoch.
    #[test]
    fn brv2_5_tick_advances_epoch() {
        let mut l = launcher(5);
        let mut h = l.launch().unwrap();
        h.tick(3);
        assert_eq!(h.current_epoch(), 4); // starts at 1, advance 3 → 4
    }

    // BRV2_6: stop transitions to Stopped.
    #[test]
    fn brv2_6_stop() {
        let mut l = launcher(6);
        let mut h = l.launch().unwrap();
        h.stop().unwrap();
        assert_eq!(h.state(), RuntimeState::Stopped);
    }

    // BRV2_7: flow engine is accessible on handle.
    #[test]
    fn brv2_7_flow_accessible() {
        let mut l = launcher(7);
        let h = l.launch().unwrap();
        assert_eq!(h.flow.outbound_queue().len(), 0);
    }

    // BRV2_8: epoch_driver on handle starts at initial_epoch.
    #[test]
    fn brv2_8_epoch_driver_initial() {
        let mut l = BetaRuntimeLauncherV2::new(LaunchConfig::new(nid(8)).with_initial_epoch(5));
        let h = l.launch().unwrap();
        assert_eq!(h.epoch_driver.epoch(), 5);
    }

    // BRV2_9: LaunchConfig::with_initial_epoch stores the value.
    #[test]
    fn brv2_9_launch_config_epoch() {
        let cfg = LaunchConfig::new(nid(9)).with_initial_epoch(42);
        assert_eq!(cfg.initial_epoch, 42);
    }

    // BRV2_10: enqueue_circuit_build works after launch.
    #[test]
    fn brv2_10_circuit_build_after_launch() {
        let mut l = launcher(10);
        let mut h = l.launch().unwrap();
        let enqueued =
            h.rt.enqueue_circuit_build(vec![nid(20), nid(21), nid(22)], 999);
        assert!(enqueued);
        h.tick(1);
        assert_eq!(h.rt.build_driver().in_flight_count(), 1);
    }
}
