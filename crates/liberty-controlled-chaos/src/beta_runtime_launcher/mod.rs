//! Beta runtime launcher — composes the beta mesh stack into a single launchable unit.
//!
//! Assembles `MeshNodeRuntime`, `PeerHandshakeRuntime`, `BetaBootstrapper`,
//! `MeshDirectoryService`, `MeshHealthRuntime`, and `LiveCircuitBuildProtocol`
//! behind one lifecycle object.

use crate::beta_node_bootstrap::{BetaBootstrapper, BootstrapConfig, BootstrapResult};
use crate::live_circuit_build_protocol::LiveCircuitBuildProtocol;
use crate::mesh_directory_service::MeshDirectoryService;
use crate::mesh_health_runtime::MeshHealthRuntime;
use crate::mesh_node_runtime::{MeshNodeRuntime, NodePhase, NodeRuntimeError};
use crate::peer_handshake_runtime::PeerHandshakeRuntime;
use crate::resource_guard::ResourceBudget;
use crate::secure_bootstrap::BootstrapSeed;

// ---------------------------------------------------------------------------
// LauncherPhase
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LauncherPhase {
    Bootstrapping,
    Running,
    Stopped,
}

// ---------------------------------------------------------------------------
// LauncherError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LauncherError {
    Bootstrap(String),
    Runtime(NodeRuntimeError),
    AlreadyRunning,
    NotRunning,
    AlreadyStopped,
}

impl From<NodeRuntimeError> for LauncherError {
    fn from(e: NodeRuntimeError) -> Self {
        LauncherError::Runtime(e)
    }
}

// ---------------------------------------------------------------------------
// BetaRuntimeLauncher
// ---------------------------------------------------------------------------

pub struct BetaRuntimeLauncher {
    pub node_id: [u8; 32],
    phase: LauncherPhase,
    epoch: u64,
    pub node_runtime: MeshNodeRuntime,
    pub handshake_rt: PeerHandshakeRuntime,
    pub directory: MeshDirectoryService,
    pub health: MeshHealthRuntime,
    pub circuit_builder: LiveCircuitBuildProtocol,
    bootstrap_result: Option<BootstrapResult>,
}

impl BetaRuntimeLauncher {
    pub fn new(
        node_id: [u8; 32],
        budget: ResourceBudget,
        bootstrap_config: BootstrapConfig,
    ) -> Self {
        let required_seeds = bootstrap_config.required_seeds;
        let _ = required_seeds;
        Self {
            node_id,
            phase: LauncherPhase::Bootstrapping,
            epoch: 0,
            node_runtime: MeshNodeRuntime::new(node_id, budget),
            handshake_rt: PeerHandshakeRuntime::new(node_id, 5, 1000),
            directory: MeshDirectoryService::new(512, 10),
            health: MeshHealthRuntime::new(2, 5, 50),
            circuit_builder: LiveCircuitBuildProtocol::new(),
            bootstrap_result: None,
        }
    }

    /// Accept seed peers. Delegates to internal `BetaBootstrapper`.
    pub fn bootstrap_from_seeds(
        &mut self,
        seeds: Vec<BootstrapSeed>,
        local_epoch: u64,
        required_seeds: usize,
    ) -> Result<BootstrapResult, LauncherError> {
        let cfg = BootstrapConfig {
            local_epoch,
            max_epoch_skew: 5,
            required_seeds,
        };
        let mut bootstrapper = BetaBootstrapper::new(cfg);
        for seed in seeds {
            bootstrapper
                .accept_seed(seed)
                .map_err(|e| LauncherError::Bootstrap(format!("{e:?}")))?;
        }
        let result = bootstrapper
            .finish()
            .map_err(|e| LauncherError::Bootstrap(format!("{e:?}")))?;
        for &peer_id in &result.verified_peers {
            self.directory.register_node_id(peer_id);
            self.health.register_node(peer_id);
        }
        self.bootstrap_result = Some(result.clone());
        Ok(result)
    }

    /// Transition from Bootstrapping → Running.
    pub fn start(&mut self) -> Result<(), LauncherError> {
        if self.phase == LauncherPhase::Running {
            return Err(LauncherError::AlreadyRunning);
        }
        if self.phase == LauncherPhase::Stopped {
            return Err(LauncherError::AlreadyStopped);
        }
        self.node_runtime.start().map_err(LauncherError::from)?;
        self.phase = LauncherPhase::Running;
        Ok(())
    }

    pub fn stop(&mut self) -> Result<(), LauncherError> {
        if self.phase == LauncherPhase::Stopped {
            return Err(LauncherError::AlreadyStopped);
        }
        self.node_runtime.stop().map_err(LauncherError::from)?;
        self.phase = LauncherPhase::Stopped;
        Ok(())
    }

    pub fn tick(&mut self, epoch: u64) {
        self.epoch = epoch;
        self.node_runtime.tick(epoch);
        self.health.apply_staleness(epoch);
    }

    pub fn phase(&self) -> LauncherPhase {
        self.phase
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn node_phase(&self) -> NodePhase {
        self.node_runtime.phase()
    }

    pub fn bootstrap_result(&self) -> Option<&BootstrapResult> {
        self.bootstrap_result.as_ref()
    }
}

// ---------------------------------------------------------------------------
// MeshDirectoryService extension — register by node_id only
// ---------------------------------------------------------------------------

impl MeshDirectoryService {
    pub fn register_node_id(&mut self, node_id: [u8; 32]) {
        use crate::mesh_directory_service::NodeDescriptor;
        let desc = NodeDescriptor {
            node_id,
            address: String::new(),
            epoch: 0,
            tags: Vec::new(),
        };
        let _ = self.insert(desc, 0);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_guard::ResourceBudget;
    use crate::secure_bootstrap::BootstrapSeed;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn seed(b: u8, addr: &str, nonce: u64, epoch: u64) -> BootstrapSeed {
        BootstrapSeed {
            node_id: nid(b),
            address: addr.to_string(),
            nonce,
            epoch,
        }
    }

    fn launcher() -> BetaRuntimeLauncher {
        let cfg = BootstrapConfig::default();
        BetaRuntimeLauncher::new(nid(1), ResourceBudget::default(), cfg)
    }

    // BRL1: initial phase is Bootstrapping.
    #[test]
    fn brl1_initial_phase() {
        let l = launcher();
        assert_eq!(l.phase(), LauncherPhase::Bootstrapping);
    }

    // BRL2: start without bootstrap transitions to Running.
    #[test]
    fn brl2_start() {
        let mut l = launcher();
        l.start().unwrap();
        assert_eq!(l.phase(), LauncherPhase::Running);
        assert_eq!(l.node_phase(), NodePhase::Running);
    }

    // BRL3: double start returns AlreadyRunning.
    #[test]
    fn brl3_double_start() {
        let mut l = launcher();
        l.start().unwrap();
        assert_eq!(l.start(), Err(LauncherError::AlreadyRunning));
    }

    // BRL4: stop transitions to Stopped.
    #[test]
    fn brl4_stop() {
        let mut l = launcher();
        l.start().unwrap();
        l.stop().unwrap();
        assert_eq!(l.phase(), LauncherPhase::Stopped);
    }

    // BRL5: double stop returns AlreadyStopped.
    #[test]
    fn brl5_double_stop() {
        let mut l = launcher();
        l.start().unwrap();
        l.stop().unwrap();
        assert_eq!(l.stop(), Err(LauncherError::AlreadyStopped));
    }

    // BRL6: tick advances epoch.
    #[test]
    fn brl6_tick_epoch() {
        let mut l = launcher();
        l.start().unwrap();
        l.tick(7);
        assert_eq!(l.epoch(), 7);
    }

    // BRL7: bootstrap_from_seeds with two valid seeds returns BootstrapResult.
    #[test]
    fn brl7_bootstrap_seeds() {
        let mut l = launcher();
        let seeds = vec![
            seed(2, "127.0.0.1:9001", 1, 0),
            seed(3, "127.0.0.1:9002", 2, 0),
        ];
        let result = l.bootstrap_from_seeds(seeds, 0, 2).unwrap();
        assert_eq!(result.verified_peers.len(), 2);
    }

    // BRL8: bootstrap_result is stored after successful bootstrap.
    #[test]
    fn brl8_bootstrap_result_stored() {
        let mut l = launcher();
        let seeds = vec![seed(2, "127.0.0.1:9001", 1, 0)];
        l.bootstrap_from_seeds(seeds, 0, 1).unwrap();
        assert!(l.bootstrap_result().is_some());
    }

    // BRL9: bootstrap_from_seeds with not enough seeds returns error.
    #[test]
    fn brl9_bootstrap_not_enough() {
        let mut l = launcher();
        let seeds = vec![seed(2, "127.0.0.1:9001", 1, 0)];
        assert!(l.bootstrap_from_seeds(seeds, 0, 2).is_err());
    }

    // BRL10: node_runtime accessible after start.
    #[test]
    fn brl10_node_runtime_accessible() {
        let mut l = launcher();
        l.start().unwrap();
        assert_eq!(l.node_runtime.phase(), NodePhase::Running);
    }
}
