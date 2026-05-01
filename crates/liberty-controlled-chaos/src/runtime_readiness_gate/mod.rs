//! Runtime readiness gate — evaluates whether a node stack is ready to enter
//! Running state.
//!
//! `RuntimeReadinessGate::evaluate()` inspects:
//! - `NodeConfig` — validates essential configuration (node_id, listen address).
//! - `NodeCapabilityRegistry` — verifies the local node has required capabilities.
//! - `MeshDirectoryService` — checks that at least one directory peer is known.
//! - `PeerConnectionPool` — confirms there is at least one active connection.
//!
//! Returns a `ReadinessReport` built with the `ReadinessReportBuilder`.

use crate::mesh_directory_service::MeshDirectoryService;
use crate::node_capability_registry::{Capability, CapabilitySet, NodeCapabilityRegistry};
use crate::node_config::NodeConfig;
use crate::peer_connection_pool::PeerConnectionPool;
use crate::readiness_report::{ReadinessReport, ReadinessReportBuilder};

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Tunable thresholds for readiness checks.
#[derive(Debug, Clone)]
pub struct GateConfig {
    /// Minimum number of active peer connections required.
    pub min_active_connections: usize,
    /// Minimum number of known directory entries required.
    pub min_directory_entries: usize,
    /// Required local capabilities (set by the operator).
    pub required_capabilities: CapabilitySet,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_active_connections: 1,
            min_directory_entries: 1,
            required_capabilities: CapabilitySet::empty()
                .with(Capability::OnionRelay)
                .with(Capability::CircuitExtend),
        }
    }
}

// ---------------------------------------------------------------------------
// RuntimeReadinessGate
// ---------------------------------------------------------------------------

pub struct RuntimeReadinessGate {
    config: GateConfig,
    caps: NodeCapabilityRegistry,
    directory: MeshDirectoryService,
    pool: PeerConnectionPool,
    evaluations: u64,
}

impl RuntimeReadinessGate {
    pub fn new(config: GateConfig) -> Self {
        Self {
            config,
            caps: NodeCapabilityRegistry::new(),
            directory: MeshDirectoryService::new(256, 10),
            pool: PeerConnectionPool::new(64),
            evaluations: 0,
        }
    }

    // -----------------------------------------------------------------------
    // Population helpers
    // -----------------------------------------------------------------------

    /// Register local node capabilities.
    pub fn register_local_caps(&mut self, node_id: [u8; 32], caps: CapabilitySet) {
        self.caps.register(node_id, caps);
    }

    /// Expose mutable access to the directory service for pre-population.
    pub fn directory_mut(&mut self) -> &mut MeshDirectoryService {
        &mut self.directory
    }

    /// Expose mutable access to the connection pool for pre-population.
    pub fn pool_mut(&mut self) -> &mut PeerConnectionPool {
        &mut self.pool
    }

    // -----------------------------------------------------------------------
    // Core evaluation
    // -----------------------------------------------------------------------

    /// Evaluate readiness and return a `ReadinessReport`.
    pub fn evaluate(&mut self, node_config: &NodeConfig, epoch: u64) -> ReadinessReport {
        self.evaluations += 1;
        let mut builder = ReadinessReportBuilder::new(epoch);

        // --- Module: node_config ---
        builder.add_module("node_config");
        if node_config.node_id == [0u8; 32] {
            builder.add_blocker("node_config", "node_id is all-zeros (unset)");
        }
        if node_config.listen_address.is_empty() {
            builder.add_warning("node_config", "listen_address not configured");
        }

        // --- Module: node_capability_registry ---
        builder.add_module("node_capability_registry");
        if !self
            .caps
            .capabilities(&node_config.node_id)
            .map(|c| c.satisfies(self.config.required_capabilities))
            .unwrap_or(false)
        {
            builder.add_blocker(
                "node_capability_registry",
                "local node missing required capabilities",
            );
        }

        // --- Module: mesh_directory_service ---
        builder.add_module("mesh_directory_service");
        if self.directory.entry_count() < self.config.min_directory_entries {
            builder.add_blocker(
                "mesh_directory_service",
                "insufficient directory entries — cannot discover peers",
            );
        }

        // --- Module: peer_connection_pool ---
        builder.add_module("peer_connection_pool");
        let active = self.pool.active_connections().len();
        if active < self.config.min_active_connections {
            builder.add_blocker("peer_connection_pool", "no active peer connections");
        }

        builder.set_test_count(self.evaluations as u32);
        builder.build()
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    pub fn evaluations(&self) -> u64 {
        self.evaluations
    }

    pub fn caps(&self) -> &NodeCapabilityRegistry {
        &self.caps
    }

    pub fn directory(&self) -> &MeshDirectoryService {
        &self.directory
    }

    pub fn pool(&self) -> &PeerConnectionPool {
        &self.pool
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh_directory_service::NodeDescriptor;
    use crate::node_config::NodeConfig;
    use crate::readiness_report::ReadinessLevel;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn full_caps() -> CapabilitySet {
        CapabilitySet::empty()
            .with(Capability::OnionRelay)
            .with(Capability::CircuitExtend)
    }

    fn make_gate() -> RuntimeReadinessGate {
        RuntimeReadinessGate::new(GateConfig::default())
    }

    fn make_config(id: u8) -> NodeConfig {
        NodeConfig::new(nid(id)).with_listen_address("127.0.0.1:9000".into())
    }

    // RRG1: all blockers present → NotReady.
    #[test]
    fn rrg1_empty_gate_not_ready() {
        let mut gate = make_gate();
        let cfg = make_config(1);
        let report = gate.evaluate(&cfg, 1);
        assert_eq!(report.level, ReadinessLevel::NotReady);
        assert!(!report.blockers().is_empty());
    }

    // RRG2: fully configured node → Ready.
    #[test]
    fn rrg2_fully_configured_ready() {
        let mut gate = make_gate();
        let cfg = make_config(5);

        // Register capabilities.
        gate.register_local_caps(nid(5), full_caps());

        // Insert directory entry.
        gate.directory_mut()
            .insert(
                NodeDescriptor {
                    node_id: nid(10),
                    address: "127.0.0.1:9001".into(),
                    epoch: 1,
                    tags: Vec::new(),
                },
                1,
            )
            .unwrap();

        // Add active connection.
        gate.pool_mut().connect(nid(10), 1).unwrap();
        gate.pool_mut().activate(&nid(10)).unwrap();

        let report = gate.evaluate(&cfg, 1);
        assert_eq!(report.level, ReadinessLevel::Ready);
        assert!(report.blockers().is_empty());
    }

    // RRG3: missing capability → blocker.
    #[test]
    fn rrg3_missing_capability_blocks() {
        let mut gate = make_gate();
        let cfg = make_config(2);

        // Only partial capabilities (missing CircuitExtend).
        gate.register_local_caps(nid(2), CapabilitySet::empty().with(Capability::OnionRelay));
        gate.directory_mut()
            .insert(
                NodeDescriptor {
                    node_id: nid(20),
                    address: "127.0.0.1:9002".into(),
                    epoch: 1,
                    tags: Vec::new(),
                },
                1,
            )
            .unwrap();
        gate.pool_mut().connect(nid(20), 1).unwrap();
        gate.pool_mut().activate(&nid(20)).unwrap();

        let report = gate.evaluate(&cfg, 1);
        assert_eq!(report.level, ReadinessLevel::NotReady);
        assert!(
            report
                .blockers()
                .iter()
                .any(|b| b.module == "node_capability_registry")
        );
    }

    // RRG4: no directory entries → blocker.
    #[test]
    fn rrg4_no_directory_entries_blocks() {
        let mut gate = make_gate();
        let cfg = make_config(3);

        gate.register_local_caps(nid(3), full_caps());
        gate.pool_mut().connect(nid(30), 1).unwrap();
        gate.pool_mut().activate(&nid(30)).unwrap();

        let report = gate.evaluate(&cfg, 1);
        assert!(
            report
                .blockers()
                .iter()
                .any(|b| b.module == "mesh_directory_service")
        );
    }

    // RRG5: no active connections → blocker.
    #[test]
    fn rrg5_no_active_connections_blocks() {
        let mut gate = make_gate();
        let cfg = make_config(4);

        gate.register_local_caps(nid(4), full_caps());
        gate.directory_mut()
            .insert(
                NodeDescriptor {
                    node_id: nid(40),
                    address: "127.0.0.1:9003".into(),
                    epoch: 1,
                    tags: Vec::new(),
                },
                1,
            )
            .unwrap();
        // No pool.connect/activate call.

        let report = gate.evaluate(&cfg, 1);
        assert!(
            report
                .blockers()
                .iter()
                .any(|b| b.module == "peer_connection_pool")
        );
    }

    // RRG6: empty listen_address → warning, not blocker.
    #[test]
    fn rrg6_missing_listen_address_is_warning() {
        let mut gate = make_gate();
        let cfg = NodeConfig::new(nid(6)).with_listen_address("".into());

        gate.register_local_caps(nid(6), full_caps());
        gate.directory_mut()
            .insert(
                NodeDescriptor {
                    node_id: nid(60),
                    address: "127.0.0.1:9004".into(),
                    epoch: 1,
                    tags: Vec::new(),
                },
                1,
            )
            .unwrap();
        gate.pool_mut().connect(nid(60), 1).unwrap();
        gate.pool_mut().activate(&nid(60)).unwrap();

        let report = gate.evaluate(&cfg, 1);
        // Warning about listen_address, but no blockers.
        assert_eq!(report.level, ReadinessLevel::ReadyWithWarnings);
        assert!(!report.warnings().is_empty());
    }

    // RRG7: zero node_id → blocker.
    #[test]
    fn rrg7_zero_node_id_blocks() {
        let mut gate = make_gate();
        let cfg = NodeConfig::new([0u8; 32]).with_listen_address("127.0.0.1:9005".into());

        gate.register_local_caps([0u8; 32], full_caps());
        gate.directory_mut()
            .insert(
                NodeDescriptor {
                    node_id: nid(70),
                    address: "127.0.0.1:9005".into(),
                    epoch: 1,
                    tags: Vec::new(),
                },
                1,
            )
            .unwrap();
        gate.pool_mut().connect(nid(70), 1).unwrap();
        gate.pool_mut().activate(&nid(70)).unwrap();

        let report = gate.evaluate(&cfg, 1);
        assert!(report.blockers().iter().any(|b| b.module == "node_config"));
    }

    // RRG8: evaluation counter increments per call.
    #[test]
    fn rrg8_evaluation_counter() {
        let mut gate = make_gate();
        let cfg = make_config(8);
        gate.evaluate(&cfg, 1);
        gate.evaluate(&cfg, 2);
        assert_eq!(gate.evaluations(), 2);
    }

    // RRG9: report lists all checked modules.
    #[test]
    fn rrg9_report_modules_listed() {
        let mut gate = make_gate();
        let cfg = make_config(9);
        let report = gate.evaluate(&cfg, 1);
        assert!(report.modules_checked.contains(&"node_config".to_string()));
        assert!(
            report
                .modules_checked
                .contains(&"node_capability_registry".to_string())
        );
        assert!(
            report
                .modules_checked
                .contains(&"mesh_directory_service".to_string())
        );
        assert!(
            report
                .modules_checked
                .contains(&"peer_connection_pool".to_string())
        );
    }

    // RRG10: custom gate config with zero min_connections → connection check skipped.
    #[test]
    fn rrg10_custom_config_no_connection_required() {
        let cfg_gate = GateConfig {
            min_active_connections: 0,
            min_directory_entries: 0,
            required_capabilities: CapabilitySet::empty(),
        };
        let mut gate = RuntimeReadinessGate::new(cfg_gate);
        let cfg = make_config(10);

        // Register node with empty caps so the registry lookup returns Some.
        gate.register_local_caps(nid(10), CapabilitySet::empty());

        let report = gate.evaluate(&cfg, 1);
        // No blockers (thresholds are all zero/empty).
        assert_eq!(report.level, ReadinessLevel::Ready);
    }
}
