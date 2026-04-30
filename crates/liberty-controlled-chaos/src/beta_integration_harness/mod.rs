//! Beta integration harness — end-to-end test scaffold for Sprint 101-120 modules.
//!
//! Composes BetaNetworkSimulator, MeshHealthRuntime, CircuitRateLimiter, and
//! PeerBanList into scenario-driven integration tests.

use crate::beta_network_simulator::BetaNetworkSimulator;
use crate::circuit_rate_limiter::{BucketConfig, CircuitRateLimiter};
use crate::mesh_health_runtime::MeshHealthRuntime;
use crate::peer_ban_list::PeerBanList;

// ---------------------------------------------------------------------------
// BetaIntegrationHarness
// ---------------------------------------------------------------------------

pub struct BetaIntegrationHarness {
    pub sim: BetaNetworkSimulator,
    pub health: MeshHealthRuntime,
    pub rate_limiter: CircuitRateLimiter,
    pub ban_list: PeerBanList,
    pub epoch: u64,
}

impl BetaIntegrationHarness {
    pub fn new(sim_seed: u64) -> Self {
        Self {
            sim: BetaNetworkSimulator::new(sim_seed),
            health: MeshHealthRuntime::new(3, 6, 20),
            rate_limiter: CircuitRateLimiter::new(BucketConfig::default()),
            ban_list: PeerBanList::new(),
            epoch: 0,
        }
    }

    /// Register a node in the simulator and health runtime.
    pub fn add_node(&mut self, node_id: [u8; 32]) {
        self.sim.add_node(node_id);
        self.health.register_node(node_id);
    }

    /// Advance epoch: tick the simulator, refill rate limits, apply staleness.
    pub fn tick(&mut self) {
        self.epoch += 1;
        self.sim.tick(self.epoch);
        self.rate_limiter.tick_epoch();
        self.health.apply_staleness(self.epoch);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beta_network_simulator::LinkConfig;
    use crate::mesh_health_runtime::HealthStatus;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn harness() -> BetaIntegrationHarness {
        BetaIntegrationHarness::new(0xCAFE)
    }

    // BIH1: nodes registered in both sim and health runtime.
    #[test]
    fn bih1_node_registration() {
        let mut h = harness();
        h.add_node(nid(1));
        h.add_node(nid(2));
        assert_eq!(h.sim.node(&nid(1)).unwrap().online, true);
        assert_eq!(h.health.status(&nid(1)), Some(HealthStatus::Healthy));
    }

    // BIH2: packet delivered through sim after tick.
    #[test]
    fn bih2_packet_delivery() {
        let mut h = harness();
        h.add_node(nid(1));
        h.add_node(nid(2));
        h.sim.set_link(
            nid(1),
            nid(2),
            LinkConfig {
                latency_epochs: 1,
                drop_pct: 0,
                bw_limit: 0,
            },
        );
        h.sim.send(nid(1), nid(2), b"data".to_vec());
        h.tick();
        assert_eq!(h.sim.total_delivered(), 1);
    }

    // BIH3: ban list integration.
    #[test]
    fn bih3_ban_list() {
        let mut h = harness();
        h.ban_list.ban(nid(1), "bad actor".into(), 0, None).unwrap();
        assert!(h.ban_list.is_banned(&nid(1), h.epoch));
    }

    // BIH4: rate limiter integration.
    #[test]
    fn bih4_rate_limiter() {
        let mut h = harness();
        h.rate_limiter.register_circuit(1);
        assert!(h.rate_limiter.try_consume(1, 100).is_ok());
    }

    // BIH5: health failures accumulate.
    #[test]
    fn bih5_health_failures() {
        let mut h = harness();
        h.add_node(nid(1));
        for i in 0..3 {
            h.health.record_failure(nid(1), i);
        }
        assert_eq!(h.health.status(&nid(1)), Some(HealthStatus::Degraded));
    }

    // BIH6: tick advances epoch.
    #[test]
    fn bih6_tick_epoch() {
        let mut h = harness();
        h.tick();
        assert_eq!(h.epoch, 1);
    }

    // BIH7: sim offline node prevents delivery.
    #[test]
    fn bih7_offline_node() {
        let mut h = harness();
        h.add_node(nid(1));
        h.add_node(nid(2));
        h.sim.set_online(&nid(2), false);
        let sent = h.sim.send(nid(1), nid(2), b"x".to_vec());
        assert!(!sent);
    }

    // BIH8: stale node marked Unreachable after window.
    #[test]
    fn bih8_staleness() {
        let mut h = harness();
        h.add_node(nid(1));
        h.health.record_success(nid(1), 0);
        for _ in 0..25 {
            h.tick();
        }
        assert_eq!(h.health.status(&nid(1)), Some(HealthStatus::Unreachable));
    }

    // BIH9: rate limiter refills on tick.
    #[test]
    fn bih9_rate_refill() {
        let mut h = harness();
        h.rate_limiter.register_circuit(1);
        h.rate_limiter.try_consume(1, 65536).unwrap();
        h.tick();
        assert!(h.rate_limiter.available_tokens(1).unwrap() > 0);
    }

    // BIH10: ban list expiry check.
    #[test]
    fn bih10_ban_expiry() {
        let mut h = harness();
        h.ban_list.ban(nid(5), "temp".into(), 0, Some(5)).unwrap();
        assert!(h.ban_list.is_banned(&nid(5), 4));
        assert!(!h.ban_list.is_banned(&nid(5), 5));
    }
}
