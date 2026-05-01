//! Production gap register — structured catalog of known production gaps
//! that must be resolved before Beta launch.
//!
//! Each gap has a priority (Critical / High / Medium), an owner subsystem,
//! a description, and a status (Open / InProgress / Resolved).
//!
//! The register is queryable by priority and subsystem, enabling automated
//! readiness checks (e.g., "are all Critical gaps Resolved?").

// ---------------------------------------------------------------------------
// GapPriority
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapPriority {
    /// Must be resolved before any Beta deployment.
    Critical = 2,
    /// Should be resolved for Beta; may be deferred with justification.
    High = 1,
    /// Nice-to-have for Beta; can be deferred to v1.0.
    Medium = 0,
}

// ---------------------------------------------------------------------------
// GapStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GapStatus {
    Open,
    InProgress,
    Resolved,
}

// ---------------------------------------------------------------------------
// ProductionGap
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ProductionGap {
    pub id: &'static str,
    pub subsystem: &'static str,
    pub description: &'static str,
    pub priority: GapPriority,
    pub status: GapStatus,
}

// ---------------------------------------------------------------------------
// ProductionGapRegister
// ---------------------------------------------------------------------------

pub struct ProductionGapRegister {
    gaps: Vec<ProductionGap>,
}

impl Default for ProductionGapRegister {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductionGapRegister {
    pub fn new() -> Self {
        Self { gaps: Vec::new() }
    }

    /// Construct with the canonical Beta-blockers list.
    pub fn with_beta_gaps() -> Self {
        let mut r = Self::new();
        r.gaps = vec![
            ProductionGap {
                id: "CRYPTO-001",
                subsystem: "link_crypto",
                description: "HMAC-SHA256 only — no confidentiality; Noise XX not implemented",
                priority: GapPriority::Critical,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "EPOCH-001",
                subsystem: "epoch_clock",
                description: "Epoch clock is caller-provided; no monotonic OS-backed source",
                priority: GapPriority::High,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "CIRCUIT-001",
                subsystem: "circuit_build",
                description: "Circuit build protocol is driven manually; no auto-rebuild on failure",
                priority: GapPriority::High,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "COVER-001",
                subsystem: "cover_traffic",
                description: "Cover traffic not started automatically at bootstrap",
                priority: GapPriority::High,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "PERSIST-001",
                subsystem: "security_state",
                description: "SecurityStateStore not loaded on restart; no session persistence",
                priority: GapPriority::Critical,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "RESOURCE-001",
                subsystem: "resource_guard",
                description: "ResourceGuard enforces per-packet limits only; no total rate cap",
                priority: GapPriority::Medium,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "DIRECTORY-001",
                subsystem: "directory_client",
                description: "Directory bootstrap is manual; no seeded authority list",
                priority: GapPriority::High,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "VPN-001",
                subsystem: "android_vpn",
                description: "ShieldVpnService not wired to FFI; TUN fd not passed to Rust",
                priority: GapPriority::Critical,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "GOSSIP-001",
                subsystem: "node_discovery",
                description: "Peer discovery is static list only; no gossip protocol",
                priority: GapPriority::High,
                status: GapStatus::Open,
            },
            ProductionGap {
                id: "TEST-001",
                subsystem: "beta_integration",
                description: "No end-to-end integration test with real Android VPN service",
                priority: GapPriority::Critical,
                status: GapStatus::Open,
            },
        ];
        r
    }

    /// Add a gap to the register.
    pub fn add(&mut self, gap: ProductionGap) {
        self.gaps.push(gap);
    }

    /// Update the status of a gap by ID.  Returns true if found.
    pub fn update_status(&mut self, id: &str, status: GapStatus) -> bool {
        for g in &mut self.gaps {
            if g.id == id {
                g.status = status;
                return true;
            }
        }
        false
    }

    /// Returns all gaps.
    pub fn all(&self) -> &[ProductionGap] {
        &self.gaps
    }

    /// Returns gaps matching `priority`.
    pub fn by_priority(&self, priority: GapPriority) -> Vec<&ProductionGap> {
        self.gaps
            .iter()
            .filter(|g| g.priority == priority)
            .collect()
    }

    /// Returns gaps matching `subsystem`.
    pub fn by_subsystem(&self, subsystem: &str) -> Vec<&ProductionGap> {
        self.gaps
            .iter()
            .filter(|g| g.subsystem == subsystem)
            .collect()
    }

    /// Returns true if all `Critical` gaps are `Resolved`.
    pub fn all_critical_resolved(&self) -> bool {
        self.gaps
            .iter()
            .filter(|g| g.priority == GapPriority::Critical)
            .all(|g| g.status == GapStatus::Resolved)
    }

    /// Count gaps by status.
    pub fn count_by_status(&self, status: GapStatus) -> usize {
        self.gaps.iter().filter(|g| g.status == status).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // PGR1: beta gaps register has 10 entries.
    #[test]
    fn pgr1_ten_beta_gaps() {
        let r = ProductionGapRegister::with_beta_gaps();
        assert_eq!(r.all().len(), 10);
    }

    // PGR2: all beta gaps start as Open.
    #[test]
    fn pgr2_all_gaps_open() {
        let r = ProductionGapRegister::with_beta_gaps();
        assert_eq!(r.count_by_status(GapStatus::Open), 10);
        assert_eq!(r.count_by_status(GapStatus::Resolved), 0);
    }

    // PGR3: by_priority returns correct subset.
    #[test]
    fn pgr3_by_priority_critical() {
        let r = ProductionGapRegister::with_beta_gaps();
        let critical = r.by_priority(GapPriority::Critical);
        assert!(critical.len() >= 1);
        for g in &critical {
            assert_eq!(g.priority, GapPriority::Critical);
        }
    }

    // PGR4: all_critical_resolved returns false with open critical gaps.
    #[test]
    fn pgr4_critical_not_resolved() {
        let r = ProductionGapRegister::with_beta_gaps();
        assert!(!r.all_critical_resolved());
    }

    // PGR5: update_status changes a gap's status.
    #[test]
    fn pgr5_update_status() {
        let mut r = ProductionGapRegister::with_beta_gaps();
        assert!(r.update_status("CRYPTO-001", GapStatus::Resolved));
        let g = r.all().iter().find(|g| g.id == "CRYPTO-001").unwrap();
        assert_eq!(g.status, GapStatus::Resolved);
    }

    // PGR6: update_status on unknown id returns false.
    #[test]
    fn pgr6_update_unknown_returns_false() {
        let mut r = ProductionGapRegister::with_beta_gaps();
        assert!(!r.update_status("NONEXISTENT-999", GapStatus::Resolved));
    }

    // PGR7: all_critical_resolved returns true after resolving all critical gaps.
    #[test]
    fn pgr7_all_critical_resolved_after_update() {
        let mut r = ProductionGapRegister::with_beta_gaps();
        let critical_ids: Vec<&str> = r
            .by_priority(GapPriority::Critical)
            .iter()
            .map(|g| g.id)
            .collect();
        for id in critical_ids {
            r.update_status(id, GapStatus::Resolved);
        }
        assert!(r.all_critical_resolved());
    }

    // PGR8: by_subsystem returns correct gaps.
    #[test]
    fn pgr8_by_subsystem() {
        let r = ProductionGapRegister::with_beta_gaps();
        let vpn = r.by_subsystem("android_vpn");
        assert!(!vpn.is_empty());
        for g in &vpn {
            assert_eq!(g.subsystem, "android_vpn");
        }
    }

    // PGR9: add inserts a new gap.
    #[test]
    fn pgr9_add_gap() {
        let mut r = ProductionGapRegister::new();
        r.add(ProductionGap {
            id: "TEST-999",
            subsystem: "test",
            description: "test gap",
            priority: GapPriority::Medium,
            status: GapStatus::Open,
        });
        assert_eq!(r.all().len(), 1);
    }

    // PGR10: GapPriority ordering: Critical > High > Medium.
    #[test]
    fn pgr10_priority_ordering() {
        assert!(GapPriority::Critical > GapPriority::High);
        assert!(GapPriority::High > GapPriority::Medium);
    }
}
