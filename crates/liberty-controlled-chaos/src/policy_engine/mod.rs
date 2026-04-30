//! Policy engine — enforces runtime rules for circuit builds, peer admission,
//! traffic class gating, and privacy mode restrictions.
//!
//! `PolicyEngine` evaluates `PolicyRequest`s against a set of `PolicyRule`s.
//! Rules are evaluated in order; the first matching rule wins.

// ---------------------------------------------------------------------------
// TrafficClass
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrafficClass {
    Normal,
    Priority,
    Cover,
    Management,
}

// ---------------------------------------------------------------------------
// PolicyAction
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
    Quarantine,
}

// ---------------------------------------------------------------------------
// PolicyRequest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum PolicyRequest {
    CircuitBuild {
        guard: [u8; 32],
        relay: [u8; 32],
        exit: [u8; 32],
    },
    PeerAdmission {
        node_id: [u8; 32],
        trust_score: f64,
    },
    TrafficSend {
        circuit_id: u64,
        class: TrafficClass,
    },
    PrivacyModeChange {
        new_mode: u8,
    },
}

// ---------------------------------------------------------------------------
// PolicyRule
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub name: String,
    pub action: PolicyAction,
    /// Minimum trust score for PeerAdmission (0 = no requirement).
    pub min_trust: f64,
    /// Denied traffic classes.
    pub denied_classes: Vec<TrafficClass>,
    /// Max allowed privacy mode value (0 = no limit).
    pub max_privacy_mode: u8,
}

impl PolicyRule {
    pub fn allow_all() -> Self {
        Self {
            name: "allow-all".into(),
            action: PolicyAction::Allow,
            min_trust: 0.0,
            denied_classes: Vec::new(),
            max_privacy_mode: 0,
        }
    }

    pub fn deny_low_trust(threshold: f64) -> Self {
        Self {
            name: "deny-low-trust".into(),
            action: PolicyAction::Deny,
            min_trust: threshold,
            denied_classes: Vec::new(),
            max_privacy_mode: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// PolicyEngine
// ---------------------------------------------------------------------------

pub struct PolicyEngine {
    rules: Vec<PolicyRule>,
    decisions: u64,
    denials: u64,
}

impl PolicyEngine {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            decisions: 0,
            denials: 0,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
    }

    /// Evaluate a request.  Returns `Allow` if no rules deny it.
    pub fn evaluate(&mut self, req: &PolicyRequest) -> PolicyAction {
        self.decisions += 1;
        for rule in &self.rules {
            let action = self.match_rule(rule, req);
            if action != PolicyAction::Allow {
                self.denials += 1;
                return action;
            }
        }
        PolicyAction::Allow
    }

    fn match_rule(&self, rule: &PolicyRule, req: &PolicyRequest) -> PolicyAction {
        match req {
            PolicyRequest::PeerAdmission { trust_score, .. } => {
                if rule.action == PolicyAction::Deny && *trust_score < rule.min_trust {
                    return PolicyAction::Deny;
                }
            }
            PolicyRequest::TrafficSend { class, .. } => {
                if rule.denied_classes.contains(class) {
                    return rule.action;
                }
            }
            PolicyRequest::PrivacyModeChange { new_mode } => {
                if rule.max_privacy_mode > 0 && *new_mode > rule.max_privacy_mode {
                    return PolicyAction::Deny;
                }
            }
            PolicyRequest::CircuitBuild { .. } => {}
        }
        PolicyAction::Allow
    }

    pub fn decisions(&self) -> u64 {
        self.decisions
    }

    pub fn denials(&self) -> u64 {
        self.denials
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
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

    // PE1: no rules → allow all.
    #[test]
    fn pe1_no_rules_allow() {
        let mut e = PolicyEngine::new();
        let result = e.evaluate(&PolicyRequest::CircuitBuild {
            guard: nid(1),
            relay: nid(2),
            exit: nid(3),
        });
        assert_eq!(result, PolicyAction::Allow);
    }

    // PE2: deny rule blocks low-trust peer.
    #[test]
    fn pe2_deny_low_trust() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule::deny_low_trust(0.5));
        let result = e.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(1),
            trust_score: 0.3,
        });
        assert_eq!(result, PolicyAction::Deny);
    }

    // PE3: allow high-trust peer past deny rule.
    #[test]
    fn pe3_allow_high_trust() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule::deny_low_trust(0.5));
        let result = e.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(1),
            trust_score: 0.8,
        });
        assert_eq!(result, PolicyAction::Allow);
    }

    // PE4: denied traffic class is blocked.
    #[test]
    fn pe4_traffic_class_denied() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule {
            name: "no-priority".into(),
            action: PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![TrafficClass::Priority],
            max_privacy_mode: 0,
        });
        let result = e.evaluate(&PolicyRequest::TrafficSend {
            circuit_id: 1,
            class: TrafficClass::Priority,
        });
        assert_eq!(result, PolicyAction::Deny);
    }

    // PE5: allowed traffic class passes.
    #[test]
    fn pe5_traffic_class_allowed() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule {
            name: "no-priority".into(),
            action: PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![TrafficClass::Priority],
            max_privacy_mode: 0,
        });
        let result = e.evaluate(&PolicyRequest::TrafficSend {
            circuit_id: 1,
            class: TrafficClass::Normal,
        });
        assert_eq!(result, PolicyAction::Allow);
    }

    // PE6: privacy mode change above max is denied.
    #[test]
    fn pe6_privacy_mode_capped() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule {
            name: "cap-mode".into(),
            action: PolicyAction::Deny,
            min_trust: 0.0,
            denied_classes: vec![],
            max_privacy_mode: 2,
        });
        assert_eq!(
            e.evaluate(&PolicyRequest::PrivacyModeChange { new_mode: 3 }),
            PolicyAction::Deny
        );
        assert_eq!(
            e.evaluate(&PolicyRequest::PrivacyModeChange { new_mode: 2 }),
            PolicyAction::Allow
        );
    }

    // PE7: decisions counter increments.
    #[test]
    fn pe7_decisions_counter() {
        let mut e = PolicyEngine::new();
        e.evaluate(&PolicyRequest::CircuitBuild {
            guard: nid(1),
            relay: nid(2),
            exit: nid(3),
        });
        e.evaluate(&PolicyRequest::CircuitBuild {
            guard: nid(1),
            relay: nid(2),
            exit: nid(3),
        });
        assert_eq!(e.decisions(), 2);
    }

    // PE8: denials counter only counts denied requests.
    #[test]
    fn pe8_denials_counter() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule::deny_low_trust(0.5));
        e.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(1),
            trust_score: 0.1,
        });
        e.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(2),
            trust_score: 0.9,
        });
        assert_eq!(e.denials(), 1);
    }

    // PE9: first matching deny rule wins.
    #[test]
    fn pe9_first_matching_wins() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule::deny_low_trust(0.8));
        e.add_rule(PolicyRule::allow_all());
        let r = e.evaluate(&PolicyRequest::PeerAdmission {
            node_id: nid(1),
            trust_score: 0.5,
        });
        assert_eq!(r, PolicyAction::Deny);
    }

    // PE10: rule_count reflects added rules.
    #[test]
    fn pe10_rule_count() {
        let mut e = PolicyEngine::new();
        e.add_rule(PolicyRule::allow_all());
        e.add_rule(PolicyRule::deny_low_trust(0.5));
        assert_eq!(e.rule_count(), 2);
    }
}
