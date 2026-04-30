//! Network policy enforcer — applies rules to allow/deny network operations.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyAction {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyTarget {
    Circuit,
    Stream,
    Peer,
}

#[derive(Debug, Clone)]
pub struct PolicyRule {
    pub target: PolicyTarget,
    pub pattern: [u8; 4],
    pub action: PolicyAction,
    pub priority: u32,
}

pub struct NetworkPolicyEnforcer {
    rules: Vec<PolicyRule>,
    allow_count: u64,
    deny_count: u64,
    default_action: PolicyAction,
}

impl NetworkPolicyEnforcer {
    pub fn new(default_action: PolicyAction) -> Self {
        Self {
            rules: Vec::new(),
            allow_count: 0,
            deny_count: 0,
            default_action,
        }
    }

    pub fn add_rule(&mut self, rule: PolicyRule) {
        self.rules.push(rule);
        self.rules.sort_by_key(|r| std::cmp::Reverse(r.priority));
    }

    pub fn remove_rule(&mut self, pattern: &[u8; 4], target: PolicyTarget) {
        self.rules
            .retain(|r| !(r.pattern == *pattern && r.target == target));
    }

    pub fn evaluate(&mut self, target: PolicyTarget, pattern: [u8; 4]) -> PolicyAction {
        let action = self
            .rules
            .iter()
            .find(|r| r.target == target && r.pattern == pattern)
            .map(|r| r.action)
            .unwrap_or(self.default_action);
        match action {
            PolicyAction::Allow => self.allow_count += 1,
            PolicyAction::Deny => self.deny_count += 1,
        }
        action
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
    pub fn allow_count(&self) -> u64 {
        self.allow_count
    }
    pub fn deny_count(&self) -> u64 {
        self.deny_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(b: u8) -> [u8; 4] {
        [b; 4]
    }

    fn rule(pattern: u8, target: PolicyTarget, action: PolicyAction, priority: u32) -> PolicyRule {
        PolicyRule {
            target,
            pattern: pat(pattern),
            action,
            priority,
        }
    }

    // NPE1: matching allow rule allows.
    #[test]
    fn npe1_allow_rule() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Deny);
        e.add_rule(rule(1, PolicyTarget::Circuit, PolicyAction::Allow, 10));
        assert_eq!(
            e.evaluate(PolicyTarget::Circuit, pat(1)),
            PolicyAction::Allow
        );
    }

    // NPE2: matching deny rule denies.
    #[test]
    fn npe2_deny_rule() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        e.add_rule(rule(1, PolicyTarget::Peer, PolicyAction::Deny, 10));
        assert_eq!(e.evaluate(PolicyTarget::Peer, pat(1)), PolicyAction::Deny);
    }

    // NPE3: no matching rule uses default.
    #[test]
    fn npe3_default_action() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        assert_eq!(
            e.evaluate(PolicyTarget::Stream, pat(1)),
            PolicyAction::Allow
        );
    }

    // NPE4: higher priority rule wins.
    #[test]
    fn npe4_priority() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Deny);
        e.add_rule(rule(1, PolicyTarget::Circuit, PolicyAction::Deny, 5));
        e.add_rule(rule(1, PolicyTarget::Circuit, PolicyAction::Allow, 10));
        assert_eq!(
            e.evaluate(PolicyTarget::Circuit, pat(1)),
            PolicyAction::Allow
        );
    }

    // NPE5: allow_count increments.
    #[test]
    fn npe5_allow_count() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        e.evaluate(PolicyTarget::Circuit, pat(1));
        e.evaluate(PolicyTarget::Circuit, pat(2));
        assert_eq!(e.allow_count(), 2);
    }

    // NPE6: deny_count increments.
    #[test]
    fn npe6_deny_count() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Deny);
        e.evaluate(PolicyTarget::Peer, pat(1));
        assert_eq!(e.deny_count(), 1);
    }

    // NPE7: remove_rule clears matching rules.
    #[test]
    fn npe7_remove_rule() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        e.add_rule(rule(1, PolicyTarget::Circuit, PolicyAction::Deny, 10));
        e.remove_rule(&pat(1), PolicyTarget::Circuit);
        assert_eq!(e.rule_count(), 0);
    }

    // NPE8: different targets don't interfere.
    #[test]
    fn npe8_target_separation() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        e.add_rule(rule(1, PolicyTarget::Peer, PolicyAction::Deny, 10));
        assert_eq!(
            e.evaluate(PolicyTarget::Circuit, pat(1)),
            PolicyAction::Allow
        );
    }

    // NPE9: rule_count correct.
    #[test]
    fn npe9_rule_count() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Allow);
        e.add_rule(rule(1, PolicyTarget::Circuit, PolicyAction::Deny, 1));
        e.add_rule(rule(2, PolicyTarget::Peer, PolicyAction::Allow, 1));
        assert_eq!(e.rule_count(), 2);
    }

    // NPE10: default deny with no rules denies all.
    #[test]
    fn npe10_default_deny_all() {
        let mut e = NetworkPolicyEnforcer::new(PolicyAction::Deny);
        assert_eq!(
            e.evaluate(PolicyTarget::Circuit, pat(99)),
            PolicyAction::Deny
        );
        assert_eq!(
            e.evaluate(PolicyTarget::Stream, pat(99)),
            PolicyAction::Deny
        );
    }
}
