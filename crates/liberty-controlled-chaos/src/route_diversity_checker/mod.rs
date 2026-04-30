//! Route diversity checker — validates that circuit paths meet diversity constraints.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiversityViolation {
    TooFewDistinctGroups,
    SameGroupConsecutive,
    ExcessiveGroupRepetition,
}

#[derive(Debug, Clone, Copy)]
pub struct DiversityConstraints {
    pub min_distinct_groups: usize,
    pub allow_consecutive_same_group: bool,
    pub max_group_repetitions: usize,
}

impl Default for DiversityConstraints {
    fn default() -> Self {
        Self {
            min_distinct_groups: 2,
            allow_consecutive_same_group: false,
            max_group_repetitions: 2,
        }
    }
}

pub struct RouteDiversityChecker {
    constraints: DiversityConstraints,
}

impl RouteDiversityChecker {
    pub fn new(constraints: DiversityConstraints) -> Self {
        Self { constraints }
    }

    pub fn check(&self, groups: &[u32]) -> Result<(), DiversityViolation> {
        if groups.is_empty() {
            return Ok(());
        }
        let distinct: std::collections::HashSet<u32> = groups.iter().copied().collect();
        if distinct.len() < self.constraints.min_distinct_groups {
            return Err(DiversityViolation::TooFewDistinctGroups);
        }
        if !self.constraints.allow_consecutive_same_group {
            for w in groups.windows(2) {
                if w[0] == w[1] {
                    return Err(DiversityViolation::SameGroupConsecutive);
                }
            }
        }
        let max_reps = self.constraints.max_group_repetitions;
        for &g in &distinct {
            let count = groups.iter().filter(|&&x| x == g).count();
            if count > max_reps {
                return Err(DiversityViolation::ExcessiveGroupRepetition);
            }
        }
        Ok(())
    }

    pub fn is_diverse(&self, groups: &[u32]) -> bool {
        self.check(groups).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_checker() -> RouteDiversityChecker {
        RouteDiversityChecker::new(DiversityConstraints::default())
    }

    // RDC1: diverse path passes.
    #[test]
    fn rdc1_diverse_ok() {
        let c = default_checker();
        assert!(c.is_diverse(&[1, 2, 3]));
    }

    // RDC2: single group fails distinct check.
    #[test]
    fn rdc2_single_group() {
        let c = default_checker();
        assert_eq!(
            c.check(&[1, 1, 1]),
            Err(DiversityViolation::TooFewDistinctGroups)
        );
    }

    // RDC3: consecutive same group fails.
    #[test]
    fn rdc3_consecutive_same() {
        let c = default_checker();
        assert_eq!(
            c.check(&[1, 2, 2, 3]),
            Err(DiversityViolation::SameGroupConsecutive)
        );
    }

    // RDC4: consecutive allowed when flag set.
    #[test]
    fn rdc4_consecutive_allowed() {
        let c = RouteDiversityChecker::new(DiversityConstraints {
            min_distinct_groups: 2,
            allow_consecutive_same_group: true,
            max_group_repetitions: 5,
        });
        assert!(c.is_diverse(&[1, 1, 2]));
    }

    // RDC5: excessive group repetition fails.
    #[test]
    fn rdc5_excessive_repetition() {
        let c = RouteDiversityChecker::new(DiversityConstraints {
            min_distinct_groups: 2,
            allow_consecutive_same_group: true,
            max_group_repetitions: 2,
        });
        assert_eq!(
            c.check(&[1, 2, 1, 2, 1]),
            Err(DiversityViolation::ExcessiveGroupRepetition)
        );
    }

    // RDC6: empty path is always valid.
    #[test]
    fn rdc6_empty_path() {
        let c = default_checker();
        assert!(c.is_diverse(&[]));
    }

    // RDC7: two distinct groups satisfies min_distinct_groups=2.
    #[test]
    fn rdc7_two_groups() {
        let c = default_checker();
        assert!(c.is_diverse(&[1, 2, 1, 2]));
    }

    // RDC8: min_distinct_groups=3 rejects two groups.
    #[test]
    fn rdc8_min_three_groups() {
        let c = RouteDiversityChecker::new(DiversityConstraints {
            min_distinct_groups: 3,
            allow_consecutive_same_group: false,
            max_group_repetitions: 5,
        });
        assert_eq!(
            c.check(&[1, 2, 1, 2]),
            Err(DiversityViolation::TooFewDistinctGroups)
        );
    }

    // RDC9: is_diverse returns bool wrapper.
    #[test]
    fn rdc9_is_diverse_bool() {
        let c = default_checker();
        assert!(c.is_diverse(&[1, 2, 3]));
        assert!(!c.is_diverse(&[1, 1]));
    }

    // RDC10: max_group_repetitions=1 fails on any repetition.
    #[test]
    fn rdc10_max_one_rep() {
        let c = RouteDiversityChecker::new(DiversityConstraints {
            min_distinct_groups: 2,
            allow_consecutive_same_group: false,
            max_group_repetitions: 1,
        });
        assert_eq!(
            c.check(&[1, 2, 1]),
            Err(DiversityViolation::ExcessiveGroupRepetition)
        );
    }
}
