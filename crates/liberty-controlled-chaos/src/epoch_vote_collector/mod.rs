//! Epoch vote collector — aggregates signed epoch advancement votes.

use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VoteError {
    DuplicateVote,
    EpochMismatch,
}

#[derive(Debug, Clone)]
pub struct EpochVote {
    pub voter_id: [u8; 32],
    pub proposed_epoch: u64,
    pub signature: [u8; 32],
}

pub struct EpochVoteCollector {
    current_epoch: u64,
    quorum: usize,
    votes: HashMap<[u8; 32], EpochVote>,
    total_votes: u64,
    epochs_advanced: u64,
}

impl EpochVoteCollector {
    pub fn new(current_epoch: u64, quorum: usize) -> Self {
        Self {
            current_epoch,
            quorum,
            votes: HashMap::new(),
            total_votes: 0,
            epochs_advanced: 0,
        }
    }

    pub fn submit_vote(&mut self, vote: EpochVote) -> Result<(), VoteError> {
        if vote.proposed_epoch != self.current_epoch + 1 {
            return Err(VoteError::EpochMismatch);
        }
        if self.votes.contains_key(&vote.voter_id) {
            return Err(VoteError::DuplicateVote);
        }
        self.votes.insert(vote.voter_id, vote);
        self.total_votes += 1;
        Ok(())
    }

    pub fn has_quorum(&self) -> bool {
        self.votes.len() >= self.quorum
    }

    /// If quorum reached, advance epoch and reset votes.
    pub fn try_advance(&mut self) -> Option<u64> {
        if !self.has_quorum() {
            return None;
        }
        self.current_epoch += 1;
        self.votes.clear();
        self.epochs_advanced += 1;
        Some(self.current_epoch)
    }

    pub fn vote_count(&self) -> usize {
        self.votes.len()
    }

    pub fn current_epoch(&self) -> u64 {
        self.current_epoch
    }

    pub fn total_votes(&self) -> u64 {
        self.total_votes
    }

    pub fn epochs_advanced(&self) -> u64 {
        self.epochs_advanced
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(b: u8) -> [u8; 32] {
        [b; 32]
    }
    fn sig(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn vote(voter: u8, epoch: u64) -> EpochVote {
        EpochVote {
            voter_id: vid(voter),
            proposed_epoch: epoch,
            signature: sig(voter),
        }
    }

    // EVC1: submit valid vote.
    #[test]
    fn evc1_submit_vote() {
        let mut c = EpochVoteCollector::new(0, 3);
        c.submit_vote(vote(1, 1)).unwrap();
        assert_eq!(c.vote_count(), 1);
    }

    // EVC2: duplicate vote returns DuplicateVote.
    #[test]
    fn evc2_duplicate() {
        let mut c = EpochVoteCollector::new(0, 3);
        c.submit_vote(vote(1, 1)).unwrap();
        assert_eq!(c.submit_vote(vote(1, 1)), Err(VoteError::DuplicateVote));
    }

    // EVC3: wrong epoch returns EpochMismatch.
    #[test]
    fn evc3_epoch_mismatch() {
        let mut c = EpochVoteCollector::new(0, 3);
        assert_eq!(c.submit_vote(vote(1, 5)), Err(VoteError::EpochMismatch));
    }

    // EVC4: has_quorum false below quorum.
    #[test]
    fn evc4_no_quorum() {
        let mut c = EpochVoteCollector::new(0, 3);
        c.submit_vote(vote(1, 1)).unwrap();
        assert!(!c.has_quorum());
    }

    // EVC5: has_quorum true at quorum.
    #[test]
    fn evc5_quorum_reached() {
        let mut c = EpochVoteCollector::new(0, 2);
        c.submit_vote(vote(1, 1)).unwrap();
        c.submit_vote(vote(2, 1)).unwrap();
        assert!(c.has_quorum());
    }

    // EVC6: try_advance returns None below quorum.
    #[test]
    fn evc6_advance_no_quorum() {
        let mut c = EpochVoteCollector::new(0, 3);
        c.submit_vote(vote(1, 1)).unwrap();
        assert!(c.try_advance().is_none());
    }

    // EVC7: try_advance advances epoch and clears votes.
    #[test]
    fn evc7_advance_clears() {
        let mut c = EpochVoteCollector::new(0, 2);
        c.submit_vote(vote(1, 1)).unwrap();
        c.submit_vote(vote(2, 1)).unwrap();
        let new_epoch = c.try_advance().unwrap();
        assert_eq!(new_epoch, 1);
        assert_eq!(c.vote_count(), 0);
    }

    // EVC8: epochs_advanced counter increments.
    #[test]
    fn evc8_epochs_advanced() {
        let mut c = EpochVoteCollector::new(0, 1);
        c.submit_vote(vote(1, 1)).unwrap();
        c.try_advance().unwrap();
        assert_eq!(c.epochs_advanced(), 1);
    }

    // EVC9: total_votes accumulates across advances.
    #[test]
    fn evc9_total_votes() {
        let mut c = EpochVoteCollector::new(0, 1);
        c.submit_vote(vote(1, 1)).unwrap();
        c.try_advance().unwrap();
        c.submit_vote(vote(1, 2)).unwrap();
        c.try_advance().unwrap();
        assert_eq!(c.total_votes(), 2);
    }

    // EVC10: current_epoch returns correct value.
    #[test]
    fn evc10_current_epoch() {
        let c = EpochVoteCollector::new(42, 3);
        assert_eq!(c.current_epoch(), 42);
    }
}
