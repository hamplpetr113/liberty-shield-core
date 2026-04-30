//! Peer ban list — tracks banned peers with optional epoch-based expiry.
//!
//! Bans can be permanent or time-limited.  Expired bans are lazily removed.

use std::collections::HashMap;

// ---------------------------------------------------------------------------
// BanEntry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct BanEntry {
    pub node_id: [u8; 32],
    pub reason: String,
    pub banned_at_epoch: u64,
    /// None = permanent.
    pub expires_at_epoch: Option<u64>,
}

impl BanEntry {
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        match self.expires_at_epoch {
            None => false,
            Some(exp) => current_epoch >= exp,
        }
    }
}

// ---------------------------------------------------------------------------
// BanError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanError {
    AlreadyBanned,
    NotBanned,
}

// ---------------------------------------------------------------------------
// PeerBanList
// ---------------------------------------------------------------------------

pub struct PeerBanList {
    bans: HashMap<[u8; 32], BanEntry>,
    total_bans: u64,
    total_expired: u64,
}

impl PeerBanList {
    pub fn new() -> Self {
        Self {
            bans: HashMap::new(),
            total_bans: 0,
            total_expired: 0,
        }
    }

    pub fn ban(
        &mut self,
        node_id: [u8; 32],
        reason: String,
        epoch: u64,
        duration: Option<u64>,
    ) -> Result<(), BanError> {
        if self.bans.contains_key(&node_id) {
            return Err(BanError::AlreadyBanned);
        }
        let expires_at_epoch = duration.map(|d| epoch + d);
        self.bans.insert(
            node_id,
            BanEntry {
                node_id,
                reason,
                banned_at_epoch: epoch,
                expires_at_epoch,
            },
        );
        self.total_bans += 1;
        Ok(())
    }

    pub fn unban(&mut self, node_id: &[u8; 32]) -> Result<(), BanError> {
        if self.bans.remove(node_id).is_none() {
            return Err(BanError::NotBanned);
        }
        Ok(())
    }

    /// Check ban status, respecting expiry.
    pub fn is_banned(&self, node_id: &[u8; 32], current_epoch: u64) -> bool {
        match self.bans.get(node_id) {
            None => false,
            Some(e) => !e.is_expired(current_epoch),
        }
    }

    pub fn entry(&self, node_id: &[u8; 32]) -> Option<&BanEntry> {
        self.bans.get(node_id)
    }

    /// Remove expired bans. Returns number removed.
    pub fn evict_expired(&mut self, current_epoch: u64) -> usize {
        let before = self.bans.len();
        self.bans.retain(|_, e| !e.is_expired(current_epoch));
        let evicted = before - self.bans.len();
        self.total_expired += evicted as u64;
        evicted
    }

    pub fn active_ban_count(&self) -> usize {
        self.bans.len()
    }

    pub fn total_bans(&self) -> u64 {
        self.total_bans
    }

    pub fn total_expired(&self) -> u64 {
        self.total_expired
    }
}

impl Default for PeerBanList {
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

    // PBL1: ban a peer, is_banned returns true.
    #[test]
    fn pbl1_ban() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "spam".into(), 0, None).unwrap();
        assert!(bl.is_banned(&nid(1), 100));
    }

    // PBL2: unbanned peer returns false.
    #[test]
    fn pbl2_not_banned() {
        let bl = PeerBanList::new();
        assert!(!bl.is_banned(&nid(1), 0));
    }

    // PBL3: double ban returns AlreadyBanned.
    #[test]
    fn pbl3_double_ban() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "x".into(), 0, None).unwrap();
        assert_eq!(
            bl.ban(nid(1), "y".into(), 0, None),
            Err(BanError::AlreadyBanned)
        );
    }

    // PBL4: unban removes the ban.
    #[test]
    fn pbl4_unban() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "x".into(), 0, None).unwrap();
        bl.unban(&nid(1)).unwrap();
        assert!(!bl.is_banned(&nid(1), 0));
    }

    // PBL5: time-limited ban expires.
    #[test]
    fn pbl5_expiry() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "temp".into(), 0, Some(5)).unwrap();
        assert!(bl.is_banned(&nid(1), 4));
        assert!(!bl.is_banned(&nid(1), 5));
    }

    // PBL6: evict_expired removes expired bans.
    #[test]
    fn pbl6_evict_expired() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "short".into(), 0, Some(3)).unwrap();
        bl.ban(nid(2), "perm".into(), 0, None).unwrap();
        let n = bl.evict_expired(10);
        assert_eq!(n, 1);
        assert_eq!(bl.active_ban_count(), 1);
    }

    // PBL7: total_bans accumulates.
    #[test]
    fn pbl7_total_bans() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "a".into(), 0, None).unwrap();
        bl.ban(nid(2), "b".into(), 0, None).unwrap();
        assert_eq!(bl.total_bans(), 2);
    }

    // PBL8: total_expired increments on evict.
    #[test]
    fn pbl8_total_expired() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "t".into(), 0, Some(1)).unwrap();
        bl.evict_expired(5);
        assert_eq!(bl.total_expired(), 1);
    }

    // PBL9: unban non-existent returns NotBanned.
    #[test]
    fn pbl9_unban_not_found() {
        let mut bl = PeerBanList::new();
        assert_eq!(bl.unban(&nid(99)), Err(BanError::NotBanned));
    }

    // PBL10: entry returns ban details.
    #[test]
    fn pbl10_entry() {
        let mut bl = PeerBanList::new();
        bl.ban(nid(1), "reason".into(), 5, Some(10)).unwrap();
        let e = bl.entry(&nid(1)).unwrap();
        assert_eq!(e.banned_at_epoch, 5);
        assert_eq!(e.expires_at_epoch, Some(15));
    }
}
