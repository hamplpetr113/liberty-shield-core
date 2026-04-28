use super::types::{CellNonce, ReplayError};

/// Sliding window that tracks which nonces have been seen.
///
/// - Nonces older than `last_nonce - window_size` are rejected as expired.
/// - Nonces already in `seen_nonces` are rejected as duplicates.
/// - New nonces within the window are recorded; the window advances with
///   `last_nonce`.
pub struct ReplayWindow {
    /// Highest nonce accepted so far (0 when nothing has been seen).
    pub last_nonce: u64,
    /// Width of the sliding window.
    pub window_size: usize,
    /// Nonces accepted within the current window.
    pub seen_nonces: Vec<u64>,
}

impl ReplayWindow {
    pub fn new(window_size: usize) -> Self {
        Self {
            last_nonce: 0,
            window_size,
            seen_nonces: Vec::new(),
        }
    }

    /// Check `nonce` against the window and, if valid, record it.
    pub fn check_and_record(&mut self, nonce: CellNonce) -> Result<(), ReplayError> {
        let n = nonce.0;

        // Duplicate check.
        if self.seen_nonces.contains(&n) {
            return Err(ReplayError::DuplicateNonce);
        }

        // Window check — only meaningful once at least one nonce has been seen.
        if !self.seen_nonces.is_empty() {
            let cutoff = self.last_nonce.saturating_sub(self.window_size as u64);
            if n < cutoff {
                return Err(ReplayError::WindowExpired);
            }
        }

        // Accept: record and advance.
        self.seen_nonces.push(n);
        if n > self.last_nonce {
            self.last_nonce = n;
        }

        // Prune nonces that have fallen below the new window floor.
        let floor = self.last_nonce.saturating_sub(self.window_size as u64);
        self.seen_nonces.retain(|&x| x >= floor);

        Ok(())
    }
}
