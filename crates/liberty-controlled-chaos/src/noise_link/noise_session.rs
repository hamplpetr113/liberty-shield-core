/// Cryptographic state for one NoiseLink session.
///
/// `send_key` encrypts outbound cells; `recv_key` decrypts inbound cells.
/// `nonce` is the monotonically-incrementing send-side counter.
#[derive(Debug)]
pub struct NoiseSession {
    pub send_key: [u8; 32],
    pub recv_key: [u8; 32],
    pub(super) nonce: u64,
}

impl NoiseSession {
    pub fn new(send_key: [u8; 32], recv_key: [u8; 32]) -> Self {
        Self {
            send_key,
            recv_key,
            nonce: 0,
        }
    }

    pub fn current_nonce(&self) -> u64 {
        self.nonce
    }

    /// Advance the send-side nonce by one (wrapping).
    pub(super) fn advance_nonce(&mut self) {
        self.nonce = self.nonce.wrapping_add(1);
    }

    /// Replace session keys (e.g. after a renegotiation) and optionally reset the nonce.
    pub fn rotate_keys(&mut self, new_send: [u8; 32], new_recv: [u8; 32], reset_nonce: bool) {
        self.send_key = new_send;
        self.recv_key = new_recv;
        if reset_nonce {
            self.nonce = 0;
        }
    }
}
