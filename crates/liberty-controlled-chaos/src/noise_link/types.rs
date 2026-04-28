use crate::cell_encoder::CELL_SIZE;

pub const ENCRYPTED_CELL_SIZE: usize = 8 + 8 + CELL_SIZE + 16; // 1482

/// Per-message nonce, incremented monotonically by the sender.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseNonce(pub(super) u64);

impl NoiseNonce {
    pub fn new(v: u64) -> Self {
        Self(v)
    }
    pub fn value(&self) -> u64 {
        self.0
    }
}

/// An encrypted, authenticated, fixed-size transport cell.
///
/// Wire layout (1482 bytes):
///   path_id(8) | nonce(8) | ciphertext(1450) | auth_tag(16)
pub struct EncryptedCell {
    pub path_id: u64,
    pub nonce: u64,
    pub ciphertext: [u8; CELL_SIZE],
    pub auth_tag: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub enum NoiseError {
    /// AEAD authentication tag did not match — ciphertext or metadata is corrupted.
    AuthenticationFailure,
}
