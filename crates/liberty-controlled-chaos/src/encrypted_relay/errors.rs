//! Error types for the encrypted relay cell layer.

/// Errors produced by `EncryptedRelayCell` operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptedRelayError {
    /// AEAD authentication failed — the cell was tampered or keys are wrong.
    AuthenticationFailed,
    /// Payload exceeds `MAX_RELAY_PAYLOAD`.
    PayloadTooLarge,
    /// Buffer is shorter than the minimum header size.
    BufferTooShort,
    /// Declared payload length exceeds the available bytes.
    TruncatedPayload,
    /// The command tag byte is not a known variant.
    UnknownCommand(u8),
    /// Session send-nonce exhausted; renegotiation required.
    NonceExhausted,
}
