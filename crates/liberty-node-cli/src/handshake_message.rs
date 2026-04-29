use crate::handshake_types::{HandshakeMessageType, HandshakeNodeId};

/// A single message exchanged during the 3-way handshake.
///
/// Wire layout (in-memory only for the loopback testnet):
///   source_node, target_node, message_type, sequence, payload
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeMessage {
    pub source_node: HandshakeNodeId,
    pub target_node: HandshakeNodeId,
    pub message_type: HandshakeMessageType,
    /// Monotonic sequence number: 0=ClientHello, 1=ServerHello, 2=ClientFinish.
    pub sequence: u32,
    /// Type-specific payload:
    ///   ClientHello / ServerHello → 8 LE bytes of the sender's nonce.
    ///   ClientFinish / Reject     → empty.
    pub payload: Vec<u8>,
}

impl HandshakeMessage {
    /// Extract the 64-bit nonce from a ClientHello or ServerHello payload.
    /// Returns 0 if the payload is too short.
    pub fn extract_nonce(&self) -> u64 {
        if self.payload.len() >= 8 {
            let arr: [u8; 8] = self.payload[..8].try_into().unwrap_or([0u8; 8]);
            u64::from_le_bytes(arr)
        } else {
            0
        }
    }

    /// Build a payload from an 8-byte nonce.
    pub fn nonce_payload(nonce: u64) -> Vec<u8> {
        nonce.to_le_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handshake_types::HandshakeNodeId;

    fn msg(mt: HandshakeMessageType, seq: u32, payload: Vec<u8>) -> HandshakeMessage {
        HandshakeMessage {
            source_node: HandshakeNodeId(1),
            target_node: HandshakeNodeId(2),
            message_type: mt,
            sequence: seq,
            payload,
        }
    }

    // HM1: nonce round-trips through payload
    #[test]
    fn hm1_nonce_roundtrip() {
        let nonce = 0xDEADBEEF_12345678u64;
        let m = msg(
            HandshakeMessageType::ClientHello,
            0,
            HandshakeMessage::nonce_payload(nonce),
        );
        assert_eq!(m.extract_nonce(), nonce);
    }

    // HM2: short payload returns 0
    #[test]
    fn hm2_short_payload_returns_zero() {
        let m = msg(HandshakeMessageType::ClientFinish, 2, Vec::new());
        assert_eq!(m.extract_nonce(), 0);
    }

    // HM3: messages with different types are not equal
    #[test]
    fn hm3_different_types_not_equal() {
        let a = msg(HandshakeMessageType::ClientHello, 0, vec![]);
        let b = msg(HandshakeMessageType::ServerHello, 0, vec![]);
        assert_ne!(a, b);
    }
}
