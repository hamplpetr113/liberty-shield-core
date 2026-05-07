/// HMAC-SHA256 authentication for Hello frames.
///
/// Authenticated Hello frame payload layout:
///   [32 bytes: HMAC-SHA256 token][original payload]
///
/// HMAC canonical message:
///   session_id (8 bytes, big-endian)
///   || sequence  (8 bytes, big-endian)
///   || msg_type  (1 byte = 0x01 for Hello)
///   || original_payload (variable)
///
/// This binds the token to the session, the sequence number, and the message type,
/// preventing reuse across sessions, sequence numbers, or frame types.
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::packet::MessageType;

type HmacSha256 = Hmac<Sha256>;

pub const MAC_LEN: usize = 32;

/// Compute the HMAC-SHA256 token for an outgoing authenticated Hello frame.
/// The caller prepends the returned token to `original_payload` before encoding.
pub fn compute_hello_mac(
    psk: &[u8; 32],
    session_id: u64,
    sequence: u64,
    original_payload: &[u8],
) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any key size");
    mac.update(&session_id.to_be_bytes());
    mac.update(&sequence.to_be_bytes());
    mac.update(&[MessageType::Hello as u8]);
    mac.update(original_payload);
    mac.finalize().into_bytes().into()
}

/// Verify the HMAC-SHA256 token on a received Hello frame payload.
/// `frame_payload` = [32-byte MAC token][original payload]
/// Returns false if the payload is too short or the MAC is invalid.
/// Comparison is constant-time via `hmac::Mac::verify_slice`.
pub fn verify_hello_mac(
    psk: &[u8; 32],
    session_id: u64,
    sequence: u64,
    frame_payload: &[u8],
) -> bool {
    if frame_payload.len() < MAC_LEN {
        return false;
    }
    let (token, original_payload) = frame_payload.split_at(MAC_LEN);
    let mut mac = HmacSha256::new_from_slice(psk).expect("HMAC accepts any key size");
    mac.update(&session_id.to_be_bytes());
    mac.update(&sequence.to_be_bytes());
    mac.update(&[MessageType::Hello as u8]);
    mac.update(original_payload);
    mac.verify_slice(token).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: [u8; 32] = [0x42u8; 32];
    const ALT_PSK: [u8; 32] = [0x11u8; 32];

    fn authenticated_payload(
        psk: &[u8; 32],
        session_id: u64,
        sequence: u64,
        original: &[u8],
    ) -> Vec<u8> {
        let mac = compute_hello_mac(psk, session_id, sequence, original);
        let mut p = mac.to_vec();
        p.extend_from_slice(original);
        p
    }

    #[test]
    fn mac_is_deterministic() {
        let a = compute_hello_mac(&PSK, 1, 1, b"hello");
        let b = compute_hello_mac(&PSK, 1, 1, b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn valid_mac_accepted() {
        let payload = authenticated_payload(&PSK, 42, 7, b"hello");
        assert!(verify_hello_mac(&PSK, 42, 7, &payload));
    }

    #[test]
    fn wrong_key_rejected() {
        let payload = authenticated_payload(&PSK, 1, 1, b"hello");
        assert!(!verify_hello_mac(&ALT_PSK, 1, 1, &payload));
    }

    #[test]
    fn flipped_bit_rejected() {
        let mut payload = authenticated_payload(&PSK, 1, 1, b"hello");
        payload[0] ^= 0x01;
        assert!(!verify_hello_mac(&PSK, 1, 1, &payload));
    }

    #[test]
    fn wrong_session_id_rejected() {
        let payload = authenticated_payload(&PSK, 1, 1, b"hello");
        assert!(!verify_hello_mac(&PSK, 2, 1, &payload));
    }

    #[test]
    fn wrong_sequence_rejected() {
        let payload = authenticated_payload(&PSK, 1, 1, b"hello");
        assert!(!verify_hello_mac(&PSK, 1, 2, &payload));
    }

    #[test]
    fn too_short_payload_rejected() {
        let short = vec![0u8; MAC_LEN - 1];
        assert!(!verify_hello_mac(&PSK, 1, 1, &short));
    }

    #[test]
    fn empty_payload_rejected() {
        assert!(!verify_hello_mac(&PSK, 1, 1, &[]));
    }

    #[test]
    fn exactly_mac_len_payload_accepted_when_original_empty() {
        // payload = MAC over empty original — valid
        let payload = authenticated_payload(&PSK, 1, 1, b"");
        assert_eq!(payload.len(), MAC_LEN);
        assert!(verify_hello_mac(&PSK, 1, 1, &payload));
    }
}
