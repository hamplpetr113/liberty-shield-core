//! Link crypto provider trait — abstraction over the link-layer encryption
//! implementation used by `PacketFlowEngine`.
//!
//! Concrete implementations:
//! - `HmacLinkCryptoProvider` — wraps `LinkSession` (HMAC-SHA256, NON-PRODUCTION)
//!
//! This trait decouples the flow engine from the crypto implementation, making
//! it possible to swap in Noise XX or other constructions without modifying the
//! packet processing pipeline.

use crate::link_crypto_v2::{LinkFrame, LinkSession};

// ---------------------------------------------------------------------------
// LinkCryptoProvider trait
// ---------------------------------------------------------------------------

pub trait LinkCryptoProvider: Send {
    /// Seal (encrypt + authenticate) `plaintext` for outbound transmission.
    /// Returns the wire bytes.
    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8>;

    /// Open (authenticate + decrypt) `wire_bytes` received from the link.
    /// Returns `None` on authentication failure or invalid format.
    fn open(&mut self, wire_bytes: &[u8]) -> Option<Vec<u8>>;

    /// Human-readable name of the provider for diagnostics.
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// HmacLinkCryptoProvider — wraps LinkSession
// ---------------------------------------------------------------------------

pub struct HmacLinkCryptoProvider {
    session: LinkSession,
}

impl HmacLinkCryptoProvider {
    pub fn new(session: LinkSession) -> Self {
        Self { session }
    }

    pub fn session(&self) -> &LinkSession {
        &self.session
    }
}

/// Encode a `LinkFrame` to wire bytes: 8 bytes sequence || 32 bytes tag || payload.
fn frame_to_wire(frame: &LinkFrame) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 32 + frame.payload.len());
    out.extend_from_slice(&frame.sequence.to_le_bytes());
    out.extend_from_slice(&frame.auth_tag);
    out.extend_from_slice(&frame.payload);
    out
}

/// Decode wire bytes back into a `LinkFrame`.
fn wire_to_frame(wire: &[u8]) -> Option<LinkFrame> {
    if wire.len() < 40 {
        return None;
    }
    let sequence = u64::from_le_bytes(wire[..8].try_into().ok()?);
    let mut auth_tag = [0u8; 32];
    auth_tag.copy_from_slice(&wire[8..40]);
    let payload = wire[40..].to_vec();
    Some(LinkFrame {
        sequence,
        payload,
        auth_tag,
    })
}

impl LinkCryptoProvider for HmacLinkCryptoProvider {
    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        match self.session.seal(plaintext.to_vec()) {
            Ok(frame) => frame_to_wire(&frame),
            Err(_) => Vec::new(),
        }
    }

    fn open(&mut self, wire_bytes: &[u8]) -> Option<Vec<u8>> {
        let frame = wire_to_frame(wire_bytes)?;
        self.session.open(frame).ok()
    }

    fn name(&self) -> &str {
        "HmacLinkCryptoProvider"
    }
}

// ---------------------------------------------------------------------------
// NullCryptoProvider — pass-through for testing
// ---------------------------------------------------------------------------

pub struct NullCryptoProvider;

impl LinkCryptoProvider for NullCryptoProvider {
    fn seal(&mut self, plaintext: &[u8]) -> Vec<u8> {
        plaintext.to_vec()
    }

    fn open(&mut self, wire_bytes: &[u8]) -> Option<Vec<u8>> {
        Some(wire_bytes.to_vec())
    }

    fn name(&self) -> &str {
        "NullCryptoProvider"
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::link_crypto_v2::{LinkFrame, LinkSession};

    fn make_hmac() -> HmacLinkCryptoProvider {
        let session = LinkSession::new([0xAAu8; 32], [0xBBu8; 32], 1000);
        HmacLinkCryptoProvider::new(session)
    }

    fn make_peer_hmac() -> HmacLinkCryptoProvider {
        // Peer side: keys are mirrored (send/recv swapped).
        let session = LinkSession::new([0xBBu8; 32], [0xAAu8; 32], 1000);
        HmacLinkCryptoProvider::new(session)
    }

    // LCP1: NullCryptoProvider name returns expected string.
    #[test]
    fn lcp1_null_provider_name() {
        let p = NullCryptoProvider;
        assert_eq!(p.name(), "NullCryptoProvider");
    }

    // LCP2: NullCryptoProvider seal is identity.
    #[test]
    fn lcp2_null_seal_identity() {
        let mut p = NullCryptoProvider;
        let data = b"hello";
        assert_eq!(p.seal(data), data);
    }

    // LCP3: NullCryptoProvider open returns Some(identical bytes).
    #[test]
    fn lcp3_null_open_identity() {
        let mut p = NullCryptoProvider;
        let data = b"world";
        assert_eq!(p.open(data), Some(data.to_vec()));
    }

    // LCP4: HmacLinkCryptoProvider name returns expected string.
    #[test]
    fn lcp4_hmac_provider_name() {
        let p = make_hmac();
        assert_eq!(p.name(), "HmacLinkCryptoProvider");
    }

    // LCP5: seal produces output of different length from input (HMAC tag added).
    #[test]
    fn lcp5_seal_adds_tag() {
        let mut p = make_hmac();
        let plain = b"test payload";
        let sealed = p.seal(plain);
        assert_ne!(sealed.len(), plain.len());
        assert!(sealed.len() > plain.len());
    }

    // LCP6: seal + open round-trip recovers plaintext.
    #[test]
    fn lcp6_seal_open_round_trip() {
        let mut sender = make_hmac();
        let mut receiver = make_peer_hmac();
        let plain = b"round-trip message";
        let sealed = sender.seal(plain);
        let opened = receiver.open(&sealed).expect("open failed");
        assert_eq!(opened, plain);
    }

    // LCP7: open with tampered bytes returns None.
    #[test]
    fn lcp7_tampered_returns_none() {
        let mut sender = make_hmac();
        let mut receiver = make_peer_hmac();
        let plain = b"sensitive data";
        let mut sealed = sender.seal(plain);
        // Flip a byte in the middle.
        let mid = sealed.len() / 2;
        sealed[mid] ^= 0xFF;
        assert!(receiver.open(&sealed).is_none());
    }

    // LCP8: HmacLinkCryptoProvider::session() exposes the underlying session.
    #[test]
    fn lcp8_session_accessor() {
        let p = make_hmac();
        let _ = p.session();
    }

    // LCP9: trait object dispatch works (dynamic dispatch).
    #[test]
    fn lcp9_dyn_dispatch() {
        let mut provider: Box<dyn LinkCryptoProvider> = Box::new(NullCryptoProvider);
        let sealed = provider.seal(b"dynamic");
        let opened = provider.open(&sealed).unwrap();
        assert_eq!(opened, b"dynamic");
    }

    // LCP10: two independent providers don't share state.
    #[test]
    fn lcp10_independent_providers() {
        let mut p1 = NullCryptoProvider;
        let mut p2 = NullCryptoProvider;
        let a = p1.seal(b"aaa");
        let b = p2.seal(b"bbb");
        assert_ne!(a, b);
    }
}
