//! NON-PRODUCTION placeholder AEAD.
//!
//! Cipher  : ChaCha8 keystream XOR  (reuses the inline ChaCha8 from `transmitter::shadow_sync`)
//! MAC     : SipHash-2-4-128 over (nonce ‖ path_id ‖ ciphertext) with a subkey derived
//!           from the session key.
//!
//! REPLACE WITH: `chacha20poly1305` crate (ChaCha20-Poly1305 / RFC 8439) before any
//! real networking.  The current construction is deterministic and key-dependent but
//! provides no formal security proof.

use crate::cell_encoder::{CELL_SIZE, Cell};
use crate::transmitter::shadow_sync::ChaCha8Rng;

use super::noise_session::NoiseSession;
use super::types::{EncryptedCell, NoiseError};

// ── Low-level crypto primitives ───────────────────────────────────────────────

/// Derive a per-message key by mixing the session key with the nonce.
/// NON-PRODUCTION: simple byte-level XOR mix; replace with HKDF in production.
fn derive_msg_key(session_key: &[u8; 32], nonce: u64) -> [u8; 32] {
    let nb = nonce.to_le_bytes();
    let mut k = *session_key;
    for i in 0..32 {
        k[i] ^= nb[i % 8];
    }
    k
}

/// XOR `input` with a ChaCha8 keystream seeded by `key`, writing into `output`.
fn xor_keystream(key: &[u8; 32], input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(input.len(), output.len());
    let mut rng = ChaCha8Rng::from_seed(key);
    let mut i = 0;
    while i + 4 <= input.len() {
        let ks = rng.next_u32().to_le_bytes();
        output[i] = input[i] ^ ks[0];
        output[i + 1] = input[i + 1] ^ ks[1];
        output[i + 2] = input[i + 2] ^ ks[2];
        output[i + 3] = input[i + 3] ^ ks[3];
        i += 4;
    }
    if i < input.len() {
        let ks = rng.next_u32().to_le_bytes();
        for j in 0..(input.len() - i) {
            output[i + j] = input[i + j] ^ ks[j];
        }
    }
}

// ── SipHash-2-4-128 ───────────────────────────────────────────────────────────

#[inline(always)]
fn sip_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

fn siphash_128(k0: u64, k1: u64, data: &[u8]) -> [u8; 16] {
    let mut v0 = k0 ^ 0x736f_6d65_7073_6575_u64;
    let mut v1 = k1 ^ 0x646f_7261_6e64_6f6d_u64;
    let mut v2 = k0 ^ 0x6c79_6765_6e65_7261_u64;
    let mut v3 = k1 ^ 0x7465_6462_7974_6573_u64;
    v1 ^= 0xee; // 128-bit output variant

    let len = data.len();
    let blocks = len / 8;

    for i in 0..blocks {
        let m = u64::from_le_bytes(data[i * 8..(i + 1) * 8].try_into().unwrap());
        v3 ^= m;
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
        v0 ^= m;
    }

    // Final partial block padded with (len & 0xff) in the high byte.
    let tail = &data[blocks * 8..];
    let mut last = (len as u64 & 0xff) << 56;
    for (i, &b) in tail.iter().enumerate() {
        last |= (b as u64) << (i * 8);
    }
    v3 ^= last;
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= last;

    // First finalization → first 8 bytes of tag.
    v2 ^= 0xee;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    let b0 = v0 ^ v1 ^ v2 ^ v3;

    // Second finalization → last 8 bytes of tag.
    v1 ^= 0xdd;
    for _ in 0..4 {
        sip_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    let b1 = v0 ^ v1 ^ v2 ^ v3;

    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&b0.to_le_bytes());
    tag[8..].copy_from_slice(&b1.to_le_bytes());
    tag
}

/// Compute a 16-byte authentication tag over (nonce ‖ path_id ‖ ciphertext).
fn compute_tag(session_key: &[u8; 32], nonce: u64, path_id: u64, ciphertext: &[u8]) -> [u8; 16] {
    let k0 = u64::from_le_bytes(session_key[0..8].try_into().unwrap()) ^ nonce;
    let k1 = u64::from_le_bytes(session_key[8..16].try_into().unwrap()) ^ path_id;

    // Build MAC input: nonce(8) ‖ path_id(8) ‖ ciphertext(1450)
    let mut msg = Vec::with_capacity(16 + ciphertext.len());
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.extend_from_slice(&path_id.to_le_bytes());
    msg.extend_from_slice(ciphertext);

    siphash_128(k0, k1, &msg)
}

/// Constant-time byte-slice equality to avoid timing side-channels in tag comparison.
fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ── NoiseLinkEncoder ──────────────────────────────────────────────────────────

/// Encrypts `Cell` → `EncryptedCell` and decrypts back.
///
/// `encode` uses `session.send_key` and the current session nonce (then increments it).
/// `decode` uses `session.recv_key` and the nonce carried inside the `EncryptedCell`.
pub struct NoiseLinkEncoder {
    session: NoiseSession,
}

impl NoiseLinkEncoder {
    pub fn new(session: NoiseSession) -> Self {
        Self { session }
    }

    pub fn session(&self) -> &NoiseSession {
        &self.session
    }

    /// Encrypt one `Cell` into an `EncryptedCell`.  Nonce is advanced after encryption.
    pub fn encode(&mut self, cell: Cell) -> EncryptedCell {
        let nonce = self.session.current_nonce();
        let path_id = cell.header().path_id;

        let msg_key = derive_msg_key(&self.session.send_key, nonce);
        let mut ciphertext = [0u8; CELL_SIZE];
        xor_keystream(&msg_key, cell.as_bytes(), &mut ciphertext);

        let auth_tag = compute_tag(&self.session.send_key, nonce, path_id, &ciphertext);

        self.session.advance_nonce();

        EncryptedCell {
            path_id,
            nonce,
            ciphertext,
            auth_tag,
        }
    }

    /// Decrypt one `EncryptedCell` back into a `Cell`.
    ///
    /// Returns `Err(AuthenticationFailure)` if the tag does not match.
    pub fn decode(&mut self, enc: EncryptedCell) -> Result<Cell, NoiseError> {
        let expected = compute_tag(
            &self.session.recv_key,
            enc.nonce,
            enc.path_id,
            &enc.ciphertext,
        );
        if !ct_eq(&expected, &enc.auth_tag) {
            return Err(NoiseError::AuthenticationFailure);
        }

        let msg_key = derive_msg_key(&self.session.recv_key, enc.nonce);
        let mut plain = [0u8; CELL_SIZE];
        xor_keystream(&msg_key, &enc.ciphertext, &mut plain);

        Ok(Cell::from_raw(plain))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cell_encoder::{CELL_VERSION, HEADER_SIZE};

    fn make_test_cell(seed: u8) -> Cell {
        let mut data = [0u8; CELL_SIZE];
        data[0] = CELL_VERSION;
        // path_id at bytes 18..26 (LE u64), set to a recognisable value.
        let path_id: u64 = 0x0102_0304_0506_0708;
        data[18..26].copy_from_slice(&path_id.to_le_bytes());
        // payload: repeating `seed` byte.
        for b in data[HEADER_SIZE..].iter_mut() {
            *b = seed;
        }
        Cell::from_raw(data)
    }

    fn symmetric_session() -> NoiseSession {
        let key = [0xABu8; 32];
        NoiseSession::new(key, key)
    }

    // ── N1: roundtrip ─────────────────────────────────────────────────────────

    #[test]
    fn n1_encode_decode_roundtrip() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        let cell = make_test_cell(0x42);
        let original_bytes = *cell.as_bytes();

        let encrypted = enc.encode(cell);
        let recovered = enc.decode(encrypted).expect("decode must succeed");

        assert_eq!(
            recovered.as_bytes(),
            &original_bytes,
            "decoded cell must equal original"
        );
    }

    // ── N2: nonce increments after encode ─────────────────────────────────────

    #[test]
    fn n2_nonce_increments_after_encode() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        assert_eq!(enc.session().current_nonce(), 0);
        enc.encode(make_test_cell(1));
        assert_eq!(enc.session().current_nonce(), 1);
        enc.encode(make_test_cell(2));
        assert_eq!(enc.session().current_nonce(), 2);
    }

    // ── N3: tampered ciphertext → AuthenticationFailure ───────────────────────

    #[test]
    fn n3_auth_failure_on_tampered_ciphertext() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        let mut encrypted = enc.encode(make_test_cell(0x55));
        // Flip one bit in the ciphertext.
        encrypted.ciphertext[100] ^= 0x01;

        let result = enc.decode(encrypted);
        assert_eq!(
            result.unwrap_err(),
            NoiseError::AuthenticationFailure,
            "tampered ciphertext must be rejected"
        );
    }

    // ── N4: deterministic — same key + same nonce → same ciphertext ──────────

    #[test]
    fn n4_deterministic_same_key_same_nonce() {
        let cell_a = make_test_cell(0x77);
        let cell_b = make_test_cell(0x77);
        assert_eq!(cell_a.as_bytes(), cell_b.as_bytes());

        let mut enc_a = NoiseLinkEncoder::new(symmetric_session());
        let mut enc_b = NoiseLinkEncoder::new(symmetric_session());

        let ea = enc_a.encode(cell_a);
        let eb = enc_b.encode(cell_b);

        assert_eq!(ea.nonce, eb.nonce);
        assert_eq!(
            ea.ciphertext, eb.ciphertext,
            "same key+nonce must yield same ciphertext"
        );
        assert_eq!(
            ea.auth_tag, eb.auth_tag,
            "same key+nonce must yield same auth tag"
        );
    }

    // ── N5: ciphertext payload size is constant ───────────────────────────────

    #[test]
    fn n5_ciphertext_size_constant() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        for seed in [0u8, 1, 64, 128, 255] {
            let encrypted = enc.encode(make_test_cell(seed));
            assert_eq!(
                encrypted.ciphertext.len(),
                CELL_SIZE,
                "ciphertext must always be {CELL_SIZE} bytes"
            );
        }
    }

    // ── N6: decode with wrong key fails ───────────────────────────────────────

    #[test]
    fn n6_wrong_recv_key_fails() {
        let mut sender = NoiseLinkEncoder::new(symmetric_session());
        let encrypted = sender.encode(make_test_cell(0x33));

        // Decoder with a different recv_key.
        let wrong_key = [0xFFu8; 32];
        let bad_session = NoiseSession::new([0xABu8; 32], wrong_key);
        let mut receiver = NoiseLinkEncoder::new(bad_session);

        let result = receiver.decode(encrypted);
        assert_eq!(
            result.unwrap_err(),
            NoiseError::AuthenticationFailure,
            "wrong recv_key must be rejected"
        );
    }

    // ── N7: tampered auth_tag is rejected ─────────────────────────────────────

    #[test]
    fn n7_tampered_auth_tag_rejected() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        let mut encrypted = enc.encode(make_test_cell(0x11));
        encrypted.auth_tag[0] ^= 0x01;

        assert_eq!(
            enc.decode(encrypted).unwrap_err(),
            NoiseError::AuthenticationFailure
        );
    }

    // ── N8: tampered path_id is rejected ──────────────────────────────────────

    #[test]
    fn n8_tampered_path_id_rejected() {
        let mut enc = NoiseLinkEncoder::new(symmetric_session());
        let mut encrypted = enc.encode(make_test_cell(0x22));
        encrypted.path_id ^= 0x01; // path_id is part of the MAC input

        assert_eq!(
            enc.decode(encrypted).unwrap_err(),
            NoiseError::AuthenticationFailure
        );
    }
}
