use crate::noise_link::{ENCRYPTED_CELL_SIZE, EncryptedCell};

pub const ONION_PACKET_SIZE: usize = 1 + 8 + ENCRYPTED_CELL_SIZE + 16; // 1507

#[derive(Clone)]
pub struct OnionLayerKey {
    pub bytes: [u8; 32],
}

/// A fixed-size onion-wrapped cell.
///
/// Wire layout (1507 bytes):
///   layer_count(1) | nonce(8 LE) | payload(1482) | outer_auth(16)
///
/// Inner layers carry `outer_auth = [0u8; 16]` (NON-PRODUCTION).
/// Only the outermost layer's tag is verified on peel.
pub struct OnionPacket {
    pub layer_count: u8,
    pub nonce: u64,
    pub payload: [u8; ENCRYPTED_CELL_SIZE],
    pub outer_auth: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub enum OnionError {
    /// Authentication tag mismatch on the outermost layer.
    InvalidLayer,
    /// Attempted to peel a packet that has no layers remaining.
    NoLayersRemaining,
    /// Attempted final extraction but layers are still present.
    LayersRemaining(u8),
    /// `wrap` called with an empty key slice.
    EmptyKeySet,
    /// Key slice exceeds 255 entries (layer_count would overflow u8).
    TooManyLayers,
}

// ── Shared crypto helpers (NON-PRODUCTION) ────────────────────────────────────

/// ChaCha8 quarter-round (used to build the keystream).
#[inline]
fn qr(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(16);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(12);
    let a = a.wrapping_add(b);
    let d = (d ^ a).rotate_left(8);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_left(7);
    (a, b, c, d)
}

/// Fill `out` with the XOR of its current bytes and a ChaCha8 keystream derived
/// from `key` and `nonce`.  Suitable for in-place encryption or decryption.
pub(super) fn xor_keystream_layer(out: &mut [u8], key: &[u8; 32], nonce: u64) {
    let constant: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
    let key_words: [u32; 8] = {
        let mut kw = [0u32; 8];
        for i in 0..8 {
            kw[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
        }
        kw
    };
    let nonce_lo = nonce as u32;
    let nonce_hi = (nonce >> 32) as u32;

    let mut block_idx: u64 = 0;
    let mut pos = 0;

    while pos < out.len() {
        let mut s = [
            constant[0],
            constant[1],
            constant[2],
            constant[3],
            key_words[0],
            key_words[1],
            key_words[2],
            key_words[3],
            key_words[4],
            key_words[5],
            key_words[6],
            key_words[7],
            block_idx as u32,
            (block_idx >> 32) as u32,
            nonce_lo,
            nonce_hi,
        ];

        let orig = s;
        for _ in 0..4 {
            (s[0], s[4], s[8], s[12]) = qr(s[0], s[4], s[8], s[12]);
            (s[1], s[5], s[9], s[13]) = qr(s[1], s[5], s[9], s[13]);
            (s[2], s[6], s[10], s[14]) = qr(s[2], s[6], s[10], s[14]);
            (s[3], s[7], s[11], s[15]) = qr(s[3], s[7], s[11], s[15]);
            (s[0], s[5], s[10], s[15]) = qr(s[0], s[5], s[10], s[15]);
            (s[1], s[6], s[11], s[12]) = qr(s[1], s[6], s[11], s[12]);
            (s[2], s[7], s[8], s[13]) = qr(s[2], s[7], s[8], s[13]);
            (s[3], s[4], s[9], s[14]) = qr(s[3], s[4], s[9], s[14]);
        }
        for i in 0..16 {
            s[i] = s[i].wrapping_add(orig[i]);
        }

        let mut keyblock = [0u8; 64];
        for i in 0..16 {
            keyblock[i * 4..i * 4 + 4].copy_from_slice(&s[i].to_le_bytes());
        }

        let take = (out.len() - pos).min(64);
        for j in 0..take {
            out[pos + j] ^= keyblock[j];
        }
        pos += take;
        block_idx += 1;
    }
}

// ── SipHash-2-4-128 (NON-PRODUCTION MAC) ─────────────────────────────────────

#[inline]
pub(super) fn sip_round(v0: u64, v1: u64, v2: u64, v3: u64) -> (u64, u64, u64, u64) {
    let v0 = v0.wrapping_add(v1);
    let v1 = v1.rotate_left(13) ^ v0;
    let v0 = v0.rotate_left(32);
    let v2 = v2.wrapping_add(v3);
    let v3 = v3.rotate_left(16) ^ v2;
    let v0 = v0.wrapping_add(v3);
    let v3 = v3.rotate_left(21) ^ v0;
    let v2 = v2.wrapping_add(v1);
    let v1 = v1.rotate_left(17) ^ v2;
    let v2 = v2.rotate_left(32);
    (v0, v1, v2, v3)
}

pub(super) fn siphash_128(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let k0 = u64::from_le_bytes(key[0..8].try_into().unwrap());
    let k1 = u64::from_le_bytes(key[8..16].try_into().unwrap());
    let k2 = u64::from_le_bytes(key[16..24].try_into().unwrap());
    let k3 = u64::from_le_bytes(key[24..32].try_into().unwrap());

    let mut v0 = k0 ^ 0x736f6d6570736575u64;
    let mut v1 = k1 ^ 0x646f72616e646f6du64;
    let mut v2 = k2 ^ 0x6c7967656e657261u64;
    let mut v3 = k3 ^ 0x7465646279746573u64;
    // SipHash-128 initialisation XOR
    v1 ^= 0xee;

    let mut chunks = data.chunks_exact(8);
    for chunk in chunks.by_ref() {
        let m = u64::from_le_bytes(chunk.try_into().unwrap());
        v3 ^= m;
        (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
        (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }

    let rem = chunks.remainder();
    let len = data.len();
    let mut last = (len as u64 & 0xff) << 56;
    for (i, &b) in rem.iter().enumerate() {
        last |= (b as u64) << (i * 8);
    }
    v3 ^= last;
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    v0 ^= last;

    v2 ^= 0xee;
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    let b1 = v0 ^ v1 ^ v2 ^ v3;

    v1 ^= 0xdd;
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    (v0, v1, v2, v3) = sip_round(v0, v1, v2, v3);
    let b2 = v0 ^ v1 ^ v2 ^ v3;

    let mut tag = [0u8; 16];
    tag[0..8].copy_from_slice(&b1.to_le_bytes());
    tag[8..16].copy_from_slice(&b2.to_le_bytes());
    tag
}

pub(super) fn compute_onion_tag(
    key: &OnionLayerKey,
    nonce: u64,
    layer_count: u8,
    payload: &[u8; ENCRYPTED_CELL_SIZE],
) -> [u8; 16] {
    let mut msg = Vec::with_capacity(9 + ENCRYPTED_CELL_SIZE);
    msg.extend_from_slice(&nonce.to_le_bytes());
    msg.push(layer_count);
    msg.extend_from_slice(payload);
    siphash_128(&key.bytes, &msg)
}

#[inline]
pub(super) fn ct_eq(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut acc = 0u8;
    for i in 0..16 {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}

// ── EncryptedCell ↔ [u8; 1482] serialization ─────────────────────────────────

pub(super) fn cell_to_bytes(cell: &EncryptedCell) -> [u8; ENCRYPTED_CELL_SIZE] {
    let mut buf = [0u8; ENCRYPTED_CELL_SIZE];
    buf[0..8].copy_from_slice(&cell.path_id.to_le_bytes());
    buf[8..16].copy_from_slice(&cell.nonce.to_le_bytes());
    buf[16..16 + crate::cell_encoder::CELL_SIZE].copy_from_slice(&cell.ciphertext);
    buf[16 + crate::cell_encoder::CELL_SIZE..].copy_from_slice(&cell.auth_tag);
    buf
}

pub(super) fn bytes_to_cell(buf: [u8; ENCRYPTED_CELL_SIZE]) -> EncryptedCell {
    use crate::cell_encoder::CELL_SIZE;
    let path_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let nonce = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let mut ciphertext = [0u8; CELL_SIZE];
    ciphertext.copy_from_slice(&buf[16..16 + CELL_SIZE]);
    let mut auth_tag = [0u8; 16];
    auth_tag.copy_from_slice(&buf[16 + CELL_SIZE..]);
    EncryptedCell {
        path_id,
        nonce,
        ciphertext,
        auth_tag,
    }
}
