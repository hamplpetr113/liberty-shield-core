//! Poly1305 one-time MAC per RFC 8439 §2.5.
//!
//! 16-byte key clamp, 128-bit field arithmetic.
//! Zero-dependency, no unsafe code.
//!
//! The 130-bit prime p = 2^130 - 5 is operated on using five 26-bit limbs
//! to avoid needing u128 overflow concerns for carry propagation.

/// Compute a Poly1305 tag over `data` using `key` (32 bytes).
///
/// `key[0..16]` → r (clamped)
/// `key[16..32]` → s (added to final accumulator)
pub fn poly1305_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    // ── Clamp r ──────────────────────────────────────────────────────────────
    let mut r = [0u64; 5];
    let r_bytes = &key[0..16];
    // r is 130-bit, stored as 5×26-bit limbs (from 128-bit LE input)
    // Clamping: clear certain bits per spec.
    let r0 = u32::from_le_bytes(r_bytes[0..4].try_into().unwrap()) as u64;
    let r1 = u32::from_le_bytes(r_bytes[4..8].try_into().unwrap()) as u64;
    let r2 = u32::from_le_bytes(r_bytes[8..12].try_into().unwrap()) as u64;
    let r3 = u32::from_le_bytes(r_bytes[12..16].try_into().unwrap()) as u64;

    r[0] = r0 & 0x3ffffff;
    r[1] = ((r0 >> 26) | (r1 << 6)) & 0x3ffff03;
    r[2] = ((r1 >> 20) | (r2 << 12)) & 0x3ffc0ff;
    r[3] = ((r2 >> 14) | (r3 << 18)) & 0x3f03fff;
    r[4] = (r3 >> 8) & 0x00fffff;

    // 5×r values (precomputed r[i] * 5 for faster reduction)
    let rr0 = r[0];
    let rr1 = r[1];
    let rr2 = r[2];
    let rr3 = r[3];
    let rr4 = r[4];
    let s1 = rr1 * 5;
    let s2 = rr2 * 5;
    let s3 = rr3 * 5;
    let s4 = rr4 * 5;

    // ── Accumulator ──────────────────────────────────────────────────────────
    let mut h = [0u64; 5];

    let mut i = 0;
    while i < data.len() {
        // Build a 17-byte block; add the 1-bit after the message bytes.
        let block_len = if data.len() - i >= 16 {
            16
        } else {
            data.len() - i
        };
        let mut block = [0u8; 17];
        block[..block_len].copy_from_slice(&data[i..i + block_len]);
        block[block_len] = 1; // append bit

        // Load block into 5×26-bit limbs
        let n0 = u32::from_le_bytes(block[0..4].try_into().unwrap()) as u64;
        let n1 = u32::from_le_bytes(block[4..8].try_into().unwrap()) as u64;
        let n2 = u32::from_le_bytes(block[8..12].try_into().unwrap()) as u64;
        let n3 = u32::from_le_bytes(block[12..16].try_into().unwrap()) as u64;
        let n4 = block[16] as u64;

        h[0] += n0 & 0x3ffffff;
        h[1] += ((n0 >> 26) | (n1 << 6)) & 0x3ffffff;
        h[2] += ((n1 >> 20) | (n2 << 12)) & 0x3ffffff;
        h[3] += ((n2 >> 14) | (n3 << 18)) & 0x3ffffff;
        h[4] += (n3 >> 8) | (n4 << 24);

        // Multiply h by r mod p = 2^130-5, using the schoolbook method.
        let d0: u64 = h[0] * rr0 + h[1] * s4 + h[2] * s3 + h[3] * s2 + h[4] * s1;
        let d1: u64 = h[0] * rr1 + h[1] * rr0 + h[2] * s4 + h[3] * s3 + h[4] * s2;
        let d2: u64 = h[0] * rr2 + h[1] * rr1 + h[2] * rr0 + h[3] * s4 + h[4] * s3;
        let d3: u64 = h[0] * rr3 + h[1] * rr2 + h[2] * rr1 + h[3] * rr0 + h[4] * s4;
        let d4: u64 = h[0] * rr4 + h[1] * rr3 + h[2] * rr2 + h[3] * rr1 + h[4] * rr0;

        // Partial reduction mod 2^130-5
        let mut c: u64;
        c = d0 >> 26;
        h[0] = d0 & 0x3ffffff;
        let d1 = d1 + c;
        c = d1 >> 26;
        h[1] = d1 & 0x3ffffff;
        let d2 = d2 + c;
        c = d2 >> 26;
        h[2] = d2 & 0x3ffffff;
        let d3 = d3 + c;
        c = d3 >> 26;
        h[3] = d3 & 0x3ffffff;
        let d4 = d4 + c;
        c = d4 >> 26;
        h[4] = d4 & 0x3ffffff;
        h[0] += c * 5; // wrap: 2^130 ≡ 5 (mod p)
        c = h[0] >> 26;
        h[0] &= 0x3ffffff;
        h[1] += c;

        i += 16;
    }

    // ── Full reduction mod p ──────────────────────────────────────────────────
    // Bring h fully in range [0, p).
    let mut c = h[1] >> 26;
    h[1] &= 0x3ffffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x3ffffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x3ffffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x3ffffff;
    h[0] += c * 5;
    c = h[0] >> 26;
    h[0] &= 0x3ffffff;
    h[1] += c;

    // Compute g = h - p = h - (2^130 - 5)
    let mut g = [0u64; 5];
    g[0] = h[0].wrapping_add(5);
    c = g[0] >> 26;
    g[0] &= 0x3ffffff;
    g[1] = h[1].wrapping_add(c);
    c = g[1] >> 26;
    g[1] &= 0x3ffffff;
    g[2] = h[2].wrapping_add(c);
    c = g[2] >> 26;
    g[2] &= 0x3ffffff;
    g[3] = h[3].wrapping_add(c);
    c = g[3] >> 26;
    g[3] &= 0x3ffffff;
    g[4] = h[4].wrapping_add(c).wrapping_sub(1 << 26); // subtract 2^130

    // Select h if h < p else g (constant-time mask)
    let mask = (g[4] >> 63).wrapping_sub(1); // all-1s if h >= p, else 0
    for i in 0..5 {
        h[i] = (h[i] & !mask) | (g[i] & mask);
    }

    // Reassemble h into 16 bytes
    let h0 = (h[0] | (h[1] << 26)) as u32;
    let h1 = ((h[1] >> 6) | (h[2] << 20)) as u32;
    let h2 = ((h[2] >> 12) | (h[3] << 14)) as u32;
    let h3 = ((h[3] >> 18) | (h[4] << 8)) as u32;

    // Add s (pad)
    let s0 = u32::from_le_bytes(key[16..20].try_into().unwrap());
    let s1_w = u32::from_le_bytes(key[20..24].try_into().unwrap());
    let s2_w = u32::from_le_bytes(key[24..28].try_into().unwrap());
    let s3_w = u32::from_le_bytes(key[28..32].try_into().unwrap());

    let f0 = (h0 as u64) + (s0 as u64);
    let f1 = (h1 as u64) + (s1_w as u64) + (f0 >> 32);
    let f2 = (h2 as u64) + (s2_w as u64) + (f1 >> 32);
    let f3 = (h3 as u64) + (s3_w as u64) + (f2 >> 32);

    let mut tag = [0u8; 16];
    tag[0..4].copy_from_slice(&(f0 as u32).to_le_bytes());
    tag[4..8].copy_from_slice(&(f1 as u32).to_le_bytes());
    tag[8..12].copy_from_slice(&(f2 as u32).to_le_bytes());
    tag[12..16].copy_from_slice(&(f3 as u32).to_le_bytes());

    tag
}

/// Constant-time 16-byte comparison.
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    // PL1: RFC 8439 §2.5.2 test vector
    #[test]
    fn pl1_rfc8439_test_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(&key, msg);
        let expected: [u8; 16] = [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9,
        ];
        assert_eq!(tag, expected);
    }

    // PL2: different keys produce different tags
    #[test]
    fn pl2_different_keys_differ() {
        let key1 = [0x01u8; 32];
        let key2 = [0x02u8; 32];
        let msg = b"test message";
        let t1 = poly1305_mac(&key1, msg);
        let t2 = poly1305_mac(&key2, msg);
        assert_ne!(t1, t2);
    }

    // PL3: tampered message → different tag
    #[test]
    fn pl3_tamper_detection() {
        let key = [0xAAu8; 32];
        let msg1 = b"good message";
        let msg2 = b"bad_message!";
        let t1 = poly1305_mac(&key, msg1);
        let t2 = poly1305_mac(&key, msg2);
        assert_ne!(t1, t2);
    }

    // PL4: empty message
    #[test]
    fn pl4_empty_message() {
        let key = [0x10u8; 32];
        let tag = poly1305_mac(&key, b"");
        // Should not panic and should equal the s value
        let s0 = u32::from_le_bytes(key[16..20].try_into().unwrap());
        assert_eq!(&tag[0..4], &s0.to_le_bytes());
    }

    // PL5: deterministic
    #[test]
    fn pl5_deterministic() {
        let key = [0x77u8; 32];
        let msg = b"determinism check";
        let t1 = poly1305_mac(&key, msg);
        let t2 = poly1305_mac(&key, msg);
        assert_eq!(t1, t2);
    }

    // PL6: ct_eq_16 distinguishes different tags
    #[test]
    fn pl6_ct_eq() {
        let a = [1u8; 16];
        let b = [2u8; 16];
        assert!(!ct_eq_16(&a, &b));
        assert!(ct_eq_16(&a, &a));
    }
}
