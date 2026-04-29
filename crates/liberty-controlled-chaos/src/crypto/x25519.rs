//! X25519 Diffie-Hellman function — RFC 7748 §5.
//!
//! Montgomery ladder over Curve25519 (p = 2^255 − 19).
//! Zero external dependencies. No unsafe code.
//!
//! NON-PRODUCTION: no formal side-channel audit has been performed.
//! Do not use in a deployed product without a professional security review.

/// A 32-byte X25519 private (scalar) key.
pub type X25519PrivateKey = [u8; 32];
/// A 32-byte X25519 public (u-coordinate) key.
pub type X25519PublicKey = [u8; 32];
/// A 32-byte X25519 shared secret.
pub type X25519SharedSecret = [u8; 32];

/// The canonical Curve25519 basepoint u = 9 (little-endian).
pub const X25519_BASEPOINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

// ---------------------------------------------------------------------------
// GF(2^255 - 19) field arithmetic
// ---------------------------------------------------------------------------
//
// Field elements use five u64 limbs in radix-2^51:
//   value = h[0] + h[1]·2^51 + h[2]·2^102 + h[3]·2^153 + h[4]·2^204
//
// After reduction each limb is in [0, 2^51).

type Fe = [u64; 5];

const MASK51: u64 = (1 << 51) - 1;

#[inline(always)]
fn fe_zero() -> Fe {
    [0; 5]
}

#[inline(always)]
fn fe_one() -> Fe {
    [1, 0, 0, 0, 0]
}

/// Propagate carries so every limb is in [0, 2^51), then canonically reduce
/// into [0, p-1] by subtracting p when h ≥ p.
///
/// Without the final subtraction, fe_sub(a,a) produces [p] rather than [0],
/// which would silently corrupt downstream arithmetic (e.g. x25519 of a
/// low-order point must return all-zero but wouldn't).
fn fe_reduce(h: &mut Fe) {
    for _ in 0..2 {
        let c0 = h[0] >> 51;
        h[0] &= MASK51;
        h[1] += c0;
        let c1 = h[1] >> 51;
        h[1] &= MASK51;
        h[2] += c1;
        let c2 = h[2] >> 51;
        h[2] &= MASK51;
        h[3] += c2;
        let c3 = h[3] >> 51;
        h[3] &= MASK51;
        h[4] += c3;
        let c4 = h[4] >> 51;
        h[4] &= MASK51;
        h[0] += 19 * c4;
    }
    // After two carry passes every limb is in [0, 2^51-1].
    // h ≥ p iff h[1..4] == MASK51 and h[0] ≥ p[0] = 2^51-19.
    // Branchless: (h[i]+1)>>51 == 1 iff h[i] == MASK51; (h[0]+19)>>51 == 1 iff h[0] ≥ p[0].
    let above = ((h[0].wrapping_add(19)) >> 51)
        & ((h[1].wrapping_add(1)) >> 51)
        & ((h[2].wrapping_add(1)) >> 51)
        & ((h[3].wrapping_add(1)) >> 51)
        & ((h[4].wrapping_add(1)) >> 51);
    // p = [2^51-19, 2^51-1, 2^51-1, 2^51-1, 2^51-1] = [MASK51-18, MASK51, ...]
    h[0] -= above * (MASK51 - 18);
    h[1] -= above * MASK51;
    h[2] -= above * MASK51;
    h[3] -= above * MASK51;
    h[4] -= above * MASK51;
}

fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [
        a[0] + b[0],
        a[1] + b[1],
        a[2] + b[2],
        a[3] + b[3],
        a[4] + b[4],
    ];
    fe_reduce(&mut r);
    r
}

fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    // Add 2p before subtracting to stay non-negative in u64.
    // 2·P[k]: for k=0 use 2*(2^51-19) = 2^52-38; for k>0 use 2*(2^51-1) = 2^52-2.
    let mut r = [
        a[0].wrapping_add(0xFFFFFFFFFFFDA).wrapping_sub(b[0]), // 2*(2^51-19)
        a[1].wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b[1]), // 2*(2^51-1)
        a[2].wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b[2]),
        a[3].wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b[3]),
        a[4].wrapping_add(0xFFFFFFFFFFFFE).wrapping_sub(b[4]),
    ];
    fe_reduce(&mut r);
    r
}

/// Multiplication mod p using u128 accumulators (explicit schoolbook).
fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let (a0, a1, a2, a3, a4) = (
        a[0] as u128,
        a[1] as u128,
        a[2] as u128,
        a[3] as u128,
        a[4] as u128,
    );
    let (b0, b1, b2, b3, b4) = (
        b[0] as u128,
        b[1] as u128,
        b[2] as u128,
        b[3] as u128,
        b[4] as u128,
    );
    // Pre-multiply high-degree b coefficients by 19 (from 2^255 ≡ 19 mod p).
    let b1_19 = 19 * b1;
    let b2_19 = 19 * b2;
    let b3_19 = 19 * b3;
    let b4_19 = 19 * b4;

    let mut t0 = a0 * b0 + a1 * b4_19 + a2 * b3_19 + a3 * b2_19 + a4 * b1_19;
    let mut t1 = a0 * b1 + a1 * b0 + a2 * b4_19 + a3 * b3_19 + a4 * b2_19;
    let mut t2 = a0 * b2 + a1 * b1 + a2 * b0 + a3 * b4_19 + a4 * b3_19;
    let mut t3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0 + a4 * b4_19;
    let mut t4 = a0 * b4 + a1 * b3 + a2 * b2 + a3 * b1 + a4 * b0;

    // Two-pass carry propagation (second pass handles 19·c4 overflow).
    for _ in 0..2 {
        let c = t0 >> 51;
        t0 &= MASK51 as u128;
        t1 += c;
        let c = t1 >> 51;
        t1 &= MASK51 as u128;
        t2 += c;
        let c = t2 >> 51;
        t2 &= MASK51 as u128;
        t3 += c;
        let c = t3 >> 51;
        t3 &= MASK51 as u128;
        t4 += c;
        let c = t4 >> 51;
        t4 &= MASK51 as u128;
        t0 += 19 * c;
    }

    [t0 as u64, t1 as u64, t2 as u64, t3 as u64, t4 as u64]
}

fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

/// Conditional swap: swap (a, b) when `swap == 1`; leave unchanged when `swap == 0`.
fn fe_cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
    let mask = swap.wrapping_neg(); // 0x0000…0000 or 0xFFFF…FFFF
    for i in 0..5 {
        let x = mask & (a[i] ^ b[i]);
        a[i] ^= x;
        b[i] ^= x;
    }
}

/// Inversion via Fermat: a^(p−2) mod p.
/// Addition chain from RFC 7748 / Bernstein 2006.
fn fe_invert(a: &Fe) -> Fe {
    let a2 = fe_sq(a);
    let a4 = fe_sq(&a2);
    let a8 = fe_sq(&a4);
    let a9 = fe_mul(a, &a8);
    let a11 = fe_mul(&a9, &a2);
    let a22 = fe_sq(&a11);
    let b5 = fe_mul(&a22, &a9); // a^(2^5 - 1)

    // a^(2^10 - 1)
    let mut t = b5;
    for _ in 0..5 {
        t = fe_sq(&t);
    }
    let b10 = fe_mul(&t, &b5);

    // a^(2^20 - 1)
    t = b10;
    for _ in 0..10 {
        t = fe_sq(&t);
    }
    let b20 = fe_mul(&t, &b10);

    // a^(2^40 - 1)
    t = b20;
    for _ in 0..20 {
        t = fe_sq(&t);
    }
    let b40 = fe_mul(&t, &b20);

    // a^(2^50 - 1)
    t = b40;
    for _ in 0..10 {
        t = fe_sq(&t);
    }
    let b50 = fe_mul(&t, &b10);

    // a^(2^100 - 1)
    t = b50;
    for _ in 0..50 {
        t = fe_sq(&t);
    }
    let b100 = fe_mul(&t, &b50);

    // a^(2^200 - 1)
    t = b100;
    for _ in 0..100 {
        t = fe_sq(&t);
    }
    let b200 = fe_mul(&t, &b100);

    // a^(2^250 - 1)
    t = b200;
    for _ in 0..50 {
        t = fe_sq(&t);
    }
    let b250 = fe_mul(&t, &b50);

    // a^(2^255 - 21)  → five more squarings then ×a^11
    t = b250;
    for _ in 0..5 {
        t = fe_sq(&t);
    }
    fe_mul(&t, &a11)
}

// ---------------------------------------------------------------------------
// Encoding / decoding
// ---------------------------------------------------------------------------

/// Decode 32 little-endian bytes into a field element.
fn fe_from_bytes(bytes: &[u8; 32]) -> Fe {
    let mut b = *bytes;
    b[31] &= 0x7F; // clear the unused high bit per RFC 7748

    // Load two 128-bit halves (bytes 0-15 and 16-31).
    let lo = u128::from_le_bytes(b[0..16].try_into().unwrap());
    let hi = u128::from_le_bytes(b[16..32].try_into().unwrap());

    // Unpack: the 255-bit value spans lo (bits 0-127) and hi (bits 128-255).
    // Limb widths: 51, 51, 51, 51, 51 bits from bit 0 upward.
    let h0 = lo & MASK51 as u128;
    let h1 = (lo >> 51) & MASK51 as u128;
    // h2 straddles the lo/hi boundary at bit 102:
    //   low 26 bits from lo >> 102, high 25 bits from hi & 0x1FFFFFF
    let h2 = ((lo >> 102) & 0x3FFFFFF) | ((hi & 0x1FFFFFF) << 26);
    let h3 = (hi >> 25) & MASK51 as u128;
    let h4 = (hi >> 76) & MASK51 as u128;

    [h0 as u64, h1 as u64, h2 as u64, h3 as u64, h4 as u64]
}

/// Encode a field element into 32 little-endian bytes (canonical form).
fn fe_to_bytes(h: &Fe) -> [u8; 32] {
    let mut f = *h;
    fe_reduce(&mut f);

    // Conditionally subtract p to reach fully-canonical form.
    // Add 19 and propagate; if the carry out of limb 4 is 1, f ≥ p.
    let mut g = f;
    g[0] = g[0].wrapping_add(19);
    let c0 = g[0] >> 51;
    g[0] &= MASK51;
    let c1 = (g[1] + c0) >> 51;
    g[1] = (g[1] + c0) & MASK51;
    let c2 = (g[2] + c1) >> 51;
    g[2] = (g[2] + c1) & MASK51;
    let c3 = (g[3] + c2) >> 51;
    g[3] = (g[3] + c2) & MASK51;
    g[4] = g[4].wrapping_add(c3);
    let high_bit = g[4] >> 51; // 1 if f ≥ p
    // Swap f and g when high_bit == 1 (i.e., f ≥ p, use the reduced g).
    fe_cswap(&mut f, &mut g, high_bit);
    fe_reduce(&mut f);

    // Pack 5×51-bit limbs into two u128s, then into 32 bytes.
    // lo  covers bits   0-127: limb0 (51b) | limb1 (51b) | limb2[0:25] (26b)
    // hi  covers bits 128-255: limb2[26:50] (25b) | limb3 (51b) | limb4 (51b)
    let lo: u128 = (f[0] as u128) | ((f[1] as u128) << 51) | (((f[2] as u128) & 0x3FFFFFF) << 102);

    let hi: u128 = ((f[2] as u128) >> 26) | ((f[3] as u128) << 25) | ((f[4] as u128) << 76);

    let mut out = [0u8; 32];
    out[0..16].copy_from_slice(&lo.to_le_bytes());
    out[16..32].copy_from_slice(&hi.to_le_bytes());
    out
}

// ---------------------------------------------------------------------------
// Montgomery ladder (RFC 7748 §5)
// ---------------------------------------------------------------------------

fn ladder(k: &[u8; 32], u: &Fe) -> Fe {
    // a24 = (A - 2) / 4 where A = 486662
    let a24: Fe = [121665, 0, 0, 0, 0];

    let x_1 = *u;
    let mut x_2 = fe_one();
    let mut z_2 = fe_zero();
    let mut x_3 = *u;
    let mut z_3 = fe_one();
    let mut swap: u64 = 0;

    // Iterate over bits 254 down to 0 (bit 255 is always 0 after clamping).
    for t in (0..255usize).rev() {
        let k_t = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= k_t;
        fe_cswap(&mut x_2, &mut x_3, swap);
        fe_cswap(&mut z_2, &mut z_3, swap);
        swap = k_t;

        let a = fe_add(&x_2, &z_2);
        let aa = fe_sq(&a);
        let b = fe_sub(&x_2, &z_2);
        let bb = fe_sq(&b);
        let e = fe_sub(&aa, &bb);
        let c = fe_add(&x_3, &z_3);
        let d = fe_sub(&x_3, &z_3);
        let da = fe_mul(&d, &a);
        let cb = fe_mul(&c, &b);

        x_3 = fe_sq(&fe_add(&da, &cb));
        z_3 = fe_mul(&x_1, &fe_sq(&fe_sub(&da, &cb)));
        x_2 = fe_mul(&aa, &bb);
        z_2 = fe_mul(&e, &fe_add(&aa, &fe_mul(&a24, &e)));
    }
    fe_cswap(&mut x_2, &mut x_3, swap);
    fe_cswap(&mut z_2, &mut z_3, swap);

    fe_mul(&x_2, &fe_invert(&z_2))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Apply RFC 7748 scalar clamping to a raw 32-byte private key.
///
/// - Clears the three low bits of byte 0 (cofactor clearing)
/// - Clears the high bit of byte 31 (keep scalar < 2^255)
/// - Sets the second-highest bit of byte 31 (fix scalar magnitude)
pub fn clamp_scalar(mut k: X25519PrivateKey) -> X25519PrivateKey {
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    k
}

/// Perform the X25519 DH function: scalar × public_key_point.
///
/// The scalar is clamped per RFC 7748 before use.
/// Returns the u-coordinate of the resulting point (little-endian).
pub fn x25519(private_key: X25519PrivateKey, public_key: X25519PublicKey) -> X25519SharedSecret {
    let k = clamp_scalar(private_key);
    let u = fe_from_bytes(&public_key);
    let result = ladder(&k, &u);
    fe_to_bytes(&result)
}

/// Compute the X25519 public key: scalar × basepoint.
pub fn x25519_basepoint(private_key: X25519PrivateKey) -> X25519PublicKey {
    x25519(private_key, X25519_BASEPOINT)
}

/// Return `true` if the shared secret is all-zero (low-order input point).
///
/// An all-zero shared secret indicates the peer provided a low-order point
/// and the session key material would be trivially guessable.
pub fn is_zero_shared_secret(secret: &X25519SharedSecret) -> bool {
    secret.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// Ephemeral keypair — forward-secrecy building block
// ---------------------------------------------------------------------------

/// An X25519 ephemeral keypair for use in forward-secret key exchange.
///
/// In production the private scalar **must** be generated by a CSPRNG.
/// Use `generate_ephemeral_from_seed` with a fixed seed for deterministic tests.
///
/// NON-PRODUCTION: the private field is intentionally opaque; callers use
/// `derive_ephemeral_shared` to compute the DH output without exposing the scalar.
pub struct EphemeralKeypair {
    private: X25519PrivateKey,
    /// The corresponding public key (u-coordinate) to send to the peer.
    pub public: X25519PublicKey,
}

/// Derive an ephemeral keypair deterministically from a 32-byte seed.
///
/// The seed is used directly as the private scalar; RFC 7748 scalar clamping
/// is applied inside `x25519_basepoint`.  For production use the seed **must**
/// come from a cryptographically-secure random number generator.
pub fn generate_ephemeral_from_seed(seed: &[u8; 32]) -> EphemeralKeypair {
    let private = *seed;
    let public = x25519_basepoint(private);
    EphemeralKeypair { private, public }
}

/// Compute the X25519 shared secret between `our` ephemeral key and `peer_pub`.
pub fn derive_ephemeral_shared(
    our: &EphemeralKeypair,
    peer_pub: &X25519PublicKey,
) -> X25519SharedSecret {
    x25519(our.private, *peer_pub)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // X1: RFC 7748 §6.1 — Alice's public key from her private key
    #[test]
    fn x1_rfc7748_alice_public_key() {
        let alice_priv: X25519PrivateKey = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let expected_pub: X25519PublicKey = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        assert_eq!(x25519_basepoint(alice_priv), expected_pub);
    }

    // X2: RFC 7748 §6.1 — Bob's public key from his private key
    #[test]
    fn x2_rfc7748_bob_public_key() {
        let bob_priv: X25519PrivateKey = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let expected_pub: X25519PublicKey = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4,
            0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14,
            0x6f, 0x88, 0x2b, 0x4f,
        ];
        assert_eq!(x25519_basepoint(bob_priv), expected_pub);
    }

    // X3: RFC 7748 §6.1 — Alice and Bob derive the same shared secret
    #[test]
    fn x3_rfc7748_shared_secret() {
        let alice_priv: X25519PrivateKey = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_priv: X25519PrivateKey = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80,
            0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27,
            0xff, 0x88, 0xe0, 0xeb,
        ];
        let alice_pub = x25519_basepoint(alice_priv);
        let bob_pub = x25519_basepoint(bob_priv);

        let shared_alice = x25519(alice_priv, bob_pub);
        let shared_bob = x25519(bob_priv, alice_pub);

        let expected: X25519SharedSecret = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35,
            0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c,
            0x1e, 0x16, 0x17, 0x42,
        ];
        assert_eq!(shared_alice, expected, "Alice shared secret mismatch");
        assert_eq!(shared_bob, expected, "Bob shared secret mismatch");
        assert_eq!(shared_alice, shared_bob);
    }

    // X4: scalar clamping sets/clears the correct bits
    #[test]
    fn x4_clamp_scalar() {
        let raw = [0xFFu8; 32];
        let c = clamp_scalar(raw);
        assert_eq!(c[0] & 0b0000_0111, 0, "low 3 bits of byte 0 must be zero");
        assert_eq!(c[31] & 0b1000_0000, 0, "high bit of byte 31 must be zero");
        assert_eq!(
            c[31] & 0b0100_0000,
            64,
            "second-high bit of byte 31 must be one"
        );
    }

    // X5: x25519 is symmetric — both parties derive the same secret
    #[test]
    fn x5_symmetric_dh() {
        let a_priv = [0x01u8; 32];
        let b_priv = [0x02u8; 32];
        let a_pub = x25519_basepoint(a_priv);
        let b_pub = x25519_basepoint(b_priv);
        let s_a = x25519(a_priv, b_pub);
        let s_b = x25519(b_priv, a_pub);
        assert_eq!(s_a, s_b);
        assert!(!is_zero_shared_secret(&s_a));
    }

    // X6: different peer keys produce different shared secrets
    #[test]
    fn x6_different_peers_different_secrets() {
        let a_priv = [0xAAu8; 32];
        let b_priv = [0xBBu8; 32];
        let c_priv = [0xCCu8; 32];
        let b_pub = x25519_basepoint(b_priv);
        let c_pub = x25519_basepoint(c_priv);
        assert_ne!(x25519(a_priv, b_pub), x25519(a_priv, c_pub));
    }

    // X7: all-zero public key (low-order point) yields all-zero shared secret
    #[test]
    fn x7_zero_public_key_gives_zero_secret() {
        let priv_key = [0x42u8; 32];
        let zero_pub = [0u8; 32];
        let secret = x25519(priv_key, zero_pub);
        assert!(
            is_zero_shared_secret(&secret),
            "scalar × 0 must give 0 (low-order point)"
        );
    }

    // X8: x25519 is deterministic
    #[test]
    fn x8_deterministic() {
        let priv_key = [0x7Au8; 32];
        let pub_key = x25519_basepoint([0x3Eu8; 32]);
        assert_eq!(x25519(priv_key, pub_key), x25519(priv_key, pub_key));
    }

    // X9: public key output is exactly 32 bytes
    #[test]
    fn x9_public_key_size() {
        let k = x25519_basepoint([0x11u8; 32]);
        assert_eq!(k.len(), 32);
    }

    // X10: shared secret output is exactly 32 bytes
    #[test]
    fn x10_shared_secret_size() {
        let s = x25519([0x05u8; 32], x25519_basepoint([0x06u8; 32]));
        assert_eq!(s.len(), 32);
    }

    // X11: no panic on all-zero scalar (clamping makes it valid: k[31] = 64)
    #[test]
    fn x11_zero_scalar_no_panic() {
        let _ = x25519([0u8; 32], X25519_BASEPOINT);
    }

    // X12: no panic on all-0xFF scalar
    #[test]
    fn x12_max_scalar_no_panic() {
        let _ = x25519([0xFFu8; 32], X25519_BASEPOINT);
    }

    // X13: x25519_basepoint == x25519(k, BASEPOINT)
    #[test]
    fn x13_basepoint_consistency() {
        let k = [0x1Cu8; 32];
        assert_eq!(x25519_basepoint(k), x25519(k, X25519_BASEPOINT));
    }

    // X14: is_zero_shared_secret correctly passes non-zero secrets
    #[test]
    fn x14_nonzero_secret_not_flagged() {
        let s = x25519([0x01u8; 32], x25519_basepoint([0x02u8; 32]));
        assert!(!is_zero_shared_secret(&s));
    }

    // FS1: two distinct seeds produce distinct ephemeral keypairs
    #[test]
    fn fs1_different_seeds_give_different_keypairs() {
        let kp1 = generate_ephemeral_from_seed(&[0x11u8; 32]);
        let kp2 = generate_ephemeral_from_seed(&[0x22u8; 32]);
        assert_ne!(
            kp1.public, kp2.public,
            "distinct seeds must yield distinct public keys"
        );
    }

    // FS2: ephemeral DH is symmetric — both parties compute the same shared secret
    #[test]
    fn fs2_ephemeral_dh_symmetric() {
        let alice = generate_ephemeral_from_seed(&[0x33u8; 32]);
        let bob = generate_ephemeral_from_seed(&[0x44u8; 32]);
        let s_a = derive_ephemeral_shared(&alice, &bob.public);
        let s_b = derive_ephemeral_shared(&bob, &alice.public);
        assert_eq!(s_a, s_b, "ephemeral DH must be symmetric");
        assert!(!is_zero_shared_secret(&s_a));
    }

    // FS3: traffic encrypted under new session keys cannot be decrypted with old keys
    #[test]
    fn fs3_old_session_cannot_decrypt_new_traffic() {
        use crate::crypto::SessionKeys;
        let old_key = [0x55u8; 32];
        let new_key = [0x66u8; 32];

        let mut new_sender = SessionKeys::new(new_key, new_key);
        let old_receiver = SessionKeys::new(old_key, old_key);

        let ct = new_sender
            .encrypt_packet(b"", b"new session traffic")
            .unwrap();
        // Old session keys must not be able to decrypt the new-key ciphertext.
        assert!(
            old_receiver.decrypt_packet(b"", 0, &ct).is_err(),
            "old session keys must not decrypt new-session traffic"
        );
    }
}
