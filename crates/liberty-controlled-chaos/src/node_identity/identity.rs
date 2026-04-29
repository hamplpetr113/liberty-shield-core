//! `NodeIdentity` — a node's long-term keypair and derived identifier.
//!
//! NON-PRODUCTION: `generate()` uses a time + PID seed. Replace with a
//! CSPRNG before any deployed use.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::{
    X25519PrivateKey, X25519PublicKey, generate_ephemeral_from_seed, sha256, x25519_basepoint,
};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from node identity operations.
#[derive(Debug, PartialEq)]
pub enum IdentityError {
    /// Hex string had an odd number of characters.
    BadHexLength,
    /// Hex string contained a non-hex character.
    BadHexChar,
    /// Decoded bytes were the wrong length.
    WrongKeyLength,
    /// JSON was malformed or a required field was missing.
    BadJson,
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::BadHexLength => write!(f, "hex string has odd length"),
            IdentityError::BadHexChar => write!(f, "invalid hex character"),
            IdentityError::WrongKeyLength => write!(f, "decoded key is the wrong length"),
            IdentityError::BadJson => write!(f, "malformed JSON or missing field"),
        }
    }
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

pub(super) fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(super) fn from_hex(s: &str) -> Result<Vec<u8>, IdentityError> {
    if !s.len().is_multiple_of(2) {
        return Err(IdentityError::BadHexLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<char> = s.chars().collect();
    for pair in chars.chunks(2) {
        let hi = pair[0].to_digit(16).ok_or(IdentityError::BadHexChar)?;
        let lo = pair[1].to_digit(16).ok_or(IdentityError::BadHexChar)?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

pub(super) fn from_hex_32(s: &str) -> Result<[u8; 32], IdentityError> {
    let bytes = from_hex(s)?;
    bytes.try_into().map_err(|_| IdentityError::WrongKeyLength)
}

// ---------------------------------------------------------------------------
// NodeIdentity
// ---------------------------------------------------------------------------

/// A node's long-term identity: X25519 keypair + SHA-256 node identifier.
#[derive(Clone, Debug, PartialEq)]
pub struct NodeIdentity {
    /// SHA-256 of the public key — the canonical node identifier.
    pub node_id: [u8; 32],
    /// Long-term X25519 private key.
    pub private_key: X25519PrivateKey,
    /// Long-term X25519 public key.
    pub public_key: X25519PublicKey,
}

impl NodeIdentity {
    /// Derive a `NodeIdentity` from a raw 32-byte seed.
    ///
    /// Deterministic: identical seeds produce identical identities.
    /// Useful for tests and reproducible setups.
    pub fn generate_from_seed(seed: [u8; 32]) -> Self {
        let kp = generate_ephemeral_from_seed(&seed);
        let public_key = kp.public;
        let private_key = seed; // seed is the private scalar (clamping applied on use)
        let node_id = sha256(&public_key);
        Self {
            node_id,
            private_key,
            public_key,
        }
    }

    /// Generate a fresh `NodeIdentity` using a time + PID seed.
    ///
    /// NON-PRODUCTION: not cryptographically random. For tests or local nodes only.
    pub fn generate() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let pid = std::process::id() as u64;
        let mut seed_input = [0u8; 16];
        seed_input[0..8].copy_from_slice(&nanos.to_le_bytes());
        seed_input[8..16].copy_from_slice(&pid.to_le_bytes());
        let seed = sha256(&seed_input);
        Self::generate_from_seed(seed)
    }

    /// Verify that `node_id == SHA256(public_key)`.
    pub fn is_valid(&self) -> bool {
        sha256(&self.public_key) == self.node_id
    }

    /// Serialize to a compact JSON object (no external dependencies).
    ///
    /// Fields: `node_id`, `private_key`, `public_key` — all hex-encoded.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"node_id\":\"{}\",\"private_key\":\"{}\",\"public_key\":\"{}\"}}",
            to_hex(&self.node_id),
            to_hex(&self.private_key),
            to_hex(&self.public_key),
        )
    }

    /// Deserialize from JSON produced by `to_json`.
    pub fn from_json(json: &str) -> Result<Self, IdentityError> {
        let node_id = extract_json_field(json, "node_id")?;
        let private_key = extract_json_field(json, "private_key")?;
        let public_key = extract_json_field(json, "public_key")?;

        Ok(Self {
            node_id: from_hex_32(&node_id)?,
            private_key: from_hex_32(&private_key)?,
            public_key: from_hex_32(&public_key)?,
        })
    }

    /// Re-derive the public key from the private key and confirm it matches.
    pub fn check_keypair_consistency(&self) -> bool {
        let expected_pub = x25519_basepoint(self.private_key);
        expected_pub == self.public_key
    }
}

// ---------------------------------------------------------------------------
// JSON field extractor
// ---------------------------------------------------------------------------

/// Pull the string value of `field` from a flat JSON object.
///
/// Looks for `"field":"<value>"` and returns `<value>`.
fn extract_json_field(json: &str, field: &str) -> Result<String, IdentityError> {
    let key = format!("\"{field}\":\"");
    let start = json.find(&key).ok_or(IdentityError::BadJson)?;
    let value_start = start + key.len();
    let rest = &json[value_start..];
    let end = rest.find('"').ok_or(IdentityError::BadJson)?;
    Ok(rest[..end].to_string())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // NI1: generate() creates a valid identity (node_id = SHA256(public_key)).
    #[test]
    fn ni1_generate_valid_identity() {
        let id = NodeIdentity::generate();
        assert!(id.is_valid(), "node_id must equal SHA256(public_key)");
    }

    // NI2: node_id is exactly SHA256(public_key).
    #[test]
    fn ni2_node_id_derivation() {
        let seed = [0x42u8; 32];
        let id = NodeIdentity::generate_from_seed(seed);
        assert_eq!(id.node_id, sha256(&id.public_key));
    }

    // NI3: generate_from_seed is deterministic.
    #[test]
    fn ni3_deterministic_from_seed() {
        let seed = [0x7Fu8; 32];
        let a = NodeIdentity::generate_from_seed(seed);
        let b = NodeIdentity::generate_from_seed(seed);
        assert_eq!(a.node_id, b.node_id);
        assert_eq!(a.private_key, b.private_key);
        assert_eq!(a.public_key, b.public_key);
    }

    // NI4: to_json / from_json round-trip.
    #[test]
    fn ni4_json_roundtrip() {
        let seed = [0x11u8; 32];
        let original = NodeIdentity::generate_from_seed(seed);
        let json = original.to_json();
        let restored = NodeIdentity::from_json(&json).expect("from_json failed");
        assert_eq!(original.node_id, restored.node_id);
        assert_eq!(original.private_key, restored.private_key);
        assert_eq!(original.public_key, restored.public_key);
    }

    // NI5: different seeds produce different identities.
    #[test]
    fn ni5_different_seeds_differ() {
        let a = NodeIdentity::generate_from_seed([0x01u8; 32]);
        let b = NodeIdentity::generate_from_seed([0x02u8; 32]);
        assert_ne!(a.node_id, b.node_id);
        assert_ne!(a.public_key, b.public_key);
    }

    // NI6: public_key is the X25519 basepoint scalar product of private_key.
    #[test]
    fn ni6_keypair_consistency() {
        let seed = [0x55u8; 32];
        let id = NodeIdentity::generate_from_seed(seed);
        assert!(id.check_keypair_consistency());
    }

    // NI7: from_json rejects empty / malformed input.
    #[test]
    fn ni7_from_json_rejects_malformed() {
        assert_eq!(NodeIdentity::from_json("{}"), Err(IdentityError::BadJson));
        assert_eq!(
            NodeIdentity::from_json("not json"),
            Err(IdentityError::BadJson)
        );
        assert_eq!(
            NodeIdentity::from_json("{\"node_id\":\"gg\"}"),
            Err(IdentityError::BadJson) // missing private_key + public_key
        );
    }

    // NI8: hex helpers round-trip correctly.
    #[test]
    fn ni8_hex_roundtrip() {
        let bytes = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF];
        let hex = to_hex(&bytes);
        assert_eq!(hex, "deadbeef00ff");
        let back = from_hex(&hex).unwrap();
        assert_eq!(back, bytes);
    }

    // NI9: from_hex rejects odd-length and non-hex strings.
    #[test]
    fn ni9_hex_error_cases() {
        assert_eq!(from_hex("abc"), Err(IdentityError::BadHexLength));
        assert_eq!(from_hex("zz"), Err(IdentityError::BadHexChar));
    }

    // NI10: generate() calls do not produce duplicate identities (time differs).
    #[test]
    fn ni10_generate_not_duplicate() {
        let a = NodeIdentity::generate();
        let b = NodeIdentity::generate();
        // With overwhelming probability (different nanosecond timestamps) these differ.
        // If they somehow collide the test fails safely rather than silently.
        assert_ne!(a.public_key, b.public_key);
    }
}
