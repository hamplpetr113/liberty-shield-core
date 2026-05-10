use std::net::SocketAddr;

pub struct Config {
    pub bind_addr: SocketAddr,
    pub health_bind: SocketAddr,
    /// Parsed PSK. `None` only when `dev_mode` is true.
    /// In production mode, `None` causes startup to fail.
    pub psk: Option<[u8; 32]>,
    /// True when `LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1` is set.
    /// Must never be enabled on a production node.
    pub dev_mode: bool,
}

/// Returns true only when the env var value is exactly `"1"`.
/// Any other value ("0", "false", "true", "", unset) leaves dev mode disabled.
pub fn parse_dev_mode(val: Option<&str>) -> bool {
    val == Some("1")
}

/// Parse a hex-encoded 32-byte PSK string.
/// Panics with a clear message on invalid input — intended for startup validation only.
/// The PSK value is never stored as a string after this call.
pub fn parse_psk(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("LIBERTY_PSK must be valid hex");
    bytes
        .try_into()
        .expect("LIBERTY_PSK must be exactly 32 bytes (64 hex characters)")
}

impl Config {
    pub fn from_env() -> Self {
        let bind_addr: SocketAddr = std::env::var("LIBERTY_EXIT_BIND")
            .unwrap_or_else(|_| "0.0.0.0:51820".to_string())
            .parse()
            .expect("LIBERTY_EXIT_BIND must be a valid socket address (e.g. 0.0.0.0:51820)");

        let health_bind: SocketAddr = std::env::var("LIBERTY_EXIT_HEALTH_BIND")
            .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
            .parse()
            .expect("LIBERTY_EXIT_HEALTH_BIND must be a valid socket address");

        let dev_mode = parse_dev_mode(
            std::env::var("LIBERTY_ALLOW_UNAUTHENTICATED_DEV")
                .ok()
                .as_deref(),
        );
        let psk = std::env::var("LIBERTY_PSK").ok().map(|v| parse_psk(&v));

        Self {
            bind_addr,
            health_bind,
            psk,
            dev_mode,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_psk_parsed() {
        let hex = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2";
        let psk = parse_psk(hex);
        assert_eq!(psk[0], 0xa1);
        assert_eq!(psk[1], 0xb2);
        assert_eq!(psk.len(), 32);
    }

    #[test]
    fn all_zeroes_psk_parsed() {
        let hex = "0".repeat(64);
        let psk = parse_psk(&hex);
        assert_eq!(psk, [0u8; 32]);
    }

    #[test]
    fn all_ff_psk_parsed() {
        let hex = "f".repeat(64);
        let psk = parse_psk(&hex);
        assert_eq!(psk, [0xFFu8; 32]);
    }

    #[test]
    #[should_panic(expected = "exactly 32 bytes")]
    fn psk_too_short_panics() {
        parse_psk("aabbcc"); // only 3 bytes
    }

    #[test]
    #[should_panic(expected = "exactly 32 bytes")]
    fn psk_too_long_panics() {
        parse_psk(&"aa".repeat(33)); // 33 bytes
    }

    #[test]
    #[should_panic(expected = "valid hex")]
    fn psk_non_hex_panics() {
        parse_psk("gghhiijjkkllmmnnooppqqrrssttuuvvwwxxyyzz00112233445566778899aabb");
    }

    // ── dev_mode parsing ──────────────────────────────────────────────────────

    #[test]
    fn dev_mode_enabled_for_exact_one() {
        assert!(parse_dev_mode(Some("1")));
    }

    #[test]
    fn dev_mode_disabled_when_not_set() {
        assert!(!parse_dev_mode(None));
    }

    #[test]
    fn dev_mode_disabled_for_zero() {
        assert!(!parse_dev_mode(Some("0")));
    }

    #[test]
    fn dev_mode_disabled_for_false() {
        assert!(!parse_dev_mode(Some("false")));
    }

    #[test]
    fn dev_mode_disabled_for_true() {
        assert!(!parse_dev_mode(Some("true")));
    }

    #[test]
    fn dev_mode_disabled_for_empty_string() {
        assert!(!parse_dev_mode(Some("")));
    }

    #[test]
    fn dev_mode_disabled_for_yes() {
        assert!(!parse_dev_mode(Some("yes")));
    }
}
