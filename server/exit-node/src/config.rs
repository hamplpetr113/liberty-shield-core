use std::net::SocketAddr;

pub struct Config {
    pub bind_addr: SocketAddr,
    pub health_bind: SocketAddr,
    pub psk_present: bool,
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

        let psk_present = std::env::var("LIBERTY_PSK").is_ok();

        Self {
            bind_addr,
            health_bind,
            psk_present,
        }
    }
}
