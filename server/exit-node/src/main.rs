use liberty_exit_node::config::Config;
use liberty_exit_node::server::{self, AuthMode};
use tokio::net::UdpSocket;
use tracing::{error, info};

#[tokio::main]
async fn main() {
    let log_level = std::env::var("LIBERTY_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let cfg = Config::from_env();

    let auth = match (cfg.psk, cfg.dev_mode) {
        (Some(psk), _) => {
            info!("auth: HMAC-SHA256 PSK");
            AuthMode::Psk(psk)
        }
        (None, true) => {
            info!("auth: LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1 — all frames accepted (dev only)");
            AuthMode::DevAllowAll
        }
        (None, false) => {
            error!(
                "LIBERTY_PSK is not set and LIBERTY_ALLOW_UNAUTHENTICATED_DEV is not set. \
                 Set LIBERTY_PSK to a 64-hex-character 32-byte key, or set \
                 LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1 for local development only."
            );
            std::process::exit(1);
        }
    };

    info!(bind = %cfg.bind_addr, "Liberty Exit Node starting");

    let socket = UdpSocket::bind(cfg.bind_addr)
        .await
        .expect("failed to bind UDP socket");

    info!("packet receive loop running");

    tokio::select! {
        _ = server::run_udp(socket, auth) => {},
        _ = server::run_health(cfg.health_bind) => {},
    }
}
