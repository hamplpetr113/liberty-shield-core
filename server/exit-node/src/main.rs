mod config;
mod metrics;
mod packet;
mod server;

use tokio::net::UdpSocket;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    let log_level = std::env::var("LIBERTY_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt().with_env_filter(log_level).init();

    let cfg = config::Config::from_env();

    info!(bind = %cfg.bind_addr, "Liberty Exit Node starting");
    info!(health = %cfg.health_bind, "health endpoint starting");

    if !cfg.psk_present {
        warn!("LIBERTY_PSK not set — running without authentication (skeleton mode only)");
    }

    let socket = UdpSocket::bind(cfg.bind_addr)
        .await
        .expect("failed to bind UDP socket");

    info!("packet receive loop running");

    tokio::select! {
        _ = server::run_udp(socket) => {},
        _ = server::run_health(cfg.health_bind) => {},
    }
}
