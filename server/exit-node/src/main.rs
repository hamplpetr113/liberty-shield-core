// Liberty Shield — Exit Node (v0.5 skeleton)
//
// NOT FUNCTIONAL. This file establishes the entry point, configuration loading,
// and placeholder receive loop. Actual packet forwarding, session management,
// and cryptography are TODOs listed below.
//
// TODO: Noise XX handshake for authenticated key exchange
// TODO: client session registry (peer addr → session keys + nonce counter)
// TODO: replay window / nonce deduplication
// TODO: packet framing (version byte + length prefix + encrypted payload)
// TODO: NAT / TUN fd for exit forwarding to public internet
// TODO: pre-shared key (PSK) loading from LIBERTY_PSK env var (never hardcoded)
// TODO: health HTTP endpoint on LIBERTY_EXIT_HEALTH_BIND
// TODO: metrics: packets_rx, packets_tx, active_sessions, errors
// TODO: graceful SIGTERM / SIGINT shutdown

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{error, info, warn};

#[tokio::main]
async fn main() {
    // Logging — respects LIBERTY_LOG_LEVEL or RUST_LOG
    let log_level = std::env::var("LIBERTY_LOG_LEVEL")
        .or_else(|_| std::env::var("RUST_LOG"))
        .unwrap_or_else(|_| "info".to_string());
    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .init();

    let bind_addr: SocketAddr = std::env::var("LIBERTY_EXIT_BIND")
        .unwrap_or_else(|_| "0.0.0.0:51820".to_string())
        .parse()
        .expect("LIBERTY_EXIT_BIND must be a valid socket address (e.g. 0.0.0.0:51820)");

    let health_bind: SocketAddr = std::env::var("LIBERTY_EXIT_HEALTH_BIND")
        .unwrap_or_else(|_| "127.0.0.1:8081".to_string())
        .parse()
        .expect("LIBERTY_EXIT_HEALTH_BIND must be a valid socket address");

    info!(bind = %bind_addr, "Liberty Exit Node starting");
    info!(health = %health_bind, "health endpoint placeholder (not yet implemented)");

    // TODO: load LIBERTY_PSK from environment, validate length, never log value
    if std::env::var("LIBERTY_PSK").is_err() {
        warn!("LIBERTY_PSK not set — running without authentication (skeleton mode only)");
    }

    let socket = UdpSocket::bind(bind_addr)
        .await
        .expect("failed to bind UDP socket");

    info!("packet receive loop running — skeleton, no forwarding yet");

    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                // TODO: authenticate packet (check PSK / Noise session)
                // TODO: look up or create client session for peer
                // TODO: decrypt + deframe packet
                // TODO: validate replay window
                // TODO: forward decapsulated IP packet via TUN/NAT
                info!(peer = %peer, bytes = len, "received packet (drop — no forwarding yet)");
            }
            Err(e) => {
                error!(error = %e, "recv_from error");
            }
        }
    }
}
