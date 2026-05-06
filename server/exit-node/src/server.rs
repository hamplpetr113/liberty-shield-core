use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

use crate::metrics::METRICS;
use crate::packet::{MessageType, parse_frame};

pub async fn run_udp(socket: UdpSocket) {
    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => {
                METRICS.packets_rx.fetch_add(1, Ordering::Relaxed);
                METRICS.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);

                match parse_frame(&buf[..len]) {
                    Ok(frame) => {
                        match frame.msg_type {
                            MessageType::Hello => {
                                info!(peer = %peer, session = frame.session_id, "Hello frame received (no auth yet)");
                            }
                            MessageType::Data => {
                                // TODO: decrypt + validate replay window + forward via TUN
                                info!(
                                    peer = %peer,
                                    session = frame.session_id,
                                    seq = frame.sequence,
                                    payload_bytes = frame.payload.len(),
                                    "Data frame received (drop — no forwarding yet)"
                                );
                            }
                            MessageType::Keepalive => {
                                info!(peer = %peer, session = frame.session_id, "Keepalive");
                            }
                            MessageType::Close => {
                                info!(peer = %peer, session = frame.session_id, "Close frame received");
                            }
                        }
                    }
                    Err(e) => {
                        METRICS.parse_errors.fetch_add(1, Ordering::Relaxed);
                        warn!(peer = %peer, error = %e, "frame parse error — packet dropped");
                    }
                }
            }
            Err(e) => {
                error!(error = %e, "recv_from error");
            }
        }
    }
}

pub async fn run_health(bind: SocketAddr) {
    let listener = match TcpListener::bind(bind).await {
        Ok(l) => {
            info!(health = %bind, "health endpoint listening");
            l
        }
        Err(e) => {
            error!(error = %e, bind = %bind, "failed to bind health endpoint");
            return;
        }
    };

    loop {
        match listener.accept().await {
            Ok((mut stream, _)) => {
                // Drain the HTTP request so the receive buffer is empty before close.
                // Without this, Windows sends RST instead of FIN when the socket closes.
                let mut req_buf = [0u8; 2048];
                let _ = tokio::time::timeout(
                    std::time::Duration::from_millis(50),
                    stream.read(&mut req_buf),
                )
                .await;

                let snap = METRICS.snapshot();
                let body = format!(
                    "{{\"status\":\"ok\",\"packets_rx\":{},\"packets_tx\":{},\
                     \"bytes_rx\":{},\"bytes_tx\":{},\"active_sessions\":{},\
                     \"parse_errors\":{},\"auth_failures\":{}}}",
                    snap.packets_rx,
                    snap.packets_tx,
                    snap.bytes_rx,
                    snap.bytes_tx,
                    snap.active_sessions,
                    snap.parse_errors,
                    snap.auth_failures,
                );
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body,
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
            Err(e) => {
                error!(error = %e, "health endpoint accept error");
            }
        }
    }
}
