use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tracing::{error, info, warn};

use crate::auth::verify_hello_mac;
use crate::metrics::METRICS;
use crate::packet::{Frame, MessageType, parse_frame};

/// Authentication mode for the UDP receive loop.
pub enum AuthMode {
    /// All Hello frames must carry a valid HMAC-SHA256 token.
    Psk([u8; 32]),
    /// Accept all frames without authentication.
    /// Only valid when `LIBERTY_ALLOW_UNAUTHENTICATED_DEV=1`. Never for production.
    DevAllowAll,
}

/// Outcome of processing one received UDP datagram.
/// Determines which counter to increment and whether to log acceptance.
pub(crate) enum FrameAction {
    Accept(Frame),
    AuthFail { session_id: u64 },
    ParseFail,
}

/// Determine how to handle a raw UDP buffer given the current auth mode.
///
/// Pure function — no side effects, no global state. All counter updates
/// and logging happen in `run_udp` after inspecting the returned action.
///
/// Counter semantics:
/// - `Accept`    → `packets_rx` and `bytes_rx` increment
/// - `AuthFail`  → `auth_failures` increments; `packets_rx`/`bytes_rx` do NOT
/// - `ParseFail` → `parse_errors` increments; `packets_rx`/`bytes_rx` do NOT
pub(crate) fn process_received(buf: &[u8], auth: &AuthMode) -> FrameAction {
    let frame = match parse_frame(buf) {
        Ok(f) => f,
        Err(_) => return FrameAction::ParseFail,
    };

    match frame.msg_type {
        MessageType::Hello => match auth {
            AuthMode::Psk(psk) => {
                if verify_hello_mac(psk, frame.session_id, frame.sequence, &frame.payload) {
                    FrameAction::Accept(frame)
                } else {
                    FrameAction::AuthFail {
                        session_id: frame.session_id,
                    }
                }
            }
            AuthMode::DevAllowAll => FrameAction::Accept(frame),
        },
        // Data / Keepalive / Close: per-frame authentication is deferred to v0.6 Noise XX.
        _ => FrameAction::Accept(frame),
    }
}

pub async fn run_udp(socket: UdpSocket, auth: AuthMode) {
    let mut buf = vec![0u8; 65_535];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, peer)) => match process_received(&buf[..len], &auth) {
                FrameAction::Accept(frame) => {
                    METRICS.packets_rx.fetch_add(1, Ordering::Relaxed);
                    METRICS.bytes_rx.fetch_add(len as u64, Ordering::Relaxed);
                    match frame.msg_type {
                        MessageType::Hello => {
                            info!(
                                peer = %peer,
                                session = frame.session_id,
                                "Hello frame received"
                            );
                        }
                        MessageType::Data => {
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
                            info!(
                                peer = %peer,
                                session = frame.session_id,
                                "Close frame received"
                            );
                        }
                    }
                }
                FrameAction::AuthFail { session_id } => {
                    METRICS.auth_failures.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        peer = %peer,
                        session = session_id,
                        "Hello auth failure — MAC invalid, frame rejected"
                    );
                }
                FrameAction::ParseFail => {
                    METRICS.parse_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(peer = %peer, "frame parse error — packet dropped");
                }
            },
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
                // Drain the incoming HTTP request before responding.
                // Without this, Windows sends RST instead of FIN when the socket closes,
                // because there is unread data in the receive buffer at close time.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::compute_hello_mac;
    use crate::packet::{Frame, MessageType, VERSION_1, encode_frame};

    const PSK: [u8; 32] = [0x42u8; 32];
    const ALT_PSK: [u8; 32] = [0x11u8; 32];

    fn encode_hello(session_id: u64, sequence: u64, payload: Vec<u8>) -> Vec<u8> {
        let frame = Frame {
            version: VERSION_1,
            msg_type: MessageType::Hello,
            flags: 0,
            session_id,
            sequence,
            payload,
        };
        let mut buf = Vec::new();
        encode_frame(&frame, &mut buf).unwrap();
        buf
    }

    fn auth_payload(session_id: u64, sequence: u64, original: &[u8]) -> Vec<u8> {
        let mac = compute_hello_mac(&PSK, session_id, sequence, original);
        let mut p = mac.to_vec();
        p.extend_from_slice(original);
        p
    }

    // --- PSK mode: Hello frame acceptance ---

    #[test]
    fn valid_psk_hello_accepted() {
        let payload = auth_payload(1, 1, b"hello");
        let buf = encode_hello(1, 1, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::Accept(_)
        ));
    }

    #[test]
    fn valid_psk_hello_empty_original_accepted() {
        let payload = auth_payload(7, 99, b"");
        let buf = encode_hello(7, 99, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::Accept(_)
        ));
    }

    // --- PSK mode: Hello frame auth failures ---

    #[test]
    fn invalid_mac_hello_auth_fails() {
        let mut payload = vec![0u8; 32]; // all-zero MAC — invalid
        payload.extend_from_slice(b"hello");
        let buf = encode_hello(1, 1, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    #[test]
    fn missing_mac_payload_too_short_auth_fails() {
        // Payload only 16 bytes — shorter than MAC_LEN (32)
        let buf = encode_hello(1, 1, vec![0u8; 16]);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    #[test]
    fn empty_payload_auth_fails() {
        let buf = encode_hello(1, 1, vec![]);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    #[test]
    fn mac_for_wrong_session_id_auth_fails() {
        // MAC computed for session=1, but frame says session=2
        let payload = auth_payload(1, 1, b"hello");
        let buf = encode_hello(2, 1, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    #[test]
    fn mac_for_wrong_sequence_auth_fails() {
        let payload = auth_payload(1, 1, b"hello");
        let buf = encode_hello(1, 2, payload); // sequence mismatch
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    #[test]
    fn mac_from_alt_psk_auth_fails() {
        // MAC computed with ALT_PSK — rejected by server using PSK
        let mac = compute_hello_mac(&ALT_PSK, 1, 1, b"hello");
        let mut payload = mac.to_vec();
        payload.extend_from_slice(b"hello");
        let buf = encode_hello(1, 1, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::AuthFail { .. }
        ));
    }

    // --- DevAllowAll mode ---

    #[test]
    fn dev_mode_hello_without_mac_accepted() {
        let buf = encode_hello(1, 1, b"hello".to_vec());
        assert!(matches!(
            process_received(&buf, &AuthMode::DevAllowAll),
            FrameAction::Accept(_)
        ));
    }

    #[test]
    fn dev_mode_hello_with_mac_also_accepted() {
        // Even with a MAC present, dev mode just accepts it
        let payload = auth_payload(1, 1, b"hello");
        let buf = encode_hello(1, 1, payload);
        assert!(matches!(
            process_received(&buf, &AuthMode::DevAllowAll),
            FrameAction::Accept(_)
        ));
    }

    // --- Parse failures (malformed frames) ---

    #[test]
    fn malformed_bytes_parse_fail() {
        assert!(matches!(
            process_received(&[0xDE, 0xAD, 0xBE, 0xEF], &AuthMode::Psk(PSK)),
            FrameAction::ParseFail
        ));
    }

    #[test]
    fn empty_buffer_parse_fail() {
        assert!(matches!(
            process_received(&[], &AuthMode::Psk(PSK)),
            FrameAction::ParseFail
        ));
    }

    #[test]
    fn bad_version_parse_fail() {
        // 22-byte header with version=99
        let mut buf = vec![0u8; 22];
        buf[0] = 99;
        buf[1] = 1; // Hello msg_type
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::ParseFail
        ));
    }

    // --- Non-Hello frames (auth deferred to v0.6) ---

    #[test]
    fn data_frame_accepted_in_psk_mode() {
        let frame = Frame {
            version: VERSION_1,
            msg_type: MessageType::Data,
            flags: 0,
            session_id: 1,
            sequence: 1,
            payload: b"data".to_vec(),
        };
        let mut buf = Vec::new();
        encode_frame(&frame, &mut buf).unwrap();
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::Accept(_)
        ));
    }

    #[test]
    fn keepalive_accepted_in_psk_mode() {
        let frame = Frame {
            version: VERSION_1,
            msg_type: MessageType::Keepalive,
            flags: 0,
            session_id: 1,
            sequence: 0,
            payload: vec![],
        };
        let mut buf = Vec::new();
        encode_frame(&frame, &mut buf).unwrap();
        assert!(matches!(
            process_received(&buf, &AuthMode::Psk(PSK)),
            FrameAction::Accept(_)
        ));
    }
}
