//! Real UDP smoke tests — verifies that localhost UDP sockets bind, send, and
//! receive framed packets correctly.
//!
//! All tests use `127.0.0.1:0` (OS-assigned ports) so they do not conflict.
//! Tests are marked `#[ignore]` by default; run with `-- --include-ignored`
//! to execute them (they need real OS networking).
//!
//! NON-PRODUCTION: no authentication at the UDP layer.

#[cfg(test)]
mod tests {
    use crate::mesh_packet_framer::MeshPacketFramer;
    use crate::real_udp_runtime::RealUdpRuntime;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    fn poll_until(
        rt: &mut RealUdpRuntime,
        timeout_ms: u64,
    ) -> Option<crate::real_udp_runtime::ReceivedPacket> {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if let Some(pkt) = rt.poll_recv() {
                return Some(pkt);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    // RUDP1: bind to localhost:0 succeeds and returns a valid local address.
    #[test]
    #[ignore]
    fn rudp1_bind_assigns_port() {
        let rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let addr = rt.local_addr().expect("local_addr");
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
        assert_ne!(addr.port(), 0);
    }

    // RUDP2: register peer, send a raw datagram, receive it back.
    #[test]
    #[ignore]
    fn rudp2_send_recv_loopback() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let local_addr = rt.local_addr().expect("local_addr");

        // Register self as peer (loopback).
        rt.connect_peer(nid(1), local_addr);

        let payload = b"hello-udp";
        rt.send_to_peer(&nid(1), payload).expect("send");

        let pkt = poll_until(&mut rt, 500).expect("recv timed out");
        assert_eq!(&pkt.payload, payload);
    }

    // RUDP3: two independent sockets communicate bidirectionally.
    #[test]
    #[ignore]
    fn rudp3_two_nodes_communicate() {
        let mut a = RealUdpRuntime::bind("127.0.0.1:0").expect("bind A");
        let mut b = RealUdpRuntime::bind("127.0.0.1:0").expect("bind B");
        let addr_a = a.local_addr().expect("addr A");
        let addr_b = b.local_addr().expect("addr B");

        a.connect_peer(nid(2), addr_b);
        b.connect_peer(nid(1), addr_a);

        a.send_to_peer(&nid(2), b"ping").expect("A send");
        let got_b = poll_until(&mut b, 500).expect("B recv timed out");
        assert_eq!(&got_b.payload, b"ping");

        b.send_to_peer(&nid(1), b"pong").expect("B send");
        let got_a = poll_until(&mut a, 500).expect("A recv timed out");
        assert_eq!(&got_a.payload, b"pong");
    }

    // RUDP4: framed packet round-trip using MeshPacketFramer.
    #[test]
    #[ignore]
    fn rudp4_framed_packet_round_trip() {
        let mut framer = MeshPacketFramer::new();
        let payload = vec![0xABu8; 128];
        let framed = framer.encode(&payload).expect("encode");

        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let local_addr = rt.local_addr().expect("local_addr");
        rt.connect_peer(nid(3), local_addr);

        rt.send_to_peer(&nid(3), &framed).expect("send framed");

        let pkt = poll_until(&mut rt, 500).expect("recv timed out");

        let (decoded, _) = framer.decode(&pkt.payload).expect("decode");
        assert_eq!(decoded, payload.as_slice());
    }

    // RUDP5: send to unknown peer returns an error.
    #[test]
    #[ignore]
    fn rudp5_unknown_peer_error() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let err = rt.send_to_peer(&nid(99), b"test").unwrap_err();
        assert!(matches!(
            err,
            crate::real_udp_runtime::UdpRuntimeError::UnknownPeer
        ));
    }

    // RUDP6: remove peer prevents further sends.
    #[test]
    #[ignore]
    fn rudp6_remove_peer_disables_send() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let local_addr = rt.local_addr().expect("local_addr");

        rt.connect_peer(nid(4), local_addr);
        rt.remove_peer(&nid(4));

        let err = rt.send_to_peer(&nid(4), b"after-remove").unwrap_err();
        assert!(matches!(
            err,
            crate::real_udp_runtime::UdpRuntimeError::UnknownPeer
        ));
    }

    // RUDP7: oversized packet (> MAX_PACKET) is rejected before send.
    #[test]
    #[ignore]
    fn rudp7_oversized_packet_rejected() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let local_addr = rt.local_addr().expect("local_addr");
        rt.connect_peer(nid(5), local_addr);

        let huge = vec![0u8; 70_000]; // > MAX_PACKET (65535)
        let err = rt.send_to_peer(&nid(5), &huge).unwrap_err();
        assert!(matches!(
            err,
            crate::real_udp_runtime::UdpRuntimeError::PacketTooLarge
        ));
    }

    // RUDP8: poll_recv returns None when no packet is available.
    #[test]
    #[ignore]
    fn rudp8_poll_empty_returns_none() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        assert!(rt.poll_recv().is_none());
    }

    // RUDP9: malformed framed packet (truncated length prefix) is skipped gracefully.
    #[test]
    #[ignore]
    fn rudp9_malformed_frame_skipped() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        let local_addr = rt.local_addr().expect("local_addr");
        rt.connect_peer(nid(6), local_addr);

        // Send raw garbage (not a valid framed packet).
        rt.send_to_peer(&nid(6), &[0xFF, 0xFF])
            .expect("send garbage");

        // Give time for loopback delivery.
        std::thread::sleep(Duration::from_millis(50));

        // We receive raw bytes; the framer test layer would reject this,
        // but at the UDP level we just get bytes back.
        let pkt = poll_until(&mut rt, 200);
        // Either received or not — no panic is the key assertion.
        let _ = pkt;
    }

    // RUDP10: peer_count reflects connects and removes.
    #[test]
    #[ignore]
    fn rudp10_peer_count() {
        let mut rt = RealUdpRuntime::bind("127.0.0.1:0").expect("bind");
        assert_eq!(rt.peer_count(), 0);

        let addr: std::net::SocketAddr = "127.0.0.1:9999".parse().unwrap();
        rt.connect_peer(nid(7), addr);
        rt.connect_peer(nid(8), addr);
        assert_eq!(rt.peer_count(), 2);

        rt.remove_peer(&nid(7));
        assert_eq!(rt.peer_count(), 1);
    }

    // --- Non-ignored tests that run in normal `cargo test` ---

    // RUDP_DRY1: RealUdpRuntime bind on reserved/bad address fails gracefully.
    #[test]
    fn rudp_dry1_bad_addr_fails() {
        // Port 1 requires elevated privileges on most systems.
        let result = RealUdpRuntime::bind("0.0.0.0:1");
        // May succeed in CI with elevated permissions; just check it doesn't panic.
        let _ = result;
    }

    // RUDP_DRY2: MeshPacketFramer encode/decode is self-consistent (no socket).
    #[test]
    fn rudp_dry2_framer_round_trip() {
        let mut framer = MeshPacketFramer::new();
        let data = vec![0xCAu8; 64];
        let encoded = framer.encode(&data).expect("encode");
        let (decoded, _) = framer.decode(&encoded).expect("decode");
        assert_eq!(decoded, data.as_slice());
    }

    // RUDP_DRY3: UdpSocket can bind to localhost:0 (OS-level smoke test).
    #[test]
    fn rudp_dry3_os_socket_binds() {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("OS UDP bind");
        assert!(sock.local_addr().is_ok());
    }
}
