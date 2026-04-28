//! UdpTransport — sends and receives `EncryptedCell` datagrams over UDP.
//!
//! Sits at the end of the pipeline after `NoiseLink`:
//!   StreamMux → CellEncoder → NoiseLink → UdpTransport
//!
//! Every datagram is exactly `WIRE_SIZE` (1482) bytes.  Datagrams of any other
//! length are rejected by the receiver.
//!
//! Contains no unsafe code and does not inspect payload content.

mod receiver;
mod sender;
pub mod types;

pub use receiver::UdpReceiver;
pub use sender::UdpSender;
pub use types::{PeerAddress, TransportError, UdpPacket, WIRE_SIZE};

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::net::UdpSocket;
    use std::time::Duration;

    use crate::cell_encoder::CELL_SIZE;
    use crate::noise_link::{ENCRYPTED_CELL_SIZE, EncryptedCell};

    use super::*;

    fn make_cell(seed: u8) -> EncryptedCell {
        EncryptedCell {
            path_id: 0xDEAD_BEEF_0000_0001,
            nonce: 0x0000_0000_0000_0042,
            ciphertext: [seed; CELL_SIZE],
            auth_tag: [seed ^ 0xff; 16],
        }
    }

    // ── T1: UdpPacket serialise / deserialise round-trip ─────────────────────

    #[test]
    fn t1_packet_encode_decode_roundtrip() {
        let cell = make_cell(0xAB);
        let packet = UdpPacket::from_encrypted_cell(&cell);

        assert_eq!(packet.bytes.len(), WIRE_SIZE);

        let recovered = packet.to_encrypted_cell();
        assert_eq!(recovered.path_id, cell.path_id);
        assert_eq!(recovered.nonce, cell.nonce);
        assert_eq!(recovered.ciphertext, cell.ciphertext);
        assert_eq!(recovered.auth_tag, cell.auth_tag);
    }

    // ── T2: send / receive round-trip over localhost ──────────────────────────

    #[test]
    fn t2_send_receive_roundtrip_localhost() {
        let receiver = UdpReceiver::bind("127.0.0.1:0").expect("receiver bind");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");

        let recv_addr = receiver.local_addr().expect("local_addr");
        let sender = UdpSender::bind("127.0.0.1:0").expect("sender bind");
        let peer = PeerAddress::new(recv_addr);

        let cell = make_cell(0x55);
        sender.send(&cell, &peer).expect("send");

        let (received, _from) = receiver.receive().expect("receive");
        assert_eq!(received.path_id, cell.path_id);
        assert_eq!(received.nonce, cell.nonce);
        assert_eq!(received.ciphertext, cell.ciphertext);
        assert_eq!(received.auth_tag, cell.auth_tag);
    }

    // ── T3: wire size is constant ─────────────────────────────────────────────

    #[test]
    fn t3_constant_wire_size() {
        assert_eq!(WIRE_SIZE, ENCRYPTED_CELL_SIZE);
        assert_eq!(WIRE_SIZE, 1482);

        for seed in [0u8, 1, 128, 255] {
            let packet = UdpPacket::from_encrypted_cell(&make_cell(seed));
            assert_eq!(
                packet.bytes.len(),
                WIRE_SIZE,
                "packet must always be {WIRE_SIZE} bytes"
            );
        }
    }

    // ── T4: truncated datagram is rejected ────────────────────────────────────

    #[test]
    fn t4_truncated_datagram_rejected() {
        let receiver = UdpReceiver::bind("127.0.0.1:0").expect("receiver bind");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let recv_addr = receiver.local_addr().expect("local_addr");

        // Send a short datagram (100 bytes) directly via std::net::UdpSocket.
        let raw = UdpSocket::bind("127.0.0.1:0").unwrap();
        raw.send_to(&[0xFFu8; 100], recv_addr).unwrap();

        let result = receiver.receive();
        assert!(
            matches!(
                result,
                Err(TransportError::TruncatedPacket {
                    received: 100,
                    expected: 1482
                })
            ),
            "expected TruncatedPacket {{ received: 100, expected: 1482 }}"
        );
    }

    // ── T5: WouldBlock on empty non-blocking socket ───────────────────────────

    #[test]
    fn t5_would_block_when_no_data() {
        let receiver = UdpReceiver::bind("127.0.0.1:0").expect("receiver bind");
        receiver.set_nonblocking(true).expect("set_nonblocking");

        let result = receiver.receive();
        assert!(
            matches!(result, Err(TransportError::WouldBlock)),
            "empty non-blocking receive must return WouldBlock"
        );
    }

    // ── T6: PeerAddress round-trip from sender perspective ───────────────────

    #[test]
    fn t6_peer_address_identifies_sender() {
        let receiver = UdpReceiver::bind("127.0.0.1:0").expect("receiver bind");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let recv_addr = receiver.local_addr().expect("local_addr");

        let sender = UdpSender::bind("127.0.0.1:0").expect("sender bind");
        let sender_addr = sender.local_addr().expect("sender local_addr");

        sender
            .send(&make_cell(0x11), &PeerAddress::new(recv_addr))
            .unwrap();
        let (_cell, from) = receiver.receive().expect("receive");

        assert_eq!(from.inner().port(), sender_addr.port());
    }
}
