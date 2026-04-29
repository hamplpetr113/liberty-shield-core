//! `TcpLink` — framed TCP transport for encrypted relay cells.
//!
//! Wire frame: `length(4 LE)` ‖ `cell_bytes(length)`.
//!
//! Maximum frame body is capped at `MAX_FRAME_BODY` bytes to reject obviously
//! malformed or malicious length fields before allocating memory.
//!
//! NON-PRODUCTION: no TLS, no authentication of the peer, no DoS hardening.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::encrypted_relay::EncryptedRelayCell;

/// Maximum accepted frame body size (1 MiB).
const MAX_FRAME_BODY: u32 = 1 << 20;

/// Read timeout applied to accepted/connected streams.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors from `TcpLink` operations.
#[derive(Debug)]
pub enum TcpLinkError {
    Io(std::io::Error),
    FrameTooLarge(u32),
    FrameTooShort,
    CellDecode(crate::encrypted_relay::EncryptedRelayError),
}

impl std::fmt::Display for TcpLinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TcpLinkError::Io(e) => write!(f, "TCP I/O error: {e}"),
            TcpLinkError::FrameTooLarge(n) => write!(f, "frame body too large: {n} bytes"),
            TcpLinkError::FrameTooShort => write!(f, "frame body shorter than minimum cell"),
            TcpLinkError::CellDecode(e) => write!(f, "cell decode error: {e:?}"),
        }
    }
}

impl From<std::io::Error> for TcpLinkError {
    fn from(e: std::io::Error) -> Self {
        TcpLinkError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// TcpLink
// ---------------------------------------------------------------------------

/// Framed TCP connection for relay cell transport.
pub struct TcpLink {
    stream: TcpStream,
    peer_addr: SocketAddr,
}

impl TcpLink {
    /// Connect to a remote address and return a `TcpLink`.
    pub fn connect(addr: SocketAddr) -> Result<Self, TcpLinkError> {
        let stream = TcpStream::connect(addr)?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        let peer_addr = stream.peer_addr()?;
        Ok(Self { stream, peer_addr })
    }

    /// Wrap an already-accepted `TcpStream` in a `TcpLink`.
    pub fn accept(stream: TcpStream) -> Result<Self, TcpLinkError> {
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        let peer_addr = stream.peer_addr()?;
        Ok(Self { stream, peer_addr })
    }

    /// Remote address of the peer.
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    /// Send one `EncryptedRelayCell` as a length-prefixed frame.
    pub fn send_cell(&mut self, cell: &EncryptedRelayCell) -> Result<(), TcpLinkError> {
        let body = cell.to_wire();
        let len = body.len() as u32;
        self.stream.write_all(&len.to_le_bytes())?;
        self.stream.write_all(&body)?;
        Ok(())
    }

    /// Receive one `EncryptedRelayCell` frame (blocking).
    pub fn recv_cell(&mut self) -> Result<EncryptedRelayCell, TcpLinkError> {
        // Read 4-byte length prefix.
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_le_bytes(len_buf);

        if len > MAX_FRAME_BODY {
            return Err(TcpLinkError::FrameTooLarge(len));
        }

        // Minimum: 8 bytes sequence + 16 bytes tag.
        if len < 24 {
            return Err(TcpLinkError::FrameTooShort);
        }

        let mut body = vec![0u8; len as usize];
        self.stream.read_exact(&mut body)?;

        EncryptedRelayCell::from_wire(&body).map_err(TcpLinkError::CellDecode)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use super::*;
    use crate::crypto::SessionKeys;
    use crate::encrypted_relay::{RelayCellCommand, RelayCellPlaintext};

    fn loopback_pair() -> (TcpLink, TcpLink) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client_handle = std::thread::spawn(move || TcpLink::connect(addr).unwrap());
        let (server_stream, _) = listener.accept().unwrap();
        let server = TcpLink::accept(server_stream).unwrap();
        let client = client_handle.join().unwrap();
        (client, server)
    }

    fn make_cell(seq_hint: u64) -> EncryptedRelayCell {
        let mut send = SessionKeys::new([0xAAu8; 32], [0xAAu8; 32]);
        let pt = RelayCellPlaintext::new(1, 1, RelayCellCommand::Data, seq_hint, b"test".to_vec());
        let cell = crate::encrypted_relay::EncryptedRelayCell::seal(&mut send, &pt).unwrap();
        cell
    }

    // TR1: basic send → recv round-trip.
    #[test]
    fn tr1_basic_send_recv() {
        let (mut client, mut server) = loopback_pair();
        let cell = make_cell(0);

        let handle = std::thread::spawn(move || server.recv_cell().unwrap());
        client.send_cell(&cell).unwrap();
        let received = handle.join().unwrap();

        assert_eq!(received.sequence, cell.sequence);
        assert_eq!(received.ciphertext_and_tag, cell.ciphertext_and_tag);
    }

    // TR2: multi-message framing — 5 cells sent and received in order.
    #[test]
    fn tr2_multi_message_framing() {
        let (mut client, mut server) = loopback_pair();
        let cells: Vec<_> = (0u64..5).map(make_cell).collect();
        let sequences: Vec<u64> = cells.iter().map(|c| c.sequence).collect();

        let handle = std::thread::spawn(move || {
            (0..5)
                .map(|_| server.recv_cell().unwrap())
                .collect::<Vec<_>>()
        });

        for cell in &cells {
            client.send_cell(cell).unwrap();
        }

        let received = handle.join().unwrap();
        let recv_seqs: Vec<u64> = received.iter().map(|c| c.sequence).collect();
        assert_eq!(recv_seqs, sequences);
    }

    // TR3: frame with body > MAX_FRAME_BODY is rejected by recv_cell.
    #[test]
    fn tr3_oversized_frame_rejected() {
        let (mut client, mut server) = loopback_pair();

        let handle = std::thread::spawn(move || server.recv_cell());

        // Write a frame header with length exceeding MAX_FRAME_BODY.
        let bad_len = (MAX_FRAME_BODY + 1).to_le_bytes();
        client.stream.write_all(&bad_len).unwrap();
        // No body — the receiver should reject before reading.

        let result = handle.join().unwrap();
        assert!(matches!(result, Err(TcpLinkError::FrameTooLarge(_))));
    }

    // TR4: frame with body shorter than minimum (< 24 bytes) is rejected.
    #[test]
    fn tr4_too_short_frame_rejected() {
        let (mut client, mut server) = loopback_pair();

        let handle = std::thread::spawn(move || server.recv_cell());

        // Write a length of 10 (below the 24-byte minimum).
        let short_len = 10u32.to_le_bytes();
        client.stream.write_all(&short_len).unwrap();

        let result = handle.join().unwrap();
        assert!(matches!(result, Err(TcpLinkError::FrameTooShort)));
    }

    // TR5: peer_addr returns the remote address.
    #[test]
    fn tr5_peer_addr() {
        let (client, server) = loopback_pair();
        // Client's peer is the server's local address and vice versa.
        assert_eq!(client.peer_addr(), server.stream.local_addr().unwrap());
        assert_eq!(server.peer_addr(), client.stream.local_addr().unwrap());
    }

    // TR6: send_cell → recv_cell preserves the full ciphertext.
    #[test]
    fn tr6_ciphertext_preserved() {
        let (mut client, mut server) = loopback_pair();
        let cell = make_cell(42);
        let expected = cell.ciphertext_and_tag.clone();

        let handle = std::thread::spawn(move || server.recv_cell().unwrap());
        client.send_cell(&cell).unwrap();
        let received = handle.join().unwrap();

        assert_eq!(received.ciphertext_and_tag, expected);
    }

    // TR7: replay detection works through TcpLink + RelayPipeline.
    #[test]
    fn tr7_replay_detection_via_tcp() {
        use crate::encrypted_relay::{PipelineResult, RelayPipeline};

        let (mut client, mut server) = loopback_pair();

        let key = [0xBBu8; 32];
        let mut send_pipeline = RelayPipeline::new();
        let mut recv_pipeline = RelayPipeline::new();
        send_pipeline.register_circuit(1, SessionKeys::new(key, key), SessionKeys::new(key, key));
        recv_pipeline.register_circuit(1, SessionKeys::new(key, key), SessionKeys::new(key, key));

        let pt = RelayCellPlaintext::new(1, 1, RelayCellCommand::Data, 0, b"replay-test".to_vec());
        let enc = send_pipeline.send_cell(1, 1, pt).unwrap();

        // Send the same cell twice.
        let enc_clone = enc.clone();
        let handle = std::thread::spawn(move || {
            let c1 = server.recv_cell().unwrap();
            let c2 = server.recv_cell().unwrap();
            (c1, c2)
        });

        client.send_cell(&enc).unwrap();
        client.send_cell(&enc_clone).unwrap();

        let (c1, c2) = handle.join().unwrap();
        assert!(matches!(
            recv_pipeline.receive_cell(1, 1, &c1),
            PipelineResult::Accepted(_)
        ));
        assert_eq!(
            recv_pipeline.receive_cell(1, 1, &c2),
            PipelineResult::ReplayRejected
        );
    }

    // TR8: transport replay filter integration — duplicate sequence rejected before AEAD.
    #[test]
    fn tr8_transport_replay_filter() {
        use crate::encrypted_relay::{PipelineResult, RelayPipeline};

        let key = [0xCCu8; 32];
        let mut send_pipeline = RelayPipeline::new();
        let mut recv_pipeline = RelayPipeline::new();
        send_pipeline.register_circuit(2, SessionKeys::new(key, key), SessionKeys::new(key, key));
        recv_pipeline.register_circuit(2, SessionKeys::new(key, key), SessionKeys::new(key, key));

        let pt = RelayCellPlaintext::new(2, 1, RelayCellCommand::Data, 0, b"dup".to_vec());
        let enc = send_pipeline.send_cell(2, 1, pt).unwrap();

        // First receive: accepted.
        assert!(matches!(
            recv_pipeline.receive_cell(2, 1, &enc),
            PipelineResult::Accepted(_)
        ));
        // Second receive of same cell: rejected by transport filter.
        assert_eq!(
            recv_pipeline.receive_cell(2, 1, &enc),
            PipelineResult::ReplayRejected
        );
    }

    // TR9: TcpLink can send large cells (near MAX_RELAY_PAYLOAD).
    #[test]
    fn tr9_large_cell() {
        use crate::encrypted_relay::MAX_RELAY_PAYLOAD;

        let (mut client, mut server) = loopback_pair();
        let mut send = SessionKeys::new([0xDDu8; 32], [0xDDu8; 32]);
        let payload = vec![0x42u8; MAX_RELAY_PAYLOAD];
        let pt = RelayCellPlaintext::new(1, 1, RelayCellCommand::Data, 0, payload.clone());
        let cell = crate::encrypted_relay::EncryptedRelayCell::seal(&mut send, &pt).unwrap();

        let handle = std::thread::spawn(move || server.recv_cell().unwrap());
        client.send_cell(&cell).unwrap();
        let received = handle.join().unwrap();
        assert_eq!(received.sequence, cell.sequence);
    }

    // TR10: TcpLink correctly handles connection to a non-listening port.
    #[test]
    fn tr10_connect_failure() {
        // Port 1 is almost certainly not listening (requires root to bind on most OSes).
        let result = TcpLink::connect("127.0.0.1:1".parse().unwrap());
        assert!(result.is_err());
    }
}
