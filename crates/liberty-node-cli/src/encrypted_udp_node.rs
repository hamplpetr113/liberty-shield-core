use std::collections::HashMap;
use std::net::SocketAddr;

use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;
use liberty_controlled_chaos::replay_protection::{CellNonce, ReplayWindow};

use crate::encrypted_cell_fixture::make_cell;
use crate::encrypted_peer_session::EncryptedPeerSessionTable;
use crate::encrypted_udp_packet::{
    EncryptedUdpPacket, bytes_to_encrypted_cell, encrypted_cell_to_bytes,
};
use crate::encrypted_udp_socket::EncryptedUdpSocket;
use crate::encrypted_udp_types::{
    EncryptedUdpError, EncryptedUdpNodeConfig, EncryptedUdpNodeId, EncryptedUdpPacketKind,
};

#[derive(Debug)]
pub struct EncryptedUdpNode {
    config: EncryptedUdpNodeConfig,
    socket: EncryptedUdpSocket,
    sessions: EncryptedPeerSessionTable,
    sequence_counter: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub encrypted_cells_sent: u64,
    pub encrypted_cells_received: u64,
    replay_windows: HashMap<u64, ReplayWindow>,
}

#[derive(Debug, Clone)]
pub struct EncryptedUdpNodeSnapshot {
    pub node_id: EncryptedUdpNodeId,
    pub local_addr: SocketAddr,
    pub peer_count: usize,
    pub packets_sent: u64,
    pub packets_received: u64,
    pub packets_dropped: u64,
    pub encrypted_cells_sent: u64,
    pub encrypted_cells_received: u64,
}

impl EncryptedUdpNode {
    pub fn start(config: EncryptedUdpNodeConfig) -> Result<Self, EncryptedUdpError> {
        config.validate()?;
        let socket = EncryptedUdpSocket::bind(&config)?;
        Ok(Self {
            config,
            socket,
            sessions: EncryptedPeerSessionTable::new(),
            sequence_counter: 0,
            packets_sent: 0,
            packets_received: 0,
            packets_dropped: 0,
            encrypted_cells_sent: 0,
            encrypted_cells_received: 0,
            replay_windows: HashMap::new(),
        })
    }

    /// Add a session with `peer_id` using deterministic seeds.
    ///
    /// For two nodes A and B to communicate:
    ///   A.add_peer_session(B.id, send_seed=S, recv_seed=R)
    ///   B.add_peer_session(A.id, send_seed=R, recv_seed=S)
    pub fn add_peer_session(
        &mut self,
        peer_id: EncryptedUdpNodeId,
        send_seed: u64,
        recv_seed: u64,
    ) -> Result<(), EncryptedUdpError> {
        self.sessions.add_peer(peer_id, send_seed, recv_seed)
    }

    /// Send an already-encrypted `EncryptedCell` to `target_node` at `target_addr`.
    pub fn send_encrypted_cell(
        &mut self,
        target_node: EncryptedUdpNodeId,
        target_addr: SocketAddr,
        cell_bytes: Vec<u8>,
    ) -> Result<(), EncryptedUdpError> {
        if cell_bytes.len() != ENCRYPTED_CELL_SIZE {
            return Err(EncryptedUdpError::InvalidEncryptedCellSize);
        }
        let seq = self.next_seq();
        let packet = EncryptedUdpPacket {
            source_node: self.config.node_id,
            target_node,
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: seq,
            encrypted_cell_bytes: cell_bytes,
        };
        self.socket.send_to(&packet, target_addr)?;
        self.packets_sent += 1;
        self.encrypted_cells_sent += 1;
        Ok(())
    }

    /// Encrypt `payload` and send to `target_node` at `target_addr`.
    /// Requires a session with `target_node` to be present.
    pub fn send_payload_encrypted(
        &mut self,
        target_node: EncryptedUdpNodeId,
        target_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), EncryptedUdpError> {
        let cell = make_cell(payload, self.config.node_id.0)
            .map_err(|_| EncryptedUdpError::EncryptionFailed)?;
        let enc_cell = {
            let session = self
                .sessions
                .get_peer_mut(target_node)
                .ok_or(EncryptedUdpError::SessionNotFound)?;
            session.send_encoder.encode(cell)
        };
        let cell_bytes = encrypted_cell_to_bytes(&enc_cell);
        self.send_encrypted_cell(target_node, target_addr, cell_bytes)
    }

    /// Non-blocking receive and decrypt. Returns the decrypted payload bytes on success.
    ///
    /// - Returns `Ok(Some(bytes))` when a valid encrypted packet is received and decrypted.
    /// - Returns `Ok(None)` when the socket is empty or a packet is malformed (dropped).
    /// - Returns `Err(ReplayDetected)` when a duplicate nonce is received.
    /// - Returns `Err(SessionNotFound)` when no session exists for the source node.
    pub fn poll_once(&mut self) -> Result<Option<Vec<u8>>, EncryptedUdpError> {
        let result = self.socket.try_recv();
        let packet = match result {
            Ok(Some((pkt, _from))) => pkt,
            Ok(None) => return Ok(None),
            Err(_) => {
                self.packets_dropped += 1;
                return Ok(None);
            }
        };

        self.packets_received += 1;

        match packet.packet_kind {
            EncryptedUdpPacketKind::Shutdown => {
                Ok(Some(Vec::new()))
            }
            EncryptedUdpPacketKind::EncryptedCell | EncryptedUdpPacketKind::ProbeEncrypted => {
                let enc_cell = match bytes_to_encrypted_cell(&packet.encrypted_cell_bytes) {
                    Ok(c) => c,
                    Err(_) => {
                        self.packets_dropped += 1;
                        return Ok(None);
                    }
                };

                let nonce = enc_cell.nonce;
                let source_id = packet.source_node.0;

                // Replay check (separate scope to release borrow before sessions borrow)
                let replay_ok = {
                    let window = self
                        .replay_windows
                        .entry(source_id)
                        .or_insert_with(|| ReplayWindow::new(64));
                    window.check_and_record(CellNonce(nonce)).is_ok()
                };
                if !replay_ok {
                    self.packets_dropped += 1;
                    return Err(EncryptedUdpError::ReplayDetected);
                }

                let cell = {
                    let session = self
                        .sessions
                        .get_peer_mut(packet.source_node)
                        .ok_or(EncryptedUdpError::SessionNotFound)?;
                    session
                        .recv_encoder
                        .decode(enc_cell)
                        .map_err(|_| EncryptedUdpError::DecryptionFailed)?
                };

                self.encrypted_cells_received += 1;
                Ok(Some(cell.payload_bytes().to_vec()))
            }
        }
    }

    pub fn snapshot(&self) -> EncryptedUdpNodeSnapshot {
        EncryptedUdpNodeSnapshot {
            node_id: self.config.node_id,
            local_addr: self.socket.local_addr(),
            peer_count: self.sessions.peer_count(),
            packets_sent: self.packets_sent,
            packets_received: self.packets_received,
            packets_dropped: self.packets_dropped,
            encrypted_cells_sent: self.encrypted_cells_sent,
            encrypted_cells_received: self.encrypted_cells_received,
        }
    }

    fn next_seq(&mut self) -> u64 {
        let seq = self.sequence_counter;
        self.sequence_counter += 1;
        seq
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_config(id: u64, port: u16) -> EncryptedUdpNodeConfig {
        EncryptedUdpNodeConfig {
            node_id: EncryptedUdpNodeId(id),
            bind_address: "127.0.0.1".to_string(),
            bind_port: port,
            allow_real_udp: true,
            simulation_mode: false,
        }
    }

    // EN1: start node binds socket and returns accurate snapshot
    #[test]
    fn en1_start_node() {
        let node = EncryptedUdpNode::start(node_config(1, 43020)).unwrap();
        let snap = node.snapshot();
        assert_eq!(snap.node_id, EncryptedUdpNodeId(1));
        assert_eq!(snap.packets_sent, 0);
        assert_eq!(snap.packets_received, 0);
        assert_eq!(snap.peer_count, 0);
    }

    // EN2: add_peer_session succeeds and reflects in snapshot
    #[test]
    fn en2_add_peer_session() {
        let mut node = EncryptedUdpNode::start(node_config(1, 43021)).unwrap();
        node.add_peer_session(EncryptedUdpNodeId(2), 100, 200)
            .unwrap();
        assert_eq!(node.snapshot().peer_count, 1);
    }

    // EN3: send_encrypted_cell increments sent counters
    #[test]
    fn en3_send_encrypted_cell_increments_counters() {
        let mut sender = EncryptedUdpNode::start(node_config(1, 43022)).unwrap();
        let receiver = EncryptedUdpNode::start(node_config(2, 43023)).unwrap();
        let target_addr = receiver.snapshot().local_addr;
        sender
            .add_peer_session(EncryptedUdpNodeId(2), 1000, 2000)
            .unwrap();
        sender
            .send_payload_encrypted(EncryptedUdpNodeId(2), target_addr, b"hello")
            .unwrap();
        let snap = sender.snapshot();
        assert_eq!(snap.packets_sent, 1);
        assert_eq!(snap.encrypted_cells_sent, 1);
    }

    // EN4: two nodes exchange encrypted cell and receiver decrypts payload
    #[test]
    fn en4_two_nodes_exchange_encrypted_cell() {
        let mut node_a = EncryptedUdpNode::start(node_config(1, 43024)).unwrap();
        let mut node_b = EncryptedUdpNode::start(node_config(2, 43025)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        // A sends to B: send_seed=S, recv_seed=R
        // B receives from A: send_seed=R, recv_seed=S  (keys must match)
        node_a
            .add_peer_session(EncryptedUdpNodeId(2), 0xAAAA, 0xBBBB)
            .unwrap();
        node_b
            .add_peer_session(EncryptedUdpNodeId(1), 0xBBBB, 0xAAAA)
            .unwrap();
        let payload = b"encrypted message";
        node_a
            .send_payload_encrypted(EncryptedUdpNodeId(2), b_addr, payload)
            .unwrap();
        let received = node_b.poll_once().unwrap().unwrap();
        assert_eq!(
            &received[..payload.len()],
            payload,
            "decrypted payload must match original"
        );
        assert_eq!(node_b.snapshot().encrypted_cells_received, 1);
    }

    // EN5: send without session returns SessionNotFound
    #[test]
    fn en5_send_without_session_rejected() {
        let mut sender = EncryptedUdpNode::start(node_config(1, 43026)).unwrap();
        let receiver = EncryptedUdpNode::start(node_config(2, 43027)).unwrap();
        let target_addr = receiver.snapshot().local_addr;
        assert_eq!(
            sender
                .send_payload_encrypted(EncryptedUdpNodeId(2), target_addr, b"hello")
                .unwrap_err(),
            EncryptedUdpError::SessionNotFound
        );
    }

    // EN6: replay packet returns ReplayDetected
    #[test]
    fn en6_replay_packet_rejected() {
        use crate::encrypted_cell_fixture::make_encrypted_cell;
        use crate::encrypted_udp_packet::encrypted_cell_to_bytes;
        use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;

        let mut sender = EncryptedUdpNode::start(node_config(1, 43028)).unwrap();
        let mut receiver = EncryptedUdpNode::start(node_config(2, 43029)).unwrap();
        let r_addr = receiver.snapshot().local_addr;

        sender
            .add_peer_session(EncryptedUdpNodeId(2), 0xCCCC, 0xDDDD)
            .unwrap();
        receiver
            .add_peer_session(EncryptedUdpNodeId(1), 0xDDDD, 0xCCCC)
            .unwrap();

        // Build an EncryptedCell directly and send it twice using send_encrypted_cell
        // so both packets have the same nonce (0).
        let enc = make_encrypted_cell(b"replay", 0xCCCC).unwrap();
        let cell_bytes = encrypted_cell_to_bytes(&enc);
        assert_eq!(cell_bytes.len(), ENCRYPTED_CELL_SIZE);

        // First send — should be received
        let pkt1 = EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: 0,
            encrypted_cell_bytes: cell_bytes.clone(),
        };
        sender.socket.send_to(&pkt1, r_addr).unwrap();
        sender.packets_sent += 1;

        // Second send — same nonce (0), should be detected as replay
        let pkt2 = EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: 1,
            encrypted_cell_bytes: cell_bytes,
        };
        sender.socket.send_to(&pkt2, r_addr).unwrap();
        sender.packets_sent += 1;

        // Receive first — ok
        receiver.poll_once().unwrap();
        // Receive second — replay
        assert_eq!(
            receiver.poll_once().unwrap_err(),
            EncryptedUdpError::ReplayDetected
        );
    }

    // EN7: snapshot accurately reflects all counters
    #[test]
    fn en7_snapshot_accurate() {
        let mut node_a = EncryptedUdpNode::start(node_config(1, 43030)).unwrap();
        let mut node_b = EncryptedUdpNode::start(node_config(2, 43031)).unwrap();
        let b_addr = node_b.snapshot().local_addr;
        node_a
            .add_peer_session(EncryptedUdpNodeId(2), 0x1234, 0x5678)
            .unwrap();
        node_b
            .add_peer_session(EncryptedUdpNodeId(1), 0x5678, 0x1234)
            .unwrap();
        node_a
            .send_payload_encrypted(EncryptedUdpNodeId(2), b_addr, b"snap test")
            .unwrap();
        node_b.poll_once().unwrap();
        let snap_a = node_a.snapshot();
        let snap_b = node_b.snapshot();
        assert_eq!(snap_a.packets_sent, 1);
        assert_eq!(snap_a.encrypted_cells_sent, 1);
        assert_eq!(snap_a.packets_received, 0);
        assert_eq!(snap_b.packets_received, 1);
        assert_eq!(snap_b.encrypted_cells_received, 1);
        assert_eq!(snap_b.packets_sent, 0);
    }
}
