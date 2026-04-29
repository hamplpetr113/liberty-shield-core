// Wire layout (big-endian):
//  [0..8]   source_node         u64
//  [8..16]  target_node         u64
//  [16]     packet_kind         u8  (0=EncryptedCell, 1=ProbeEncrypted, 2=Shutdown)
//  [17..25] sequence_number     u64
//  [25..27] encrypted_cell_len  u16
//  [27..]   encrypted cell bytes  (ENCRYPTED_CELL_SIZE for cell/probe; 0 for shutdown)
//
// EncryptedCell wire layout within the payload (big-endian):
//  [0..8]     path_id     u64
//  [8..16]    nonce       u64
//  [16..1466] ciphertext  [u8; 1450]
//  [1466..1482] auth_tag  [u8; 16]

use liberty_controlled_chaos::cell_encoder::CELL_SIZE;
use liberty_controlled_chaos::noise_link::{ENCRYPTED_CELL_SIZE, EncryptedCell};

use crate::encrypted_udp_types::{EncryptedUdpError, EncryptedUdpNodeId, EncryptedUdpPacketKind};

pub const ENCRYPTED_UDP_HEADER_SIZE: usize = 27;

#[derive(Debug, PartialEq)]
pub struct EncryptedUdpPacket {
    pub source_node: EncryptedUdpNodeId,
    pub target_node: EncryptedUdpNodeId,
    pub packet_kind: EncryptedUdpPacketKind,
    pub sequence_number: u64,
    pub encrypted_cell_bytes: Vec<u8>,
}

fn kind_to_byte(kind: EncryptedUdpPacketKind) -> u8 {
    match kind {
        EncryptedUdpPacketKind::EncryptedCell => 0,
        EncryptedUdpPacketKind::ProbeEncrypted => 1,
        EncryptedUdpPacketKind::Shutdown => 2,
    }
}

fn byte_to_kind(b: u8) -> Result<EncryptedUdpPacketKind, EncryptedUdpError> {
    match b {
        0 => Ok(EncryptedUdpPacketKind::EncryptedCell),
        1 => Ok(EncryptedUdpPacketKind::ProbeEncrypted),
        2 => Ok(EncryptedUdpPacketKind::Shutdown),
        _ => Err(EncryptedUdpError::InvalidPacketKind),
    }
}

fn validate_cell_len(kind: EncryptedUdpPacketKind, len: usize) -> Result<(), EncryptedUdpError> {
    match kind {
        EncryptedUdpPacketKind::EncryptedCell | EncryptedUdpPacketKind::ProbeEncrypted => {
            if len != ENCRYPTED_CELL_SIZE {
                return Err(EncryptedUdpError::InvalidEncryptedCellSize);
            }
        }
        EncryptedUdpPacketKind::Shutdown => {
            if len != 0 {
                return Err(EncryptedUdpError::InvalidEncryptedCellSize);
            }
        }
    }
    Ok(())
}

pub fn encode_encrypted_udp_packet(
    packet: &EncryptedUdpPacket,
) -> Result<Vec<u8>, EncryptedUdpError> {
    let cell_len = packet.encrypted_cell_bytes.len();
    validate_cell_len(packet.packet_kind, cell_len)?;
    let mut buf = Vec::with_capacity(ENCRYPTED_UDP_HEADER_SIZE + cell_len);
    buf.extend_from_slice(&packet.source_node.0.to_be_bytes());
    buf.extend_from_slice(&packet.target_node.0.to_be_bytes());
    buf.push(kind_to_byte(packet.packet_kind));
    buf.extend_from_slice(&packet.sequence_number.to_be_bytes());
    buf.extend_from_slice(&(cell_len as u16).to_be_bytes());
    buf.extend_from_slice(&packet.encrypted_cell_bytes);
    Ok(buf)
}

pub fn decode_encrypted_udp_packet(bytes: &[u8]) -> Result<EncryptedUdpPacket, EncryptedUdpError> {
    if bytes.len() < ENCRYPTED_UDP_HEADER_SIZE {
        return Err(EncryptedUdpError::PacketDecodeFailed);
    }
    let source_node = EncryptedUdpNodeId(u64::from_be_bytes(bytes[0..8].try_into().unwrap()));
    let target_node = EncryptedUdpNodeId(u64::from_be_bytes(bytes[8..16].try_into().unwrap()));
    let packet_kind = byte_to_kind(bytes[16])?;
    let sequence_number = u64::from_be_bytes(bytes[17..25].try_into().unwrap());
    let cell_len = u16::from_be_bytes(bytes[25..27].try_into().unwrap()) as usize;
    if bytes.len() != ENCRYPTED_UDP_HEADER_SIZE + cell_len {
        return Err(EncryptedUdpError::PacketDecodeFailed);
    }
    validate_cell_len(packet_kind, cell_len)?;
    let encrypted_cell_bytes = bytes[ENCRYPTED_UDP_HEADER_SIZE..].to_vec();
    Ok(EncryptedUdpPacket {
        source_node,
        target_node,
        packet_kind,
        sequence_number,
        encrypted_cell_bytes,
    })
}

/// Serialize an `EncryptedCell` struct to its 1482-byte wire representation.
pub fn encrypted_cell_to_bytes(cell: &EncryptedCell) -> Vec<u8> {
    let mut buf = Vec::with_capacity(ENCRYPTED_CELL_SIZE);
    buf.extend_from_slice(&cell.path_id.to_be_bytes());
    buf.extend_from_slice(&cell.nonce.to_be_bytes());
    buf.extend_from_slice(&cell.ciphertext);
    buf.extend_from_slice(&cell.auth_tag);
    buf
}

/// Deserialize 1482 bytes back into an `EncryptedCell` struct.
pub fn bytes_to_encrypted_cell(bytes: &[u8]) -> Result<EncryptedCell, EncryptedUdpError> {
    if bytes.len() != ENCRYPTED_CELL_SIZE {
        return Err(EncryptedUdpError::InvalidEncryptedCellSize);
    }
    let path_id = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
    let nonce = u64::from_be_bytes(bytes[8..16].try_into().unwrap());
    let ciphertext: [u8; CELL_SIZE] = bytes[16..16 + CELL_SIZE]
        .try_into()
        .map_err(|_| EncryptedUdpError::InvalidEncryptedCellSize)?;
    let auth_tag: [u8; 16] = bytes[16 + CELL_SIZE..ENCRYPTED_CELL_SIZE]
        .try_into()
        .map_err(|_| EncryptedUdpError::InvalidEncryptedCellSize)?;
    Ok(EncryptedCell {
        path_id,
        nonce,
        ciphertext,
        auth_tag,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_encrypted_cell_bytes() -> Vec<u8> {
        vec![0xAAu8; ENCRYPTED_CELL_SIZE]
    }

    fn cell_packet(src: u64, dst: u64, seq: u64) -> EncryptedUdpPacket {
        EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(src),
            target_node: EncryptedUdpNodeId(dst),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: seq,
            encrypted_cell_bytes: make_encrypted_cell_bytes(),
        }
    }

    fn shutdown_packet() -> EncryptedUdpPacket {
        EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::Shutdown,
            sequence_number: 0,
            encrypted_cell_bytes: Vec::new(),
        }
    }

    // EP1: encode and decode an EncryptedCell packet roundtrip
    #[test]
    fn ep1_encode_decode_encrypted_cell_packet() {
        let pkt = cell_packet(1, 2, 42);
        let encoded = encode_encrypted_udp_packet(&pkt).unwrap();
        assert_eq!(
            encoded.len(),
            ENCRYPTED_UDP_HEADER_SIZE + ENCRYPTED_CELL_SIZE
        );
        let decoded = decode_encrypted_udp_packet(&encoded).unwrap();
        assert_eq!(decoded.source_node, EncryptedUdpNodeId(1));
        assert_eq!(decoded.target_node, EncryptedUdpNodeId(2));
        assert_eq!(decoded.packet_kind, EncryptedUdpPacketKind::EncryptedCell);
        assert_eq!(decoded.sequence_number, 42);
        assert_eq!(decoded.encrypted_cell_bytes.len(), ENCRYPTED_CELL_SIZE);
    }

    // EP2: invalid packet kind rejected
    #[test]
    fn ep2_invalid_packet_kind_rejected() {
        let mut encoded = encode_encrypted_udp_packet(&cell_packet(1, 2, 0)).unwrap();
        encoded[16] = 99;
        assert_eq!(
            decode_encrypted_udp_packet(&encoded).unwrap_err(),
            EncryptedUdpError::InvalidPacketKind
        );
    }

    // EP3: truncated packet rejected
    #[test]
    fn ep3_truncated_packet_rejected() {
        let encoded = encode_encrypted_udp_packet(&cell_packet(1, 2, 0)).unwrap();
        let truncated = &encoded[..10];
        assert_eq!(
            decode_encrypted_udp_packet(truncated).unwrap_err(),
            EncryptedUdpError::PacketDecodeFailed
        );
    }

    // EP4: encrypted cell wrong size rejected on encode and decode
    #[test]
    fn ep4_encrypted_cell_wrong_size_rejected() {
        let pkt = EncryptedUdpPacket {
            source_node: EncryptedUdpNodeId(1),
            target_node: EncryptedUdpNodeId(2),
            packet_kind: EncryptedUdpPacketKind::EncryptedCell,
            sequence_number: 0,
            encrypted_cell_bytes: vec![0u8; 100], // wrong size
        };
        assert_eq!(
            encode_encrypted_udp_packet(&pkt).unwrap_err(),
            EncryptedUdpError::InvalidEncryptedCellSize
        );
    }

    // EP5: shutdown packet allows empty payload
    #[test]
    fn ep5_shutdown_allows_empty_payload() {
        let pkt = shutdown_packet();
        let encoded = encode_encrypted_udp_packet(&pkt).unwrap();
        assert_eq!(encoded.len(), ENCRYPTED_UDP_HEADER_SIZE);
        let decoded = decode_encrypted_udp_packet(&encoded).unwrap();
        assert_eq!(decoded.packet_kind, EncryptedUdpPacketKind::Shutdown);
        assert!(decoded.encrypted_cell_bytes.is_empty());
    }

    // EP6: length mismatch rejected
    #[test]
    fn ep6_length_mismatch_rejected() {
        let mut encoded = encode_encrypted_udp_packet(&cell_packet(1, 2, 0)).unwrap();
        // Set cell_len field to wrong value
        encoded[25] = 0;
        encoded[26] = 5;
        assert_eq!(
            decode_encrypted_udp_packet(&encoded).unwrap_err(),
            EncryptedUdpError::PacketDecodeFailed
        );
    }

    // Roundtrip: encrypted_cell_to_bytes / bytes_to_encrypted_cell
    #[test]
    fn bytes_roundtrip() {
        let cell = EncryptedCell {
            path_id: 0xDEAD_BEEF,
            nonce: 42,
            ciphertext: [0xABu8; CELL_SIZE],
            auth_tag: [0xCDu8; 16],
        };
        let bytes = encrypted_cell_to_bytes(&cell);
        assert_eq!(bytes.len(), ENCRYPTED_CELL_SIZE);
        let recovered = bytes_to_encrypted_cell(&bytes).unwrap();
        assert_eq!(recovered.path_id, 0xDEAD_BEEF);
        assert_eq!(recovered.nonce, 42);
        assert_eq!(recovered.auth_tag, [0xCDu8; 16]);
    }
}
