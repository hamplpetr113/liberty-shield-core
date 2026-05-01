use crate::udp_testnet_types::{UdpTestnetError, UdpTestnetNodeId, UdpTestnetPacketKind};

// Wire layout (big-endian):
//  [0..8]   source_node    u64
//  [8..16]  target_node    u64
//  [16]     packet_kind    u8  (0=Probe 1=Data 2=Cover 3=Shutdown)
//  [17..25] sequence_number u64
//  [25..27] payload_len    u16
//  [27..]   payload bytes
pub const PACKET_HEADER_SIZE: usize = 27;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpTestnetPacket {
    pub source_node: UdpTestnetNodeId,
    pub target_node: UdpTestnetNodeId,
    pub packet_kind: UdpTestnetPacketKind,
    pub sequence_number: u64,
    pub payload: Vec<u8>,
}

fn kind_to_byte(kind: UdpTestnetPacketKind) -> u8 {
    match kind {
        UdpTestnetPacketKind::Probe => 0,
        UdpTestnetPacketKind::Data => 1,
        UdpTestnetPacketKind::Cover => 2,
        UdpTestnetPacketKind::Shutdown => 3,
    }
}

fn byte_to_kind(b: u8) -> Result<UdpTestnetPacketKind, UdpTestnetError> {
    match b {
        0 => Ok(UdpTestnetPacketKind::Probe),
        1 => Ok(UdpTestnetPacketKind::Data),
        2 => Ok(UdpTestnetPacketKind::Cover),
        3 => Ok(UdpTestnetPacketKind::Shutdown),
        _ => Err(UdpTestnetError::PacketDecodeFailed),
    }
}

pub fn encode_packet(packet: &UdpTestnetPacket) -> Vec<u8> {
    let payload_len = packet.payload.len();
    let mut buf = Vec::with_capacity(PACKET_HEADER_SIZE + payload_len);
    buf.extend_from_slice(&packet.source_node.0.to_be_bytes());
    buf.extend_from_slice(&packet.target_node.0.to_be_bytes());
    buf.push(kind_to_byte(packet.packet_kind));
    buf.extend_from_slice(&packet.sequence_number.to_be_bytes());
    buf.extend_from_slice(&(payload_len as u16).to_be_bytes());
    buf.extend_from_slice(&packet.payload);
    buf
}

pub fn decode_packet(bytes: &[u8]) -> Result<UdpTestnetPacket, UdpTestnetError> {
    if bytes.len() < PACKET_HEADER_SIZE {
        return Err(UdpTestnetError::PacketDecodeFailed);
    }
    let source_node = UdpTestnetNodeId(u64::from_be_bytes(bytes[0..8].try_into().unwrap()));
    let target_node = UdpTestnetNodeId(u64::from_be_bytes(bytes[8..16].try_into().unwrap()));
    let packet_kind = byte_to_kind(bytes[16])?;
    let sequence_number = u64::from_be_bytes(bytes[17..25].try_into().unwrap());
    let payload_len = u16::from_be_bytes(bytes[25..27].try_into().unwrap()) as usize;
    if bytes.len() != PACKET_HEADER_SIZE + payload_len {
        return Err(UdpTestnetError::PacketDecodeFailed);
    }
    let payload = bytes[27..].to_vec();
    Ok(UdpTestnetPacket {
        source_node,
        target_node,
        packet_kind,
        sequence_number,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn probe_packet() -> UdpTestnetPacket {
        UdpTestnetPacket {
            source_node: UdpTestnetNodeId(1),
            target_node: UdpTestnetNodeId(2),
            packet_kind: UdpTestnetPacketKind::Probe,
            sequence_number: 0,
            payload: Vec::new(),
        }
    }

    // PK1: encode and decode a Probe packet
    #[test]
    fn pk1_encode_decode_probe() {
        let pkt = probe_packet();
        let encoded = encode_packet(&pkt);
        assert_eq!(encoded.len(), PACKET_HEADER_SIZE);
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.packet_kind, UdpTestnetPacketKind::Probe);
    }

    // PK2: encode and decode a Data packet with payload
    #[test]
    fn pk2_encode_decode_data() {
        let pkt = UdpTestnetPacket {
            source_node: UdpTestnetNodeId(3),
            target_node: UdpTestnetNodeId(7),
            packet_kind: UdpTestnetPacketKind::Data,
            sequence_number: 42,
            payload: b"hello world".to_vec(),
        };
        let encoded = encode_packet(&pkt);
        assert_eq!(encoded.len(), PACKET_HEADER_SIZE + 11);
        let decoded = decode_packet(&encoded).unwrap();
        assert_eq!(decoded, pkt);
        assert_eq!(decoded.payload, b"hello world");
    }

    // PK3: unknown packet kind rejected
    #[test]
    fn pk3_invalid_kind_rejected() {
        let mut bytes = encode_packet(&probe_packet());
        bytes[16] = 99; // invalid kind byte
        assert_eq!(
            decode_packet(&bytes),
            Err(UdpTestnetError::PacketDecodeFailed)
        );
    }

    // PK4: truncated packet rejected
    #[test]
    fn pk4_truncated_packet_rejected() {
        let bytes = &encode_packet(&probe_packet())[..10];
        assert_eq!(
            decode_packet(bytes),
            Err(UdpTestnetError::PacketDecodeFailed)
        );
    }

    // PK5: payload_len mismatch rejected (encoded len says 5 but actual payload differs)
    #[test]
    fn pk5_payload_len_mismatch_rejected() {
        let mut bytes = encode_packet(&probe_packet());
        // Set payload_len field to 5 but leave payload empty
        bytes[25] = 0;
        bytes[26] = 5;
        assert_eq!(
            decode_packet(&bytes),
            Err(UdpTestnetError::PacketDecodeFailed)
        );
    }
}
