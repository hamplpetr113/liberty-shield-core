use crate::relay_cell::{MAX_RELAY_PAYLOAD, RelayCell, RelayCommand};

/// Errors produced by relay cell encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCellError {
    /// Tag byte does not correspond to any known command.
    UnknownCommand(u8),
    /// The encoded buffer is shorter than the minimum header size.
    BufferTooShort,
    /// The payload length field claims more bytes than are present.
    TruncatedPayload,
    /// The payload exceeds `MAX_RELAY_PAYLOAD`.
    PayloadTooLarge,
}

/// Fixed size of the relay cell header in bytes.
///   8 (circuit_id) + 8 (stream_id) + 1 (command) + 8 (sequence) + 2 (payload_len)
pub const RELAY_HEADER_SIZE: usize = 27;

/// Encode a `RelayCell` into a byte buffer.
///
/// Returns `Err(PayloadTooLarge)` if `cell.payload.len() > MAX_RELAY_PAYLOAD`.
pub fn encode_relay_cell(cell: &RelayCell) -> Result<Vec<u8>, RelayCellError> {
    if cell.payload.len() > MAX_RELAY_PAYLOAD {
        return Err(RelayCellError::PayloadTooLarge);
    }
    let mut buf = Vec::with_capacity(RELAY_HEADER_SIZE + cell.payload.len());
    buf.extend_from_slice(&cell.circuit_id.to_le_bytes());
    buf.extend_from_slice(&cell.stream_id.to_le_bytes());
    buf.push(cell.command.tag());
    buf.extend_from_slice(&cell.sequence.to_le_bytes());
    buf.extend_from_slice(&(cell.payload.len() as u16).to_le_bytes());
    buf.extend_from_slice(&cell.payload);
    Ok(buf)
}

/// Decode a byte buffer into a `RelayCell`.
pub fn decode_relay_cell(buf: &[u8]) -> Result<RelayCell, RelayCellError> {
    if buf.len() < RELAY_HEADER_SIZE {
        return Err(RelayCellError::BufferTooShort);
    }
    let circuit_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
    let stream_id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
    let tag = buf[16];
    let command = RelayCommand::from_tag(tag).ok_or(RelayCellError::UnknownCommand(tag))?;
    let sequence = u64::from_le_bytes(buf[17..25].try_into().unwrap());
    let payload_len = u16::from_le_bytes(buf[25..27].try_into().unwrap()) as usize;

    if payload_len > MAX_RELAY_PAYLOAD {
        return Err(RelayCellError::PayloadTooLarge);
    }
    if buf.len() < RELAY_HEADER_SIZE + payload_len {
        return Err(RelayCellError::TruncatedPayload);
    }
    let payload = buf[RELAY_HEADER_SIZE..RELAY_HEADER_SIZE + payload_len].to_vec();
    Ok(RelayCell {
        circuit_id,
        stream_id,
        command,
        sequence,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay_cell::{MAX_RELAY_PAYLOAD, RelayCell, RelayCommand};

    fn cell(cmd: RelayCommand, payload: &[u8]) -> RelayCell {
        RelayCell::new(42, 7, cmd, 100, payload.to_vec())
    }

    // RC1: encode/decode RelayData roundtrip
    #[test]
    fn rc1_encode_decode_relay_data() {
        let c = cell(RelayCommand::RelayData, b"hello world");
        let encoded = encode_relay_cell(&c).unwrap();
        let decoded = decode_relay_cell(&encoded).unwrap();
        assert_eq!(decoded, c);
    }

    // RC2: encode/decode RelayExtend roundtrip
    #[test]
    fn rc2_encode_decode_relay_extend() {
        let c = cell(RelayCommand::RelayExtend, b"extend-target");
        let encoded = encode_relay_cell(&c).unwrap();
        let decoded = decode_relay_cell(&encoded).unwrap();
        assert_eq!(decoded, c);
    }

    // RC3: unknown command tag rejected during decode
    #[test]
    fn rc3_unknown_command_rejected() {
        let mut buf = encode_relay_cell(&cell(RelayCommand::RelayData, b"x")).unwrap();
        buf[16] = 99; // overwrite command byte with unknown tag
        assert_eq!(
            decode_relay_cell(&buf).unwrap_err(),
            RelayCellError::UnknownCommand(99)
        );
    }

    // RC4: buffer shorter than header rejected
    #[test]
    fn rc4_malformed_input_rejected() {
        let short = vec![0u8; RELAY_HEADER_SIZE - 1];
        assert_eq!(
            decode_relay_cell(&short).unwrap_err(),
            RelayCellError::BufferTooShort
        );
    }

    // RC5: sequence number is preserved through encode/decode
    #[test]
    fn rc5_sequence_preserved() {
        let c = RelayCell::new(1, 2, RelayCommand::RelayData, 0xDEAD_BEEF, b"seq".to_vec());
        let decoded = decode_relay_cell(&encode_relay_cell(&c).unwrap()).unwrap();
        assert_eq!(decoded.sequence, 0xDEAD_BEEF);
    }

    // RC6: padding cell accepted (all command variants roundtrip)
    #[test]
    fn rc6_padding_cell_accepted() {
        let c = cell(RelayCommand::RelayPadding, b"noise");
        let decoded = decode_relay_cell(&encode_relay_cell(&c).unwrap()).unwrap();
        assert_eq!(decoded.command, RelayCommand::RelayPadding);
    }

    // RC7: payload exceeding MAX_RELAY_PAYLOAD rejected
    #[test]
    fn rc7_max_payload_enforced() {
        let too_large = vec![0u8; MAX_RELAY_PAYLOAD + 1];
        let c = RelayCell::new(1, 1, RelayCommand::RelayData, 0, too_large);
        assert_eq!(
            encode_relay_cell(&c).unwrap_err(),
            RelayCellError::PayloadTooLarge
        );
    }

    // RC8: encoding is deterministic — same cell produces identical bytes
    #[test]
    fn rc8_deterministic_encoding() {
        let c = cell(RelayCommand::RelayData, b"deterministic");
        let b1 = encode_relay_cell(&c).unwrap();
        let b2 = encode_relay_cell(&c).unwrap();
        assert_eq!(b1, b2);
    }

    // RC9: all command variants encode and decode correctly
    #[test]
    fn rc9_all_commands_roundtrip() {
        use RelayCommand::*;
        for cmd in [
            RelayData,
            RelayExtend,
            RelayExtended,
            RelayBegin,
            RelayEnd,
            RelayDrop,
            RelayPadding,
        ] {
            let c = RelayCell::new(1, 1, cmd, 0, b"test".to_vec());
            let decoded = decode_relay_cell(&encode_relay_cell(&c).unwrap()).unwrap();
            assert_eq!(decoded.command, c.command);
        }
    }

    // RC10: truncated payload field rejected
    #[test]
    fn rc10_truncated_payload_rejected() {
        let c = cell(RelayCommand::RelayData, b"full payload here");
        let mut encoded = encode_relay_cell(&c).unwrap();
        // Claim 200 bytes of payload but only provide a few
        encoded[25] = 200;
        encoded[26] = 0;
        encoded.truncate(RELAY_HEADER_SIZE + 5);
        assert_eq!(
            decode_relay_cell(&encoded).unwrap_err(),
            RelayCellError::TruncatedPayload
        );
    }

    // RC11: circuit_id and stream_id preserved
    #[test]
    fn rc11_ids_preserved() {
        let c = RelayCell::new(
            0xCAFE_BABE,
            0x1234_5678,
            RelayCommand::RelayBegin,
            99,
            vec![],
        );
        let decoded = decode_relay_cell(&encode_relay_cell(&c).unwrap()).unwrap();
        assert_eq!(decoded.circuit_id, 0xCAFE_BABE);
        assert_eq!(decoded.stream_id, 0x1234_5678);
    }

    // RC12: empty payload accepted
    #[test]
    fn rc12_empty_payload_accepted() {
        let c = RelayCell::new(1, 1, RelayCommand::RelayDrop, 0, vec![]);
        let decoded = decode_relay_cell(&encode_relay_cell(&c).unwrap()).unwrap();
        assert!(decoded.payload.is_empty());
    }
}
