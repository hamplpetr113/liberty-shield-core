//! Fixed-size cell framing for the Liberty Shield transport layer.
//!
//! Every cell on the wire is exactly `CELL_FRAME_SIZE` bytes, regardless of
//! the actual payload size.  Short payloads are zero-padded; the 4-byte
//! length prefix allows correct extraction at the receiver.
//!
//! Wire format:
//!   version(1) | payload_len(4 LE) | payload(≤ MAX_FRAME_PAYLOAD) | padding
//!
//! All bytes after `payload_len + 5` (header bytes) are padding and MUST be
//! zero on send.  The receiver ignores them after verifying length bounds.

/// Total wire size of one framed cell.
pub const CELL_FRAME_SIZE: usize = 512;

/// Header: version byte (1) + payload length (4 LE u32).
const HEADER_SIZE: usize = 5;

/// Maximum payload bytes that fit in a single frame.
pub const MAX_FRAME_PAYLOAD: usize = CELL_FRAME_SIZE - HEADER_SIZE; // 507

/// Current frame format version.
pub const FRAME_VERSION: u8 = 0x01;

/// Error variants for cell framing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// Payload exceeds `MAX_FRAME_PAYLOAD`.
    PayloadTooLarge,
    /// Buffer is not exactly `CELL_FRAME_SIZE` bytes.
    InvalidFrameSize,
    /// Version byte is not `FRAME_VERSION`.
    UnknownVersion,
    /// Declared payload length exceeds available bytes.
    LengthOverflow,
}

/// A fixed-size framed cell: exactly `CELL_FRAME_SIZE` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FramedCell {
    buf: [u8; CELL_FRAME_SIZE],
}

impl FramedCell {
    /// Return the raw wire bytes.
    pub fn as_bytes(&self) -> &[u8; CELL_FRAME_SIZE] {
        &self.buf
    }

    /// Return the payload slice (without header or padding).
    pub fn payload(&self) -> &[u8] {
        let len = u32::from_le_bytes(self.buf[1..5].try_into().unwrap()) as usize;
        &self.buf[HEADER_SIZE..HEADER_SIZE + len]
    }

    /// Return the declared payload length.
    pub fn payload_len(&self) -> usize {
        u32::from_le_bytes(self.buf[1..5].try_into().unwrap()) as usize
    }
}

/// Encode `payload` into a fixed-size `FramedCell`.
///
/// Zero-pads the frame to exactly `CELL_FRAME_SIZE` bytes.
pub fn frame_cell(payload: &[u8]) -> Result<FramedCell, FrameError> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(FrameError::PayloadTooLarge);
    }
    let mut buf = [0u8; CELL_FRAME_SIZE];
    buf[0] = FRAME_VERSION;
    let len = payload.len() as u32;
    buf[1..5].copy_from_slice(&len.to_le_bytes());
    buf[HEADER_SIZE..HEADER_SIZE + payload.len()].copy_from_slice(payload);
    // Remainder is already zeroed by array initialisation.
    Ok(FramedCell { buf })
}

/// Decode a `FramedCell` from a fixed-size buffer.
///
/// Verifies version and length bounds; ignores padding.
pub fn parse_cell(raw: &[u8; CELL_FRAME_SIZE]) -> Result<FramedCell, FrameError> {
    if raw[0] != FRAME_VERSION {
        return Err(FrameError::UnknownVersion);
    }
    let payload_len = u32::from_le_bytes(raw[1..5].try_into().unwrap()) as usize;
    if payload_len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::LengthOverflow);
    }
    Ok(FramedCell { buf: *raw })
}

/// Parse a cell from an arbitrary byte slice.
///
/// Slice must be exactly `CELL_FRAME_SIZE` bytes.
pub fn parse_cell_slice(raw: &[u8]) -> Result<FramedCell, FrameError> {
    if raw.len() != CELL_FRAME_SIZE {
        return Err(FrameError::InvalidFrameSize);
    }
    let arr: &[u8; CELL_FRAME_SIZE] = raw.try_into().unwrap();
    parse_cell(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    // CF1: short payload is padded to CELL_FRAME_SIZE
    #[test]
    fn cf1_short_payload_padded() {
        let payload = b"hello";
        let framed = frame_cell(payload).unwrap();
        assert_eq!(framed.as_bytes().len(), CELL_FRAME_SIZE);
        assert_eq!(framed.payload(), payload);
        // Bytes after the payload must be zero.
        let after = &framed.as_bytes()[HEADER_SIZE + payload.len()..];
        assert!(after.iter().all(|&b| b == 0));
    }

    // CF2: max-length payload fits exactly
    #[test]
    fn cf2_max_payload() {
        let payload = vec![0xAAu8; MAX_FRAME_PAYLOAD];
        let framed = frame_cell(&payload).unwrap();
        assert_eq!(framed.payload(), &payload);
        assert_eq!(framed.payload_len(), MAX_FRAME_PAYLOAD);
    }

    // CF3: payload one byte too large returns error
    #[test]
    fn cf3_overflow_rejected() {
        let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert_eq!(
            frame_cell(&payload).unwrap_err(),
            FrameError::PayloadTooLarge
        );
    }

    // CF4: empty payload
    #[test]
    fn cf4_empty_payload() {
        let framed = frame_cell(b"").unwrap();
        assert_eq!(framed.payload_len(), 0);
        assert_eq!(framed.payload(), b"");
    }

    // CF5: roundtrip — frame then parse
    #[test]
    fn cf5_roundtrip() {
        let payload = b"Liberty Shield cell frame test";
        let framed = frame_cell(payload).unwrap();
        let parsed = parse_cell(framed.as_bytes()).unwrap();
        assert_eq!(parsed.payload(), payload);
    }

    // CF6: version byte is checked
    #[test]
    fn cf6_bad_version() {
        let mut buf = [0u8; CELL_FRAME_SIZE];
        buf[0] = 0xFF; // unknown version
        assert_eq!(parse_cell(&buf).unwrap_err(), FrameError::UnknownVersion);
    }

    // CF7: declared length overflow is rejected
    #[test]
    fn cf7_length_overflow() {
        let mut buf = [0u8; CELL_FRAME_SIZE];
        buf[0] = FRAME_VERSION;
        let bad_len = (MAX_FRAME_PAYLOAD + 1) as u32;
        buf[1..5].copy_from_slice(&bad_len.to_le_bytes());
        assert_eq!(parse_cell(&buf).unwrap_err(), FrameError::LengthOverflow);
    }

    // CF8: wrong slice length rejected
    #[test]
    fn cf8_wrong_slice_length() {
        let short = vec![0u8; CELL_FRAME_SIZE - 1];
        assert_eq!(
            parse_cell_slice(&short).unwrap_err(),
            FrameError::InvalidFrameSize
        );
        let long = vec![0u8; CELL_FRAME_SIZE + 1];
        assert_eq!(
            parse_cell_slice(&long).unwrap_err(),
            FrameError::InvalidFrameSize
        );
    }

    // CF9: padding is consistently zero on frame
    #[test]
    fn cf9_padding_is_zero() {
        let payload = b"short";
        let framed = frame_cell(payload).unwrap();
        let raw = framed.as_bytes();
        for &b in &raw[HEADER_SIZE + payload.len()..] {
            assert_eq!(b, 0, "padding must be zero");
        }
    }

    // CF10: framed cells are constant size for all payload lengths
    #[test]
    fn cf10_constant_size() {
        for len in [0, 1, 100, 255, MAX_FRAME_PAYLOAD] {
            let payload = vec![0u8; len];
            let framed = frame_cell(&payload).unwrap();
            assert_eq!(framed.as_bytes().len(), CELL_FRAME_SIZE);
        }
    }

    // CF11: parse_cell_slice accepts a valid cell
    #[test]
    fn cf11_parse_slice_valid() {
        let payload = b"slice parse test";
        let framed = frame_cell(payload).unwrap();
        let parsed = parse_cell_slice(framed.as_bytes()).unwrap();
        assert_eq!(parsed.payload(), payload);
    }
}
