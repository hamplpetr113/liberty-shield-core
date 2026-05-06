/// Wire frame format (22-byte fixed header):
///
/// | Offset | Size | Field       |
/// |--------|------|-------------|
/// | 0      | 1    | version     |
/// | 1      | 1    | msg_type    |
/// | 2      | 2    | flags       |
/// | 4      | 8    | session_id  |
/// | 12     | 8    | sequence    |
/// | 20     | 2    | payload_len |
/// | 22     | N    | payload     |

pub const VERSION_1: u8 = 1;
pub const HEADER_SIZE: usize = 22;
pub const MAX_FRAME_SIZE: usize = 1500;
pub const MAX_PAYLOAD_SIZE: usize = MAX_FRAME_SIZE - HEADER_SIZE;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    Hello = 1,
    Data = 2,
    Keepalive = 3,
    Close = 4,
}

impl MessageType {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::Data),
            3 => Some(Self::Keepalive),
            4 => Some(Self::Close),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: u8,
    pub msg_type: MessageType,
    pub flags: u16,
    pub session_id: u64,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooShort,
    UnsupportedVersion(u8),
    UnknownMessageType(u8),
    PayloadTooLarge(usize),
    LengthMismatch { declared: usize, available: usize },
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort => write!(f, "buffer too short for frame header"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported version: {v}"),
            Self::UnknownMessageType(t) => write!(f, "unknown message type: {t}"),
            Self::PayloadTooLarge(n) => write!(f, "payload too large: {n} > {MAX_PAYLOAD_SIZE}"),
            Self::LengthMismatch {
                declared,
                available,
            } => {
                write!(
                    f,
                    "payload_len={declared} but only {available} bytes available"
                )
            }
        }
    }
}

pub fn parse_frame(buf: &[u8]) -> Result<Frame, FrameError> {
    if buf.len() < HEADER_SIZE {
        return Err(FrameError::TooShort);
    }

    let version = buf[0];
    if version != VERSION_1 {
        return Err(FrameError::UnsupportedVersion(version));
    }

    let msg_type_raw = buf[1];
    let msg_type =
        MessageType::from_u8(msg_type_raw).ok_or(FrameError::UnknownMessageType(msg_type_raw))?;

    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    let session_id = u64::from_be_bytes(buf[4..12].try_into().unwrap());
    let sequence = u64::from_be_bytes(buf[12..20].try_into().unwrap());
    let payload_len = u16::from_be_bytes([buf[20], buf[21]]) as usize;

    if payload_len > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(payload_len));
    }

    let available = buf.len() - HEADER_SIZE;
    if payload_len > available {
        return Err(FrameError::LengthMismatch {
            declared: payload_len,
            available,
        });
    }

    Ok(Frame {
        version,
        msg_type,
        flags,
        session_id,
        sequence,
        payload: buf[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec(),
    })
}

#[allow(dead_code)] // used by server once outbound sending is implemented
pub fn encode_frame(frame: &Frame, out: &mut Vec<u8>) -> Result<(), FrameError> {
    if frame.payload.len() > MAX_PAYLOAD_SIZE {
        return Err(FrameError::PayloadTooLarge(frame.payload.len()));
    }

    out.push(frame.version);
    out.push(frame.msg_type as u8);
    out.extend_from_slice(&frame.flags.to_be_bytes());
    out.extend_from_slice(&frame.session_id.to_be_bytes());
    out.extend_from_slice(&frame.sequence.to_be_bytes());
    out.extend_from_slice(&(frame.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&frame.payload);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_frame(
        msg_type: MessageType,
        session_id: u64,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Frame {
        Frame {
            version: VERSION_1,
            msg_type,
            flags: 0,
            session_id,
            sequence,
            payload,
        }
    }

    #[test]
    fn roundtrip_empty_payload() {
        let f = make_frame(MessageType::Keepalive, 42, 0, vec![]);
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE);
        let parsed = parse_frame(&buf).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn roundtrip_data_frame() {
        let payload = b"hello world".to_vec();
        let f = make_frame(
            MessageType::Data,
            0xDEAD_BEEF_CAFE_1234,
            99,
            payload.clone(),
        );
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE + payload.len());
        let parsed = parse_frame(&buf).unwrap();
        assert_eq!(parsed.payload, payload);
        assert_eq!(parsed.session_id, 0xDEAD_BEEF_CAFE_1234);
        assert_eq!(parsed.sequence, 99);
    }

    #[test]
    fn roundtrip_all_message_types() {
        for mt in [
            MessageType::Hello,
            MessageType::Data,
            MessageType::Keepalive,
            MessageType::Close,
        ] {
            let f = make_frame(mt, 1, 1, vec![0xAA]);
            let mut buf = Vec::new();
            encode_frame(&f, &mut buf).unwrap();
            let parsed = parse_frame(&buf).unwrap();
            assert_eq!(parsed.msg_type, mt);
        }
    }

    #[test]
    fn parse_error_too_short() {
        assert_eq!(parse_frame(&[0u8; 10]), Err(FrameError::TooShort));
        assert_eq!(parse_frame(&[]), Err(FrameError::TooShort));
    }

    #[test]
    fn parse_error_unsupported_version() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0] = 99;
        buf[1] = MessageType::Data as u8;
        assert_eq!(parse_frame(&buf), Err(FrameError::UnsupportedVersion(99)));
    }

    #[test]
    fn parse_error_unknown_message_type() {
        let mut buf = vec![0u8; HEADER_SIZE];
        buf[0] = VERSION_1;
        buf[1] = 255;
        assert_eq!(parse_frame(&buf), Err(FrameError::UnknownMessageType(255)));
    }

    #[test]
    fn parse_error_payload_too_large_declared() {
        let mut buf = vec![0u8; HEADER_SIZE + 10];
        buf[0] = VERSION_1;
        buf[1] = MessageType::Data as u8;
        let big: u16 = (MAX_PAYLOAD_SIZE + 1) as u16;
        buf[20] = (big >> 8) as u8;
        buf[21] = (big & 0xFF) as u8;
        assert_eq!(
            parse_frame(&buf),
            Err(FrameError::PayloadTooLarge(MAX_PAYLOAD_SIZE + 1))
        );
    }

    #[test]
    fn parse_error_length_mismatch() {
        let mut buf = vec![0u8; HEADER_SIZE + 2];
        buf[0] = VERSION_1;
        buf[1] = MessageType::Data as u8;
        buf[20] = 0;
        buf[21] = 10; // claims 10 bytes but only 2 available
        assert_eq!(
            parse_frame(&buf),
            Err(FrameError::LengthMismatch {
                declared: 10,
                available: 2
            })
        );
    }

    #[test]
    fn encode_error_payload_too_large() {
        let f = Frame {
            version: VERSION_1,
            msg_type: MessageType::Data,
            flags: 0,
            session_id: 0,
            sequence: 0,
            payload: vec![0u8; MAX_PAYLOAD_SIZE + 1],
        };
        let mut buf = Vec::new();
        assert_eq!(
            encode_frame(&f, &mut buf),
            Err(FrameError::PayloadTooLarge(MAX_PAYLOAD_SIZE + 1))
        );
    }

    #[test]
    fn header_fields_big_endian() {
        let f = make_frame(
            MessageType::Hello,
            0x0102030405060708,
            0x090A0B0C0D0E0F10,
            vec![],
        );
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        assert_eq!(
            &buf[4..12],
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        assert_eq!(
            &buf[12..20],
            &[0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
        );
    }

    #[test]
    fn max_payload_roundtrip() {
        let payload = vec![0xBBu8; MAX_PAYLOAD_SIZE];
        let f = make_frame(MessageType::Data, 7, 1000, payload.clone());
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        assert_eq!(buf.len(), MAX_FRAME_SIZE);
        let parsed = parse_frame(&buf).unwrap();
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn flags_preserved() {
        let f = Frame {
            version: VERSION_1,
            msg_type: MessageType::Data,
            flags: 0xABCD,
            session_id: 0,
            sequence: 0,
            payload: vec![],
        };
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        let parsed = parse_frame(&buf).unwrap();
        assert_eq!(parsed.flags, 0xABCD);
    }

    #[test]
    fn partial_buffer_after_payload_ignored() {
        let payload = b"abc".to_vec();
        let f = make_frame(MessageType::Data, 1, 1, payload.clone());
        let mut buf = Vec::new();
        encode_frame(&f, &mut buf).unwrap();
        // append trailing garbage
        buf.extend_from_slice(&[0xFF; 50]);
        let parsed = parse_frame(&buf).unwrap();
        assert_eq!(parsed.payload, payload);
    }
}
