//! Mesh packet framer — encodes/decodes length-prefixed frames for the mesh layer.
//!
//! Frame format: [4-byte LE length][payload bytes]
//! Maximum frame payload: 65535 bytes.

// ---------------------------------------------------------------------------
// FrameError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Truncated,
    ZeroLength,
}

// ---------------------------------------------------------------------------
// MeshPacketFramer
// ---------------------------------------------------------------------------

pub const MAX_FRAME_PAYLOAD: usize = 65535;

pub struct MeshPacketFramer {
    frames_encoded: u64,
    frames_decoded: u64,
    decode_errors: u64,
}

impl MeshPacketFramer {
    pub fn new() -> Self {
        Self {
            frames_encoded: 0,
            frames_decoded: 0,
            decode_errors: 0,
        }
    }

    /// Encode a payload into a length-prefixed frame.
    pub fn encode(&mut self, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
        if payload.is_empty() {
            return Err(FrameError::ZeroLength);
        }
        if payload.len() > MAX_FRAME_PAYLOAD {
            return Err(FrameError::TooLarge);
        }
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(4 + payload.len());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(payload);
        self.frames_encoded += 1;
        Ok(out)
    }

    /// Decode a single frame from `buf`. Returns (payload, bytes_consumed).
    pub fn decode<'a>(&mut self, buf: &'a [u8]) -> Result<(&'a [u8], usize), FrameError> {
        if buf.len() < 4 {
            self.decode_errors += 1;
            return Err(FrameError::Truncated);
        }
        let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == 0 {
            self.decode_errors += 1;
            return Err(FrameError::ZeroLength);
        }
        if len > MAX_FRAME_PAYLOAD {
            self.decode_errors += 1;
            return Err(FrameError::TooLarge);
        }
        if buf.len() < 4 + len {
            self.decode_errors += 1;
            return Err(FrameError::Truncated);
        }
        self.frames_decoded += 1;
        Ok((&buf[4..4 + len], 4 + len))
    }

    /// Decode all frames from a buffer.
    pub fn decode_all<'a>(&mut self, buf: &'a [u8]) -> Vec<&'a [u8]> {
        let mut out = Vec::new();
        let mut pos = 0;
        while pos < buf.len() {
            match self.decode(&buf[pos..]) {
                Ok((payload, consumed)) => {
                    out.push(payload);
                    pos += consumed;
                }
                Err(_) => break,
            }
        }
        out
    }

    pub fn frames_encoded(&self) -> u64 {
        self.frames_encoded
    }

    pub fn frames_decoded(&self) -> u64 {
        self.frames_decoded
    }

    pub fn decode_errors(&self) -> u64 {
        self.decode_errors
    }
}

impl Default for MeshPacketFramer {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // MPF1: encode→decode roundtrip.
    #[test]
    fn mpf1_roundtrip() {
        let mut f = MeshPacketFramer::new();
        let frame = f.encode(b"hello world").unwrap();
        let (payload, consumed) = f.decode(&frame).unwrap();
        assert_eq!(payload, b"hello world");
        assert_eq!(consumed, 4 + 11);
    }

    // MPF2: empty payload returns ZeroLength.
    #[test]
    fn mpf2_zero_length_encode() {
        let mut f = MeshPacketFramer::new();
        assert_eq!(f.encode(&[]), Err(FrameError::ZeroLength));
    }

    // MPF3: oversized payload returns TooLarge.
    #[test]
    fn mpf3_too_large() {
        let mut f = MeshPacketFramer::new();
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert_eq!(f.encode(&big), Err(FrameError::TooLarge));
    }

    // MPF4: truncated buffer returns Truncated.
    #[test]
    fn mpf4_truncated() {
        let mut f = MeshPacketFramer::new();
        let frame = f.encode(b"data").unwrap();
        assert_eq!(
            f.decode(&frame[..frame.len() - 1]),
            Err(FrameError::Truncated)
        );
    }

    // MPF5: buffer shorter than header returns Truncated.
    #[test]
    fn mpf5_header_truncated() {
        let mut f = MeshPacketFramer::new();
        assert_eq!(f.decode(b"ab"), Err(FrameError::Truncated));
    }

    // MPF6: decode_all handles multiple frames.
    #[test]
    fn mpf6_decode_all() {
        let mut f = MeshPacketFramer::new();
        let mut buf = Vec::new();
        buf.extend(f.encode(b"first").unwrap());
        buf.extend(f.encode(b"second").unwrap());
        let frames = f.decode_all(&buf);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0], b"first");
        assert_eq!(frames[1], b"second");
    }

    // MPF7: frames_encoded counter increments.
    #[test]
    fn mpf7_encoded_counter() {
        let mut f = MeshPacketFramer::new();
        f.encode(b"a").unwrap();
        f.encode(b"b").unwrap();
        assert_eq!(f.frames_encoded(), 2);
    }

    // MPF8: frames_decoded counter increments.
    #[test]
    fn mpf8_decoded_counter() {
        let mut f = MeshPacketFramer::new();
        let frame = f.encode(b"x").unwrap();
        f.decode(&frame).unwrap();
        assert_eq!(f.frames_decoded(), 1);
    }

    // MPF9: decode_errors increments on bad input.
    #[test]
    fn mpf9_decode_error_counter() {
        let mut f = MeshPacketFramer::new();
        f.decode(b"x").unwrap_err();
        assert_eq!(f.decode_errors(), 1);
    }

    // MPF10: max-size payload encodes and decodes correctly.
    #[test]
    fn mpf10_max_payload() {
        let mut f = MeshPacketFramer::new();
        let max = vec![0xABu8; MAX_FRAME_PAYLOAD];
        let frame = f.encode(&max).unwrap();
        let (payload, _) = f.decode(&frame).unwrap();
        assert_eq!(payload.len(), MAX_FRAME_PAYLOAD);
    }
}
