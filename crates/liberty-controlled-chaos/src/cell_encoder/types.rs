//! Public types for the CellEncoder layer.

// ── Constants ─────────────────────────────────────────────────────────────────

/// Fixed size of every transport cell in bytes.
pub const CELL_SIZE: usize = 1450;

/// Size of the cell header in bytes.
/// Layout: version(1) + flags(1) + stream_id(8) + seq(8) + path_id(8) +
///         fragment_id(8) + payload_length(2) + reserved(7) = 43 bytes.
pub const HEADER_SIZE: usize = 43;

/// Maximum payload bytes that fit in a single cell.
pub const MAX_PAYLOAD: usize = CELL_SIZE - HEADER_SIZE; // 1407

// Header field byte offsets.
const OFF_VERSION: usize = 0;
const OFF_FLAGS: usize = 1;
const OFF_STREAM_ID: usize = 2;
const OFF_SEQ: usize = 10;
const OFF_PATH_ID: usize = 18;
const OFF_FRAGMENT_ID: usize = 26;
const OFF_PAYLOAD_LEN: usize = 34;
// Bytes 36-42: reserved, zeroed.

/// Current cell format version byte.
pub const CELL_VERSION: u8 = 0x01;

// ── CellHeader ────────────────────────────────────────────────────────────────

/// Parsed view of the 43-byte cell header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellHeader {
    pub version: u8,
    pub flags: u8,
    pub stream_id: u64,
    pub sequence_number: u64,
    pub path_id: u64,
    pub fragment_id: u64,
    pub payload_length: u16,
}

impl CellHeader {
    /// True when the `is_cover` flag (bit 0) is set.
    pub fn is_cover(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// True when the `is_reset` flag (bit 1) is set.
    pub fn is_reset(&self) -> bool {
        self.flags & 0x02 != 0
    }
}

// ── Cell ──────────────────────────────────────────────────────────────────────

/// Fixed-size transport cell: exactly 1450 bytes.
///
/// The constructor is private to this module; cells may only be produced by
/// `CellEncoder::encode`, which guarantees the invariants.
#[derive(Debug)]
pub struct Cell {
    pub(super) data: [u8; CELL_SIZE],
}

impl Cell {
    /// Construct a `Cell` from a raw 1450-byte buffer produced by decryption.
    /// `pub(crate)` so that `NoiseLink` can reconstruct a `Cell` after decrypting
    /// an `EncryptedCell` without exposing the constructor to external crates.
    pub(crate) fn from_raw(data: [u8; CELL_SIZE]) -> Self {
        Self { data }
    }

    /// Parse and return the 43-byte header.
    pub fn header(&self) -> CellHeader {
        CellHeader {
            version: self.data[OFF_VERSION],
            flags: self.data[OFF_FLAGS],
            stream_id: u64::from_le_bytes(
                self.data[OFF_STREAM_ID..OFF_STREAM_ID + 8]
                    .try_into()
                    .unwrap(),
            ),
            sequence_number: u64::from_le_bytes(
                self.data[OFF_SEQ..OFF_SEQ + 8].try_into().unwrap(),
            ),
            path_id: u64::from_le_bytes(
                self.data[OFF_PATH_ID..OFF_PATH_ID + 8].try_into().unwrap(),
            ),
            fragment_id: u64::from_le_bytes(
                self.data[OFF_FRAGMENT_ID..OFF_FRAGMENT_ID + 8]
                    .try_into()
                    .unwrap(),
            ),
            payload_length: u16::from_le_bytes(
                self.data[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
                    .try_into()
                    .unwrap(),
            ),
        }
    }

    /// Slice of the actual payload bytes (length = `header.payload_length`).
    pub fn payload_bytes(&self) -> &[u8] {
        let len = u16::from_le_bytes(
            self.data[OFF_PAYLOAD_LEN..OFF_PAYLOAD_LEN + 2]
                .try_into()
                .unwrap(),
        ) as usize;
        &self.data[HEADER_SIZE..HEADER_SIZE + len]
    }

    /// The full 1450-byte cell for `NoiseLink`.
    pub fn as_bytes(&self) -> &[u8; CELL_SIZE] {
        &self.data
    }
}

// ── CellEncoderError ──────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CellEncoderError {
    /// Payload exceeds the maximum capacity of a single cell.
    PayloadTooLarge { length: usize, max: usize },
}
