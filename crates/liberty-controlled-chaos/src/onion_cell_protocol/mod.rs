//! OnionCellProtocol — binary encoding/decoding for onion protocol cells.
//!
//! Wire layout per cell:
//!   circuit_id(8 LE) | cell_type(1) | payload_len(4 LE) | payload(N)
//!
//! No encryption; no network I/O; fully deterministic.

mod cell;
mod cell_types;
mod decoder;
mod encoder;

pub use cell::OnionCell;
pub use cell_types::OnionCellType;
pub use decoder::{OnionCellError, decode_cell};
pub use encoder::encode_cell;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use crate::circuit_builder::CircuitId;

    use super::*;

    // ── oc1: encode / decode roundtrip ────────────────────────────────────────

    #[test]
    fn oc1_roundtrip_relay_data() {
        let cell = OnionCell::new(CircuitId(42), OnionCellType::RelayData, vec![1, 2, 3, 4]);
        let encoded = encode_cell(&cell);
        let decoded = decode_cell(&encoded).unwrap();
        assert_eq!(decoded, cell);
    }

    #[test]
    fn oc1_roundtrip_empty_payload() {
        let cell = OnionCell::new(CircuitId(0), OnionCellType::KeepAlive, vec![]);
        let encoded = encode_cell(&cell);
        let decoded = decode_cell(&encoded).unwrap();
        assert_eq!(decoded, cell);
    }

    // ── oc2: payload length mismatch rejected ─────────────────────────────────

    #[test]
    fn oc2_payload_length_mismatch_rejected() {
        let mut cell = OnionCell::new(CircuitId(1), OnionCellType::RelayData, vec![10, 20, 30]);
        let mut encoded = encode_cell(&cell);

        // Corrupt the payload_len field to claim 10 bytes instead of 3.
        encoded[9] = 10;
        encoded[10] = 0;
        encoded[11] = 0;
        encoded[12] = 0;

        let err = decode_cell(&encoded).unwrap_err();
        assert!(matches!(
            err,
            OnionCellError::PayloadLengthMismatch {
                stated: 10,
                actual: 3
            }
        ));

        // Also check: truncating the buffer below the stated payload_len.
        cell.payload = vec![0u8; 20];
        let mut encoded2 = encode_cell(&cell);
        encoded2.truncate(13 + 5); // only 5 bytes of payload instead of 20
        let err2 = decode_cell(&encoded2).unwrap_err();
        assert!(matches!(
            err2,
            OnionCellError::PayloadLengthMismatch {
                stated: 20,
                actual: 5
            }
        ));
    }

    // ── oc3: padding cell accepted ────────────────────────────────────────────

    #[test]
    fn oc3_padding_cell_accepted() {
        let cell = OnionCell::new(CircuitId(7), OnionCellType::Padding, vec![0u8; 64]);
        let encoded = encode_cell(&cell);
        let decoded = decode_cell(&encoded).unwrap();
        assert_eq!(decoded.cell_type, OnionCellType::Padding);
        assert_eq!(decoded.payload.len(), 64);
    }

    // ── oc4: all cell types roundtrip ─────────────────────────────────────────

    #[test]
    fn oc4_all_cell_types_roundtrip() {
        let types = [
            OnionCellType::RelayData,
            OnionCellType::RelayControl,
            OnionCellType::Padding,
            OnionCellType::Cover,
            OnionCellType::Destroy,
            OnionCellType::KeepAlive,
        ];
        for ct in types {
            let cell = OnionCell::new(CircuitId(99), ct, vec![0xAB; 4]);
            let decoded = decode_cell(&encode_cell(&cell)).unwrap();
            assert_eq!(decoded.cell_type, ct);
        }
    }

    // ── oc5: too-short buffer rejected ────────────────────────────────────────

    #[test]
    fn oc5_short_buffer_rejected() {
        let err = decode_cell(&[0u8; 12]).unwrap_err();
        assert_eq!(err, OnionCellError::InvalidLength);
    }

    // ── oc6: invalid cell type byte rejected ──────────────────────────────────

    #[test]
    fn oc6_invalid_cell_type_rejected() {
        let cell = OnionCell::new(CircuitId(1), OnionCellType::RelayData, vec![]);
        let mut encoded = encode_cell(&cell);
        encoded[8] = 0xFF; // unknown cell type
        let err = decode_cell(&encoded).unwrap_err();
        assert_eq!(err, OnionCellError::InvalidCellType);
    }
}
