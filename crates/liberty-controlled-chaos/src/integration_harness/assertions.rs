use crate::cell_encoder::{CELL_SIZE, Cell};
use crate::noise_link::ENCRYPTED_CELL_SIZE;
use crate::onion_layer::ONION_PACKET_SIZE;

/// Assert the cell's byte buffer is exactly `CELL_SIZE` (1450) bytes.
pub fn assert_cell_size(cell: &Cell) {
    assert_eq!(
        cell.as_bytes().len(),
        CELL_SIZE,
        "cell must be exactly {CELL_SIZE} bytes"
    );
}

/// Assert the `ENCRYPTED_CELL_SIZE` constant equals 1482.
///
/// Wire layout: path_id(8) + nonce(8) + ciphertext(1450) + auth_tag(16) = 1482.
pub fn assert_encrypted_cell_wire_size() {
    assert_eq!(
        ENCRYPTED_CELL_SIZE, 1482,
        "ENCRYPTED_CELL_SIZE must be exactly 1482"
    );
}

/// Assert the `ONION_PACKET_SIZE` constant equals 1507.
///
/// Wire layout: layer_count(1) + nonce(8) + payload(1482) + outer_auth(16) = 1507.
pub fn assert_onion_packet_wire_size() {
    assert_eq!(
        ONION_PACKET_SIZE, 1507,
        "ONION_PACKET_SIZE must be exactly 1507"
    );
}

/// Assert the `ONION_PACKET_SIZE` constant is consistent with its wire-layout parts.
pub fn assert_onion_packet_formula() {
    assert_eq!(ONION_PACKET_SIZE, 1 + 8 + ENCRYPTED_CELL_SIZE + 16);
}
