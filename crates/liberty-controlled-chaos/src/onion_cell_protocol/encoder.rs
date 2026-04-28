use super::cell::OnionCell;

/// Wire layout (little-endian):
///   circuit_id  : u64   (8 bytes)
///   cell_type   : u8    (1 byte)
///   payload_len : u32   (4 bytes)
///   payload     : [u8]  (payload_len bytes)
pub fn encode_cell(cell: &OnionCell) -> Vec<u8> {
    let mut out = Vec::with_capacity(13 + cell.payload.len());
    out.extend_from_slice(&cell.circuit_id.0.to_le_bytes());
    out.push(cell.cell_type.to_u8());
    out.extend_from_slice(&(cell.payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&cell.payload);
    out
}
