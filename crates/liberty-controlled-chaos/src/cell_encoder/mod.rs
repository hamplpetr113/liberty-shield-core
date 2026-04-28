//! CellEncoder — converts `StreamFrame` values into fixed-size `Cell` values.
//!
//! Sits between `StreamMux` and `NoiseLink`.  Every cell is exactly 1450 bytes;
//! padding fills the remainder to prevent payload-size inference by observers.
//!
//! `CellEncoder` never encrypts, never opens sockets, and contains no unsafe.

mod encoder;
pub mod types;

pub use encoder::CellEncoder;
pub use types::{Cell, CellEncoderError, CellHeader, CELL_SIZE, HEADER_SIZE, MAX_PAYLOAD};
