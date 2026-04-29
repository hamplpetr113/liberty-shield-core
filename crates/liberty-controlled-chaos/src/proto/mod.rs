//! Wire protocol primitives for Liberty Shield.
//!
//! Modules:
//! - `cell_frame`: fixed-size cell framing with zero-padding.

pub mod cell_frame;

pub use cell_frame::{
    CELL_FRAME_SIZE, FRAME_VERSION, FrameError, FramedCell, MAX_FRAME_PAYLOAD, frame_cell,
    parse_cell, parse_cell_slice,
};
