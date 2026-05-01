/// Maximum byte length of a relay cell payload.
pub const MAX_RELAY_PAYLOAD: usize = 498;

/// Commands a relay cell can carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayCommand {
    /// Carry user data.
    RelayData,
    /// Ask the next hop to extend the circuit.
    RelayExtend,
    /// Confirm that extension succeeded.
    RelayExtended,
    /// Open a new stream to a destination.
    RelayBegin,
    /// Close a stream.
    RelayEnd,
    /// Sent to keep circuits alive; payload is ignored.
    RelayDrop,
    /// Random padding; payload is ignored.
    RelayPadding,
}

impl RelayCommand {
    /// Wire tag used in the encoded cell header.
    pub fn tag(&self) -> u8 {
        match self {
            RelayCommand::RelayData => 1,
            RelayCommand::RelayExtend => 2,
            RelayCommand::RelayExtended => 3,
            RelayCommand::RelayBegin => 4,
            RelayCommand::RelayEnd => 5,
            RelayCommand::RelayDrop => 6,
            RelayCommand::RelayPadding => 7,
        }
    }

    /// Decode a wire tag back to a command variant.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(RelayCommand::RelayData),
            2 => Some(RelayCommand::RelayExtend),
            3 => Some(RelayCommand::RelayExtended),
            4 => Some(RelayCommand::RelayBegin),
            5 => Some(RelayCommand::RelayEnd),
            6 => Some(RelayCommand::RelayDrop),
            7 => Some(RelayCommand::RelayPadding),
            _ => None,
        }
    }
}

/// A relay cell travelling inside an onion circuit.
///
/// Wire layout (little-endian):
///   [0..8]   circuit_id  u64
///   [8..16]  stream_id   u64
///   [16]     command tag u8
///   [17..25] sequence    u64
///   [25..27] payload_len u16
///   [27..]   payload     bytes (≤ MAX_RELAY_PAYLOAD)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCell {
    pub circuit_id: u64,
    pub stream_id: u64,
    pub command: RelayCommand,
    pub sequence: u64,
    pub payload: Vec<u8>,
}

impl RelayCell {
    pub fn new(
        circuit_id: u64,
        stream_id: u64,
        command: RelayCommand,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            circuit_id,
            stream_id,
            command,
            sequence,
            payload,
        }
    }
}
