//! Types for encrypted relay cells.

use super::errors::EncryptedRelayError;

/// Commands that can appear in a relay cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RelayCellCommand {
    /// Application data forwarded through the circuit.
    Data = 1,
    /// Tear down a stream on this circuit.
    End = 2,
    /// Confirm that a stream is open at the exit.
    Connected = 3,
    /// Flow-control credit acknowledgement.
    SendMe = 4,
    /// Request to extend the circuit by one hop.
    Extend = 5,
    /// Confirm that the circuit was extended.
    Extended = 6,
    /// Cover / padding cell; receivers discard it.
    Drop = 7,
}

impl RelayCellCommand {
    /// Convert the `u8` tag to a variant.  Returns an error for unknown tags.
    pub fn from_tag(tag: u8) -> Result<Self, EncryptedRelayError> {
        match tag {
            1 => Ok(Self::Data),
            2 => Ok(Self::End),
            3 => Ok(Self::Connected),
            4 => Ok(Self::SendMe),
            5 => Ok(Self::Extend),
            6 => Ok(Self::Extended),
            7 => Ok(Self::Drop),
            _ => Err(EncryptedRelayError::UnknownCommand(tag)),
        }
    }

    pub fn tag(self) -> u8 {
        self as u8
    }
}

/// Maximum payload bytes in a single relay cell.
pub const MAX_RELAY_PAYLOAD: usize = 498;

/// Wire header size: circuit_id(8) + stream_id(8) + sequence(8) + command(1) + payload_len(2).
pub const RELAY_HEADER_SIZE: usize = 27;

/// The plaintext content of one relay cell before encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCellPlaintext {
    pub circuit_id: u64,
    pub stream_id: u64,
    pub sequence: u64,
    pub command: RelayCellCommand,
    pub payload: Vec<u8>,
}

impl RelayCellPlaintext {
    pub fn new(
        circuit_id: u64,
        stream_id: u64,
        command: RelayCellCommand,
        sequence: u64,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            circuit_id,
            stream_id,
            sequence,
            command,
            payload,
        }
    }

    /// Serialize to bytes for AEAD encryption.
    pub fn encode(&self) -> Result<Vec<u8>, EncryptedRelayError> {
        if self.payload.len() > MAX_RELAY_PAYLOAD {
            return Err(EncryptedRelayError::PayloadTooLarge);
        }
        let mut buf = Vec::with_capacity(RELAY_HEADER_SIZE + self.payload.len());
        buf.extend_from_slice(&self.circuit_id.to_le_bytes());
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.extend_from_slice(&self.sequence.to_le_bytes());
        buf.push(self.command.tag());
        buf.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        Ok(buf)
    }

    /// Deserialize from bytes (output of `encode`).
    pub fn decode(buf: &[u8]) -> Result<Self, EncryptedRelayError> {
        if buf.len() < RELAY_HEADER_SIZE {
            return Err(EncryptedRelayError::BufferTooShort);
        }
        let circuit_id = u64::from_le_bytes(buf[0..8].try_into().unwrap());
        let stream_id = u64::from_le_bytes(buf[8..16].try_into().unwrap());
        let sequence = u64::from_le_bytes(buf[16..24].try_into().unwrap());
        let command = RelayCellCommand::from_tag(buf[24])?;
        let payload_len = u16::from_le_bytes(buf[25..27].try_into().unwrap()) as usize;
        if payload_len > MAX_RELAY_PAYLOAD {
            return Err(EncryptedRelayError::PayloadTooLarge);
        }
        if buf.len() < RELAY_HEADER_SIZE + payload_len {
            return Err(EncryptedRelayError::TruncatedPayload);
        }
        let payload = buf[RELAY_HEADER_SIZE..RELAY_HEADER_SIZE + payload_len].to_vec();
        Ok(Self {
            circuit_id,
            stream_id,
            sequence,
            command,
            payload,
        })
    }
}
