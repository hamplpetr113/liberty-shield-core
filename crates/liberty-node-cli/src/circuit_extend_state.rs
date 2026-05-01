use std::collections::HashSet;

/// States a circuit extension can be in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtendState {
    Created,
    Extending,
    Extended,
    Failed,
    Closed,
}

impl ExtendState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExtendState::Created => "Created",
            ExtendState::Extending => "Extending",
            ExtendState::Extended => "Extended",
            ExtendState::Failed => "Failed",
            ExtendState::Closed => "Closed",
        }
    }
}

/// An extend request: ask the current last hop to connect to `target_node`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendRequest {
    pub target_node: u64,
    pub next_hop: u64,
    /// NON-PRODUCTION placeholder key material (deterministic).
    pub onion_key_material: Vec<u8>,
}

/// Response from an extend request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtendResponse {
    pub accepted: bool,
    pub reason: String,
    pub next_circuit_id: u64,
}

/// The mutable state of a single circuit extension session.
#[derive(Debug)]
pub struct CircuitExtendState {
    pub circuit_id: u64,
    pub state: ExtendState,
    /// Ordered hop node IDs already in the circuit.
    pub hops: Vec<u64>,
    /// Set for fast duplicate detection.
    hop_set: HashSet<u64>,
    /// Pending extend request waiting for a response.
    pub pending_target: Option<u64>,
}

impl CircuitExtendState {
    pub fn new(circuit_id: u64, origin_node: u64) -> Self {
        let mut hop_set = HashSet::new();
        hop_set.insert(origin_node);
        Self {
            circuit_id,
            state: ExtendState::Created,
            hops: vec![origin_node],
            hop_set,
            pending_target: None,
        }
    }

    pub fn hop_count(&self) -> usize {
        self.hops.len()
    }

    pub fn contains_node(&self, node_id: u64) -> bool {
        self.hop_set.contains(&node_id)
    }

    /// Mark the circuit as Extending toward `target_node`.
    pub fn begin_extending(&mut self, target_node: u64) {
        self.state = ExtendState::Extending;
        self.pending_target = Some(target_node);
    }

    /// Confirm the extension: add the new hop.
    pub fn confirm_extended(&mut self, new_node: u64) {
        self.hops.push(new_node);
        self.hop_set.insert(new_node);
        self.pending_target = None;
        self.state = ExtendState::Extended;
    }

    pub fn fail(&mut self) {
        self.pending_target = None;
        self.state = ExtendState::Failed;
    }

    pub fn close(&mut self) {
        self.pending_target = None;
        self.state = ExtendState::Closed;
    }
}
