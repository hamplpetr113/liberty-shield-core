/// Aggregate statistics collected during a mesh simulation run.
#[derive(Debug, Clone, Default)]
pub struct MeshMetrics {
    /// Total packets injected by the simulated client.
    pub packets_sent: u64,
    /// Total successful hop-forwards across all nodes and all packets.
    pub packets_forwarded: u64,
    /// Total packets that were dropped at any hop (replay or other).
    pub packets_dropped: u64,
    /// Total packets rejected by replay detection.
    pub replay_rejected: u64,
    /// Total cover-traffic intents generated across all epochs.
    pub cover_packets: u64,
    /// Sum of path lengths for all fully-delivered packets.
    total_path_hops: u64,
    /// Number of packets that reached the exit node.
    pub paths_completed: u64,
}

impl MeshMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_sent(&mut self) {
        self.packets_sent += 1;
    }

    pub fn record_hop_forward(&mut self) {
        self.packets_forwarded += 1;
    }

    pub fn record_drop(&mut self) {
        self.packets_dropped += 1;
    }

    pub fn record_replay_rejected(&mut self) {
        self.replay_rejected += 1;
    }

    pub fn record_cover(&mut self) {
        self.cover_packets += 1;
    }

    pub fn record_delivery(&mut self, hop_count: u64) {
        self.paths_completed += 1;
        self.total_path_hops += hop_count;
    }

    /// Mean path length across all delivered packets.
    /// Returns `0.0` if no packets have been delivered yet.
    pub fn average_path_length(&self) -> f64 {
        if self.paths_completed == 0 {
            return 0.0;
        }
        self.total_path_hops as f64 / self.paths_completed as f64
    }
}
