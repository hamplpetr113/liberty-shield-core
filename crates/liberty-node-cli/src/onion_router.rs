use crate::encrypted_circuit_path::CircuitError;
use crate::encrypted_circuit_runtime::EncryptedCircuitRuntime;
use crate::encrypted_udp_types::EncryptedUdpNodeId;
use crate::onion_packet::{OnionPacket, OnionPacketError, wrap_layers};

/// Errors produced by the onion router.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnionRouterError {
    /// The circuit referenced by the packet is not registered.
    UnknownCircuit,
    /// The onion packet layer could not be unwrapped.
    CryptoError(OnionPacketError),
    /// The underlying circuit runtime returned an error.
    CircuitError(CircuitError),
}

impl From<OnionPacketError> for OnionRouterError {
    fn from(e: OnionPacketError) -> Self {
        OnionRouterError::CryptoError(e)
    }
}

impl From<CircuitError> for OnionRouterError {
    fn from(e: CircuitError) -> Self {
        OnionRouterError::CircuitError(e)
    }
}

/// The result of processing one onion packet.
#[derive(Debug, Clone)]
pub enum ProcessResult {
    /// Packet was decrypted and forwarded; inner packet is ready for the next hop.
    Forward(OnionPacket),
    /// Packet has reached the exit hop; inner bytes are the final plaintext.
    Delivered(Vec<u8>),
}

/// Onion router: receives packets, decrypts one layer, and forwards to the next hop.
///
/// Each `OnionRouter` instance owns one `EncryptedCircuitRuntime` for hop tracking.
pub struct OnionRouter {
    runtime: EncryptedCircuitRuntime,
    /// Hop node IDs indexed by circuit ID.
    circuit_hops: std::collections::HashMap<u64, Vec<u64>>,
}

impl OnionRouter {
    pub fn new() -> Self {
        Self {
            runtime: EncryptedCircuitRuntime::new(),
            circuit_hops: std::collections::HashMap::new(),
        }
    }

    /// Register a circuit with its ordered hop node IDs.
    ///
    /// `hop_node_ids` must be ordered [guard, relay…, exit].
    pub fn register_circuit(
        &mut self,
        circuit_id: u64,
        hop_node_ids: Vec<u64>,
    ) -> Result<(), OnionRouterError> {
        use crate::encrypted_circuit_path::EncryptedCircuitPath;

        if hop_node_ids.len() < 3 {
            return Err(OnionRouterError::CircuitError(CircuitError::TooFewHops));
        }
        let udp_hops: Vec<EncryptedUdpNodeId> = hop_node_ids
            .iter()
            .map(|&id| EncryptedUdpNodeId(id))
            .collect();
        let path = EncryptedCircuitPath::new(circuit_id, udp_hops, 1000)
            .map_err(OnionRouterError::CircuitError)?;
        self.runtime
            .register_circuit(path)
            .map_err(OnionRouterError::CircuitError)?;
        self.circuit_hops.insert(circuit_id, hop_node_ids);
        Ok(())
    }

    /// Build an outbound onion packet from `plaintext` for a registered circuit.
    pub fn build_packet(
        &self,
        circuit_id: u64,
        plaintext: &[u8],
    ) -> Result<OnionPacket, OnionRouterError> {
        let hops = self
            .circuit_hops
            .get(&circuit_id)
            .ok_or(OnionRouterError::UnknownCircuit)?;
        wrap_layers(circuit_id, plaintext, hops).map_err(Into::into)
    }

    /// Process one incoming onion packet: decrypt the current hop's layer and
    /// return either a `Forward` (more hops remain) or `Delivered` (final hop).
    pub fn process_packet(&mut self, pkt: OnionPacket) -> Result<ProcessResult, OnionRouterError> {
        let circuit_id = pkt.circuit_id;
        let hops = self
            .circuit_hops
            .get(&circuit_id)
            .ok_or(OnionRouterError::UnknownCircuit)?;

        let current_node_id = *hops
            .get(pkt.hop_index)
            .ok_or(OnionRouterError::UnknownCircuit)?;
        let is_final = pkt.hop_index + 1 >= hops.len();

        let inner = pkt.unwrap_layer(current_node_id)?;

        if is_final {
            Ok(ProcessResult::Delivered(inner.encrypted_payload))
        } else {
            Ok(ProcessResult::Forward(inner))
        }
    }

    pub fn circuit_count(&self) -> usize {
        self.circuit_hops.len()
    }
}

impl Default for OnionRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hops() -> Vec<u64> {
        vec![10, 20, 30]
    }

    fn router_with_circuit(circuit_id: u64) -> OnionRouter {
        let mut r = OnionRouter::new();
        r.register_circuit(circuit_id, hops()).unwrap();
        r
    }

    // OR1: packet moves hop-by-hop through the circuit
    #[test]
    fn or1_packet_moves_hop_by_hop() {
        let mut r = router_with_circuit(1);
        let pkt = r.build_packet(1, b"hello").unwrap();
        assert_eq!(pkt.hop_index, 0);

        let ProcessResult::Forward(pkt1) = r.process_packet(pkt).unwrap() else {
            panic!("expected Forward at hop 0");
        };
        assert_eq!(pkt1.hop_index, 1);

        let ProcessResult::Forward(pkt2) = r.process_packet(pkt1).unwrap() else {
            panic!("expected Forward at hop 1");
        };
        assert_eq!(pkt2.hop_index, 2);
    }

    // OR2: one onion layer is removed at each hop
    #[test]
    fn or2_onion_layer_removed_each_hop() {
        let mut r = router_with_circuit(1);
        let plaintext = b"layer test".to_vec();
        let pkt = r.build_packet(1, &plaintext).unwrap();
        let outer_payload = pkt.encrypted_payload.clone();

        let ProcessResult::Forward(pkt1) = r.process_packet(pkt).unwrap() else {
            panic!("expected Forward");
        };
        // After unwrapping one layer the bytes should differ from the original wrapped form
        assert_ne!(pkt1.encrypted_payload, outer_payload);
    }

    // OR3: final hop delivers the original plaintext
    #[test]
    fn or3_final_hop_returns_payload() {
        let mut r = router_with_circuit(1);
        let plaintext = b"secret message".to_vec();
        let mut pkt = r.build_packet(1, &plaintext).unwrap();

        // Forward through all hops except the last
        for _ in 0..(hops().len() - 1) {
            match r.process_packet(pkt).unwrap() {
                ProcessResult::Forward(next) => pkt = next,
                ProcessResult::Delivered(_) => panic!("delivered too early"),
            }
        }
        // Last hop should deliver
        match r.process_packet(pkt).unwrap() {
            ProcessResult::Delivered(payload) => assert_eq!(payload, plaintext),
            ProcessResult::Forward(_) => panic!("expected delivery at final hop"),
        }
    }

    // OR4: unknown circuit returns error
    #[test]
    fn or4_unknown_circuit_error() {
        let r = OnionRouter::new();
        let pkt = OnionPacket::new(99, 0, vec![1, 2, 3]);
        match r.circuit_hops.get(&99) {
            None => {} // expected
            _ => panic!("circuit 99 should not exist"),
        }
        // Verify build_packet also rejects unknown circuits
        assert_eq!(
            r.build_packet(99, b"x").unwrap_err(),
            OnionRouterError::UnknownCircuit
        );
    }

    // OR5: fewer than 3 hops rejected at registration
    #[test]
    fn or5_too_few_hops_rejected() {
        let mut r = OnionRouter::new();
        assert!(matches!(
            r.register_circuit(1, vec![10, 20]).unwrap_err(),
            OnionRouterError::CircuitError(_)
        ));
    }

    // OR6: circuit count reflects registered circuits
    #[test]
    fn or6_circuit_count() {
        let mut r = OnionRouter::new();
        r.register_circuit(1, hops()).unwrap();
        r.register_circuit(2, vec![10, 20, 30]).unwrap();
        assert_eq!(r.circuit_count(), 2);
    }

    // OR7: full end-to-end simulation with 4 hops
    #[test]
    fn or7_four_hop_end_to_end() {
        let hops4 = vec![10, 20, 30, 40];
        let mut r = OnionRouter::new();
        r.register_circuit(2, hops4.clone()).unwrap();

        let plaintext = b"four hop test".to_vec();
        let mut pkt = r.build_packet(2, &plaintext).unwrap();

        for _ in 0..(hops4.len() - 1) {
            match r.process_packet(pkt).unwrap() {
                ProcessResult::Forward(next) => pkt = next,
                ProcessResult::Delivered(_) => panic!("delivered too early"),
            }
        }
        match r.process_packet(pkt).unwrap() {
            ProcessResult::Delivered(payload) => assert_eq!(payload, plaintext),
            ProcessResult::Forward(_) => panic!("expected delivery"),
        }
    }
}
