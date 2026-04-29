// NON-PRODUCTION: deterministic cover traffic for the loopback testnet.
// Cover packets are real EncryptedCell-sized ciphertext blobs indistinguishable
// in size from genuine traffic. The deterministic RNG seed makes tests reproducible.
//
// In production: nonces must be randomly generated per packet.

use liberty_controlled_chaos::noise_link::ENCRYPTED_CELL_SIZE;

use crate::encrypted_cell_fixture::{make_encrypted_cell, seed_to_key};

/// A cover packet is a fixed-size byte buffer matching `ENCRYPTED_CELL_SIZE`.
/// It is indistinguishable in size from an encrypted data cell.
#[derive(Debug, Clone)]
pub struct CoverPacket {
    /// Always exactly `ENCRYPTED_CELL_SIZE` bytes.
    pub bytes: Vec<u8>,
    pub sequence: u64,
}

/// Wraps either a real payload or a cover packet for mixing.
#[derive(Debug, Clone)]
pub enum CoverOrReal {
    Real(Vec<u8>),
    Cover(CoverPacket),
}

/// Generates and schedules cover traffic for one node.
///
/// NON-PRODUCTION: uses a ChaCha8-derived sequence for determinism.
#[derive(Debug)]
pub struct CoverTrafficEngine {
    node_id: u64,
    /// Seed that drives all deterministic generation.
    seed: u64,
    /// Monotonic packet counter used as nonce input.
    counter: u64,
    /// Pre-scheduled tick indices at which cover packets should be emitted.
    schedule: Vec<u64>,
}

impl CoverTrafficEngine {
    /// Create a new engine for `node_id` with the given `seed`.
    pub fn new(node_id: u64, seed: u64) -> Self {
        Self {
            node_id,
            seed,
            counter: 0,
            schedule: Vec::new(),
        }
    }

    /// Generate one cover packet.
    ///
    /// The packet is created by encrypting a deterministic dummy payload using
    /// `make_encrypted_cell`, then serialising to bytes.  If cell creation
    /// fails for any reason a zeroed buffer of `ENCRYPTED_CELL_SIZE` is used
    /// as a fallback (still the correct size).
    pub fn generate_cover_packet(&mut self) -> CoverPacket {
        let nonce = self.counter;
        self.counter += 1;
        // Derive a per-packet seed: mix node_id, base seed, and counter.
        let pkt_seed = self
            .seed
            .wrapping_mul(0x9e3779b97f4a7c15)
            .wrapping_add(self.node_id)
            .wrapping_add(nonce);
        // Dummy payload: 64 deterministic bytes.
        let payload = build_dummy_payload(pkt_seed, 64);
        let bytes = match make_encrypted_cell(&payload, pkt_seed) {
            Ok(cell) => {
                // Serialise EncryptedCell → bytes manually (same layout as encrypted_udp_packet).
                let mut buf = Vec::with_capacity(ENCRYPTED_CELL_SIZE);
                buf.extend_from_slice(&cell.path_id.to_be_bytes());
                buf.extend_from_slice(&cell.nonce.to_be_bytes());
                buf.extend_from_slice(&cell.ciphertext);
                buf.extend_from_slice(&cell.auth_tag);
                buf
            }
            Err(_) => vec![0u8; ENCRYPTED_CELL_SIZE],
        };
        CoverPacket {
            bytes,
            sequence: nonce,
        }
    }

    /// Pre-schedule `n` cover packets at deterministic tick offsets.
    ///
    /// Schedule is derived from the seed so it is reproducible.
    pub fn schedule_cover_traffic(&mut self, n: usize) {
        self.schedule.clear();
        let mut s = self.seed.wrapping_add(0xdeadbeef);
        for i in 0..n {
            s = s
                .wrapping_mul(0x6c62272e07bb0142)
                .wrapping_add(i as u64 + 1);
            // Tick offset: spread over [1, 100] range.
            self.schedule.push(s % 100 + 1);
        }
    }

    /// Return the current schedule (tick offsets at which cover packets are due).
    pub fn schedule(&self) -> &[u64] {
        &self.schedule
    }

    /// Mix `real_packets` with `cover_count` freshly generated cover packets.
    ///
    /// Returns the interleaved list in a deterministic order derived from the seed.
    /// The returned slice always has `real_packets.len() + cover_count` entries.
    pub fn mix_cover_and_real_packets(
        &mut self,
        real_packets: Vec<Vec<u8>>,
        cover_count: usize,
    ) -> Vec<CoverOrReal> {
        let mut cover: Vec<CoverOrReal> = (0..cover_count)
            .map(|_| CoverOrReal::Cover(self.generate_cover_packet()))
            .collect();
        let mut real: Vec<CoverOrReal> = real_packets.into_iter().map(CoverOrReal::Real).collect();
        // Interleave deterministically: take one real then one cover, repeating.
        let mut result = Vec::with_capacity(cover.len() + real.len());
        let mut toggle = false;
        while !cover.is_empty() || !real.is_empty() {
            if !cover.is_empty() && (toggle || real.is_empty()) {
                result.push(cover.remove(0));
            } else if !real.is_empty() {
                result.push(real.remove(0));
            }
            toggle = !toggle;
        }
        result
    }
}

/// Build a deterministic `len`-byte dummy payload from a seed.
fn build_dummy_payload(seed: u64, len: usize) -> Vec<u8> {
    let key = seed_to_key(seed);
    let mut payload = Vec::with_capacity(len);
    for i in 0..len {
        payload.push(key[i % 32] ^ (i as u8));
    }
    payload
}

#[cfg(test)]
mod tests {
    use super::*;

    // CT1: cover packet is ENCRYPTED_CELL_SIZE bytes
    #[test]
    fn ct1_cover_packet_correct_size() {
        let mut eng = CoverTrafficEngine::new(1, 0xABCD);
        let pkt = eng.generate_cover_packet();
        assert_eq!(
            pkt.bytes.len(),
            ENCRYPTED_CELL_SIZE,
            "cover packet must be exactly ENCRYPTED_CELL_SIZE bytes"
        );
    }

    // CT2: schedule_cover_traffic produces n entries
    #[test]
    fn ct2_schedule_produces_n_entries() {
        let mut eng = CoverTrafficEngine::new(1, 0x1234);
        eng.schedule_cover_traffic(5);
        assert_eq!(eng.schedule().len(), 5);
        for &tick in eng.schedule() {
            assert!(tick >= 1 && tick <= 100, "tick must be in [1, 100]");
        }
    }

    // CT3: cover packet encryption produces non-zero bytes
    #[test]
    fn ct3_cover_packet_non_zero() {
        let mut eng = CoverTrafficEngine::new(2, 0x5678);
        let pkt = eng.generate_cover_packet();
        let all_zero = pkt.bytes.iter().all(|&b| b == 0);
        assert!(!all_zero, "cover packet must not be all-zero");
    }

    // CT4: mixing real and cover produces correct total count
    #[test]
    fn ct4_mix_correct_count() {
        let mut eng = CoverTrafficEngine::new(1, 0xCAFE);
        let real = vec![b"hello".to_vec(), b"world".to_vec()];
        let mixed = eng.mix_cover_and_real_packets(real, 3);
        assert_eq!(mixed.len(), 5);
        let real_count = mixed
            .iter()
            .filter(|m| matches!(m, CoverOrReal::Real(_)))
            .count();
        let cover_count = mixed
            .iter()
            .filter(|m| matches!(m, CoverOrReal::Cover(_)))
            .count();
        assert_eq!(real_count, 2);
        assert_eq!(cover_count, 3);
    }

    // CT5: deterministic seed reproduces same sequence of packets
    #[test]
    fn ct5_deterministic_seed_reproducibility() {
        let packets1: Vec<Vec<u8>> = {
            let mut eng = CoverTrafficEngine::new(1, 0xDEAD);
            (0..3).map(|_| eng.generate_cover_packet().bytes).collect()
        };
        let packets2: Vec<Vec<u8>> = {
            let mut eng = CoverTrafficEngine::new(1, 0xDEAD);
            (0..3).map(|_| eng.generate_cover_packet().bytes).collect()
        };
        assert_eq!(packets1, packets2, "same seed must produce same packets");
    }

    // CT6: different seeds produce different packets
    #[test]
    fn ct6_different_seeds_different_packets() {
        let mut eng1 = CoverTrafficEngine::new(1, 0x1111);
        let mut eng2 = CoverTrafficEngine::new(1, 0x2222);
        let p1 = eng1.generate_cover_packet().bytes;
        let p2 = eng2.generate_cover_packet().bytes;
        assert_ne!(p1, p2);
    }

    // CT7: sequence counter increments
    #[test]
    fn ct7_sequence_increments() {
        let mut eng = CoverTrafficEngine::new(1, 0xABCD);
        let p0 = eng.generate_cover_packet();
        let p1 = eng.generate_cover_packet();
        assert_eq!(p0.sequence, 0);
        assert_eq!(p1.sequence, 1);
    }
}
