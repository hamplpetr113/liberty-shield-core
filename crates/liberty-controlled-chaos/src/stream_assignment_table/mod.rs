//! Stream assignment table — maps (circuit_id, stream_id) pairs to application handles.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignError {
    AlreadyAssigned,
    CircuitNotFound,
    StreamNotFound,
}

#[derive(Debug, Clone)]
pub struct StreamHandle {
    pub circuit_id: u64,
    pub stream_id: u32,
    pub app_tag: u64,
    pub created_epoch: u64,
    pub bytes_relayed: u64,
}

pub struct StreamAssignmentTable {
    streams: HashMap<(u64, u32), StreamHandle>,
    next_stream_id: u32,
}

impl StreamAssignmentTable {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            next_stream_id: 1,
        }
    }

    pub fn assign(
        &mut self,
        circuit_id: u64,
        app_tag: u64,
        epoch: u64,
    ) -> Result<u32, AssignError> {
        let stream_id = self.next_stream_id;
        self.next_stream_id = self.next_stream_id.wrapping_add(1);
        let key = (circuit_id, stream_id);
        if self.streams.contains_key(&key) {
            return Err(AssignError::AlreadyAssigned);
        }
        self.streams.insert(
            key,
            StreamHandle {
                circuit_id,
                stream_id,
                app_tag,
                created_epoch: epoch,
                bytes_relayed: 0,
            },
        );
        Ok(stream_id)
    }

    pub fn get(&self, circuit_id: u64, stream_id: u32) -> Option<&StreamHandle> {
        self.streams.get(&(circuit_id, stream_id))
    }

    pub fn remove(&mut self, circuit_id: u64, stream_id: u32) -> Result<(), AssignError> {
        if self.streams.remove(&(circuit_id, stream_id)).is_none() {
            return Err(AssignError::StreamNotFound);
        }
        Ok(())
    }

    pub fn record_bytes(&mut self, circuit_id: u64, stream_id: u32, bytes: u64) {
        if let Some(h) = self.streams.get_mut(&(circuit_id, stream_id)) {
            h.bytes_relayed += bytes;
        }
    }

    pub fn streams_for_circuit(&self, circuit_id: u64) -> Vec<u32> {
        self.streams
            .keys()
            .filter(|(cid, _)| *cid == circuit_id)
            .map(|(_, sid)| *sid)
            .collect()
    }

    pub fn remove_circuit(&mut self, circuit_id: u64) -> usize {
        let before = self.streams.len();
        self.streams.retain(|(cid, _), _| *cid != circuit_id);
        before - self.streams.len()
    }

    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }
}

impl Default for StreamAssignmentTable {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // SAT1: assign returns stream ID.
    #[test]
    fn sat1_assign() {
        let mut t = StreamAssignmentTable::new();
        let sid = t.assign(1, 42, 0).unwrap();
        assert!(sid > 0);
    }

    // SAT2: get returns assigned handle.
    #[test]
    fn sat2_get() {
        let mut t = StreamAssignmentTable::new();
        let sid = t.assign(1, 99, 5).unwrap();
        let h = t.get(1, sid).unwrap();
        assert_eq!(h.app_tag, 99);
        assert_eq!(h.created_epoch, 5);
    }

    // SAT3: remove deletes stream.
    #[test]
    fn sat3_remove() {
        let mut t = StreamAssignmentTable::new();
        let sid = t.assign(1, 0, 0).unwrap();
        t.remove(1, sid).unwrap();
        assert!(t.get(1, sid).is_none());
    }

    // SAT4: remove non-existent returns StreamNotFound.
    #[test]
    fn sat4_remove_not_found() {
        let mut t = StreamAssignmentTable::new();
        assert_eq!(t.remove(1, 99), Err(AssignError::StreamNotFound));
    }

    // SAT5: record_bytes accumulates.
    #[test]
    fn sat5_record_bytes() {
        let mut t = StreamAssignmentTable::new();
        let sid = t.assign(1, 0, 0).unwrap();
        t.record_bytes(1, sid, 100);
        t.record_bytes(1, sid, 200);
        assert_eq!(t.get(1, sid).unwrap().bytes_relayed, 300);
    }

    // SAT6: streams_for_circuit returns correct IDs.
    #[test]
    fn sat6_streams_for_circuit() {
        let mut t = StreamAssignmentTable::new();
        t.assign(1, 0, 0).unwrap();
        t.assign(1, 0, 0).unwrap();
        t.assign(2, 0, 0).unwrap();
        assert_eq!(t.streams_for_circuit(1).len(), 2);
    }

    // SAT7: remove_circuit removes all streams for circuit.
    #[test]
    fn sat7_remove_circuit() {
        let mut t = StreamAssignmentTable::new();
        t.assign(1, 0, 0).unwrap();
        t.assign(1, 0, 0).unwrap();
        t.assign(2, 0, 0).unwrap();
        let removed = t.remove_circuit(1);
        assert_eq!(removed, 2);
        assert_eq!(t.stream_count(), 1);
    }

    // SAT8: stream IDs monotonically increase.
    #[test]
    fn sat8_monotonic_ids() {
        let mut t = StreamAssignmentTable::new();
        let a = t.assign(1, 0, 0).unwrap();
        let b = t.assign(1, 0, 0).unwrap();
        assert!(b > a);
    }

    // SAT9: stream_count tracks total.
    #[test]
    fn sat9_stream_count() {
        let mut t = StreamAssignmentTable::new();
        t.assign(1, 0, 0).unwrap();
        t.assign(2, 0, 0).unwrap();
        assert_eq!(t.stream_count(), 2);
    }

    // SAT10: record_bytes on unknown stream is no-op.
    #[test]
    fn sat10_unknown_bytes() {
        let mut t = StreamAssignmentTable::new();
        t.record_bytes(99, 99, 1000); // no panic
        assert_eq!(t.stream_count(), 0);
    }
}
