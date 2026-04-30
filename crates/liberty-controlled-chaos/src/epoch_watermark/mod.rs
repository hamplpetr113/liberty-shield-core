//! Epoch watermark — high-water mark tracking for monotonic epoch advancement.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatermarkError {
    RegressionDetected,
    NodeNotFound,
}

pub struct EpochWatermark {
    watermarks: HashMap<[u8; 32], u64>,
    global_high: u64,
    regression_count: u64,
}

impl EpochWatermark {
    pub fn new() -> Self {
        Self {
            watermarks: HashMap::new(),
            global_high: 0,
            regression_count: 0,
        }
    }

    pub fn advance(&mut self, node_id: [u8; 32], epoch: u64) -> Result<(), WatermarkError> {
        let current = self.watermarks.entry(node_id).or_insert(0);
        if epoch < *current {
            self.regression_count += 1;
            return Err(WatermarkError::RegressionDetected);
        }
        *current = epoch;
        if epoch > self.global_high {
            self.global_high = epoch;
        }
        Ok(())
    }

    pub fn get(&self, node_id: &[u8; 32]) -> Option<u64> {
        self.watermarks.get(node_id).copied()
    }

    pub fn global_high(&self) -> u64 {
        self.global_high
    }

    pub fn regression_count(&self) -> u64 {
        self.regression_count
    }

    pub fn nodes_behind(&self, epoch: u64) -> Vec<[u8; 32]> {
        self.watermarks
            .iter()
            .filter(|(_, w)| **w < epoch)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn remove(&mut self, node_id: &[u8; 32]) -> Result<(), WatermarkError> {
        if self.watermarks.remove(node_id).is_none() {
            return Err(WatermarkError::NodeNotFound);
        }
        Ok(())
    }

    pub fn node_count(&self) -> usize {
        self.watermarks.len()
    }
}

impl Default for EpochWatermark {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nid(b: u8) -> [u8; 32] {
        [b; 32]
    }

    // EW1: advance stores watermark.
    #[test]
    fn ew1_advance() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 5).unwrap();
        assert_eq!(w.get(&nid(1)), Some(5));
    }

    // EW2: regression returns RegressionDetected.
    #[test]
    fn ew2_regression() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 10).unwrap();
        assert_eq!(
            w.advance(nid(1), 5),
            Err(WatermarkError::RegressionDetected)
        );
    }

    // EW3: global_high tracks maximum.
    #[test]
    fn ew3_global_high() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 5).unwrap();
        w.advance(nid(2), 10).unwrap();
        assert_eq!(w.global_high(), 10);
    }

    // EW4: regression_count increments.
    #[test]
    fn ew4_regression_count() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 5).unwrap();
        w.advance(nid(1), 3).unwrap_err();
        assert_eq!(w.regression_count(), 1);
    }

    // EW5: same epoch is not a regression.
    #[test]
    fn ew5_same_epoch() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 5).unwrap();
        assert!(w.advance(nid(1), 5).is_ok());
    }

    // EW6: nodes_behind returns correct nodes.
    #[test]
    fn ew6_nodes_behind() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 3).unwrap();
        w.advance(nid(2), 10).unwrap();
        let behind = w.nodes_behind(10);
        assert_eq!(behind.len(), 1);
        assert_eq!(behind[0], nid(1));
    }

    // EW7: remove deletes node.
    #[test]
    fn ew7_remove() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 5).unwrap();
        w.remove(&nid(1)).unwrap();
        assert!(w.get(&nid(1)).is_none());
    }

    // EW8: remove unknown returns NodeNotFound.
    #[test]
    fn ew8_remove_not_found() {
        let mut w = EpochWatermark::new();
        assert_eq!(w.remove(&nid(99)), Err(WatermarkError::NodeNotFound));
    }

    // EW9: node_count correct.
    #[test]
    fn ew9_node_count() {
        let mut w = EpochWatermark::new();
        w.advance(nid(1), 1).unwrap();
        w.advance(nid(2), 1).unwrap();
        assert_eq!(w.node_count(), 2);
    }

    // EW10: unknown node returns None.
    #[test]
    fn ew10_unknown() {
        let w = EpochWatermark::new();
        assert!(w.get(&nid(99)).is_none());
    }
}
