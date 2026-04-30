//! Cell pipeline — ordered processing stages for relay cells.

use crate::onion_cell_v2::OnionCellV2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageResult {
    Pass,
    Drop,
    Modify,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PipelineError {
    StageDrop,
    PipelineEmpty,
}

pub struct Stage {
    pub name: &'static str,
    pub pass_count: u64,
    pub drop_count: u64,
    pub modify_count: u64,
    handler: fn(&mut OnionCellV2) -> StageResult,
}

impl Stage {
    pub fn new(name: &'static str, handler: fn(&mut OnionCellV2) -> StageResult) -> Self {
        Self {
            name,
            pass_count: 0,
            drop_count: 0,
            modify_count: 0,
            handler,
        }
    }

    fn process(&mut self, cell: &mut OnionCellV2) -> StageResult {
        let result = (self.handler)(cell);
        match result {
            StageResult::Pass => self.pass_count += 1,
            StageResult::Drop => self.drop_count += 1,
            StageResult::Modify => self.modify_count += 1,
        }
        result
    }
}

pub struct CellPipeline {
    stages: Vec<Stage>,
    total_processed: u64,
    total_dropped: u64,
}

impl CellPipeline {
    pub fn new() -> Self {
        Self {
            stages: Vec::new(),
            total_processed: 0,
            total_dropped: 0,
        }
    }

    pub fn add_stage(&mut self, stage: Stage) {
        self.stages.push(stage);
    }

    pub fn process(&mut self, mut cell: OnionCellV2) -> Result<OnionCellV2, PipelineError> {
        if self.stages.is_empty() {
            return Err(PipelineError::PipelineEmpty);
        }
        self.total_processed += 1;
        for stage in &mut self.stages {
            if stage.process(&mut cell) == StageResult::Drop {
                self.total_dropped += 1;
                return Err(PipelineError::StageDrop);
            }
        }
        Ok(cell)
    }

    pub fn stage_count(&self) -> usize {
        self.stages.len()
    }
    pub fn total_processed(&self) -> u64 {
        self.total_processed
    }
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }
}

impl Default for CellPipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onion_cell_v2::{CMD_DATA, OnionCellV2};

    fn cell() -> OnionCellV2 {
        OnionCellV2 {
            command: CMD_DATA,
            circuit_id: 1,
            stream_id: 0,
            sequence: 0,
            header_mac: [0u8; 32],
            payload: [0u8; 1364],
        }
    }

    fn pass_stage() -> Stage {
        Stage::new("pass", |_| StageResult::Pass)
    }
    fn drop_stage() -> Stage {
        Stage::new("drop", |_| StageResult::Drop)
    }
    fn modify_stage() -> Stage {
        Stage::new("modify", |c| {
            c.sequence += 1;
            StageResult::Modify
        })
    }

    // CP1: empty pipeline returns PipelineEmpty.
    #[test]
    fn cp1_empty() {
        let mut p = CellPipeline::new();
        assert_eq!(p.process(cell()).err(), Some(PipelineError::PipelineEmpty));
    }

    // CP2: pass stage forwards cell.
    #[test]
    fn cp2_pass() {
        let mut p = CellPipeline::new();
        p.add_stage(pass_stage());
        assert!(p.process(cell()).is_ok());
    }

    // CP3: drop stage returns StageDrop.
    #[test]
    fn cp3_drop() {
        let mut p = CellPipeline::new();
        p.add_stage(drop_stage());
        assert_eq!(p.process(cell()).err(), Some(PipelineError::StageDrop));
    }

    // CP4: modify stage alters cell.
    #[test]
    fn cp4_modify() {
        let mut p = CellPipeline::new();
        p.add_stage(modify_stage());
        let out = p.process(cell()).unwrap();
        assert_eq!(out.sequence, 1);
    }

    // CP5: total_processed increments.
    #[test]
    fn cp5_total_processed() {
        let mut p = CellPipeline::new();
        p.add_stage(pass_stage());
        p.process(cell()).unwrap();
        p.process(cell()).unwrap();
        assert_eq!(p.total_processed(), 2);
    }

    // CP6: total_dropped increments on drop.
    #[test]
    fn cp6_total_dropped() {
        let mut p = CellPipeline::new();
        p.add_stage(drop_stage());
        p.process(cell()).unwrap_err();
        assert_eq!(p.total_dropped(), 1);
    }

    // CP7: stages run in order.
    #[test]
    fn cp7_stage_order() {
        let mut p = CellPipeline::new();
        p.add_stage(modify_stage()); // seq -> 1
        p.add_stage(modify_stage()); // seq -> 2
        let out = p.process(cell()).unwrap();
        assert_eq!(out.sequence, 2);
    }

    // CP8: drop stage stops processing.
    #[test]
    fn cp8_drop_stops() {
        let mut p = CellPipeline::new();
        p.add_stage(drop_stage());
        p.add_stage(modify_stage());
        p.process(cell()).unwrap_err();
        assert_eq!(p.stages[1].modify_count, 0);
    }

    // CP9: pass_count in stage increments.
    #[test]
    fn cp9_stage_pass_count() {
        let mut p = CellPipeline::new();
        p.add_stage(pass_stage());
        p.process(cell()).unwrap();
        assert_eq!(p.stages[0].pass_count, 1);
    }

    // CP10: stage_count correct.
    #[test]
    fn cp10_stage_count() {
        let mut p = CellPipeline::new();
        p.add_stage(pass_stage());
        p.add_stage(drop_stage());
        assert_eq!(p.stage_count(), 2);
    }
}
