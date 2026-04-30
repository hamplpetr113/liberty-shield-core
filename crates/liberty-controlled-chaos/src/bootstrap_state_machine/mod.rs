//! Bootstrap state machine — models node startup phase transitions.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootstrapPhase {
    Idle,
    ResolvingSeeds,
    Connecting,
    Handshaking,
    FetchingDirectory,
    Building,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    InvalidTransition,
    AlreadyReady,
    AlreadyFailed,
}

pub struct BootstrapStateMachine {
    phase: BootstrapPhase,
    started_epoch: Option<u64>,
    ready_epoch: Option<u64>,
    failed_reason: Option<&'static str>,
}

impl BootstrapStateMachine {
    pub fn new() -> Self {
        Self {
            phase: BootstrapPhase::Idle,
            started_epoch: None,
            ready_epoch: None,
            failed_reason: None,
        }
    }

    pub fn start(&mut self, epoch: u64) -> Result<(), TransitionError> {
        if self.phase != BootstrapPhase::Idle {
            return Err(TransitionError::InvalidTransition);
        }
        self.phase = BootstrapPhase::ResolvingSeeds;
        self.started_epoch = Some(epoch);
        Ok(())
    }

    pub fn advance(&mut self) -> Result<BootstrapPhase, TransitionError> {
        let next = match self.phase {
            BootstrapPhase::ResolvingSeeds => BootstrapPhase::Connecting,
            BootstrapPhase::Connecting => BootstrapPhase::Handshaking,
            BootstrapPhase::Handshaking => BootstrapPhase::FetchingDirectory,
            BootstrapPhase::FetchingDirectory => BootstrapPhase::Building,
            BootstrapPhase::Building => BootstrapPhase::Ready,
            BootstrapPhase::Ready => return Err(TransitionError::AlreadyReady),
            BootstrapPhase::Failed => return Err(TransitionError::AlreadyFailed),
            BootstrapPhase::Idle => return Err(TransitionError::InvalidTransition),
        };
        self.phase = next;
        Ok(next)
    }

    pub fn set_ready(&mut self, epoch: u64) -> Result<(), TransitionError> {
        if self.phase == BootstrapPhase::Ready {
            return Err(TransitionError::AlreadyReady);
        }
        if self.phase == BootstrapPhase::Failed {
            return Err(TransitionError::AlreadyFailed);
        }
        self.phase = BootstrapPhase::Ready;
        self.ready_epoch = Some(epoch);
        Ok(())
    }

    pub fn fail(&mut self, reason: &'static str) -> Result<(), TransitionError> {
        if self.phase == BootstrapPhase::Failed {
            return Err(TransitionError::AlreadyFailed);
        }
        self.phase = BootstrapPhase::Failed;
        self.failed_reason = Some(reason);
        Ok(())
    }

    pub fn phase(&self) -> BootstrapPhase {
        self.phase
    }

    pub fn is_ready(&self) -> bool {
        self.phase == BootstrapPhase::Ready
    }

    pub fn is_failed(&self) -> bool {
        self.phase == BootstrapPhase::Failed
    }

    pub fn startup_duration(&self, current_epoch: u64) -> Option<u64> {
        self.started_epoch.map(|s| current_epoch.saturating_sub(s))
    }

    pub fn failed_reason(&self) -> Option<&'static str> {
        self.failed_reason
    }
}

impl Default for BootstrapStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // BSM1: initial phase is Idle.
    #[test]
    fn bsm1_initial_idle() {
        let m = BootstrapStateMachine::new();
        assert_eq!(m.phase(), BootstrapPhase::Idle);
    }

    // BSM2: start transitions to ResolvingSeeds.
    #[test]
    fn bsm2_start() {
        let mut m = BootstrapStateMachine::new();
        m.start(1).unwrap();
        assert_eq!(m.phase(), BootstrapPhase::ResolvingSeeds);
    }

    // BSM3: advance progresses through phases.
    #[test]
    fn bsm3_advance() {
        let mut m = BootstrapStateMachine::new();
        m.start(1).unwrap();
        assert_eq!(m.advance().unwrap(), BootstrapPhase::Connecting);
        assert_eq!(m.advance().unwrap(), BootstrapPhase::Handshaking);
    }

    // BSM4: set_ready marks ready.
    #[test]
    fn bsm4_set_ready() {
        let mut m = BootstrapStateMachine::new();
        m.start(1).unwrap();
        m.set_ready(5).unwrap();
        assert!(m.is_ready());
    }

    // BSM5: fail marks failed with reason.
    #[test]
    fn bsm5_fail() {
        let mut m = BootstrapStateMachine::new();
        m.start(1).unwrap();
        m.fail("timeout").unwrap();
        assert!(m.is_failed());
        assert_eq!(m.failed_reason(), Some("timeout"));
    }

    // BSM6: double start returns InvalidTransition.
    #[test]
    fn bsm6_double_start() {
        let mut m = BootstrapStateMachine::new();
        m.start(1).unwrap();
        assert_eq!(m.start(2), Err(TransitionError::InvalidTransition));
    }

    // BSM7: advance from Ready returns AlreadyReady.
    #[test]
    fn bsm7_advance_ready() {
        let mut m = BootstrapStateMachine::new();
        m.start(0).unwrap();
        m.set_ready(1).unwrap();
        assert_eq!(m.advance(), Err(TransitionError::AlreadyReady));
    }

    // BSM8: fail from Failed returns AlreadyFailed.
    #[test]
    fn bsm8_double_fail() {
        let mut m = BootstrapStateMachine::new();
        m.start(0).unwrap();
        m.fail("e1").unwrap();
        assert_eq!(m.fail("e2"), Err(TransitionError::AlreadyFailed));
    }

    // BSM9: startup_duration computed from started_epoch.
    #[test]
    fn bsm9_startup_duration() {
        let mut m = BootstrapStateMachine::new();
        m.start(10).unwrap();
        assert_eq!(m.startup_duration(15), Some(5));
    }

    // BSM10: full phase progression to Ready.
    #[test]
    fn bsm10_full_progression() {
        let mut m = BootstrapStateMachine::new();
        m.start(0).unwrap();
        for _ in 0..4 {
            m.advance().unwrap();
        }
        assert_eq!(m.advance().unwrap(), BootstrapPhase::Ready);
        assert!(m.is_ready());
    }
}
