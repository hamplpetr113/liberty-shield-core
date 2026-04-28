//! Public types for the runtime boundary layer.
//!
//! `RuntimePacketIntent` can only be constructed inside this module tree
//! (via `RuntimeBoundaryValidator::validate`).  The `pub(in crate::runtime_boundary)`
//! constructor prevents downstream layers from forging a validated intent.

use std::collections::HashMap;

use crate::transmitter::PlanInvalidationEvent;

// ── PacketClass ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketClass {
    Real,
    Shadow,
    Cover,
}

impl PacketClass {
    pub fn is_shadow_or_cover(&self) -> bool {
        matches!(self, PacketClass::Shadow | PacketClass::Cover)
    }
}

// ── PayloadRef ────────────────────────────────────────────────────────────────

/// Opaque handle into a caller-managed encrypted buffer pool.
/// No raw pointer access is exposed; length is validated at construction.
#[derive(Debug, Clone)]
pub struct PayloadRef {
    pool_index: u32,
    length: u16,
}

impl PayloadRef {
    /// Construct a valid `PayloadRef`. Returns `Err` if `length ∉ [64, 1500]`.
    pub fn new(pool_index: u32, length: u16) -> Result<Self, &'static str> {
        if !(64..=1500).contains(&length) {
            return Err("PayloadRef length must be in [64, 1500]");
        }
        Ok(Self { pool_index, length })
    }

    pub fn pool_index(&self) -> u32 {
        self.pool_index
    }

    pub fn length(&self) -> u16 {
        self.length
    }

    /// True when the length field satisfies the [64, 1500] invariant.
    /// Always true for refs built via `new()`; used by V5 as a defence-in-depth
    /// check against future unchecked construction paths.
    pub fn is_valid(&self) -> bool {
        (64..=1500).contains(&self.length)
    }
}

#[cfg(test)]
impl PayloadRef {
    /// Construct a `PayloadRef` without validation.  Test-only: used to exercise
    /// the V5 (invalid payload_ref) rejection path in `RuntimeBoundaryValidator`.
    pub fn new_unchecked(pool_index: u32, length: u16) -> Self {
        Self { pool_index, length }
    }
}

// ── KillSwitchState ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KillSwitchState {
    Active,
    Inactive,
}

// ── TunnelState ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelState {
    TunnelUp,
    TunnelConnecting,
    TunnelFailed,
    TunnelTeardown,
}

impl TunnelState {
    pub fn is_up(&self) -> bool {
        matches!(self, TunnelState::TunnelUp)
    }
}

// ── ControlledChaosOutput ─────────────────────────────────────────────────────

/// The sole output type of the Controlled Chaos Engine.
///
/// Carries scheduling intent only — no socket handles, no raw pointers,
/// no plaintext payload bytes.  Consumed by `RuntimeBoundaryValidator::validate`
/// and promoted to `RuntimePacketIntent` on success.
#[derive(Debug, Clone)]
pub struct ControlledChaosOutput {
    pub path_id: u64,
    pub flow_id: u64,
    /// Even = real packet; odd = cover/shadow (namespace isolation from Scheduler).
    pub fragment_id: u64,
    /// Earliest dispatch time (μs, monotonic clock).
    pub scheduled_send_time: u64,
    pub packet_class: PacketClass,
    /// Redundant with `packet_class == Shadow`; explicit to catch class-mismatch bugs.
    pub shadow_flag: bool,
    /// Absolute deadline (μs).  Intent must be discarded if `now_us > latency_deadline`.
    pub latency_deadline: u64,
    pub payload_ref: PayloadRef,
}

// ── RuntimePacketIntent ───────────────────────────────────────────────────────

/// Proof token: a `ControlledChaosOutput` that has passed all six
/// `RuntimeBoundaryValidator` checks.
///
/// The private constructor (`pub(in crate::runtime_boundary)`) guarantees that
/// no code outside this module tree can construct one without going through
/// `validate()`.  `StreamMux` receives only `RuntimePacketIntent` values.
#[derive(Debug)]
pub struct RuntimePacketIntent {
    inner: ControlledChaosOutput,
}

impl RuntimePacketIntent {
    /// Only callable within `crate::runtime_boundary`.
    pub(in crate::runtime_boundary) fn new(inner: ControlledChaosOutput) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &ControlledChaosOutput {
        &self.inner
    }

    pub fn path_id(&self) -> u64 {
        self.inner.path_id
    }

    pub fn flow_id(&self) -> u64 {
        self.inner.flow_id
    }

    pub fn fragment_id(&self) -> u64 {
        self.inner.fragment_id
    }

    pub fn scheduled_send_time(&self) -> u64 {
        self.inner.scheduled_send_time
    }

    pub fn packet_class(&self) -> &PacketClass {
        &self.inner.packet_class
    }

    pub fn latency_deadline(&self) -> u64 {
        self.inner.latency_deadline
    }

    pub fn payload_ref(&self) -> &PayloadRef {
        &self.inner.payload_ref
    }
}

// ── RejectionReason ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RejectionReason {
    KillSwitchActive,
    TunnelDown,
    PathNotFound {
        path_id: u64,
        /// Populated for real packets; `None` for shadow/cover (silent drop).
        invalidation: Option<PlanInvalidationEvent>,
    },
    DeadlineMissed {
        path_id: u64,
        late_by_us: u64,
    },
    PayloadRefInvalid,
    ShadowBudgetExceeded {
        flow_id: u64,
    },
}

// ── RuntimeValidationResult ───────────────────────────────────────────────────

#[derive(Debug)]
pub enum RuntimeValidationResult {
    Accept(RuntimePacketIntent),
    Reject(RejectionReason),
}

impl RuntimeValidationResult {
    pub fn is_accepted(&self) -> bool {
        matches!(self, RuntimeValidationResult::Accept(_))
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, RuntimeValidationResult::Reject(_))
    }

    pub fn rejection_reason(&self) -> Option<&RejectionReason> {
        match self {
            RuntimeValidationResult::Reject(r) => Some(r),
            RuntimeValidationResult::Accept(_) => None,
        }
    }
}

// ── ShadowBudgetTracker ───────────────────────────────────────────────────────

/// Per-flow epoch shadow-byte budget.
///
/// Owned by the caller; `RuntimeBoundaryValidator` borrows it mutably during
/// `validate()` to record consumption for shadow/cover packets (V6).
/// Call `reset_epoch()` at the start of each accounting epoch.
#[derive(Debug)]
pub struct ShadowBudgetTracker {
    per_flow_budget_bytes: u64,
    consumed: HashMap<u64, u64>,
}

impl ShadowBudgetTracker {
    pub fn new(per_flow_budget_bytes: u64) -> Self {
        Self {
            per_flow_budget_bytes,
            consumed: HashMap::new(),
        }
    }

    /// Returns `true` if consuming `bytes` for `flow_id` stays within budget.
    pub fn has_budget(&self, flow_id: u64, bytes: u16) -> bool {
        let used = self.consumed.get(&flow_id).copied().unwrap_or(0);
        used.saturating_add(bytes as u64) <= self.per_flow_budget_bytes
    }

    /// Record `bytes` as consumed for `flow_id`.  Only call after `has_budget` is `true`.
    pub fn consume(&mut self, flow_id: u64, bytes: u16) {
        *self.consumed.entry(flow_id).or_insert(0) += bytes as u64;
    }

    /// Reset all per-flow counters at the start of a new epoch.
    pub fn reset_epoch(&mut self) {
        self.consumed.clear();
    }

    pub fn consumed_for(&self, flow_id: u64) -> u64 {
        self.consumed.get(&flow_id).copied().unwrap_or(0)
    }
}
