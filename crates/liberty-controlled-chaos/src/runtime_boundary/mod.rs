//! Runtime Boundary — validation checkpoint between the Controlled Chaos Engine
//! and the network stack.
//!
//! The boundary enforces the six runtime checks from the Runtime Boundary
//! Contract (docs/controlled-chaos/runtime_boundary_contract.md):
//!   V1  KillSwitch inactive
//!   V2  TunnelState is TunnelUp
//!   V3  path_id exists
//!   V4  latency_deadline not elapsed
//!   V5  payload_ref valid
//!   V6  shadow budget not exceeded
//!
//! `RuntimePacketIntent` is the only type that may be passed to `StreamMux`.
//! It cannot be constructed outside this module — its private constructor
//! enforces that every intent has passed `RuntimeBoundaryValidator::validate`.

pub mod types;
pub mod validator;

pub use types::{
    ControlledChaosOutput, KillSwitchState, PacketClass, PayloadRef, RejectionReason,
    RuntimePacketIntent, RuntimeValidationResult, ShadowBudgetTracker, TunnelState,
};
pub use validator::RuntimeBoundaryValidator;
