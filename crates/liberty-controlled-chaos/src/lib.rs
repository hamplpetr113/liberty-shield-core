pub mod correlation_score_engine;
pub mod path_fragmenter;
pub mod route_shadower;
pub mod runtime_boundary;
pub mod temporal_decoupler;
pub mod traffic_classifier;
pub mod transmitter;

pub use route_shadower::{
    ChargingState, DecisionInputs, NetworkReputation, OperatingMode, ShadowDecision, TrafficClass,
    resolve_shadow_params,
};

pub use path_fragmenter::{
    CandidatePath, DegradationReason, FragmentPlan, PathAllocation, build_fragment_plan,
};
