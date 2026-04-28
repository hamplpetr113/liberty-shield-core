pub mod cell_encoder;
pub mod correlation_score_engine;
pub mod mesh_router;
pub mod noise_link;
pub mod path_fragmenter;

pub mod route_shadower;
pub mod runtime_boundary;
pub mod stream_mux;
pub mod temporal_decoupler;
pub mod traffic_classifier;
pub mod transmitter;
pub mod udp_transport;

pub use route_shadower::{
    ChargingState, DecisionInputs, NetworkReputation, OperatingMode, ShadowDecision, TrafficClass,
    resolve_shadow_params,
};

pub use path_fragmenter::{
    CandidatePath, DegradationReason, FragmentPlan, PathAllocation, build_fragment_plan,
};
