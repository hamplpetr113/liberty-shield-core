pub mod anti_correlation_scheduler;
pub mod cell_encoder;
pub mod circuit_builder;
pub mod circuit_rotation;
pub mod circuit_runtime;
pub mod correlation_score_engine;
pub mod cover_traffic;
pub mod guard_selection;
pub mod mesh_router;
pub mod multi_circuit_distributor;
pub mod node_discovery;
pub mod noise_link;
pub mod onion_layer;
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
