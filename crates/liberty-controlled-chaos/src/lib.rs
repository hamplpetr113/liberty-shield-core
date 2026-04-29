pub mod anti_correlation_scheduler;
pub mod cell_encoder;
pub mod circuit_builder;
pub mod circuit_extension;
pub mod circuit_identity;
pub mod circuit_rotation;
pub mod circuit_runtime;
pub mod correlation_score_engine;
pub mod cover_traffic;
pub mod crypto;
pub mod directory_authority;
pub mod encrypted_relay;
pub mod guard_selection;
pub mod mesh_router;
pub mod multi_circuit_distributor;
pub mod node_descriptor;
pub mod node_discovery;
pub mod node_identity;
pub mod noise_link;
pub mod onion;
pub mod onion_cell_protocol;
pub mod onion_layer;
pub mod padding_scheduler;
pub mod path_fragmenter;
pub mod path_selection;
pub mod proto;
pub mod resource_guard;

pub mod mesh_simulator;
pub mod protocol_runtime;
pub mod relay_protocol;
pub mod replay_protection;
pub mod route_shadower;
pub mod runtime_boundary;
pub mod security_state;
pub mod stream_mux;
pub mod temporal_decoupler;
pub mod traffic_classifier;
pub mod transmitter;
pub mod transport;
pub mod udp_transport;

pub use route_shadower::{
    ChargingState, DecisionInputs, NetworkReputation, OperatingMode, ShadowDecision, TrafficClass,
    resolve_shadow_params,
};

pub use path_fragmenter::{
    CandidatePath, DegradationReason, FragmentPlan, PathAllocation, build_fragment_plan,
};

#[cfg(test)]
pub mod integration_harness;

#[cfg(test)]
pub mod invariant_tests;
