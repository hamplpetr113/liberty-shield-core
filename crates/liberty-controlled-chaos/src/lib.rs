pub mod adaptive_cover;
pub mod adaptive_path_rotation;
pub mod alpha_runtime;
pub mod anti_correlation_scheduler;
pub mod anti_correlation_timing;
pub mod backpressure;
pub mod bandwidth_accounting;
pub mod cell_encoder;
pub mod chaos_harness;
pub mod circuit_builder;
pub mod circuit_builder_runtime;
pub mod circuit_extension;
pub mod circuit_health_monitor;
pub mod circuit_identity;
pub mod circuit_manager;
pub mod circuit_recovery;
pub mod circuit_rotation;
pub mod circuit_rotation_scheduler;
pub mod circuit_runtime;
pub mod circuit_scheduler;
pub mod congestion_controller;
pub mod control_plane;
pub mod correlation_score_engine;
pub mod cover_traffic;
pub mod crypto;
pub mod deception_traffic;
pub mod directory_authority;
pub mod directory_client;
pub mod directory_client_runtime;
pub mod directory_consensus;
pub mod encrypted_relay;
pub mod guard_selection;
pub mod link_crypto_v2;
pub mod link_handshake;
pub mod mesh_packet_router;
pub mod mesh_router;
pub mod mini_testnet;
pub mod mini_testnet_v2;
pub mod multi_circuit_distributor;
pub mod multipath_circuits;
pub mod neighbor_runtime;
pub mod network_runtime;
pub mod network_telemetry;
pub mod node_config;
pub mod node_descriptor;
pub mod node_discovery;
pub mod node_discovery_engine;
pub mod node_handshake;
pub mod node_identity;
pub mod node_state_store;
pub mod noise_link;
pub mod onion;
pub mod onion_cell_protocol;
pub mod onion_cell_v2;
pub mod onion_layer;
pub mod padding_scheduler;
pub mod path_fragmenter;
pub mod path_selection;
pub mod path_selection_engine;
pub mod peer_admission;
pub mod peer_reputation;
pub mod peer_table;
pub mod policy_engine;
pub mod privacy_profiles;
pub mod proto;
pub mod readiness_report;
pub mod reliability;
pub mod resource_guard;
pub mod runtime_audit;
pub mod secure_bootstrap;
pub mod stream_mux_v2;
pub mod telemetry_exporter;
pub mod testnet;
pub mod trust_risk_engine;

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
pub mod traffic_shaping;
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

#[cfg(test)]
pub mod security_invariants_v2;
