#[cfg(feature = "android-ffi")]
pub mod android_ffi_boundary;

pub mod adaptive_cover;
pub mod adaptive_path_rotation;
pub mod alpha_runtime;
pub mod alpha_to_beta_migration;
pub mod anti_correlation_scheduler;
pub mod anti_correlation_timing;
pub mod backpressure;
pub mod bandwidth_accounting;
pub mod beta_integration_harness;
pub mod beta_network_simulator;
pub mod beta_node_bootstrap;
pub mod beta_runtime_launcher;
pub mod bootstrap_state_machine;
pub mod cell_dispatch_queue;
pub mod cell_encoder;
pub mod cell_pipeline;
pub mod cell_reassembler;
pub mod chaos_harness;
pub mod circuit_admission_policy;
pub mod circuit_builder;
pub mod circuit_builder_runtime;
pub mod circuit_extension;
pub mod circuit_health_monitor;
pub mod circuit_identity;
pub mod circuit_manager;
pub mod circuit_metrics_collector;
pub mod circuit_path_validator;
pub mod circuit_rate_limiter;
pub mod circuit_recovery;
pub mod circuit_rotation;
pub mod circuit_rotation_scheduler;
pub mod circuit_runtime;
pub mod circuit_scheduler;
pub mod circuit_teardown_manager;
pub mod circuit_window_manager;
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
pub mod directory_snapshot;
pub mod encrypted_relay;
pub mod epoch_scheduler;
pub mod epoch_vote_collector;
pub mod epoch_watermark;
pub mod failure_recovery_runtime;
pub mod flow_controller;
pub mod gossip_cache;
pub mod guard_selection;
pub mod integrated_node_runtime;
pub mod link_crypto_v2;
pub mod link_handshake;
pub mod link_quality_monitor;
pub mod link_state_tracker;
pub mod live_circuit_build_protocol;
pub mod mesh_directory_service;
pub mod mesh_health_runtime;
pub mod mesh_node_runtime;
pub mod mesh_packet_framer;
pub mod mesh_packet_router;
pub mod mesh_router;
pub mod mesh_session_store;
pub mod mini_testnet;
pub mod mini_testnet_v2;
pub mod multi_circuit_distributor;
pub mod multipath_circuits;
pub mod neighbor_runtime;
pub mod network_policy_enforcer;
pub mod network_runtime;
pub mod network_telemetry;
pub mod node_capability_registry;
pub mod node_config;
pub mod node_descriptor;
pub mod node_discovery;
pub mod node_discovery_engine;
pub mod node_event_bus;
pub mod node_handshake;
pub mod node_health_ledger;
pub mod node_identity;
pub mod node_scoring_engine;
pub mod node_state_store;
pub mod node_uptime_tracker;
pub mod node_version_registry;
pub mod noise_link;
pub mod onion;
pub mod onion_cell_protocol;
pub mod onion_cell_v2;
pub mod onion_layer;
pub mod onion_relay_runtime;
pub mod outbound_send_queue;
pub mod packet_flow_engine;
pub mod packet_sequence_tracker;
pub mod padding_budget;
pub mod padding_scheduler;
pub mod path_fragmenter;
pub mod path_selection;
pub mod path_selection_engine;
pub mod peer_admission;
pub mod peer_ban_list;
pub mod peer_connection_pool;
pub mod peer_handshake_runtime;
pub mod peer_latency_tracker;
pub mod peer_reputation;
pub mod peer_score_ledger;
pub mod peer_table;
pub mod policy_engine;
pub mod privacy_profiles;
pub mod proto;
pub mod readiness_report;
pub mod real_udp_runtime;
pub mod relay_cell_buffer;
pub mod relay_heartbeat;
pub mod relay_path_cache;
pub mod reliability;
pub mod resource_guard;
pub mod route_diversity_checker;
pub mod runtime_audit;
pub mod runtime_epoch_driver;
pub mod runtime_event_bridge;
pub mod runtime_readiness_gate;
pub mod secure_bootstrap;
pub mod stream_assignment_table;
pub mod stream_mux_v2;
pub mod stream_priority_queue;
pub mod telemetry_exporter;
pub mod testnet;
pub mod topology_snapshot;
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

#[cfg(test)]
pub mod node_runtime_tests;

#[cfg(test)]
pub mod real_udp_smoke_tests;
