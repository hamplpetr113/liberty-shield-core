# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

Workspace root builds three crates (`Cargo.toml` `[workspace]` members: `.`, `crates/liberty-controlled-chaos`, `crates/liberty-node-cli`).

```bash
cargo build              # debug: shield binary + chaos rlib + node-cli
cargo build --release
cargo run                # runs root crate liberty-shield (Windows daemon)
cargo test               # all workspace tests
cargo clippy             # lint
```

Run tests or binaries for one crate:

```bash
cargo test -p liberty-controlled-chaos
cargo run -p liberty-node-cli -- <cli-args>
```

Single test:

```bash
cargo test <test_name>
```

Android native library (`libliberty_controlled_chaos.so`): cross-compile `liberty-controlled-chaos` with feature **`android-ffi`** as `cdylib` (see `crates/liberty-controlled-chaos/Cargo.toml`). Kotlin loads it via `System.loadLibrary("liberty_controlled_chaos")`.

## Architecture overview

Liberty Shield is a **Rust 2024 workspace** combining:

1. **Windows security daemon** (`liberty-shield`, repo root `src/`) — local sensors, correlation engine, HTTP ingest for remote telemetry.
2. **Overlay protocol stack** (`crates/liberty-controlled-chaos`) — circuits, onion-style relaying, mesh framing, UDP transport, scheduling (“controlled chaos”), optional JNI/`cdylib` for Android.
3. **CLI harness** (`crates/liberty-node-cli`) — drives chaos scenarios and prints JSON (clusters, encrypted UDP testnets, onion paths, etc.).
4. **Android app** (`android/`) — `VpnService` + TUN, packet relay and telemetry via HTTP to the daemon gateway; optional FFI bridge into Rust (`RuntimeBridge` / `LibertyNative`).

Additional design notes live under `docs/`.

---

## Root crate: `liberty-shield` (`src/`)

Primary target: **Windows**. Entry point **`main.rs`**:

**Data flow (high level):**

```
main()
  → self_protection::acquire_lock()     # liberty-shield.lock (fs2)
  → ShieldConfig::load("liberty-shield.conf")
  → mpsc channel for SensorEvent
  → spawn: process_monitor::list_processes(tx)   # suspicious processes (sysinfo)
  → spawn: network_sensor::monitor_connections(tx)  # netstat polling, IPv4 flows
  → optional --simulate: attack_simulator
  → ShieldEngine + detectors (process, network, lateral movement, patterns)
  → ResponseEngine (kill, network block, escalation, pattern handlers)
  → tokio: gateway::start(tx)   # Axum POST /sensor/event on 0.0.0.0:8080
  → engine.run(rx)               # blocking correlation loop
```

**Notable modules:**

| Module | Role |
|--------|------|
| `engine.rs` | Correlates `SensorEvent`s, behavior graph |
| `gateway.rs` | Axum server; JSON `SensorRequest` → channel |
| `process_monitor.rs` | Process telemetry / suspicious process detection |
| `network_sensor.rs` | Periodic `netstat` → new connections |
| `network_detector.rs`, `threat_detector.rs`, `pattern_matcher.rs`, `lateral_movement_detector.rs` | Detection surfaces |
| `response_engine.rs` | Actions (e.g. kill process, block network) |
| `self_protection.rs` | Single-instance lock |
| `config.rs` | `ShieldConfig` |

**Key dependencies:** `sysinfo`, `fs2`, `tokio`, `axum`, `serde`, `serde_json`.

---

## Crate: `liberty-controlled-chaos`

Large library: peer/circuit lifecycle, **`PacketFlowEngine`** (framing → link crypto → onion relay path), **`NetworkRuntime`** (epoch loop, optional **`UdpLink`**), **`UdpTransport`** / **`noise_link`**, **`transport`** (TCP/UDP links), **`runtime_boundary`** (validated scheduling intents, tunnel-related rejection reasons), directory/consensus-style modules, cover/shadow traffic schedulers, etc.

**Android boundary:**

- **`android_vpn_bridge_contract`** — Rust types for TUN packet flow and VPN lifecycle commands/status (documentation describes alignment with FFI).
- **`android_ffi_boundary`** (feature **`android-ffi`**) — C ABI (`liberty_*`) + JNI exports; global **`IntegratedNodeRuntime`** + **`PacketFlowEngine`** behind a mutex (`liberty_ingest_packet`, `liberty_poll_send_intent`, `liberty_tick_runtime`, etc.).

Much of this crate is labeled **NON-PRODUCTION** in comments where crypto or auth is simplified.

---

## Crate: `liberty-node-cli`

Thin binary delegating to **`liberty_node_cli::run_cli`**: parses args, runs subcommands, returns JSON strings for benchmarking and testnets.

---

## Android VPN layer (`android/`)

- **`ShieldVpnService`** — establishes TUN (e.g. `10.0.0.2`, default route), foreground service; **`PacketReader`** reads IP from TUN, **`PacketForwarder`** writes replies (DNS/UDP uses `VpnService.protect()` where needed).
- **`GatewayClient`** — queues JSON events and POSTs to **`BuildConfig.GATEWAY_URL`** (same ingest shape as desktop gateway `/sensor/event`).
- **`com.libertyshield.agent.ffi`** — JNI wrappers loading **`liberty_controlled_chaos`** when building with the Rust `cdylib`; intended integration path for feeding packets into **`PacketFlowEngine`** (parallel to Kotlin-local forwarding/telemetry).

---

## Historical note

Older revisions described only process monitoring and `logger`-centric flow. The **current** architecture includes **`ShieldEngine`**, **network sensors**, **Axum gateway**, the **`liberty-controlled-chaos`** workspace crate, **`liberty-node-cli`**, and the **Android VPN / FFI** surfaces above.
