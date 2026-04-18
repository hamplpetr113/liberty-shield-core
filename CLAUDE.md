# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
cargo build          # debug build
cargo build --release
cargo run            # build and run
cargo test           # run all tests
cargo clippy         # lint
```

Run a single test:
```bash
cargo test <test_name>
```

## Architecture

Liberty Shield is a Windows process-monitoring security tool (Rust, edition 2024). It detects suspicious processes and prevents multiple instances from running simultaneously.

**Data flow:**
```
main()
  → self_protection::acquire_lock()   # creates liberty-shield.lock (fs2 file lock)
  → process_monitor::list_processes() # infinite loop, refreshes every 5 s via sysinfo
      → threat_detector::is_suspicious()  # case-insensitive match against hardcoded list
      → logger::log()                     # prefixes output with [LIBERTY SHIELD]
```

**Modules** (`src/`):
- `main.rs` — entry point; wires lock + monitor
- `self_protection.rs` — single-instance enforcement via `ShieldLock` guard (fs2)
- `process_monitor.rs` — polls `sysinfo::System`, tracks known PIDs in a `HashSet<String>`, emits alerts for new suspicious processes
- `threat_detector.rs` — hardcoded suspicious process list (xmrig, mimikatz, keylogger, etc.)
- `logger.rs` — thin wrapper that prefixes all output

**Key dependencies:** `sysinfo` 0.30 (cross-platform process info), `fs2` 0.4 (file locking).
