# First Real Device Test — Liberty Shield Two-Phone Harness

**Sprint 210 | Status: READY TO RUN (pending .so build)**

---

## What Is Implemented

### Kotlin Layer (Android — `com.libertyshield.agent`)

| File | Sprint | Purpose |
|------|--------|---------|
| `ffi/LibertyNative.kt` | 201 | JNI declarations for 7 Rust FFI functions |
| `ffi/RuntimeBridge.kt` | 201 | Safe Kotlin wrapper — init/start/stop/ingest/pollSendIntent/tick |
| `test/TestIdentity.kt` | 202 | Deterministic 32-byte node IDs from seed byte (test only) |
| `test/PeerConfig.kt` | 203 | Manual peer config + SharedPreferences persistence |
| `test/UdpBridge.kt` | 204 | UDP socket I/O — receive → ingest, pollSendIntent → send |
| `test/RuntimeHud.kt` | 205 | HUD snapshot + formatted string for display |
| `test/TestModeController.kt` | 206 | Full session orchestrator — init, UDP, tick, ping/pong |
| `test/TestModeActivity.kt` | 206 | Minimal programmatic UI — config fields + HUD view |
| `test/TestPacket.kt` | 207 | 54-byte test wire format — PING/PONG build + parse |
| `test/LibertyLogger.kt` | 208 | Logcat logging under tag `LIBERTY_TEST` |
| `test/TestModeService.kt` | 209 | Foreground service with stop-action notification |

### Rust Layer (`crates/liberty-controlled-chaos`)

FFI functions exported by `android_ffi_boundary/mod.rs`:

| C symbol | Kotlin external fun | Description |
|----------|---------------------|-------------|
| `liberty_init_node` | `nativeInitNode(nodeId: ByteArray): Int` | Load 32-byte node ID |
| `liberty_start_node` | `nativeStartNode(): Int` | Transition to Running |
| `liberty_stop_node` | `nativeStopNode(): Int` | Transition to Stopped |
| `liberty_runtime_status` | `nativeRuntimeStatus(): Int` | State code 0–5 |
| `liberty_ingest_packet` | `nativeIngestPacket(data: ByteArray): Int` | Feed received bytes |
| `liberty_poll_send_intent` | `nativePollSendIntent(buf: ByteArray): Int` | Drain outbound queue |
| `liberty_tick_runtime` | `nativeTickRuntime(n: Int): Int` | Advance epoch by n |

Return codes: `0` = OK, `-1` = wrong state, `-2` = not initialized, `-3` = malformed, `-5` = no packet, `-6` = buffer too small.

---

## How to Build the Rust .so

### Prerequisites

- Rust toolchain with Android targets:
  ```
  rustup target add aarch64-linux-android armv7-linux-androideabi
  ```
- Android NDK installed (r26 recommended, set `ANDROID_NDK_HOME`)
- `cargo-ndk` installed: `cargo install cargo-ndk`

### Build

```bash
cd crates/liberty-controlled-chaos
cargo ndk -t arm64-v8a -t armeabi-v7a -o ../../android/app/src/main/jniLibs build --release
```

This places the `.so` files at:
- `android/app/src/main/jniLibs/arm64-v8a/libliberty_controlled_chaos.so`
- `android/app/src/main/jniLibs/armeabi-v7a/libliberty_controlled_chaos.so`

### Android Build

```bash
cd android
./gradlew assembleDebug
```

Install on device:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

---

## How to Run the Two-Phone Test

### Setup

Both phones must be on the same Wi-Fi network. Note each phone's IP address:

```
adb shell ip addr show wlan0
```

### Phone A Configuration

- Local UDP port: `9000`
- Peer IP: `<Phone B's IP>`
- Peer UDP port: `9001`
- Phone seed: `10`

### Phone B Configuration

- Local UDP port: `9001`
- Peer IP: `<Phone A's IP>`
- Peer UDP port: `9000`
- Phone seed: `11`

### Launch

There are two ways to run the test:

**Option A — TestModeActivity (interactive UI):**
```bash
adb shell am start -n com.libertyshield.agent/.test.TestModeActivity
```
Fill in the config fields, tap "Start", then "Ping".

**Option B — TestModeService (headless):**
```bash
# Phone A example
adb shell am startservice \
  -n com.libertyshield.agent/.test.TestModeService \
  --ei local_seed 10 \
  --ei peer_seed 11 \
  --ei local_port 9000 \
  --es peer_ip 192.168.1.101 \
  --ei peer_port 9001
```

### Monitor Logs

```bash
adb logcat -s LIBERTY_TEST
```

Expected log sequence on Phone A after sending a ping:
```
[INIT] OK
[START] OK
[UDP_BIND] port=9000 result=OK
[STATUS] TestModeController running — local=0a0a0a0a...
[PING_SEND] seq=1
[UDP_SEND] bytes=54 to=192.168.1.101:9001 result=OK
[UDP_RECV] bytes=54 from=192.168.1.101:9001
[INGEST] bytes=54 result=OK
[PONG_RECV] seq=1
```

Expected log sequence on Phone B:
```
[INIT] OK
[START] OK
[UDP_BIND] port=9001 result=OK
[UDP_RECV] bytes=54 from=192.168.1.100:9000
[INGEST] bytes=54 result=OK
[STATUS] PING_RECV seq=1
[UDP_SEND] bytes=54 to=192.168.1.100:9000 result=OK
[PONG_RECV] seq=1
```

---

## Known Limitations

1. **No real crypto** — The Rust runtime uses NON-PRODUCTION key material. Packets are not authenticated or encrypted for real-world use.
2. **No peer discovery** — IP addresses must be configured manually before the test.
3. **NAT traversal not implemented** — Both phones must be on the same LAN (no STUN/TURN/hole-punching).
4. **Single peer** — The test harness connects exactly one Phone A to one Phone B.
5. **No persistent identity** — Node IDs are derived from a single seed byte and are trivially guessable.
6. **Rust outbound queue behavior** — `pollSendIntent` returns whatever the Rust runtime queues. The test packet PING/PONG protocol bypasses the Rust queue (uses `sendRaw`). Rust-generated outbound packets are also forwarded but may be ignored by the receiving phone's Rust runtime if they fail internal validation.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---------|-------------|-----|
| `[INIT] FAIL` | `.so` not found or wrong ABI | Rebuild with correct `cargo ndk` targets |
| `[UDP_BIND] port=9000 result=FAIL` | Port in use or missing `INTERNET` permission | Kill other apps using the port; check manifest |
| `[UDP_SEND] result=FAIL` | Peer IP wrong or firewall blocking UDP | Verify IPs; check phone firewall settings |
| `[INGEST] result=FAIL` | Packet too short (< 4 bytes) | Check sender is using correct TestPacket format |
| No `[PONG_RECV]` after ping | Phone B not running or wrong peer port | Confirm Phone B is running and config matches |
| Service stops immediately | Missing foreground service permission | Check manifest has `FOREGROUND_SERVICE` and `FOREGROUND_SERVICE_DATA_SYNC` |

---

## Production Blockers

This test harness is explicitly NOT production-ready. The following gaps must be resolved before any real deployment:

| Gap ID | Subsystem | Blocker |
|--------|-----------|---------|
| CRYPTO-001 | Transport crypto | Real authenticated encryption (replace NON-PRODUCTION AEAD) |
| PERSIST-001 | Security state | Persistent session state and key storage |
| VPN-001 | VPN integration | Route real device traffic through the Rust runtime |
| TEST-001 | Test infrastructure | Property-based and cross-platform integration tests |

See `crates/liberty-controlled-chaos/src/production_gap_register/mod.rs` for the full gap register.

---

## File Map

```
android/app/src/main/
  java/com/libertyshield/agent/
    ffi/
      LibertyNative.kt       # JNI declarations
      RuntimeBridge.kt       # Safe wrapper
    test/
      LibertyLogger.kt       # Logcat logger (LIBERTY_TEST tag)
      PeerConfig.kt          # Manual peer config + persistence
      RuntimeHud.kt          # HUD snapshot
      TestIdentity.kt        # Test node IDs from seed
      TestModeActivity.kt    # Debug UI
      TestModeController.kt  # Session orchestrator
      TestModeService.kt     # Foreground service
      TestPacket.kt          # 54-byte test wire format
      UdpBridge.kt           # UDP socket I/O
  jniLibs/
    arm64-v8a/               # Place libliberty_controlled_chaos.so here
    armeabi-v7a/             # Place libliberty_controlled_chaos.so here

crates/liberty-controlled-chaos/src/
  android_ffi_boundary/mod.rs   # C ABI exports + JNI wrappers
```
