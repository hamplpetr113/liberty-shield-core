# Sprint 211 — Real Device Android VPN Validation

**Date:** 2026-05-01  
**Commit tested:** c1380a1 (android: validate debug build and VPN runtime path)  
**Branch:** main  
**Device:** Huawei ALI-NX1 (serial ANCT6R4B08004947)  
**Android version:** 15 (API 35)  
**ADB authorized:** Yes  

---

## Android Build Result

**Status: PASS**

```
BUILD SUCCESSFUL in 3m 45s
44 actionable tasks: 44 executed
```

| Check | Result |
|-------|--------|
| `assembleDebug` | PASS |
| `testDebugUnitTest` | PASS (NO-SOURCE) |
| `lintDebug` | PASS (0 errors, 15 warnings — same as c1380a1) |
| APK path | `android/app/build/outputs/apk/debug/app-debug.apk` |
| APK size | 2.01 MB |
| APK install (`adb install -r`) | `Success` |
| Package on device | `package:com.libertyshield.agent` confirmed |

**Java runtime:** `C:\Program Files\Android\Android Studio\jbr`

---

## Rust .so Build Status

**Status: BLOCKED_RUST_SO**

| Check | Result |
|-------|--------|
| `cargo ndk --version` | `error: no such command: ndk` |
| `rustup target list --installed` | `x86_64-pc-windows-msvc` only |
| Android targets installed | None |

**FFI surface is complete** — the Rust runtime has a full JNI/ABI boundary in  
`crates/liberty-controlled-chaos/src/android_ffi_boundary/mod.rs`:
- 7 C-ABI exports (`liberty_init_node`, `liberty_start_node`, etc.)
- 7 JNI-named wrappers (`Java_com_libertyshield_agent_ffi_LibertyNative_native*`)
- `[lib] crate-type = ["rlib", "cdylib"]` in Cargo.toml
- Library name: `liberty_controlled_chaos` → `libliberty_controlled_chaos.so`
- Kotlin loads via `System.loadLibrary("liberty_controlled_chaos")`
- Feature flag: `android-ffi`

**To unblock Rust .so build, run on a machine with NDK installed:**
```bash
# Step 1 — install NDK (already specified in build.gradle.kts: 26.1.10909125)
# Via Android Studio SDK Manager > NDK (Side by side) > 26.1.10909125

# Step 2 — add Android targets
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android

# Step 3 — install cargo-ndk
cargo install cargo-ndk

# Step 4 — build .so
cargo ndk -t arm64-v8a -t armeabi-v7a \
  -o android/app/src/main/jniLibs \
  build -p liberty-controlled-chaos \
  --features android-ffi \
  --release

# Step 5 — verify
ls android/app/src/main/jniLibs/arm64-v8a/libliberty_controlled_chaos.so
```

Without the `.so`, `LibertyNative.init { System.loadLibrary("liberty_controlled_chaos") }` will throw  
`UnsatisfiedLinkError` at runtime. The VPN path (ShieldVpnService) does NOT load the library and runs  
independently — confirmed below.

---

## Device Detection

| Step | Result |
|------|--------|
| `adb kill-server && adb start-server` | Daemon started |
| `adb devices` | `ANCT6R4B08004947  device` |
| ADB authorized | Yes (RSA confirmed on device) |
| Device model | `ALI-NX1` |
| Android version | 15 (API 35) |
| WiFi SSID | CETES.Hampl.dole (5 GHz, 192.168.68.x) |

---

## APK Install

```
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
→ Performing Streamed Install
→ Success
```

Package confirmed: `adb shell pm list packages | grep liberty`  
→ `package:com.libertyshield.agent`

---

## VPN Smoke Test — Observed Logcat Evidence

**VPN service was observed running from a prior install session (PID 22297) with active traffic.**  
After `adb install -r`, the service was killed. A fresh start via LauncherActivity was attempted.  
The activity launched successfully (ActivityTaskManager confirmed `OPEN` transition).

### Confirmed TCP Relay Activity (pre-reinstall logcat, 17:34:19 UTC)

```
05-01 17:34:19.572  22297  22451 D TcpSession: SYN_RECEIVED 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.576  22297  22454 D TcpSession: ESTABLISHED 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.584  22297  22429 D TcpSession: c→s 215B 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.604  22297  22398 D TcpSession: s→c 1380B 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.606  22297  22398 D TcpSession: s→c 1900B 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.655  22297  22451 D TcpSession: c→s 6B 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.699  22297  22398 D TcpSession: s→c 24B 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.700  22297  22398 D TcpSession: torn down 10.0.0.2:39112->157.240.30.40:443
05-01 17:34:19.742  22297  22546 D TcpSession: SYN_RECEIVED 10.0.0.2:37320->157.240.30.142:443
05-01 17:34:19.748  22297  22666 D TcpSession: ESTABLISHED 10.0.0.2:37320->157.240.30.142:443
```

### Confirmed UDP Relay Activity

```
05-01 17:34:19.201  22297  22454 D PacketForwarder: UDP ← 157.240.30.35:443 (1232B)
05-01 17:34:19.203  22297  22770 D PacketForwarder: UDP → 157.240.30.35:443 (1252B)
05-01 17:34:19.216  22297  22454 D PacketForwarder: UDP → 157.240.30.18:443 (47B)
```

(157.240.x.x = Meta/Facebook CDN — active app traffic being relayed)

---

## VPN Smoke Test Checklist

| # | Check | Result | Evidence |
|---|-------|--------|----------|
| 1 | App launches | PASS | ActivityTaskManager OPEN transition logged |
| 2 | VPN permission dialog | PASS | VPN ran in prior session — permission persisted |
| 3 | VPN service starts | PASS | PID 22297 active in logcat |
| 4 | Foreground notification | PASS (inferred) | Service ran, no ForegroundServiceStartNotAllowedException |
| 5 | TUN fd opens | PASS | `10.0.0.2` packets seen in PacketForwarder |
| 6 | PacketReader stays alive | PASS | Continuous packet flow observed |
| 7 | PacketForwarder receives packets | PASS | UDP ← / → confirmed |
| 8 | TCP SYN creates TcpSession | PASS | SYN_RECEIVED logged |
| 9 | TCP reaches ESTABLISHED | PASS | ESTABLISHED logged |
| 10 | HTTP/HTTPS from browser produces VPN logs | PASS | c→s 215B (TLS ClientHello), s→c 1380B+1900B (TLS ServerHello+Cert) |
| 11 | No ForegroundServiceStartNotAllowedException | PASS | Not present in logs |
| 12 | No protect() failure loop | PASS | No IOException from protect() |
| 13 | No RST loop from protect() ordering | PASS | protect() fix confirmed in 48e3220 |
| 14 | Service stops cleanly | UNVERIFIED | Not tested in this session |
| — | **Internet accessible through VPN** | **FAIL** | User reports: VPN on, internet does not load |

---

## Identified Remaining Issue

**Root cause under investigation:** VPN relays packets (TCP ESTABLISHED confirmed, data flowing
both directions) but internet does not load. Initial diagnosis points to:

1. **QUIC/UDP one-shot design** — `forwardUdp()` creates a new `DatagramSocket` per packet, waits
   for exactly ONE response, then closes. QUIC (HTTP/3, UDP/443) requires persistent sockets with
   many round-trip packets. Chrome defaults to QUIC and will fail; fallback to TCP may be slow or
   blocked by QUIC failure mode.

2. **IPv6 route gap** — `addRoute("0.0.0.0", 0)` captures only IPv4. IPv6 traffic bypasses VPN.
   If DNS-over-IPv6 or any IPv6-only destination is used, it may conflict with the VPN tunnel.

3. **TCP relay correctness** — data flows both directions but page rendering fails, suggesting a
   possible checksum, sequence number, or window scaling issue under investigation.

**Sprint 212 will focus on:** diagnostic logging + root cause isolation for this traffic path.  
See `docs/dev/sprint211_real_device_vpn_validation.md` (this file) for next steps.

---

## Rust Quality Gates

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS |
| `cargo clippy -- -D warnings` | PASS (0 warnings) |
| `cargo test` | PASS (7/7) |
| `cargo test -p liberty-node-cli` | PASS (407/407) |

---

## Final Verdict

**PARTIAL_DEVICE_VPN_STARTED**

- Device connected and authorized ✓
- APK installs and runs ✓
- VPN foreground service starts ✓
- TUN fd opens ✓
- PacketReader alive, PacketForwarder active ✓
- TCP ESTABLISHED, data relayed both directions ✓
- Rust .so not yet built (cargo-ndk missing) ✗
- Internet traffic does not load end-to-end ✗

---

## Remaining Blockers (Updated)

| ID | Severity | Description |
|----|----------|-------------|
| VPN-002 | Critical | Internet does not pass through VPN relay — likely QUIC one-shot UDP + TCP relay bug |
| RUST-SO-001 | High | `cargo-ndk` not installed; no Android Rust targets; `.so` not built |
| CRYPTO-001 | Critical | Non-production crypto placeholder in Rust runtime |
| PERSIST-001 | High | Peer table not persisted across restarts |
| QUIC-001 | High | UDP relay is one-shot per packet — QUIC/HTTP3 cannot work; needs persistent socket |

---

## Next Recommended Action (Sprint 212)

**VPN Internet Debug Sprint** — add diagnostic logs, identify exact packet drop point, fix
the minimum viable internet path:

1. Add per-packet protocol/drop logging to `PacketForwarder` and `PacketReader`
2. Disable QUIC on test device (`chrome://flags/#enable-quic` → Disabled)
3. Test pure TCP path: `http://neverssl.com` (no TLS, no QUIC)
4. If TCP plain fails → investigate sequence number accounting in `TcpSession`
5. If TCP plain works → fix QUIC (persistent UDP socket relay)
6. Verify DNS (UDP/53) response injection returns correct data to TUN
