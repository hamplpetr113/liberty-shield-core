# Android Real Device Validation Report

**Date:** 2026-05-01  
**Commit tested:** 7f56674 (liberty-shield: root crate clippy cleanup sprint)  
**Branch:** main  

---

## Build Result

**Status: PASS**

```
BUILD SUCCESSFUL in 3m 50s
35 actionable tasks: 35 executed
```

**APK path:** `android/app/build/outputs/apk/debug/app-debug.apk`  
**APK size:** 2.01 MB  
**APK timestamp:** 2026-05-01 16:57:22  

**Gradle commands run:**

```bash
# Java runtime used
JAVA_HOME = C:\Program Files\Android\Android Studio\jbr

cd android
./gradlew clean assembleDebug
./gradlew testDebugUnitTest
./gradlew lintDebug
```

---

## Source Inspection Checklist

| Check | File | Result |
|-------|------|--------|
| foregroundServiceType in manifest | AndroidManifest.xml | `dataSync` on ShieldVpnService and TestModeService — matches `FOREGROUND_SERVICE_TYPE_DATA_SYNC` in `startAsForeground()` |
| VPN permission | AndroidManifest.xml | `BIND_VPN_SERVICE`, `FOREGROUND_SERVICE_DATA_SYNC`, `CHANGE_NETWORK_STATE` all present |
| minSdk / targetSdk | build.gradle.kts | minSdk=26, targetSdk=34 — correct |
| `protect()` ordering | TcpSession.kt:123-124 | `sock.bind(InetSocketAddress(0))` called before `vpnService.protect(sock)` — fixed in 48e3220 |
| TUN read loop | PacketReader.kt:29-31 | `len < 0` → break; `len == 0` → continue — fixed in 48e3220 |
| TCP SYN→SYN-ACK | TcpSession.kt:116-141 | `onSyn()` connects to real server, sends SYN-ACK, enters SYN_RECEIVED |
| TCP SYN-ACK→ESTABLISHED | TcpSession.kt:144-153 | ACK received → ESTABLISHED → `startServerReader()` → piggybacked payload forwarded |
| TCP teardown guard | TcpSession.kt:217 | `if (state == State.CLOSED_FINAL) return` — double-teardown prevented |
| Piggybacked payload (TLS ClientHello) | TcpSession.kt:151 | `handleEstablished(seg, buf)` called immediately after ESTABLISHED transition |
| Bounds check in extractPayload | TcpSession.kt:76 | `val end = minOf(seg.payloadOffset + seg.payloadLen, buf.size)` |
| VPN state machine | ShieldVpnService.kt | STOPPED→STARTING→RUNNING; duplicate start guarded; FAILED→stopSelf() |
| DNS servers | ShieldVpnService.kt:102-103 | `8.8.8.8` and `1.1.1.1` added |
| `protect()` failure in UDP | PacketForwarder.kt:53-54 | throws `IOException` instead of silent return — fixed in 48e3220 |
| Kotlin version | build.gradle.kts | 1.9.22 — compatible with coroutines 1.7.3 |
| FOREGROUND_SERVICE_TYPE_DATA_SYNC | ShieldVpnService.kt:187 | Correct constant on API >= Q |

---

## Unit Tests

**Status: PASS (NO-SOURCE — no JVM unit tests written)**

```
Task :app:testDebugUnitTest NO-SOURCE
BUILD SUCCESSFUL in 14s
```

The project has no JVM unit tests. All logic resides in the Android runtime (VPN service, coroutines, JNI). Behavioral testing requires on-device instrumentation.

---

## Lint

**Status: PASS (0 errors, 15 warnings)**

```
BUILD SUCCESSFUL in 2m 10s
```

Lint warnings classified:

| Warning ID | Count | Classification | Action |
|------------|-------|----------------|--------|
| `GradleDependency` | 1 | Non-blocking — ktx 1.12.0 vs 1.18.0 available | Dep bump in future sprint |
| `HardwareIds` | 2 | Expected — agent intentionally uses ANDROID_ID for device fingerprinting | Accept |
| `DataExtractionRules` | 1 | Android 12+ advisory — missing xml backup config | Low priority |
| `ObsoleteSdkInt` | 4 | minSdk=26; SDK_INT >= O checks always true | Cleanup in future sprint |
| `MissingApplicationIcon` | 1 | Dev APK — no icon defined | Non-blocking |
| `SetTextI18n` | 6 | TestModeActivity debug strings are not translated | Acceptable for test harness |

**No VPN, security, or IPC errors.**

---

## Rust Gates

| Gate | Result |
|------|--------|
| `cargo fmt --check` | PASS |
| `cargo clippy -- -D warnings` | PASS (0 warnings) |
| `cargo test` | PASS (7/7) |
| `cargo test -p liberty-node-cli` | PASS (407/407) |

---

## ADB / Device Status

**ADB location:** `C:\Users\phamp\AppData\Local\Android\Sdk\platform-tools\adb.exe`  
**Devices connected:** None (`List of devices attached` — empty)  

Real device validation could not be performed on this machine at this time.

---

## Manual Device Test Checklist

To be executed on a physical Android device (API 26+):

### Prerequisites
- [ ] Enable Developer Options and USB Debugging on device
- [ ] Connect via USB: `adb devices` shows device serial
- [ ] Clear old logcat: `adb logcat -c`

### Install
```bash
adb install -r android/app/build/outputs/apk/debug/app-debug.apk
```

### VPN Path Test
1. [ ] Launch Liberty Shield Agent from launcher
2. [ ] Grant VPN permission when system dialog appears
3. [ ] Confirm foreground notification appears: "Liberty Shield — Network telemetry active"
4. [ ] Run logcat filter:
   ```bash
   adb logcat | grep -E "ShieldVpnService|PacketReader|PacketForwarder|TcpSession|VPN"
   ```
5. [ ] Verify log sequence:
   - `VPN [STOPPED → STARTING]`
   - `step 1: startForeground`
   - `step 2: init GatewayClient`
   - `step 3: Builder.establish()`
   - `step 4: TUN established fd=<n>, starting relay`
   - `VPN [STARTING → RUNNING]`
   - Heartbeat every 5 s: `heartbeat state=RUNNING tcpSessions=...`
6. [ ] Open Chrome, navigate to `http://example.com`
7. [ ] Verify TCP session lifecycle in logs:
   - `SYN_RECEIVED <srcIp>:<port>->93.184.216.34:80`
   - `ESTABLISHED <srcIp>:<port>->93.184.216.34:80`
   - `c→s <N>B ...`
   - `s→c <M>B ...`
   - `torn down ...`
8. [ ] Verify UDP/DNS in logs:
   - `UDP → 8.8.8.8:53 (<N>B)`
   - `UDP ← 8.8.8.8:53 (<M>B)`
9. [ ] Confirm no `ForegroundServiceStartNotAllowedException`
10. [ ] Confirm no `SecurityException` for foreground service type
11. [ ] Confirm no RST loop (repeated `TCP connect failed` for the same destination)
12. [ ] Stop VPN: send `adb shell am startservice -n com.libertyshield.agent/.vpn.ShieldVpnService -a com.libertyshield.agent.VPN_STOP`
13. [ ] Verify `VPN [RUNNING → STOPPING]` → `VPN [STOPPING → STOPPED]`

### Test Mode (Two-Phone) Path
1. [ ] Launch `[TEST] Liberty Shield` activity (TestModeActivity)
2. [ ] Fill in peer IP, local/peer UDP ports, and seed
3. [ ] Tap **Start**
4. [ ] Verify `TestModeController running` in logcat
5. [ ] Tap **Ping** — observe `PING_RECV seq=1` on peer device
6. [ ] Verify `pongsReceived` counter increments on sender

---

## Remaining Blockers

| ID | Severity | Description |
|----|----------|-------------|
| CRYPTO-001 | Critical | No real crypto — NON-PRODUCTION Rust runtime (ChaCha20 placeholder) |
| PERSIST-001 | Critical | SecurityStateStore journal is in-memory; peer table not persisted across restarts |
| VPN-001 | High | No real device test yet — VPN path not end-to-end verified on hardware |
| TEST-001 | Medium | No JVM unit tests; instrumentation tests required for `TcpSession` / `PacketForwarder` |
| LINT-001 | Low | 4× `ObsoleteSdkInt` warnings; 1× missing app icon |
| GW-001 | Low | GATEWAY_URL hardcoded to `192.168.68.107:8080` in BuildConfig |

---

## Next Recommended Sprint

**Sprint 211 — Real Device Smoke Test**

Prerequisites:
1. Build `.so` with `cargo ndk -t arm64-v8a -o android/app/src/main/jniLibs build --release`
   (requires NDK 26.1.10909125 installed, available via Android Studio SDK Manager)
2. Rebuild APK with JNI libs present
3. Install on physical device
4. Execute manual checklist above
5. Capture logcat transcript and attach to sprint report

Goal: confirm VPN starts, TUN fd stays open, TCP ESTABLISHED reached for one real HTTP connection.
