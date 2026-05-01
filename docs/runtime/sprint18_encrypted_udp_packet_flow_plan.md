# Sprint 18 — Encrypted UDP Packet Flow

## Goal

Replace the plaintext `UdpTestnetPacket` payload with actual `EncryptedCell` objects from
`liberty-controlled-chaos`. Wire a Noise channel handshake between `UdpTestnetNode` peers
before any data exchange, then route `send_payload()` traffic through the encrypted path.
Connect `ReplayFilter` (Sprint 13) to `poll_encrypted()` to reject duplicate nonces.

---

## Prerequisites

| Component | Crate | Status |
|-----------|-------|--------|
| `NoiseLink` / Noise XX handshake | `liberty-controlled-chaos` | Implemented |
| `EncryptedCell` wire format | `liberty-controlled-chaos` | Implemented |
| `ReplayFilter` (nonce dedup) | `liberty-controlled-chaos` | Implemented (Sprint 13) |
| `UdpLoopbackSocket` | `liberty-node-cli` | Implemented (Sprint 17) |
| `UdpTestnetNode` | `liberty-node-cli` | Implemented (Sprint 17) |
| `UdpTestnetCluster` | `liberty-node-cli` | Implemented (Sprint 17) |

---

## Design

### Handshake flow (Noise XX)

```
Initiator                    Responder
─────────                    ─────────
send_handshake_init() ──────► recv_handshake_init()
                             send_handshake_resp() ──────► recv_handshake_resp()
Noise session established
```

Both sides call `UdpLoopbackSocket::send_to` / `try_recv` for handshake messages.
Handshake frames are framed with a 1-byte type tag (`0x00` = handshake, `0x01` = data)
prepended to the existing wire format.

### Per-peer state

`UdpTestnetNode` gains a `peer_sessions: HashMap<UdpTestnetNodeId, NoiseLink>` field.
`NoiseLink` is borrowed from `liberty-controlled-chaos`.

### New API

```rust
impl UdpTestnetNode {
    /// Run Noise XX handshake as initiator; stores session keyed by peer_id.
    pub fn connect_to_peer(
        &mut self,
        peer_id: UdpTestnetNodeId,
        peer_addr: SocketAddr,
    ) -> Result<(), UdpTestnetError>;

    /// Run Noise XX handshake as responder; stores session keyed by peer_id.
    pub fn accept_from_peer(
        &mut self,
        peer_id: UdpTestnetNodeId,
    ) -> Result<(), UdpTestnetError>;

    /// Encrypt plaintext with peer's NoiseLink, then UDP-send.
    pub fn send_encrypted(
        &mut self,
        peer_id: UdpTestnetNodeId,
        plaintext: &[u8],
    ) -> Result<(), UdpTestnetError>;

    /// UDP-recv, decrypt, and replay-filter in one call.
    /// Returns Ok(None) if no packet is ready.
    pub fn poll_encrypted(&mut self) -> Result<Option<Vec<u8>>, UdpTestnetError>;
}
```

Sprint 17 plaintext `send_probe` / `send_data` / `poll_once` are retained as a
`simulation_mode`-style debug path.

### EncryptedCell wire layout

`EncryptedCell` objects from `liberty-controlled-chaos` are serialised as-is into the
`UdpTestnetPacket.payload` field. The `packet_kind` byte is set to `0x01` (`Data`) for
all encrypted frames.

Total wire size: `27 (header) + EncryptedCell::SIZE` bytes, which fits within the 1509-byte
`max_packet_size` limit.

### ReplayFilter integration

Each `UdpTestnetNode` holds a `ReplayFilter`. On every `poll_encrypted()` call:

1. Decrypt the `EncryptedCell` → extract nonce.
2. Call `replay_filter.check(nonce)` — returns `Err` if seen before.
3. If duplicate → increment `packets_dropped`, return `Ok(None)`.
4. If fresh → commit nonce to filter, return `Ok(Some(plaintext))`.

---

## New Error Variants

Add to `UdpTestnetError`:

```rust
HandshakeFailed,      // Noise XX exchange failed
PeerNotConnected,     // send_encrypted called before connect_to_peer
ReplayDetected,       // ReplayFilter rejected the nonce
```

---

## Test Plan

| ID | What it tests |
|----|---------------|
| EN1 | Two nodes complete Noise handshake without error |
| EN2 | `send_encrypted` + `poll_encrypted` round-trip 32-byte plaintext |
| EN3 | Duplicate `EncryptedCell` (replayed nonce) rejected by `ReplayFilter` |
| EN4 | `send_encrypted` before `connect_to_peer` returns `PeerNotConnected` |
| EN5 | 3-node cluster: all pairs handshake and exchange encrypted probes |
| EN6 | `poll_encrypted` returns `Ok(None)` when socket is empty |
| EN7 | Plaintext path (`poll_once`) still works alongside encrypted path |
| EN8 | Encrypted cluster bench: N rounds × ring topology, throughput ≥ Sprint 17 plaintext bench |

All tests remain loopback-only. Safety gates SG1–SG8 carry over unchanged.

---

## Files to Create

| File | Purpose |
|------|---------|
| `crates/liberty-node-cli/src/udp_testnet_session.rs` | `PeerSessionMap` — `HashMap<UdpTestnetNodeId, NoiseLink>` wrapper |
| `crates/liberty-node-cli/src/udp_replay_guard.rs` | `UdpReplayGuard` — thin wrapper combining `ReplayFilter` + per-node state |

## Files to Modify

| File | Change |
|------|--------|
| `udp_testnet_types.rs` | Add `HandshakeFailed`, `PeerNotConnected`, `ReplayDetected` error variants |
| `udp_testnet_node.rs` | Add `peer_sessions`, `replay_guard` fields; implement `connect_to_peer`, `accept_from_peer`, `send_encrypted`, `poll_encrypted` |
| `udp_testnet_cluster.rs` | Add `handshake_all()` — runs full-mesh Noise XX across all node pairs |
| `args.rs` | Add `udp-testnet-encrypted-probe` command |
| `output.rs` | Add `udp_testnet_encrypted_probe_json` |
| `lib.rs` | Wire execute arm + tests EN1–EN8 |

---

## What Remains Non-Production After Sprint 18

- No peer discovery — addresses still pre-configured
- No certificate pinning or identity verification beyond Noise XX ephemeral keys
- `NodeIdentity` keys remain deterministic test vectors
- No rate limiting, congestion control, or flow control
- Loopback-only — no public networking

## Next Sprint Recommendation (Sprint 19)

**Sprint 19 — Peer Discovery Bootstrap**

Add a minimal bootstrap mechanism: `UdpTestnetCluster` broadcasts a signed `PeerAnnounce`
packet to all known nodes. Nodes accumulate peer tables dynamically rather than requiring
pre-configured addresses.
