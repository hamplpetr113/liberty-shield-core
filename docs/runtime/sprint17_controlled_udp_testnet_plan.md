# Sprint 17 Plan — Controlled Local UDP Testnet

## Goal

Graduate from the fully in-process dry-run cluster (Sprint 16) to a controlled local UDP
testnet where each node binds a real UDP socket on a loopback address and exchanges actual
Noise-encrypted onion packets with its peers. No public network is involved. All nodes run
in the same process or on the same loopback interface.

## Prerequisites

- Sprint 16 `LocalCluster` + `ClusterTopologyProfile` wiring layer ✓
- Sprint 13 `MeshSimulator` + Noise channel layer ✓
- Sprint 15 `NodeService` with real UDP guard (`allow_real_udp: false`) ✓

## Architecture Change

```
Sprint 16 (dry-run):                Sprint 17 (UDP testnet):
  LocalCluster                        LocalCluster
    MeshSimulator (in-process)    →     UdpCluster
    NodeService (no sockets)              NodeUdpService (binds socket)
                                          NoiseChannel (per peer)
                                          PacketRouter
```

The new `UdpCluster` replaces `MeshSimulator`-based routing with real loopback UDP.
`NodeService` gains an optional UDP mode controlled by a new `allow_real_udp: true` config
combined with `simulation_mode: false`.

## Loopback Address Strategy

Assign unique loopback IPs per node to avoid port conflicts:

```
Node 1 → 127.0.0.1:39001
Node 2 → 127.0.0.2:39001
Node 3 → 127.0.0.3:39001
...
Node N → 127.0.0.N:39001
```

Windows requires enabling each additional loopback IP via:
```
netsh interface ipv4 add address "Loopback Pseudo-Interface 1" 127.0.0.2 255.0.0.0
```

Alternatively, use a single loopback address (127.0.0.1) with distinct ports per node,
starting from BASE_PORT=39001. This is the recommended approach for portability.

## Phases

### Phase 1 — NodeUdpService (config + socket binding)
- Add `allow_real_udp: true` path to `NodeService::start()`
- Bind `UdpSocket` on `127.0.0.1:{bind_port}`
- Store socket handle; expose `local_addr()` for peer wiring
- Enforce: `simulation_mode` must be `false` when `allow_real_udp` is `true`

### Phase 2 — Noise handshake over UDP
- Reuse `NoiseChannel` from `liberty-controlled-chaos`
- Initiator sends Noise handshake message 1; responder replies with message 2
- After handshake, both sides hold a `TransportState` for encrypt/decrypt
- Timeout after 500 ms; retry up to 3 times

### Phase 3 — Packet routing layer (PacketRouter)
- `PacketRouter` owns a map of `peer_id → TransportState + UdpSocket`
- `send(peer_id, plaintext)` → onion-wraps, Noise-encrypts, sends via UDP
- `recv()` → reads from socket, Noise-decrypts, strips onion layer
- Handle replay rejection from Sprint 13 `ReplayFilter`

### Phase 4 — UdpCluster lifecycle
- `UdpCluster::new(profile)` — builds node configs with `allow_real_udp: true`
- `start_all()` — binds all sockets, runs handshakes in deterministic order
- `run_packet(payload)` — routes a single payload through guard → relay → exit
- `stop_all()` — closes all sockets

### Phase 5 — CLI command: `liberty-node udp-testnet`
```
liberty-node udp-testnet --profile tiny --packets 100
```
Output: `{ "command": "udp-testnet", "delivered": 100, "dropped": 0, "elapsed_us": ... }`

### Phase 6 — Integration tests
- Tiny profile (5 nodes): all packets delivered, no drops
- Handshake failure: node unreachable → graceful error
- Replay attack: duplicate nonce rejected by `ReplayFilter`
- Concurrent sends: 2 senders, 1 shared relay — no race conditions

### Phase 7 — Documentation
- `docs/runtime/controlled_udp_testnet_sprint17.md`
- Architecture diagram: loopback UDP topology
- How to run on Windows (loopback interface note)

## Key Design Constraints

1. **No public network**: all sockets bind `127.0.0.x` or `127.0.0.1:{port}`
2. **No randomness**: nonces are still monotonic; handshake keys from deterministic
   `NodeIdentity` derivation
3. **Real encryption**: Noise XX handshake with `X25519` + `ChaCha20Poly1305`
4. **Backward compatible**: `allow_real_udp: false` path (Sprint 16 dry-run) remains
   fully functional and tested

## Estimated Test Count

~40 new tests across UdpCluster, PacketRouter, handshake, CLI, integration.

## Risk: Windows loopback

Windows does not automatically route all `127.x.x.x` addresses to loopback. If distinct
IPs are used, test setup must call `netsh` (or use a PowerShell helper). Mitigation:
use a single loopback IP with distinct ports — no OS configuration required.

## Success Criterion

`liberty-node udp-testnet --profile tiny --packets 1000` runs to completion with
`delivered=1000`, `dropped=0`, and valid timing output — on any clean Windows or Linux
loopback without any external network dependencies.
