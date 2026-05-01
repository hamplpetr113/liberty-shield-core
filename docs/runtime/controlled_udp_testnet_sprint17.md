# Sprint 17 — Controlled Local UDP Testnet

## Purpose

Sprint 17 introduces real UDP socket binding to Liberty Shield for the first time. Nodes
bind `UdpSocket` handles and exchange packets over loopback. This is a controlled testnet,
not a production network. The goal is to prove that the packet codec and socket wiring work
correctly before any encrypted packet flow is introduced in Sprint 18.

---

## Safety Model

**No public networking is enabled in this sprint.**

Every constraint is enforced in code, not just convention:

| Rule | Enforcement point |
|------|-------------------|
| `bind_address` must be `"127.0.0.1"` | `UdpTestnetNodeConfig::validate()` **and** `UdpLoopbackSocket::bind()` |
| `allow_real_udp` must be `true` | `UdpTestnetNodeConfig::validate()` |
| `simulation_mode` must be `false` | `UdpTestnetNodeConfig::validate()` |
| `send_to` target must be loopback | `UdpLoopbackSocket::send_to()` via `IpAddr::is_loopback()` |
| Default `NodeConfig` stays simulation-only | `NodeConfig::default()` has `simulation_mode=true, allow_real_udp=false` |
| Sprint 16 dry-run cluster unchanged | `ClusterNodeConfig` always has `allow_real_udp=false` |

**Eight safety-gate tests** (SG1–SG8) verify each constraint independently.

---

## Why Loopback Only

Binding to `0.0.0.0` or any public interface would:
- expose the testnet to other processes on the machine
- risk sending test packets to real network destinations
- violate the "local, controlled, opt-in" principle

All socket addresses are `127.0.0.1:{port}`. The `is_loopback()` check in `send_to`
rejects `SocketAddr` values outside the `127.0.0.0/8` block, including IPv6 addresses
other than `::1`.

---

## Real UDP is Opt-In

The default runtime is **simulation-only**:

```rust
NodeConfig::default()
// simulation_mode: true
// allow_real_udp: false
```

To enable real UDP, a caller must explicitly construct `UdpTestnetNodeConfig` with
`allow_real_udp: true` and `simulation_mode: false`. Passing anything else to
`UdpTestnetNode::start()` returns `Err(UdpTestnetError::RealUdpDisabled)` or
`Err(UdpTestnetError::PublicBindRejected)`.

---

## UDP Testnet Node

`UdpTestnetNode` wraps a single nonblocking `UdpLoopbackSocket` and maintains:

- `sequence_counter` — monotonically incremented per `send_*()` call (deterministic,
  no randomness)
- `packets_sent / packets_received / packets_dropped` — counters updated on every
  operation
- `snapshot()` — returns a `UdpTestnetNodeSnapshot` with all counters, the bound address,
  and the next sequence number

The node never blocks. `poll_once()` calls `try_recv()` which returns `Ok(None)` on
`WouldBlock` / `TimedOut` OS errors.

### Packet kinds

| Kind | Wire byte | Use |
|------|-----------|-----|
| Probe | 0 | Connectivity test (empty payload) |
| Data | 1 | Application payload delivery |
| Cover | 2 | Traffic obfuscation (future) |
| Shutdown | 3 | Graceful teardown signal |

---

## UDP Testnet Cluster

`UdpTestnetCluster` manages a `Vec<UdpTestnetNode>`. All nodes are assigned:

- `node_id`: 1, 2, …, n (sequential)
- `bind_address`: `127.0.0.1` (always)
- `bind_port`: `base_port`, `base_port+1`, …, `base_port+n-1` (deterministic)

### Ring topology

Probe and data sends follow a ring: node i → node (i+1) % n. This gives exactly n
packets sent and n packets received per round.

```
  Node 1 → Node 2
    ↑          ↓
  Node 3 ← Node 2
     (3-node ring example)
```

`poll_all()` drains every node's receive buffer until empty and returns the total count.

---

## CLI Commands

| Command | Default args | JSON output |
|---------|-------------|-------------|
| `liberty-node udp-testnet-start --nodes N --base-port P` | nodes=3, port=41000 | `{"command":"udp-testnet-start","mode":"loopback-only","nodes":N,"base_port":P,"state":"started"}` |
| `liberty-node udp-testnet-probe --nodes N --base-port P` | nodes=3, port=41000 | `{"command":"udp-testnet-probe","nodes":N,"packets_sent":N,"packets_received":N}` |
| `liberty-node udp-testnet-data --nodes N --base-port P --payload TEXT` | nodes=3, port=41000 | `{"command":"udp-testnet-data","nodes":N,"payload_len":L,"packets_sent":N,"packets_received":N}` |
| `liberty-node udp-testnet-status --nodes N --base-port P` | nodes=3, port=41000 | `{"command":"udp-testnet-status","nodes":N,"snapshots":[...]}` |

Each command creates a fresh in-process `UdpTestnetCluster`, performs the operation,
polls nonblocking sockets (up to 200 attempts), emits JSON, then exits. Sockets are
released when the cluster drops at end of scope.

---

## What Is Real Now

- Real UDP sockets (`std::net::UdpSocket`) are bound for testnet commands
- Actual loopback OS packet delivery (kernel route: send → recv buffer)
- Per-packet sequence numbers (deterministic, not random)
- Wire-format packet codec (27-byte header + payload)
- Non-blocking `try_recv()` with `WouldBlock` handling

---

## What Is Still Non-Production

- **No encryption**: packets travel as plaintext over loopback
- **No Noise handshake**: Sprint 18 will route `EncryptedCell` objects through this layer
- **No peer discovery**: addresses are pre-configured, not discovered
- **No replay protection**: the `ReplayFilter` from Sprint 13 is not wired to this path yet
- **Placeholder crypto marker**: `NodeIdentity` keys are deterministic test vectors, not
  cryptographically secure key pairs
- **No rate limiting, congestion control, or flow control**

---

## Security Gates (SG1–SG8)

All eight gates are automated tests in `lib.rs`:

| Test | What it verifies |
|------|-----------------|
| SG1 | `0.0.0.0` bind address rejected at config level |
| SG2 | `allow_real_udp=false` rejected at config level |
| SG3 | `simulation_mode=true` rejected at config level |
| SG4 | Non-loopback `send_to` target rejected at socket level |
| SG5 | CLI UDP commands never emit `"0.0.0.0"` in JSON output |
| SG6 | `NodeConfig::default()` remains `simulation_mode=true, allow_real_udp=false` |
| SG7 | Sprint 16 dry-run `LocalCluster::start_all()` succeeds without UDP |
| SG8 | `UdpTestnetNode::start()` refuses `allow_real_udp=false` config |

---

## Next Sprint Recommendation

**Sprint 18 — Encrypted UDP Packet Flow**

Replace the plaintext `UdpTestnetPacket` payload with actual `EncryptedCell` objects from
`liberty-controlled-chaos`. Wire the Noise channel handshake between `UdpTestnetNode` peers
before any data exchange, then route `send_payload()` traffic through the encrypted path.

Specifically:
- `UdpTestnetNode::connect_to_peer(peer_id, peer_addr)` — run Noise XX initiator/responder
- `UdpTestnetNode::send_encrypted(peer_id, plaintext)` — Noise-encrypt then UDP-send
- `UdpTestnetNode::poll_encrypted()` — UDP-recv then Noise-decrypt
- `ReplayFilter` from Sprint 13 wired to `poll_encrypted()` to reject duplicate nonces
- Sprint 17 plaintext path retained as a debug/test mode
