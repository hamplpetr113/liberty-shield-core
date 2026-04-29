# Encrypted UDP Packet Flow — Sprint 18

## Purpose

Sprint 18 layers authenticated encryption on top of the Sprint 17 loopback UDP testnet.
`EncryptedCell` values produced by `liberty-controlled-chaos::noise_link` travel over
real UDP sockets that are restricted to `127.0.0.1`.

**WARNING — NON-PRODUCTION CRYPTO.** The `NoiseLinkEncoder` uses a ChaCha8/SipHash-2-4
placeholder cipher and deterministic key derivation from numeric seeds. This is
intentional for testnet use only. Replace with ChaCha20-Poly1305 (RFC 8439) and a
real Noise XX handshake before any real networking.

---

## Architecture

```
payload &[u8]
  │
  ▼  encrypted_cell_fixture::make_cell()
Cell  (fixed 1450-byte plaintext block, built via CellEncoder full pipeline)
  │
  ▼  EncryptedPeerSession::send_encoder.encode()
EncryptedCell  { path_id, nonce, ciphertext[1450], auth_tag[16] }  (1482 bytes)
  │
  ▼  encrypted_udp_packet::encrypted_cell_to_bytes()
[u8; 1482]
  │
  ▼  EncryptedUdpSocket::send_to()  ──►  loopback UDP
27-byte EncryptedUdpPacket header + 1482-byte cell body
  │
  ▼  EncryptedUdpSocket::try_recv()
EncryptedUdpPacket
  │
  ▼  encrypted_udp_packet::bytes_to_encrypted_cell()
EncryptedCell
  │
  ▼  EncryptedPeerSession::recv_encoder.decode()
Cell
  │
  ▼  cell.payload_bytes().to_vec()
payload Vec<u8>
```

---

## EncryptedUdpPacket Wire Format

Big-endian layout, total = 27 + cell_len bytes:

| Offset | Size | Field               | Notes                                      |
|--------|------|---------------------|--------------------------------------------|
| 0      | 8    | source_node         | u64                                        |
| 8      | 8    | target_node         | u64                                        |
| 16     | 1    | packet_kind         | 0=EncryptedCell, 1=ProbeEncrypted, 2=Shutdown |
| 17     | 8    | sequence_number     | u64, monotonic per sender                  |
| 25     | 2    | encrypted_cell_len  | u16; must be 1482 for cell/probe, 0 for shutdown |
| 27     | var  | encrypted_cell_bytes | `ENCRYPTED_CELL_SIZE` bytes or empty        |

`EncryptedCell` byte layout within the payload (big-endian):

| Offset   | Size | Field      |
|----------|------|------------|
| 0        | 8    | path_id    |
| 8        | 8    | nonce      |
| 16..1466 | 1450 | ciphertext |
| 1466     | 16   | auth_tag   |

Total: `ENCRYPTED_CELL_SIZE = 1482` bytes.

---

## EncryptedUdpSocket

`EncryptedUdpSocket` (`encrypted_udp_socket.rs`) wraps `std::net::UdpSocket` with two safety gates:

1. **Bind guard** — `bind_address` must equal `"127.0.0.1"` (validated in `EncryptedUdpNodeConfig::validate()`).
2. **Send guard** — `send_to()` checks `target.ip().is_loopback()` and returns `Err(PublicBindRejected)` otherwise.

The socket is set to non-blocking mode. `try_recv()` returns `Ok(None)` on `WouldBlock`/`TimedOut`.

---

## Peer Sessions

`EncryptedPeerSession` (`encrypted_peer_session.rs`) holds two `NoiseLinkEncoder` instances:

- `send_encoder` — uses `NoiseSession::new(seed_to_key(send_seed), [0;32])`.
  Only `encode()` is called; `send_key` is the AEAD key.
- `recv_encoder` — uses `NoiseSession::new([0;32], seed_to_key(recv_seed))`.
  Only `decode()` is called; `recv_key` is the AEAD verification key.

For A→B communication to work, A's `send_seed` must equal B's `recv_seed` so both
derive the same 32-byte key.

`seed_to_key(seed)` repeats the 8-byte LE representation of `seed` four times.
**NON-PRODUCTION** — not a real KDF.

`EncryptedPeerSessionTable` stores sessions keyed by `EncryptedUdpNodeId`.

---

## EncryptedUdpNode

`EncryptedUdpNode` (`encrypted_udp_node.rs`) owns:

- One `EncryptedUdpSocket` bound to a loopback port.
- One `EncryptedPeerSessionTable`.
- Per-source `HashMap<u64, ReplayWindow>` for duplicate nonce detection.
- Packet and cell counters.

Key methods:

| Method | Description |
|--------|-------------|
| `start(config)` | Validates config, binds socket. |
| `add_peer_session(peer_id, send_seed, recv_seed)` | Installs a deterministic session. |
| `send_payload_encrypted(target, addr, payload)` | Full pipeline: Cell → encrypt → send. |
| `send_encrypted_cell(target, addr, cell_bytes)` | Send pre-encrypted bytes (no session lookup). |
| `poll_once()` | Non-blocking receive: replay check then decrypt. |
| `snapshot()` | Returns a copy of all counters and metadata. |

`poll_once()` uses two separate borrow scopes to avoid aliasing `replay_windows` and `sessions`:

```rust
// Scope 1 — replay check
let replay_ok = {
    let window = self.replay_windows.entry(source_id).or_insert_with(|| ReplayWindow::new(64));
    window.check_and_record(CellNonce(nonce)).is_ok()
};
// Scope 2 — decrypt
let cell = {
    let session = self.sessions.get_peer_mut(packet.source_node)?;
    session.recv_encoder.decode(enc_cell)?
};
```

---

## EncryptedUdpCluster

`EncryptedUdpCluster` (`encrypted_udp_cluster.rs`) manages a ring of `EncryptedUdpNode` instances.

- `start_loopback_cluster(count, base_port)` — binds `count` nodes on contiguous ports.
- `wire_deterministic_sessions()` — installs ring sessions using `pair_seed(from_id, to_id) = from_id * 1000 + to_id`. For direction A→B: A uses `send_seed = pair_seed(A,B)`, B uses `recv_seed = pair_seed(A,B)`.
- `send_encrypted_ring(payload)` — each node sends one encrypted payload to its ring successor.
- `poll_all()` — drains all nodes. `ReplayDetected` is counted as a drop and does not abort.

---

## CLI Commands

New commands added to `liberty-node`:

| Command | Description | Key Defaults |
|---------|-------------|--------------|
| `encrypted-udp-start` | Start loopback cluster | nodes=3, port=43000 |
| `encrypted-udp-probe` | Wire sessions + send probe ring | nodes=3, port=43000 |
| `encrypted-udp-send --payload <text>` | Wire sessions + send payload ring | nodes=3, port=43000 |
| `encrypted-udp-status` | Return node snapshots | nodes=3, port=43000 |
| `encrypted-udp-bench --rounds N` | Time N rounds of encrypted ring | nodes=5, port=43100, rounds=100 |

All commands produce JSON. The `mode` field is always `"loopback-only"`.

---

## Safety Gates (EG1–EG8)

| Gate | What is checked |
|------|-----------------|
| EG1 | Public bind address rejected at config level |
| EG2 | Non-loopback send target rejected at socket level |
| EG3 | `EncryptedCell` with wrong byte count rejected at codec level |
| EG4 | `send_payload_encrypted` without a session returns `SessionNotFound` |
| EG5 | Duplicate nonce in received cell returns `ReplayDetected` |
| EG6 | Default `NodeConfig` retains `simulation_mode=true, allow_real_udp=false` |
| EG7 | Sprint 17 plaintext UDP testnet still operational alongside encrypted testnet |
| EG8 | CLI output never contains `"0.0.0.0"` |

---

## Limitations

- **Loopback only.** All sockets are bound to and can only send to `127.0.0.1`.
- **No public networking.** The code will panic (socket-level guard) on any attempt to
  address a non-loopback destination.
- **No real Noise handshake.** Sessions are seeded by a numeric seed, not established
  via Noise XX ephemeral key exchange. There is no forward secrecy.
- **Placeholder cipher.** ChaCha8 + SipHash-2-4-128 provides no formal security guarantees.
  Replace with `chacha20poly1305` crate before any real-world use.
- **Single-threaded.** `EncryptedUdpNode` is not `Send`. All operations happen in the
  calling thread with non-blocking I/O.
- **Port range.** Module tests use 43000–43092; integration tests use 43100–43244.
  Do not overlap with Sprint 17 range (42100–42611).

---

## Next Sprint Recommendation

Sprint 19 should replace the deterministic session seeds with a real **Noise XX handshake**
state machine:

1. Implement ephemeral key generation (X25519 or equivalent).
2. Model the Noise XX three-message exchange (`e`, `e,ee,s,es`, `s,se`).
3. Derive `send_key` / `recv_key` from the completed handshake transcript.
4. Replace `seed_to_key()` and the `NON-PRODUCTION` session seeding in `EncryptedPeerSession`.
5. Replace `NoiseLinkEncoder`'s placeholder AEAD with `ChaCha20-Poly1305` (RFC 8439).

All existing tests should continue to pass if the public API of `EncryptedPeerSession`
and `EncryptedUdpNode` is preserved.
