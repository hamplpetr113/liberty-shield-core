# Sprint 19 Plan — Real Noise XX Handshake

## Goal

Replace the deterministic seed-based session establishment in Sprint 18 with a real
**Noise XX** handshake, giving each pair of nodes an authenticated, forward-secret channel.
The encrypted packet pipeline (`EncryptedCell` → `EncryptedUdpPacket` → UDP) and the
replay-protection layer remain unchanged.

---

## What Changes

### Phase 1 — Ephemeral Key Primitives (`crates/liberty-controlled-chaos`)

1. Add a `noise_handshake` module alongside `noise_link/`.
2. Implement X25519 Diffie-Hellman (use the `x25519-dalek` crate or an inline
   Curve25519 scalar-mult from a vendored source — no `unsafe`).
3. Expose:
   - `EphemeralKeyPair::generate(seed: u64) -> EphemeralKeyPair` — deterministic for tests.
   - `EphemeralKeyPair::public_key() -> [u8; 32]`
   - `EphemeralKeyPair::diffie_hellman(peer_public: [u8; 32]) -> [u8; 32]`

### Phase 2 — Noise XX State Machine

Noise XX has three messages:

```
→ e
← e, ee, s, es
→ s, se
```

Implement `NoiseHandshake` as a state machine with three states:
`SendE`, `RecvEES`, `SendSSE`, `Complete`.

Each state transition takes in a received message (if any) and returns the next
message to send. On `Complete`, the handshake produces a `NoiseSession` with
`send_key` and `recv_key` derived from the transcript.

Key derivation: HKDF-SHA256 over the Noise chaining key. Replace the current
`seed_to_key` placeholder with this for production sessions.

```rust
pub struct NoiseHandshake { ... }

impl NoiseHandshake {
    pub fn initiator(local_static: &StaticKeyPair, local_ephemeral: EphemeralKeyPair) -> Self;
    pub fn responder(local_static: &StaticKeyPair, local_ephemeral: EphemeralKeyPair) -> Self;
    pub fn write_message(&mut self) -> Result<Vec<u8>, HandshakeError>;
    pub fn read_message(&mut self, msg: &[u8]) -> Result<Option<NoiseSession>, HandshakeError>;
}
```

### Phase 3 — `EncryptedPeerSession` Upgrade (`crates/liberty-node-cli`)

Replace `EncryptedPeerSession::new(peer_id, send_seed, recv_seed)` with:

```rust
impl EncryptedPeerSession {
    // NON-PRODUCTION (test only):
    pub fn from_seeds(peer_id, send_seed, recv_seed) -> Self;
    // Production path:
    pub fn from_noise_session(peer_id, session: NoiseSession) -> Self;
}
```

`EncryptedUdpNode::add_peer_session` will grow a counterpart
`add_peer_session_from_noise(peer_id, session: NoiseSession)`.

### Phase 4 — Handshake Transport

Two additional `EncryptedUdpPacketKind` variants:

- `HandshakeInit` — carries the initiator's first Noise message.
- `HandshakeResp` — carries the responder's reply.

Add `initiate_handshake(peer_id, peer_addr)` and `process_handshake_packet(pkt)` to
`EncryptedUdpNode`. Once both messages are exchanged, the node installs a
`NoiseSession`-derived peer session automatically.

### Phase 5 — Replace Placeholder Cipher

Swap `NoiseLinkEncoder` internals from ChaCha8/SipHash-2-4 to
`chacha20poly1305::ChaCha20Poly1305` (IETF variant, RFC 8439).

This is a drop-in replacement for the `encode`/`decode` methods; the `EncryptedCell`
wire format (path_id, nonce, ciphertext, auth_tag) does not change.

### Phase 6 — Tests

New test IDs (EH1–EH10):

- EH1: Initiator completes handshake with responder — both derive the same `NoiseSession`.
- EH2: Responder rejects tampered `HandshakeInit` message.
- EH3: Replay of `HandshakeInit` is rejected.
- EH4: `EncryptedUdpNode::initiate_handshake` → `process_handshake_packet` → session installed.
- EH5: Post-handshake ring send + poll succeeds (replacing seed-based test).
- EH6: Wrong static key rejects the handshake at message 2.
- EH7: Two simultaneous handshakes on the same node do not interfere.
- EH8: `from_seeds` (test path) still works alongside `from_noise_session`.
- EH9: ChaCha20-Poly1305 round-trip succeeds.
- EH10: Tampered ciphertext still returns `AuthenticationFailure`.

---

## What Does NOT Change

- `EncryptedUdpPacket` wire format (27-byte header + 1482-byte cell body).
- `EncryptedCell` wire layout.
- `EncryptedUdpSocket` loopback-only safety gates.
- `ReplayWindow` per-source nonce tracking.
- CLI command names and JSON output shapes.
- Sprint 17 plaintext UDP testnet (untouched by design).

---

## Open Questions Before Coding

1. **X25519 dependency.** Add `x25519-dalek` to `liberty-controlled-chaos/Cargo.toml`
   or inline a minimal scalar-mult? Inline avoids a new dependency but is harder to audit.

2. **Static key storage.** Where do long-term static key pairs live?
   `NodeIdentity` in `identity.rs` is the natural home. Extend it or add a separate
   `StaticKeyPair` type?

3. **Handshake serialization.** Noise messages include ephemeral public keys and
   AEAD-encrypted static keys. Use a flat byte layout (no serde) for simplicity.

4. **Test determinism.** Noise handshakes require random ephemeral keys. Use a seeded
   PRNG (`ChaCha8Rng::from_seed`) for test ephemeral key generation, same pattern as
   `encrypted_cell_fixture.rs`.

5. **Timeout / retry.** If a handshake message is lost (UDP is unreliable), should
   `EncryptedUdpNode` retransmit? Sprint 19 can skip retry and document it as a
   known limitation.

---

## Estimated Scope

| Phase | New Files | New Tests |
|-------|-----------|-----------|
| 1 Ephemeral keys | `noise_handshake/ephemeral.rs` | ~5 |
| 2 State machine | `noise_handshake/state.rs` | ~8 |
| 3 Session upgrade | modify `encrypted_peer_session.rs` | ~3 |
| 4 Handshake transport | modify `encrypted_udp_node.rs`, `encrypted_udp_packet.rs` | ~6 |
| 5 Cipher swap | modify `noise_link/link_encryptor.rs` | ~4 |
| 6 Tests | `lib.rs` integration | ~10 |
| **Total** | ~4 new files | **~36 new tests** |

Estimated test count after Sprint 19: ~237.
