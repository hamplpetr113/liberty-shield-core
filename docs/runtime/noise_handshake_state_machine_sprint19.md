# Noise Handshake State Machine — Sprint 19

## Overview

Sprint 19 implements a deterministic 3-message in-memory handshake for the loopback testnet.
This is **NON-PRODUCTION**: keys are derived from node IDs, not from a real Noise XX exchange.

## Files

| File | Purpose |
|------|---------|
| `handshake_types.rs` | Core types: `HandshakeNodeId`, `HandshakeRole`, `HandshakeState`, `HandshakeError` |
| `handshake_message.rs` | `HandshakeMessage` struct with nonce payload helpers |
| `handshake_state.rs` | `PeerHandshake` state machine per peer |
| `handshake_manager.rs` | `HandshakeManager` for one local node |

## Message Flow

```
Initiator (A)                        Responder (B)
─────────────────────────────────────────────────
start_handshake(B) ──ClientHello(seq=0)──▶ receive(msg)
                                            auto-creates PeerHandshake
receive(ServerHello) ◀──ServerHello(seq=1)── (reply)
→ Established                          
──ClientFinish(seq=2)───────────────▶ receive(msg) → Established
                                            returns None
```

## State Transitions

```
Created → Message1Sent        (initiator calls next_message)
Created → Message1Received    (responder receives ClientHello)
        → Message2Sent        (responder replies ServerHello)
Message1Sent → Message2Received (initiator receives ServerHello)
             → Established    (initiator returns ClientFinish)
Message2Sent → Established    (responder receives ClientFinish)
Any state  → Failed           (Reject message received)
```

## Seed Derivation

Nonces are deterministic: `nonce_from_id(id) = id * K1 + K2`.

After the 3-way exchange:

```
send_seed = mix(local_nonce, remote_nonce)
recv_seed = mix(remote_nonce, local_nonce)
```

**Symmetry invariant**: `A.send_seed == B.recv_seed` and `B.send_seed == A.recv_seed`.
This allows each side to derive matching AEAD keys independently.

## Tests (H1–H9, HT1–HT3, HM1–HM3, HS1–HS10)

- H8: end-to-end test — two managers complete exchange, seeds match
- HS5: symmetry invariant verified algebraically
- H3/H4: out-of-order and duplicate messages rejected
