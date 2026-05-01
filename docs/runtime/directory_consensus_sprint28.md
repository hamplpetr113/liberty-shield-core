# Sprint 28 — Directory Consensus

## Purpose

Provides a deterministic, authority-signed view of the network's node descriptors. Authorities sign descriptors and build a consensus document listing guards, relays, and exits for a given epoch.

## NON-PRODUCTION Notice

Signatures in this sprint are deterministic hashes, not real cryptography. The field hash uses an FNV-style accumulator; the signature is `field_hash XOR authority_id`. Real Ed25519 or similar signatures are planned for Sprint 33+.

## Key Types

| Type                  | Description                                      |
|-----------------------|--------------------------------------------------|
| `DirectoryAuthorityId` | Wraps a `u64` authority identifier             |
| `NodeDescriptor`      | node_id, role, address, port, reliability, latency_ms |
| `SignedDescriptor`    | Descriptor + authority_id + NON-PRODUCTION sig  |
| `DirectoryConsensus`  | Epoch, authority, list of signed descriptors    |

## Authority Operations

| Method                          | Description                                     |
|---------------------------------|-------------------------------------------------|
| `sign_descriptor(desc)`         | Produce a `SignedDescriptor`                    |
| `verify_descriptor(signed)`     | Verify signature matches authority              |
| `add_descriptor(signed)`        | Add a verified descriptor to the consensus      |
| `build_consensus(epoch)`        | Freeze descriptors into a `DirectoryConsensus`  |
| `verify_consensus(consensus)`   | Verify all signatures in a consensus doc        |
| `list_guards(consensus)`        | Return Guard-role descriptors                   |
| `list_relays(consensus)`        | Return Relay-role descriptors                   |
| `list_exits(consensus)`         | Return Exit-role descriptors                    |

## Deterministic Factory

`build_deterministic_consensus(epoch, authority_id, node_ids, base_port)` produces a fully-signed consensus from a list of node IDs in one call. Used by tests and CLI commands.

## Module

- `crates/liberty-node-cli/src/directory_consensus.rs` — full implementation + 10 tests (DC1–DC10)
