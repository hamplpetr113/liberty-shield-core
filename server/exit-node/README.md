# liberty-exit-node

Liberty Shield single exit node service.

Receives encapsulated IP packets from Android clients over UDP, decapsulates them,
and forwards them to the public internet via kernel NAT. Return traffic is
re-encapsulated and sent back to the client.

## Status

**Skeleton — not functional yet.**

TODOs before v0.5 is usable:

- [ ] Noise XX handshake for session key establishment
- [ ] Client session registry (client ID → session state + keys)
- [ ] Replay protection (nonce window / counter)
- [ ] Packet framing (length-prefix + version byte)
- [ ] NAT/forwarding integration (TUN fd or raw socket)
- [ ] Pre-shared key loading from environment (never from source)
- [ ] Metrics: packets in/out, active sessions, errors
- [ ] Graceful shutdown on SIGTERM
- [ ] Health endpoint (HTTP, localhost only)

## Configuration (environment variables)

| Variable | Default | Description |
|---|---|---|
| `LIBERTY_EXIT_BIND` | `0.0.0.0:51820` | UDP bind address |
| `LIBERTY_EXIT_HEALTH_BIND` | `127.0.0.1:8081` | Health HTTP bind (local only) |
| `LIBERTY_LOG_LEVEL` | `info` | Log level |
| `LIBERTY_PSK` | (required) | Pre-shared key (hex); provision out-of-band |

**Never set `LIBERTY_PSK` in source code, git, or any chat log.**

## Build

```bash
cargo build --release -p liberty-exit-node
```

## Run (development)

```bash
LIBERTY_EXIT_BIND=127.0.0.1:51820 cargo run -p liberty-exit-node
```

## See also

- Architecture: `docs/architecture/v0.5-single-exit-node-mvp.md`
- VPS setup: `docs/deployment/vps-single-exit-node-setup.md`
