# VPS Public Hello — Command Reference

Copy-paste command templates for the v0.5.3 live test.
Replace `<VPS_IP>`, `<ssh-user>`, and `<repo-url>` with your actual values.

**Do not paste SSH keys, passwords, PSK, or root credentials here or into chat.**

---

## On VPS (via SSH)

```bash
# 1 — System setup
sudo apt update && sudo apt upgrade -y
sudo apt install -y git curl build-essential pkg-config

# 2 — Rust (if not installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# 3 — Get the repo
git clone <repo-url> liberty-shield
cd liberty-shield
git checkout feature/runtime-dashboard
git pull

# 4 — Verify build
cargo check -p liberty-exit-node --bins
cargo test -p liberty-exit-node

# 5 — Open firewall (if UFW enabled)
sudo ufw allow 51820/udp
sudo ufw allow 22/tcp
sudo ufw status

# 6 — Verify port after server starts
sudo ss -ulnp | grep 51820

# 7 — Run server (keep this terminal open, or use screen/tmux)
LIBERTY_EXIT_BIND=0.0.0.0:51820 \
LIBERTY_EXIT_HEALTH_BIND=127.0.0.1:8081 \
LIBERTY_LOG_LEVEL=info \
cargo run -p liberty-exit-node
```

---

## On Local PC

```bash
# Terminal A — SSH tunnel to health endpoint (keep open)
ssh -L 8081:127.0.0.1:8081 <ssh-user>@<VPS_IP>

# Terminal B — health before test
curl http://127.0.0.1:8081/health

# Terminal B — send Hello frame (run from liberty-shield repo root)
LIBERTY_HELLO_TARGET=<VPS_IP>:51820 cargo run -p liberty-exit-node --bin send_hello

# Terminal B — health after test (packets_rx should be ≥ 1)
curl http://127.0.0.1:8081/health
```

---

## Expected outputs

### send_hello (local)

```
target:     <VPS_IP>:51820
frame_len:  27
session_id: 1
sequence:   1
msg_type:   Hello
sent OK
```

### Server log (VPS)

```
INFO liberty_exit_node::server: Hello frame received (no auth yet) peer=<PUBLIC_IP>:<port> session=1
```

### /health (after Hello)

```json
{"status":"ok","packets_rx":1,"packets_tx":0,"bytes_rx":27,"bytes_tx":0,"active_sessions":0,"parse_errors":0,"auth_failures":0}
```

---

## Troubleshooting quick-ref

| Problem | Check |
|---|---|
| No VPS log after send_hello | UDP 51820 blocked — open in cloud panel + UFW |
| Health connection refused | SSH tunnel not open or server stopped |
| parse_errors > 0 | Binary version mismatch — `git pull` + rebuild on VPS |
| Server exits immediately | Port conflict — check `ss -ulnp \| grep 8081` |
