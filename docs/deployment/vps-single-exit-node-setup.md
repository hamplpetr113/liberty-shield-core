# VPS Single Exit Node — Setup Guide

> **WARNING:** This is a controlled engineering MVP, not a production anonymity system.
> Do not use this to protect sensitive activity until a full security audit is complete,
> device provisioning is implemented, and the Noise handshake is in place.

---

## Required VPS Parameters

| Parameter | Minimum | Recommended |
|---|---|---|
| vCPU | 2 | 4 |
| RAM | 2 GB | 4 GB |
| Disk | 20 GB | 40 GB |
| OS | Ubuntu 22.04 LTS | Ubuntu 24.04 LTS |
| Public IPv4 | required | static preferred |
| Root / sudo | required | |
| UDP port (default 51820) | must be open | |
| IP forwarding | must be enabled | |

Supported providers (tested or planned): WEDOS, Hetzner, DigitalOcean, any provider
with a clean public IPv4, unrestricted UDP, and `ip_forward` support.

---

## What You Must Provide (privately — do NOT paste into chat)

To configure the exit node you will need:

| Item | Where to use |
|---|---|
| VPS public IPv4 | set in Android debug build config |
| SSH username | your local terminal only |
| SSH private key or password | your local terminal only |

**Never share the following with anyone, including AI assistants:**
- SSH private keys
- Server sudo/root passwords
- Any generated pre-shared keys or session secrets
- API tokens from your VPS provider
- `/etc/liberty-exit-node/` configuration files

---

## Step 1 — Provision the Server

Order a VPS with the parameters above.
Log in via SSH from your local terminal:

```bash
ssh <your-user>@<vps-ipv4>
```

Update packages:

```bash
sudo apt update && sudo apt upgrade -y
```

---

## Step 2 — Enable IP Forwarding

```bash
# Immediate (survives until next reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Persistent across reboots
echo "net.ipv4.ip_forward = 1" | sudo tee /etc/sysctl.d/99-liberty-forward.conf
sudo sysctl -p /etc/sysctl.d/99-liberty-forward.conf
```

Verify:

```bash
sysctl net.ipv4.ip_forward
# expected: net.ipv4.ip_forward = 1
```

---

## Step 3 — Configure NAT with nftables

Install nftables if not present:

```bash
sudo apt install -y nftables
sudo systemctl enable --now nftables
```

Create the NAT ruleset. Replace `eth0` with your actual outbound interface name
(check with `ip route | grep default`):

```bash
sudo tee /etc/nftables.conf > /dev/null <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    chain input {
        type filter hook input priority 0; policy drop;
        ct state established,related accept
        iif lo accept
        ip protocol icmp accept
        tcp dport 22 accept          # SSH — required for management
        udp dport 51820 accept       # Liberty exit node tunnel port
        # Health endpoint (local only — do not open 8081 publicly)
        drop
    }
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        # Accept forwarded packets from tunnel clients
        iif lo accept
        accept
    }
    chain output {
        type filter hook output priority 0; policy accept;
    }
}

table ip nat {
    chain postrouting {
        type nat hook postrouting priority 100;
        oif "eth0" masquerade        # replace eth0 with your outbound interface
    }
}
EOF

sudo nft -f /etc/nftables.conf
```

Verify the ruleset loaded without errors:

```bash
sudo nft list ruleset
```

---

## Step 4 — Create a Service User

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin liberty-exit
```

---

## Step 5 — Install the Liberty Exit Node Binary

Build on the VPS or cross-compile from your development machine:

```bash
# On VPS — install Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

# Clone the repository (or copy the binary via scp)
git clone <your-repo-url> liberty-shield
cd liberty-shield/server/exit-node
cargo build --release
sudo cp target/release/liberty-exit-node /usr/local/bin/
sudo chmod 755 /usr/local/bin/liberty-exit-node
```

---

## Step 6 — Configure the Exit Node

Create the configuration directory (root-only):

```bash
sudo mkdir -p /etc/liberty-exit-node
sudo chmod 700 /etc/liberty-exit-node
```

Create the environment file (do NOT commit this to git):

```bash
sudo tee /etc/liberty-exit-node/env > /dev/null <<'EOF'
LIBERTY_EXIT_BIND=0.0.0.0:51820
LIBERTY_EXIT_HEALTH_BIND=127.0.0.1:8081
LIBERTY_LOG_LEVEL=info
# LIBERTY_PSK=<32-byte hex key — provision separately, never hardcode>
EOF

sudo chmod 600 /etc/liberty-exit-node/env
sudo chown root:root /etc/liberty-exit-node/env
```

The pre-shared key (`LIBERTY_PSK`) must be generated out-of-band and provisioned
separately. It must never appear in source code, git history, or chat logs.

---

## Step 7 — Create a systemd Service

```bash
sudo tee /etc/systemd/system/liberty-exit-node.service > /dev/null <<'EOF'
[Unit]
Description=Liberty Shield Exit Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=liberty-exit
EnvironmentFile=/etc/liberty-exit-node/env
ExecStart=/usr/local/bin/liberty-exit-node
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable liberty-exit-node
sudo systemctl start liberty-exit-node
sudo systemctl status liberty-exit-node
```

---

## Step 8 — Verify the Service is Running

```bash
# Check service status
sudo systemctl status liberty-exit-node

# Tail logs
sudo journalctl -u liberty-exit-node -f

# Verify UDP port is listening
sudo ss -ulnp | grep 51820

# Check health endpoint (local only)
curl http://127.0.0.1:8081/health
```

Expected log output on startup:

```
INFO liberty_exit_node: Liberty Exit Node starting bind=0.0.0.0:51820
INFO liberty_exit_node: health endpoint starting bind=127.0.0.1:8081
INFO liberty_exit_node: packet receive loop running
```

---

## Step 9 — Configure Android Debug Build

In your Android debug `build.gradle` or `local.properties` (git-ignored):

```
DEBUG_EXIT_NODE_HOST=<your-vps-ipv4>
DEBUG_EXIT_NODE_PORT=51820
```

These values are injected via `BuildConfig` in debug builds only. They must not
appear in release APKs.

---

## Step 10 — End-to-End Verification

1. Start the VPN on the phone (dashboard → Start VPN).
2. Navigate to any "what is my IP" page in a browser.
3. The displayed IP should be the VPS IPv4, not the phone's mobile/Wi-Fi IP.
4. Check the dashboard for `tunnelConnected = true` and `exitPublicIp` matching VPS IP.

---

## Security Checklist Before Any Real Use

- [ ] SSH password login disabled; key-only auth enforced
- [ ] Firewall blocks all ports except 22 (SSH) and 51820 (tunnel)
- [ ] Health endpoint (`8081`) is NOT exposed publicly
- [ ] `LIBERTY_PSK` was generated with a cryptographically secure RNG (not typed manually)
- [ ] PSK is not in any git commit, log file, or chat history
- [ ] VPS logs do not contain payload content
- [ ] VPN status is clearly visible to user at all times
- [ ] Noise XX handshake is planned for v0.6 before production use

---

## Known Limitations (MVP)

- Pre-shared key only; no Noise handshake yet (planned v0.6).
- No multi-hop; single VPS exit only.
- No route rotation or cover traffic.
- No device provisioning system yet; PSK must be manually configured.
- This is an engineering MVP. Do not use for sensitive activity.

---

## v0.5.2 — Live Handshake Test

> **Goal:** Verify that a Hello frame from a local PC reaches the VPS and is logged.
> No real traffic is routed. No Android client involved.

### On the VPS — start the server

Install Rust (if not already present):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

Pull or copy the repository, then run:

```bash
cd liberty-shield
LIBERTY_EXIT_BIND=0.0.0.0:51820 \
LIBERTY_EXIT_HEALTH_BIND=127.0.0.1:8081 \
LIBERTY_LOG_LEVEL=info \
cargo run -p liberty-exit-node
```

Expected output:

```
INFO liberty_exit_node: Liberty Exit Node starting bind=0.0.0.0:51820
INFO liberty_exit_node: health endpoint starting bind=127.0.0.1:8081
INFO liberty_exit_node: LIBERTY_PSK not set — running without authentication (skeleton mode only)
INFO liberty_exit_node: packet receive loop running
```

### On local PC — verify health via SSH tunnel

Open an SSH tunnel to the health endpoint (keep open in a separate terminal):

```bash
ssh -L 8081:127.0.0.1:8081 <your-user>@<VPS_IP>
```

In another terminal:

```bash
curl http://127.0.0.1:8081/health
```

Expected:

```json
{"status":"ok","packets_rx":0,"packets_tx":0,"bytes_rx":0,"bytes_tx":0,"active_sessions":0,"parse_errors":0,"auth_failures":0}
```

### On local PC — send UDP Hello frame

```bash
LIBERTY_HELLO_TARGET=<VPS_IP>:51820 cargo run -p liberty-exit-node --bin send_hello
```

Expected client output:

```
target:     <VPS_IP>:51820
frame_len:  27
session_id: 1
sequence:   1
msg_type:   Hello
sent OK
```

Expected server log (VPS terminal):

```
INFO liberty_exit_node: Hello frame received session=1
```

After sending, re-check health:

```bash
curl http://127.0.0.1:8081/health
```

`packets_rx` must be ≥ 1. `parse_errors` must be 0.

### Important

- Do NOT expose the health endpoint publicly. It must stay bound to `127.0.0.1:8081`.
- Do NOT paste your VPS IP, SSH key, PSK, or credentials into chat or source code.
- Frame is unencrypted at v0.5.2; do not send sensitive payloads.
