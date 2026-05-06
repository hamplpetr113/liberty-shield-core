# local-smoke-test.ps1 — Liberty Exit Node local smoke test
# Runs cargo test, verifies both binaries build, and prints manual live-test instructions.
# No secrets required. Does not start or stop any server.

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Host "`n=== liberty-exit-node: cargo test ===" -ForegroundColor Cyan
cargo test -p liberty-exit-node
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: cargo test failed" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== liberty-exit-node: cargo check --bins ===" -ForegroundColor Cyan
cargo check -p liberty-exit-node --bins
if ($LASTEXITCODE -ne 0) {
    Write-Host "FAIL: cargo check --bins failed" -ForegroundColor Red
    exit 1
}

Write-Host "`n=== All checks passed ===" -ForegroundColor Green

Write-Host @"

--- Manual live test (two terminals required) ---

Terminal A — start local server:
  `$env:LIBERTY_EXIT_BIND = "127.0.0.1:51820"
  `$env:LIBERTY_EXIT_HEALTH_BIND = "127.0.0.1:8081"
  `$env:LIBERTY_LOG_LEVEL = "info"
  cargo run -p liberty-exit-node

Terminal B — send Hello frame:
  `$env:LIBERTY_HELLO_TARGET = "127.0.0.1:51820"
  cargo run -p liberty-exit-node --bin send_hello

Expected server log (Terminal A):
  INFO liberty_exit_node: Hello frame received session=1

Expected health response:
  curl http://127.0.0.1:8081/health
  {"status":"ok","packets_rx":1,...}

--- VPS live test ---

Set LIBERTY_HELLO_TARGET to your VPS public IP:
  `$env:LIBERTY_HELLO_TARGET = "VPS_IP:51820"
  cargo run -p liberty-exit-node --bin send_hello

Do NOT paste your VPS IP, SSH key, or PSK into chat.
See docs/deployment/vps-single-exit-node-setup.md for full VPS setup steps.
"@
