# Liberty Shield — AI Agent Control Layer

This folder defines the agent-safe development control layer for Liberty Shield and Liberty Apps.

## Purpose

AI agents (Claude Code, Cursor, ChatGPT, future orchestrators) may propose, draft, and test
changes to this repository. They may not merge to protected branches, self-approve pull
requests, push secrets, or modify production infrastructure without explicit human command.

Human approval is mandatory at every gate before code reaches `main` or the VPS.

## What Agents May NOT Do

- Merge to main or any protected branch
- Self-approve pull requests
- Push secrets or credentials
- Deploy to the VPS without explicit human command
- Bypass CI, tests, or review gates

## Index

| File | Purpose |
|---|---|
| `agent-operating-model.md` | Roles, allowed flow, forbidden flow |
| `agent-security-policy.md` | Secrets, PSK, credential, and deployment policy |
| `agent-mission-lifecycle.md` | Mission states and gate requirements |
| `first-safe-missions.md` | Initial missions safe for agent execution |
| `github-protection-requirements.md` | Required GitHub settings before autonomous ops |
