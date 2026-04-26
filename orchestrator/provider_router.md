# Liberty Dev Orchestrator — Provider Router

**Version:** 0.1

---

## 1. Responsibilities

The ProviderRouter maintains a registry of AI providers, tracks their
availability state, selects the best available provider for each call, and
abstracts the invocation mechanism so the OrchestratorLoop does not need to
know whether it is calling a CLI tool or an HTTP API.

---

## 2. Provider Registry

Configured in `orchestrator/providers.yaml` (runtime config, not checked in
with secrets).

```yaml
# orchestrator/providers.yaml
# ─────────────────────────────────────────────────────────────────────────────
# priority: lower number = tried first
# type: cli | http | local
# For cli: command is the executable + any fixed flags.
# For http: endpoint + model + auth_env (env var name holding the API key).
# rate_limit_cooldown_seconds: how long to wait after a rate-limit response
#   before retrying this provider.
# timeout_cooldown_seconds: how long to wait after a timeout before retrying.
# enabled: set to false to disable without removing the entry.

providers:

  - id: "claude-code"
    type: cli
    command: "claude"
    priority: 1
    rate_limit_cooldown_seconds: 300
    timeout_cooldown_seconds: 30
    enabled: true

  - id: "gemini-cli"
    type: cli
    command: "gemini"
    priority: 2
    rate_limit_cooldown_seconds: 300
    timeout_cooldown_seconds: 30
    enabled: true

  - id: "openai-api"
    type: http
    endpoint: "https://api.openai.com/v1/chat/completions"
    model: "gpt-4o"
    auth_env: "OPENAI_API_KEY"
    priority: 3
    rate_limit_cooldown_seconds: 60
    timeout_cooldown_seconds: 30
    enabled: true

  - id: "local-model"
    type: local
    command: "ollama run codellama"
    priority: 4
    rate_limit_cooldown_seconds: 0
    timeout_cooldown_seconds: 0
    enabled: false    # disabled until local model quality is verified
```

---

## 3. Provider State

Each provider has a runtime state that the router maintains in memory and
persists to the checkpoint.

| State | Meaning |
|-------|---------|
| `AVAILABLE` | Can receive calls immediately. |
| `ACTIVE` | Currently handling a call (prevents double-dispatch). |
| `COOLDOWN` | Hit a rate limit or timeout; cannot be called until `cooldown_until`. |
| `DISABLED` | Configured as `enabled: false`; never selected. |
| `UNKNOWN` | Not yet contacted this session; treated as AVAILABLE. |

State transitions:

```
AVAILABLE / UNKNOWN
    │
    ├── selected for call ──────────────────► ACTIVE
    │
ACTIVE
    ├── call succeeds ───────────────────────► AVAILABLE
    ├── rate limit response ─────────────────► COOLDOWN (cooldown_until = now + rate_limit_cooldown_s)
    ├── timeout ─────────────────────────────► COOLDOWN (cooldown_until = now + timeout_cooldown_s)
    └── other error ─────────────────────────► AVAILABLE (error logged; provider not penalised)

COOLDOWN
    └── now >= cooldown_until ───────────────► AVAILABLE
```

---

## 4. Selection Algorithm

Called by the OrchestratorLoop before every provider invocation. Returns a
`ProviderHandle` or `NO_PROVIDER_AVAILABLE`.

```
function select(task):

  1. Refresh cooldown states:
       for each provider in registry:
         if provider.state == COOLDOWN and now >= provider.cooldown_until:
           provider.state = AVAILABLE

  2. Build candidate list:
       candidates = [p for p in registry
                     if p.enabled
                     and p.state in (AVAILABLE, UNKNOWN)
                     and p.id != ACTIVE]

  3. If candidates is empty:
       return NO_PROVIDER_AVAILABLE

  4. If task.preferred_provider is set and preferred is in candidates:
       move preferred to front of candidates list

  5. Sort remaining candidates by priority ascending (lower number = higher priority).
     Ties broken by provider id lexicographically (deterministic).

  6. Return ProviderHandle for candidates[0].
```

The task's `preferred_provider` only affects the first call. After a
provider switch (due to rate limit), the standard priority order applies.

---

## 5. ProviderHandle Interface

The ProviderHandle abstracts the invocation mechanism. The OrchestratorLoop
calls a single method regardless of provider type.

```
ProviderHandle.invoke(prompt: string, context: InvokeContext) -> InvokeResult
```

**InvokeContext:**
```
repo_path:          string     absolute path to repository root
allowed_files:      []string   files the provider may modify
forbidden_files:    []string   files the provider must not touch
task_id:            string     for logging
attempt:            int        for logging
repair_attempt:     int        0 = original call, >0 = repair
```

**InvokeResult:**
```
type: SUCCESS | RATE_LIMITED | TIMEOUT | ERROR

# on SUCCESS:
files_changed:      []string   relative paths modified by the provider
explanation:        string     provider's summary (used in commit message annotation)

# on RATE_LIMITED:
retry_after_seconds: int | null   from Retry-After header or provider response body

# on ERROR:
error_message:      string
```

---

## 6. Per-Provider Invocation Detail

### 6.1 Claude Code (CLI)

```
claude \
  --print \
  --no-interactive \
  --allowedTools Edit,Write,Read,Bash \
  --output-format json \
  --timeout <task.timeout_seconds> \
  "<prompt>"
```

- `--no-interactive`: prevents the CLI from blocking on user input.
- `--print`: non-interactive single-pass mode.
- `--allowedTools Edit,Write,Read,Bash`: restricts to file-editing tools only.
- stdout is JSON; stderr is discarded unless exit code != 0.

Rate limit detection: exit code 1 with stderr containing "rate limit" or
"429". `retry_after_seconds` parsed from stderr if present.

### 6.2 Gemini CLI

```
gemini \
  --no-interactive \
  --format json \
  "<prompt>"
```

Rate limit detection: exit code != 0 with stderr containing "RESOURCE_EXHAUSTED"
or "429".

### 6.3 OpenAI API (HTTP)

```
POST https://api.openai.com/v1/chat/completions
Authorization: Bearer $OPENAI_API_KEY
Content-Type: application/json

{
  "model": "gpt-4o",
  "messages": [
    {"role": "system", "content": "<system_prompt>"},
    {"role": "user", "content": "<task_prompt>"}
  ],
  "max_tokens": 8192
}
```

The orchestrator sends the prompt and parses the assistant's response for
file-edit instructions using a structured output format (defined separately;
out of scope for v0.1).

Rate limit detection: HTTP 429 response. `retry_after_seconds` from
`Retry-After` response header.

**Note:** OpenAI API does not natively execute code or write files. The
orchestrator must parse the model's response and apply edits itself. A
structured output schema is needed (v0.2 scope). In v0.1, GPT/OpenAI is a
placeholder provider marked lower priority than CLI providers.

### 6.4 Local Model (CLI placeholder)

```
ollama run codellama "<prompt>"
```

Treated as always-available (no rate limits). Used as last-resort fallback.
Quality is not guaranteed. Disabled by default in `providers.yaml`.

---

## 7. Prompt Construction

The ProviderRouter constructs the full prompt before calling the handle.
Prompt sections (in order):

```
[1] SYSTEM PREAMBLE
    You are a software engineer working on the Liberty Shield project.
    Repository: {repo_path}
    Task type: {task.type}

[2] REFERENCE DOCUMENTS
    {for each doc in task.context.reference_docs:
       === {doc_path} ===
       {doc_contents}
    }

[3] BACKGROUND
    {task.context.background}

[4] TASK DESCRIPTION
    {task.description}

[5] FILE CONSTRAINTS
    You may ONLY modify these files:
    {task.allowed_files}

    You must NEVER modify these files:
    {task.forbidden_files}

[6] REQUIRED OUTCOME
    All of the following commands must succeed after your changes:
    {task.required_commands}

[7] REPAIR CONTEXT (only present when repair_attempt > 0)
    === REPAIR ATTEMPT {repair_attempt} / {max_repair_attempts} ===
    The previous attempt produced these failures:
    {TestReport.failed_checks — see repair_prompt template in architecture doc}

[8] CURRENT FILE STATE (always present)
    === CURRENT DIFF (changes so far vs git HEAD) ===
    {git diff HEAD -- {allowed_files}}
```

Section [7] is omitted on the first call (repair_attempt == 0).
Section [8] shows an empty diff on the first call, which is informative
(provider knows no changes have been made yet).

---

## 8. Rate Limit Fallback Sequence Example

```
Attempt 1:
  select() → claude-code (priority 1, AVAILABLE)
  invoke()  → RATE_LIMITED (retry_after=300s)
  claude-code.state = COOLDOWN, cooldown_until = now+300s

Fallback:
  select() → gemini-cli (priority 2, AVAILABLE)
  invoke()  → RATE_LIMITED (retry_after=300s)
  gemini-cli.state = COOLDOWN, cooldown_until = now+300s

Fallback:
  select() → openai-api (priority 3, AVAILABLE)
  invoke()  → SUCCESS

Attempt 2 (if needed):
  select() → openai-api (claude-code, gemini-cli still cooling down)
```

If all enabled providers are COOLDOWN simultaneously, `select()` returns
`NO_PROVIDER_AVAILABLE` and the orchestrator transitions to PAUSED.

---

## 9. Provider Switch Transparency

When the router switches providers mid-task, the new provider receives the
FULL prompt including the current diff (section [8]). It does not assume
any prior work was done. The new provider may re-implement, extend, or fix
whatever the previous provider wrote. This is intentional: partial work
is better than no work, and the test gate is the arbiter of quality.

The execution log records which provider handled each call:

```jsonl
{"event":"PROVIDER_CALL","provider":"claude-code","attempt":1,"repair_attempt":0}
{"event":"PROVIDER_RATE_LIMITED","provider":"claude-code","switching_to":"gemini-cli"}
{"event":"PROVIDER_CALL","provider":"gemini-cli","attempt":1,"repair_attempt":0}
```
