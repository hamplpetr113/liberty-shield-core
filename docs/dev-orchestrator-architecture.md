# Liberty Dev Orchestrator v0.1 — Architecture

**Status:** Design (pre-implementation)
**Date:** 2026-04-26
**Scope:** Local autonomous development loop with multi-provider fallback

---

## 1. Purpose

Liberty Dev Orchestrator is a local process that reads a task queue from
`task.yaml`, delegates implementation work to an available AI provider
(Claude Code CLI, Gemini CLI, OpenAI API, or a local model), runs the project's
own test suite, and only commits when every gate passes. It survives provider
rate limits by switching to an alternative provider or pausing with full state
saved. It survives test failures by entering a repair loop that sends the
failure output back to a provider as a targeted fix prompt.

The orchestrator never implements code itself. It routes work, enforces rules,
and records everything.

---

## 2. System Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Developer workstation                                                       │
│                                                                              │
│   task.yaml ──► TaskQueue ──► OrchestratorLoop                              │
│                                      │                                       │
│                           ┌──────────┼──────────────────┐                   │
│                           │          │                   │                   │
│                    ProviderRouter  CheckpointSystem  ExecutionLog            │
│                           │                                                  │
│              ┌────────────┼────────────────────────┐                        │
│              │            │            │            │                        │
│         Claude Code   Gemini CLI   OpenAI API   Local Model                 │
│         (CLI)         (CLI)        (HTTP)        (CLI/HTTP)                  │
│              └────────────┼────────────────────────┘                        │
│                           │                                                  │
│                        TestGate                                              │
│                       ┌───┴────┐                                             │
│                     PASS     FAIL                                            │
│                       │        │                                             │
│                  GitCommit  RepairLoop                                       │
│                                │                                             │
│                          (max attempts)                                      │
│                                │                                             │
│                    rollback ◄──┴──► FAILED                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Components

### 3.1 TaskQueue

Reads `task.yaml` on startup. Maintains an ordered list of pending tasks.
Pops one task at a time. A task is not removed from the queue until it reaches
a terminal state (COMMITTED or FAILED). Paused tasks remain at the head.

**Persistence:** The queue's current position is written to
`orchestrator/.state/queue.json` after every state change so a restart resumes
at the correct task.

### 3.2 OrchestratorLoop

The main control loop. Each iteration:

1. Pop the next task from TaskQueue.
2. Load or create a Checkpoint for this task.
3. Call ProviderRouter to get an available provider.
4. Save Checkpoint (state = EXECUTING).
5. Invoke the provider with the task prompt.
6. Save Checkpoint (state = TESTING).
7. Run TestGate.
8. On PASS → GitCommit → mark task COMMITTED → next iteration.
9. On FAIL → RepairLoop → back to step 3 with repair prompt.
10. On rate limit at step 5 → switch provider → back to step 3.
11. On all providers exhausted → save Checkpoint (state = PAUSED) → halt.

### 3.3 ProviderRouter

Maintains a registry of configured providers and their current availability
state. Selects the highest-priority provider not in cooldown. Returns a
`ProviderHandle` that abstracts CLI invocation vs. HTTP call.

Detailed specification: `orchestrator/provider_router.md`.

### 3.4 CheckpointSystem

Writes a snapshot of the orchestrator's full execution state to disk before
every provider call and before every test run. A checkpoint includes the task
definition, attempt counters, provider states, the git commit hash at task
start, and the last test result.

On restart, the CheckpointSystem finds the most recent checkpoint for any
paused task and hands it to the OrchestratorLoop, which resumes from that
state without re-running completed work.

### 3.5 TestGate

A pipeline of independent checks that all must pass before a commit is
permitted. Checks are run in dependency order (scope → build → tests → lint)
but failures in earlier steps do not suppress later steps unless a later step
is logically impossible (cannot run tests if build fails). All failures are
collected into a single `TestReport` so the repair prompt has complete
information.

Detailed specification: `orchestrator/test_gate.md`.

### 3.6 GitCommit Gate

The final gatekeeper. Only reached when TestGate returns PASS. Performs a
final verification that only allowed files were modified, then stages those
files and commits with the task's configured message. The commit hash is
recorded in the checkpoint and execution log.

Hard rule: never called unless TestGate passed in the same attempt.

### 3.7 RepairLoop

When TestGate returns FAIL, RepairLoop constructs a repair prompt from the
`TestReport` and the current diff. It submits the repair prompt to the
ProviderRouter (which may choose a different provider than the one that wrote
the failing code). After the provider responds, control returns to TestGate.

RepairLoop tracks a `repair_attempt` counter per task attempt. When
`repair_attempt` reaches `task.max_repair_attempts`, the task is marked FAILED
and the git working tree is reset to the pre-task commit hash.

### 3.8 ExecutionLog

Append-only JSONL file at `orchestrator/logs/run-<timestamp>.jsonl`. One event
per line. Every state transition, provider call, test result, repair attempt,
and commit is recorded. The log is the audit trail; it is never modified after
being written.

---

## 4. Data Flow

### 4.1 Happy Path (task succeeds first attempt)

```
task.yaml
  │
  ▼
TaskQueue.pop()
  │
  ▼
Checkpoint.save(state=EXECUTING, attempt=1)
  │
  ▼
ProviderRouter.select() → claude-code
  │
  ▼
ProviderHandle.invoke(task_prompt, context)
  │  [provider writes files]
  ▼
Checkpoint.save(state=TESTING)
  │
  ▼
TestGate.run()  → PASS
  │
  ▼
GitCommit.commit("Sprint 6 Phase 2: …")
  │
  ▼
Checkpoint.save(state=COMMITTED)
  │
  ▼
ExecutionLog: TASK_COMMITTED
  │
  ▼
TaskQueue.next()
```

### 4.2 Rate-Limit Path

```
ProviderHandle.invoke()  → RATE_LIMITED
  │
  ▼
Checkpoint.save(provider_state[claude-code]=COOLDOWN)
  │
  ▼
ProviderRouter.select()  → gemini-cli  (next priority)
  │
  ▼
Checkpoint.save(state=EXECUTING, provider=gemini-cli)
  │
  ▼
ProviderHandle.invoke(gemini-cli, same_prompt)
  │
  ▼
… continues on happy path …
```

If ProviderRouter.select() returns NO_PROVIDER_AVAILABLE:

```
Checkpoint.save(state=PAUSED, pause_reason=ALL_PROVIDERS_RATE_LIMITED)
  │
  ▼
ExecutionLog: ORCHESTRATOR_PAUSED
  │
  ▼
[halt — operator resumes manually or after TTL]
```

### 4.3 Repair Path

```
TestGate.run()  → FAIL
  │
  ▼
RepairLoop.build_prompt(TestReport, diff)
  │
  ▼
Checkpoint.save(state=REPAIRING, repair_attempt=1)
  │
  ▼
ProviderRouter.select()  → gemini-cli (may differ from original)
  │
  ▼
ProviderHandle.invoke(repair_prompt)
  │
  ▼
Checkpoint.save(state=TESTING)
  │
  ▼
TestGate.run()  → PASS  →  GitCommit
               → FAIL   →  repair_attempt++ → loop
               → repair_attempt == max_repair_attempts
                         │
                         ▼
                  git reset --hard <pre-task-hash>
                  Checkpoint.save(state=FAILED)
                  ExecutionLog: TASK_FAILED
                  TaskQueue.next()
```

---

## 5. File Layout

```
liberty-shield/
├── task.yaml                          ← task queue input
├── orchestrator/
│   ├── task_schema.yaml               ← schema + annotated example
│   ├── state_machine.md               ← full state transition table
│   ├── provider_router.md             ← provider selection algorithm
│   ├── test_gate.md                   ← gate pipeline specification
│   ├── providers.yaml                 ← provider registry (runtime config)
│   ├── .state/
│   │   ├── queue.json                 ← queue position persistence
│   │   └── ckpt-<timestamp>.json      ← checkpoint files
│   └── logs/
│       └── run-<timestamp>.jsonl      ← execution logs
└── docs/
    └── dev-orchestrator-architecture.md   ← this file
```

---

## 6. Execution Log Format

Append-only JSONL. Each line is a self-contained JSON object.

```jsonl
{"ts":"2026-04-26T14:00:00Z","level":"INFO","event":"ORCHESTRATOR_START","version":"0.1"}
{"ts":"2026-04-26T14:00:01Z","level":"INFO","event":"TASK_START","task_id":"task-001","attempt":1}
{"ts":"2026-04-26T14:00:01Z","level":"INFO","event":"CHECKPOINT_SAVED","checkpoint_id":"ckpt-20260426-140001","state":"EXECUTING"}
{"ts":"2026-04-26T14:00:01Z","level":"INFO","event":"PROVIDER_CALL","provider":"claude-code","attempt":1}
{"ts":"2026-04-26T14:02:15Z","level":"INFO","event":"PROVIDER_DONE","provider":"claude-code","duration_s":134}
{"ts":"2026-04-26T14:02:15Z","level":"INFO","event":"CHECKPOINT_SAVED","checkpoint_id":"ckpt-20260426-140215","state":"TESTING"}
{"ts":"2026-04-26T14:02:20Z","level":"INFO","event":"TEST_GATE","passed":true,"checks":["file_scope","build","tests","lint"]}
{"ts":"2026-04-26T14:02:21Z","level":"INFO","event":"COMMIT","hash":"a1b2c3d","message":"Sprint 6 Phase 2: implement PathFragmenter"}
{"ts":"2026-04-26T14:02:21Z","level":"INFO","event":"TASK_COMMITTED","task_id":"task-001"}
{"ts":"2026-04-26T14:02:15Z","level":"WARN","event":"PROVIDER_RATE_LIMITED","provider":"claude-code","switching_to":"gemini-cli"}
{"ts":"2026-04-26T14:02:15Z","level":"WARN","event":"TEST_GATE_FAIL","failed_checks":["build","tests"],"repair_attempt":1}
{"ts":"2026-04-26T14:02:15Z","level":"ERROR","event":"TASK_FAILED","task_id":"task-001","reason":"max_repair_attempts_exceeded"}
{"ts":"2026-04-26T14:02:16Z","level":"INFO","event":"ROLLBACK","to_commit":"e8bbe22"}
```

---

## 7. Checkpoint Format

Saved to `orchestrator/.state/ckpt-<iso8601-compact>.json`.

```json
{
  "checkpoint_id": "ckpt-20260426-140001",
  "task_id": "task-001",
  "state": "EXECUTING",
  "attempt": 1,
  "repair_attempt": 0,
  "provider_id": "claude-code",
  "timestamp": "2026-04-26T14:00:01Z",
  "git_state": {
    "pre_task_commit": "e8bbe22",
    "branch": "main"
  },
  "allowed_files_snapshot": {
    "crates/liberty-controlled-chaos/src/path_fragmenter.rs": null
  },
  "last_test_report": null,
  "provider_states": {
    "claude-code":  { "status": "ACTIVE" },
    "gemini-cli":   { "status": "AVAILABLE" },
    "openai-api":   { "status": "RATE_LIMITED", "cooldown_until": "2026-04-26T14:05:00Z" },
    "local-model":  { "status": "AVAILABLE" }
  }
}
```

States: `ACTIVE` (currently in use), `AVAILABLE`, `RATE_LIMITED`, `DISABLED`.
`cooldown_until` present only in `RATE_LIMITED` state.

---

## 8. Repair Prompt Template

```
REPAIR TASK
===========
Original task: {task.description}
Repair attempt: {repair_attempt} / {task.max_repair_attempts}

ALLOWED FILES (you may only edit these):
{task.allowed_files — one per line}

FORBIDDEN FILES (never modify):
{task.forbidden_files — one per line}

CURRENT DIFF (changes made so far):
{git diff HEAD}

FAILED CHECKS:
{for each failed check:
  CHECK: {check.name}
  EXIT CODE: {check.exit_code}
  OUTPUT:
  {check.output — truncated to 4000 chars if longer}
}

INSTRUCTION:
Fix the above failures.
- Modify only the ALLOWED FILES listed above.
- Never touch the FORBIDDEN FILES.
- After your changes, every command in the list below must succeed:
{task.required_commands — one per line}
- Do not remove or regress any previously passing tests.
```

---

## 9. Hard Rules (enforced, not advisory)

| Rule | Enforcement point |
|------|------------------|
| No commit unless all TestGate checks pass | GitCommit gate refuses if `TestReport.gate_passed == false` |
| No edits outside `allowed_files` | TestGate file-scope check; also asserted before prompt construction |
| Never modify `forbidden_files` | TestGate forbidden-file check; repair prompt reinforces this |
| Save checkpoint before every provider call | OrchestratorLoop saves before invoking ProviderHandle |
| Switch provider or pause on rate limit | ProviderRouter returns NO_PROVIDER_AVAILABLE; OrchestratorLoop pauses |
| Never modify security-critical frozen modules unless explicitly listed in `allowed_files` | Same as above — frozen module paths are listed in `forbidden_files` per task |
| Rollback on max repair attempts | RepairLoop resets working tree to `pre_task_commit` before marking FAILED |

---

## 10. Out of Scope for v0.1

- Parallel task execution (one task at a time).
- Remote provider APIs beyond OpenAI format.
- Web UI or dashboard.
- Auto-scaling or cloud deployment.
- Automatic task generation from GitHub issues.
- Cost tracking per provider call.
- Provider credential management (assumes credentials pre-configured in environment).
