# Liberty Dev Orchestrator — State Machine

**Version:** 0.1
**Scope:** Per-task execution lifecycle

---

## 1. States

| State | Label | Description |
|-------|-------|-------------|
| `IDLE` | Idle | No task in flight. Waiting for TaskQueue to yield the next task. |
| `LOADING` | Loading | Task dequeued and being validated (schema, file paths, forbidden-file pre-check). |
| `EXECUTING` | Executing | A provider call is in progress. The provider is writing files. |
| `TESTING` | Testing | TestGate pipeline is running. No provider is active. |
| `REPAIRING` | Repairing | TestGate failed. A repair prompt is being sent to a provider. |
| `COMMITTING` | Committing | TestGate passed. Git commit is being written. |
| `RATE_LIMITED` | Rate limited | The selected provider returned a rate-limit response. Attempting fallback. |
| `PAUSED` | Paused | All providers are in cooldown. Orchestrator halted with state saved. |
| `COMMITTED` | Committed | Task completed and committed. Terminal — task leaves the queue. |
| `FAILED` | Failed | Task exhausted max_attempts or max_repair_attempts. Working tree rolled back. Terminal. |

---

## 2. State Transition Table

Each row: (From, Event, Guard, To, Side Effects)

| # | From | Event | Guard | To | Side Effects |
|---|------|-------|-------|----|--------------|
| T01 | IDLE | task_dequeued | queue not empty | LOADING | log TASK_START |
| T02 | IDLE | queue_empty | — | IDLE | log QUEUE_EMPTY; halt or sleep |
| T03 | LOADING | validation_passed | — | EXECUTING | save checkpoint(EXECUTING); log CHECKPOINT_SAVED |
| T04 | LOADING | validation_failed | — | FAILED | log TASK_FAILED(validation_error); advance queue |
| T05 | EXECUTING | provider_done | — | TESTING | save checkpoint(TESTING); log PROVIDER_DONE |
| T06 | EXECUTING | provider_rate_limited | fallback_available | RATE_LIMITED | log PROVIDER_RATE_LIMITED; record cooldown |
| T07 | EXECUTING | provider_rate_limited | !fallback_available | PAUSED | save checkpoint(PAUSED); log ORCHESTRATOR_PAUSED; halt |
| T08 | EXECUTING | provider_timeout | — | RATE_LIMITED | treat as transient error; provider enters 30 s cooldown |
| T09 | EXECUTING | provider_error | attempt < max_attempts | LOADING | increment attempt; save checkpoint; log PROVIDER_ERROR |
| T10 | EXECUTING | provider_error | attempt == max_attempts | FAILED | rollback; log TASK_FAILED(provider_error) |
| T11 | TESTING | gate_passed | — | COMMITTING | log TEST_GATE(passed) |
| T12 | TESTING | gate_failed | repair_attempt < max_repair_attempts | REPAIRING | increment repair_attempt; save checkpoint(REPAIRING); log TEST_GATE_FAIL |
| T13 | TESTING | gate_failed | repair_attempt == max_repair_attempts AND attempt < max_attempts | LOADING | rollback to pre-attempt state; increment attempt; reset repair_attempt=0 |
| T14 | TESTING | gate_failed | repair_attempt == max_repair_attempts AND attempt == max_attempts | FAILED | rollback to pre-task commit; log TASK_FAILED(max_repair_attempts) |
| T15 | REPAIRING | provider_done | — | TESTING | save checkpoint(TESTING); log REPAIR_PROVIDER_DONE |
| T16 | REPAIRING | provider_rate_limited | fallback_available | RATE_LIMITED | log PROVIDER_RATE_LIMITED |
| T17 | REPAIRING | provider_rate_limited | !fallback_available | PAUSED | save checkpoint(PAUSED); log ORCHESTRATOR_PAUSED; halt |
| T18 | REPAIRING | provider_timeout | — | RATE_LIMITED | same as T08 |
| T19 | COMMITTING | commit_success | — | COMMITTED | record commit_hash in checkpoint; log COMMIT; log TASK_COMMITTED |
| T20 | COMMITTING | commit_failed | — | FAILED | log TASK_FAILED(commit_error); do NOT rollback (tests passed; human intervention needed) |
| T21 | RATE_LIMITED | fallback_selected | provider available | EXECUTING | save checkpoint(EXECUTING, new_provider); log PROVIDER_SWITCH |
| T22 | RATE_LIMITED | no_provider_available | — | PAUSED | save checkpoint(PAUSED); log ORCHESTRATOR_PAUSED; halt |
| T23 | PAUSED | resume_requested | at least one provider available | EXECUTING | reload checkpoint; restore provider states; log ORCHESTRATOR_RESUMED |
| T24 | PAUSED | resume_requested | no provider available | PAUSED | log RESUME_REJECTED(all_providers_cooling_down) |
| T25 | COMMITTED | — | — | IDLE | TaskQueue.advance(); log ready for next task |
| T26 | FAILED | — | — | IDLE | TaskQueue.advance(); output repair_prompt file if last_test_report exists |

---

## 3. State Diagram

```
                    ┌──────────────────────────────────────────┐
                    │  queue_empty / T02 (sleep)               │
                    ▼                                          │
              ┌──────────┐   task_dequeued/T01    ┌──────────┐ │
              │   IDLE   │──────────────────────►│ LOADING  │ │
              │          │◄──────────────────────│          │ │
              └──────────┘  (COMMITTED/T25,      └─────┬────┘ │
                    ▲        FAILED/T26,                │ validation_passed/T03
                    │        via IDLE)                   ▼
                    │                           ┌──────────────┐
                    │                           │  EXECUTING   │◄──────────────────────┐
                    │                           │              │                       │
                    │                           └──┬───────┬───┘                       │
                    │          provider_done/T05  │       │ rate_limit/T06,T08         │
                    │                             │       ▼                            │
                    │                             │  ┌──────────────┐                 │
                    │                             │  │ RATE_LIMITED │                 │
                    │                             │  │              │                 │
                    │                             │  └──┬───────┬───┘                 │
                    │                             │     │       │ fallback/T21        │
                    │                             │     │ no    └──────────────────────┘
                    │                             │     │ provider
                    │                             │     ▼
                    │                             │  ┌──────────┐  resume/T23
                    │                             │  │  PAUSED  │──────────────┐
                    │                             │  │          │              │
                    │                             │  └──────────┘              │
                    │                             │  (halt)                    │
                    │                             ▼                            │
                    │                       ┌──────────┐                      │
                    │                       │ TESTING  │                      │
                    │                       │          │                      │
                    │                       └──┬────┬──┘                      │
                    │          gate_passed/T11 │    │ gate_failed/T12         │
                    │                          │    ▼                         │
                    │                          │  ┌───────────┐               │
                    │                          │  │ REPAIRING │               │
                    │                          │  │           │               │
                    │                          │  └──┬────────┘               │
                    │                          │     │ provider_done/T15 ─────┘
                    │                          │     │ (back to TESTING)
                    │                          ▼
                    │                    ┌───────────┐
                    │                    │COMMITTING │
                    │                    │           │
                    │                    └──┬─────┬──┘
                    │      commit_success/  │     │ commit_failed/T20
                    │      T19             │     ▼
                    │                      │  ┌─────────┐
                    │                      │  │  FAILED │──────────────►─┐
                    │                      ▼  └─────────┘                │
                    │                ┌───────────┐                       │
                    └────────────────│ COMMITTED │◄──────────────────────┘
                                     └───────────┘         (both advance queue)
```

---

## 4. Attempt vs. Repair Attempt Counter Semantics

**`attempt`** counts how many times the task has been submitted to a provider
from scratch (with the original task prompt, not a repair prompt).
Incremented by: T09, T13.
Reset to 0 when: a new task is started.
Ceiling: `task.max_attempts`. At ceiling + failure: T10 or T14 fires → FAILED.

**`repair_attempt`** counts repair iterations within a single `attempt`.
Incremented by: T12.
Reset to 0 when: `attempt` increments (T13).
Ceiling: `task.max_repair_attempts`. At ceiling: T13 or T14 fires.

Example — max_attempts=2, max_repair_attempts=3:

```
attempt=1, repair_attempt=0  → EXECUTING (original prompt)
attempt=1, repair_attempt=1  → REPAIRING (repair 1)
attempt=1, repair_attempt=2  → REPAIRING (repair 2)
attempt=1, repair_attempt=3  → REPAIRING (repair 3 — last)
  → repair_attempt==max AND attempt<max → T13: rollback partial, attempt=2, repair=0
attempt=2, repair_attempt=0  → EXECUTING (fresh start, attempt 2)
attempt=2, repair_attempt=1  → REPAIRING
attempt=2, repair_attempt=2  → REPAIRING
attempt=2, repair_attempt=3  → REPAIRING (last)
  → repair_attempt==max AND attempt==max → T14: rollback to pre-task commit → FAILED
```

---

## 5. Rollback Semantics

**Partial rollback (T13):** Resets the working tree to the state at the START
of the current `attempt` (i.e., the git stash or working-tree snapshot saved
at the first EXECUTING checkpoint of that attempt). Design docs are not
reverted. Only modified source files within `allowed_files` are affected.

**Full rollback (T14, T10):** Resets the working tree to `pre_task_commit` —
the commit hash recorded when the task first entered LOADING. This undoes all
changes made during any attempt of this task.

Both rollbacks are implemented as `git checkout HEAD -- <allowed_files>` (for
files that existed at HEAD) and `git rm <allowed_files>` (for new files not
present at HEAD). They do not touch files outside `allowed_files`.

---

## 6. Checkpoint Timing

A checkpoint is written at each state transition that involves external I/O or
an irreversible action. Minimum checkpoint points:

| Transition | Checkpoint written |
|------------|-------------------|
| LOADING → EXECUTING | state=EXECUTING, attempt=N, provider=X |
| EXECUTING → TESTING | state=TESTING |
| TESTING → REPAIRING | state=REPAIRING, repair_attempt=N, test_report=... |
| REPAIRING → TESTING | state=TESTING |
| TESTING → COMMITTING | state=COMMITTING |
| COMMITTING → COMMITTED | state=COMMITTED, commit_hash=... |
| Any → PAUSED | state=PAUSED, pause_reason=... |
| Any → FAILED | state=FAILED, failure_reason=... |

The checkpoint for PAUSED must be complete enough that the orchestrator can
resume in EXECUTING state with the correct provider and attempt counters.

---

## 7. Pause and Resume Protocol

**Pause (T07, T17, T22):**
1. Write checkpoint with `state=PAUSED`.
2. Write human-readable status to stdout:
   ```
   ORCHESTRATOR PAUSED
   Task: task-001 (attempt 1, repair 0)
   Reason: all providers in cooldown
   Providers cooling down:
     claude-code  → available at 14:35:00
     openai-api   → available at 14:40:00
     gemini-cli   → available at 14:38:00
   Resume with: orchestrator resume
   ```
3. Exit process (or sleep if running as daemon).

**Resume (T23):**
1. Load most recent checkpoint with `state=PAUSED`.
2. Refresh provider cooldown clocks (compare saved `cooldown_until` to now).
3. If at least one provider is available: transition to EXECUTING.
4. If no provider available: print updated wait times; remain PAUSED.
