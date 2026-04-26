# Liberty Dev Orchestrator — Test Gate

**Version:** 0.1

---

## 1. Purpose

The TestGate is the quality enforcer between a provider's output and a git
commit. It runs a deterministic pipeline of checks. All checks are independent
where possible. A commit is forbidden unless every check passes.

The TestGate also produces the `TestReport` that the RepairLoop injects into
the repair prompt, so it must capture complete, actionable failure output —
not just pass/fail.

---

## 2. Pipeline Overview

```
Provider finishes writing files
           │
           ▼
 ┌─────────────────────┐
 │  Check 1            │  File Scope
 │  (always runs)      │  Were any files outside allowed_files modified?
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │  Check 2            │  Forbidden File Guard
 │  (always runs)      │  Were any forbidden_files touched?
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │  Check 3            │  Build
 │  (always runs)      │  Does cargo build / gradle / etc. succeed?
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │  Check 4            │  Tests
 │  (skip if build     │  Do all test commands succeed?
 │   failed AND        │
 │   skip_on_prior     │
 │   _failure=true)    │
 └──────────┬──────────┘
            │
            ▼
 ┌─────────────────────┐
 │  Check 5            │  Lint
 │  (configurable      │  Does clippy / linter succeed?
 │   skip_on_prior)    │
 └──────────┬──────────┘
            │
            ▼
    Aggregate TestReport
           │
    ┌──────┴──────┐
   PASS         FAIL
    │             │
 GitCommit    RepairLoop
```

---

## 3. Checks

### Check 1 — File Scope

**Always runs. Cannot be configured to skip.**

Compares the current `git diff --name-only HEAD` against `task.allowed_files`.
Any file that appears in the diff but is NOT in `allowed_files` is a violation.

```
allowed_files = set(task.allowed_files)
changed_files = set(git_diff_name_only())
violations = changed_files - allowed_files

if violations is not empty:
  FAIL with:
    check_name: "file_scope"
    violations: list of out-of-scope file paths
    message: "Provider modified files outside allowed_files"
```

If this check FAILS, the other checks still run (to provide a complete report)
but the gate cannot pass regardless of other results.

**Why not short-circuit?** Subsequent check output (build errors, lint
warnings) may reveal WHY the provider edited extra files, which makes the
repair prompt more useful.

### Check 2 — Forbidden File Guard

**Always runs. Cannot be configured to skip.**

Compares `git diff --name-only HEAD` against `task.forbidden_files`.

```
forbidden = set(task.forbidden_files)
changed_files = set(git_diff_name_only())
violations = changed_files ∩ forbidden

if violations is not empty:
  FAIL with:
    check_name: "forbidden_file"
    violations: list of forbidden files that were modified
    message: "Provider modified forbidden files"
```

This check failing is an immediate and serious violation. The repair prompt
must explicitly re-state that these files must not be touched and must instruct
the provider to revert the changes.

If a forbidden file was modified, the gate also schedules a targeted revert:
`git checkout HEAD -- <forbidden_file>` is run BEFORE the repair prompt is
sent, so the forbidden file is restored before the next provider call sees
it. The repair prompt notes that this revert occurred.

### Check 3 — Build

**Always runs. Other checks may skip on this failure.**

Runs the first `required_command` that has `skip_on_prior_failure: false`
(if any) or the first command in the list. In practice the build command is
always first.

More precisely: all commands with `skip_on_prior_failure: false` run
regardless. Commands with `skip_on_prior_failure: true` are skipped if any
earlier command failed.

```
for cmd in task.required_commands:
  if cmd.skip_on_prior_failure and any_prior_failure:
    result = SKIPPED
  else:
    result = run(cmd, timeout=cmd.timeout_seconds)

  append result to check_results
  if result.exit_code != 0:
    any_prior_failure = true
```

The "Build" check in the TestReport is the aggregated result of all
`required_commands`. Individual command results are stored in the report for
granularity.

### Check 4 — Tests

Not a separate executable check; it is the subset of `required_commands` that
are test commands (identified by convention or by a `is_test: true` flag in
the command definition). Reported separately in the TestReport for clarity.

In the Liberty Shield project context:
- `cargo test -p liberty-controlled-chaos` → Test check
- `cargo build` → Build check
- `cargo clippy ... -- -D warnings` → Lint check

### Check 5 — Lint

Not a separate executable; it is the subset of `required_commands` that run
a linter (`clippy`, `eslint`, `mypy`, etc.). Configured individually with
`skip_on_prior_failure`.

---

## 4. TestReport Format

The TestReport is the output of the TestGate. It is stored in the checkpoint
and injected into the repair prompt.

```json
{
  "gate_passed": false,
  "timestamp": "2026-04-26T14:02:18Z",
  "task_id": "task-001",
  "attempt": 1,
  "repair_attempt": 0,
  "checks": [
    {
      "name": "file_scope",
      "status": "PASS",
      "violations": [],
      "output": null
    },
    {
      "name": "forbidden_file",
      "status": "PASS",
      "violations": [],
      "output": null
    },
    {
      "name": "build",
      "status": "FAIL",
      "cmd": "cargo build",
      "exit_code": 101,
      "duration_ms": 4820,
      "output": "error[E0277]: the trait bound... (truncated to 4000 chars)",
      "output_truncated": true
    },
    {
      "name": "tests",
      "status": "SKIPPED",
      "cmd": "cargo test -p liberty-controlled-chaos",
      "reason": "prior_failure"
    },
    {
      "name": "lint",
      "status": "FAIL",
      "cmd": "cargo clippy -p liberty-controlled-chaos -- -D warnings",
      "exit_code": 101,
      "duration_ms": 2110,
      "output": "error: manual implementation of an assign operation...",
      "output_truncated": false
    }
  ],
  "summary": {
    "total": 5,
    "passed": 2,
    "failed": 2,
    "skipped": 1
  },
  "changed_files": [
    "crates/liberty-controlled-chaos/src/path_fragmenter.rs",
    "crates/liberty-controlled-chaos/src/lib.rs"
  ]
}
```

**Status values per check:**

| Status | Meaning |
|--------|---------|
| `PASS` | Command exited 0 or constraint satisfied. |
| `FAIL` | Command exited non-zero or constraint violated. |
| `SKIPPED` | Not run due to prior failure and `skip_on_prior_failure: true`. |
| `ERROR` | Orchestrator could not run the command (missing binary, permission denied, etc.). |
| `TIMEOUT` | Command exceeded `timeout_seconds`. |

---

## 5. Output Truncation

Provider prompts have context limits. Long compiler errors are truncated to
4 000 characters per check output to avoid overflowing the prompt. When
truncated:
- `output_truncated: true` is set in the TestReport.
- The last 200 characters of the output are preserved (error summaries often
  appear at the end).
- The repair prompt includes a note: "[output truncated — see full log]".

The full untruncated output is always written to the execution log.

---

## 6. Forbidden File Revert Procedure

When Check 2 detects forbidden file modifications:

```
1. For each forbidden file that was modified:
   a. git checkout HEAD -- <forbidden_file>
   b. Log: FORBIDDEN_FILE_REVERTED, file=<path>

2. Record in TestReport:
   "forbidden_file_reverts": ["path/to/file.rs"]

3. Add to repair prompt section [7]:
   "IMPORTANT: The following files were automatically reverted because they
   are forbidden. Do not modify them in your repair:
   {list of reverted files}"
```

The revert happens BEFORE the repair prompt is constructed so that
`git diff HEAD` in section [8] of the repair prompt reflects the reverted
state. The provider sees a clean diff without the forbidden modifications.

---

## 7. Commit Gate (final check before git commit)

Called only when `gate_passed == true`. One final verification before writing
the commit:

```
1. Re-run file_scope check (fast; git diff is cheap).
   Purpose: guard against race conditions or file system changes
   between the TestGate run and the commit.

2. If file_scope fails: abort commit, re-enter RepairLoop.

3. Stage allowed files:
   git add -- <task.allowed_files>

4. Verify staged diff is non-empty:
   git diff --cached --quiet  →  exit 1 means changes exist (good)
   If staged diff IS empty: mark task as COMMITTED (no-op; nothing to commit).

5. Write commit:
   git commit -m "<task.commit_message_template (with {task_id} substituted)>
   
   Co-Authored-By: Liberty Dev Orchestrator v0.1"

6. Capture commit hash from git output.

7. Record in checkpoint and execution log.
```

Step 4 handles the edge case where a provider produces output that makes no
net change to the repository (e.g. it reads files but writes identical content).

---

## 8. Repair Prompt Injection

When `gate_passed == false`, the RepairLoop calls the TestGate's
`build_repair_section(TestReport) -> string`:

```
FAILED CHECKS
─────────────
{for each check where status == FAIL or status == ERROR or status == TIMEOUT:}

CHECK: {check.name}
COMMAND: {check.cmd}
EXIT CODE: {check.exit_code}
{if check.output_truncated: "[Output truncated to 4000 chars. Full output in logs.]"}
OUTPUT:
{check.output}

{end for}

SKIPPED CHECKS (could not run due to prior failures):
{for each check where status == SKIPPED:}
  - {check.name}: {check.cmd}
{end for}

UNCHANGED (passed — do not break these):
{for each check where status == PASS:}
  ✓ {check.name}
{end for}
```

This section is injected as section [7] of the repair prompt (see
`provider_router.md §7`). The "UNCHANGED" subsection explicitly tells the
provider which checks were passing — so it knows not to regress them while
fixing the failing ones.

---

## 9. Acceptance Criteria for TestGate Implementation

| Criterion | Requirement |
|-----------|-------------|
| File scope check always runs | Even if all other checks fail |
| Forbidden file check always runs | Even if file scope fails |
| Forbidden files reverted before repair prompt | `git checkout HEAD -- <file>` called before prompt construction |
| Output captured per command | Both stdout and stderr, merged |
| Output truncated at 4000 chars | With tail-preservation (last 200 chars kept) |
| SKIPPED propagation | A FAIL in check N causes SKIPPED in check N+1 only if `skip_on_prior_failure: true` |
| Commit gate re-checks file scope | Fresh `git diff` after test run, before staging |
| No commit on FAIL | GitCommit gate refuses if `TestReport.gate_passed == false` |
| TestReport persisted to checkpoint | Written before returning to OrchestratorLoop |
| Repair section covers all failures | No failing check omitted from repair prompt |
