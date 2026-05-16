# Agent Audit Trail

## Purpose

This document defines the audit trail required for AI-assisted development in Liberty Shield.

Every agent-assisted change must leave enough evidence for a human reviewer to reconstruct what happened, why it happened, which agent or tool acted, which files changed, which commands ran, which checks passed or failed, and whether human approval was required.

Auditability is a security requirement. If an agent action cannot be reconstructed after the fact, it must not be treated as safe.

## Required PR Audit Metadata

Every agent-assisted pull request must include the following audit metadata:

- agent/tool name
- model name/version if known
- trigger source
- issue link or mission reference
- prompt summary
- touched files
- commands run
- test results
- risk level
- human approval requirement
- rollback notes
- security-sensitive files touched
- whether deployment is required
- whether secrets were touched
- whether CI configuration was touched

If any required metadata is missing, the PR must be treated as incomplete and must not be merged.

## Agent Identity

Every agent-assisted PR must identify the agent or tool that performed the work.

The audit record must include:

- agent/tool name
- model name/version if known
- execution environment
- whether the agent had repository write access
- whether the agent had access to external tools
- whether the agent had access to secrets
- whether the agent acted locally, in GitHub Actions, or through another runner

Agents must not hide or obscure which tool performed the change.

If the model version is unknown, the audit record must state "model version unknown" rather than omit the field.

## Mission Traceability

Every agent-assisted change must be traceable to a mission, Issue, or explicit human instruction.

The audit record must include:

- issue link or mission reference
- trigger source
- prompt summary
- requested objective
- acceptance criteria
- approved scope
- files allowed for modification
- files explicitly forbidden for modification
- human approver if applicable

If no Issue exists, the PR must include a mission summary explaining who requested the work and why.

The agent must not expand the mission scope without explicit human approval.

## Command and Test Evidence

Every agent-assisted PR must record the commands that were run and the evidence produced by those commands.

The audit record must include:

- commands run
- working directory where commands were run
- whether commands modified files
- test commands executed
- formatting commands executed
- lint commands executed
- build commands executed
- security scan commands executed
- command results
- failed commands and error summaries
- skipped checks and reason for skipping

Agents must not claim that tests passed unless the test command was actually run and the result was observed.

If a command fails, the agent must record the failure instead of hiding or rewriting it.

If tests are skipped, the PR must explain why skipping is acceptable for the mission.

## Risk and Approval Record

Every agent-assisted PR must classify the risk level of the change.

Allowed risk levels:

- LOW
- MEDIUM
- HIGH
- CRITICAL

The audit record must include:

- selected risk level
- reason for the risk level
- whether human approval is required
- who approved the mission if applicable
- whether CODEOWNER review is required
- whether security-sensitive files were touched
- whether production deployment is required
- whether rollback is required
- whether additional review is recommended

HIGH or CRITICAL changes must not be merged without explicit human approval.

Any change that touches authentication, cryptography, routing, replay protection, scheduler, VPS service logic, CI security gates, CODEOWNERS, secrets, or deployment paths must be treated as HIGH or CRITICAL unless explicitly downgraded by the human owner.

## Security-Sensitive Changes

Every agent-assisted PR must explicitly state whether security-sensitive files or logic were touched.

Security-sensitive areas include:

- `.github/`
- `.github/CODEOWNERS`
- `.github/workflows/`
- `.github/copilot-instructions.md`
- `CLAUDE.md`
- authentication logic
- cryptography
- PSK handling
- token handling
- routing
- replay protection
- scheduler logic
- VPS service logic
- deployment scripts
- secrets handling
- dependency files
- build configuration

The audit record must include:

- whether any security-sensitive area was touched
- exact files touched
- why the change was necessary
- whether CODEOWNER review is required
- whether human approval is required
- whether tests or security checks were run
- whether rollback is straightforward or risky

If the agent is unsure whether a file is security-sensitive, it must treat it as security-sensitive and request human review.

## Rollback and Deployment Notes

Every agent-assisted PR must state whether deployment is required.

If deployment is required, the audit record must include:

- deployment target
- deployment owner
- deployment commands proposed
- whether the agent executed any deployment command
- rollback plan
- rollback commands proposed
- post-deploy verification steps
- expected service health checks
- known risks
- human approval requirement

Agents may propose deployment, rollback, and verification commands, but must not execute production deployment.

If no deployment is required, the audit record must explicitly state "deployment not required".

If rollback is not applicable, the audit record must explain why.

Any PR that requires deployment but lacks rollback notes must be treated as incomplete.

## Default Rule

If an agent-assisted change cannot be audited, it must not be merged.

The agent must stop and request human review if:

- the agent/tool identity is unclear
- the model version is unknown and not recorded
- the trigger source is missing
- the mission or Issue link is missing
- touched files are not listed
- commands run are not listed
- test results are missing
- risk level is missing
- approval requirement is unclear
- security-sensitive files may have been touched but are not identified
- deployment requirement is unclear
- rollback notes are missing where required
- secrets or CI configuration may have been touched but are not declared

The safe default is to preserve evidence, stop work, and request human approval.
