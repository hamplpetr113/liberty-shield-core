# Cost Limits

## Purpose

This document defines cost control rules for AI-assisted workflows in Liberty Shield.

Cost control is a security requirement, not only a billing concern. Uncontrolled agent loops, uncapped API retries, and runaway CI workflows can exhaust budget, trigger provider-side throttling, and mask active incidents. These rules exist to prevent that.

All workflows, autonomous agent runs, and AI API integrations must comply with the limits in this document.

## Required Workflow Limits

Every GitHub Actions workflow must define:

- `timeout-minutes` for every job
- `permissions` with least privilege
- `concurrency` with `cancel-in-progress` where safe
- explicit trigger scope
- no deploy trigger unless explicitly approved
- no recursive workflow trigger unless explicitly approved

Workflows that run AI agents, tests, scans, or build jobs must fail closed when required limits are missing.

PR workflows must not access production secrets or deployment credentials.

## Forbidden Cost Patterns

The following patterns are forbidden unless explicitly approved by the human owner:

- infinite retry loops
- recursive agent triggering
- scheduled autonomous coding loops
- auto-retry loops that call paid AI APIs without a hard cap
- workflows that trigger other workflows without a defined maximum depth
- agents that reopen or recreate failed missions indefinitely
- background tasks that continue after the approved mission ends
- test jobs that call paid external APIs by default
- build or scan loops without timeout limits
- any automation that can spend money without a budget limit

If a proposed change introduces one of these patterns, it must be redesigned or marked as high risk for explicit human approval.

## Paid AI API Guardrails

Any workflow, agent, or script that can call a paid AI API must define hard limits before it is enabled.

Required limits:

- maximum number of model calls per mission
- maximum retry count
- maximum wall-clock runtime
- maximum cost budget where supported by the provider
- explicit human approval before increasing limits
- no hidden background execution
- no recursive self-invocation
- no automatic escalation to more expensive models without human approval

Paid AI API keys must not be available to PR workflows.

Paid AI API usage must be logged with mission ID, agent name, trigger source, approximate call count, and failure state.

## Alerting

Cost and runaway-risk events must produce human-visible alerts before autonomous loops are enabled.

Future alerting must include Telegram notifications for:

- workflow failures caused by timeout
- repeated failed agent missions
- repeated retries
- unexpectedly high model-call count
- budget threshold reached
- blocked recursive trigger attempt
- attempted use of paid AI API without configured limits
- attempted execution after mission scope ended

Alerts must include:

- mission ID if available
- agent name
- trigger source
- workflow run link if available
- failure or cost condition
- recommended human action

Until alerting exists, scheduled autonomous coding loops must remain disabled.

## Manual Kill Switch

A manual kill switch procedure must exist before any scheduled autonomous coding loop or paid AI automation is enabled.

The kill switch must be able to stop:

- scheduled workflow triggers
- autonomous agent loops
- paid AI API calls
- recursive retry chains
- deployment-related automation
- notification spam
- runaway test or build jobs

The procedure must document:

1. how to disable the workflow or scheduler
2. how to revoke or rotate API keys if needed
3. how to stop running jobs
4. how to preserve logs for investigation
5. how to notify the human owner
6. how to confirm the system is no longer spending money

If a kill switch is missing or untested, autonomous loops must remain disabled.

## Provider-Side Budget Controls

Provider-side budget limits must be configured outside the repository before paid autonomous agent loops are enabled.

Required external controls include, where supported by the provider:

- monthly spend limits
- per-project budget limits
- usage alerts
- API key scoping
- model access restrictions
- rate limits
- organization-level billing alerts
- automatic suspension or manual approval before budget increase

Repository policy must not contain real API keys, billing credentials, payment details, or provider secrets.

Documentation may describe required controls, but actual provider configuration must be performed outside the repository by the human owner.

If provider-side budget controls are unavailable, paid autonomous loops must remain disabled.

## Default Rule

If cost impact is unclear, the agent must stop and request human approval.

If a workflow, script, or agent can spend money, call paid APIs, trigger repeated jobs, or run without a clear upper bound, it must be treated as high risk.

No autonomous loop may be enabled until all of the following exist:

1. hard runtime limit
2. hard retry limit
3. hard model-call limit
4. provider-side budget limit where available
5. alerting path
6. manual kill switch
7. human approval

When in doubt, disable automation rather than risk runaway cost.
