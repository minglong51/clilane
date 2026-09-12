# TODOS

## CI

### Extract legacy smoke checks into locally runnable scripts

**What:** Move the existing inline lifecycle, fleet, and hub smoke checks from `.github/workflows/smoke.yml` into locally runnable scripts invoked unchanged by the macOS and Linux jobs.

**Why:** The workflow is approximately 395 lines and its heredoc-based checks are difficult to reproduce locally; one executable source makes CI failures faster to diagnose without changing coverage.

**Context:** v0.5.1 will add `tests/test_profiles.py` and a separate provider-evidence `--check` command while deliberately retaining the existing inline smoke body. After v0.5.1 is released and stable, extract the legacy checks as a maintenance-only change, preserve every current lifecycle, fleet, hub, and real-tmux assertion on both operating systems, and keep the commands runnable without CI-only state. Do not introduce a reusable workflow until a second real consumer exists.

**Effort:** M
**Priority:** P2
**Depends on:** v0.5.1 release and a stable local profile-test harness

## Architecture

### Review OTel identity export and the agent-usage-manager consumer contract

**What:** Run a separate engineering review for the v0.6 OTel task-identity export and downstream agent-usage-manager probe before either amendment is implemented.

**Why:** These contracts were added concurrently after the reduced review scope was fixed, so their environment merge behavior, provider compatibility, privacy boundary, and failure semantics have not been cleared.

**Context:** The attention-cockpit design preserves a proposal to inject `clilane.task_generation` through `OTEL_RESOURCE_ATTRIBUTES` and let agent-usage-manager join CLI Lane task identity to provider sessions. The follow-up review must verify raw and profile launch behavior, duplicate-key precedence against pinned SDKs, exact provider-version evidence, task-generation stability, secret-free telemetry, failure behavior when OTel is absent, and the downstream consumer's read-only boundary. Phase 0 may invalidate or narrow the provider claims; do not turn the amendment into v0.6 implementation work merely because it is already written into the design.

**Effort:** S
**Priority:** P1
**Depends on:** v0.5.1 clean-profile release and the Phase-0 capability matrix
**Blocked by:** Unverified provider OTel behavior

## Completed
