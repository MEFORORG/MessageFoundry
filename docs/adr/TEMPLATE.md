# NNNN — <decision title>

- **Status:** Proposed  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** <YYYY-MM-DD>
- **Related:** <ADR links · CLAUDE.md §x · BACKLOG #N>

---

## Context

<The forcing problem. Quote the [CLAUDE.md](../../CLAUDE.md) invariant(s) in play **verbatim**. What
constraints bound the choice (reliability/purity, count-and-log, no-grouping-unit, PHI rules)?>

## Decision

<The choice in one line, then the detail — and what it must **not** break.>

## Acceptance Criteria

> Behavioural acceptance criteria in **EARS** (Easy Approach to Requirements Syntax) — testable,
> unambiguous, each linked (`→`) to the test or fixture that verifies it. Recommended (SHOULD) per
> [Secure Development Standards §5](../Secure_Development_Standards.md). Forms: ubiquitous
> `THE SYSTEM SHALL …` · event-driven `WHEN <trigger> THE SYSTEM SHALL <response>` · state-driven
> `WHILE <state> …` · unwanted-behaviour `IF <condition> THEN THE SYSTEM SHALL …` · optional
> `WHERE <feature> …`. `messagefoundry adr-analyze` checks each `→` link resolves to a real file.

- **AC-1** — WHEN <trigger>, THE SYSTEM SHALL <response>.
  → `tests/test_<area>.py::test_<name>`
- **AC-2** — IF <condition>, THEN THE SYSTEM SHALL <response> (e.g. record `ERROR`, never accept-and-drop).
  → `tests/test_<area>.py::test_<name>`  <!-- or a fixture: fixtures/<inbound>/<msg>.hl7 (+ .expect) -->

## Options considered

1. **<chosen>** — … **CHOSEN.**
2. **<alternative>** — … Rejected: ….

## Consequences

**Positive** — …

**Negative / risks** — …

**Out of scope** — …

## To resolve on acceptance

> The **clarify** step: open questions to settle before this flips to `Accepted`. Track each as a task
> item so `adr-analyze` surfaces anything still open. Delete the block (or leave it resolved) on a
> clean acceptance.

- [ ] <open question to resolve before Accepted>
