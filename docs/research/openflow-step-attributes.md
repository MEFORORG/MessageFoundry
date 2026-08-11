# OpenFlow step attributes vs. the engine vocabulary (research / findings)

**Date:** 2026-08-06 · **Status:** research / findings (no code) · **Owner action:** none required — informational vocabulary map.

This is BACKLOG **[#238](../archive/backlog/BACKLOG-CLOSED.md)**. It reads Windmill's **OpenFlow** step-attribute vocabulary
(Apache-2.0, safe to read and cite) as a **completeness checklist** against MessageFoundry's own
step/connector semantics, and records, per attribute, whether the engine already covers it (and where),
covers it partially, or does not have it — and why. **OpenFlow is explicitly NOT a compatibility
target.** Emitting or consuming it is a separate, unauthorized question, and adopting a *declarative
artifact* remains declined by [ADR 0076](../adr/0076-typed-action-vocabulary-action-list-lens.md) §7 and
BACKLOG #26. This note exists so the mapping need not be re-derived; the gaps below are described as
**vocabulary differences, not defects**, and nothing here is a to-build list. MessageFoundry is a
not-deployed beta, so claims are stated in the conditional.

The one fact worth leading with: **most of these attributes already have an engine analogue, but at a
different locus** — a per-connection / delivery / pipeline policy, or plain Python control flow inside a
Handler — rather than as an attribute hanging off a single step row. Saying *where* each lives precisely
is most of the value here.

## The seven attributes, mapped

| Attribute | What it is (OpenFlow) | Engine analogue (symbol · file) | Gap |
|---|---|---|---|
| `retry` | A per-step retry policy (constant or exponential backoff, N attempts) before the step is treated as failed. | `RetryPolicy` (`config/models.py`) — `max_attempts` / `backoff_seconds` / `backoff_multiplier` / `max_backoff_seconds`; attached per-outbound as `Destination.retry`, drained by the outbound delivery worker under the staged-queue at-least-once model. | **Covered, different locus** — retry is a per-**outbound-connection** delivery policy, not a per-handler-row attribute. |
| `timeout` | A per-step wall-clock timeout after which the step is killed. | Boundary timeouts only: `Validation.strict_timeout_s` (`config/models.py`) / `_STRICT_VALIDATE_TIMEOUT_SECONDS` (`pipeline/wiring_runner.py`) bound strict validation; `_LOOKUP_RESULT_TIMEOUT_SECONDS` (`pipeline/wiring_runner.py`) bounds a bridged `db_lookup`/`fhir_lookup`; connectors carry their own (`timeout_seconds`/`connect_timeout` in `transports/tcp.py`, `transports/mllp.py`; `acquire_timeout` in `transports/database.py`). | **Partial** — timeouts bound the external / parse boundaries; there is **no** generic per-handler/transform wall-clock timeout (a pure transform is CPU-bounded by design). |
| `stop_after_if` | Stop the flow early (as success or skip) when an expression over the step result is true. | A Router that forwards to no / fewer handlers yields `UNROUTED`; a Handler that returns no `Send` yields `FILTERED` (`disposition_for`, `pipeline/dryrun.py`; the count-and-log invariant). Control flow projects as `if` rows in the Steps view (`_emit_if`, `lens.py`). | **Partial / structural mismatch** — the config is a **graph** with no linear "steps after this" to stop; "stop the flow" is expressed by a Router/Handler declining to forward, not a post-step early-terminate knob. |
| `skip_if` | Skip this step when an expression is true; the flow continues past it. | Ordinary Python `if cond: return` in a `@router` / `@handler`; the router's `accepts=` seam filters which handlers ever see a message; also projects as an `if` row (`_emit_if`, `lens.py`). | **Covered, as code** — conditional skipping is plain control flow in a code-first Handler, deliberately Python rather than a declarative attribute (the #26 differentiator). |
| `continue_on_error` | Let the flow proceed when this step errors, instead of failing the run. | `InternalErrorPolicy.CONTINUE` (`config/models.py`) is the **default** — dead-letter the offending row (replayable) and keep the lane moving; each outbound drains independently; post-ACK routing/transform errors are logged `ERROR` / dead-lettered, never fatal (count-and-log). `STOP` is the opt-in opposite. | **Covered, different locus + inverted default** — error-and-continue is the pipeline **default** at the delivery / row level, per-connection, not a per-handler-row toggle. |
| `mock` | Replace a step's execution with a fixed, canned result (for testing a flow). | No per-step canned-result substitution. Adjacent: the traced dry-run (`pipeline/dryrun.py`; [ADR 0072](../adr/0072-traced-dryrun-mode.md)) runs routing + handling with **no** connectors / network (delivery previewed, not executed), and `Destination.simulate` (`config/models.py`) shadow-suppresses real egress. | **Largely absent** — the engine can mock **delivery** (dry-run / shadow suppress egress) but cannot feed a step a fixed stand-in result; `db_lookup` / `fhir_lookup` **raise** in a pure dry-run rather than returning a mock (`config/db_lookup.py` / `config/fhir_lookup.py`). |
| `cache_ttl` | Cache a step's result for N seconds, reusing it on re-run within the window. | None for handler / step results. The reliability model **requires** routers / transforms to be pure and re-runnable with identical output ([ADR 0001](../adr/0001-staged-pipeline-architecture.md)); the sanctioned non-pure inputs `db_lookup` / `fhir_lookup` ([ADR 0010](../adr/0010-handler-callable-db-lookup.md) / [ADR 0043](../adr/0043-fhir-read-lookup.md)) are deliberately **live** reads whose result may differ on a re-run. | **Absent, by design** — a per-step result cache would contradict the pure-re-run at-least-once invariant; the caches the engine does keep are engine-internal infrastructure, not step-result caches. |

*Caveat:* `file:line` anchors are a 2026-08-06 snapshot and drift — the table cites **symbol names** as
the primary anchor (`RetryPolicy`, `InternalErrorPolicy`, `Destination.simulate`,
`_LOOKUP_RESULT_TIMEOUT_SECONDS`, `disposition_for`, `_emit_if`); re-confirm at read time and cite
symbols, not just lines.

## Reading of the gap-map

Most of the seven are **already covered engine-side, at a different locus** — a connection / delivery /
pipeline policy (`retry`, `continue_on_error`, and most of `timeout`) or plain Python control flow inside
a Handler (`skip_if`, and `stop_after_if` as a Router / Handler declining to forward) — rather than as a
per-step-row attribute. Only two are genuinely absent: `mock` (the engine mocks **delivery**, not step
results) and `cache_ttl` — and `cache_ttl` is absent **by design**, because a per-step result cache would
fight the pure-re-run at-least-once invariant the pipeline depends on.

This confirms the item's framing: OpenFlow compatibility is unnecessary and unwanted here. The
vocabulary is a **lens on semantics the engine already has**, expressed at the connection / delivery /
pipeline level or as code-first control flow — not a gap-to-close list, and not a case for emitting or
consuming a declarative artifact.
