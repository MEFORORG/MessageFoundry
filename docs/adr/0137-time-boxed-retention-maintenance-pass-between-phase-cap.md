# ADR 0137 — Time-boxed retention / log-maintenance pass (between-phase cap; VACUUM non-interruptible)

- **Status:** Accepted (2026-07-19) — DEMAND-GATE-BACKLOG Wave 6 build (lane `dg-s7a`); pushes/PR owner-approved.
- **Built:** Yes — additive, off by default. `RetentionSettings.max_pass_seconds` in
  [`config/settings.py`](../../messagefoundry/config/settings.py) (own non-negative float validator,
  mirroring `_non_negative_wal`); a between-phase deadline in `RetentionRunner.run_once` +
  a `RetentionPass.capped` outcome in [`pipeline/retention.py`](../../messagefoundry/pipeline/retention.py).
  Default `0` = no cap → byte-identical to the pre-#121 unbounded pass.
- **Related:** [ADR 0027](0027-per-connection-retention.md) (the per-connection retention windows the
  pass enforces), [ADR 0042](0042-embedded-document-pruning.md) (the embedded-document strip phase),
  BACKLOG #121. A **light decision note** — this is a duration guard over the existing
  `RetentionRunner`, not a new subsystem. Sibling lane to [ADR 0130](0130-runtime-ephemeral-log-verbosity-control-and-phi-redacted-log-tail-viewer.md)
  (S7b) in the same log-maintenance cluster.

## Context

The `RetentionRunner` runs its body-purge, embedded-document strip, connection-event / alert-instance
prune, application-log-file sweep (#120), WAL-checkpoint, and daily VACUUM phases **to completion** with
**no maximum-duration cap**. The nearest controls only bound *when* a pass starts or how often it runs —
`purge_interval_seconds` sets the cadence and `vacuum_at` pins VACUUM to a daily off-peak clock time —
**none time-boxes a running pass**. On a large store a single pass (a big backlog purge, a slow VACUUM on a
bloated file) can run long enough to overlap the next maintenance window, so passes stack up. This is a
real (if marginal, demand-gated) gap versus Corepoint's log-maintenance duration ceiling.

The pass is a background asyncio task, exception-isolated per interval; the phases are all metadata /
maintenance operations. A duration cap must respect two hard constraints of this engine:

1. **A running `VACUUM` must never be interrupted.** SQLite's `VACUUM` rewrites the whole DB under a write
   lock; there is no clean mid-flight abort, and cancelling the awaiting coroutine would neither stop the
   underlying work nor leave a useful partial result. Killing it wastes the work already done and risks
   leaving `-wal`/`-shm` churn behind.
2. **Count-and-log / at-least-once are preserved.** Every phase is idempotent (a purge NULLs already-NULL
   bodies as a no-op; the strip / sweep re-scan cleanly), so *skipping* a phase this pass and *re-running*
   it next pass is always safe — nothing is lost, nothing is double-counted.

## Decision

### §1 — `max_pass_seconds` is a BETWEEN-PHASE soft cap, checked only between phases

A new `[retention].max_pass_seconds` (float; `0` = off, the default) bounds the wall time one maintenance
pass may spend. `run_once` captures a **monotonic** pass-start timestamp (injectable `monotonic=` clock,
defaulting to `time.monotonic` — separate from the window `clock`, which is `time.time` and may be frozen
in tests) and, **before each phase**, checks whether the elapsed monotonic time has reached the cap. When
it has, the remaining phases are **skipped** for this pass and the pass is marked
`RetentionPass.capped = True`. The already-completed phases keep their results.

The check is **between phases, never inside one** — the deadline is evaluated at each phase boundary
(purge → strip → prune → app-log sweep → WAL-checkpoint → VACUUM → size-check), so a phase that has already
**started always runs to completion**. In particular a **running `VACUUM` is non-interruptible**: the
deadline is checked only *before* `store.vacuum()` is dispatched, so once a VACUUM begins it is allowed to
finish even if the pass then goes over budget. This is deliberate — see constraint (1) above.

> **Amendment (2026-07-24, BACKLOG #119).** "Never inside a phase" is a rule about **non-interruptible**
> phases — a `VACUUM` or a single store call has no clean mid-flight abort, so the boundary before it is
> the only safe place to check. It is not a rule against a phase that *is* cleanly interruptible. The
> #119 application-log **compression** phase is an unbounded loop over a directory of up-to-64 MiB files,
> so a between-phases-only check left the cap unenforceable there: one dispatch would compress the entire
> directory however long that took. It therefore takes the deadline **inside** itself, re-read **between
> files** (`_compress_app_logs` receives the caller's `_deadline_hit` latch). The invariant is unchanged —
> a unit of work that has started always runs to completion; the unit is simply *one file* rather than
> *the whole phase*, and the files not reached are left untouched for the next pass (defer, don't drop —
> §2's principle applied within a phase). The interruption point is chosen so a file is compressed
> **whole or not at all**: it is never left half-archived.

### §2 — A SKIPPED maintenance phase does NOT advance its last-run marker

The WAL-checkpoint and daily-VACUUM phases are cadence-gated on `_last_wal` / `_last_vacuum_day`. Those
markers are advanced **only when the phase actually runs**. If the cap skips the WAL checkpoint or the
VACUUM, its marker is **left untouched**, so the very next pass sees the work as still due and performs it
(subject to the same cap). A capped pass therefore *defers* maintenance to the next interval rather than
silently marking it done — the whole point of the ceiling.

### §3 — Metadata-only; a capped pass is audited for operator visibility

`max_pass_seconds` and the resulting `capped` flag are pure timing metadata — no PHI. A capped pass counts
as work worth an audit row (`RetentionPass.did_work` includes `capped`), and the `retention_purge` audit
detail records `max_pass_seconds` + `capped` alongside the existing cutoffs/counts, so an operator can see
that maintenance is falling behind its window. With the cap off (`0`, the default) `capped` is always
`False` and behaviour + audit values are byte-identical to before #121.

Recommended value when enabled is ~4 hours (`14400`), matching the Corepoint default off-peak ceiling; the
knob defaults to `0` (off) to honour the `[retention]` "every window defaults to keep/off" convention so an
existing deployment is unchanged until an operator opts in.

## Options considered

1. **Between-phase soft cap; VACUUM non-interruptible (chosen).** Bounds a pass at phase granularity,
   never aborts in-flight work, re-runs the skipped tail next interval. Idempotent phases make deferral
   free.
2. **Interrupt a running VACUUM at the deadline.** Rejected — SQLite VACUUM has no clean mid-flight abort;
   cancelling the coroutine cannot stop the underlying rewrite and only wastes the work. The cap is a
   scheduling guard, not a kill switch.
3. **Per-phase `asyncio.wait_for` timeouts.** Rejected — heavier, would cancel a legitimately-running
   purge/checkpoint mid-transaction (re-run cost, and for VACUUM the same non-abortable problem), for no
   gain over the between-phase check on idempotent phases.
4. **Advance the marker even when a phase is skipped.** Rejected — that would silently *skip* the WAL
   checkpoint / VACUUM for a whole day, defeating the cap's purpose (defer, don't drop).

## Consequences

**Positive** — a maintenance pass can no longer run unbounded into the next window; the skipped tail is
re-attempted next interval with markers intact; VACUUM is never torn mid-flight; additive and off by
default (byte-identical until opted in); metadata-only, no new PHI surface.

**Negative / residual** — the cap is **soft**: a single slow phase (a large VACUUM) can still overrun the
budget on its own since it is never interrupted — the ceiling bounds *how many further phases* run, not the
worst-case single phase. Operators pair `max_pass_seconds` with `vacuum_at` (off-peak) and a sensible
`purge_interval_seconds` for the full guard. The cap is checked at phase granularity only (by design).
