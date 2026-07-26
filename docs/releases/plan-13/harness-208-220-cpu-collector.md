# PLAN-13 · Wave 1 · #208 (A) + #220 — CPU subtree-membership differencing

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `harness-208-220-cpu-collector` |
| **Wave** | 1 |
| **Status** | 🚀 Built + adversarially CONFIRMED (2026-07-20) — PR [#1125](https://github.com/MEFORORG/MessageFoundry/pull/1125) (auto-merge/squash, CI running). #208 stays 🔢-open (part B). |
| **Effort** | 2.5 |
| **Backlog items** | #208 part A + #220 (SAME code — one PR) |
| **ADR** | No — governed by ADR 0107 (§Prerequisite names the per-PID collector); the A3 fix shipped PR #861 with no ADR |
| **Store schema / 3-backend** | No — harness-only, store-backend-independent |

## Step 0 — claim the item (🚧, before any code)

Per [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas): this session is the **W1 banner owner for #220**
(and covers #208 part A). Before writing code, commit a **🚧 in-progress claim** on #220 in `docs/BACKLOG.md` (its own
commit), naming the lane — `> 🚧 **Status — in progress (lane `plan13-harness-208-220`, branch off `origin/main`).**`. It
stops a sibling worktree double-building this fix. #208 stays 🔢-open (part B excluded) — banner-note it, don't 🚧-claim
#208. Flip #220 🚧 → ✅ per *Definition of Done*.

## The work — STALE-PREMISE: the A3 collector ALREADY SHIPPED (PR #861); do NOT "restore the collector"

The real residual is **subtree-membership differencing only**. `_drain_proc` derives CPU as endpoint-difference
(`cpu_pairs[-1] - cpu_pairs[0]`) plus a per-pair peak loop, where each reading is a **sum across the engine subtree**; A3's
re-resolution (`_RESOLVE_EVERY_TICKS=8`) made that subtree mutable mid-window, so a joining PID inflates the delta by its
whole-life CPU and a departing PID drives it negative into the `max(0.0, ...)` clamp.

1. Carry `cpu_pids: frozenset[int] | None` on `ProcSample` (non-None **iff** `cpu_seconds` non-None), populated in
   `_sample_windows` (add `$_.Id` as a 4th `Get-Process` column; parse guard `len(parts)!=3 → !=4`) and `_sample_posix`
   (the PIDs where `_posix_cpu_seconds` returned non-None). Give it a `= None` default **and update the `_derive` test
   helper** to pass a stable pid set (else every interval becomes an unprovable-set gap and the existing
   `test_advancing_cpu_counter_*` / `test_flat_cpu_counter_*` start failing).
2. Rewrite `_drain_proc` from endpoint-difference to a **piecewise sum over consecutive intervals whose PID set is
   unchanged** (`cpu_total += max(0, cb-ca)`, `covered_span += eb-ea`), degrade set-change intervals to gaps, gate the
   peak-cores loop the same way, recompute the flat-gap guard (`_CPU_FLAT_GAP_SPAN_S`) + `cpu_mean` over `covered_span`,
   degrade to None when zero clean intervals contributed.
3. **Compose with** the shipped flat-CPU-gap guard — recompute over the summed `covered_span`, preserve the
   zero-clean-interval→None and <2-readings→None degrades — **never regress a real gap into a plausible 0.00.**

## Owned files / seams

`harness/load/connscale/probe.py` · `connscale/runner.py` (`_drain_proc` ~888-965 + the `_PROC_BY_SAMPLE` capture) ·
`tests/test_connscale_cpu_probe.py` · `docs/BACKLOG.md` (#220 @6608).

## Banner

Flips **#220** ✅. **#208 stays 🔢-open** — its whole-box rig reconciliation (part B: per-PID sum vs engine p95 88.4% /
max 91.9% on the self-hosted per_lane 28/s rig) has **no in-repo code** and is excluded; banner-note it.

## Dependencies

None. #208 and #220 are the identical files/functions → collapsed into **one** session (building them as separate
concurrent sessions collides).

## Verification — Definition of Done

- `ruff` + `ruff format --check`; `mypy harness/load/connscale/probe.py runner.py` **locally, advisory** (harness is out of
  the CI mypy scope).
- `$env:QT_QPA_PLATFORM='offscreen'; pytest -q tests/test_connscale_cpu_probe.py tests/test_connscale_smoke.py` then full
  `pytest -q` for the shared `_PROC_BY_SAMPLE` fan-out. Add the **falsifier** (spawn a CPU-burner mid-window; assert
  `cpu_seconds_total` does NOT jump by its pre-window CPU) + a membership-changed-interval→gap unit test. The
  `$_.Id` PowerShell format-string edit only truly exercises on the windows-2022/2025 mirror legs.
- **No `Co-Authored-By: Claude` trailer**; owner approves PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
