# HANDOFF — zizmor 1.28.0 adoption (session stopped at 96% weekly usage, 2026-08-02)

Committed on the `zizmor-1280-adoption` branch. A copy exists in the owner's local notes folder.

## STATE

- Branch `zizmor-1280-adoption`.
- **PR #130 MERGED — `851c849b`.** 30/30 green. This work is DONE.
- **PR #127 CLOSED by Dependabot itself** once #130 satisfied the versions (same as #66).
- **PR #125 OPEN, `BEHIND`** — the only outstanding item. See BLOCKED ON.
- Claim `zizmor-1280` released; `ci-dependabot` released.

## DONE (with SHAs)

| SHA | What |
|---|---|
| `851c849b` | #130 merge — zizmor 1.28.0 adopted, all 5 findings resolved |
| `2a6649fb` | #121 — uv `ignore:` rules, GHSA per-dependency fix, zizmor paths filter, coord_lock occupancy test |
| `da80fcc3`, `e78c05c9` | #127's commits, cherry-picked into #130 (bytes + authorship preserved) |

**Verified, not assumed:** zizmor 1.28.0 run against **main's actual tree** post-merge →
`No findings to report. (27 ignored, 40 suppressed)`, exit 0. This mattered because the 06:00 cron is
unwatched (zizmor is not a required context; `nightly-notice.yml` watches CI only).

Dispositions: `bot-conditions` HIGH → suppressed (fail-closed conjunction, premise pinned by a
mutation-tested guard). `ref-version-mismatch` ×3 → fixed (SHA was v7.0.0, comment said v6).
`archived-uses` → dated residual, ADR 0034 amendment.

## BLOCKED ON

**#125 (hvac cap, `hvac>=2.3.0` → `hvac>=2.3.0,<3`).** Green, zero lock churn, `BEHIND`. Parked behind
#119 by my choice, not by a dependency — #119 had been stalled three times and had the stronger claim.
Its worktree is gone, so update via API:

```bash
gh api -X PUT repos/MEFORORG/MessageFoundry/pulls/125/update-branch
gh pr merge 125 --repo MEFORORG/MessageFoundry --squash    # once green
```

Clears: anyone. Nothing depends on it.

## RETRACTIONS (corrected forms)

1. **"#131's W25 job had 81s of job-cap margin" — WRONG.** I asserted it against the old 30:00 cap
   without confirming which caps were in force. The run's own matrix shows `job_timeout:40,
   step_timeout:36` — `pull_request` composes from base+head, so #131 ran under its own edit. Correct
   form: 28:39 against 40:00 = 1.40x. No near-miss.
2. **My pooled W25 table is DEFECTIVE — do not reuse the pool.** Corrected by the ci-margin-correction
   session: the tightest *passing* W25 step was **25:51 vs 26:00 = 1.006x** (run `30724385719`), not the
   1.06x I repeated; the "11 runs" pool was really ~35-38 (a default `gh run list` page is 20 rows —
   tool truncation); two of #131's three table rows were single-run values, not maxima (W22's true max
   is 21:34 → 1.21x, not 1.39x). **Root cause: filtering the pool by JOB conclusion while measuring
   STEP durations drops the tightest cases by construction.**

**Record the rule and the pool SEPARATELY, or the rule inherits the defect.** The rule stands
independently: **size a cap so headroom exceeds the measured spread**, and record the spread with its
sample and date — not a fixed multiple, because a ratio against a single point cannot see variance.

## TRAPS (fact + measurement)

1. **Two pytest steps share one `step_timeout`.** `ci.yml:269` (`Tests (pytest)`) and `:297`
   (`Web console tests`) both take `matrix.step_timeout`; the job takes `job_timeout` at `:61`.
   2 × 36 = 72 inside a 40-minute job. **Reachable because the step PASSES:** Tests 35:59 (green) +
   WebConsole ~3:18 + overhead ~0:41 = 39:58 vs 40:00. Yields a green step then an unattributed job
   kill — exactly what the invariant at `ci.yml:218` exists to prevent. **Demonstrated** by
   ci-margin-correction: run `30724385719`, step SUCCESS 25:51, job cancelled 30:13 during the web
   console step. Pre-existing; #131 preserved the original +4 faithfully. Fix is NOT a bigger
   `job_timeout` — give the web-console step its own small cap. Filed in BACKLOG #344.
2. **Never compare a job figure to a step cap.** Four sessions did it tonight. Quote step durations
   from the step's own `started_at`/`completed_at` — never by subtracting setup from a job total,
   never from wall-clock mid-flight.
3. **`gh run list` defaults to 20 rows.** Any pool built from it is silently truncated.
4. **Pre-commit `ruff` hooks are `language: system`** — they fail with "Executable `ruff` not found" in
   any shell where the venv is not on PATH. `export PATH="$(pwd)/.venv/Scripts:$PATH"`. Never
   `--no-verify`.

## WORTH PRESERVING

- **"The test is not 'is there a check?' but 'IF THIS CHECK FAILS, WHAT STOPS THE MERGE?'"** One API
  call — `required_status_checks` is authoritative; the repo's own `required-contexts.txt` is a *claim
  about* it. Proved by asymmetry: #130 and #133 had the identical argument shape and opposite answers,
  because zizmor is not required and `test (windows-2025)` is. **#130 nearly auto-merged carrying a
  live zizmor finding** — a non-required gate on an armed PR fails *toward* landing.
- **Two defect classes** (→ ADR 0157/0158): (1) *a bound or claim stated independently of the thing it
  bounds* — ask "what measurement backs this number?"; (2) *a control that cannot observe or act on its
  own failure* — ask "if this were broken, what would tell me?" If the answer is the control, that's
  the defect.
- **"A measurement is only better than an estimate when it measures the same quantity."** (announce
  session's formulation — the word *measured* transfers authority the number hasn't earned.)
- **On sequencing #133 behind #131: "prudent under uncertainty, not vindicated."** #133 would have
  passed the old caps. The advice was right by the *headroom > spread* rule, not by the outcome. Worth
  keeping the distinction.
- **Six retractions across four sessions, every one caught by a peer measuring, none by the author
  re-reading.** Nothing in the workflow forces a claim to be re-checked against the thing it describes.

## NOT MINE, STILL OPEN

- Claim `7` orphaned by the prune (worktree deleted): `scripts\coord\claim.ps1 -Release 7`.
- `prune-merged.ps1` does not release claims held by worktrees it deletes (unfiled; use `alloc.ps1`).
- `HANDOFF-adr-0154.md` in the owner's local notes folder — rescued from a pruned worktree.
