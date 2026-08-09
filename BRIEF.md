# BRIEF — Stream C: CI hygiene and the count/prose lints

You own **`.github/workflows/asvs-scorecard.yml`** and the doc-lint scripts under `scripts/docs/`.
Three other streams are running in parallel; none of them touches your paths and you touch none of
theirs. **`scripts/asvs/scorecard.py` is Stream V's and is actively changing — do not edit it.**

**Read first:** `docs/security/HANDOFF-ASVS-TRACKING-REWORK-2026-08-08.md` in the **vault** repo
(the sibling `MessageFoundry-vault` checkout, on `origin/main`).

## Owned paths

```
.github/workflows/asvs-scorecard.yml   EXCLUSIVE
scripts/docs/**                        EXCLUSIVE (lints)
tests/test_*lint*.py, tests/test_*doc*.py  (the tests for your own lints)
```

## Tasks, in order

### C1 — the ASVS gate fires in the repo that cannot cause the drift

`asvs-scorecard.yml`'s path filter triggers on **vault** paths. The anchors point into the **engine**.
So an engine commit that moves every anchor fires nothing, and the only thing that catches it is a
daily cron bolted on afterwards. The workflow's own comments concede this.

Fix the trigger so the gate observes the tree it actually measures. Keep the nightly as the
cross-repo authority; keep the vault's verifier copy and the auto-mirror (`asvs-verifier-drift.yml`
already enforces parity in its own job and opens a mirror PR — do not undo that).

Prove the fix the same way the rest of this programme proves things: construct a change that *should*
trigger the gate, confirm it does under the new filter and did not under the old.

### C2 — the count lint, and it must be proven blind-first

**44 documents assert a whole-corpus tally; roughly 50 distinct tallies exist; approximately one is
correct.** The correct one (`ASVS-CURRENT.md`) is a Markdown table that a grep for the corpus's own
`N / N / N / N` idiom does not even find.

Build a forward-only lint that refuses a **new** hard-coded whole-corpus tally.

- **Rebuild the idiom set from the corpus, not from two guesses.** A previous attempt matched two
  shapes and missed 6 of the 8 chapter reports that were its own motivating evidence, plus 13 other
  known offenders.
- **It must red all 8 chapter reports and all 13 known offenders BEFORE it lands.** If it does not,
  it is not measuring what it claims. Print what it scanned — file count, match count — so a broken
  run and a clean run cannot look alike.
- Allowlist `ASVS-CURRENT.md` (it *is* the rendered record) and the method doc's literal "N of 345".
- Forward-only. Do **not** attempt a sweep: a 47-file banner sweep already cost ~850 net lines, needed
  its own repair commit, and the defect regenerated within four days because the eight chapter
  reports were written *after* it. A one-time sweep over a file list protects nothing authored later.

### C3 — the residual prose lint, forward-only

Roughly 1,975 `file:line` citations live inside `residual` prose across 246 cells, and **1,064 are
bare basenames** that cannot resolve even in principle. Nothing checks any of them; a sample measured
44.9% stale.

Refuse a **new** `file:line` citation in any residual a PR touches. Grandfather the existing set on a
**frozen allowlist that can only shrink.**

Do not attempt bulk promotion of those citations into gated anchors. It was costed and rejected: ~1,000
hand-authored tokens, it doubles the gated surface, and it makes *delete the citation* the cheapest
compliant act on 1,053 basenames.

## The finding that motivated this stream, for context

A PR touching only `docs/security/asvs-apply-cells.py` set `code=false` in `ci.yml`'s docs-only
detector and skipped install, lint, type-check and the whole pytest suite — because `^docs/` matches
any path under `docs/`, including `.py`. The tool that can silently un-close an owner-closed cell was
exempt from CI by virtue of its directory, and two mypy errors had been sitting in it since it was
written.

Two things made that worse than a missing test, and both are patterns to watch for in your own work:
the file's comment **states the opposite of what the regex does** ("any `*.py` ... counts as CODE"),
and the precedent was **four lines above the defect** — `.gitignore` had the identical bug, was fixed,
and the lesson was written down directly above the regex that still contained it for `docs/**/*.py`.
**The fix that does not generalise is the one that comes back.** MEFORORG#299 closes that class; if it
has not merged when you start, coordinate rather than duplicating it.

## Hard rules

- Every check prints **what it scanned**, not only what it found.
- Make each lint **fail on purpose** before believing it passes, and confirm the injected defect
  actually landed. A guard no test drives ships looking green.
- A negative control is mandatory: a pattern that cannot occur must return zero. An empty pattern
  matches every line, and `grep -c` then returns the line count — numerically identical to the
  quantity you were trying to measure.
- Allocate any BACKLOG number with `scripts\coord\alloc.ps1`. **Never grep for the next free number**;
  two sessions that both grep pick the same one, merge clean, and corrupt the ledger.
- No emoji or glyphs, including in commit messages (CLAUDE.md §11). The backlog banner alphabet is the
  one machine-parsed holdout; read it with `parse_items`, never a hand-rolled scan.

## Coordination

Commit and push freely on `asvs-ci-hygiene`; open PRs. **Do not merge to main** without the owner.
