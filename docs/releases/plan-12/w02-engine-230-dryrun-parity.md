# PLAN-12 · Wave 2 · #230 CLI dryrun/check snapshot parity (OPTIONAL)

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `engine-230-dryrun-parity` — **OPTIONAL; droppable without weakening anything** |
| **Wave** | 2 |
| **Status** | ✅ **Complete** (2026-07-16 — landed in this session's PR; #230 flips ✅ with it) |
| **Effort** | 0.5–1 |
| **Backlog items** | #230 (Phase 4 of 4 — the ungated optional fast-follow from #230:6827) |
| **ADR** | No — library defaults stay False per ADR 0104 §8.1; this threads the *service setting* into two CLI preview paths |
| **Store schema / 3-backend** | No |

## Items

| Item | Title | Status |
|---|---|---|
| #230 (P4) | Thread `[pipeline].snapshot_on_send` into CLI `dryrun`/`check` | ✅ built (this PR) |

## Owned files / seams

`messagefoundry/__main__.py` (dryrun subcommand ~:2076-2086 + its settings resolution) · `messagefoundry/checks.py`
(`_check_dryrun` region ~:449-530) · **`messagefoundry/pipeline/dryrun_trace.py`** (`trace_dry_run` ~:386-396 —
snapshot passthrough) · `messagefoundry/pipeline/dryrun.py` (docstring only) · `tests/test_checks*.py` /
`tests/test_dryrun*.py` (new cases) · also fixes the `messagefoundry/hl7structures.py:19` "byte-equal" docstring
mislabel (kept out of S1 to preserve its docs-only CI fast path).

## The work

Thread the loaded service setting into the two CLI preview paths so the Test Bench and commit gate preview what the
engine actually does (engine default **ON** since ADR 0104 §8.1; `settings.py:989`, threaded at `__main__.py:1762`):

1. `__main__.py` dryrun command and `checks.py` `_check_dryrun` resolve `settings.pipeline.snapshot_on_send` the same
   way `serve` does.
2. **Verdict-corrected (the phase as originally designed CANNOT work without this):** `trace_dry_run`
   (`pipeline/dryrun_trace.py:386-396`) has **no** `snapshot_on_send` parameter and its internal `dry_run` call
   passes none — the file MUST gain the passthrough, or `dryrun --trace` diverges from plain `dryrun` and breaks its
   documented byte-identical contract.
3. **Verdict-corrected:** where a command doesn't currently load service settings, load them best-effort with the
   fallback = the **Settings-model default (True)** — NOT False, which would preview the wrong posture for exactly
   the default engine this phase exists to mirror. Say so in `--help`.
4. The `dry_run`/`route_message` **library** defaults stay `False` (ADR 0104 §8.1 — a preview that doesn't opt in
   still does not snapshot); update the `dryrun.py` ~:512-520 docstring to note the CLI now passes the setting.

## Dependencies

None — independent of every other session (the S1 tracker-errata gate deliberately does not apply: this phase acts
on the service setting, not the #230 tracker's picker text); can be dropped entirely — **but if dropped, fold the
one-line `hl7structures.py:19` docstring fix into S8's grep-for-stub-prose pass** (else it's orphaned). **Merging it
BEFORE [w03-store-235-flip](w03-store-235-flip.md) keeps the `checks.py`/`test_checks.py` rebase burden on S8, which
expects it.** Never run in the same wave as S8 (shared files, line-disjoint).

## Notes & gotchas

- PHI: fixtures are **synthetic HL7 only**; never redirect `dryrun` stdout to a committed file (CLAUDE.md §9).
- New test cases: a divergent-fan-out fixture (mutate-between-Sends, the ADR 0104 §2.1 shape) previews
  per-destination bytes under CLI dryrun when the setting is ON; explicit False restores single-state preview;
  `check`'s dryrun sub-check disposition expectations unchanged.
- No store/SQL Server surface — no server-DB CI legs needed.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict) → `QT_QPA_PLATFORM=offscreen pytest -q`.
- `dryrun --trace` remains byte-identical to plain `dryrun` under both setting values (the contract the passthrough
  preserves).
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
