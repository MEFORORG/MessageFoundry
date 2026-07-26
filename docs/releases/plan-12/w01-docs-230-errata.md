# PLAN-12 · Wave 1 · #230 docs errata — kill the stale tracker

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status** —
> when its work lands, update the Status field here (and the status cell in the [dir index](README.md)). Shared
> rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `docs-230-errata` |
| **Wave** | 1 — **must merge before any other #230 work starts anywhere** |
| **Status** | ✅ Done (2026-07-16) — errata committed on `plan12-docs-230-errata`; PR/merge via coordinator |
| **Effort** | 0.5 |
| **Backlog items** | #230 (Phase 1 of 4) |
| **ADR** | No new ADR — dated factual **errata** only (ADR 0104:3 status line; ADR 0089:3-5,:73) |
| **Store schema / 3-backend** | No |

## Items

| Item | Title | Status |
|---|---|---|
| #230 (P1) | Kill the stale tracker: BACKLOG entry + ADR 0104/0089 errata | ✅ done (2026-07-16) |

## Owned files / seams

`docs/BACKLOG.md` #230 entry (:6811–6829) · `docs/adr/0104-copy-on-send-…md:3` ·
`docs/adr/0089-recognition-first-lens-native-idioms.md:3-5,73` · `docs/adr/README.md` (check the 0104/0089 rows for
the same stale phrases)

## The work

Correct three stale claims **before any build session can act on them**:

1. **BACKLOG #230:6813** ("Only remainder: the Q3 IDE field picker") and **:6824-6827** — rewrite: the Steps-view
   picker **SHIPPED** in PR #1001 (commit `5b90a695`, authored **2026-07-13 UTC** — 2026-07-12 is a local-timezone
   rendering), P1 picker + P2 scoping + P3 round-trip badges, including the "centralize `generators/adt.py`'s map"
   resolver (now `messagefoundry/hl7structures.py:34-92` + the `messagefoundry hl7structures` CLI + the CI sync
   test). The genuine remainder = **ADR 0104 §2.3 Step 1** (inline autocomplete extension) + optional fast-follows.
2. **ADR 0104:3** — status-line phrase "Q3 §2.3 HL7 field picker building" → "Q3 §2.3 Steps picker shipped
   (PR #1001); §2.3 Step 1 inline-autocomplete extension outstanding".
3. **ADR 0089** — dated erratum on the line-5 Related and §7:73: the "Phases A–E map to BACKLOG #226–#230" numbering
   is stale (live #226–#229 are unrelated ledger items — #226 closed to the migration estate, #228 sidebar search
   shipped, #229 A4b guard); state that phases are tracked per-item at filing time instead.

**Fact discipline (verdict-corrected):** describe `tests/test_ide_artifacts.py:28` as a **recompute-and-compare
parsed-JSON equality gate**, NOT "byte-equal"; cite `parsing/message.py:248-250` (`set()`) alongside `:100`
(`field()`) for any kwarg claim; verify every cited PR/commit against `git log` before committing.

## Dependencies

None — buildable now. **The tracker-guided #230 build (S5) gates on this merging** (a session that trusts the
current entry as written will rebuild `ide/src/hl7Picker.ts` and collide with main). The optional S6 is
tracker-independent and exempt.

## Notes & gotchas

- Docs-only; **no ADR/BACKLOG numbers allocated** (no `alloc.ps1`). The ledger gate passes untouched.
- Errata are dated factual corrections — **no ratified decision text changes.**
- Wave-1 `docs/BACKLOG.md` co-toucher is `ide-238-setup` (#238 entry, ~175 lines away — line-disjoint; serialize the
  merges anyway).

## Verification — Definition of Done

- Docs-only PR; rides the docs-only CI fast path; the always-on ledger gate passes (no numbers touched).
- Every cited PR/commit ref manually verified against `git log` (e.g. `5b90a695` is a verified ancestor of
  `origin/main`).
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves push/PR.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
