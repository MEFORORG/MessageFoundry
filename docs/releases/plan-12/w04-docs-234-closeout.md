# PLAN-12 · Wave 4 · #234 close-out sweep + follow-up filing

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `docs-234-closeout` |
| **Wave** | 4 (solo, last) |
| **Status** | ✅ **Complete** (2026-07-16 — full gauntlet green on the merged tree; #240/#241 filed via alloc.ps1) |
| **Effort** | 0.5 |
| **Backlog items** | #234 (Phase 4 of 4) |
| **ADR** | No — records that full-replace semantics were deliberately retained (the ADR 0007 flip condition was NOT taken) |
| **Store schema / 3-backend** | No |

## Items

| Item | Title | Status |
|---|---|---|
| #234 (P4) | Full-gauntlet sweep + BACKLOG flip + follow-up item filing + docs note | ✅ built (this PR) |

## Owned files / seams

`docs/BACKLOG.md` (#234 flip + **the new follow-up item — this plan's ONLY number allocation**) ·
`docs/CONNECTIONS.md` (note: the GUI/CLI editor now preserves every read-schema field; unknown posted keys fail
loud) · `docs/adr/` **expected UNCHANGED** (assert no amendment needed since full-replace kept).

## The work

1. **Full-gauntlet sweep on the final merged tree** (post any interleaved #230/#238/#235 merges): `ruff check` +
   `ruff format --check` → `mypy messagefoundry` (strict) → `QT_QPA_PLATFORM=offscreen pytest -q` →
   `cd ide && npm run typecheck && npm run compile && npm run test:unit`.
2. **File the follow-up backlog item** via `pwsh -NoProfile -File scripts/coord/alloc.ps1 -Kind backlog -Title "…"`
   — NEVER grep for the next number; heading + entry in the same commit. Contents: the same silent-strip idiom in
   the sibling writers (`config/codeset_edit.py` / `config/alerts_edit.py`), **plus the create/clone/wizard
   name-collision full-replace overwrite hole if [w03-ide-234-merge-fix](w03-ide-234-merge-fix.md) re-scoped it**.
3. **Flip BACKLOG #234 to built** — with the **corrected** casualty accounting (verdict-corrected: **19
   per-direction slots / 16 distinct keys INCLUDING inbound `metadata`** — not the entry's original list;
   `source_ip_allowlist` called out as a security regression), and record that **full-replace semantics were
   deliberately retained** (no ADR 0007 amendment; the merge-on-absent flip condition was evaluated and rejected).
4. `docs/CONNECTIONS.md` note per above.

## Dependencies

- **Gate: [w03-ide-234-merge-fix](w03-ide-234-merge-fix.md) merged** (and transitively S3). Runs LAST so the sweep
  covers the fully-merged tree.
- W4 is solo — no BACKLOG.md contention (W3's touch belonged to the #235 flip alone).

## Notes & gotchas

- The wrong-arithmetic failure mode is real: publishing the design's uncorrected "29 keys"/18-item list would put a
  wrong "corrected" ledger entry into the record — **the exact failure class #234 exists to close.** Use the §E.b
  numbers from the master.
- The pre-commit ledger hook enforces the allocation (a number not allocated to THIS worktree is rejected);
  `install-git-hooks.ps1` installs it into the shared `.git/hooks`.

## Verification — Definition of Done

- The complete CLAUDE.md §5 gauntlet green on the final merged tree (engine + ide legs).
- Follow-up item allocated through the ledger gate; index/heading in the same commit.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
