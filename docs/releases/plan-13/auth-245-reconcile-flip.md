# PLAN-13 · Wave 1 · #245 + #246 — reconcile the already-built branch to main

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).

| | |
|---|---|
| **Session** | `auth-245-reconcile-flip` |
| **Wave** | 1 |
| **Status** | 🔢 Not started — **owner-gated; the build is already committed** |
| **Effort** | 0.5 |
| **Backlog items** | #245 (all cells) + #246 (rides the same branch) |
| **ADR** | None to write — the ADR 0077 7.5.1 amendment is **already committed** on `asvs-wp245` (`ab1bad6f`) |
| **Store schema / 3-backend** | No — step-up grants are process-local in-memory |

## CRITICAL — do NOT re-build 7.5.1

The entire #245 deliverable is committed on branch **`asvs-wp245`** (sibling worktree
`C:/Users/<you>/Code/MessageFoundry-asvs-wp245`, tip `597d6eb9`, **unpushed**), a **clean descendant of `origin/main` @
`be1fbbab`**: `ab1bad6f` (7.5.1 part a **and** b + the ADR 0077 amendment), `844be7e1` (the last-admin-guard PATCH test
follow-up), `597d6eb9` (the 2026-07-17 11-agent re-score — already superseded the verdict-of-record + deleted
`_wp245-plans/`). #246 is on the same branch (`410349fd` folded the delegated proxy-TLS rows into the L3 register). The
current worktree branch `claude/asvs-drive-to-pass` is a **superseded parallel line** (re-did WP242-244 individually;
squash `ccddf53e` is not its ancestor) — do **NOT** merge it.

## The work (reconcile only)

1. In the **sibling worktree** (the nested plan worktree is checkout-blocked by worktree-gate Rule-3): `git merge main`
   into `asvs-wp245`; confirm the full-suite leg (ruff + mypy over `messagefoundry_webconsole`) **and** the separate
   `pytest packaging/messagefoundry-webconsole/tests` leg green.
2. **OWNER:** approve push → open PR → approve → merge to main. **Ratify the already-produced re-score (`597d6eb9`)** as
   the verdict-of-record — **do NOT re-run it.** 7.1.3 build-or-accept is already resolved as **accept** (`26432cc2`).
3. #245 / #246 banners flip ✅ with the merge (already updated on-branch).

## Owned files / seams

(sibling worktree) `docs/BACKLOG.md` (#245 @7121, #246) + the re-score docs — **no source build.**

## Notes & gotchas

- On a known-flaky `sql server (store + connector)` leg (pyodbc/py3.14 segfault, mkleehammer/pyodbc#1459, unrelated —
  grants are process-local, backend-independent): `gh run rerun <id> --failed`.
- **No `Co-Authored-By: Claude` trailer** (CLA gate). Line-disjoint with the other W1 BACKLOG touchers.

## Verification — Definition of Done

- CI legs green on the PR; owner-ratified re-score is the verdict-of-record; #245/#246 banners ✅ on main. Do **not**
  self-certify Pass without the ratified re-score.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
