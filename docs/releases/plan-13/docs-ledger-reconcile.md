# PLAN-13 · Wave 1 · Ledger reconciliation — flip the shipped/dead banners

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md).
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `docs-ledger-reconcile` |
| **Wave** | 1 |
| **Status** | 🔢 Not started — **merge FIRST** |
| **Effort** | 0.75 |
| **Backlog items** | none (banner-rot only; item-numbers disjoint from every build session) |
| **ADR** | No new number — flips ADR 0106 doc-status *Proposed → Accepted* (index-row Status cell same commit) |
| **Store schema / 3-backend** | No (docs only) |

## Why this merges first

The whole plan is designed against the corrected ledger. Building against the stale banners risks redoing shipped work
(the exact failure the reconciliation caught for #245). This session lands the corrected states before any build
session cites them.

## The work — flips (see master §E for the evidence table)

**Unambiguous ✅ (flip in this PR):** #209, #213 (PR #952 / ADR 0084) · #227 (PR #1008) · #218 (C1 / PR #868) ·
#215 (Phase 5 DECLINING) · #221 (ADR 0100 / PR #886) · #222 (ADR 0076 + 0103/0106/0108) · #239 (tray ADR 0113 /
PR #1084-#1088) · #48 (flip the glyph — text already says done). Also flip **ADR 0106** doc-status → *Accepted*
(palette shipped #1013/#1022) + its `docs/adr/README.md` row.

**Owner-ratify (flip only if ratified; else annotate + cite the superseding ADR):** #210 → ⛔ WITHDRAWN
(THROUGHPUT-STATUS 2026-07-12; ADR 0107/0114) · #217 → ⛔ DECLINED (ADRs 0069/0099/0107/0114) · #212 → owner-closed:
stays OFF (ADR 0107) · #211 → owner-closed: characterization-only (ADR 0114).

## Owned files / seams

`docs/BACKLOG.md` (the 13 banners above — **all disjoint item-numbers from every build session's banner**, so no
same-wave banner is co-owned) · `docs/adr/0106-*.md` status line · `docs/adr/README.md` 0106 row.

## Explicitly NOT touched

#207 / #208 / #220 / #229 / #240 / #241 / #245 / #246 banners — those belong to the build sessions. Never edit them here.

## Dependencies

None. Unblocks nothing structurally, but merging first prevents build-against-stale-ledger.

## Verification — Definition of Done

- No engine change → `ruff`/`mypy`/`pytest` are unaffected; the change is Markdown + the ADR status row.
- Each flip cites its PR/ADR in the banner and matches the master §E table.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves push/PR. Serialize this merge
  **before** the other W1 BACKLOG touchers.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`. Master: [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md)._
