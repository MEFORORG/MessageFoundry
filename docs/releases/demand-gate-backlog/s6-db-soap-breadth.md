# DEMAND-GATE-BACKLOG · S6 · DB stored-proc OUT-param capture + WSDL import codec

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S6` |
| **Wave** | 1 |
| **Status** | **🚧 In progress (ADR 0122, ADR 0013)** |
| **Effort** | L |
| **Backlog items** | #67 · #69 |
| **Build order** | #67 → #69 |
| **ADR(s)** | amend ADR 0013 — ADR 0013 amendment — DATABASE capture of stored-proc OUT parameters + scalar return value; NEW — WSDL import — pure SOAP operation/message type-tree + envelope validation on the hardened [xml] extra (no zeep) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | Yes |
| **Branch** | `dg-s6` (new.ps1 names branch after -Name) |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #67 | Stored-procedure OUT-param / return-value binding | ○ open |
| #69 | WSDL import — SOAP type-tree + validate-against-WSDL | ○ open |

## Owned files / seams

- `messagefoundry/transports/database.py (DatabaseDestination.__init__ capture knobs; send() pre-commit {?=CALL}/OUT bind+readback; _capture merge, never raises)`
- `messagefoundry/config/wiring.py (widen the DATABASE capture gate ~3041-3048 via an explicit opt-in flag, NOT by loosening the 'output' substring test)`
- `messagefoundry/parsing/xml/wsdl.py (NEW pure module reusing harden.parse_bytes + schema.validate_against), parsing/xml/__init__.py + errors.py`

## Notes, PHI & gotchas

#67 OUT/return scalars are PHI-class like a result-set → ride the existing AES-256-GCM response table, body-gated GET /messages/{id}/responses; never log at INFO+; keep capture bounds; _capture must not un-succeed the write. Same-cursor pre-commit read only (never a post-commit SELECT); gate via explicit opt-in flag; record the proc-internal-transaction atomicity risk (a proc that COMMIT/ROLLBACKs internally can defeat the pre-commit-capture assumption). #69 envelope validation runs over PHI SOAP bodies → PHI-safe failure reporting (path + reason category only, never the element value); untrusted docs through harden.parse_bytes (XXE/DTD off); keep remote schema fetch disabled AND lock the DISTINCT wsdl:import resolution path to no-network (a separate code path NOT auto-covered by the existing xmlschema no-network config). No new deps ([sqlserver] + [xml] already locked; AVOID zeep). Both P3 demand-gate.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s6\`, branch \`s6-db-soap-breadth\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
