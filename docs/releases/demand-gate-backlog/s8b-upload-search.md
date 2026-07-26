# DEMAND-GATE-BACKLOG · S8b · Offline uploaded-logs subsystem + saved/layered search presets

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S8b` |
| **Wave** | 5 |
| **Status** | **○ Not started** |
| **Effort** | XL |
| **Backlog items** | #125 · #126 · #151 |
| **Build order** | #125 → #126 → #151 |
| **ADR(s)** | NEW — Offline uploaded-logs viewer — connection-decoupled file upload, browse, per-message resend (multipart dep vet, PHI-at-rest posture); (decision note) Uploaded-file deletion + audit (section under the #125 uploaded-logs ADR); NEW — Per-user saved & layered Log-Search filter presets (extends ADR 0046 search seam) |
| **Store schema / 3-backend** | Yes |
| **Parallel-safe** | No |
| **Branch** | `claude/s8b-upload-search` |
| **Depends on** | 125, 151 |

## Items

| Item | Title | Status |
|---|---|---|
| #125 | Uploaded Logs page — import & browse external files offline | ○ open |
| #126 | Delete an uploaded data file from the server | ○ open |
| #151 | Saved / layered Log-Search filter presets | ○ open |

## Owned files / seams

- `messagefoundry_webconsole/pages/ + routes/ (NEW uploaded-logs page + upload/list/browse/resend/save/delete; save/recall/layer preset UI), routes/search.py, pages/messages.py`
- `messagefoundry/api/app.py + api/models.py (upload/list/browse/delete + preset CRUD + layered-query composer over search_messages — COUPLED with S7b #124's basic-filter export)`
- `messagefoundry/parsing/split.py (split_batch), the store.reingress seam (ADR 0090)`
- `messagefoundry/store/store.py + sqlserver.py + postgres.py + base.py (NEW per-user search_presets table — ADR 0045 roles-migration precedent)`
- `messagefoundry/auth/permissions.py (deny-by-default upload/browse/delete permissions), config/settings.py (uploaded-files storage dir)`
- `messagefoundry_webconsole/static/app.js — HOTSPOT shared with S7b/S8a (all different waves)`

## Notes, PHI & gotchas

STORE-SERIALIZED: this is the THIRD/LAST store slot — must land AFTER S3a and S1b; never co-wave with them (waves 3/4/5). MAJOR new PHI surfaces. #125 puts real HL7 PHI at rest OUTSIDE the AES-256-GCM store — encrypt or explicitly document the tier (PHI.md data-at-rest inventory), audit every access, step-up gate like content search, never log bodies at INFO+; prefer filesystem storage to keep it decoupled. #126 delete is destructive/irreversible → confirm step + audit row + path-traversal validation on the attacker-influenced identifier. #151 saved content/field_value criteria are PHI-shaped (routes/search.py deliberately drops the content term across the step-up redirect) → encrypt the preset column (store/crypto.py) + step-up + audit, OR restrict presets to metadata-only fields. NEW DEP python-multipart (verify exists → pyproject + re-lock; OWNER-APPROVED — contradicts the no-multipart stance in routes/core.py; or hand-parse with stdlib). VERIFIER GAP for #125: store.reingress presupposes an existing origin store row keyed by origin_message_id — an uploaded (never-ingested) file has none, so #125 needs a distinct inject/ingest path, not naive reingress reuse. #151 layering = AND-compose over typed search_messages params, bounded by ADR 0046 caps. #126 hard-depends on #125. Follow ADR 0045 roles-migration for the 3-backend table. Shares api/app.py (disjoint routes) with S10 in wave 5 — coordinate.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s8b\`, branch \`claude/s8b-upload-search\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** this session edits the store — run SQLite + Postgres + SQL Server (win CI) parity tests; coordinate the ADR 0111 schema-hash bump; respect the store-serialization order.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
