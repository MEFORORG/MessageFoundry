# DEMAND-GATE-BACKLOG · S7b · Logging surfaces — runtime verbosity + redacted log viewer + bulk body export

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S7b` |
| **Wave** | 3 |
| **Status** | **○ Not started** |
| **Effort** | M |
| **Backlog items** | #171 · #124 |
| **Build order** | #171 → #124 |
| **ADR(s)** | (decision note) Runtime (ephemeral, reset-on-restart) log-verbosity control + PHI-redacted paginated log-tail viewer; NEW — Bulk raw-message-body export from a search result (step-up, audited PHI egress) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `claude/s7b-logging-surfaces` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #171 | Runtime log-verbosity control + in-product log viewer | ○ open |
| #124 | Batch-export message bodies from a connection log to a file | ○ open |

## Owned files / seams

- `messagefoundry/logging_setup.py (set_runtime_level helper — root + _UVICORN_LOGGERS; validate against LOG_LEVELS) — HOTSPOT: land BEFORE S7a's #122 file-handler work`
- `messagefoundry/api/app.py (GET/PATCH /logging/level; GET /logs/tail reusing support/redact.redact_log_text + a _log_tail-style reader; streaming export route mirroring /audit/export, require_step_up(MESSAGES_VIEW_RAW), enforce_phi_read_hop, _scope, messages_export audit counting EVERY body)`
- `messagefoundry/auth/permissions.py (new LOGS_VIEW / optional MESSAGES_EXPORT; BUILTIN_ROLE_PERMISSIONS)`
- `messagefoundry_webconsole/static/app.js (verbosity control, paginated viewer, save-selected/save-all + progress/stop) — HOTSPOT shared with S8a/S8b (all different waves)`

## Notes, PHI & gotchas

#124 is the LARGEST PHI surface in the cluster — bulk raw bodies exported to an operator-chosen file: MESSAGES_VIEW_RAW + step-up, per-channel _scope on every streamed row, enforce_phi_read_hop, dedicated audit that counts every exposed body so a scripted save-all can't harvest unaudited; PHI-safe-destination is the operator's responsibility. Prefer looping get_message per id — AVOID a 3-backend bulk iterator (would flip store_schema true). SEARCH-SURFACE COUPLING: #124's selection reuses /messages/search + search_messages, which S8b (125/126/151) also extends (layered queries/presets) — keep #124 scoped to BASIC search filters for MVP; if export-from-layered-preset is later wanted, sequence it AFTER S8b's search work. #171 viewer exposes redacted app-log content to the browser (best-effort regex redaction, residual single-token PHI) → RBAC + audit like message_view; it is a genuine new PHI read surface the 'light' ADR must own. VERIFIER REFUTED: configure_logging does NOT re-run on /config/reload — a runtime level override survives a reload and resets only on PROCESS RESTART; document 'ephemeral, reset on restart'. New routes must inherit enforce_phi_read_hop/_scope exactly as /messages/search. Both edit api/app.py + app.js → serialize within the session.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s7b\`, branch \`claude/s7b-logging-surfaces\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
