# DEMAND-GATE-BACKLOG · S1b · Alert engine II — store (suspend/mute + escalation/schedule/content triggers)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S1b` |
| **Wave** | 4 |
| **Status** | **○ Not started** |
| **Effort** | XL |
| **Backlog items** | #143 · #81 |
| **Build order** | #143 → #81 |
| **ADR(s)** | amend ADR 0044 — ADR 0044 amendment — windowed suspend/mute of alert instances (and per-rule mute); NEW — Alert escalation tiers, schedule-aware thresholds, and content-triggered alerts (the #56 remainder) |
| **Store schema / 3-backend** | Yes |
| **Parallel-safe** | No |
| **Branch** | `claude/s1b-alert-store` |
| **Depends on** | 143 |

## Items

| Item | Title | Status |
|---|---|---|
| #143 | Alert suspend / mute (windowed) | ○ open |
| #81 | Alert escalation tiers + day/time thresholds + content alerting | ○ open |

## Owned files / seams

- `messagefoundry/store/store.py + sqlserver.py + postgres.py (alert_instance block — add suspend column then escalation state; SQL Server via the COL_LENGTH-gated ADD-COLUMN DDL, NOT a symbol named _ADDITIVE_COLUMNS)`
- `messagefoundry/store/base.py (QueueStore alert methods)`
- `messagefoundry/pipeline/alert_sinks.py (_emit suspend gate; escalation logic; schedule-aware decide)`
- `messagefoundry/config/settings.py (AlertRule mute/schedule/escalation/content-match)`
- `messagefoundry/api/app.py (POST /alerts/{id}/suspend + resume), api/models.py (AlertInstanceInfo)`
- `messagefoundry_webconsole/routes/monitoring_writes.py + pages/monitoring.py (suspend control)`

## Notes, PHI & gotchas

STORE-SERIALIZED: this is the SECOND store slot — must land AFTER S3a (processed_files) and BEFORE S8b (search_presets); never co-wave with either (waves 3/4/5). #81 content-triggered alerts inspect message content: match-only, off the routing hot path; emitted event MUST stay PHI-free (connection + rule id + boolean/label), never the matched field value. VERIFIER PURITY GAP: a Handler that emits a content-triggered alert is a side effect — a stage re-run re-emits it; the ADR must reconcile Handler-emitted alerts with transforms-must-be-pure at-least-once (rely on the (event_type,connection) throttle/dedup, or route content-triggers off the transform path). Suspend gates NOTIFICATION only (ADR 0044 AC-3), never hides the open condition/count. Timed escalation is partly DECLINED (ADR 0014/#93) — keep escalation occurrence/severity-driven; any timed re-eval sweep must be leader-gated. Serialize 143 then 81 within the session (both ALTER alert_instance). Shares api/app.py (disjoint routes) with S3b in wave 4 — coordinate.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s1b\`, branch \`claude/s1b-alert-store\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** this session edits the store — run SQLite + Postgres + SQL Server (win CI) parity tests; coordinate the ADR 0111 schema-hash bump; respect the store-serialization order.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
