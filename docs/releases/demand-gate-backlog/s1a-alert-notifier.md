# DEMAND-GATE-BACKLOG · S1a · Alert engine II — notifier (recipients, templates, HA/DR events, control action)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S1a` |
| **Wave** | 2 |
| **Status** | **○ Not started** |
| **Effort** | L |
| **Backlog items** | #146 · #138 · #145 · #144 |
| **Build order** | #146 → #138 → #145 → #144 |
| **ADR(s)** | amend ADR 0014 — ADR 0014 amendment — per-rule alert recipient override; NEW — Operator-editable alert-email templates with a non-PHI variable allowlist; amend ADR 0014 — ADR 0014 amendment — HA leadership + DR transition alert events (retires the 'no protocol/engine change' self-scope); NEW — Alert-rule connection-control action (auto stop/restart on fire) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `claude/s1a-alert-notifier` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #146 | Per-rule alert recipients | ○ open |
| #138 | Customisable alert-email subject and body templates | ○ open |
| #145 | HA / DR failover event alert | ○ open |
| #144 | Alert-triggered connection-control action | ○ open |

## Owned files / seams

- `messagefoundry/config/settings.py (AlertRule, AlertsSettings, _ALERT_EVENT_TYPES)`
- `messagefoundry/pipeline/alert_sinks.py (_RuleDecision, AlertRuleSet.decide, _emit, _handle, EmailTransport)`
- `messagefoundry/pipeline/alerts.py (AlertSink Protocol + LoggingAlertSink)`
- `messagefoundry/config/alerts_edit.py (_RULE_FIELDS)`
- `messagefoundry/pipeline/cluster.py + cluster_sqlserver.py (thread alert_sink, emit at leadership transitions — EDIT BOTH)`
- `messagefoundry/pipeline/dr.py (emit on existing self._alert_sink at activate/release)`
- `messagefoundry/pipeline/wiring_runner.py (restart_inbound/restart_outbound as the injected control seam)`
- `messagefoundry/api/app.py (lifespan wiring ~3348-3420; injected control callback), api/models.py`

## Notes, PHI & gotchas

#138 is the PHI item: alert-email templates MUST enforce a CLOSED non-PHI variable allowlist (severity/type/connection/timestamps/counts/cooldown/rule id) and REJECT any other reference at config-load; HTML alternative must be escaped; keep a plain-text part. #146 recipient addresses are operator config, not PHI — pop the internal _recipients key before any webhook payload. #145 events carry node/connection/role/epoch only. Build 146 → 138 → 145 → 144 serially (heavy alert_sinks.py/settings.py overlap). #144 must inject an async control callback (off-worker, never-raise), NOT import RegistryRunner; ADR cites the sink's decoupling + never-block emit contract (pipeline→pipeline import is layering-legal). #145 edits cluster.py AND cluster_sqlserver.py in lockstep; route any restored/failback inverse through _AUTO_RESOLVE (NOT _ALERT_EVENT_TYPES). CONTENDS api/app.py + api/models.py with S7b/S8a/S8b/S10/S11 — different routes (disjoint), but coordinate if concurrent.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s1a\`, branch \`claude/s1a-alert-notifier\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
