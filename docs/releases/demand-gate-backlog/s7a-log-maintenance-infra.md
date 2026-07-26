# DEMAND-GATE-BACKLOG · S7a · Log-maintenance infra — retention pass cap + engine-managed log file (marginal)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S7a` |
| **Wave** | 6 |
| **Status** | **○ Not started** |
| **Effort** | L |
| **Backlog items** | #121 · #122 |
| **Build order** | #121 → #122 |
| **ADR(s)** | (decision note) Time-boxed retention/log-maintenance pass (between-phase cap; VACUUM non-interruptible); NEW — Opt-in engine-managed application-log file lifecycle with fail-closed connection stop on unwritable log |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `claude/s7a-log-maintenance-infra` |
| **Depends on** | 171 |

## Items

| Item | Title | Status |
|---|---|---|
| #121 | Maximum log-maintenance task duration cap | ○ open |
| #122 | Corrupted application-log detection, rollover, and connection-stop | ○ open |

## Owned files / seams

- `messagefoundry/pipeline/retention.py (run_once between-phase deadline; RetentionPass.capped; don't advance _last_wal/_last_vacuum_day for a skipped phase)`
- `messagefoundry/config/settings.py (RetentionSettings.max_pass_seconds — own FLOAT validator like _non_negative_wal, NOT the int-days list; LoggingSettings opt-in log_file knobs)`
- `messagefoundry/logging_setup.py (opt-in file handler with rename+roll on write failure + injected fail-closed callback; _install_phi_filters must attach RedactionFilter+ControlCharScrubFilter) — HOTSPOT shared with S7b (S7b's set_runtime_level MUST land first)`
- `messagefoundry/pipeline/engine.py or wiring_runner.py (wire injected stop-callback + record rollover audit), messagefoundry/__main__.py`

## Notes, PHI & gotchas

COUPLING: S7a and S7b both edit logging_setup.py; #122's file-handler work overlaps #171's set_runtime_level helper — S7b MUST land before S7a (waves 3 then 6). #121 metadata only. #122 adds a NEW at-rest PHI surface (engine-owned log file): the handler MUST carry RedactionFilter + ControlCharScrubFilter; rollover event is metadata-only; the #120 app-log sweep must never delete the actively-written engine log. #122 is an ARCHITECTURE reversal of the stdout-only/NSSM-rotation invariant — OWNER SIGN-OFF before build; strong candidate to keep demand-gated (stdout+NSSM+#50 metering cover most value). logging_setup MUST NOT import config/pipeline — the fail-closed stop is an INJECTED callback (non-async / scheduled onto the loop, never await from sync — reentrancy/deadlock hazard). VERIFIER: a log-write failure is PROCESS-WIDE, not one connection — the ADR must decide blast radius (all connections or process halt, not 'the affected connection'). Consider deferring 122 and shipping 121 alone.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s7a\`, branch \`claude/s7a-log-maintenance-infra\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
