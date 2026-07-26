# DEMAND-GATE-BACKLOG · S4 · Compression codec + cron scheduling

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S4` |
| **Wave** | 1 |
| **Status** | **🚧 In progress (ADR 0123, ADR 0011)** |
| **Effort** | L |
| **Backlog items** | #172 · #160 |
| **Build order** | #172 → #160 |
| **ADR(s)** | NEW — Compression codec (gzip/zip/deflate) + file-connector compress/decompress option; amend ADR 0011 — ADR 0011 amendment — cron/calendar next-fire for the timer source (lift the reserved-setting deferral) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | Yes |
| **Branch** | `dg-s4` (new.ps1 names branch after -Name) |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #172 | Gzip/zip compression codec + file-connector option | ○ open |
| #160 | Timer-source cron / calendar schedule | ○ open |

## Owned files / seams

- `messagefoundry/parsing/compression.py (NEW pure module; CompressionError(ValueError)), parsing/__init__.py, messagefoundry/__init__.py`
- `messagefoundry/transports/file.py (FileDestination._write compress; FileSource._scan_once gunzip BEFORE the _looks_like_hl7 sniff/AV scan/batch split; decompressed-size ceiling)`
- `messagefoundry/transports/timer.py (remove cron NotImplemented raise; pure stdlib 5-field next-fire evaluator; recompute per-tick sleep)`
- `messagefoundry/config/wiring.py (File() ~L980 gzip knobs; Timer() ~L1019 cron_expression kwarg — disjoint factories)`

## Notes, PHI & gotchas

#172 IS a PHI surface (added to the census): gzip-out writes PHI to disk (same channel FileDestination already writes) AND gunzip-in decompression-bomb DoS: _oversize caps only the COMPRESSED input (st_size); MUST add a decompressed-size ceiling that also bounds post-split expansion, and decompress must precede the AV/ICAP scan and the _looks_like_hl7 sniff. Corrupt/oversized archive → ERROR/.error, never accept-and-drop; never log decompressed bodies. Restrict the connector compress option to single-stream gzip (leave multi-entry zip to a Handler-composed codec call). #160: prefer a pure-stdlib DST-aware evaluator (zoneinfo already used); croniter is a NEW locked dep needing owner-approved DEP-1 lock refresh — record the choice in the amendment. Cron must NOT fire at t=0 and must not busy-loop when next-fire is in the past. Do not conflate with ADR 0095 ActiveWindow. Two disjoint items sharing only different wiring.py factories (File() vs Timer()).

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s4\`, branch \`s4-compression-cron\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
