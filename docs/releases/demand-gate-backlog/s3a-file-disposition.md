# DEMAND-GATE-BACKLOG · S3a · File source disposition — startup dir validation + process-in-place dedup ledger

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S3a` |
| **Wave** | 3 |
| **Status** | **○ Not started** |
| **Effort** | L |
| **Backlog items** | #114 · #142 |
| **Build order** | #114 → #142 |
| **ADR(s)** | amend ADR 0031 — ADR 0031 amendment — opt-in File/RemoteFile startup directory validation (invalid → reported `failed`); NEW — Process-in-place file disposition + cross-backend processed-file dedup ledger (hashed filename key) |
| **Store schema / 3-backend** | Yes |
| **Parallel-safe** | No |
| **Branch** | `claude/s3a-file-disposition` |
| **Depends on** | 114 |

## Items

| Item | Title | Status |
|---|---|---|
| #114 | Directory validation toggle (perform vs suppress startup validation) | ○ open |
| #142 | 'Leave source file' — process-in-place file/FTP disposition | ○ open |

## Owned files / seams

- `messagefoundry/transports/file.py (FileSource/FileDestination; validate-on-start hook; after_read 'leave' branch; _candidates filter; record-after-success) — HOTSPOT shared with S3b (serialize S3a FIRST)`
- `messagefoundry/transports/remotefile.py (RemoteFileSource parity) — HOTSPOT shared with S3b`
- `messagefoundry/store/store.py + sqlserver.py + postgres.py (new processed_files ledger — HASH the filename key, not cleartext) + store/base.py (QueueStore protocol)`
- `messagefoundry/pipeline/wiring_runner.py (start_inbound → _start_inbound_unsafe:1779 probe when flag set; NOT build_check)`
- `messagefoundry/config/wiring.py (inbound/outbound factories), config/models.py (settings docs — HOTSPOT, doc-only, shared with S2/S3b/S8a)`

## Notes, PHI & gotchas

STORE-SERIALIZED: this is the FIRST store slot (wave 3) — must land before S1b and S8b; never co-wave with them. MUST land before S3b (they share transports/file.py + remotefile.py + config/models.py + config/wiring.py in the SAME methods _scan_once/_write/_probe_dir_writable/after_read); rebase S3b on this. #142 filename ledger: filenames can embed PHI (MRN). VERIFIER CORRECTION: the delivered_keys/resend_log precedent stores HASHES/IDS ONLY — the ADR must HASH the filename key (a derived id), not merely encrypt a cleartext-filename column. Content hash of a PHI body is a derived id, store-only, never logged at INFO+. Bound growth with an age/count prune. VERIFIER SEMANTIC GAP for #114: _probe_dir_writable's first line mkdir(parents=True, exist_ok=True) CREATES a missing dir before probing — reusing it verbatim silently creates a merely-missing dir and PASSES, not `failed`. If 'missing dir fails startup' is desired, add a no-mkdir exists check. Fix the ADR amendment rationale: the 'File connectors don't validate the dir' statement is from BACKLOG #114, NOT ADR 0031. Record processed AFTER emit success; file (not per-message) is the dedup unit for batch splits.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s3a\`, branch \`claude/s3a-file-disposition\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** this session edits the store — run SQLite + Postgres + SQL Server (win CI) parity tests; coordinate the ADR 0111 schema-hash bump; respect the store-serialization order.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
