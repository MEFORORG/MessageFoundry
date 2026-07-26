# DEMAND-GATE-BACKLOG · S3b · File connector alternate Windows credential (UNC/SMB, win32 ctypes)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S3b` |
| **Wave** | 4 |
| **Status** | **○ Not started** |
| **Effort** | L |
| **Backlog items** | #111 |
| **Build order** | #111 |
| **ADR(s)** | NEW — Per-endpoint alternate Windows credential for File/UNC shares (win32 ctypes, no pywin32, no impersonation privilege) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `claude/s3b-file-alt-credential` |
| **Depends on** | None |

## Items

| Item | Title | Status |
|---|---|---|
| #111 | File-endpoint alternate Windows / network-share credentials | ○ open |

## Owned files / seams

- `messagefoundry/transports/file.py (wrap _run/_scan_once/_write/_probe_dir_writable in a credential context) — HOTSPOT shared with S3a: rebase on S3a; the credential context must WRAP S3a's new disposition/validation logic`
- `new win32 util (ctypes.windll — WNetAddConnection2W / LogonUser; mirror service.py:124/270 + the tray package + ADR 0113, all present on this branch)`
- `messagefoundry/config/models.py (credential sub-model, password via env()) — HOTSPOT (models.py) shared with S2/S3a/S8a, config/wiring.py (passthrough), api/app.py (credentialed test probe — disjoint route, shared with S1b in wave 4)`
- `docs/CONNECTIONS.md`

## Notes, PHI & gotchas

SERIALIZE AFTER S3a (wave 4, after S3a's wave 3): S3a and S3b edit transports/file.py + remotefile.py + config/models.py + config/wiring.py in the SAME methods — land S3a's file.py/models.py/wiring.py first, rebase S3b, and make the credential context wrap S3a's disposition/validation logic. Expands PHI-access surface: message files on a UNC share read/written under a new identity + a credential secret handled. Password only from env()/MEFOR_*, never source/tests/config/commit/logs (reuse remotefile._redact host:path-only). No payload bodies logged. Win32-only runtime (sys_platform gate + clear POSIX error); CI cannot exercise a real alt-cred UNC share — validate on Windows CI legs/manual. WNetAddConnection2W maps process-wide (collisions to same host); LogonUser+Impersonate is per-thread but must run blocking I/O on a dedicated impersonated thread. Release mapping/token on stop/reload. VERIFIER: ADR 0113 + tray package DO exist on this branch — cite them (plus service.py:124/270) as the ctypes-no-pywin32 precedent.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s3b\`, branch \`claude/s3b-file-alt-credential\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
