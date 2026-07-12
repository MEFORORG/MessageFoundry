# PLAN-11 · Wave 7 · Connection lifecycle & active-window scheduling

> **Phase document** — one of the per-session build docs split out of the monolithic [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md) on 2026-07-11. **This file is the maintainable source of truth for this session's status** — when its items land, update the Status field + the Items table here (and the one-line pointer in the [dir index](README.md)). Shared coordination rules, the contention matrix, and full wave sequencing live in the [master index](../MULTISESSION-PLAN-11.md).

| | |
|---|---|
| **Session** | `connection-lifecycle-scheduling` |
| **Wave** | 7 |
| **Status** | **✅ Complete** |
| **Effort** | 11 |
| **Backlog items** | #109 · #147 |
| **ADR** | **0095** — RegistryRunner active-window scheduler + credential-fault lane-stop seam. |
| **Store schema / 3-backend** | No. |

## Items

| Item | Title | Status |
|---|---|---|
| #109 | Invalid-credential sender auto-stop (partner-account lockout protection) | ✅ shipped #966 (ADR 0095) |
| #147 | Per-connection active-window scheduler | ✅ shipped #966 (ADR 0095) |

## Owned files / seams

`pipeline/stage_dispatcher.py`, `transports/remotefile.py`, `config/settings.py`, `transports/base.py`, `config/wiring.py`, `pipeline/wiring_runner.py`, `config/connections_file.py`, `console/connections.py`, `console/client.py`

## Dependencies

None. Disjoint from the W7 log-uploaded session.

## Notes & gotchas

**✅ Both shipped 2026-07-12 (#966, ADR 0095).** One `RegistryRunner`/`stage_dispatcher` seam, two behaviours reusing the existing per-connection start/stop path: #147 a declarative pydantic `Schedule` (day-set + local time-of-day windows + IANA tz + `invert`), `schedule=None` = always-on byte-identical, one cooperatively-cancellable scheduler task per scheduled connection with an injectable `schedule_clock`; #109 a `credential_fault` marker (FTP/SFTP login-refused only) → immediate lane STOP + `store.release_claimed` retains the row UN-ERRORED (no dead-letter, no re-auth lockout storm), `credential_fault_policy=stop|dead_letter`. Adversarial review verified the retain-not-dead-letter property + no re-claim storm. **Real-FTP lockout + clock-driven soak validation → PLAN-11 Wave 19.** Owns W7 settings + wiring + `wiring_runner.py`.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests).
- **New engine seam — ratify the ADR FIRST; do not write code ahead of it.** ADR next-free on `origin/main` is **0089**.
- Every PR: `git merge main` first (the CI gate hangs otherwise); **no `Co-Authored-By: Claude` trailer** (the CLA bot fails on it).
- The finishing PR carries `BACKLOG #N` and flips that item's ✅ banner in `docs/BACKLOG.md`.
- Re-check in-flight file ownership before starting (`git worktree list`, `gh pr list --state all`, `git log origin/main`) — a parallel session may already own or have merged a hotspot file.

---
_Last reconciled: 2026-07-11 against `origin/main` @ 08f0b0c. Master index: [MULTISESSION-PLAN-11](../MULTISESSION-PLAN-11.md)._
