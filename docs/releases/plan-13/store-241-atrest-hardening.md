# PLAN-13 · Wave 1 · #241 F1+F2 — SQL Server `state` at-rest + fail-closed keyless-open

> **Phase document** of [MULTISESSION-PLAN-13](../MULTISESSION-PLAN-13.md). Shared rules live in the master.

| | |
|---|---|
| **Session** | `store-241-atrest-hardening` |
| **Wave** | 1 |
| **Status** | 🔢 Not started — **DB-leg CI gate before done** |
| **Effort** | 2 |
| **Backlog items** | #241 findings 1 + 2 |
| **ADR** | No — increments ADR 0005 (transform-state at-rest) on the one backend that missed it + an error-quality fix on the ADR 0005/0006 eager-read paths |
| **Store schema / 3-backend** | **Yes** — SQL Server + Postgres CI legs are the only authoritative proof |

## Step 0 — claim the item (🚧, before any code)

Per [master §D](../MULTISESSION-PLAN-13.md#d-coordination-rules--gotchas): this session is the **W1 banner owner for #241**.
Before writing code, commit a **🚧 in-progress claim** on #241 in `docs/BACKLOG.md` (its own commit), naming the lane —
`> 🚧 **Status — in progress (lane `plan13-store-241`, branch off `origin/main`).**`. This is the only cross-session
signal that stops a sibling worktree double-building #241 (neither the worktree nor the ledger gate catches it). The
sibling `verify-241-snapshot-thread` (F3) does **not** write a second claim. Flip 🚧 → ✅ per *Definition of Done*.

## Items

| Item | Title | Status |
|---|---|---|
| #241 F1 | SQL Server composite-PK `state` at-rest encryption pass | 🔢 to build |
| #241 F2 | Fail-closed operator-facing error on keyless decode across all 6 eager-read seams | 🔢 to build |

## The work — navigate by SYMBOL, not the drifted banner line numbers

**Finding 1 (PHI at-rest completeness).** `SqlServerStore._encrypt_existing_rows` migrates messages/queue/outbox/users +
nullable PHI cols + `response` + `reference`, but **never** the composite-PK `state` table — so a no-key→key transition on
SQL Server alone leaves legacy `state` plaintext at rest (SQLite `store.py:1987-2003` and Postgres `postgres.py:1366-1368`
both migrate `state.value`). Add an **inline** `state` while-loop after the reference pass, **mirroring SQL Server's own
reference loop** — SS has **no** `_encrypt_existing_composite` helper; do **not** port Postgres's. Reuse the
`value <> '' AND NOT LIKE 'mfenc:%'` guard so a purged `''` never becomes ciphertext. Add a **3-backend migration-parity
test** enumerating every cipher-covered table.

**Finding 2 (keyless-open crash → operator error).** Across the **6** eager-read seams (reference + state reads on all 3
backends), on decode failure check `cipher.is_encrypted(...)` and **RAISE** a consistent operator-facing store error naming
the table + remedy ("store carries encrypted rows but no store key is configured") instead of a raw `JSONDecodeError`.
**Un-mask** SQL Server `_load_state_cache`'s current silent-skip of encrypted rows (it catches `(CipherError, ValueError)`
and skips — arguably worse). Likely a shared `decrypt+json.loads` helper + a new operator-facing error class in
`store/crypto.py` (today only `DbaDelegatedError` / `CipherError` exist). **Fail-closed, not degrade-open, not silent** — a
PHI hard rule.

## Owned files / seams

`store/sqlserver.py` (F1 `_encrypt_existing_rows`; F2 `_load_state_cache` + `_read_active_reference_snapshots`) ·
`store/postgres.py` + `store/store.py` (F2 state + reference reads) · `store/crypto.py` (shared helper + error class) ·
`tests/test_store_encryption.py` · `tests/test_sqlserver_store.py` · `tests/test_postgres_store.py` ·
`docs/BACKLOG.md` (#241 @7052).

## Dependencies

None to start. **Hard verify gate before "done":** the mssql service-container leg (`MEFOR_TEST_SQLSERVER=1` +
`MEFOR_STORE_*`) **and** the Postgres leg green on this PR — both findings were surfaced by those legs (PR #1075/#1078)
and local pytest silently skips the T-SQL. File-disjoint from `verify-241-snapshot-thread` (F3).

## Notes & gotchas

- Owns the #241 banner: record F1+F2 shipped, point at verify-241 for F3, note **F4 deferred** (build-only-if-recurs) so
  the item does not fully close.
- Ship F1 and F2 as **separate coherent commits**.
- Coordinate lightly with the live `sql-server-default-admin` worktree (off the hot claim path). `git merge main` before push.

## Verification — Definition of Done

- `ruff` + `ruff format --check` → `mypy --strict messagefoundry` → `pytest -q` (SQLite portions of the parity +
  keyless-open errors run locally) → **mssql + Postgres CI legs green** (the T-SQL proof).
- **No `Co-Authored-By: Claude` trailer**; owner approves the mid-stream push + PR.

---
_Authored 2026-07-17 against `origin/main` @ `be1fbbab`._
