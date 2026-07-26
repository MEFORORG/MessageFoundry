# PLAN-12 · Wave 2 · #235 real-server tests + rotation coverage (the T-SQL proof)

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `store-235-ci-tests` |
| **Wave** | 2 |
| **Status** | ✅ **Complete** (2026-07-16 — battery landed in this session's PR; its green server-DB legs are the W3 hard gate) |
| **Effort** | 1 |
| **Backlog items** | #235 (Phase 2 of 3) |
| **ADR** | No (the ADR 0006 amendment lands with the W3 flip) |
| **Store schema / 3-backend** | **Yes — this session IS the 3-backend proof.** Its green server-DB CI legs are the HARD GATE for the W3 flip. |

## Items

| Item | Title | Status |
|---|---|---|
| #235 (P2) | Real-server reference-set tests + first-ever reference-row rotation coverage (all three backends) | ✅ built (this PR) |

## Owned files / seams

`tests/test_sqlserver_store.py` · `tests/test_reference_sets.py` (SQLite rotation gap) · `tests/test_postgres_store.py`
(PG rotation gap). **No source files.**

## The work

1. **Fixture hygiene FIRST:** the clean-slate DELETE list (`test_sqlserver_store.py:57-81`) gains `reference` +
   `reference_version` (no FK — anywhere before `messages`). Without this, leaked reference rows break the **exact
   `assert reencrypt_to_active() == 6`** at `:879` the moment the new rotation pass exists.
2. Snapshot write/read + atomic version flip + reopen-reloads-active + **empty-set-stays-present** tests (mirror
   `test_postgres_store.py:1031-1051`).
3. Follower **converge** read-through via a second `SqlServerStore.open` handle on the same DB — idempotence + the
   empty-snapshot case (mirror `test_postgres_store.py:1054-1090`) — **plus the pin that
   `converge_reference_cache()` returns `[]` after the leader's own write** (post-commit bookkeeping set both cache
   and versions).
4. **At-rest proof:** `SELECT value FROM reference` asserts the `mfenc` ciphertext prefix while `reference_view()`
   serves plaintext; a non-ASCII JSON value round-trips through pyodbc/aioodbc NVARCHAR(MAX) (SQLite analog:
   `test_reference_sets.py:157-173`).
5. **Over-long-key guard trio (verdict-corrected, UTF-16 semantics):** a 450-code-unit key **passes**; a
   451-code-unit key **fails the guard** (named error, prior snapshot stays live, no raw key in the message); an
   **astral-plane key under 450 code points but over 450 UTF-16 code units fails the GUARD, not the INSERT**.
6. **Collation round-trip (verdict-corrected):** case-differing keys load and read back distinctly (binary collation
   — no PK-duplicate mid-transaction).
7. **No-key→key reopen migration test:** rows written under `IdentityCipher` (plaintext JSON) are encrypted by the
   new `_encrypt_existing_rows` reference pass on reopen with a key.
8. **Rotation:** a reference row written under k1 rotates to k2 via `reencrypt_to_active` and still decrypts — and
   the same **first-ever reference-row rotation test lands on the two donors** (`test_reference_sets.py` SQLite;
   `test_postgres_store.py` PG), closing the pre-existing gap.

## Dependencies

- **Gate: [w01-store-235-port](w01-store-235-port.md) merged.**
- **Owner-approved MID-STREAM branch push** — the path-gated CI legs are the only authoritative T-SQL proof:
  `ci.yml:404`'s alternation matches `messagefoundry/store/` and `tests/test_(sqlserver|postgres)`, and the existing
  named steps (sqlserver-store at ~:537-539 — a **2022 + 2025 image MATRIX**, wrapped in `retry-native-crash.sh` for
  the known pyodbc 5.3.0/py3.14 segfault noise — and the postgres-store job ~:702) pick the extended files up
  with **zero ci.yml edits**.

## Notes & gotchas

- **Local pytest silently skips without `MEFOR_TEST_SQLSERVER=1` / `MEFOR_TEST_POSTGRES=1`** — a locally-green run
  proves nothing about the T-SQL. The CI legs are the deliverable's proof; their green state is the **HARD GATE**
  for [w03-store-235-flip](w03-store-235-flip.md).
- PHI: reference keys may be PHI — assert the guard's error text carries set name + key length/ordinal/hash only.
- The self-hosted win2025 leg (`selfhosted-win2025-sql.yml`) is corroborating, not blocking.

## Verification — Definition of Done

- The new tests ARE the deliverable. Locally: full `QT_QPA_PLATFORM=offscreen pytest -q` (SQLite rotation test runs
  unconditionally); backend suites against local containers if available.
- **Authoritative: sqlserver-store (both matrix images) AND postgres-store legs green on the pushed PR branch.**
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves the mid-stream push AND the
  merge.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
