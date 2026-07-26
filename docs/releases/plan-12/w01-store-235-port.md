# PLAN-12 · Wave 1 · #235 T-SQL reference-set port (flag stays False)

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `store-235-port` |
| **Wave** | 1 |
| **Status** | ✅ **Complete** (2026-07-16 — port landed, flag stays `False`; the T-SQL proof is W2's CI gate) |
| **Effort** | 1 |
| **Backlog items** | #235 (Phase 1 of 3) |
| **ADR** | Not in this session — the ADR 0006 amendment lands with the W3 flip ([w03-store-235-flip](w03-store-235-flip.md)) |
| **Store schema / 3-backend** | Yes (new tables on SQL Server) — but the **authoritative server-DB proof is W2's job**; this session keeps the tree green with the capability flag `False` |

## Items

| Item | Title | Status |
|---|---|---|
| #235 (P1) | Port `reference`/`reference_version` + the five store methods to T-SQL | ✅ built (this PR) |

## Owned files / seams

`messagefoundry/store/sqlserver.py` — **only** file touched.

## The work

Donor: the **Postgres port** (`store/postgres.py:1140-1192` — same tables, same build-new-then-atomic-flip contract,
same convergence semantics). SQLite (`test_reference_sets.py`) is the reference implementation.

1. **DDL** appended to `_SCHEMA` (after the state block ~:780-785): `reference` (`name NVARCHAR(256)`,
   `version NVARCHAR(64)`, `[key] NVARCHAR(450)` — bracket-quoted like `state`'s — `value NVARCHAR(MAX)`,
   `CONSTRAINT pk_reference PRIMARY KEY NONCLUSTERED (name, version, [key])`) + `ix_reference_name`;
   `reference_version` (`name NVARCHAR(256)` PK, `version`, `synced_at FLOAT`, `row_count INT`).
   **Verdict-corrected:** declare a **binary collation** (`COLLATE Latin1_General_100_BIN2`) on
   `name`/`version`/`[key]` so key equality is byte-comparison like SQLite/Postgres — without it,
   externally-sourced keys differing only by case (or a trailing space, per ANSI-padding unique-key behavior) raise a
   PK-duplicate mid-transaction → a perpetual per-interval sync-failure alert.
2. **Caches**: `_reference_cache`/`_reference_versions` in `__init__` (beside `_state_cache` ~:1078);
   `_load_reference_cache` called from `open()` after `_load_state_cache` (~:1209); `_read_active_reference_snapshots`
   (LEFT JOIN — the **empty-set-stays-present** contract, donor `postgres.py:1140-1172`).
3. **Replace the three stubs** (:3610-3635): `reference_view` → `MappingProxyType(self._reference_cache)`;
   `write_reference_snapshot` → fail-closed **over-long-key guard BEFORE the transaction** (so
   `reference_sync.py:317`'s generic handler keeps last-good and alerts), then ONE transaction: DELETE + per-row
   INSERT of `cipher.encrypt(json.dumps(v))` + `reference_version` upsert (UPDATE-then-INSERT-if-rowcount-0 or
   `MERGE WITH (HOLDLOCK)` — the `SqlServerCoordinator` idiom, see `pipeline/cluster_sqlserver.py`);
   `converge_reference_cache` → real read-through over `_read_active_reference_snapshots`
   (donor `postgres.py:1174-1192`).
   **Verdict-corrected:** the guard measures **UTF-16 code units** (`len(key.encode('utf-16-le'))//2 > 450`), not
   Python code points — a naive `len()` passes astral-plane keys into a mid-transaction truncation failure — and
   extends to `name` (NVARCHAR(256)). The guard's error **NEVER contains the raw key value** (keys may be PHI for
   patient-keyed sets — `reference_sync.py` logs only the exception class for exactly this reason): set name + key
   length/ordinal/truncated-hash only. Post-commit, set BOTH `self._reference_cache[name]` AND
   `self._reference_versions[name]`.
4. **Rotation + migration passes**: add the reference composite pass to `reencrypt_to_active` (mirror the state pass
   ~:3750-3773) **and to `_encrypt_existing_rows` (:1322-1426)**. Verdict-corrected: the "tables are born encrypted,
   no legacy plaintext possible" omission rationale is **FALSE** — under a no-key deployment `IdentityCipher` writes
   plaintext JSON, and the no-key→key transition is that method's entire purpose.
5. **Do NOT touch `supports_reference_sets` (:1044)** — it stays `False`; every gate/capability test still asserts
   refusal, the tree stays green, and the new code is exercised only by direct store-handle calls until W2 proves it.

## Dependencies

None — all prerequisites (gate, flag, donors) are shipped and verified. Unblocks
[w02-store-235-ci-tests](w02-store-235-ci-tests.md).

## Notes & gotchas

- The content-addressed `_SCHEMA` hash (~:934-940) forces one full guarded DDL re-run on the first open after this
  change — expected, benign; note it in the PR.
- Docstrings of the replaced stubs must be rewritten (they currently document the incapability).
- The T-SQL is **NOT proven** by this session — local pytest silently skips without `MEFOR_TEST_SQLSERVER=1`. Phase 2
  (W2) owns the proof; never let this session's green run be cited as one.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict — all new methods fully typed) →
  `QT_QPA_PLATFORM=offscreen pytest -q` (proves no SQLite-visible regression).
- If a local mssql container is available: `MEFOR_TEST_SQLSERVER=1` + `MEFOR_STORE_*` smoke of
  `tests/test_sqlserver_store.py` (DDL batch sanity) — corroborating only.
- One coherent commit; PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves push/PR.

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
