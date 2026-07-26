# PLAN-12 · Wave 3 · #235 the atomic flip — flag + refusal prose + docs + ADR 0006 amendment

> **Phase document** — one of the per-session build docs of [MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)
> (authored with the plan, 2026-07-16). **This file is the maintainable source of truth for this session's status.**
> Shared rules, the contention matrix, and wave sequencing live in the master.

| | |
|---|---|
| **Session** | `store-235-flip` |
| **Wave** | 3 |
| **Status** | ✅ **Complete** (2026-07-16 — gate satisfied on PR #1078; the flip landed in this session's PR) |
| **Effort** | 0.5–1 |
| **Backlog items** | #235 (Phase 3 of 3) |
| **ADR** | **Yes — ADR 0006 dated in-file amendment** (drafted below; appended in the flip commit; `docs/adr/README.md` 0006 row Status cell updated in the SAME commit) |
| **Store schema / 3-backend** | Yes — the flip makes the engine accept `Reference(...)` graphs on the production backend |

## Items

| Item | Title | Status |
|---|---|---|
| #235 (P3) | Flip `supports_reference_sets`, rewrite refusal prose, pin docs, amend ADR 0006, flip BACKLOG | ✅ built (this PR) |

## Owned files / seams

`messagefoundry/store/sqlserver.py` (flag :1044 + comment :1038-1043) · `messagefoundry/pipeline/wiring_runner.py`
(docstring ~:5531-5535 + refusal string ~:5557-5561) · `messagefoundry/checks.py` (`_check_reference_backend`
docstring ~:723-739 + detail ~:785-789) · `messagefoundry/store/base.py` (~:209-218 flag docstring) ·
`messagefoundry/pipeline/engine.py` (~:1063-1069 docstring) · `docs/CONFIGURATION.md:101` row + :115-118 prose ·
`docs/adr/0006-external-data-lookups.md` (amendment) · `docs/adr/README.md` (0006 row) · `docs/BACKLOG.md` (#235
flip) · `tests/test_reference_sets.py` · `tests/test_store_capability_matrix.py` · `tests/test_checks.py`.

## The work — ONE commit (the pieces break individually)

`tests/test_store_capability_matrix.py:51-114` **parses `docs/CONFIGURATION.md`'s capability table and asserts every
cell against the class flags** — landing the flag and the doc row in separate commits breaks CI. The coupled set:

1. `sqlserver.py:1044` → `True`, rewriting the :1038-1043 comment.
2. Refusal-prose rewrites: `wiring_runner.py` + `checks.py` drop "(SQLite or PostgreSQL)" for allow-list wording
   ("a store backend that implements ADR 0006 reference snapshots") — **the gate itself stays**, for future
   backends. `base.py` + `engine.py` docstrings drop the "SQL Server has no tables" clause; grep `sqlserver.py` for
   remaining stub prose.
3. `docs/CONFIGURATION.md:101` cell no→yes + :115-118 prose rewrite — **mandatory same-commit** (see above).
4. Tests: `test_reference_sets.py:588` → `True` (the :594-607 drift guard asserts equality — needs no edit);
   `test_store_capability_matrix.py:142-155` — reference sets stop being "a capability that varies," so rework to
   pin all-three-True while `fused_sync_handoff` remains the varying row; `test_checks.py:560-568` — **preserve the
   failing-arm coverage** by monkeypatching `SqlServerStore.supports_reference_sets = False`
   (`backend_supports_reference_sets` resolves the class flag lazily, `base.py:1636-1639`, so the patch flows
   through) and add the **positive arm**: the sqlserver TOML + `Reference(...)` now PASSES the reference-backend
   check. (`test_reference_sets.py:610-646` gate tests need nothing — they already fake the flag on a SQLite store.)
5. **ADR 0006 amendment** (append; precedent: the 2026-07-14 amendment at :171-173): Backend-support table row :179 →
   *implemented*; Built section :11 and Consequences :228-233 updated. **Update the 0006 index-row Status cell in
   `docs/adr/README.md` in the SAME commit** (repo amendment convention).
6. `docs/BACKLOG.md` #235 → built + date + PR.

### ADR 0006 amendment — draft (append as `## Amendment (YYYY-MM-DD) — reference sets implemented on SQL Server (BACKLOG #235)`)

Key decisions the amendment records (facts verdict-corrected):

- **Schema:** `reference`/`reference_version` at SQLite/Postgres parity; `[key] NVARCHAR(450)` with a
  **NONCLUSTERED PK** — 450 was **chosen** so the worst-case composite (256+64+450 code units = 1540 bytes max)
  can never hit the 1700-byte nonclustered-index cap; **the runtime rejector is the NVARCHAR(450) column width
  (truncation)**, not the index cap. (A clustered PK would declare-with-warning and fail only on actual
  over-900-byte rows — hence nonclustered.)
- **Fail-closed sizing guard:** over-long `name`/`key` measured in **UTF-16 code units** raises BEFORE the
  transaction, never embedding the raw key (PHI for patient-keyed sets) — set name + length/ordinal/truncated-hash
  only; the sync runner keeps last-good and alerts.
- **Two recorded divergences from the donors:** (1) the sizing guard above (SQLite/PG have no equivalent limit);
  (2) **binary collation** (`COLLATE Latin1_General_100_BIN2`) on `name`/`version`/`[key]` so key equality is
  byte-comparison like SQLite/Postgres (SQL Server's default collation is case-insensitive + ANSI-padded).
- **Encryption:** values `cipher.encrypt(json.dumps(v))` at rest (`mfenc`), covered by `reencrypt_to_active` AND
  `_encrypt_existing_rows` (the no-key→key migration — `IdentityCipher` writes plaintext JSON under a no-key
  deployment, so "born encrypted" is false and the pass is required).
- **Convergence:** multi-node read-through per the donor contract; the leader's own write updates both the cache and
  the versions map post-commit (`converge_reference_cache()` returns `[]` for the writer).
- **Upsert idiom:** `reference_version` UPDATE-then-INSERT-if-rowcount-0 (or `MERGE WITH (HOLDLOCK)`) — the
  `SqlServerCoordinator` idiom, `pipeline/cluster_sqlserver.py` (SQL Server store Phase 4 active-passive HA).
- The capability gate stays for future backends; SQL Server's row moves out of the refusal table.

## Dependencies

- **HARD GATE: [w02-store-235-ci-tests](w02-store-235-ci-tests.md)'s sqlserver-store AND postgres-store legs green.**
  Never flip on unproven T-SQL — flipping makes the engine ACCEPT `Reference(...)` graphs on the production backend
  (fail-closed invariant).
- Rebases over [w02-engine-230-dryrun-parity](w02-engine-230-dryrun-parity.md)'s `checks.py`/`test_checks.py` edits
  **if it ran** (line-disjoint functions; never same wave).
- Owns W3's `docs/BACKLOG.md` touch alone (the #234 flip is deferred to W4 because the #234/#235 entries are
  line-**adjacent** at :6922/:6923).

## Notes & gotchas

- First post-upgrade open of a production DB re-runs the full guarded DDL batch once under the schema applock with
  the timeout exemption (content-addressed `_SCHEMA`) — by design, benign; note in the PR.
- No `alloc.ps1` — an in-place ADR amendment allocates no number; the ledger gate applies only to new numbers.

## Verification — Definition of Done

- `ruff check` + `ruff format --check` → `mypy messagefoundry` (strict) → `QT_QPA_PLATFORM=offscreen pytest -q` —
  the flipped assertions, the capability-matrix doc parser, and the reworked checks tests all run in the normal
  (SQLite) CI job; the sqlserver-store leg re-runs on the PR (store file touched), proving the now-reachable end
  state.
- ADR 0006 amendment + `docs/adr/README.md` row in the SAME commit; full CI green including both server-DB legs.
- PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer**; owner approves (auto-merge = main).

---
_Last reconciled: 2026-07-16 against `origin/main` @ `8e413919`. Master index:
[MULTISESSION-PLAN-12](../MULTISESSION-PLAN-12.md)._
