# Proposed backlog items from Fable review packet 15 (data integrity, migrations, retention)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number, with
the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-15-DATAINTEGRITY-2026-09-11-FINDINGS.md` (vault branch
`vault/fable-packet15-dataintegrity`); this file names the subject, the mechanism and the fix only.

Engine ref measured: `70063ab55`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0). Product migration cost is zero, so no proposal asks for a compatibility shim.

Duplicate search method: `parse_items` from `scripts/docs/backlog_status_check.py` over both
`docs/BACKLOG.md` (518 items) and `docs/archive/backlog/BACKLOG-CLOSED.md` (237 items), matching each
item's whole text by symptom, path and symbol. The needles are listed per proposal.

---

## Proposal 1. DR: the engine backs up and verifies a `.mfbak` archive and has no way to restore one

> Filed 2026-09-12 - not started. Found by Fable review packet 15 (finding P15-01). The CLI ships
> `backup` and `restore-verify` and no `restore`; `pipeline/dr.py` `activate` verifies the cold-seed
> archive into a temporary directory, discards it, and serves from whatever store the box opened at boot,
> then records a `dr_seed` audit marker naming the archive. `docs/adr/0048` and `docs/CONFIGURATION.md`
> say the engine "cold-seeds the store from a `.mfbak` archive"; `docs/EARLY-ADOPTER-GUIDE.md` section 10
> says "No existing repo doc covers this" and gives a `sqlite3 .backup` recipe that predates the archive
> format. Measured by read of the dispatch table, `dr.py` (no extract, copy or rename of the verified
> snapshot anywhere in the file) and the three documents.

**Cluster:** Admin & Deployment / DR. **Priority:** P1. **Verdict:** build. **Severity:** high. A first
deployment following the docs would hold nightly archives that verify `PASS` and, on the day it needed
one, would have no tool and no procedure that turns an archive back into a store; a DR activation's audit
row would record a "verified cold seed" for a store that was never seeded from it.

**Mechanism.** ADR 0049 built the artifact and the verify primitive; ADR 0048 consumes the verify and
defers "the restore mechanic" back to ADR 0049. Neither built it.

**Fix.** A `messagefoundry restore <archive> --to <store-path> [--config-to <dir>]` subcommand:
resolve the decrypt keyring through `resolve_decrypt_keys`, stream the tar through the bounded
`_extract_member` reader, refuse an existing destination, and leave `reset_stale_inflight` to the next
open (ADR 0049 AC-11). Have `activate` call it when the DR store is absent or empty, or refuse with the
restore step named; stop recording "verified cold seed" for an archive that was not loaded. Rewrite guide
section 10 around the shipped surface, and correct ADR 0048 and the `[dr]` table.

**Duplicate search.** No item. #60 (closed) built backup plus restore-verify and names no restore
follow-up; #61 (closed) built activation on the premise that #60 owns the restore mechanic; #102 (closed)
is the server-DB attestation gate; #155 (open, demand-gate) is a server-move runbook that cites section 10
as already covering restore. Needles: `messagefoundry restore`, `restore command`, `cold seed`,
`extract .mfbak`, `decrypt .mfbak`, `restore path`, `restore-verify`.

---

## Proposal 2. DR: `full_restore_verify` opens the snapshot with no key, so it passes a corrupted store and fails a good archive that holds a state or reference row

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-02). `pipeline/dr_backup.py`
> `_full_open_check` calls `open_store(StoreSettings(path=str(snap)))`; a bare `StoreSettings` carries no
> key and no key provider (measured: `resolve_active_key` returns `None` with the env key set), so the
> snapshot opens under the identity cipher. Measured on a keyed SQLite store: with one ciphertext byte of
> `messages.raw` flipped, a backup with `verify_after_backup` and `full_restore_verify` on reports
> `verify PASS`; with one transform-state row and nothing corrupted, the full verify fails with
> `StoreKeylessError` on `state`, the scheduled backup raises `BackupError kind=verify`, and on Windows the
> operator-visible reason is a `PermissionError` from temp-dir cleanup because the failed open never closed
> its connection.

**Cluster:** Store / DR. **Priority:** P1. **Verdict:** build. **Severity:** high. The setting's doc row
promises the snapshot is opened "through the real `open_store` path (cipher + migrations)"; on a keyed
store it proves less than the light verify and, on any store using transform state or reference sets,
would turn every scheduled backup into a failure with a misleading reason.

**Fix.** Build the cipher from the `store_settings` the runner already holds (`build_store_cipher`) or
pass the resolved `keys` into `_full_open_check`; make the full verify read every ciphered cell back
through the cipher and report `KEY_MISMATCH` when the keyring cannot. Two tests: one state row on a keyed
store must `PASS`; one corrupted cell must `FAIL`. Close the connection on a failed open (packet 10's
P10-03) so the temp directory can be removed.

**Duplicate search.** No item. Needles: `full_restore_verify`, `_full_open_check`, `full restore-verify`,
`open_store(StoreSettings(path`.

---

## Proposal 3. Store: no shipped control reads a ciphered cell back through the cipher

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-03). `integrity_check` is
> `PRAGMA quick_check` (and the structural equivalents on the server backends), restore-verify counts rows,
> `audit-verify` covers `audit_log` only, and `verify/checks.py` has no cipher check. The only code that
> decrypts every covered cell is `reencrypt_to_active`, offline under `rotate-key`. A corrupt or wrong-AAD
> value is discovered at first use, by a dead letter or a `CipherError` in a view. Measured: a store with a
> corrupted `messages.raw` ciphertext reports `integrity_ok True` and verifies `PASS` under both modes.

**Cluster:** Security / Store. **Priority:** P2. **Verdict:** build. **Severity:** medium. The at-rest
integrity property is the AEAD tag and nothing checks it until a row is needed, so a cell damaged by a disk
fault, a botched restore or a wrong retired key would sit in a store whose every integrity report says `ok`.

**Fix.** A `messagefoundry cipher-audit` subcommand (or `--decrypt` on `restore-verify` plus a
`[backup].verify_decrypt` knob) walking the rotation's cell inventory (`_CIPHER_COLUMNS` plus the composite
passes), decrypting each value with the keyring, reporting per-table counts and the first failing cell id,
never a plaintext. Reuse the inventory the parity guard already mechanises so it cannot drift from the
writers.

**Duplicate search.** No item. #1169 (open) is the strict-ciphertext *read* (refusing an unmarked value on
the hot path); this is an offline read-back audit and is complementary. Needles: `corrupted cipher`,
`undecryptable`, `decrypt every`, `cipher audit`, `cipher scan`.

---

## Proposal 4. Store: schema migration is additive-only behind existence guards and nothing verifies the live schema afterwards, so a mismatched table is skipped and the hash marker records it as current

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-04, widening packet 4's P4-09).
> The `search_presets` table shipped with an `owner` column from #151 (2026-07-18) to #544 (2026-08-23)
> and is in release v0.3.2 (2026-07-28, the latest on PyPI); the current tree expects `owner_user_id` and
> carries no rename. Measured with the v0.3.2 DDL: SQLite `open()` succeeds, `_migrate` adds `last_used_at`
> to the old table, and the first preset use raises `no such column: owner_user_id`; Postgres 16 `open()`
> refuses at `_SCHEMA` statement 56 of 60 (`CREATE UNIQUE INDEX IF NOT EXISTS ... (owner_user_id, name)`,
> which Postgres validates before the name check) with a raw `UndefinedColumnError` on every restart; SQL
> Server fails at first use with 42S22 (packet 4's observation). A second instance on Postgres: a
> pre-existing relation named `ix_queue_fifo_in_seq` makes `CREATE INDEX IF NOT EXISTS` skip, `open()`
> succeeds, and the marker records a schema whose index was never built. BACKLOG #1232's amendment ruled
> "write no migration" on the premise that the schema hash forces one on the server backends; the hash
> forces a re-run of a batch whose guards skip the table, so the premise is false.

**Cluster:** Store / schema. **Priority:** P2. **Verdict:** build. **Severity:** medium. Any future
non-additive change (a rename, a type widening, a `NOT NULL`) would land with no mechanism to apply it and
none to notice it was not applied, and would be found the way this one was, by a session opening an older
database.

**Fix.** Post-batch schema verification on every backend: derive the expected `(table, column)` set from
`_SCHEMA` (or a declared inventory beside `_CIPHER_COLUMNS`), read `PRAGMA table_info` /
`information_schema.columns` / `sys.columns`, refuse `open()` with the table, column and remedy named when
they differ, and on the server backends write the marker only after that check passes. Decide the `owner`
column on its own: `ALTER TABLE search_presets RENAME COLUMN owner TO owner_user_id` is one statement on
all three engines (SQLite 3.25+, Postgres, `sp_rename` on SQL Server), or state in #1232 that a v0.3.2 store
must be recreated. Correct #1232's premise either way. Tests: open each backend on the v0.3.2 shape and on a
colliding relation name and assert the refusal text.

**Duplicate search.** No item for schema verification. #1232 (closed) is the rename itself and carries the
false premise; #1008 (open, owner-deferred) is the store-principal privilege preflight, adjacent and
different; #1225 (closed) is the owner-key change. Needles: `search_presets.owner`, `owner_user_id`,
`schema_meta`, `_schema_hash`, `schema drift`, `schema mismatch`, `rename column migration`,
`guarded CREATE`.

---

## Proposal 5. PHI: a restore-verify that fails after extraction leaves the decrypted snapshot in the OS temp directory permanently

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-05). `_verify_archive_blocking`
> extracts `store.db` under a `TemporaryDirectory(prefix="mefor-verify-")`; when `_full_open_check` raises
> inside `MessageStore.open` after the connection exists, the file stays open, Windows refuses the unlink,
> `cleanup()` raises `PermissionError`, and the directory survives with `extracted_store.db`, its `-wal` and
> `-shm`. Measured: 15 such directories in `%TEMP%` after the packet's probes. `docs/PHI.md` section 2 row
> 100 says these directories are transient "but not on a crash or `SIGKILL`"; this is the routine failure
> path.

**Cluster:** Security / PHI at rest. **Priority:** P2. **Verdict:** build. **Severity:** medium. On a
first deployment with `full_restore_verify` on and any state or reference row, every nightly run would leave
a decrypted copy of the whole archive (config bundle and every non-ciphered column in the clear) under
`%TEMP%`, outside the ACL'd data directory, once per day, until someone looked.

**Fix.** Close the connection on every failed-open path (packet 10's P10-03), retry the unlink after the
aiosqlite thread exits, and as a fail-safe overwrite-then-unlink the extracted members before dropping the
directory; extract under the data directory's ACL rather than `%TEMP%` if the platform allows. Correct
`PHI.md` row 100.

**Duplicate search.** Related, not duplicate: packet 10's proposal 3 (P10-03, the failed-open connection
leak) removes the trigger; this is the cleanup fail-safe and the doc claim, and stands on its own for any
other exception raised between extraction and cleanup. Needles: `mefor-verify`, `TemporaryDirectory`,
`extracted_store`, `WinError 32`, `transient`.

---

## Proposal 6. Tests: restore-verify's row-count compare is unpinned, and it samples four tables

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-06). Replacing the compare in
> `_verify_archive_blocking` with `if False and ...` left five backup suites green (46 passed, exit 0); the
> one assertion that touches the counts asserts equality on a good archive. `_VERIFY_TABLES` is
> `messages`, `queue`, `message_events`, `audit_log`; a snapshot whose `users`, `state`, `reference`,
> `response`, `attachment_chunk` or `search_presets` tables are truncated or absent verifies `PASS`.

**Cluster:** Tests / DR. **Priority:** P2. **Verdict:** build. **Severity:** none on a deployment axis; a
control's only pin is the docs.

**Fix.** One test that rewrites the manifest inside a re-sealed tar (or truncates a member) and asserts
`FAIL` with `row-count mismatch`; widen `_VERIFY_TABLES` to every table in `sqlite_master` at manifest
time.

**Duplicate search.** No item. Needles: `row-count compare`, `row_counts`, `row-count mismatch`,
`_VERIFY_TABLES`.

---

## Proposal 7. Tests: the cipher-sweep parity guard is blind to `INSERT OR REPLACE` and `MERGE` tables, and Postgres has no keyless-to-keyed on-open test at all

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-07, settling packet 4's handover).
> `tests/test_store_cipher_sweep_parity.py` scopes demanded cells with `INSERT INTO\s+(\w+)`; SQLite writes
> `state` with `INSERT OR REPLACE INTO` and SQL Server with `MERGE`, so `state.value` is not demanded on
> either (the guard's own helpers report `demanded=False`). Deleting SQLite's `state` on-open pass left the
> guard green; the keyed runtime suite caught it. No `MEFOR_TEST_POSTGRES`-gated test names
> `_encrypt_existing_rows`; the SQL Server leg's one on-open test covers 3 of 16 written cells. The Postgres
> migration was executed by the packet on PostgreSQL 16.14 across all 17 written cells and works; the SQL
> Server one was not executed.

**Cluster:** Tests / Store. **Priority:** P2. **Verdict:** build. **Severity:** none on a deployment axis;
the guard's docstring says it exists because "no CI leg can catch this at runtime", and its scope excludes
the table whose writer uses the backend's native upsert on exactly those backends.

**Fix.** Widen the regex to `(INSERT(\s+OR\s+\w+)?\s+INTO|MERGE(\s+INTO)?)\s+(\w+)` with a synthetic
control for each form; add a keyless-then-keyed on-open test on both server legs that writes one plaintext
value into every written cell, re-opens keyed, and asserts each cell is sealed and reads back; make the
docstring say which leg runs what.

**Duplicate search.** #1169 (open) built the guard as a precondition and is a research item on the
strict-ciphertext read; this is a defect in the guard and a coverage gap on the server legs, filed
separately so it can close. Needles: `_encrypt_existing_rows`, `cipher_sweep_parity`, `at-rest migration`,
`INSERT OR REPLACE`, `MERGE`.

---

## Proposal 8. DR: keep-N pruning is scoped to the current run's extension, so `.mfbak.plain` archives outlive the window once a key is configured

> Filed 2026-09-12 - not started. Fable review packet 15 (finding P15-08). `_prune_keep_n(dest_dir, inst,
> ext)` globs the current run's extension only; archives written as `.mfbak.plain` under
> `[backup].allow_unencrypted` before a key existed are never counted or pruned by a keyed run. By read; no
> runtime dependence.

**Cluster:** DR / retention. **Priority:** P4. **Verdict:** build. **Severity:** low. The one case in which
a cleartext archive exists is the one where its retention matters most, and the classified window
`[backup].retention_keep` silently stops applying to it.

**Fix.** Prune both extensions under one keep-N over the union, or refuse to start a keyed instance whose
destination still holds `.mfbak.plain` archives, and say which in the `[backup]` table.

**Duplicate search.** No item. Needles: `mfbak.plain`, `allow_unencrypted prune`, `keep-N plain`.

---

## Deliberately not proposed

- The `.processed` directory growing without bound (packet 2's handover): `PHI.md` classifies it as an
  honest gap and #1188 (open) lists the spill-directory sweep as its remaining work; `after_read = "delete"`
  is the operator's existing bound. One wording flag for packet 18 is in the findings document.
- The retention writers without rollback and `snapshot_to`'s `icacls` on the loop: packet 5's proposals 2
  and 5.
- The daily backup latch (one failed 02:00 run means no backup until the next day): documented design,
  alerted; deprioritized in the findings document.
- Doc-versus-code flags handed to packet 18: `EARLY-ADOPTER-GUIDE.md` section 10, ADR 0048 line 231 and
  `CONFIGURATION.md`'s `[dr]` preamble (the engine does not cold-seed), `PHI.md` row 100 (transient only on
  crash), `PHI.md` section 8's `.processed` rationale, and the parity guard's "every leg is keyless" line.
