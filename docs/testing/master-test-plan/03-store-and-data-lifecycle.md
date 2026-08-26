[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 2. Message Store, Backends & Data Lifecycle (incl. DB purging)

**ID prefix:** `STORE` · **Surface:** engine (+ CLI, infra; one web-console legibility row)
· **Primary risk:** the retention/purge code that irreversibly deletes PHI, and the at-rest write
format that protects it, are both proven almost entirely on SQLite under a writer the shipped
configuration does not use — so a purge that deletes the wrong feed's bodies, or one that silently
stops deleting, is green in CI on the production backend.

### 2.1 Scope & objectives

**In scope.**

- The **Store protocol + `open_store` seam** ([store/base.py:1739](../../../messagefoundry/store/base.py)) over
  **SQLite / PostgreSQL / SQL Server**, including `build_store_cipher`
  ([base.py:1717](../../../messagefoundry/store/base.py)) and the backend capability flags
  ([base.py:179–218](../../../messagefoundry/store/base.py)).
- **Schema init + migration**: the ADR 0064 content-hash `schema_meta` fast-path
  ([postgres.py:606](../../../messagefoundry/store/postgres.py), [sqlserver.py:1358](../../../messagefoundry/store/sqlserver.py)),
  Postgres `_MIGRATION_REV` ([postgres.py:603](../../../messagefoundry/store/postgres.py)), and SQLite's 17
  guarded `ADD COLUMN` on-open migrations ([store.py:2932](../../../messagefoundry/store/store.py)).
- **Encryption at rest**: AES-256-GCM `mfenc:v1`/`v2` ([store/crypto.py](../../../messagefoundry/store/crypto.py)),
  cell-AAD binding (`[store].aad_bind`, default **True**, [settings.py:381](../../../messagefoundry/config/settings.py)),
  DEK rotation (`reencrypt_to_active`), the KeyProvider seam, and the Vault/OpenBao Transit cipher
  (ADR 0138, `mfenc:v3`) **only where they touch store columns, purge write-back, or rotation**.
- **Retention / purge / maintenance — the owner-named "DB purging" item, covered exhaustively**:
  `RetentionRunner` ([pipeline/retention.py:210](../../../messagefoundry/pipeline/retention.py)), per-connection
  retention (ADR 0027), embedded-document pruning (ADR 0042), the time-boxed pass cap (ADR 0137),
  every `purge_*` / `strip_*` / `wal_checkpoint` / `vacuum` method on all three backends, purge under
  sustained load, purge vs in-flight rows, purge vs per-lane FIFO, purge attribution + audit trail,
  orphaned attachment cleanup, disk reclamation, retention misconfiguration and fail-safes, and
  legal-hold/exception cases.
- **Attachment / claim-check substrate** (ADR 0105 — the repo's real claim-check: content-addressed
  chunked storage, dedup, incref/decref/GC, `sweep_orphan_attachments`, the `message_attachment`
  linkage and its purge decref).
- **DR backup / restore / verify** (ADR 0049, ADR 0102) **only for the server-DB half that has never
  executed**, plus backup↔retention interaction.
- **Store pool sizing** (ADR 0062) **only where a maintenance pass contends for it**.

**Explicitly NOT in scope here — owned elsewhere, cite and move on.**

| Area | Owner | Do not restate |
|---|---|---|
| Staged-pipeline handoffs, seq-only FIFO, batch/pooled claim, dispatcher state machine, ACK-on-receipt | FEATURE-COVERAGE-PLAN §9 `[STORE]` rows 1–22 | `FCP:STORE-2/4/7/10/12/14/19/22` — **foreign IDs**, not this chapter's STORE-02/04/… |
| Dead-letter capture/replay, resend/edit-resend, content search, group-commit, store-once, outbound batch | FEATURE-COVERAGE-PLAN §10 `[STOREF]` rows 1–18 (esp. `FCP:STOREF-8/9/11/12/15/17`) | the whole operational-feature audit |
| Cipher primitives, KeyProvider root-of-trust (`FCP:CRIT-1`), `require_encryption` fail-closed, DPAPI scope, secret leak assertions | FEATURE-COVERAGE-PLAN §11 `[CRYPTO]` rows 1–10 | `FCP:CRYPTO-3` is the plan-level P0; this chapter tests only the **store-column / purge write-back** consequences |
| DR end-to-end audit (snapshot, codec, runner, scheduling, keep-N, standby, restore-verify, CLI) | FEATURE-COVERAGE-PLAN §18 `[DR]` rows 1–27 | this chapter adds **only** the server-DB legs that never run |
| On-box `store.connect` per backend, healthy→PROCESSED under the NSSM service identity, DPAPI admin-mints/service-decrypts, `rotate-key` under the service account with `require_encryption=true` | WIN2025-TEST-PLAN `W25:S1.3` / `W25:S2.1` / `W25:S2.2` / `W25:B3` | this chapter only asks that WIN2025 gain the **missing retention/backup rows** |
| The authoritative per-backend purge specification (enforced / no-op (DBA-owned) / DBA-delegated) | [docs/PHI.md §8](../../PHI.md) lines 924–1053 | it is correct — test against it, don't rewrite it |
| Engine-shard partitioning and the unified-store guard | ADR 0063 + `tests/test_sharding.py` | only the **concurrent orphan sweep** interaction appears here |

**Objectives.** (1) Make the production backends prove the purge SQL that deletes PHI. (2) Make the
suite exercise the at-rest format the product actually writes. (3) Close the retention fail-open
paths (serve gate bypass, silent no-op knobs, unbounded materialization). (4) Give an operator an
observable signal that maintenance is keeping up. (5) Get retention and backup into an acceptance
matrix at all.

### 2.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_retention.py` (1374 lines, 52 tests) | SQLite purge windows; metadata NULLed **in the same statement** as the body + the pre-upgrade sweep; in-flight guard; idempotency; leader gate + mid-pass demotion; WAL/VACUUM cadence; `max_db_mb` alert; ADR 0137 cap (skip-phase, non-interruptible VACUUM, off = byte-identical); app-log delete + gzip incl. per-file deadline; preset windows |
| `tests/test_per_connection_retention.py` (373 lines, 9 tests) | ADR 0027 AC-1…AC-6/AC-8 **on SQLite**: inbound/outbound keying, global-only byte-identity, in-flight guard, `0` = keep-forever, one audit row carrying the per-connection cutoffs |
| `tests/test_embedded_document_pruning.py` (367 lines, 10 tests) | ADR 0042 AC-1…AC-7 **on SQLite**: `mfb64` + OBX-5 ED tombstoning, re-parse, in-flight guard, `min_bytes` threshold, `documents_pruned` flag, audit counts |
| `tests/test_attachment_substrate.py` (27 tests, SQLite) + `tests/test_sqlserver_store.py:2587-2870` + `tests/test_postgres_store.py:2539-2820` | ADR 0105 substrate on **all three** backends: verbatim chunked round-trip, dedup, incref/decref/GC, startup orphan + incomplete sweep, key-rotation chunk re-seal, two-object ingress commit + rollback, purge decref, shared/double-purge no-underflow, fan-out single decref, DEAD/replay live-holder split |
| `tests/test_sqlserver_store.py:805,850,861,887,916`; `tests/test_postgres_store.py:2950-3013,3432` | Real-backend **global** `purge_message_bodies` (delivered blanked, metadata nulled with the body, pre-upgrade sweep, in-flight guard), `purge_search_presets` incl. last-used keying, `purge_alert_instances`, `purge_state` |
| `tests/test_store_encryption.py` (~45 tests) + `tests/test_store_aad_binding.py` (13 tests) | AES-GCM round-trip, keyless passthrough, wrong-key fail-loud, undecryptable-row dead-letter at claim, on-open migration encrypt, rotation + retired-key bridge, frozen v1 fixture, v2 dispatch, unknown version/alg fail-closed, cell-AAD bind/mismatch/relocation rejection, `rotate-key` v1→v2 in place (SQLite) |
| `tests/test_keyprovider.py` + `tests/test_keyprovider_vault.py` + `tests/test_crypto_transit.py` | `auto`/`env`/`dpapi` built-ins, unknown-name and unbuilt-external fail-closed, Vault KEK unwrap, Transit cipher, no key material in exception text |
| `tests/test_backup_runner.py` (20) + `test_backup_crypto.py` (18) + `test_restore_verify.py` + `test_backup_restore_atleastonce.py` + `test_cli_backup_dispatch.py` + `test_backup_runner_concurrent_writer.py` | ADR 0049 single-pass orchestration, both snapshot methods consistent + non-mutating, archive under the store DEK, refuse-unencrypted-PHI, keep-N excluding verify-failed, leader gate, daily latch, `.mfbak` tamper/truncate/append/reorder matrix, restore-verify pass/fail/key-mismatch, at-least-once across restore, PHI-free CLI stdout |
| `tests/test_phi_at_rest_inventory.py` (~30 doc-vs-code guards) | Every cipher-covered cell is inventoried in PHI.md §2 with a protection level **and** a stated retention position; every `purge_*` + maintenance method is defined on all three backends and documented per backend ([:356](../../../tests/test_phi_at_rest_inventory.py), [:928](../../../tests/test_phi_at_rest_inventory.py) binds the verdicts to the method bodies); what `purge_message_bodies` blanks is named in §8 ([:377](../../../tests/test_phi_at_rest_inventory.py)); retired false retention claims cannot reappear |
| `tests/test_store_schema_hash.py` (6) + `tests/test_sqlserver_schema_init.py` (5) | ADR 0064 content hash tracks DDL + `_MIGRATION_REV`; applock taken before any CREATE; a current marker skips the batch, the applock and the timeout exemption |
| `tests/test_pool_warm.py` (20) + `test_store_read_pool.py` (8) + `test_store_capability_matrix.py` | Warm-target clamping, fence validator, partial/timeout/cancel release, SQLite no-op, SQLite read pool `query_only`, over-provision thresholds (pure fn), capability-flag/doc parity |
| `tests/test_cli.py:1383-1500` | The PHI retention posture gate: prod refuse-to-start naming `[security].delete_message_bodies_after_days`, staging/loopback auto-bound to 30 d, `allow_keeping_phi_indefinitely` audited override |
| `.github/workflows/ci.yml:483` (sqlserver-store, 2022 + 2025) / `:732` (postgres-store) | Real-backend legs exist and run the store suites, coordinator/failover, throughput levers, RTE — nightly / `workflow_dispatch` / `serverdb`-path-gated PRs |
| `.github/workflows/selfhosted-win2025-sql.yml` | Real Windows Server 2025 + SQL Server 2025 hardware run (`workflow_dispatch` only) |

**Done — do not re-plan.** The **SQLite** retention story is complete and should not be re-tested: windows,
the in-flight guard, idempotency, the double leader gate + mid-pass demotion, the ADR 0137 cap semantics,
and the app-log delete/gzip phases are all pinned, including the awkward cases (the per-file deadline
re-read inside `_compress_app_logs`, the "cap off is byte-identical" proof). The **attachment substrate**
is genuinely three-backend and its killer hazard — refcount underflow across shared/dead/replay purge
orders — is covered on all three. The **`.mfbak` codec** tamper matrix and the **restore-verify** decision
table are complete against a SQLite store. The **PHI.md §8 doc-vs-code guard suite** is unusually strong
and is the right place to add new documentation assertions rather than writing a parallel one. The
**cipher primitives** and the **KeyProvider seam** belong to FEATURE-COVERAGE-PLAN §11 `[CRYPTO]`; this
chapter must not restate `FCP:CRYPTO-3`.

**Two published coverage claims in this area are stale and are corrected by this chapter, not repeated:**
FEATURE-COVERAGE-PLAN **`FCP:STOREF-5`** ([:956](../FEATURE-COVERAGE-PLAN.md)) marks
per-connection retention "covered … (incl. three_backend_parity)" and **`FCP:STOREF-6`** ([:957](../FEATURE-COVERAGE-PLAN.md))
the same for document pruning — the parity tests exist but **no CI leg invokes those
files** (§2.3 R1/R4). **`FCP:STOREF-18`** still schedules ADR 0105 Phase 3b as a build
([:398](../FEATURE-COVERAGE-PLAN.md), [:535](../FEATURE-COVERAGE-PLAN.md)) while it ships
([base.py:850](../../../messagefoundry/store/base.py), [api/app.py:3225](../../../messagefoundry/api/app.py),
`tests/test_attachment_download_api.py`), as does [docs/adr/README.md:134](../../adr/README.md)
(FEATURE-COVERAGE-PLAN [:379](../FEATURE-COVERAGE-PLAN.md) already flags the row as stale —
the scheduling rows below it were never corrected).

### 2.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| **R1** ADR 0027 per-connection purge `CASE` has never run on PG/SQL Server. **RE-VERIFIED LIVE 2026-08-15 (BACKLOG #1100) — every claim holds, with a positive control, and the gap is DOUBLE.** `connection_cutoffs` appears **0** times in `tests/test_postgres_store.py` and `tests/test_sqlserver_store.py` (control: it appears in exactly **2** files repo-wide, so the zero is real and not a broken grep). **Those two files are `test_per_connection_retention.py` AND `test_embedded_document_pruning.py`** — the row named only the first. Neither is named by any workflow step, and the `serverdb` path-gate regex (**`ci.yml:993`**, not the cited `:434`) matches `per_connection_retention` **0** times. **THAT IS A STRICTLY WORSE SHAPE THAN THE ONE AT `02-pipeline-reliability.md:145`:** those three suites are *matched by the gate but run by no step*, so the expensive leg at least fires; **these two are matched by nothing and named by nothing**, so editing the per-connection purge predicate triggers no server-DB leg at all and runs no test that mentions `connection_cutoffs` | A wrong `_pg_cutoff_case` / `_qmark_cutoff_case` predicate purges the **wrong feed's** PHI bodies (irreversible; the count-and-log row survives so nothing looks broken) or silently purges nothing (unbounded PHI at rest) | Every PHI feed on the production backend; irreversible either way | **No.** SQLite stays green in both directions | **P0** |
| **R2** The **exhaustive** at-rest AAD sweep never runs in CI (was: "the shipped writer is barely exercised" — **narrowed 2026-08-15, BACKLOG #1100**). **CONFIRMED, and the framing corrected.** Still true: `[store].aad_bind` defaults `True` (`settings.py:388`), `make_cipher`'s library default is `write_v2=False` (`crypto.py:812`), and **no workflow sets `MEFOR_TEST_FORCE_AAD_BIND`** — **0** occurrences across `.github/workflows/` against a positive control of **14** for `MEFOR_TEST_SQLSERVER`. **But "barely exercised" now overstates it**, and the flag's own docstring (`tests/conftest.py:133-138`) says why: *"The flag is OFF by default and stays meaningful even though `[store].aad_bind` now DEFAULTS TRUE (ADR 0148 GIVEN 1)... The settings default governs what `open_store` builds; **this flag governs every cipher in the process, which is what makes the sweep exhaustive rather than merely representative**."* So the shipped `mfenc:v2` writer **is** exercised by every ordinary store test via the default; what is missing is the process-wide forcing that also catches ciphers built with an **explicit** `write_v2=False`. **The parenthetical was also wrong: EIGHT test files reference the flag**, not `conftest.py` alone — `test_store_aad_binding`, `test_store_encryption`, `test_transform_state`, `test_ack_sent_store`, `test_alert_state`, `test_connection_event_store`, `test_ed_documents_e2e`, `test_sqlserver_store`. **The residual risk is unchanged and still P0:** a half-threaded `cell_aad` on purge re-encrypt, document strip write-back, attachment re-seal or restore would surface only under the forced sweep, and that sweep runs nowhere | An unbound or mis-threaded `cell_aad` on any write path — purge re-encrypt, document strip write-back, attachment re-seal, restore — yields rows the shipped cipher cannot decrypt (unreadable PHI) or silently drops the binding (ASVS 11.3.3 regression) | Whole store; discovered only in production | **No.** 13 SQLite-only targeted tests | **P0** |
| **R3** The PHI serve retention gate reads **only global** windows and never consults the registry's per-connection overrides. **CONFIRMED 2026-08-15 (BACKLOG #1100); anchors re-pointed — the gate MOVED and is no longer built inline.** `unbounded_windows` is now defined at [`config/retention_classification.py:186`](../../../messagefoundry/config/retention_classification.py) (20 lines) and called from [`__main__.py:2240`](../../../messagefoundry/__main__.py) as `_unbounded_windows(settings)` — **`settings` alone, no registry**. Read whole via AST, the function contains **no** `registry`, `connection`, `per_connection`, `overrides` or `inbound` token, and `__main__.py:2240` is its **only** caller in the package. **The bypass is documented in the code that creates it** (`wiring.py:3125-3126`): *"Per-connection retention override (#34, ADR 0027): None = inherit the global `[retention].messages_days` window; **0 = keep this connection's bodies forever**; >0 = days"* — and that override **is** honoured at purge time (`pipeline/retention.py:150`, "inbound name -> messages_days"). So the two halves are individually correct and jointly permissive: **a deploying PHI instance would pass the gate on its global window while retaining every body forever per-connection** | A PHI instance with a global 30-day window and every inbound at `messages_days=0` passes the fail-closed gate and retains PHI forever | An audited, security-labelled fail-closed control (ASVS 14.2.4) is bypassable by ordinary Connection config | **No.** No warning, no audit entry, no test | **P0** |
| **R4** ADR 0042 `strip_embedded_documents` has never run on PG/SQL Server (**0** occurrences in both server suites) — and it is a select → decrypt → codec-transform → **re-encrypt write-back** over stored PHI bodies ([postgres.py:6395](../../../messagefoundry/store/postgres.py), [sqlserver.py:5626](../../../messagefoundry/store/sqlserver.py)) | A dialect or write-back bug corrupts stored bodies (unparseable HL7) or leaves bulky base64 PHI in place forever | Every document feed on the production backend | **No** | **P1** |
| **R5** `strip_embedded_documents` materializes and **decrypts every eligible row with no LIMIT/TOP/batch** on all three backends ([store.py:8465](../../../messagefoundry/store/store.py), [postgres.py:6420](../../../messagefoundry/store/postgres.py), [sqlserver.py:5650](../../../messagefoundry/store/sqlserver.py)); the ADR 0137 deadline is checked only **before** the phase ([retention.py:443](../../../messagefoundry/pipeline/retention.py)), never inside the per-threshold loop | The first pass after enabling `prune_documents_after` pulls the entire un-stripped backlog of full PHI bodies into engine heap: OOM / engine crash mid-purge, unbounded PHI plaintext in memory, and a pass that blows straight through `max_pass_seconds` | Engine availability + PHI-in-heap exposure at exactly the moment PHI is being reduced | **No.** No test bounds the candidate set | **P1** |
| **R6** Purge under sustained load is untested on every backend. SQLite holds the single writer lock across the whole multi-statement purge transaction (`async with self._lock`, [store.py:8345](../../../messagefoundry/store/store.py)); SQL Server builds an unbatched `#eligible` temp table ([sqlserver.py:5566](../../../messagefoundry/store/sqlserver.py)) and **`messages` has no `LOCK_ESCALATION=DISABLE`** (only `queue` does, [sqlserver.py:1057-1063](../../../messagefoundry/store/sqlserver.py)) | A first large purge escalates to a table X lock on `messages` and blocks ingress inserts, stalling ACKs past the MLLP receive timeout | Availability incident on the production backend, during a scheduled maintenance window | **No.** No concurrent-purge test anywhere; no purge profile in `docs/LOAD-TESTING.md`; no metric to see it coming | **P1** |
| **R7** Retention, purge, VACUUM and backup appear in **no** acceptance or on-box evidence matrix. `harness/acceptance/matrix.py` has store rows B1–B6 / C1–C8 and no retention or backup row; WIN2025-TEST-PLAN / -MATRIX / -ACCEPTANCE never mention retention, purge, vacuum, `.mfbak` or restore | A fully green on-box sign-off is compatible with retention never running and backups never being written | Every release sign-off | **No.** FEATURE-COVERAGE-PLAN §18 records the DR half; the retention half is unrecorded | **P1** |
| **R8** No retention observability. `api/metrics.py` exports 22 series with **no** DB-size gauge, purged-row counters, last-successful-pass timestamp, or the ADR 0137 `capped` flag. The only signals are the `storage_threshold` alert ([retention.py:658](../../../messagefoundry/pipeline/retention.py)) and the `retention_purge` audit detail ([:943](../../../messagefoundry/pipeline/retention.py)). DB size *is* on `GET /status` ([app.py:4430,4512](../../../messagefoundry/api/app.py)) but not scrapeable | An operator cannot tell maintenance is falling behind, capped every interval, or that the store is growing — until the disk fills. ADR 0137 §3 states the cap exists "so an operator can see that maintenance is falling behind"; the only surface is a JSON blob in the audit log | Silent capacity failure | **Partially** (`/status` DB size only) | **P1** |
| **R9** `sweep_orphan_attachments` DELETEs `refcount<=0` and header-less chunk groups with **no age or grace guard** ([store.py:3540-3549](../../../messagefoundry/store/store.py), [postgres.py:4509](../../../messagefoundry/store/postgres.py), [sqlserver.py:7319](../../../messagefoundry/store/sqlserver.py)) and runs at **every** process start, **not leader-gated** ([engine.py:882](../../../messagefoundry/pipeline/engine.py) — the comment says "safe on any node"). The ADR 0105 two-object commit deliberately commits chunks at refcount 0 *before* the incref lands | A restarting sibling (engine shard, HA standby) sweeps a peer's in-flight chunks. Fails closed (ingress rolls back, no ACK) — but repeatedly kills a busy node's large-document ingress. With no reconciliation sweep (Phase 3a declined one), a refcount over-count retains PHI chunks forever, undetected | Large-document ingress availability; silent PHI retention | **No.** No concurrent-sweep test | **P1** |
| **R10** `outbox.payload` (the SQL Server legacy table) carries PHI, is in `_CIPHER_COLUMNS` ([sqlserver.py:2222](../../../messagefoundry/store/sqlserver.py)), is **recreated on every open** ([sqlserver.py:988](../../../messagefoundry/store/sqlserver.py)), and is touched by **no purge on any backend** ([PHI.md:1039](../../PHI.md) documents it as retained forever) | If any path still writes it, PHI accumulates outside every retention window and outside the audited purge | Direct ASVS 14.2.7 / HIPAA minimum-necessary failure the count-and-log invariant would not surface | **No.** No test asserts the table stays empty or that no writer targets it | **P1** |
| **R11** `[retention].wal_checkpoint_seconds` / `vacuum_at` on a server DB are **silent no-ops** ([sqlserver.py:5804,5808](../../../messagefoundry/store/sqlserver.py), [postgres.py:6565,6569](../../../messagefoundry/store/postgres.py)) — no settings validation, no serve warning, and the runner's startup log still prints `vacuum_at=…` ([retention.py:296-310](../../../messagefoundry/pipeline/retention.py)) as if enabled. [docs/FEATURE-MAP.md:97](../../FEATURE-MAP.md) says "Retention / purge / maintenance ✅ (SQLite, PG, SQL Server)" with no DBA-delegated caveat | Operator configures nightly reclamation on SQL Server, sees it in the log, sees no error, believes disk is being reclaimed. Space grows until the volume fills | Hard outage. PHI.md §8 gets this right; the map, the log and the config surface do not | **No** | **P1** |
| **R12** Backup and DR against a real server-DB store have **never executed**: `test_backup_runner_server_db_{postgres,sqlserver}.py`, `test_dr7_server_config_only_backup_{postgres,sqlserver}.py`, `test_dr_server_seed_gate_{postgres,sqlserver}.py` are all `MEFOR_TEST_*`-gated and named by **no** CI step | The `DbaDelegatedError` → config-only fallback, the `dr_backup` audit row on a server-DB store, and the ADR 0102 live seed gate are the whole DR story for the production backend, asserted only against a monkeypatched SQLite store | DR sign-off on the production backend | **No** (`FCP:DR-7` flags the shape; the sharper point is the tests exist and never run) | **P1** |
| **R13** ADR 0027 D3 / AC-6 promises the audit row records "the per-connection cutoffs **+ per-connection purged counts**". The shipped detail ([retention.py:943-990](../../../messagefoundry/pipeline/retention.py)) records `messages_overrides` / `dead_letter_overrides` plus only **aggregate** `messages_purged` / `dead_purged`; the AC-6 test asserts exactly that | An auditor cannot answer "how many bodies did feed X lose in this pass". The ADR's own acceptance criterion is not met | Purge attribution — the audit trail for irreversible PHI deletion | **No** (silent doc/code divergence) | **P2** |
| **R14** No purge-at-scale, VACUUM-duration, freelist/index-bloat or disk-reclamation measurement on any backend. The ADR 0137 cap is proved only with an injected fake monotonic clock (`test_retention.py:632-733`) | The recommended `max_pass_seconds` (~14400) and off-peak `vacuum_at` guidance are unvalidated; an operator sizing a maintenance window has no number. A VACUUM that outruns the window blocks the whole DB and the cap by design cannot stop it | Maintenance-window planning; a self-inflicted outage | **No** | **P2** |
| **R15** No **legal-hold / litigation-hold / per-message retention exception** exists anywhere (grep across `messagefoundry/` and `docs/` finds only `CLA.md:40` and a counsel brief, both patent-litigation). The only exception is per-connection `messages_days=0`, which is feed-wide | A HIPAA / e-discovery hold on one patient's messages cannot be honoured without disabling an entire feed's window (over-retaining everyone else's PHI); no artifact proves held data was preserved | Regulatory / discovery exposure | **No** — the mechanism does not exist | **P2** |
| **R16** Schema drift and mixed-version fleets untested. ADR 0064 accepts that out-of-band drift is no longer healed on open (remedy: manual `DELETE FROM schema_meta`) and that two builds alternating opens re-run the full batch under the exclusive lock. SQLite carries 17 ad-hoc `ADD COLUMN` migrations with exactly **one** upgrade-path test (`test_retention.py:374`, the #306 `last_used_at` column) | A hand-dropped index is silently permanent (plans degrade with no error); a rolling upgrade across an HA pair or engine-shard fleet reintroduces the startup convoy ADR 0064 removed | Cold-start latency + query-plan degradation; upgrade risk | **No.** No pre-migration fixture DB exists | **P2** |
| **R17** Purge vs **per-lane FIFO** asserted only indirectly. `purge_message_bodies` UPDATEs `queue` rows on the same hot table/indexes the claimers seek; the FIFO suites (`test_seq_only_fifo`, `test_claim_fifo_heads`, `test_batch_claim_fifo`) never run a purge | A lock or index interaction that blocks or reorders a lane head is invisible to both suites | Ordering guarantee — a core reliability claim | **No** | **P2** |
| **R18** Retention passes consume the shared server-DB pool (`_timed_acquire` / `_acquire`) with **no reservation or priority**; ADR 0062's inverted-U sizing was measured **without** a concurrent maintenance pass | At the measured knee (N≈32 inbounds, pool 40) a long purge holding slots for minutes shifts the whole engine along the inverted-U | Engine-wide throughput during maintenance | **No.** Pool-wait metrics exist; nothing correlates them with a pass | **P2** |
| **R19** Postgres `rotate-key` column coverage is thinner than SQL Server's (SS asserts the full response/state pass at `test_sqlserver_store.py:983`; PG only via attachment-chunk re-seal at `test_postgres_store.py:2801`). **No interrupted-rotation resume test on any backend** | A half-rotated Postgres store where one column family was missed leaves rows readable only under a retired key; drop that key and the PHI is unrecoverable | Irrecoverable PHI | **No** (recorded as `FCP:CRYPTO-4`; restated here because it is *store-column*, not cipher-primitive, coverage) | **P2** |
| **R20** [docs/FEATURE-MAP.md](../../FEATURE-MAP.md) §5 is materially behind: zero mention of ADRs 0019/0027/0042/0049/0062/0064/0105/0137; no row for DR backup, streaming attachments, the KeyProvider seam, pool sizing or schema-init. `tests/test_feature_map_claims.py` guards links and ASVS framing only | The capability catalog a reviewer, adopter and the next test-plan author reads overstates maintenance parity and understates what is built | Trust in the published capability status | **No** | **P2** |
| **R21** [ADR 0019:523](../../adr/0019-pluggable-keyprovider-hsm-kms-vault.md) still states cell-bound AAD is "opt-in via `[store].aad_bind` (**off by default**)" while [settings.py:381](../../../messagefoundry/config/settings.py) ships `aad_bind: bool = True` (flipped by ADR 0148) | The security ADR that owns the `mfenc` format contract misstates the shipped default — a reader planning a rotation or a restore reasons from the wrong posture | ASVS evidence quality | **No** | **P2** |
| **R22** **A purge pass that dies mid-transaction is untested on every backend.** Every suite kills the *process* between passes, never inside one: the multi-statement purge transaction (SQLite under `self._lock`, [store.py:8345](../../../messagefoundry/store/store.py); the SQL Server `#eligible` temp-table batch, [sqlserver.py:5566](../../../messagefoundry/store/sqlserver.py)) and the in-process day marker `_last_vacuum_day` ([retention.py:251,997-1005](../../../messagefoundry/pipeline/retention.py)) are never crash-tested together | A half-committed purge leaves bodies blanked with metadata intact (or the reverse), strands rows nothing will revisit, or advances the VACUUM/day marker past work that never ran — so the next pass skips it. Irreversible in the deleting direction, silent in the retaining direction | Every PHI feed; a maintenance-window crash is exactly when nobody is watching | **No.** No mid-transaction kill anywhere in `test_retention.py` | **P1** |
| **R23** **No disk-full / ENOSPC injection anywhere.** The purge, the WAL checkpoint/VACUUM ([store.py:8650,8658](../../../messagefoundry/store/store.py)) and the `.mfbak` write all assume the volume has room; `OSError` is caught broadly in the app-log phases ([retention.py:687,742,798,838,887,929](../../../messagefoundry/pipeline/retention.py)) but no test drives a full volume. `disk_free_bytes` is `0` on server DBs and the only capacity signal is the `storage_threshold` alert ([retention.py:658](../../../messagefoundry/pipeline/retention.py)) keyed on `max_db_mb`, not on free space | The single most common hospital-host failure. A volume that fills mid-purge, mid-checkpoint or mid-archive can corrupt a SQLite WAL, leave a truncated archive that later "restores", or drop received messages with no alert — and nothing proves the engine fails *closed* or recovers when space is freed | Whole-store availability + silent message loss + a worthless backup | **No** | **P1** |
| **R24** **Destructive operator error has no owning coverage.** Nothing refuses or audits: seeding/restoring an **older** archive over a store holding newer messages (the ADR 0102 vintage probe only guards DR activation, [dr.py:397-453](../../../messagefoundry/pipeline/dr.py)); a per-connection purge override naming a Connection that does not exist (a typo silently falls through to the global cutoff); `rotate-key` run with a new active key and **no** prior key in `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` (the guard at [__main__.py:3462-3470](../../../messagefoundry/__main__.py) only checks that an *active* key exists); `connection remove` deleting a Connection that still has queued rows ([connections_edit.py:202](../../../messagefoundry/config/connections_edit.py) is config-only and never consults the store) | The realistic loss path is an operator, not a bug: unrecoverable PHI (rotation without the retired key), the wrong feed purged, queued rows orphaned by a config edit, or newer messages overwritten by an old seed — each irreversible and, today, unaudited | The whole store; the highest-consequence, least-tested class in this chapter | **No** | **P1** |

### 2.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate**. **C** = *Characterisation* — it produces a recorded
measurement, finding or dated owner decision with no threshold yet; legitimate work, but it **cannot
fail**, so it never gates a release, and it becomes a T row the day its threshold or decision is
recorded. **A** = *Assurance* — an external engagement, blocking only for an off-loopback /
production-exposure release. This chapter carries **73 rows: 66 T, 7 C, 0 A**. **Eleven T rows are
P0** — nine owned here (STORE-01/-02/-03/-04, -07/-08/-09, -13/-14) plus the two P0 *pointer* rows
STORE-44 → HA-02 and STORE-46 → HA-48, whose gate lives in the HA chapter. The seven C rows are
STORE-22, -23, -25, -28, -34, -36 and -60 (blocked on OQ-6, OQ-6, OQ-7, an operator finding, OQ-1,
OQ-9 and the ADR 0138 throughput spike respectively).

**Pointer rows.** Nine rows are one-line pointers to the chapter that owns the deliverable (Method
`—`, no separate work scoped here): STORE-18 → PERF-29/-31, STORE-40/-41/-42/-43 → MIG-06/-09/-10,
STORE-44 → HA-02, STORE-46 → HA-48, STORE-53 → the consolidated MIG FEATURE-MAP drift-guard row, and
STORE-54 → SEC-01. Conversely **STORE-45 is the owner** of the config-only `.mfbak` /
`DbaDelegatedError` deliverable and **HA-56 points here**; purge/retention *correctness* likewise
stays owned by this chapter.

**New coverage classes.** STORE-63 through STORE-73 close four gaps no chapter previously owned:
a purge that dies **mid-transaction** (STORE-63/-64, R22), **disk-full / ENOSPC** injection across
purge, WAL-checkpoint/VACUUM and `.mfbak` write (STORE-65/-66/-67/-68, R23), the **memory-pressure
control** that stops STORE-16 passing vacuously (STORE-69, R5), and the **destructive-operator-error**
class (STORE-70/-71/-72/-73, R24). All eleven are T rows.

**Foreign IDs are prefixed** throughout: `FCP:` = a `docs/testing/FEATURE-COVERAGE-PLAN.md` gap ID,
`W25:` = a WIN2025 test ID. A bare ID (`STORE-18`, `HA-02`, `PERF-29`) always means a row of *this*
plan.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| STORE-01 | Run `tests/test_per_connection_retention.py` on the real server-DB legs | Cross-backend | CI-leg | container-CI | x2 | T | P0 | A named step in **both** `sqlserver-store` (2022 + 2025) and `postgres-store` runs the file; each leg reports 9 passed / 0 skipped; `tests/test_per_connection_retention` is added to the `ci.yml:434` `serverdb` regex so a `store/**` PR pulls it pre-merge |
| STORE-02 | Inverted-predicate mutant: flip `_pg_cutoff_case` / `_qmark_cutoff_case` to `>=` and confirm the new legs fail | Negative/Security | pytest | container-CI | x2 | T | P0 | With the mutant applied, `test_three_backend_parity` fails on **both** PG and SQL Server (not just SQLite); reverting restores green. Recorded as a one-off mutation proof in the PR, not a checked-in test |
| STORE-03 | Per-connection keep-forever (`-inf`) survives a global purge on PG + SQL Server | Cross-backend | pytest | container-CI | x2 | T | P0 | Inbound with `connection_cutoffs={"IB_KEEP": float("-inf")}` retains `messages.raw` byte-identical after a pass whose global cutoff covers it; a sibling with no override is blanked to `''` |
| STORE-04 | Per-connection **outbound** `dead_letter_days` cutoff on PG + SQL Server | Cross-backend | pytest | container-CI | x2 | T | P0 | `purge_dead_letters(connection_cutoffs={"OB_FAST": …})` blanks only `OB_FAST`'s DEAD `queue.payload`; `OB_SLOW`'s payload is unchanged and still replayable |
| STORE-05 | Run `tests/test_embedded_document_pruning.py` on the real server-DB legs | Cross-backend | CI-leg | container-CI | x2 | T | P1 | A named step in both server legs runs the file; 10 passed / 0 skipped; the filename is in the `serverdb` regex |
| STORE-06 | Strip write-back keeps the message parseable on PG + SQL Server | Cross-backend | pytest | container-CI | x2 | T | P1 | After `strip_embedded_documents`, the stored raw re-parses via `parsing/peek.py` with the same MSH-9/MSH-10; each stripped embed is a tombstone carrying size + content-type + pruned ts; `messages.documents_pruned` is set; a second call returns `StripResult(0,0,0)` |
| STORE-07 | Full-suite sweep with `MEFOR_TEST_FORCE_AAD_BIND=1` on ubuntu (SQLite) | Negative/Security | CI-leg | container-CI | SQLite | T | P0 | A scheduled workflow runs `pytest -q` with the env var set; **0 failures**; the leg is named in `ci-gate`'s roll-up and its cadence is documented in `docs/CI-QUALITY.md` |
| STORE-08 | Same sweep on both server-DB legs | Negative/Security | CI-leg | container-CI | x2 | T | P0 | The scheduled `sqlserver-store` and `postgres-store` steps run with `MEFOR_TEST_FORCE_AAD_BIND=1`; 0 failures; a planted `aad=None` in `purge_message_bodies`' re-encrypt path makes the leg red |
| STORE-09 | Purge / strip write-back preserves the `mfenc:v2` cell binding | Negative/Security | pytest | container-CI | x3 | T | P0 | With `aad_bind=True`: after `strip_embedded_documents` the rewritten `messages.raw` decrypts under `cell_aad("messages","raw",id)` and **fails** with a different row id; the stored value carries the `mfenc:v2` prefix |
| STORE-10 | `rotate-key` upgrades v1→v2 in place on PG + SQL Server | Cross-backend | pytest | container-CI | x2 | T | P1 | Seed rows written by the frozen v1 writer; after `reencrypt_to_active` every `_CIPHER_COLUMNS` cell (incl. `response.body/detail/resp_headers`, `state.value`, `attachment_chunk.ciphertext`) reads back correctly and carries `mfenc:v2`; no row remains v1 |
| STORE-11 | Interrupted `rotate-key` resumes without data loss | HA/Resilience | pytest | container-CI | x3 | T | P2 | Kill the rotation after the first `batch=500`; with the prior key in `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`, every row still decrypts; a re-run completes and leaves 0 rows under the retired key; dropping the retired key afterwards loses nothing |
| STORE-12 | ADR 0019 §11.3.3 "off by default" doc-vs-code guard | Compat | pytest | any | n/a | T | P2 | A guard in `tests/test_phi_at_rest_inventory.py` asserts that no `docs/` text claims `[store].aad_bind` is off/opt-in-by-default while `StoreSettings.aad_bind` is `True`; planting the stale sentence fails the guard |
| STORE-13 | PHI serve gate sees per-connection `messages_days=0` | Negative/Security | pytest | dev-PC | n/a | T | P0 | `serve` on a PHI instance under `enforcement=enforce` with a global 30-day window and **every** inbound at `messages_days=0` exits **2** and names the offending Connection(s); the same registry with one inbound at `30` starts |
| STORE-14 | Non-prod PHI auto-bound does not mask a per-connection keep-forever | Negative/Security | pytest | dev-PC | n/a | T | P0 | On a staging PHI instance the 30-day auto-bound still fires **and** a warning naming each `messages_days=0` inbound is printed to stderr; `allow_keeping_phi_indefinitely=true` downgrades it to the audited-warning path and emits an `AUDIT:` log line naming the connections |
| STORE-15 | `messagefoundry check` lint: unbounded per-connection PHI retention | Negative/Security | pytest | dev-PC | n/a | T | P1 | A new blocking check in `messagefoundry/checks.py` fails (`ok=False`, exit 1) for a PHI+enforce config dir whose inbounds all set `messages_days=0`; SKIPs with no `messagefoundry.toml`; passes on a synthetic/dev posture |
| STORE-16 | `strip_embedded_documents` materializes at most a bounded batch | Performance | pytest | container-CI | x3 | T | P1 | With 500 eligible candidates and a batch bound of K, a single call decrypts ≤ K bodies (counted by instrumenting the cipher) and returns; repeated calls drain the backlog; totals equal the unbounded result |
| STORE-17 | ADR 0137 deadline is honoured **inside** the document-strip phase | Performance | pytest | dev-PC | SQLite | T | P1 | With `max_pass_seconds` small and a fake monotonic clock advanced per candidate, `run_once` stops mid-strip, returns `capped=True`, leaves the remaining candidates un-stripped, and the next pass strips them |
| STORE-18 | Purge under sustained intake — ACK latency and zero loss (measurement) | Performance | — | — | — | T | P1 | Covered by PERF-29/-31; no separate work scoped. Purge/retention **correctness** stays owned here (STORE-19/-20/-21/-24) |
| STORE-19 | SQL Server lock escalation on `messages` during a large purge | Performance | load-harness | container-CI | x2 | T | P1 | While the PERF-29/-31 sustained-purge profile runs on SQL Server, `sys.dm_tran_locks` shows **no** `OBJECT`-granularity `X`/`IX`-escalated lock on `messages`; if one appears, `ALTER TABLE messages SET (LOCK_ESCALATION = DISABLE)` (mirroring `queue`) removes it and the test pins the setting |
| STORE-20 | SQLite writer-lock hold time during a purge is bounded | Performance | pytest | dev-PC | SQLite | T | P1 | Instrument `store.py`'s `self._lock`: purging a 100 k-row backlog holds the writer lock for ≤ a declared budget per call, or the purge is batched; a concurrent `enqueue_ingress` completes within the MLLP receive timeout |
| STORE-21 | Purge vs per-lane FIFO ordering | Functional | pytest | container-CI | x3 | T | P2 | A backend-parametrized case interleaves a full retention pass with active delivery: per-lane delivery order is strictly non-decreasing in `seq`, no claim head is skipped, `delivered_keys` has no gaps, and the purge's own counts are unchanged |
| STORE-22 | Purge vs pool contention on a server DB | Performance | load-harness | container-CI | x2 | C | P2 | The `connscale` rig at N≈32 inbounds with retention enabled: `messagefoundry_store_pool_acquire_wait_p99_seconds` during a purge is reported alongside the no-purge baseline; a regression threshold is agreed and pinned in `docs/LOAD-TESTING.md` |
| STORE-23 | Purge + VACUUM benchmark and disk reclamation | Performance | load-harness | dev-PC | x3 | C | P2 | Over a seeded synthetic backlog (see §2.7) the bench reports, per backend: purge duration, rows purged/s, bytes reclaimed after `VACUUM` (SQLite) or after the DBA-run reclaim (server DBs), and index size before/after. Numbers land in `docs/LOAD-TESTING.md`; the `max_pass_seconds` recommendation is either confirmed or revised |
| STORE-24 | Purge pass over a 10⁵-message backlog completes inside `max_pass_seconds` | Performance | load-harness | container-CI | x3 | T | P2 | With `max_pass_seconds=14400` and a 100 k backlog, a pass ends `capped=False`; with `max_pass_seconds` set to the measured p50 pass time / 2, it ends `capped=True` and the skipped phases stay due (their last-run markers unchanged) |
| STORE-25 | Per-connection purged counts in the `retention_purge` audit row | PHI | pytest | dev-PC | SQLite | C | P2 | Either the detail gains `messages_purged_by_connection` / `dead_purged_by_connection` maps whose values sum to the aggregates and which contain **no** message content, **or** ADR 0027 D3 is amended and a guard pins the aggregate-only contract. Whichever is chosen, a test asserts it |
| STORE-26 | `/metrics` retention series | Functional | pytest | dev-PC | x3 | T | P1 | `GET /metrics` exposes: a DB-size gauge, purged-row counters labelled by tier (messages / dead / state / conn-events / alert-instances / presets / documents), a last-successful-pass unix-timestamp gauge, and a `capped` gauge. Values move after `run_once`; none carries a connection-identifying label that leaks PHI (see OQ-10) |
| STORE-27 | Retention audit row and storage alert are PHI-free on all backends | PHI | pytest | container-CI | x3 | T | P1 | The `retention_purge` detail parses as JSON, contains no substring of any seeded body, no `raw` key, and no preset `criteria`; the `storage_threshold` alert payload carries only path + sizes |
| STORE-28 | Web-console legibility of retention state | Usability | manual | browser-matrix | SQLite | C | P2 | An operator opens `/ui`, finds the last `retention_purge` audit entry and the `storage_threshold` alert, and can answer "is maintenance keeping up?" without reading raw JSON. Recorded as pass/fail with the reviewer's note; drives whether a console retention page is scheduled |
| STORE-29 | `wal_checkpoint_seconds` / `vacuum_at` on a server DB warn or refuse | Negative/Security | pytest | dev-PC | x2 | T | P1 | Starting with either knob set on `backend=postgres`/`sqlserver` emits a startup warning naming the knob as a **no-op (DBA-owned)** and pointing at PHI.md §8 (or refuses, per OQ-8). Byte-identical on SQLite |
| STORE-30 | Runner startup log does not claim a disabled maintenance phase | Negative/Security | pytest | dev-PC | x2 | T | P1 | On a server-DB store the `retention enabled: …` line either omits `vacuum_at=` / `wal_checkpoint_seconds=` or marks them `(no-op on this backend)`; caplog assertion |
| STORE-31 | `max_db_mb` size threshold + alert on real PG and SQL Server | Functional | pytest | container-CI | x2 | T | P1 | `db_status().size_bytes` is non-zero and monotonically non-decreasing after a large insert (`SUM(size)` over `sys.database_files` / `pg_database_size()`); crossing `max_db_mb` fires exactly one `storage_threshold` alert; `disk_free_bytes` is `0` and documented as such |
| STORE-32 | Retention runner starts for a per-connection-only document-prune config | Functional | pytest | dev-PC | SQLite | T | P2 | With every `[retention]` window `0` and one inbound setting `prune_documents_after`, `RetentionRunner.enabled` is True and `start()` spawns a task; with no such inbound and no windows it stays False and spawns nothing |
| STORE-33 | Retention misconfiguration is rejected at load | Negative/Security | pytest | dev-PC | n/a | T | P2 | Negative windows, `purge_interval_seconds<=0`, a malformed `vacuum_at`, and `prune_documents_after<=0` on an inbound each raise a `ValidationError`/`ValueError` naming the field; `messages_days=0` remains legal (keep-forever) |
| STORE-34 | Legal hold — disposition and guard | Negative/Security | pytest | dev-PC | n/a | C | P2 | Pending OQ-1. If declined: a guard test asserts no `legal_hold` / hold-exception surface exists and `docs/PHI.md §8` states per-connection `messages_days=0` is the accepted answer. If accepted: a held message survives ≥ 2 purge passes, appears in the `retention_purge` audit detail as held, and cannot be cleared without an audited `hold:release` action |
| STORE-35 | Concurrent `put_attachment` vs `sweep_orphan_attachments` on PG + SQL Server | HA/Resilience | pytest | container-CI | x2 | T | P1 | Process A commits chunks (refcount 0) and pauses before the ingress incref; process B runs the startup sweep; A's ingress transaction either commits intact or rolls back cleanly (no ACK, no half-written attachment, no orphan chunk left). Repeated 20× with no flake and no PHI chunk surviving |
| STORE-36 | Orphan sweep gains an age/grace guard or a leader gate | HA/Resilience | pytest | container-CI | x2 | C | P1 | Pending OQ-9. A chunk group younger than the grace window (or written by a live peer) is **not** swept; an aged refcount-0 attachment still is; the sweep count is logged. On a `[cluster]` store the sweep runs on the leader only |
| STORE-37 | Attachment release across the DEAD / replay boundary on PG + SQL Server under `aad_bind` | Cross-backend | pytest | container-CI | x2 | T | P1 | With `MEFOR_TEST_FORCE_AAD_BIND=1`: a message whose outbound rows are all DEAD keeps its attachment through `purge_message_bodies`; `purge_dead_letters` then releases it; the chunk ciphertext decrypts under its own cell AAD right up to GC |
| STORE-38 | Attachment download API is PHI-audited on all three backends | PHI | pytest | container-CI | x3 | T | P2 | `GET /messages/{id}/attachments/{id}` returns the verbatim bytes, writes one PHI-access audit row naming the acting user, and 404s for an attachment not linked to that message. Extends `tests/test_attachment_download_api.py` to the server backends |
| STORE-39 | `outbox` legacy table stays empty on a current build | PHI | pytest | container-CI | x2 | T | P1 | After a full staged run (ingress → routed → outbound → delivered → purged) on SQL Server, `SELECT COUNT(*) FROM outbox` is `0`; a source guard asserts no `INSERT INTO outbox` / `UPDATE outbox` exists in `messagefoundry/` |
| STORE-40 | Pre-migration SQLite fixture DB opens under the current build | Upgrade | — | — | — | T | P2 | Covered by MIG-06/-09/-10 (store vintage / schema-upgrade matrix); no separate work scoped |
| STORE-41 | Alternating two-build opens on a server backend (version skew) | Upgrade | — | — | — | T | P2 | Covered by MIG-06/-09/-10; no separate work scoped |
| STORE-42 | Out-of-band schema drift is not silently healed | Upgrade | — | — | — | T | P2 | Covered by MIG-06/-09/-10; no separate work scoped |
| STORE-43 | `_MIGRATION_REV` bump guard | Upgrade | — | — | — | T | P2 | Covered by MIG-06/-09/-10; no separate work scoped |
| STORE-44 | Run the six gated DR/backup server-DB files in CI | Cross-backend | — | — | — | T | P0 | Covered by HA-02; no separate work scoped |
| STORE-45 | `snapshot_to` on a server DB raises `DbaDelegatedError` and the runner falls back — **owned here** (HA-56 points at this row) | Cross-backend | pytest | container-CI | x2 | T | P1 | Against a real PG / SQL Server store, `snapshot_to` raises `DbaDelegatedError`; `BackupRunner` writes a **config-only** `.mfbak`, restore-verifies it, and writes one `dr_backup` audit row recording `config_only=true`; with `[backup].config_only_on_server_db=false` it skips and audits the skip |
| STORE-46 | ADR 0102 server-DB DR seed gate against a real server store | HA/Resilience | — | — | — | T | P0 | Covered by HA-48; no separate work scoped |
| STORE-47 | Backup taken while a retention pass is running | HA/Resilience | pytest | dev-PC | SQLite | T | P2 | A `VACUUM INTO` / Online-Backup snapshot concurrent with `run_once` produces an archive that passes `restore-verify --full`; the live store's purge counts are unaffected; neither operation errors |
| STORE-48 | Restore-verify of an archive on a UNC share under alternate credentials | HA/Resilience | manual | W2025-box | SQLite | T | P2 | `messagefoundry restore-verify \\<server>\<share>\<name>.mfbak --json` under the NSSM service account exits 0 with `status: "OK"`; a wrong-key run exits non-zero with `KEY_MISMATCH` **before** decrypt and prints no key material |
| STORE-49 | Cross-box cold-DR restore | HA/Resilience | manual | W2025-box | SQLite | T | P2 | An archive written on box A restore-verifies on box B with the DEK supplied per the site's key-custody procedure; a DPAPI-protected key minted on A **fails closed** on B with a `DpapiError` and no partial restore. Result recorded in WIN2025-ACCEPTANCE |
| STORE-50 | Retention + backup rows exist in the acceptance matrix | Functional | acceptance-probe | any | x3 | T | P1 | `harness/acceptance/matrix.py` gains per-DB rows for: a retention pass purges past-window bodies; the pass writes one `retention_purge` audit row; the document strip runs; a `.mfbak` backup + restore-verify completes (or records the DBA-delegated fallback on a server DB). `python -m harness.acceptance` lists them and they map to real suites |
| STORE-51 | WIN2025 plan gains a retention/backup section | Functional | manual | W2025-box | x3 | T | P1 | `docs/testing/WIN2025-TEST-PLAN.md` + `-MATRIX` + `-ACCEPTANCE` each carry a retention/purge/backup section with on-box steps (service-identity purge, `vacuum_at` no-op confirmation on SQL Server, backup to a UNC destination); the grep for "retention\|purge\|vacuum\|mfbak" returns real sections |
| STORE-52 | `verify` reports retention posture on-box | Functional | verify | W2025-box | x3 | T | P2 | `messagefoundry verify --section store` reports the effective PHI-body windows, whether any Connection overrides them, and whether `vacuum_at`/`wal_checkpoint_seconds` are no-ops on this backend; PHI-free output |
| STORE-53 | `FEATURE-MAP.md` §5 vs code guard | Compat | — | — | — | T | P2 | Covered by the consolidated MIG FEATURE-MAP drift-guard row (one row extending `tests/test_feature_map_claims.py`); no separate work scoped. The §5 specifics this chapter needs — ADRs 0019/0027/0042/0049/0062/0064/0105/0137 named, rows for DR backup, streaming attachments, the KeyProvider seam, pool sizing and schema-init, and the **DBA-delegated VACUUM/WAL caveat** on the "Retention / purge / maintenance" row — are supplied to MIG as inputs |
| STORE-54 | ADR 0027 / ADR 0042 in-file Status matches the index | Compat | — | — | — | T | P2 | Covered by SEC-01 (ADR-status-vs-code hygiene guard); no separate work scoped. Input to SEC-01: both ADR files' `Status:` line must read Accepted/built, matching `docs/adr/README.md:57,72` |
| STORE-55 | ADR 0105 Phase 3b "not built" claims retired | Compat | pytest | any | n/a | T | P2 | `docs/adr/README.md:134` and `FCP:STOREF-18` (:398, :535) no longer say the operator read/download surface is unbuilt; a guard pins the claim against the presence of `Store.attachments_for` and the `/messages/{id}/attachments/{id}` route |
| STORE-56 | Pool over-provision warning fires at serve on a server DB | Functional | pytest | container-CI | x2 | T | P2 | Serving with `[store].pool_size=80` on PG/SQL Server logs the ADR 0062 cliff warning naming `POOL_SIZE_CLIFF`; `pool_size=40` logs nothing; SQLite never warns |
| STORE-57 | `uploads_retention_days` prune is audited and bounded | PHI | pytest | dev-PC | x3 | T | P2 | With `[store].uploads_dir` set, files past `uploads_retention_days` (default 30, `ge=1`) are removed by `UploadRetentionRunner` **and** by the save-time sweep; each pair writes an `upload.prune` audit row; no file body appears in any log |
| STORE-58 | `prune_processed_files` age/count prune parity | Functional | pytest | container-CI | x3 | T | P2 | Age and count prunes each delete the expected rows on all three backends and return the combined count; documented in PHI.md §8 as driven from the wiring runner (guard already exists — extend it to assert the backend parity) |
| STORE-59 | Vault Transit (`mfenc:v3`) survives purge, strip and rotation | Cross-backend | pytest | container-CI | SQLite | T | P2 | With `cipher_provider=vault_transit` against a faked/containerised Transit: a purge blanks bodies, a strip re-encrypts a rewritten body that reads back, and the audit chain MAC still verifies. No DEK bytes appear in heap dumps or logs |
| STORE-60 | Vault / OpenBao live KeyProvider + Transit leg | Cross-backend | manual | dev-PC | SQLite | C | P2 | Against a live Vault/OpenBao with Transit + KV v2: store opens, a purge pass runs, `rotate-key` completes, and the unpublished vault-benchmark throughput spike ADR 0138 names as a prerequisite is recorded. Result written into ADR 0138's implementation-status section. **C — the deliverable is a recorded number + a written status update, with no threshold to fail against; it becomes a T row when ADR 0138 records the throughput floor** |
| STORE-61 | Backend capability flags gate the attachment surface | Negative/Security | pytest | container-CI | x3 | T | P2 | With `supports_streaming_attachments` forced False, `put_attachment` / `sweep_orphan_attachments` raise rather than silently no-op, and the engine's startup sweep is skipped without an error log |
| STORE-62 | `open_store` unknown-backend and cipher-provider fail-closed | Negative/Security | pytest | dev-PC | n/a | T | P2 | `backend=mysql` raises `NotImplementedError`; `cipher_provider=aesgcm2` raises a `ValueError` naming the two valid providers; an unbuilt external `key_provider` (`aws_kms`/`azure_kv`/`gcp_kms`/`pkcs11`) raises `KeyProviderError` with no key material in the message |
| STORE-63 | Purge pass killed **mid-transaction** leaves the store consistent | HA/Resilience | pytest | container-CI | x3 | T | P1 | `SIGKILL`/connection-abort the engine inside `purge_message_bodies`' delete/blank batch (fault-injected between the body blank and the metadata NULL). On re-open: **no** row exists with `raw = ''` and `metadata IS NOT NULL` (or the reverse), row counts reconcile against a pre-kill snapshot, and no `queue`/`messages` row is left claimed-but-unowned. Repeated at 5 distinct injection points × 3 backends with no surviving inconsistency |
| STORE-64 | An interrupted purge is resumable and never advances a watermark past unpurged data | HA/Resilience | pytest | container-CI | x3 | T | P1 | After the STORE-63 kill, the next `RetentionRunner.run_once()` purges **exactly** the rows the killed pass did not, with no double-decref of a shared attachment and no rows stranded past the cutoff. `_last_vacuum_day` ([retention.py:251,548,1005](../../../messagefoundry/pipeline/retention.py)) and every phase's last-run marker are **unchanged** by a pass that did not complete, so the skipped phase stays due; a planted "mark first, work second" ordering fails the test |
| STORE-65 | Disk-full (ENOSPC) **mid-purge** fails closed and recovers | HA/Resilience | pytest | container-CI | x3 | T | P1 | Inject `OSError(ENOSPC)` (loopback/quota-bounded volume on SQLite; a filled data file on PG/SQL Server) during a purge pass: the pass aborts with a logged `ERROR`, the store re-opens cleanly, **no acknowledged message is lost** and none silently changes disposition, and an operator-visible `storage_threshold` alert fires (`AlertSink.storage_threshold`, [pipeline/alerts.py:87](../../../messagefoundry/pipeline/alerts.py)) — see the ALERT chapter for the sink/notification half. Freeing space and re-running completes the purge with no manual repair |
| STORE-66 | ENOSPC **mid WAL-checkpoint / VACUUM** does not corrupt the store | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | Fill the volume during `wal_checkpoint()` ([store.py:8650](../../../messagefoundry/store/store.py)) and during `vacuum()` ([store.py:8658](../../../messagefoundry/store/store.py)): each raises rather than silently returning, `PRAGMA integrity_check` returns `ok` afterwards, the `-wal` sidecar is not truncated mid-frame, ingress continues to fail closed (NAK, no accepted-and-dropped message), and the next successful pass reclaims the space |
| STORE-67 | ENOSPC **mid `.mfbak` write** never leaves a "restorable" truncated archive | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | Fill the destination volume during `BackupRunner`'s archive write: the run fails with a named error, writes a `dr_backup` audit row recording the failure, and either removes the partial archive or leaves one that `restore-verify` rejects (**never** exits 0). The keep-N prune does not count the failed archive; freeing space and re-running produces an archive that restore-verifies |
| STORE-68 | Free-space threshold — not just `max_db_mb` — raises an operator-visible capacity alert | Functional | pytest | container-CI | x3 | T | P1 | A free-space signal exists alongside the `max_db_mb` size threshold ([retention.py:658](../../../messagefoundry/pipeline/retention.py)): crossing a configured free-space floor fires exactly one `storage_threshold` alert carrying path + sizes only (no message content), and the alert clears/re-arms once space is freed. On PG / SQL Server, where `disk_free_bytes` is `0` by construction ([postgres.py:6592](../../../messagefoundry/store/postgres.py), [sqlserver.py:9205](../../../messagefoundry/store/sqlserver.py)), the row asserts the documented DBA-delegated position instead of a fabricated number |
| STORE-69 | The **unbounded** strip path measurably degrades (anti-vacuity control for STORE-16) | Performance | pytest | dev-PC | SQLite | T | P1 | Against the pre-fix `strip_embedded_documents` ([store.py:8425](../../../messagefoundry/store/store.py)) with a synthetic backlog of N large document bodies, peak process RSS grows approximately linearly in N and exceeds a declared bound at the target N; the bounded-batch implementation (STORE-16) stays flat under the same load. Without this control STORE-16 can pass vacuously on a backlog too small to materialize |
| STORE-70 | Restoring / seeding an **older** archive over a live store is refused or audited | Negative/Security | pytest | container-CI | x3 | T | P1 | Restoring a `.mfbak` whose newest `received_at` predates the live store's newest message either **refuses** with a named vintage reason, or completes only under an explicit operator override that writes one audit row naming the actor, both vintages and the message count at risk. The ADR 0102 vintage probe ([dr.py:397-453](../../../messagefoundry/pipeline/dr.py)) guards DR activation; this row extends the same posture to an operator-driven restore. **Never a silent overwrite** |
| STORE-71 | A per-connection retention override naming an unknown Connection cannot silently purge the wrong feed | Negative/Security | pytest | dev-PC | x3 | T | P2 | A `connection_cutoffs` key (or per-connection `messages_days`) naming a Connection absent from the registry is rejected at load with a `ValidationError`/`ValueError` naming the key — it must **not** fall through to the global cutoff. A typo'd override therefore cannot blank a feed the operator meant to keep; the negative case (a correctly-named override) still purges only its own feed |
| STORE-72 | `rotate-key` with no retired key present refuses before writing anything | Negative/Security | pytest | dev-PC | x3 | T | P1 | With a **new** active key and `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED` unset while the store already holds rows sealed under the prior key, `rotate-key` exits non-zero **before** re-encrypting any row and names the missing retired key (today's guard at [__main__.py:3462-3470](../../../messagefoundry/__main__.py) only checks that an *active* key exists). A probe read proves at least one existing row is undecryptable under the active key alone; after the run, every row still decrypts under the prior key — zero rows re-sealed |
| STORE-73 | Removing a Connection that still has queued rows is refused or audited | Negative/Security | pytest | dev-PC | x3 | T | P2 | `remove_connection` ([connections_edit.py:202](../../../messagefoundry/config/connections_edit.py)) against a Connection with undelivered `queue` rows either refuses with a count of the orphaned rows, or removes it only under an explicit `--force` that writes one audit row naming the actor and the abandoned row count. Either way the rows stay in the store and remain visible/replayable — **never** silently orphaned |

### 2.5 Detailed scenarios

#### S1 — STORE-01/02/05: promote the retention parity files onto the server-DB legs (and prove they can fail)

*Why narrative:* the tests already exist and pass locally; the whole value is in wiring them so they
**run** and demonstrating they can go red on the production backend.

**Preconditions.** A branch off `main`. Docker available (or push and let CI run). The
`sqlserver-store` matrix (`mcr.microsoft.com/mssql/server:2022-latest` and `:2025-latest`) and
`postgres-store` (`postgres:16`) legs already provision the containers and export `MEFOR_STORE_*`.

**Steps.**

1. Add `tests/test_per_connection_retention` and `tests/test_embedded_document_pruning` to the
   `serverdb` regex at `.github/workflows/ci.yml:434` (the alternation inside
   `tests/test_(sqlserver|postgres|cluster|…)`), so a `messagefoundry/store/**` PR pulls both legs
   pre-merge.
2. In the `sqlserver-store` job, add a step after the existing store-suite step, reusing that step's
   env block verbatim (`MEFOR_TEST_SQLSERVER=1`, `MEFOR_STORE_BACKEND=sqlserver`,
   `MEFOR_STORE_SERVER=localhost`, `MEFOR_STORE_PORT=1433`, `MEFOR_STORE_DATABASE=MessageFoundry`,
   `MEFOR_STORE_AUTH=sql`, `MEFOR_STORE_USERNAME=sa`, `MEFOR_STORE_PASSWORD`,
   `MEFOR_STORE_TRUST_SERVER_CERTIFICATE=true`, `MEFOR_ALLOW_INSECURE_TLS=1`,
   `PYTHONFAULTHANDLER=1`) and the `scripts/ci/retry-native-crash.sh` wrapper the other SQL Server
   steps use:
   `bash scripts/ci/retry-native-crash.sh pytest -v tests/test_per_connection_retention.py tests/test_embedded_document_pruning.py`
3. In `postgres-store`, add the plain twin (no retry wrapper; `MEFOR_TEST_POSTGRES=1`,
   `MEFOR_STORE_BACKEND=postgres`, `MEFOR_STORE_DATABASE=messagefoundry`,
   `MEFOR_STORE_USERNAME=postgres`, `MEFOR_STORE_PASSWORD=mefor`, `MEFOR_STORE_ENCRYPT=false`,
   `MEFOR_ALLOW_INSECURE_TLS=1`).
4. **Mutation proof (STORE-02), run once, not checked in.** In `messagefoundry/store/postgres.py`
   `_pg_cutoff_case` and `messagefoundry/store/store.py` `_qmark_cutoff_case`, invert the comparison
   the caller builds (`received_at <` → `received_at >=`). Push to a scratch branch, run
   `gh workflow run ci.yml --ref <branch>`.

**Observation point.** The GitHub Actions run summary for both legs: the step must report
`9 passed` / `10 passed` with **0 skipped** (a skip means `MEFOR_TEST_*` did not reach pytest — the
most likely wiring bug). For the mutant, the `test_three_backend_parity[postgres]` and
`[sqlserver]` node ids must fail; if only `[sqlite]` fails, the parametrization never reached the
server backends and step 2/3 is wrong.

**Expected result.** Green legs on the unmutated branch; red on the mutant, on both server backends.

**Cleanup / rollback.** Revert the mutant commit; delete the scratch branch. The store fixtures in
these files already `TRUNCATE … RESTART IDENTITY CASCADE` (Postgres) / `DELETE FROM …` (SQL Server)
on open, so the shared container DB is left clean; no manual DB cleanup is required.

#### S2 — STORE-07/08: the forced-AAD sweep (the shipped writer)

*Why narrative:* this is a whole-suite behaviour change driven by one env var; it will surface
failures in unrelated files and must be triaged, not just switched on.

**Preconditions.** `tests/conftest.py:122-150` already implements the session fixture — when
`MEFOR_TEST_FORCE_AAD_BIND=1` it patches `AesGcmCipher.__init__` so **every** cipher writes v2.
Nothing new is needed in the test code.

**Steps.**

1. Locally first: `$env:MEFOR_TEST_FORCE_AAD_BIND="1"; $env:QT_QPA_PLATFORM="offscreen"; pytest -q`
   (PowerShell). Triage every failure into one of two buckets — (a) a test that *pins the v1 format
   as its claim* (legitimate; those already carry the "v1 here, v2 via build_cipher/aad_bind or
   `MEFOR_TEST_FORCE_AAD_BIND`" comment, e.g. `tests/test_ack_sent_store.py:60`,
   `tests/test_transform_state.py:278`) — these must be made format-agnostic or explicitly skipped
   under the flag; (b) a **real** binding bug on a write path — file it.
2. Add a scheduled workflow (or a `schedule`-gated job in `ci.yml`) that runs `pytest -q` on
   ubuntu with the flag set.
3. Add the flag to the env block of the `sqlserver-store` store-suite step and the `postgres-store`
   store-suite step, **on the scheduled run only** (`if: github.event_name == 'schedule'`) so PR
   minutes are unaffected.
4. Prove it can fail: temporarily pass `aad=None` in the re-encrypt inside
   `messagefoundry/store/store.py::purge_message_bodies`' strip write-back path and confirm the
   forced-AAD leg goes red while the normal leg stays green.

**Observation point.** The scheduled run's summary; and `docs/CI-QUALITY.md`, which must name the
leg and its cadence so the next author knows it exists.

**Expected result.** 0 failures on the sweep; the planted mutant is caught only by the sweep.

**Cleanup / rollback.** Revert the mutant. If the sweep is too noisy to land in one pass, gate it
`continue-on-error: true` for one cycle **with a tracked ticket** — never leave it silently
non-blocking.

#### S3 — STORE-13/14/15: the per-connection PHI serve-gate bypass

*Why narrative:* it is a refuse-to-start path; getting the posture wrong makes the test pass for the
wrong reason.

**Preconditions.** A throwaway config dir (copy `samples/config`) and a `messagefoundry.toml` with
`[ai] environment = "prod"`, `data_class = "phi"`, `production = true`, and
`[security] enforcement = "enforce"`. Registry: every inbound sets `messages_days=0`.
`[retention] messages_days = 30`, `dead_letter_days = 30` (both **bounded**, so today's gate passes).

**Steps.**

1. Baseline the current (buggy) behaviour:
   `python -m messagefoundry serve --config <dir> --db <tmp>/t.db --service-config <toml>` —
   record that it starts (exit is not 2). This is the defect.
2. Extend the gate at `messagefoundry/__main__.py:1968` to fold the registry's per-connection
   overrides into `unbounded_windows`: an inbound with `messages_days == 0` and an outbound with
   `dead_letter_days == 0` are unbounded PHI windows under a PHI posture.
3. Write the pytest in the existing `tests/test_cli.py` neighbourhood of `:1383-1500` (same
   fixtures, same `capsys`/exit-code idiom): assert exit `2` and that stderr names the offending
   Connection(s) **and** `[security].delete_message_bodies_after_days` (the canonical operator-facing
   home, per PHI.md §8).
4. Non-prod twin (STORE-14): `environment = "staging"`, PHI, not enforcing — assert the 30-day
   auto-bound **still** fires for the unset global windows *and* a warning names each `messages_days=0`
   inbound.
5. Audited-override twin: `[security].allow_keeping_phi_indefinitely = true` under enforce — assert
   the refusal downgrades to the `AUDIT:` warning and that the log line names the connections.
6. `messagefoundry check` lint (STORE-15): add a blocking check beside `_check_posture` in
   `messagefoundry/checks.py`; run `python -m messagefoundry check --config <dir> --service-config <toml>`
   and assert exit 1 with the check named.

**Observation point.** Process exit code + stderr text; `caplog` for the audited-override branch;
the `check` JSON (`--json`) for the lint.

**Expected result.** Exit 2 (prod/enforce), warning (staging), audited warning (override), lint
failure at commit time.

**Cleanup / rollback.** Delete the tmp store and config dir. No PHI is involved — the config carries
no messages.

#### S4 — STORE-19/20: purge under sustained load

*Why narrative:* multi-process, timing-dependent, and the SQL Server observation needs a DMV query
run at the right moment.

*Ownership:* the **load measurement itself** (ACK latency and zero loss under a sustained purge) is
**PERF-29/-31**; STORE-18 is a pointer at it. What stays owned here are the two *correctness*
observations made **while that profile runs** — SQL Server lock escalation (STORE-19) and the SQLite
writer-lock hold budget (STORE-20). Steps 1–3 below are the PERF rig, restated only so the STORE
observations are reproducible; do not scope them twice.

**Preconditions.** A server-DB container (or the W2025 box) with a **non-OS** data volume. A
pre-seeded, PHI-free backlog: generate with `python -m messagefoundry generate` into a git-ignored
corpus and drive it in via `harness/config/load` (see §2.7 — **never** redirect `generate`/`dryrun`
stdout into a committed file, ticket, or CI log). Target ~10⁵ messages, all past the retention
window (seed with a back-dated `received_at`).

**Steps.**

1. Serve the load config against the seeded store, with retention on and a short interval:
   `MEFOR_RETENTION_MESSAGES_DAYS=1 MEFOR_RETENTION_PURGE_INTERVAL_SECONDS=60 MEFOR_RETENTION_MAX_PASS_SECONDS=0 MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_TRANSFORM=edit MEFOR_LOAD_SINK_PORT=2700 python -m messagefoundry serve --config harness/config/load --db <backend> --env dev`
2. Establish a **baseline**: run the load profile with retention **off**
   (`MEFOR_RETENTION_MESSAGES_DAYS=0`) and record ACK p50/p99 from the report JSON.
3. Re-run with retention on, so a pass fires mid-run:
   `python -m harness --load <new retention profile> --engine http://127.0.0.1:8765 --sink-port 2700 --report-json out/load/retention.json`
   (the new profile lives at `harness/load/profiles/retention.toml`; `--load` accepts a path).
4. **SQL Server only, during the pass** (STORE-19), from a separate session:
   `SELECT resource_type, request_mode, resource_associated_entity_id FROM sys.dm_tran_locks WHERE resource_type = 'OBJECT';`
   and correlate `resource_associated_entity_id` with `OBJECT_ID('messages')`. An Extended Events
   session on `lock_escalation` is the more reliable capture if the pass is short.
5. **SQLite only** (STORE-20): instrument the `self._lock` acquire/release around
   `purge_message_bodies` and log the hold duration at DEBUG **on a synthetic box only**.

**Observation point.** The load report JSON (`out/load/retention.json`) — ACK p99, loss count,
disposition histogram; the DMV/XE capture; the `retention_purge` audit row's `messages_purged`.

**Expected result.** Zero acknowledged loss; no message in `ERROR`; ACK p99 during the pass within
the agreed multiple of baseline (see OQ-6); no `OBJECT`-granularity escalated lock on `messages`.

**Cleanup / rollback.** Drop the seeded store/database. On a shared container, `DROP DATABASE` and
let the next leg's schema-init recreate it. Delete the generated corpus (it is git-ignored, but
delete it anyway — it is synthetic HL7, not a build artifact worth keeping).

#### S5 — STORE-35/36: the concurrent orphan sweep race

*Why narrative:* it needs two processes, a deliberate pause inside a transaction, and it is the one
place where the ADR 0105 two-object commit and engine sharding interact.

**Preconditions.** A PG or SQL Server store (the SQLite single-writer lock makes the race
unreachable there). Two async clients against the **same** store.

**Steps.**

1. Client A: `put_attachment(<synthetic PDF bytes>)` → chunks + header land at `refcount=0`
   (this is the deliberate ADR 0105 shape).
2. Hold A **before** `enqueue_ingress(attachment_refs=[…])` commits the incref (an
   `asyncio.Event` in the test, not a sleep).
3. Client B: `await store.sweep_orphan_attachments()` — the same call
   `messagefoundry/pipeline/engine.py:882` makes at every process start.
4. Release A and let the ingress transaction attempt to commit.
5. Assert: A either commits with the attachment intact **or** rolls back cleanly with **no** ACK,
   no half-written attachment, and no orphan chunk row left behind. Assert `attachment_chunk` has no
   rows for a rolled-back id.
6. Repeat 20× to catch a flake. Then apply the chosen guard (OQ-9: age/grace, an in-flight marker,
   or leader-gating the startup sweep) and assert the young chunk group is **not** swept while an
   aged refcount-0 attachment still is.

**Observation point.** Row counts in `attachment` / `attachment_chunk` / `message_attachment` after
each iteration; the ingress transaction's outcome; the sweep's returned reclaim count.

**Expected result.** Fail-closed today (documented), fail-**safe** after the guard: A's ingress
succeeds and B's sweep reclaims 0.

**Cleanup / rollback.** Truncate `attachment`, `attachment_chunk`, `message_attachment`, `messages`,
`queue` between iterations (the server fixtures already do this shape on open). Attachment bytes must
be synthetic — a generated PDF-shaped blob, never a real document.

#### S6 — MIG-06/-09/-10 (STORE-40/-41/-42 point here): schema drift and mixed-version fleets

*Why narrative:* it requires a checked-in binary fixture and a deliberately-broken DB — both easy to
get wrong in a way that makes the test vacuous.

*Ownership:* the store vintage / schema-upgrade matrix is **owned by MIG-06/-09/-10**; STORE-40/-41/
-42/-43 are pointers. This scenario is retained as the **store-side input** to those MIG rows — the
fixture provenance rules and the purge-over-an-upgraded-store assertion are store knowledge the MIG
chapter needs. No separate STORE work is scoped from it.

**Preconditions.** A SQLite store created by an **older** build. Build it by checking out a commit
predating the `_MESSAGE_MIGRATIONS` entries, running `python -m messagefoundry serve` briefly against
a scratch DB with **synthetic** messages only, then `messagefoundry rotate-key`-free (no key) so the
fixture carries no key material.

**Steps.**

1. Verify the fixture is PHI-free and small: open it, confirm every `messages.raw` is a generated
   HL7 body from `messagefoundry generate`, and that `audit_log`/`users` are empty. Commit it under
   `tests/fixtures/` with a README line naming its provenance.
2. STORE-40: open it with the current build (`MessageStore.open`), assert every current column
   exists (`PRAGMA table_info(messages)` ⊇ `_MESSAGE_MIGRATIONS.keys()`), then run a full
   `RetentionRunner.run_once()` and assert the pre-upgrade metadata sweep is **counted** in
   `messages_purged` (the `raw <> '' OR metadata IS NOT NULL` guard, PHI.md §8).
3. STORE-41 (server DBs): open the store, monkeypatch `_schema_hash()` to a second value, open
   again, restore, open again. Assert three successful opens, no error, no data loss, and record the
   wall-clock cost of each re-run batch.
4. STORE-42: drop an index out of band
   (`DROP INDEX ix_messages_channel ON messages;` / `DROP INDEX ix_messages_channel;`), re-open —
   assert the index is **still absent** (marker matched, batch skipped: the documented ADR 0064
   trade-off). Then `DELETE FROM schema_meta;`, re-open, assert the index is back.

**Observation point.** `PRAGMA table_info` / `sys.indexes` / `pg_indexes`; the purge count; the
per-open elapsed time.

**Expected result.** Old DB opens and purges correctly; alternating hashes are safe but measurably
costly; drift persists until the documented remedy is applied.

**Cleanup / rollback.** The fixture DB is copied to `tmp_path` before opening — never mutated in
place (assert its mtime/hash is unchanged at teardown). Drop the scratch server database.

#### S7 — STORE-45 (+ HA-02 / HA-48, which STORE-44/-46 point at): the DR/backup server-DB legs

*Why narrative:* six files that have never executed; the failure mode on first run is environmental,
not behavioural, and must not be mistaken for a product bug.

*Ownership:* **wiring the six files into CI is HA-02** and **the ADR 0102 live seed gate is HA-48**
(STORE-44 and STORE-46 are pointers, both P0, gated in the HA chapter). **STORE-45 — the config-only
`.mfbak` + `DbaDelegatedError` behaviour — is owned here**, and HA-56 points at it. Step 1 below is
the HA-02 wiring, restated only so step 3's STORE-45 assertions are reproducible.

**Preconditions.** The existing `sqlserver-store` / `postgres-store` containers. A writable local
destination directory in the runner workspace for `[backup].destination` (cloud URLs are rejected by
the `[backup]`/`[dr]` validators, so use a filesystem path).

**Steps.**

1. Add one step per leg running all three of that backend's files:
   `pytest -v tests/test_backup_runner_server_db_<be>.py tests/test_dr7_server_config_only_backup_<be>.py tests/test_dr_server_seed_gate_<be>.py`,
   reusing the leg's env block plus `MEFOR_BACKUP_DESTINATION=<workspace>/backups`.
2. Expect first-run environmental failures (destination preflight, a fixture assuming a SQLite
   `store.path`). Fix the **tests**, not the product, unless the assertion genuinely fails.
3. Assert the three behaviours explicitly: `snapshot_to` → `DbaDelegatedError`; `BackupRunner`
   writes a config-only `.mfbak` and restore-verifies it; exactly one `dr_backup` audit row records
   `config_only`. With `[backup].config_only_on_server_db = false`, the run **skips** and audits the
   skip.
4. Seed gate: on a freshly-created database `has_prior_backup_history()` is False and
   `pipeline/dr.py::_verify_live_server_seed` blocks activation with a named reason; after a
   recorded backup it is True.

**Observation point.** The CI step summary (passed, **0 skipped**); the archive files in the
workspace; the audit rows.

**Expected result.** All six files pass on both real backends.

**Cleanup / rollback.** Delete the workspace backup directory in a `always()` step so a failed run
does not leak archives into the artifact upload. Archives of a synthetic store contain no PHI, but
treat them as if they did — do not upload them as CI artifacts.

### 2.6 Automation disposition

**New pytest modules.**

| Module | Covers | Effort |
|---|---|---|
| `tests/test_retention_backend_parity.py` | STORE-03, -04, -06, -21, -27, -31 — a backend-parametrized (SQLite / PG / SQL Server, `MEFOR_TEST_*`-gated exactly like `test_per_connection_retention.py`) module for the purge behaviours the existing files assert only on SQLite: keep-forever `-inf`, outbound dead-letter cutoffs, strip re-parse, purge-vs-FIFO, audit PHI-freedom, `max_db_mb` on server DBs | **M** |
| `tests/test_retention_bounding.py` | STORE-16, -17, -20, -69 — bounded candidate materialization, the in-phase ADR 0137 deadline, the SQLite writer-lock hold budget, and the **memory-pressure control** proving the pre-fix unbounded path actually degrades (so STORE-16 cannot pass vacuously) | **M** |
| `tests/test_retention_posture_gate.py` | STORE-13, -14, -15 — the per-connection serve-gate bypass and the `check` lint (may instead extend `tests/test_cli.py:1383-1500`; a separate module keeps the registry fixtures out of the CLI file) | **S** |
| `tests/test_retention_observability.py` | STORE-26, -30 — the new `/metrics` series and the startup-log honesty assertion | **S** |
| `tests/test_attachment_sweep_race.py` | STORE-35, -36 — the concurrent `put_attachment` / `sweep_orphan_attachments` race and whichever guard OQ-9 selects. Server-DB gated | **M** |
| `tests/test_store_schema_upgrade.py` | *(pointer — built by **MIG-06/-09/-10**, not scoped here)* the pre-migration SQLite fixture, alternating-hash opens, out-of-band drift, `_MIGRATION_REV` pin. STORE-40/-41/-42/-43 point at it; S6 above is the store-side input | **—** |
| `tests/test_outbox_legacy_table.py` | STORE-39 — the SQL Server legacy `outbox` emptiness assertion + the source guard that nothing writes it | **S** |
| `tests/test_legal_hold.py` | STORE-34 — a guard that the surface does not exist (if declined) or the hold behaviour (if accepted). **Blocked on OQ-1** | **S** (guard) / **L** (mechanism) |
| `tests/test_retention_crash_recovery.py` | STORE-63, -64 — fault-injected mid-transaction kill of a purge pass on all three backends, the post-kill consistency reconciliation, and the "a pass that did not complete advances no watermark" assertion (`_last_vacuum_day` + every phase's last-run marker) | **L** |
| `tests/test_store_enospc.py` | STORE-65, -66, -67, -68 — ENOSPC injection during a purge, a WAL checkpoint / VACUUM, and a `.mfbak` write; the fail-closed + recover-when-freed assertions; and the free-space capacity signal. Needs the quota-bounded volume fixture from §2.7 | **L** |
| `tests/test_store_operator_error.py` | STORE-70, -71, -72, -73 — the destructive-operator-error class: older-archive-over-live restore, an override naming an unknown Connection, `rotate-key` without a retired key, and `connection remove` with queued rows. Every case must end in a refusal **or** an audited, recoverable outcome | **M** |

**Extensions to existing modules.**

- `tests/test_per_connection_retention.py` — nothing to change; it already parametrizes all three
  backends. It only needs to be **run** (STORE-01).
- `tests/test_embedded_document_pruning.py` — same (STORE-05).
- `tests/test_store_encryption.py` / `tests/test_store_aad_binding.py` — add STORE-09 (purge/strip
  write-back preserves the cell binding). **S**
- `tests/test_postgres_store.py` — add STORE-10 (full-column `rotate-key` parity, closing
  `FCP:CRYPTO-4`'s store-column half) and STORE-11 (interrupted-rotation resume). **M**
- `tests/test_sqlserver_store.py` — add STORE-11's SQL Server twin. **S**
- `tests/test_attachment_download_api.py` — add the server-DB legs (STORE-38). **S**
- `tests/test_phi_at_rest_inventory.py` — the right home for STORE-12, -29's doc half and -55 (it
  already owns the doc-vs-code guard idiom and the "retired claims cannot reappear" scanner). The
  ADR-status half of STORE-54 goes to **SEC-01**, not here. **S**
- `tests/test_feature_map_claims.py` — **not scoped here**: STORE-53 points at the consolidated MIG
  FEATURE-MAP drift-guard row, which extends this file once for the whole plan. Supply the §5
  specifics listed in STORE-53 to MIG as inputs. **—**
- `tests/test_settings.py` — STORE-29 (server-DB no-op knob warning/refusal), STORE-33, STORE-56. **S**
- `tests/test_retention.py` — STORE-25 (per-connection purged counts) and STORE-32
  (`enabled` with a prune-only registry). **S**
- `tests/test_backup_runner.py` — STORE-47 (backup concurrent with a retention pass) and STORE-67
  (ENOSPC mid-`.mfbak`: the failed archive must never restore-verify and must not consume a keep-N
  slot). **M**
- `tests/test_crypto_transit.py` — STORE-59. **M**
- `tests/test_store_capability_matrix.py` — STORE-61. **S**
- `tests/test_store_backend.py` — STORE-62. **S**

**New / changed CI legs.**

| Leg | Change | Effort |
|---|---|---|
| `ci.yml` `changes` job | Add `tests/test_(per_connection_retention\|embedded_document_pruning\|retention\|attachment_substrate\|backup_runner_server_db\|dr7_server_config_only_backup\|dr_server_seed_gate)` to the `serverdb` regex at `:434` | **S** |
| `ci.yml` `sqlserver-store` | One new step owned here: the retention parity files (behind `scripts/ci/retry-native-crash.sh`). The second step — the three SQL Server DR/backup files — belongs to **HA-02** | **S** |
| `ci.yml` `postgres-store` | The same, plain `pytest` (no retry wrapper) | **S** |
| New scheduled `aad-sweep` workflow | `pytest -q` with `MEFOR_TEST_FORCE_AAD_BIND=1` on ubuntu; plus the flag on the scheduled server-DB store-suite steps. Cadence per OQ-4 | **M** |
| `selfhosted-win2025-sql.yml` | Optionally extend with a retention + backup step once STORE-51's on-box section exists | **S** |

**Harness / probe capabilities.**

- `harness/load/profiles/retention.toml` + a retention hook in `harness/load/runner.py` (or simply a
  documented recipe using `MEFOR_RETENTION_*` at serve time — prefer the recipe first, the profile
  second). Covers STORE-22, -23, -24 and the STORE-19/-20 observations; the profile itself is built
  once by **PERF-29/-31** (STORE-18 points at it) — reuse it, do not build a second rig. **M**
- A purge/VACUUM **bench** (STORE-23) — a script under `tools/` or `scripts/`, not a pytest, that
  seeds a synthetic backlog and reports duration / rows-per-second / bytes reclaimed per backend. **M**
- `harness/acceptance/matrix.py` — new per-DB rows for retention pass, retention audit row, document
  strip, and backup + restore-verify (STORE-50), mapped to the suites above. **S**
- `messagefoundry verify --section store` — report the effective retention posture (STORE-52). **S**

**Stays manual (and why).**

| Item | Why it cannot be automated here |
|---|---|
| STORE-28 console legibility | A human judgement about whether an operator can tell maintenance is keeping up |
| STORE-48 UNC restore-verify under alternate credentials | Needs a domain file server and a second Windows identity (ADR 0132 path) |
| STORE-49 cross-box cold-DR restore | Key custody across two hosts is inherently un-unit-testable; DPAPI is machine/user-scoped by design |
| STORE-51 WIN2025 on-box section | On-box service-identity work; the plan section itself is a doc deliverable |
| STORE-60 live Vault/OpenBao | No CI leg exists; ADR 0138 was verified against live OpenBao once |
| DBA-side proof (`pg_dump`/PITR, `BACKUP DATABASE`/Always On, `DBCC CHECKDB`, shrink, index bloat) | The engine **refuses** these by design (`DbaDelegatedError`); they need DBA privileges and a real data volume |
| Long-horizon soak across midnight + a DST transition (daily VACUUM clock, keep-N prune, log sweep) | Requires real wall-clock days; the fake-clock tests already cover the logic, not the calendar |
| Observing SQL Server lock escalation via Extended Events on real hardware | Needs DMV/XE privileges on a real instance under real volume |
| Eyeballing a stripped-document tombstone vs a purged body in the console raw view | ADR 0042 D4 intent — "evicted" must read distinctly from "never present" |
| Counsel confirmation of an e-discovery hold procedure | No mechanism exists (OQ-1) |

**Rough total effort:** CI wiring **S** (the highest value-per-hour in this chapter), the AAD sweep
**M** (mostly triage), the new pytest modules **M–L** in aggregate, the load/bench work **M**, the
doc/guard fixes **S**.

### 2.7 Environment, data & prerequisites

**Already provisioned — reuse, do not stand up again.**

- SQL Server **2022** + **2025** containers (`mcr.microsoft.com/mssql/server:{2022,2025}-latest`) with
  `MEFOR_TEST_SQLSERVER=1` and the `MEFOR_STORE_*` block — `ci.yml:483`.
- PostgreSQL **16** container with `MEFOR_TEST_POSTGRES=1` and `MEFOR_STORE_*` — `ci.yml:732`.
- Microsoft **ODBC Driver 18** + `mssql-tools18` + `unixodbc-dev` on the runner (aioodbc/pyodbc).
  Note the pyodbc 5.3.0 / py3.14 native-crash retry wrapper `scripts/ci/retry-native-crash.sh`
  (upstream pyodbc#1459) — every new SQL Server step must use it.
- The self-hosted **Windows Server 2025 + SQL Server 2025** runner
  (`selfhosted-win2025-sql.yml`, `workflow_dispatch` only).

**To procure or stand up.**

| Need | For | Notes |
|---|---|---|
| A **scheduled CI slot** for the `MEFOR_TEST_FORCE_AAD_BIND=1` sweep (1 ubuntu + 2 server-DB runs) | STORE-07, -08 | Cadence is OQ-4 |
| A **non-OS data volume** with multi-GB headroom | STORE-23, -24 | WIN2025-TEST-PLAN `W25:A4` already calls for this shape |
| A **quota-bounded / small loopback volume** the test can deliberately fill (`truncate` + `mkfs` loop device on Linux CI; a small VHDX on the W2025 box), plus a filled PG tablespace / SQL Server data file on the container legs | STORE-65, -66, -67, -68 | The ENOSPC rig. Must be a **separate** volume from the runner workspace so filling it cannot wedge the job; unmount + delete in an `always()` step |
| A **memory-instrumented run** (`tracemalloc` + peak RSS via `psutil`, or a `resource`-limited subprocess) over a synthetic large-document backlog | STORE-69 | Only needs to be run against the pre-fix unbounded path once, to establish the degradation the bounded-batch row is measured against |
| A **local or UNC** backup destination (no cloud target — the `[backup]`/`[dr]` validators reject cloud URLs) **plus** a second box or volume | STORE-45, -48, -49 | Domain file server needed for the alternate-credential leg |
| A **domain-joined W2025 box** with NSSM, a dedicated service account (LocalSystem or gMSA) and a **separate** interactive admin account | STORE-48, -49, -51, -52 | The DPAPI boundary needs two distinct identities |
| A **Vault or OpenBao** server with Transit + KV v2 (`hvac`, `vault` extra) | STORE-59, -60 | ADR 0138 also names an unpublished throughput spike as a prerequisite |
| **DBA access** on the server-DB instances | manual reclamation, lock/space DMVs, `DBCC CHECKDB` | The delegated half of PHI.md §8 |
| **Load-harness capacity** to seed ~10⁵–10⁶ synthetic messages incl. base64 document bodies | STORE-18, -23, -24 | Sizing target is OQ-6 |

**Software prerequisites.** Python **3.14** with `[dev,sqlserver,postgres]` extras (**both** `asyncpg`
and `aioodbc` — a PG path fails at store-open without them). `QT_QPA_PLATFORM=offscreen` for any run
that touches the PySide6 harness tests.

**Synthetic data — hard rules.**

- Corpus generation: `python -m messagefoundry generate …` into the git-ignored corpus directory,
  driven in via `harness/config/load`. **All test traffic is synthetic and PHI-free.**
- Backlog ageing: back-date `received_at` at seed time (the purge keys on it) rather than waiting.
- Document bodies for the strip/attachment tests: generated base64 blobs of the target size
  (`mfb64:v1:` carriage / HL7 OBX-5 ED), never a real document.
- **`dryrun` and `generate` stdout can contain full message bodies** — never redirect them into a
  committed file, a ticket, or a CI log. Load and bench reports carry **metrics and metadata only**.
- Backup archives of a synthetic store still must not be uploaded as CI artifacts; delete the
  destination directory in an `always()` step.
- The checked-in pre-migration SQLite fixture (STORE-40) must be verified PHI-free and key-free
  before commit, and must be copied to `tmp_path` before opening — never mutated in place.

**Env vars used by the scenarios** (all real, `MEFOR_<SECTION>_<KEY>`, parsed by
`_env_overrides` at `settings.py:3777`): `MEFOR_RETENTION_MESSAGES_DAYS`,
`MEFOR_RETENTION_DEAD_LETTER_DAYS`, `MEFOR_RETENTION_PURGE_INTERVAL_SECONDS`,
`MEFOR_RETENTION_MAX_PASS_SECONDS`, `MEFOR_RETENTION_VACUUM_AT`,
`MEFOR_RETENTION_WAL_CHECKPOINT_SECONDS`, `MEFOR_RETENTION_MAX_DB_MB`,
`MEFOR_STORE_BACKEND` / `_SERVER` / `_PORT` / `_DATABASE` / `_USERNAME` / `_PASSWORD` /
`_ENCRYPT` / `_TRUST_SERVER_CERTIFICATE` / `_POOL_SIZE` / `_AAD_BIND`,
`MEFOR_STORE_ENCRYPTION_KEY`, `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`,
`MEFOR_BACKUP_DESTINATION`, `MEFOR_ALLOW_INSECURE_TLS`, `MEFOR_TEST_SQLSERVER`,
`MEFOR_TEST_POSTGRES`, `MEFOR_TEST_FORCE_AAD_BIND`.

### 2.8 Exit criteria

This area is signed off for release when **all** of the following hold. **Only T rows gate**: the
seven **C** rows (STORE-22, -23, -25, -28, -34, -36, -60) must have their measurement/decision
*recorded*, but a C row cannot fail and never blocks the release. The chapter has no **A** rows.

1. **All 9 owned P0 rows are green on the production backends.** STORE-01 through STORE-04, STORE-07
   through STORE-09, and STORE-13/-14 pass; the `sqlserver-store` (2022 **and** 2025) and
   `postgres-store` legs each report `tests/test_per_connection_retention.py` as **passed with 0
   skipped**. The two P0 *pointer* rows (STORE-44 → HA-02, STORE-46 → HA-48) gate in the HA chapter,
   not here.
2. **The mutation proofs landed.** The inverted-cutoff mutant (STORE-02) was demonstrated red on
   both server backends, and the `aad=None` mutant (S2 step 4) was demonstrated red on the forced-AAD
   sweep. Both are recorded in the PR description; neither is checked in.
3. **The forced-AAD sweep is scheduled and green.** A named workflow runs `pytest -q` with
   `MEFOR_TEST_FORCE_AAD_BIND=1` on ubuntu plus both server-DB legs, at the cadence agreed in OQ-4,
   with 0 failures, and its existence + cadence are documented in `docs/CI-QUALITY.md`.
4. **The PHI serve gate is closed.** A PHI+enforce instance whose Connections all set
   `messages_days=0` exits 2; the non-prod twin warns; the audited override is logged; and
   `messagefoundry check` fails the same config at commit time.
5. **Nothing purges unbounded.** `strip_embedded_documents` materializes a bounded batch on all three
   backends and the ADR 0137 deadline is honoured **inside** the strip phase; STORE-16 and STORE-17
   pass.
6. **A purge has been run under sustained load on every backend** (the run itself is PERF-29/-31,
   which STORE-18 points at) with zero acknowledged loss and ACK p99 within the agreed multiple of
   baseline (OQ-6); and the two STORE-owned observations made during that run pass — no
   `OBJECT`-granularity escalated lock on SQL Server's `messages` (STORE-19) and a bounded SQLite
   writer-lock hold (STORE-20). The report JSONs are archived.
7. **Retention and backup appear in an acceptance matrix.** `harness/acceptance/matrix.py` carries the
   four new per-DB rows and they map to real, passing suites; WIN2025-TEST-PLAN / -MATRIX /
   -ACCEPTANCE each carry a retention/backup section.
8. **Retention is observable.** `/metrics` exposes DB size, per-tier purged counters, a
   last-successful-pass timestamp and the `capped` flag; STORE-26 passes; the PHI/capacity-disclosure
   question (OQ-10) is answered.
9. **The config-only server-DB backup fallback is proven (STORE-45, owned here):** against a real PG
   / SQL Server store `snapshot_to` raises `DbaDelegatedError`, `BackupRunner` writes and
   restore-verifies a config-only `.mfbak`, and exactly one `dr_backup` audit row records
   `config_only`. Wiring the six gated DR/backup files into CI (HA-02) and the ADR 0102 live seed
   gate (HA-48) are preconditions supplied by the HA chapter, with 0 skipped.
10. **The silent no-op is no longer silent.** Setting `wal_checkpoint_seconds` / `vacuum_at` on a
    server DB produces a warning (or a refusal, per OQ-8); the runner's startup log no longer implies
    the phase is enabled; `docs/FEATURE-MAP.md` §5 carries the DBA-delegated caveat and is guarded by
    the consolidated MIG FEATURE-MAP drift-guard row (STORE-53 points at it).
11. **Doc-vs-code divergences are closed and guarded:** ADR 0027 and ADR 0042 in-file Status match the
    index (via SEC-01, which STORE-54 points at); ADR 0019's `aad_bind` default statement matches
    `settings.py`; ADR 0105 Phase 3b is no longer described as unbuilt in `docs/adr/README.md` or
    `FCP:STOREF-18`; ADR 0027 D3's per-connection-count promise is either implemented or amended.
    The store-side guards are pinned in `tests/test_phi_at_rest_inventory.py`.
12. **The legacy `outbox` table is dispositioned** — proven empty on a current SQL Server build with a
    source guard against writers, and either scheduled for removal or given a purge window (OQ-11).
13. **The attachment sweep race has a recorded disposition** — either a guard shipped (age/grace,
    in-flight marker, or leader gate) with STORE-35/-36 passing, or an explicit, written risk
    acceptance in ADR 0105 covering engine shards + streaming attachments on a server DB.
14. **A purge that dies mid-transaction is proven safe on all three backends** — STORE-63/-64: no
    half-purged row survives a kill at any injection point, the next pass purges exactly the
    remainder with no double-decref of a shared attachment, and no phase watermark (`_last_vacuum_day`
    included) advances past work that did not run.
15. **Disk-full fails closed and recovers** — STORE-65/-66/-67/-68: ENOSPC during a purge, during a
    WAL checkpoint / VACUUM, and during a `.mfbak` write each abort loudly with **no acknowledged
    message lost**, no corrupted store (`PRAGMA integrity_check` returns `ok`), and no truncated
    archive that restore-verifies; an operator-visible `storage_threshold` alert fires (its
    delivery/notification half is the ALERT chapter's); freeing space and re-running restores normal
    operation with no manual repair.
16. **The destructive-operator-error class is closed** — STORE-70/-71/-72/-73: restoring an older
    archive over a live store, an override naming a Connection that does not exist, `rotate-key`
    without the retired key present, and removing a Connection that still has queued rows each end in
    a **refusal** or an **audited, recoverable** outcome. No path in this class produces silent data
    loss. STORE-69 additionally proves the pre-fix unbounded strip path degrades, so STORE-16's
    bounded-batch pass cannot be vacuous.
17. **Every remaining open question in §2.9 has an owner decision recorded**, and any P2 row left
    unbuilt carries a tracked BACKLOG item — allocated via
    `pwsh -NoProfile -File scripts\coord\alloc.ps1`, never by grepping for the next free number.
18. **`ruff check` + `ruff format --check`, `mypy` (strict) and the full `pytest` suite pass** on the
    branch carrying this work, including the new modules.

### 2.9 Open questions

1. **Legal hold — in scope at all?** Is a per-message / per-patient retention exception in scope, or
   is per-connection `messages_days=0` the accepted answer? If in scope: must a hold survive a purge
   re-run, appear in the `retention_purge` audit detail, be settable from the web console, and who
   (which RBAC permission) may set and release it? *Blocks:* STORE-34, and whether a HIPAA /
   e-discovery hold can be honoured at all.
2. **Per-connection windows and the PHI serve gate.** Do we accept that
   `__main__.py:1968` ignores per-connection overrides, or should an inbound with `messages_days=0`
   on an enforcing PHI instance be a refuse-to-start **and** a `messagefoundry check` failure?
   *Blocks:* STORE-13, -14, -15 (the whole P0 fix).
3. **Server-DB CI runtime budget.** Approve adding `test_per_connection_retention.py`,
   `test_embedded_document_pruning.py` and the six DR/backup files to both server-DB legs, accepting
   the added nightly runtime — or is SQLite-only evidence acceptable for ADR 0027 AC-8 and ADR 0042
   AC-4? *Blocks:* STORE-01, -05 (the highest-value, lowest-cost rows in this chapter) and HA-02,
   which STORE-44 points at.
4. **Forced-AAD sweep cadence.** Nightly or weekly for the
   `MEFOR_TEST_FORCE_AAD_BIND=1` full-suite sweep, given the shipped at-rest format is otherwise
   essentially untested? *Blocks:* STORE-07, -08.
5. **Purge batch size / pass budget.** Should `purge_message_bodies` and
   `strip_embedded_documents` take a `LIMIT`/`TOP` and loop, or is a single unbounded transaction
   still correct for target store sizes? What is the sanctioned batch size? *Blocks:* STORE-16, -20,
   and the SQL Server lock-escalation remedy in STORE-19.
6. **Scale target and acceptable degradation.** What store size and message count should the
   purge-at-scale benchmark target (the ADR 0052 enterprise-scale figure? 45 M/day?), and what ACK p99
   degradation during a purge is acceptable? *Blocks:* STORE-23, -24 pass criteria, and PERF-29/-31
   (which STORE-18 points at).
7. **Purge attribution.** ADR 0027 D3 promises per-connection purged counts in the audit row; the
   code records only aggregates. Fix the code or amend the ADR? *Blocks:* STORE-25.
8. **Server-DB no-op knobs.** Should `[retention].wal_checkpoint_seconds` / `vacuum_at` be a **hard
   config error** on a server-DB backend, or only a startup warning? *Blocks:* STORE-29, -30.
9. **Startup attachment sweep.** Should it gain an age/grace guard, an in-flight marker, or be
   leader-gated, before engine sharding and streaming attachments are used together on a server DB?
   *Blocks:* STORE-36; determines whether STORE-35 is a bug report or a documented risk acceptance.
10. **Retention signals on `/metrics`.** Which belong there (DB size, purged counts per tier,
    last-pass timestamp, `capped`) versus staying audit-only — and does exposing per-connection purge
    counters create a PHI or capacity-disclosure concern on a scrapeable endpoint? *Blocks:* STORE-26.
11. **Legacy `outbox`.** Is the SQL Server `outbox` table definitively dead (safe to drop from
    `_SCHEMA` at `sqlserver.py:988`), or must it stay for read-compat? If it stays, does it need a
    purge window? *Blocks:* STORE-39 and a PHI.md §8 "tiers with no retention" row.
12. **Doc corrections.** Approve: flipping ADR 0027 and ADR 0042 in-file Status to Accepted (built)
    to match `docs/adr/README.md:57,72`; correcting ADR 0019:523's "off by default" `aad_bind`
    statement; retiring the ADR 0105 Phase 3b "not built" claims; and expanding `docs/FEATURE-MAP.md`
    §5 to name ADRs 0019/0027/0042/0049/0062/0064/0105/0137 with the DBA-delegated maintenance caveat.
    *Blocks:* STORE-12, -55, and the store-side inputs this chapter owes the consolidated MIG
    FEATURE-MAP drift-guard row (STORE-53) and SEC-01 (STORE-54).
13. **Rolling-upgrade posture.** Is a mixed-version fleet (two builds alternating opens against one
    unified store during a rolling upgrade of an HA pair or engine shards) a supported operation? If
    yes, the ADR 0064 convoy cost must be measured and bounded. *Blocks:* the pass criteria of
    MIG-09, which STORE-41 points at.
14. **Free-space signal.** Should the store gain a **free-space** threshold alongside `max_db_mb`
    (a `[retention].min_free_disk_mb`, or a percentage), given `disk_free_bytes` is `0` by
    construction on PG / SQL Server ([postgres.py:6592](../../../messagefoundry/store/postgres.py),
    [sqlserver.py:9205](../../../messagefoundry/store/sqlserver.py))? If it is SQLite-only, that asymmetry must
    be documented rather than silently shipped. *Blocks:* STORE-68, and the alert half of STORE-65.
15. **Destructive-operator posture.** For each case in STORE-70/-71/-72/-73 — older archive over a
    live store, an override naming an unknown Connection, `rotate-key` with no retired key,
    `connection remove` with queued rows — is the answer a **hard refusal** or a `--force`/override
    that writes an audit row? A refusal is safer; an override is operable during an incident. The
    owner must pick one **per case**; the tests assert whichever is chosen, and "silent success" is
    not an option in any of them. *Blocks:* STORE-70, -71, -72, -73.
