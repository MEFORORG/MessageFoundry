# ADR 0049 — Turnkey DR: scheduled config + SQLite-store backup with restore-verify (config-tier slice)

- **Status:** Accepted (2026-06-28 — ratified; open items resolved in 'Ratification decisions' below)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
  — **finalized 2026-06-28, EARS criteria added.** The owner DR posture is **locked into the body below
  as decided** (encrypted backup reusing the store DEK, local/UNC destination, daily + on-demand cadence,
  keep-N retention, lightweight restore-verify after each backup, cold seed for #61). This ADR stays
  `Proposed` only because the owner accepts at ratification; the remaining *To resolve* items are
  ratification-confirmations and format/contract locks, not open design forks.
- **Date:** 2026-06-28
- **ADR-index note:** the `0049` row is inserted in numeric order into [`docs/adr/README.md`](README.md)
  after the 0048 entry. `0049` is **not** the highest number on disk — [ADR 0050 — Single project-root
  config anchoring](0050-single-project-root-config-anchoring.md) was authored in parallel and already
  exists; the README table simply lists each in order. The number `0049` is the project owner's assignment
  for this work and must not be renumbered. (README row present-or-to-add; coordinator-owned on submission.)
- **Related:** ADR 0001 (staged pipeline — the WAL store this snapshots; the `reset_stale_inflight` +
  pure-stage-replay recovery a restore relies on) · ADR 0017 (consumer deployment model — config is an
  org-owned git repo, secrets per-instance; the engine wheel is a pinned re-installable dependency) ·
  ADR 0019 (the **KeyProvider / store-DEK seam** — the *key source* this backup reuses; `resolve_active_key` /
  `resolve_key_provider` / `active_key_id` fingerprint) · ADR 0027 / 0042 (per-connection retention/pruning —
  the `RetentionRunner` daily-clock scheduling + **leader-gated** singleton + one-audit-row-per-pass shape
  this mirrors) · ADR 0041 (load-path attestation — the **config fingerprint** carried in the manifest, and
  the **audit hash-chain** the archive snapshots; the chain-fork-across-DR consequence below) · ADR 0044
  (operator alert state — the `AlertSink` surface a backup failure must extend) · ADR 0048 (third-tier DR
  standby — **its COLD seed is this ADR's encrypted, restore-verified backup**; this ADR produces the
  artifact, ADR 0048 owns the *activation* that consumes it) · BACKLOG #60 (this), #61 (ADR 0048 consumes
  it), #52 (the **DB-tier backup / HA / restore = DBA-delegated** decline) · CLAUDE.md §2 (reliability +
  count-and-log invariants), §9 (PHI rules — on-prem / no-egress; never log a body)

---

## Context

MessageFoundry has a **two-pronged recovery story today** with a hole in the middle of it:

1. **Config DR is git-redeploy.** The `--config` dir (Routers/Handlers/`connections.toml`/`codesets/`/`environments/<env>.toml`)
   is an org-owned, separately-versioned repo (ADR 0017). Losing a box means re-cloning the pinned engine
   wheel and the config repo — already covered, no engine mechanic needed.
2. **DB-tier backup / HA / restore is DBA-delegated.** For the **server-DB** backends (PostgreSQL, SQL Server)
   the standing project decline (BACKLOG #52, CLUSTERING.md) is explicit: *DB-tier backup / HA / restore is
   the DBA's job* — `pg_dump` / PITR, SQL Server backups and Always On are owned by infra, not reimplemented
   in the engine.

The **gap** is the **default, single-box SQLite deployment** — the out-of-the-box posture for most adopters
(`[store].backend = "sqlite"`, the default; one `messagefoundry.db` + its `-wal`/`-shm` sidecars on local
disk). There is **no DBA** to delegate to and **no engine-managed backup**: if that disk or box is lost, the
message store — including received-but-not-yet-delivered staged-queue rows and the full audit hash-chain — is
gone. Corepoint ships turnkey scheduled/on-demand backups; MessageFoundry's competitive gap analysis
(BACKLOG #52) flags **"turnkey disaster recovery — engine-managed scheduled/on-demand backups"** as a
buyer-visible GAP. And ADR 0048's **cold DR seed** has nothing to consume: it is defined as *"seeded from
#60's scheduled config + store backup (restore-verified)"* — that backup must exist and be **decryptable at
the DR site** for the cold tier to work at all.

A naive answer — a cron `copy messagefoundry.db backup/` — is **wrong and unsafe**: (a) copying a SQLite file
out from under an open **WAL** connection captures a torn, mid-checkpoint state that may not even open;
(b) the raw DB carries **PHI bodies** (`messages.raw`, `summary`, `error`, `queue.last_error`,
`message_events.detail`) — which at rest must be protected — and the config bundle can carry secrets (a
`connections.toml` referencing an `env()` value, a `messagefoundry.toml` template); (c) a backup nobody has
ever opened is a backup that silently doesn't restore.

This decision is bounded by the standing invariants ([CLAUDE.md](../../CLAUDE.md) §2), quoted **verbatim**:

> **Reliability invariant (do not break):** the transactional **staged queue on SQLite (WAL)** gives
> at-least-once delivery, retries, replay, and dead-lettering *without* a separate broker. … Every subsequent
> stage **handoff** … is a **single committed transaction** … so a message is never lost or partially handed
> off. … At-least-once now relies on a re-run re-deriving identical output, so **routers and transforms must
> be pure** … outbound connections must still be **idempotent**.

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK** … so
> inbound counts still reflect the true received volume and nothing is accepted-and-dropped.

And by [CLAUDE.md](../../CLAUDE.md) §9 (PHI): *"Never log full message bodies at INFO or above … no PHI leaves
the local environment without explicit, reviewed configuration."* The backup mechanic must be **read-only
against the live store** (it must not claim, mutate, or perturb a staged-queue row), must **encrypt PHI at
rest**, must **never egress** (local/UNC only), and must **never log a body**.

The owner has **locked the DR posture** for this slice (2026-06-28); the decisions below are recorded as
**decided, not open**.

## Decision

**Add an engine-managed, scheduled (and on-demand) backup of the config bundle + the SQLite store, written as
a single AES-256-GCM-encrypted archive to an operator-configured local/UNC path, with a lightweight
restore-verify pass after every backup — reusing the ADR 0019 KeyProvider *key source* for encryption and the
`RetentionRunner` (leader-gated, daily-clock) scheduling shape. The server-DB store backup stays explicitly
DBA-delegated and is not reimplemented.**

In one line: a `BackupRunner` (sibling of `RetentionRunner`, **leader-gated** the same way) takes a
**consistent SQLite snapshot** (a *new* store seam, not a raw file copy), bundles it with a copy of the loaded
config dir, encrypts the whole archive with a *new* chunked-AEAD codec **keyed by the existing store DEK**,
writes it to a local/UNC destination under a keep-N retention, restore-verifies it, and records **one PHI-free
`dr_backup` audit row** per run.

This must **not** break:
- **the reliability invariant** — the snapshot **never claims, mutates, resets, completes, or dead-letters a
  staged-queue row**; it copies the queue/leader-lease/audit-chain *as they are*. At-least-once and the
  single-committed-handoff guarantee are untouched, and they extend *across a restore* via the existing
  startup `reset_stale_inflight` + pure-stage replay (proven by AC-11).
- **the count-and-log invariant** — backup is orthogonal to message disposition; it reads, it never
  accepts-or-drops. No message status changes because a backup ran.
- **the PHI rules** — the archive is **encrypted at rest** (whole-archive, because the config bundle can carry
  secrets), the destination is a **local/UNC path with no cloud target** (no new egress), and the audit row +
  logs carry **counts/sizes/paths/fingerprints only, never a message body**.
- **the no-grouping-unit / code-first identity** — this adds a background runner + a CLI + a `[backup]`
  settings section, **not** a "channel"/"route" element and **not** declarative routing.

### Boundary — SQLite-only; server-DB is DBA-delegated (BACKLOG #52)

The store-backup mechanic applies **only to `[store].backend = "sqlite"`** — the box that has no DBA. For
`backend in {postgres, sqlserver}` the engine **does not** run a store backup: it logs once at startup that
DB-tier backup is DBA-delegated (PITR / `pg_dump` / Always On) and **backs up the config bundle only** (still
useful, still encrypted), or skips entirely per `[backup].config_only_on_server_db` (default: config-only).
This is the same delegation line ADR 0048 draws for replication and CLUSTERING.md draws for DB-tier HA — the
engine owns the **single-box SQLite + config half**, infra owns the server-DB half. The CLI surfaces a clear
error if `backup` is invoked against a server-DB store without the config-only flag.

### New store surface — a consistent SQLite snapshot, never a raw file copy

> **This is net-new store code, not an exposed primitive.** A grep of `messagefoundry/store/` for
> `VACUUM INTO`, the SQLite Online Backup API, and `Connection.backup(` returns **zero** hits — neither
> mechanism exists today. The store currently exposes only `wal_checkpoint()`, `vacuum()` (a *plain* `VACUUM`,
> not `VACUUM INTO`), and `integrity_check()` (which today runs `PRAGMA quick_check`). The snapshot is a new
> `Store.snapshot_to(dest_path, *, method)` method on the **SQLite backend**; on the server-DB backends it
> raises the DBA-delegation path (AC-7) so the boundary is enforced in one place.

The store is open under **WAL** with concurrent readers/writers; a raw `cp` of `messagefoundry.db`
mid-checkpoint can capture a torn file. `snapshot_to` produces a consistent single-file copy one of two ways,
selected by `[backup].snapshot_method` (default `vacuum_into`). Both run **off the event loop** (a worker
thread, like the store's other long PRAGMA work) so they never block asyncio, and both first issue a
`PRAGMA wal_checkpoint(TRUNCATE)` (the store already exposes `wal_checkpoint()`) so the snapshot folds in the
latest committed WAL frames. The snapshot is a **point-in-time** copy: rows committed after it begins are
simply in the next backup (this sets the RPO — see *cadence*).

- **`vacuum_into` (default)** — `VACUUM INTO '<tmp>'` produces a **fresh, fully-checkpointed, defragmented**
  copy of the database in a single transactionally-consistent file with **no `-wal`/`-shm` sidecars** to
  reconcile — ideal for an encrypted archive and for ADR 0048's cold restore. **Concurrency caveat (corrected):**
  `VACUUM INTO` is a *write* statement; it **cannot** run on a pooled read connection (those are opened
  `PRAGMA query_only=ON` — *"a read conn never writes"*, `store.py` ~line 999). `snapshot_to(vacuum_into)`
  therefore runs on the **writer connection under the store lock** and, like the existing `vacuum()` (whose
  docstring states VACUUM *"holds a write lock on the whole DB for its duration and serialises on the store
  lock, so the RetentionRunner schedules it at a daily off-peak time"*), **contends the store write lock for
  its duration**. It is *not* "just another reader." This is acceptable **because it is scheduled off-peak**
  (the same reason `vacuum()` is) — that off-peak scheduling is **mandatory** for `vacuum_into`, not advisory.
- **`online_backup`** — the SQLite **Online Backup API** (`sqlite3` / `aiosqlite` `Connection.backup(dest)`),
  which copies pages incrementally, **automatically retries pages dirtied by a concurrent writer**, and yields
  between page batches — so it is the **low-contention** option that does *not* hold the write lock for the
  whole copy. Recommended for a large or busy store where a `VACUUM INTO` rewrite under the lock is too heavy.

In **both** methods the guarantee that matters for the reliability invariant is the same and is the one AC-2
asserts: the snapshot is a **point-in-time consistent copy that never claims/mutates/resets a staged-queue
row** (a row committed mid-snapshot appears wholly present or wholly absent; `integrity_check` is `ok`).

> **The snapshot is non-mutating end to end.** It never resets, claims, completes, or dead-letters a queue
> row. The staged queue, the leader lease, and the audit chain are copied **as they are**; on restore,
> `reset_stale_inflight` (which already runs on startup) recovers any rows that were in-flight at snapshot
> time, so a restored store re-runs the pure router/transform stages and re-derives identical output —
> **exactly the at-least-once contract, now spanning a restore** (AC-11 makes this a tested guarantee, not a
> prose claim).

### What's in the archive

A single file `mefor-backup-<instance>-<utc-timestamp>.mfbak` (a tar container behind the chunked-AEAD frame
below), containing:

1. **`store.db`** — the consistent SQLite snapshot (the whole message store: messages, the staged `queue`,
   `message_events`, the `audit_log` hash-chain, `state`, auth tables).
2. **`config/`** — a copy of the **loaded config dir** (`--config`): Routers/Handlers `*.py` (incl. `_*.py`),
   `connections.toml`, `codesets/`, `environments/<env>.toml`, fixtures. This makes the archive
   **self-sufficient for ADR 0048's cold seed** (store + the config that interprets it) without assuming the
   DR box can reach the org git repo at activation time.
3. **`manifest.json`** — PHI-free metadata: engine version, instance/env name, UTC timestamp,
   `snapshot_method`, the store **config fingerprint** (the ADR 0041 content hash of the loaded bundle, so a
   restore is provably tied to reviewed bytes), per-table row counts (for the restore-verify sanity check),
   the snapshot's SHA-256, the **DEK fingerprint / `key_id`** that the archive is encrypted under (the ADR 0019
   `active_key_id` — a one-way fingerprint, **never** key bytes), and the **`.mfbak` archive format version**.
   The manifest is **inside** the encrypted boundary; only enough to identify the archive lives in the
   filename.

### Encryption boundary — reuse the KEY SOURCE; the archive codec is net-new

**The whole archive is AES-256-GCM-encrypted at rest.** What is reused vs. net-new must be stated precisely
(an earlier draft over-claimed "zero new crypto surface" — corrected here):

- **Reused: the key source only.** The 32-byte store DEK is resolved through the **existing KeyProvider seam**
  — `resolve_active_key(settings.store)` / `resolve_key_provider` (ADR 0019) — exactly as `open_store` does,
  and the DEK's one-way **`active_key_id` fingerprint** (`cipher_info(...).active_key_id`) is written to the
  manifest. **No new key, no new key seam, no new rotation path** — the archive is sealed under the same key
  the store already uses (env / DPAPI / external HSM/KMS/Vault once one ships).
- **Net-new: a chunked-AEAD archive codec.** The existing store cipher (`store/crypto.py` `AesGcmCipher` /
  `make_cipher`) is a **per-value string cipher** — `encrypt(plaintext: str) -> str` over a single in-memory
  buffer behind the `mfenc:` marker. It **cannot** stream a multi-GB archive (it would base64-expand the whole
  file in RAM). So the archive uses a **new chunked AES-256-GCM streaming framing** — a `.mfbak` magic +
  version header, then fixed-size chunks each sealed with `cryptography`'s `AESGCM` under the resolved DEK with
  a per-chunk nonce + a monotonic frame counter (so chunk reordering/truncation fails the tag). This codec
  runs in the **worker thread over the archive stream**, never loading the whole store into one buffer and
  never on the event loop. It is **net-new code** (acknowledged in *Consequences*) and, because it imports
  `cryptography` / `AESGCM`, the new module **must be registered in
  `scripts/security/crypto_inventory_check.py` INVENTORY** (ASVS 11.1.3 crypto-inventory gate) or it reds the
  required leg + the inventory test.
- **Fail-closed.** If the store has **no key configured** (identity cipher) the backup of a PHI-carrying
  instance **refuses to write an unencrypted archive** — it errors loudly (the same posture as
  `[store].require_encryption`), unless the operator sets the explicit, audited `[backup].allow_unencrypted`
  escape (parallel to `[store].allow_unencrypted_phi`) for a synthetic/non-PHI box. A synthetic instance with
  no key may back up in the clear; a PHI instance may not, silently.

> **Key-availability consequence for #61's cold seed (addressed by design).** Because the archive is encrypted
> under the store DEK, **the DR site must have that DEK available to restore the cold seed.** ADR 0048's cold
> path **requires the same `KeyProvider` posture at the DR site** — env var / DPAPI key file / or reachability
> to the same HSM/KMS/Vault. A **DPAPI** key file is **machine-bound** and will **not** decrypt on the DR box,
> so a cold-seed deployment must use an **env-key or external-provider** posture (called out in the runbook).
> The manifest's DEK fingerprint lets the DR box (and the `restore-verify` tool) confirm it holds the matching
> key **before** attempting decryption — a clear key-availability error, **not** an opaque AEAD-tag failure
> (AC-5). The *activation* decision that consumes this guard is ADR 0048's (AC-9), not this ADR's.

### Leader-gated under active-passive HA (baked in, not an open question)

The `BackupRunner` is **leader-gated via the `ClusterCoordinator`** exactly like the `RetentionRunner` —
which is explicitly a *"leader-only WRITE singleton … must run on exactly one node"* (`pipeline/retention.py`),
defaulting to `NullCoordinator` (always-leader) on a single node so the common case is byte-identical. The
hazard is identical and real: a `BackupRunner` reads PHI, writes `audit_log` rows, **writes archives to a
shared local/UNC destination, and prunes keep-N** — if every HA node ran its own, they would race the same
destination directory and corrupt the keep-N prune. So under active-passive HA **only the leader backs up**.
(In practice an HA deployment is a server-DB cluster, where this slice is config-only anyway per the boundary
above; the gate is nonetheless mandatory and tested — AC-12 — so it is correct independent of backend.)

### `[backup]` settings (a new `BackupSettings` section)

A new `BackupSettings` (`config/settings.py`, a `_Section` alongside `RetentionSettings`/`ClusterSettings`,
added to `ServiceSettings`). It lives in **engine service settings** (`messagefoundry.toml`), **not**
`connections.toml` — backup cadence/destination is a property of the *deployment*, not of any endpoint.
**Mechanical (do not skip):** `"backup"` must be added to the `_SECTIONS` tuple in `config/settings.py`
(today 17 entries, no `backup`) or `MEFOR_BACKUP_*` env overrides and section parsing won't resolve.

```toml
[backup]
enabled = false                  # opt-in; a deployment with no [backup] is unaffected (no-op default)
destination = ""                 # operator-set LOCAL or UNC path, e.g. "D:/mefor-backups" or "\\nas\mefor\backups". REQUIRED when enabled. No cloud target.
schedule_at = "02:00"            # daily local "HH:MM" (reusing RetentionSettings' clock parser); "" = on-demand only
retention_keep = 7               # keep-N: prune the oldest archives beyond N after a successful new one. 0 = keep all.
snapshot_method = "vacuum_into"  # "vacuum_into" (default, writer-lock under off-peak schedule) | "online_backup" (low-contention)
include_config = true            # bundle the loaded --config dir into the archive
verify_after_backup = true       # run the lightweight restore-verify after each backup (default ON)
full_restore_verify = false      # the heavier restore-to-temp through open_store; on-demand / opt-in extra
config_only_on_server_db = true  # on postgres/sqlserver, back up config only; the DB is DBA-delegated (#52)
allow_unencrypted = false        # audited escape: permit a clear archive ONLY for a no-key synthetic instance
```

Validation (fail config load on a bad value, never a silent default): `destination` **required** and
non-empty when `enabled` **and not a cloud URL** (`s3://`/`gs://`/`http(s)://…` rejected — no cloud target);
`schedule_at` empty-or-`HH:MM`; `retention_keep >= 0`; `snapshot_method` in the enum; and **`enabled` with no
resolvable store key and `allow_unencrypted = false` on a PHI instance is rejected** (the §"fail-closed"
posture). The destination path's **writability + free space** are checked at startup (advisory warning + a
`storage_threshold`-style alert if low), not silently discovered at 02:00.

The **cadence is daily + on-demand** (owner-locked); **retention is keep-N** (owner-set, default 7). The
destination is an **operator-configurable LOCAL/UNC path; NO cloud target** (owner-locked — no new egress
surface; consistent with the on-prem/no-egress default and ADR 0026's posture).

### CLI

Two subcommands on the existing `messagefoundry` argparse surface (sibling of `serve`/`rotate-key`/`protect-key`):

- **`messagefoundry backup`** — take an **on-demand** backup now: resolve settings + the store key, snapshot,
  bundle, encrypt, write to `--destination` (or `[backup].destination`), restore-verify, prune to keep-N,
  print the archive path + manifest summary (counts/sizes/fingerprint — **no body**), record the audit row.
  Flags: `--config`, `--db`, `--destination`, `--no-verify`, `--full-verify`, `--config-only`.
- **`messagefoundry restore-verify <archive>`** — verify an existing archive **without** activating it. This
  is **0049's owned primitive** (ADR 0048's cold-seed activation *calls* it; it does not re-implement it):
  resolve the key, **check the manifest DEK fingerprint against the resolved key first** (return a clear
  `KEY_MISMATCH` result *before* decryption — not an opaque AEAD error), then decrypt, open the embedded
  `store.db` read-only, run `PRAGMA integrity_check`, compare per-table row counts against the manifest, and
  report a structured `PASS` / `FAIL` / `KEY_MISMATCH` result + the manifest. The same verification the runner
  runs after each backup.

The CLI must **never** print a message body and runs the heavy PRAGMA/decrypt work synchronously in the
command (it is not in the serving hot path).

### Audit row (PHI-free) — off-box tee covered, not deferred

Each backup run (scheduled or on-demand) that does real work writes **one** `audit_log` row via the store's
existing `record_audit(...)` seam — `action = "dr_backup"`, `detail` = a JSON object of **metadata only**:
UTC timestamp, archive filename (path, not contents), `snapshot_method`, per-table row counts, archive bytes,
snapshot SHA-256, the config fingerprint, the DEK `key_id` fingerprint, the restore-verify result
(`integrity_check` ok + row-count match), and the keep-N prune count. **No message content, ever** (mirrors
the `retention_purge` one-row-per-pass shape, ADR 0027).

The off-box tee is **already covered, not an open question**: `emit_audit_tee` redacts the `detail` field
generically through `redaction.safe_text` (HL7-shaped spans scrubbed + length-bounded) with **no per-action
allow-list** (`store/audit_tee.py`), so a new `action = "dr_backup"` row is teed PHI-safe **for free** — and
this slice's `detail` is metadata-only by construction anyway. AC-1 asserts the row carries
counts/sizes/paths/fingerprints only. Because `record_audit` tees that PHI-safe copy off-box (sec-offbox-log),
the backup event survives a host/DB compromise.

A **failed** backup records a `dr_backup` ERROR row (error **class** only, never a body) **and** raises a
**new** `AlertSink.backup_failed(...)` alert (see below), so an operator learns of a silent backup failure
from the disposition + alert, not from a missing archive discovered during a disaster.

### New AlertSink method (net-new surface, not a reuse)

There is **no generic `alert()`** on `AlertSink` and no backup-failure method today — the Protocol is a fixed
enum of typed methods (`connection_stopped`, `queue_buildup`, `message_stall`, `connection_error`,
`storage_threshold`, `cert_expiry`, `integrity_drift`, `update_available`, `connection_restored`). Emitting a
backup-failure alert therefore **adds a new typed method** `backup_failed(name, *, kind, detail)` across the
full touch list: the `AlertSink` Protocol and `LoggingAlertSink` (`pipeline/alerts.py`), the
`NotifierAlertSink` (`pipeline/alert_sinks.py`), and the `AlertRule.event_type` enum in `config/settings.py`
(so an operator can route/throttle it like any other event, ADR 0014/0044). The startup destination preflight
**reuses** the existing `storage_threshold` method for a low-free-space warning (that method exists); the
UNC-writability + free-space probe itself (via `shutil.disk_usage`) is **net-new** code.

### Restore-verify steps (lightweight, after every backup)

The owner-locked posture is **lightweight verification after each backup**, with a full restore-to-temp as an
**on-demand extra**. After writing the archive, the runner (or the `restore-verify` CLI):

1. **Key-fingerprint precheck.** Compare the manifest's DEK `key_id` against the resolved key's `active_key_id`
   (incl. retired keys). A mismatch is a clean `KEY_MISMATCH` result **before** any decrypt attempt — never an
   opaque AEAD-tag failure (AC-5).
2. **Decrypt** the archive (chunked-AEAD codec) with the resolved store key. A decrypt/auth-tag failure here is
   a hard `FAIL` — the archive is unusable: alert + `dr_backup` ERROR row.
3. **Open the embedded `store.db` read-only** and run **`PRAGMA integrity_check`** (the fuller check — the
   store's existing `integrity_check()` runs `quick_check` on a `query_only` pooled connection; the verify runs
   on its own connection off the hot path, so it can afford the fuller PRAGMA). Non-`ok` → `FAIL`.
4. **Row-count sanity check** — re-count the key tables in the snapshot and compare to the manifest's recorded
   counts (catches a truncated/torn snapshot the integrity check might miss at the logical level).
5. **Record the verify result** in the `dr_backup` audit row; on `FAIL`, **the archive is marked failed and
   the keep-N prune does not count it as the latest good backup** (so a failing backup never silently evicts
   the last *good* one).

`full_restore_verify` (opt-in / on-demand) additionally restores the snapshot to a throwaway temp DB and opens
it through the real `open_store` path (cipher + migrations) to prove an end-to-end restore — heavier, so not
the per-backup default.

## Acceptance Criteria

> EARS — testable, each linked to a test/fixture. (Paths below are the intended homes; created with the build.
> `messagefoundry adr-analyze` checks each `→` link resolves once the build lands.)

- **AC-1** — WHEN a scheduled backup completes, THE SYSTEM SHALL run `PRAGMA integrity_check` + a per-table
  row-count verify against the manifest AND record a `dr_backup` audit row whose `detail` carries
  counts/sizes/paths/fingerprints **only** (no message body) AND which is teed off-box PHI-safe via
  `emit_audit_tee`.
  → `tests/test_backup_runner.py::test_scheduled_backup_verifies_and_audits`
- **AC-2** — WHEN a backup is taken against a live, concurrently-written SQLite store, THE SYSTEM SHALL produce
  a point-in-time **consistent** single-file snapshot (a row committed mid-snapshot is wholly present or wholly
  absent; `integrity_check` ok) **without** claiming, mutating, resetting, completing, or dead-lettering any
  staged-queue row (reliability + count-and-log invariants hold).
  → `tests/test_backup_runner.py::test_snapshot_is_consistent_and_nonmutating`
- **AC-3** — WHILE a store key is configured, THE SYSTEM SHALL write the `.mfbak` archive with the chunked
  AES-256-GCM codec keyed by the resolved store DEK AND record that key's fingerprint (`active_key_id`) in the
  manifest — never any key bytes.
  → `tests/test_backup_crypto.py::test_archive_encrypted_under_store_dek`
- **AC-4** — IF `[backup].enabled` AND the store has no resolvable key on a PHI instance AND
  `allow_unencrypted = false`, THEN THE SYSTEM SHALL refuse to write a cleartext archive and fail with a clear
  error (never silently back up PHI in the clear).
  → `tests/test_backup_crypto.py::test_refuses_unencrypted_phi_backup`
- **AC-5** — WHEN `restore-verify <archive>` runs, THE SYSTEM SHALL first compare the manifest DEK fingerprint
  to the resolved key and, IF they differ, return a clear `KEY_MISMATCH` result **before** attempting
  decryption (not an opaque AEAD-tag error); WHEN they match, THE SYSTEM SHALL decrypt, open `store.db`
  read-only, run `integrity_check` + the row-count check, and report `PASS`/`FAIL`.
  → `tests/test_restore_verify.py::test_verify_pass_failclosed_and_key_mismatch`
- **AC-6** — WHEN a new backup succeeds with `retention_keep = N`, THE SYSTEM SHALL prune archives older than
  the newest N at the destination, AND SHALL NOT count a verify-FAILED archive as the latest good backup when
  pruning.
  → `tests/test_backup_runner.py::test_keep_n_prune_excludes_failed`
- **AC-7** — WHERE `[store].backend in {postgres, sqlserver}`, THE SYSTEM SHALL NOT take a DB store snapshot
  (`snapshot_to` raises the DBA-delegation path, #52) AND SHALL back up the config bundle only (or skip per
  `config_only_on_server_db`), logging the delegation once.
  → `tests/test_backup_runner.py::test_server_db_is_config_only`
- **AC-8** — WHEN a settings file sets `[backup].enabled = true` with an empty `destination`, an unknown
  `snapshot_method`, a non-`HH:MM` `schedule_at`, a negative `retention_keep`, or a cloud-URL `destination`,
  THE SYSTEM SHALL fail config load with a clear error (never a silent default).
  → `tests/test_settings.py::test_invalid_backup_settings_rejected`
- **AC-9** — IF a backup fails (snapshot, encrypt, write, or verify), THEN THE SYSTEM SHALL record a
  `dr_backup` ERROR audit row (error class, no body) AND raise an `AlertSink.backup_failed(...)` alert, leaving
  any prior good archive intact.
  → `tests/test_backup_runner.py::test_failed_backup_alerts_and_preserves_prior`
- **AC-10** — WHEN a destination is unreachable at backup time (a `[backup].destination` UNC path that cannot
  be written), THE SYSTEM SHALL record a `dr_backup` ERROR row + raise `backup_failed`, retain the prior good
  archive, AND SHALL surface the unreachability at the startup preflight (writability + free-space) when
  detectable then.
  → `tests/test_backup_runner.py::test_unreachable_destination_alerts_and_preflight`
- **AC-11** — WHEN a store restored from a backup archive starts, THE SYSTEM SHALL recover in-flight rows via
  `reset_stale_inflight` and re-run the pure router/transform stages, preserving at-least-once across the
  restore — no staged-queue row lost, re-derived output identical (a tolerated duplicate to an idempotent
  outbound, never a drop) — even for a snapshot taken mid-handoff.
  → `tests/test_backup_restore_atleastonce.py::test_restore_resumes_without_loss_or_double_drop`
- **AC-12** — WHILE clustered (active-passive HA) AND not the leader, THE SYSTEM SHALL NOT take a backup or
  prune the shared destination; WHILE single-node (`NullCoordinator`), THE SYSTEM SHALL always run.
  → `tests/test_backup_runner.py::test_backup_is_leader_gated`

## Options considered

1. **Engine-managed consistent SQLite snapshot + config bundle, encrypted with a chunked-AEAD codec keyed by
   the existing store DEK, local/UNC destination, restore-verified, leader-gated, server-DB DBA-delegated** —
   reuses the `RetentionRunner` leader-gated scheduling shape, the ADR 0019 KeyProvider *key source* +
   `active_key_id` fingerprint, the `record_audit` PHI-safe off-box tee, and the store's `wal_checkpoint()` /
   `integrity_check()` primitives; adds a new `Store.snapshot_to` seam, a new chunked-AEAD archive codec, and a
   new `AlertSink.backup_failed`. Smallest correct turnkey DR for the no-DBA SQLite box; produces exactly the
   artifact ADR 0048's cold seed needs. **CHOSEN.**
2. **Raw file copy of `messagefoundry.db` (+ sidecars) on a timer** — trivial, but captures a **torn WAL state**
   that may not open, and either copies **PHI in the clear** or bolts on a second encryption path. Rejected:
   inconsistent + unsafe; violates the PHI-at-rest rule and the snapshot-consistency need.
3. **Delegate *everything* to the OS / an external backup product (VSS, Veeam, robocopy)** — zero engine code,
   but no SQLite-consistency guarantee (same torn-WAL risk on a live file), no PHI-encryption guarantee under
   the engine's own key, and **nothing turnkey for the default adopter** — exactly the buyer-visible GAP (#52).
   Rejected as the *whole* answer; an operator may still layer an OS backup over the encrypted archives.
4. **Reimplement DB-tier backup for Postgres/SQL Server too** — Rejected: directly contradicts the standing
   **#52 DBA-delegation** decline (PITR/`pg_dump`/Always On are infra-owned); the engine would duplicate
   mature, infra-governed tooling worse.
5. **New, separate backup encryption key** — Rejected: a second key seam to provision, rotate, and lose; the
   store DEK + `KeyProvider` already exists, already rotates, and already has the HSM/KMS path. (We do add a
   new *codec*, but it is keyed by the **same** DEK — no new key.)
6. **Do nothing (git-redeploy config + "the DBA has it")** — Rejected: leaves the **default single-box SQLite
   store with no DR at all** and gives ADR 0048's cold tier nothing to seed from.

## Consequences

**Positive**
- Turnkey, opt-in DR for the **default single-box SQLite adopter** with no DBA — closes the buyer-visible #52
  GAP.
- **Consistent, PHI-encrypted, self-sufficient** archives (store + config) that **ADR 0048's cold seed
  consumes directly** — the `.mfbak` format is designed for #61, and the manifest DEK fingerprint gives the DR
  site a clear pre-decryption key check.
- **Reuses the key/KeyProvider seam** (env/DPAPI/HSM/KMS/Vault) + `active_key_id` fingerprint, the
  `record_audit` PHI-safe off-box tee (no per-action allow-list needed), and the `RetentionRunner` leader-gated
  daily-clock + one-audit-row-per-pass shape — **no new key, no new rotation path**.
- **No new egress** (local/UNC only) and **never mutates the live store** — invariants intact, no broker, no
  hot-path cost; at-least-once now provably spans a restore (AC-11).
- Restore-verify-after-every-backup means a backup is **proven openable** before a disaster, not discovered
  broken during one.

**Negative / risks**
- **Net-new code, not "zero new surface" (corrected).** Three new pieces ship: a `Store.snapshot_to`
  (`VACUUM INTO` / Online-Backup) seam, a **chunked-AEAD `.mfbak` codec** (which must be registered in the
  crypto-inventory gate), and a new `AlertSink.backup_failed` method (Protocol + Logging + Notifier +
  `AlertRule.event_type`). Only the *key source* is reused, not the cipher mechanism or the snapshot
  primitive.
- **`vacuum_into` contends the store write lock for its duration** (it runs on the writer connection, like
  `vacuum()`); off-peak scheduling is **mandatory** for it. `online_backup` (page-batched, yielding) is the
  low-contention alternative for a large/busy store.
- **RPO = backup cadence.** A daily backup means up to ~24h of message loss on a total box loss; an operator
  who needs tighter RPO must shorten the schedule (more I/O) or move to a server-DB backend with DBA PITR. This
  is the inherent cold-DR trade (ADR 0048 says the same).
- **Key-availability burden at the DR site (the #61 consequence).** The encrypted archive is only restorable
  where the DEK is available. A **DPAPI**-protected key file is machine-bound and will **not** decrypt on the
  DR box — a cold-seed deployment must use an **env-key or external-provider** posture, or pre-stage the key.
  The manifest fingerprint turns a silent failure into a clear, early error, but the operator still owns
  getting the key to the DR site.
- **Audit hash-chain fork across the DR handoff (new, ADR 0041).** The archive snapshots the `audit_log`
  hash-chain inside the encrypted boundary. A cold-restored DR store's chain **ends at the backup point**; once
  the DR box runs, it **extends that same chain** with its own rows (`dr_backup`, PHI accesses). On cold
  fail-back the recovered primary and the DR store have **forked the tamper-evident chain from a common
  ancestor** — two divergent chains that ADR 0048's fail-back runbook (which today reconciles message/queue
  rows) does not address for the *audit* chain. **Chosen handling:** on cold seed the DR box **starts a new
  audit-chain segment** — recording a seed marker (the source backup's snapshot SHA-256 + config + DEK
  fingerprints + the restored chain's tip hash) as the new segment's genesis, rather than blindly extending the
  restored chain — so each side stays independently verifiable and the fork is explicit, attributable, and
  reconcilable by node/instance. The exact segment-marker shape is a *To resolve* item with ADR 0041/0048.
- **`VACUUM INTO` cost on a large store** — rewrites the whole DB each run under the lock; `online_backup`
  mitigates, and the schedule must target an off-peak window (as `vacuum()` does today).
- **Destination is operator-trusted** — a UNC share's own access controls are infra's responsibility; the
  engine encrypts the archive but does not manage the share's ACLs.
- **A backup is a second copy of PHI at rest** — encrypted, but it widens the at-rest PHI footprint to the
  destination path; keep-N retention + the encryption boundary bound it, and PHI.md's data-at-rest inventory
  must list the backup destination.

**Out of scope**
- **Server-DB (Postgres/SQL Server) store backup/restore/PITR** — DBA-delegated (#52); the engine never
  reimplements it.
- **Cloud backup targets / off-box egress** — owner-locked out (no cloud target, no new egress).
- **The DR *standby* / failover / failback machinery and the *activation* decision** — that is **ADR 0048
  (#61)**: VIP acquire-or-abort fencing, the tier-2-lease quorum check, the manual activation runbook, and the
  cold fail-back **store-reconciliation runbook** all live there. This ADR produces the **cold seed** and the
  reusable `restore-verify` primitive ADR 0048's activation *calls* (0049 AC-5 ↔ 0048 AC-9), and stops there —
  it does **not** own the activation refusal.
- **Continuous/warm DB replication** — ADR 0048's warm path, DBA-owned.
- **Backup of the engine wheel itself** — the engine is a pinned, re-installable dependency (ADR 0017), not
  application state.

## To resolve on acceptance

> The owner DR posture is **locked into the body above**. The items below are **ratification confirmations**
> and the format/contract locks to settle before this flips to `Accepted` — tracked so `adr-analyze` surfaces
> anything still open.

- [ ] Confirm the **default `snapshot_method`** (`vacuum_into`, writer-lock under a mandatory off-peak
      schedule) vs. defaulting a very-large-store deployment to `online_backup` (low-contention).
- [ ] **Lock the `.mfbak` archive format** (the net-new crypto deliverable): tar container + the chunked
      AES-256-GCM frame (magic + version header, fixed chunk size, per-chunk nonce + monotonic frame counter so
      reorder/truncation fails the tag); confirm the new codec module is registered in
      `scripts/security/crypto_inventory_check.py` INVENTORY (ASVS 11.1.3). The format version must let a future
      bump and ADR 0048's reader agree.
- [ ] Settle the **DR-site key-availability contract** with ADR 0048/#61: env-key/external-provider **required**
      for cold seed; **DPAPI explicitly unsupported across machines**; whether the manifest carries a
      wrapped-DEK *hint* for an HSM/KMS posture (it must **never** carry key bytes). 0049 owns the
      `restore-verify` `KEY_MISMATCH` primitive (AC-5); 0048 owns the activation refusal that calls it (its
      AC-9).
- [ ] Confirm the **audit hash-chain fork handling** with ADR 0041/0048: that the cold-seeded DR box **starts a
      new chain segment** (seed-marker genesis = source snapshot SHA-256 + config/DEK fingerprints + restored
      tip hash) rather than extending the restored chain, and pin where the fail-back runbook reconciles the two
      segments by node/instance.
- [ ] Confirm `record_audit`'s `action = "dr_backup"` name and the exact PHI-free `detail` schema
      (counts/sizes/paths/fingerprints). (The off-box-tee redaction is **already confirmed**: `emit_audit_tee`
      redacts `detail` generically via `safe_text` with no per-action allow-list — no further work needed.)
- [ ] Confirm the **owner-set defaults**: `retention_keep = 7`, daily `schedule_at = "02:00"`,
      `verify_after_backup = true`, `full_restore_verify = false`, `config_only_on_server_db = true`.
- [ ] Confirm the **startup destination preflight** (writability + free-space, `shutil.disk_usage`, firing the
      existing `storage_threshold`) and the unreachable-at-backup behavior (AC-10: `backup_failed` + ERROR row,
      prior archive retained).
- [ ] Confirm the new **`AlertSink.backup_failed`** method shape and its `AlertRule.event_type` routing/throttle
      key across `pipeline/alerts.py`, `pipeline/alert_sinks.py`, and `config/settings.py`.
- [ ] Confirm the `"backup"` entry is added to `config/settings.py` `_SECTIONS` (so `MEFOR_BACKUP_*` overrides
      resolve), and insert the `0049` row into [`docs/adr/README.md`](README.md) in order after 0048
      (0050 already exists on disk); coordinator-owned on submission.


---

## Ratification decisions (2026-06-28)

- **`.mfbak` format locked:** a tar container + **chunked AES-256-GCM** frame (magic + version header, fixed chunk size, per-chunk nonce + monotonic frame counter). The new codec module **must register in `scripts/security/crypto_inventory_check.py` INVENTORY** (ASVS 11.1.3) or it reds the required leg + the inventory test — a build-lane gate.
- **`snapshot_method` default `vacuum_into`** (writer-lock, off-peak); `online_backup` for very-large / low-contention stores.
- **Owner-set defaults accepted:** `retention_keep=7`, `schedule_at='02:00'`, `verify_after_backup=true`, `full_restore_verify=false` (on-demand only), `config_only_on_server_db=true`.
- **Cold-seed key contract:** an **env-key / external KeyProvider is required** at the DR site (DPAPI is machine-scoped → unusable cross-box). The manifest may carry a **wrapped-DEK hint** for HSM/KMS, **never** key bytes. 0049 owns restore-verify `KEY_MISMATCH` (AC-5); ADR 0048 owns the activation refusal.
- **Audit-chain fork:** a cold-seeded DR box starts a **new chain segment** (seed-marker genesis = source-snapshot SHA-256 + config/DEK fingerprints + restored tip hash); the fail-back runbook reconciles the two segments by node/instance.
- New `AlertSink.backup_failed` + a PHI-free `dr_backup` audit action; **add `backup` to `config/settings.py` `_SECTIONS`** (else `MEFOR_BACKUP_*` won't resolve).
