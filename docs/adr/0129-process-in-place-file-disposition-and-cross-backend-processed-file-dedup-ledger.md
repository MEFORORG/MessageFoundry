# ADR 0129 — Process-in-place file disposition (`after_read='leave'`) + cross-backend processed-file dedup ledger

- **Status:** **Accepted (2026-07-17, owner go).** DEMAND-GATE-BACKLOG Wave 3 / S3a. Built in the same
  change. `0129` was allocated atomically (`scripts/coord/alloc.ps1`); its index row is added to
  [README.md](README.md) in the same commit.
- **Decision in one line:** the File / SFTP / FTP(S) **inbound** sources gain a third `after_read`
  disposition — **`leave`** (process **in place**, never move or delete the source file) — for a
  **read-only share** or a directory another system owns; a left file is de-duplicated against a new
  **cross-backend `processed_files` store table** that records a **HASHED per-file key** (never a
  cleartext filename), **after** the file's messages emit successfully, with the **file** (not each
  split message) as the dedup unit, bounded by an age+count prune.
- **Backlog:** [BACKLOG #142](../archive/backlog/BACKLOG-CLOSED.md#142-leave-source-file---process-in-place-fileftp-source-disposition). Sibling of [BACKLOG #114](../BACKLOG.md) / the
  [ADR 0031](0031-startup-connection-fault-isolation.md) amendment (opt-in startup directory
  validation), built in the same lane (S3a) and composing with it (a `leave` source validates a
  read-only share read-only).
- **Related:**
  - [ADR 0001](0001-staged-pipeline-architecture.md) — the reliability + **count-and-log** invariants
    (every received file logged with its disposition; at-least-once). `leave` preserves both: the
    ledger is written **after** a successful emit, so a crash between emit and record re-emits the file
    (at-least-once duplicate, acceptable — handlers are idempotent), never an accept-and-drop.
  - the H2 outbound idempotency ledger `delivered_keys` and the ADR 0090 resend ledger `resend_log`
    (both `store.py` / `sqlserver.py` / `postgres.py`) — the **IDS/HASHES-ONLY, stored-in-the-clear,
    not-part-of-the-cipher-seam** precedent this table follows (a filename can embed PHI, so the key is
    a **derived id** — a hash — never a cleartext-filename column).
  - [ADR 0064](0064-schema-init-fastpath.md) — the server-backend schema content hash: adding the
    `processed_files` DDL to `sqlserver._SCHEMA` / `postgres._SCHEMA` changes `_schema_hash()`
    automatically, forcing one guarded re-apply on the next open. SQLite applies it via
    `CREATE TABLE IF NOT EXISTS` in `_SCHEMA` (idempotent, no marker).
  - [ADR 0105](0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)
    — the 3-backend parity discipline this store change follows (SQLite exercised locally; SQL Server /
    Postgres parity validated on the Windows/Linux CI legs).

## Context

Both file sources always **consume** a read file via `after_read`: `move` (→ `.processed`) or `delete`
(`transports/file.py`, `transports/remotefile.py`). Neither offers a **leave-in-place** option, so a
feed that lands on a **read-only share**, or on a directory whose files **another system owns**, cannot
be polled without moving or deleting files the engine may not be permitted (or want) to touch. The only
workaround is an awkward external copy-job that stages files into a directory the engine *can* consume —
extra moving parts, extra latency, another failure point.

The reason `leave` isn't trivial: once we stop moving/deleting the file, **the next poll re-reads it**.
A leave-in-place disposition therefore **requires a durable dedup ledger** — "which files have I already
ingested?" — that survives a restart and is shared across the store's three backends. And filenames can
carry PHI (an MRN in the name), so the ledger must not store a cleartext filename.

## Decision

### §1 `after_read='leave'` — process in place

`after_read` accepts a third value, **`leave`**, on the File and RemoteFile **inbound** sources
(validated at construction: `move` | `delete` | `leave`, so a typo fails fast). In `leave` mode
`_after_processing` neither moves nor deletes the file — it stays exactly where it landed. Everything
else (the oversize/content-type/scan quarantine gates, the batch split, the at-least-once handoff) is
unchanged.

Because a read-only share can't host the `.processed`/`.error` subdirs, `start()` creates them
**best-effort** in `leave` mode (a failure is suppressed — the dir isn't needed) rather than failing to
start. The quarantine paths still *attempt* a best-effort move to `.error`; where the share is read-only
that move fails and the file is left in place and logged (the existing FILE-4/FILE-5 behavior), so a
malformed file on a read-only share re-logs each poll until the source owner fixes it — an accepted,
documented edge (the ledger only records **successfully-emitted** files).

### §2 The `processed_files` dedup ledger — a HASHED key, IDS-ONLY

A new store table, on **all three backends**, records each file this connection has ingested:

```
processed_files(
    channel_id   TEXT,   -- inbound connection name (config metadata, non-PHI) — scoped prune
    file_key     TEXT,   -- sha256(rel-path || mtime || size) — a HASHED derived id; NEVER a cleartext filename
    processed_at REAL,   -- epoch ts recorded AFTER emit success; drives the age/count prune
    PRIMARY KEY (channel_id, file_key)
)
```

- **Hashed key, not a cleartext-filename column.** A filename can embed an MRN. Following the
  `delivered_keys` / `resend_log` precedent (which store hashes + ids only), `file_key` is a **SHA-256
  digest** of the file's identity — the file's **path relative to the watch root** + mtime + size for
  the local source; the **full remote path** + size for the remote source (whose listing carries no
  mtime). It is a **derived id**, stored in the clear (nothing to decrypt — the table is **not** part of
  the cipher seam), and **never logged at INFO+** (the relative / remote path may itself embed PHI).
  Folding **the path** in — not just the basename — is load-bearing under `recursive=True`: two DISTINCT
  files sharing a basename in different subdirectories that (on a timestamp-preserving copy over a
  coarse-mtime SMB/CIFS/NFS share) also share mtime+size would otherwise hash to the SAME key, and the
  second would be silently deduped away — an accept-and-drop of a received file (count-and-log
  violation). Folding mtime/size in means an **updated** file (new mtime/size → new key) is re-ingested,
  while an unchanged file is skipped.
- **File-level dedup unit.** A batch file splits into N pipeline hand-offs; the ledger records **one**
  row for the **file** after **all** N emit, so a partial-emit crash re-reads and re-emits the whole
  file (at-least-once) and the file is recorded only once every message is durably in the pipeline.
- **Bounded growth.** `prune_processed_files(channel_id, older_than, keep_last)` deletes rows older than
  an age (default 30 days) and, beyond a count cap (default 100k), the oldest surplus — called
  opportunistically at the end of a poll tick only when ≥1 new file was recorded, so a stable
  read-only share (nothing new) never churns the DB.

### §3 Store-agnostic transport — a runner-injected ledger seam

`transports/` must never import `store/`. The source therefore reaches the ledger through an injected
seam (`SourceConnector.processed_ledger`, same runtime-injection shape as `on_connection_event` /
`content_type`): the runner builds a small **`ProcessedFileLedger`** adapter closing over `self.store` +
the inbound's channel id and injects it at `_start_inbound_unsafe`. The source passes only the **hashed
`file_key`** across the seam — the cleartext filename never leaves the connector, and the store never
learns the connector's file layout. When no ledger is injected (a direct caller / a unit test), the
source falls back to an in-process cache (dedup for the process lifetime only), so it is testable without
a store; production always gets the durable table.

The in-process cache is a **bounded LRU** (`OrderedDict`, cap = the ledger's count-cap
`LEAVE_SEEN_CACHE_MAX`), not an unbounded set: on a long-lived poller over a churning directory it can
never outgrow the durable ledger it fronts. It is only a **fast-path over the authoritative durable
read** — a miss (including an evicted key) falls through to `ledger.is_processed()`, so an eviction can
never cause a false re-ingest; the durable table remains the source of truth for cross-restart /
cross-process (failover) dedup.

### §4 Disposition & invariants

`leave` changes only the **file's** fate on disk, not the **message's** disposition: every message a
left file produces is counted, routed, and finalized exactly as under `move`/`delete`
(`RECEIVED` → `ROUTED`/`UNROUTED` → `PROCESSED`/`FILTERED`/`ERROR`). The dedup ledger is a pure side
record (like `delivered_keys`): it is invisible to the finalizer's `FROM queue` scan and can never pin
or flip a message's disposition. At-least-once holds because the record is written **after** emit and the
ledger key is a property of the **file bytes** (a re-run re-derives the identical key), never of live
runner state.

## Consequences

- **A read-only share is now a first-class inbound** — no external copy-job workaround.
- **Additive schema, default-off feature.** A graph that never sets `after_read='leave'` is
  byte-identical: the new table is created empty and never written, no `env()` change, no new dependency.
  The server backends' ADR-0064 schema hash changes (one guarded re-apply on the next open); SQLite
  applies the additive `CREATE TABLE IF NOT EXISTS`. **3-backend parity** (the `processed_files` DDL +
  the three store methods) is written for all three backends; SQLite is exercised locally, SQL Server /
  Postgres parity is a **CI gate** (the Windows/Linux legs — no live server DB in the build env).
- **PHI-safe by construction.** The ledger stores a hash, never a filename; it is never logged at INFO+.
- **Bounded.** The age+count prune caps table growth even for a very-long-running poller.

## Options considered

1. **No leave-in-place (status quo).** Forces an external copy-job for read-only shares. Rejected — the
   real gap #142 files.
2. **Leave-in-place with an in-memory-only dedup set.** Simple, but loses all dedup on restart (every
   file re-ingested after a bounce) and can't work across a cluster failover. Rejected as the sole
   mechanism; kept only as the no-store test fallback.
3. **Leave-in-place with a durable, hashed, cross-backend ledger (chosen).** Survives restart, follows
   the established IDS-ONLY ledger precedent, PHI-safe, and bounded by an age+count prune.
4. **Store the cleartext filename (optionally encrypted) as the dedup key.** Rejected: a filename can
   embed an MRN; the precedent (`delivered_keys`/`resend_log`) stores a **hash / derived id**, not an
   encrypted PHI column — hashing is simpler, needs no cipher seam, and is un-loggable by construction.
