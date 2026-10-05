# PHI Handling & Data Protection

MessageFoundry carries **Protected Health Information (PHI)** — full HL7 v2 message bodies
contain patient names, MRNs, dates of birth, orders, and results. This document is the single
map of **where PHI lives, how it is protected, what is built today, and what is planned**.

> **Carries PHI.** Identity, access control, and the audit of operator *actions* live in
> [SECURITY.md](SECURITY.md). This document covers the *data*: storage, transport, logging,
> retention, and de-identification. The two are complementary — read both.

Every section is tagged:

- **`[BUILT]`** — implemented and enforced in the running engine today.
- **`[ROADMAP]`** — designed/intended but **not yet enforced**; do not assume the protection exists.
- **`[MIXED]`** — partly built; the section says which parts.

---

## 1. Threat model & trust boundary

**`[MIXED]`**

**Trust boundary: the organization's private network.** MessageFoundry is deployed **inside a single
healthcare organization's private, trusted network** (on-prem / private cloud), behind its perimeter
controls (firewall, segmentation, VPN/NAC) — **never directly on the public internet** (the standard
clinical-interface-engine model). The trust boundary is therefore the **org's internal network + the
host's OS accounts**. The full operator-facing posture is [DEPLOYMENT.md](DEPLOYMENT.md).
A data-flow diagram of the trust zones is in
[SECURITY.md](SECURITY.md#trust-boundaries-and-phi-data-flow).

This is a statement about *trust*, not about the bind interface. Three planes sit at different exposure
levels:

- **Management plane** (console/IDE → API) — **loopback by default** (or a restricted management
  subnet); always **authenticated** (RBAC + audit). Smallest surface.
- **Data plane** (inbound MLLP / TCP / X12 / DB-poll feeds) — **network-bound in any real install**
  (feeds arrive from other systems on the LAN, not `127.0.0.1`), protected by **TLS on the wire**
  (MLLP-over-TLS, built), the ingress/`[egress]` allow-lists, and your network segmentation. PHI must
  not cross the LAN in cleartext — and can't accidentally: the bind-guard **refuses any non-loopback
  *plaintext* API/MLLP bind** (ADR 0002 §0).
- **Inbound web-service listener** (a partner calling *into* MEFOR) — **built**, as the inbound
  [`Http(...)` listener](CONNECTIONS.md#http-web-service-listener--http-inbound-only-adr-0023). It is a
  distinct surface with its own controls: TLS or mTLS, `source_ip_allowlist`, and `intake_auth`, which
  defaults to `none` and so checks no credential. Off loopback it refuses to start without TLS
  (the linked section says when a flag can relax that), and, under the default
  `[security].enforcement = enforce`, without an effective peer control. **CORRECTED 2026-10-03:** this
  said the listener was not built.

The security controls that only become material off-loopback (MFA, mTLS, certificate revocation,
off-box logs) are **delegated to the org's environment** (IdP/AD, PKI, SIEM, network controls) and
documented per deployment — see [DEPLOYMENT.md](DEPLOYMENT.md) and [§11](#11-hardening-roadmap).

| Actor / vector | In scope? | Mitigation |
|---|---|---|
| Operator using the console/API | Yes | Auth + RBAC + audit (built — [SECURITY.md](SECURITY.md)); step-up re-verification on sensitive ops (ASVS 7.5.3) |
| Local user reading the DB file directly | Yes | Owner-only file ACL (built, **SQLite store only** — on a server-DB store the `.mdf`/`.ldf`/tempdb permissions are the DBA's) + at-rest body encryption when a key is set (built — §3); volume encryption for the rest |
| Stolen DB file / backup | Yes | At-rest body + `summary`/`metadata` encryption (built — §3) + required volume encryption for WAL/temp |
| PHI in logs / CI output / shell redirects | **Yes** | "Never log bodies" rule + global log redaction (`RedactionFilter`) + `safe_exc()` chokepoint + prod-DEBUG startup guard (built — §7) |
| Eavesdropper on the **internal LAN** (MLLP / API) | Yes | **API/WSS TLS + MLLP-over-TLS built** (Gate #4, §4) — *enable them*; the bind-guard refuses non-loopback plaintext; + your network segmentation |
| Compromised internal host / lateral movement | Partly | Network segmentation + TLS + required auth + at-rest encryption; off-box log shipping (delegate to your SIEM — §11) for evidence beyond the host |
| **Public-internet attacker** | **Out of scope by design** | MEFOR is **not** internet-facing (trust boundary above); off-loopback exposure is internal-only and TLS-required |
| Misconfigured outbound destination | Yes | Destination allowlist (`[egress].allowed_*`, §4) |

**Note:** the management API is **loopback-default *and* always authenticated** (auth/RBAC/audit built
— [SECURITY.md](SECURITY.md)); the data plane is network-bound with TLS (above). Only *public-internet*
exposure is excluded by design.

---

## 2. Where PHI lives — data-at-rest inventory

**`[MIXED]`**

PHI is persisted in the **message store on the configured backend** — `[store].backend` selects
SQLite ([store/store.py](../messagefoundry/store/store.py), `_SCHEMA`), **SQL Server**
([store/sqlserver.py](../messagefoundry/store/sqlserver.py)) or **PostgreSQL**
([store/postgres.py](../messagefoundry/store/postgres.py)) through `open_store`
([store/base.py](../messagefoundry/store/base.py)). The store *is* the queue (one generic `queue`
table, `stage` = `ingress` | `routed` | `outbound`), so both the inbound message and the
per-destination outbound copy are retained durably. **The backends are not identical at rest** — the
per-row *Backends* column below states each tier's real coverage, and the deltas are summarised after
the table.

**Protection levels.** Every at-rest location is classified into one of five levels; each level's
*protection requirements* (encryption, integrity, who may read it by which permission/route, retention,
destruction) are documented in [§3](#3-encryption-at-rest) under the matching heading.

| Level | Meaning |
|---|---|
| **PL-1 · PHI body** | A full clinical message body (or a slice/copy of one). Highest sensitivity. |
| **PL-2 · PHI identifier / free-text fragment** | Derived identifiers (MRN, patient name) or free text that may embed message fragments. |
| **PL-3 · Authentication secret** | Not PHI, but a secret whose disclosure defeats an access control. |
| **PL-4 · Operational metadata (non-PHI)** | Ids, hashes, counts, config labels — deliberately **not** ciphered. |
| **PL-5 · Engine-unreachable substrate** | Journals, logs, version stores, indexes. The app-level AEAD **cannot** reach these; whole-DB / volume encryption is the only cover. |

| Location | Backends | Holds PHI? | Encrypted at rest? (cipher · cell-AAD · key path) | Protection level | Notes | Retention |
|---|---|---|---|---|---|---|
| `messages.raw` | all three | **Yes** — full inbound body | **Yes, when a key is set** — store cipher; AAD `("messages","raw",id)`; store DEK | **PL-1** | Preserved verbatim by design (operators must see what arrived) | `` `[security].delete_message_bodies_after_days` `` |
| `queue.payload` (stage=`ingress`/`routed`) | all three | **Yes** — the raw body, **transient on the happy path** | **Yes, when a key is set** — store cipher; AAD `("queue","payload",id)`; store DEK | **PL-1** | A second copy of the raw. On the happy path it is held only across the route→transform window: the `ingress` row is consumed at `route_handoff`, each `routed` row at `transform_handoff` (deleted, never kept). A stalled stage can hold several briefly — surfaced by the `queue_buildup` alert. **Two ways it stops being transient, and only one is now bounded.** A router or handler content fault calls `dead_letter_now` (`pipeline/wiring_runner.py:4996`, `:5030`), leaving a `dead` row that keeps its `payload` — that row now rides the dead-letter window like a dead outbound row, since `replay` re-queues it in place from its own payload. A row left **permanently pending** does not: `purge_message_bodies` excludes any message holding a pending/inflight row, so such a row pins its body and its message's body indefinitely — still an honest gap, see [§8](#8-retention--purge) | ``dead-only `[retention].dead_letter_days` `` |
| `queue.payload` (stage=`outbound`) | all three | **Yes** — transformed outbound body | **Yes, when a key is set** — store cipher; AAD `("queue","payload",id)`; store DEK | **PL-1** | One row per destination; the persistent footprint | `` `[retention].dead_letter_days` `` |
| `shared_body.body` (store-once-deliver-many) | schema on all three; **rows written on SQLite only** | **Yes** — one transformed outbound body shared by N destinations | **Yes, when a key is set** — store cipher; AAD `("shared_body","body",hash)`; store DEK | **PL-1** | `hash` is the SHA-256 of the **plaintext** body (the content address). Refcounted: GC'd the moment the last referencing outbound row's body is purged. On SQL Server and Postgres the table is schema-parity only — `queue.body_ref` stays `NULL`, so no row is ever written. **Both** server backends nonetheless keep a read-side `LEFT JOIN shared_body` deref in `resend_to` (with its own `cell_aad("shared_body","body",…)` decrypt branch), which is why the column stays **cipher-covered** on all three. It is **rotation-swept on SQLite only** — `shared_body` has a pass in `MessageStore.reencrypt_to_active` but appears in neither server backend's rotation. Harmless while `body_ref` stays `NULL` there, and recorded as a deliberate decision in `store/postgres.py`'s `_CIPHER_COLUMNS` note ("schema-only this increment … it needs no rotation pass here until the dedup insert is wired") | ``rides `[security].delete_message_bodies_after_days` `` |
| `attachment_chunk.ciphertext` (ADR 0105 / #149) | all three | **Yes** — one slice of a detached very-large document (e.g. a base64 PDF from OBX-5.5) | **Yes, when a key is set** — store cipher, **sealed per chunk on write**; AAD `("attachment_chunk","ciphertext",attachment_id,seq)`; store DEK | **PL-1** | The document is detached at ingress, content-addressed (`sha256` of the verbatim plaintext) and chunked; the message keeps only an `mfdoc:v1:ref:` handle. Read back via `GET /messages/{id}/attachments/{id}` (§3) | ``rides `[security].delete_message_bodies_after_days` `` |
| `attachment` header row (`content_type`, `total_bytes`, `refcount`, `created_at`) + `message_attachment` linkage | all three | **No** — size/type/linkage only | No (metadata, deliberately not ciphered) | **PL-4** | The linkage row is the security crux of the download route: it scopes a content address to a message the caller may already read | ``rides `[security].delete_message_bodies_after_days` `` |
| `response.body` (ADR 0013 captured replies; ADR 0021 `kind='ack_sent'`) | all three | **Yes** — the partner's reply body, or the ACK/NAK the engine returned | **Yes, when a key is set** — store cipher; AAD `("response","body",message_id,destination_name,response_seq)`; store DEK | **PL-1** | Composite PK, so it rides its own migration/rotation pass. An **ACK body is stored only when the store cipher is active** — on a keyless store it is `NULL` rather than plaintext (fail-safe), and a NAK never stores a body at all | ``rides `[security].delete_message_bodies_after_days` `` |
| `[store].uploads_dir/*.blob` + `*.meta` — the cipher cells `uploaded_file.body` / `uploaded_file.meta` (offline uploaded logs, ADR 0134) | all (filesystem, not the DB) | **Yes** — an operator-uploaded diagnostic message file, held for offline browsing decoupled from any connection | **Yes, when a key is set** — the **same store cipher** (`build_store_cipher`); AAD `("uploaded_file","body")` / `("uploaded_file","meta")` + `file_id`; store DEK. **identity/plaintext-on-disk otherwise** (the File-connector-spill tier below) | **PL-1** | A PHI-at-rest location **outside** the message store, opt-in (unset ⇒ the subsystem is disabled — no surface). On-disk identity is a random 32-hex `file_id` (path-traversal guard); the operator filename is display-only. Every access is `files:*`-gated, browse is step-up + PHI-hop-guarded, all audited (metadata only). `rotate-key` re-seals every upload under the active key, and seals a plaintext one. **On a keyed store a plaintext upload is refused on read until it does** (BACKLOG #1169, owner ruling 2026-09-23; see [§3](#3-encryption-at-rest)). The dir is created `0o700` and the sidecar written `0o600` **best-effort, and both are no-ops on Windows** — the engine applies no ACL here (it does not call the `icacls` enforcer). **Retention + quotas (ASVS 5.2.4):** uploaded files auto-prune after `[store].uploads_retention_days` (default **30**) — swept opportunistically at save time and by a periodic task. A pruned pair is audited (`upload.prune`, file_id + uploader only, never content) when the pass removed its body; a body whose unlink is refused stays, unaudited and still listed, for the next pass. **Not every removal gets a row.** At least these go unaudited: a write leftover the orphan sweep removes (no metadata exists, so it is a count and a WARNING); a runner sweep still going when its bounded shutdown wait (5 s) runs out, which is cancelled and logged at ERROR; a runner audit call that raises, logged per file; and the save-time sweep's rows when its request is cancelled or a `record_audit` call fails, since it audits only after the whole pass and catches only `OSError`. Per-uploader caps `[store].max_upload_files_per_user` (default **100**) / `[store].max_upload_total_bytes_per_user` (default **250 MiB**) bound the at-rest volume; a would-be over-quota upload is refused **HTTP 409** with an `upload.reject_quota` audit before anything is written (defaults-ON, `ge=1` floors). The quota is scoped to the **`uploads_dir`, not to the process** — the sidecar scan is uncached, so engine shards sharing one dir enforce **one** budget between them (measured 2026-08-10); shards given separate dirs get separate budgets by construction. The check and the write it authorizes are one critical section per process, and a shard mid-upload is held as an atomic reservation on the unified store every shard shares (`Store.reserve_upload_quota`). Each upload reserves, reads the in-flight total back, then scans the disk, and is refused unless the disk, the other shards' in-flight uploads and this file all fit (ASVS 2.3.4, BACKLOG #1941). The residuals that survive it, and their bounds, are stated once in `uploads.UploadQuotaError`. Harden the dir + volume encryption ([§10](#10-secure-deployment--operations-checklist)) | `` `[store].uploads_retention_days` `` |
| `[backup].destination/mefor-backup-*.mfbak` (ADR 0049 DR backup) | **SQLite only** carries bodies | **SQLite: Yes** — a consistent store snapshot (full inbound + outbound bodies) + the config bundle. **SQL Server / Postgres: No** — config bundle only | **Yes** — `.mfbak` chunked-AEAD codec under the **store DEK** (`resolve_active_key`); an identity-cipher (no-key) box is **refused** unless `[backup].allow_unencrypted` writes a `.mfbak.plain` | **PL-1** (SQLite) / **PL-4** (server backends) | On a **server-DB store `snapshot_to` raises `DbaDelegatedError`**, so the BackupRunner writes a **config-only** archive — or skips entirely when `[backup].config_only_on_server_db = false`. There is therefore **no `.mfbak` containing message bodies on SQL Server or Postgres**; the DB-tier backup there is `BACKUP DATABASE` / Always On / `pg_dump` / PITR, infra-owned. Where bodies *are* present it is a second at-rest PHI copy, bounded by keep-N retention; unlike `uploads_dir`, it is **not** re-encrypted by `rotate-key`. The share's own ACLs are infra-owned. **The keep-N bound covers the CANONICAL name only** — a `.failed` or `.part` archive at the same destination is deliberately outside the candidate set (ADR 0049, BACKLOG #1587) and nothing expires it; see [§8](#8-retention--purge)'s honest-gaps table | ``keep-N `[backup].retention_keep` `` |
| `mefor-backup-*` / `mefor-verify-*` staging dirs (ADR 0049, BACKLOG #1174): **SQLite** — the store's own data dir; **SQL Server / Postgres** — `.mefor-staging` under `[backup].destination`; a **standalone verify** (`restore-verify`, the DR cold-seed activation) — a private `mefor-verify-*` dir under the OS temp dir | SQLite carries bodies; server backends config-only | **Yes** — a full store snapshot and its tar, and on verify a **decrypted** archive | **No** — the snapshot keeps the store's own column cipher, but the staging tar and the verify extraction are **plaintext on disk**. **SQLite store:** the engine applies the store's own best-effort `_secure_file` to each staged tar and extracted store as soon as it exists and before its first byte, as `mefor-restore-*` does, and `snapshot_to` applies it to the snapshot once its copy completes. What it leaves inside a temp directory's own DACL is not always owner-only (ADR 0163). **SQL Server / Postgres:** each run's dir under `.mefor-staging` is created by `mkdtemp` and must come out owner-only (mode `0700` on POSIX; on Windows a protected DACL naming only SYSTEM, Administrators, OWNER RIGHTS and its owner), and each staged file gets `_secure_file` before its first byte. The `.mefor-staging` dir itself still inherits what the destination grants, and holds no plaintext of its own. **Standalone verify, any backend:** the dir is created by `mkdtemp`, so it is mode `0700` on POSIX and on Windows carries the protected DACL Python writes for that mode (SYSTEM, Administrators, OWNER RIGHTS, measured on 3.14.6), and each staged file gets `_secure_file` before its first byte. **All of these, since BACKLOG #1174:** each run's dir, in the data dir, in `.mefor-staging` and under the temp dir alike, must come out owner-only, or nothing is staged. On a volume that reports modes or ACLs the engine did not ask for, a backup fails with a reason naming the dir, and a standalone verify returns `FAIL` saying the volume, not the archive, is at fault. Volumes that can do this include, for example, a CIFS or Samba share without POSIX extensions, WSL `/mnt/c` without `metadata`, a Docker Desktop bind mount of a Windows path, and FAT or exFAT. A backup's own verify refused this way leaves the written archive unpublished at its staging name, not quarantined. The check trusts the owner the file system reports, and on POSIX reads mode bits only, so a server-set owner or an inherited macOS or NFSv4 extended ACL can pass it | **PL-1** | A backup snapshots the store into a `mefor-backup-*` dir and tars it **plaintext** there before sealing it into the `.mfbak` (`pipeline/dr_backup.py`), and `[backup].verify_after_backup` (**default `true`**) decrypts the archive straight back out to a `mefor-verify-*` dir on **every** run — independent of `full_restore_verify`. `restore-verify` and the DR cold-seed activation do not stage there. They stage in a private dir under the OS temp dir (`%TEMP%` / `TMPDIR`) of the account that runs them. So they do not write to the archive's own directory, which on a DR box may be a read-only share. Nor do they write beside `[store].path`, the current directory under the default relative path. The exceptions are an archive or store that sits in the temp dir itself, and a box with no writable temp dir, where Python falls back to the current directory. That dir needs about twice the archive's size free on the temp volume while it runs; the verify checks that first and returns `FAIL` naming the volume, not the archive, when it is short (a backup checks its own staging and destination volumes the same way, and fails with kind `space`); on a RAM-backed `/tmp` it is held in memory and can reach swap. Each dir holds a lock file for its whole run and is removed on success, on an exception and on cancellation; a build cancelled on the event loop keeps running on its worker thread, which removes the dir once it lets go of the files. **A crash or `SIGKILL` still leaves the dir behind**, and the OS releases its lock with the process. The **next backup** removes it. A standalone verify's dir is removed by the next standalone verify, or the next backup, that runs under the same account and temp dir. Those two sweep the temp dir for dirs with the same owner as their own new dir, because the temp dir can be shared. A dir with any other owner is never touched. On Windows the owner is the process's default owner: for an elevated process that is Administrators, so elevated runs of any admin account, and SYSTEM, can share one owner, while a non-elevated run of the same user does not. The sweep takes only a dir whose lock it can acquire and that holds the marker a run creates once it holds its lock, and it never goes by age, so a sibling engine shard's live run survives it. The sweep never runs at `serve` start. A dir whose removal is refused — on Windows, a scanner or indexer still holding a file — is retried for about two seconds, then every file in it is truncated to zero bytes in place (BACKLOG #1721). Truncation empties the FILE; the disk blocks it freed still hold the bytes until reused, and only FDE on that volume covers them ([§10](#10-secure-deployment--operations-checklist)). A holder that denies write sharing or has the file mapped refuses the truncation too. If a file can be neither removed nor emptied, the verify says so and names the dir (a `PASS` becomes `FAIL`, another verdict keeps its status, and an exception carries the dir as a note), and a backup run still publishes its good archive but raises a `backup_failed` alert of kind `cleanup`, under its own subject `dr_backup:staging`, and names the dir in its audit row; either way the next sweep of that dir's root retries it. A hard-linked file is reported, never truncated. **Still unbounded, at least:** a dir left behind when no further backup runs (an on-demand-only box, or `[backup].enabled` turned off), a standalone verify's dir when no later standalone verify or backup runs under that account and temp dir (the engine's backups never sweep an operator's profile temp), a dir something still holds open each time the sweep runs, a dir the engine's account cannot open (such as one an administrator's interactive run left; the sweep logs it), a dir on a destination that cannot lock at all (it is staged unlocked and never swept), a dir left in the instant between its creation and its lock (it holds no plaintext yet, and the sweep cannot prove it abandoned), and the freed blocks above | `UNBOUNDED — honest gap` |
| `mefor-restore-*` staging dirs (the **destination** volume, ADR 0049 / BACKLOG #1717) | SQLite only — `restore` refuses a config-only archive outright | **Yes** — the whole decrypted archive, then the whole extracted `store.db` | **No** — both staged files are **plaintext on disk**; the engine locks them down, calling the store's own `_secure_file` on each as soon as it exists, as it now does for the SQLite backup and verify staging in the row above. That ACL is owner-only for **the account that ran the restore**: `_secure_file` grants `_current_user()`, which is the account the process runs as. On this operator-driven path that is the operator's own account, not the service account | **PL-1** | `messagefoundry restore` stages on `--to`'s own volume rather than `%TEMP%`, so the restored store is published by a hard link instead of a second multi-GB copy. That choice moves the exposure off the shared temp volume and onto the data volume, where the engine's own file ACL reaches it — but the **directory** still inherits whatever the destination's parent grants on Windows, so the operator's directory ACL remains the backstop ([§10](#10-secure-deployment--operations-checklist)) — and it is the only control on a box where `_current_user()` resolves no name, since `_secure_file` is best-effort and logs rather than failing, leaving the file whatever the parent directory granted. Transient (the `TemporaryDirectory` unlinks on exit) but **not** on a crash or `SIGKILL`. A restore is an operator-driven one-shot rather than a scheduled repeat, so nothing accumulates across runs — but nothing expires what a crash leaves behind: unlike the backup and verify staging in the row above, no sweep removes a restore's directory | `UNBOUNDED — honest gap` |
| File-connector output / spill dirs (`.hl7`, `.processed`, `.error`) | all | **Yes** — plaintext on disk | **No** — no cipher at all on this path | **PL-1** | Written by the File transport; treat the directory as PHI and cover it with volume/share encryption + an ACL | `UNBOUNDED — honest gap` |
| Application log files (`[logging].log_dir`; under NSSM, `<DataDir>\logs\service.out.log` and `service.err.log`) | all (filesystem, not the DB) | **Possibly** — redaction is best-effort; a single-token identifier can survive it | **No** — plaintext on disk, no app-level cipher | **PL-1** | NSSM captures stdout/stderr; the engine writes a log file of its own only when the opt-in `[logging].file` is set (#122, ADR 0162 — same three handler filters, engine-owned rotation, refused inside `log_dir`), together with the `*.broken-*` files a write failure rolls aside, which sit outside `log_dir` and are therefore NOT swept by `[retention].app_log_days`. The defence is the three handler filters + `safe_exc()`/`safe_text()` + the never-log-bodies rule ([§7](#7-logging--phi-redaction) row 1), and the residual is stated there. The directory ACL is the NSSM installer's **best-effort** `icacls /inheritance:r`; age deletion is `[retention].app_log_days` (files by **mtime** — content is never read, so nothing selective happens here) and optional in-place gzip is `[retention].app_log_compress_days` (the compressor **does** read a file's bytes to archive + integrity-verify them, but only in-process — nothing is logged, and the archive stays inside the same ACL'd directory at the source's mtime). A support bundle copies a 500-line tail of this file out of the ACL'd directory entirely ([§7](#7-logging--phi-redaction)). Cover the volume with FDE ([§10](#10-secure-deployment--operations-checklist)) | `` `[retention].app_log_days` `` |
| Off-box forwarder spool (`[logging].forward_spool_dir`; default `log-spool/<engine or shard id>` beside `[store].path`) | all (filesystem, not the DB) | **Possibly** — it holds the same redacted text the forwarder sends, and redaction is best-effort | **No** — plaintext JSONL on disk, no app-level cipher | **PL-1** | BACKLOG #1966, ADR 0200. Records the off-box collector has not yet taken (down, backing off, or still queued at shutdown), kept in order and sent when it answers again, best effort (ADR 0200 states the limits). The spool is fed from the far side of the forwarder hand-off queue, so it only ever holds text the three handler filters already processed; a test plants a PHI-shaped value and proves only its redacted form lands. The directory is created `0o700` and segments `0o600` best-effort (no-ops on Windows, where it inherits the parent ACL). A segment is deleted once every entry in it is sent. Bounded by **size**, not age: when full the newest record is dropped and reported. `0` turns the spool off. Cover the volume with FDE ([§10](#10-secure-deployment--operations-checklist)) | `` `[logging].forward_spool_max_bytes` `` |
| `messages.summary` | all three | **Yes** — MRN / patient name / order | **Yes, when a key is set** — store cipher; AAD `("messages","summary",id)`; store DEK (EF-3) | **PL-2** | Ingest-derived; no SQL search or index exists on it, so encrypting it costs nothing. NULL/blank stay as-is | ``rides `[security].delete_message_bodies_after_days` `` |
| `messages.metadata` | all three | **Yes** — operator/handler-attached values | **Yes, when a key is set** — store cipher; AAD `("messages","metadata",id)`; store DEK (EF-3) | **PL-2** | **Nulled by `purge_message_bodies` on the `[retention].messages_days` window, in the same statement as the body** (ASVS 14.2.7) — see [§8](#8-retention--purge) | ``rides `[security].delete_message_bodies_after_days` `` |
| `messages.error` | all three | **Possibly** — may embed raw fragments from exceptions | **Yes, when a key is set** — store cipher; AAD `("messages","error",id)`; store DEK (WP-5) | **PL-2** | Also `safe_exc()`-redacted **before** write. NULL/blank values stay as-is | ``rides `[security].delete_message_bodies_after_days` `` |
| `queue.last_error` | all three | **Possibly** — same | **Yes, when a key is set** — store cipher; AAD `("queue","last_error",id)`; store DEK (WP-5) | **PL-2** | Same double defence (`safe_exc()` then cipher) | ``rides `[security].delete_message_bodies_after_days` `` |
| `message_events.detail` | all three | **Possibly** — per-message disposition detail | **Yes, when a key is set** — store cipher; AAD `("message_events","detail",message_id,ts,event)`; store DEK | **PL-2** | `id` is AUTOINCREMENT/IDENTITY and unknown at INSERT, so the AAD binds the natural tuple and the column rides its own composite migration/rotation pass. `safe_text()`-scrubbed before write | ``rides `[security].delete_message_bodies_after_days` `` |
| `response.detail`, `response.resp_headers` | all three | **Possibly** — reply diagnostics / partner response headers | **Yes, when a key is set** — store cipher; AAD `("response","detail", …)` / `("response","resp_headers",message_id,destination_name,response_seq)`; store DEK | **PL-2** | `detail` is `safe_text()`-scrubbed and 200-char bounded before the cipher | ``rides `[security].delete_message_bodies_after_days` `` |
| `state.value` (ADR 0005 transform state) | all three | **Possibly** — a correlation map (e.g. MRN→surrogate) written by a Handler | **Yes, when a key is set** — JSON-encoded then store cipher; AAD `("state","value",namespace,key)`; store DEK | **PL-2** | Composite PK; own migration/rotation pass. **No read API** — reachable only from a Handler via `state_get`/`state_set` | `` `[retention].state_max_age_days` `` |
| `reference.value` (ADR 0006 versioned lookup snapshots) | all three | **Possibly** — a snapshot row may be patient-keyed | **Yes, when a key is set** — store cipher; AAD `("reference","value",name,version,key)`; store DEK | **PL-2** | Composite PK; own migration/rotation pass. **No read API.** **`[retention].reference_snapshot_days`** — `purge_reference_snapshots` DELETEs the rows of a set config **no longer declares** whose active version was synced before the cutoff (`0` = keep forever, the default) ([§8](#8-retention--purge)). **Orphan-only, and the limit is the point:** a set that IS still declared is never touched however old its `synced_at`, because its snapshot is live data the engine serves — so the normal case, a wired set holding live PHI, is still bounded by nothing. Do not restate this as a plain window over `reference.value` | ``orphan-only `[retention].reference_snapshot_days` `` |
| `search_presets.criteria` (ADR 0136 saved Log-Search filters) | all three | **Yes** — the operator's saved `content` / `field_value` needle is PHI-shaped by construction | **Yes, when a key is set** — store cipher; AAD `("search_presets","criteria",id)`; store DEK | **PL-2** | Never returned by the API: `GET /search/presets` lists names + timestamps only; the needle is loaded server-side by `GET /search/layered`. **`[retention].search_preset_days`** — `purge_search_presets` DELETEs the whole row past the window on every backend, keyed on last-**used** — the later of `updated_at` and `last_used_at`, #306 (`0` = keep forever, the default) ([§8](#8-retention--purge)) | `` `[retention].search_preset_days` `` |
| `connection_event.reason` (#46 transport/lifecycle log, **default on**) | all three | **Possibly** — a free-text diagnostic fragment | **Yes, when a key is set** — store cipher; AAD `("connection_event","reason",connection,ts,kind)`; store DEK | **PL-2** | Defended twice: the emit site passes a `safe_exc()`-scrubbed string and the store re-applies `safe_text(reason)[:200]`. IDENTITY `id`, so its own composite pass. Every other column is bounded engine/config metadata **except `peer_host`** (its own PL-4 row below) — the table carries no frame, body or HL7 field value. The route is read under `monitoring:read`, **not** a PHI permission, so `reason` alone is gated on `messages:view_summary` and masked until a per-event reveal (BACKLOG #2443; [§7](#7-logging--phi-redaction)) | `` `[retention].connection_event_retention_hours` `` |
| `connection_event.peer_host` | all three | **No** — a network address; identifies a *host*, not a patient | No (metadata, deliberately not ciphered) | **PL-4** | The connecting peer's IP, taken from the socket; `NULL` for outbound/unknown. Personal data, not PHI — the **same class and the same decision** as `audit_log.client` / `sessions.client`: plaintext so it stays greppable for incident response. Returned to operators by `GET /events` under `monitoring:read`. Purged with its row by `[retention].connection_event_retention_hours` | ``rides `[retention].connection_event_retention_hours` `` |
| `alert_instance.reason` (ADR 0044 operator alerts) | all three | **Possibly** — the alert's `detail`/`reason` free text | **Yes, when a key is set** — store cipher; AAD `("alert_instance","reason",event_type,connection)`; store DEK | **PL-2** | `safe_text(reason)[:200]` before the cipher. The AAD binds the de-dup grain, so the same AAD covers both the INSERT and the re-fire upsert UPDATE that never sees the `id`. The route is read under `monitoring:diagnose`; `reason` alone is gated on `messages:view_summary` and masked until a per-alert reveal (BACKLOG #2443; [§7](#7-logging--phi-redaction)) | ``rides `[retention].connection_event_retention_hours` `` |
| `users.totp_secret` | all three | **No** — not PHI | **Yes, when a key is set** — store cipher; AAD `("users","totp_secret",id)`; store DEK | **PL-3** | The base32 TOTP MFA seed. It is returned **once**, when enrollment stages it. §3's PL-3 block says how. **This cell said "Never returned by any API response model" until BACKLOG #1185 corrected it.** Its siblings `users.password_hash` and `users.totp_recovery_codes` are **argon2id one-way hashes** and are deliberately **not** ciphered | `keep-forever by design` — it lives and dies with the user row |
| `queue.handler_name` / `destination_name` / `channel_id` | all three | No — names, not bodies | No (metadata, deliberately not ciphered) | **PL-4** | The handler the transform worker runs; the destination the delivery worker drains | `n/a — not PHI` |
| `messages.control_id`, `messages.message_type` | all three | Low (MSH-10/MSH-9) | **No** — plaintext by design | **PL-4** | Needed plaintext for dedup/routing/indexes (`ix_messages_control`). Covered only by the whole-DB / volume layer | `keep-forever by design` — dedup/routing keys that live and die with the message row |
| `audit_log.detail` | all three | Low — exposed IDs/counts, not bodies | **No** — plaintext by design | **PL-4** | JSON metadata about PHI *access*, not the PHI itself. Its writers only ever store filter shapes, counts and ids | `keep-forever by design` — 45 CFR 164.316(b)(2)(i) six-year documentation retention. **Not** chain-breakage: which rows a delete removes decides that, and the reasoning is stated once, in the `audit_days` row of [CONFIGURATION.md](CONFIGURATION.md#retention) |
| `audit_log.client` (ADR 0150) | all three | **No** — a network address; identifies a *host*, not a patient | No (metadata, deliberately not ciphered) | **PL-4** | The caller's client address — the "from where" of an audited action; `NULL` for engine-internal/`system` writes. **Personal data, but not PHI**, and exactly what HIPAA §164.312(b) audit controls exist to capture. Plaintext by decision: it must stay greppable/indexable for incident response, it already appears in the clear in `sessions.client`, and it is folded **inside** the tamper-evident hash chain — so it carries **integrity** protection even without confidentiality. Widens a store-file compromise from *who did what* to *who did what from where*; volume encryption + owner-only ACLs on whichever host owns the files — the engine's own `_secure_file` covers the **SQLite** store only ([§10](#10-secure-deployment--operations-checklist)) — are the control | `keep-forever by design` — same `audit_log` row lifetime as `detail`; the value is folded **inside** the hash chain |
| `delivered_keys` (H2 idempotency ledger) | all three | **No** — hashes + ids only | No (deliberately not ciphered — nothing to protect) | **PL-4** | One row per completed outbound delivery: a SHA-256 `delivery_key` over non-PHI ids + a replay-stable seq, plus `outbox_id`/`message_id`/`destination_name`/`delivery_seq`. **Never a body or any PHI** — `control_id` is only *folded into the hash input*, never stored in the clear here. Lets the FIFO claim skip-and-complete a re-claimed already-delivered head without re-sending | `keep-forever by design` — the idempotency ledger a re-claimed already-delivered row checks instead of re-sending |
| `state.namespace` / `state.key` | all three | **Possibly** — a Handler that keys correlation state on a raw MRN stores that identifier here in the clear | **No** — plaintext by construction: the pair is the composite primary key **and** the AAD input for `state.value`, so it cannot be ciphered without losing the lookup | **PL-4** | Authors must key state on a **surrogate, never a raw identifier**. Covered only by the whole-DB / volume layer. Rides `[retention].state_max_age_days` with its value | ``rides `[retention].state_max_age_days` `` |
| `reference.name` / `reference.version` / `reference.key` | all three | **Possibly** — §2's `reference.value` row notes a snapshot row may be patient-keyed; the key column is where that identifier would sit | **No** — plaintext by construction, same reason as `state` | **PL-4** | Same rule: key reference sets on a surrogate. The key columns ride the same delete: `purge_reference_snapshots` removes whole rows of an **undeclared** set, so these go with the `value` they key. A **declared** set is never touched — same orphan-only limit as `reference.value` above | ``orphan-only `[retention].reference_snapshot_days` `` |
| `sessions.token_hash` / `client`, `resend_log`, `processed_files`, `pending_approvals.params`, `webauthn_credentials.public_key` | all three | **No** | No (deliberately not ciphered) | **PL-4** | Session tokens are stored as SHA-256 only; `processed_files` holds a hashed derived file key, never a path; approval params carry connection names / channel ids / a config dir by construction; COSE public keys (ADR 0068) are **verification material, not secrets** and are explicitly excluded from the cipher and from rekey | `n/a — not PHI` |
| `known_login_addresses` (`user_id` / `address` / `first_seen` / `last_seen`, vault BACKLOG #2145) | all three | **No** — a network address tied to an account; identifies a *host*, not a patient | No (metadata, deliberately not ciphered) | **PL-4** | The first-seen sign-in address baseline (BACKLOG #288): one row per host an account finished a sign-in or passed a step-up from, keyed on the account id. **Personal data, not PHI** — the same class and the same decision as `sessions.client` and `audit_log.client`. Read only by the sign-in signal; **no API surface**. Rows past the signal's 90-day lookback are deleted at the account's next sign-in or step-up that records an address. A sign-in that records nothing, such as one that still owes a factor, prunes nothing, so a dormant account, or one that never records a new address, keeps its stale rows until it does. `delete_user` removes every row with the account, and the account's foreign key cascades to any row a racing write leaves | `n/a — not PHI` |
| `secret_rotation_meta` (`secret_key` / `fingerprint` / `tracked_since` / `last_rotated`) | **All three backends** (#1186 — SQLite `MessageStore`, `SqlServerStore` and `PostgresStore` each create the table at open and implement the `SecretRotationMetaStore` protocol) | **No** — non-secret rotation state: a **keyed MAC** (DEK-derived, one-way — never the secret value) + ISO dates only | No (deliberately not ciphered — it is neither PHI nor a secret; the MAC is one-way and un-guessable without the DEK) | **PL-4** | ASVS 13.3.4 rotation watcher (BACKLOG #282). `fingerprint` is a keyed MAC so obtaining the rows leaks no secret. Written on a keyed store; absent on a keyless one | `n/a — not PHI` |
| SQLite DB file + `-wal` / `-shm` / temp files, and every index | SQLite | **Yes** (mirror the above) | **No** — the app cipher cannot reach them | **PL-5** | WAL/shm hold recently-written PHI outside any app-level encryption. Cover: SQLCipher (whole-DB) and/or FDE on the engine host's data volume | `n/a — not PHI` |
| SQL Server `.ldf` **transaction log** + the **tempdb version store**, and every index | SQL Server | **Yes** (row images of `messages`/`queue`, ciphertext columns **plus** the always-plaintext `control_id`/`message_type`) | **No** — outside the app-level AEAD entirely | **PL-5** | The engine itself makes this load-bearing: it **force-enables `READ_COMMITTED_SNAPSHOT` and `ALLOW_SNAPSHOT_ISOLATION`** on the store database at open, so tempdb's version store holds row images for the lifetime of every open snapshot. The `.ldf` holds every row image for the same reason. Additional tempdb objects: the `#eligible` temp table used by `purge_message_bodies` and the FIFO-claim table variables (ids only, non-PHI). Cover: **SQL Server TDE at the database + FDE on the *SQL Server host's* volumes** — **not** BitLocker on the engine host | `n/a — not PHI` |
| PostgreSQL WAL (`pg_wal`), base files and every index | Postgres | **Yes** (mirror the above) | **No** — outside the app-level AEAD | **PL-5** | Cover: cluster-level / filesystem encryption on the database host, infra-owned | `n/a — not PHI` |

> **Retention column — vocabulary (ASVS 14.2.7).** Every cell is exactly one of eight forms. The serve
> gate's tier list and the §2↔§8 drift test are GENERATED from these, so there are no prose variants —
> a hand-typed tuple with a longer literal is the same defect this column exists to remove.
>
> - **`[section].window`** — bounded by its **own** named window, cited exactly as an operator types it.
> - **rides `[section].window`** — no window of its own; deleted or nulled by another tier's purge.
>   Valid **only** when §8's row for that window names this table/column in its Mechanism cell. This is
>   the form most likely to be wrong, because it asserts coverage that lives somewhere else.
> - **orphan-only `[retention].reference_snapshot_days`** — `reference.*` only: purged **only** when
>   config no longer declares the set. A **declared** set is never touched, whatever its age.
> - **dead-only `[retention].dead_letter_days`** — `queue.payload` at `ingress`/`routed` only: blanked
>   **only** once the row is `dead`. That is the whole of what the window reaches at those stages, and a
>   plain window claim over the tier would be false — a row left permanently **pending** is bounded by
>   nothing. Same shape as **orphan-only**: one state of the tier is covered and the other is not, so
>   the residual stays listed in [§8](#8-retention--purge).
> - **keep-forever by design** — a deliberate decision, not a gap; the clause after the dash is the reason.
> - **n/a — not PHI** — PL-4 operational metadata or PL-5 engine-unreachable substrate.
> - **keep-N `[backup].retention_keep`** — bounded by a **count** of retained artifacts, not an age window.
> - **UNBOUNDED — honest gap** — no purge covers this tier. Stated plainly on purpose: an honest gap is
>   worth more than a coverage claim that cannot be evidenced, and every one of these is also listed in
>   [§8](#8-retention--purge).
>
> Machine-readable by construction: the form keyword is **un-backticked** and the setting is
> **backticked**, so one pattern extracts the window from every bounded form, and the three prose forms
> contain no backticked setting at all.

**Two live fields take a stored column's rating (BACKLOG #1185).** `ConnectionRow.error` (on
`GET /connections`) and `ConnectionMetadata.error` (on `GET /connections/{name}/metadata`) are not
stored columns, so neither has a row in the table above. Each carries a live string: why a connection
failed to start (ADR 0031), or why the DR run-profile parked it (ADR 0048). The start-failure string
is `safe_exc()` text. The runner stores it through the `connection_stopped` alert, so its stored
copy is `alert_instance.reason`. **Both fields are rated PL-2, the level of `alert_instance.reason`.**
The rating is on the FIELD, not only on the start-failure string. So both routes are served
`Cache-Control: no-store`. `tests/test_no_store_phi_coverage.py` binds each field to
`alert_instance.reason` and reads the level out of that column's row above. Both routes need only
`monitoring:read`, which is not a PHI permission. So `ConnectionRow.error` is gated on
`messages:view_summary` (BACKLOG #2443, owner ruling R12): null without it, a fixed `****` with it,
and whole only on the audited `reveal=<connection name>` act on `GET /connections`.
`ConnectionMetadata.error` is gated and masked the same way, whole only on the audited
`reveal=true` act on `GET /connections/{name}/metadata`. *Corrected 2026-10-01:* this said that
field was not yet gated; the gate change that closed it is in [SECURITY.md](SECURITY.md)
"Field-level (property) authorization".

**Per-backend cipher coverage, stated exactly.** The store cipher covers **18** `(table, column)`
pairs on SQLite. **SQL Server** covers 17 = the SQLite set **minus** `shared_body.body` (never written
there). **Postgres** covers 17 = the SQLite set **minus** `shared_body.body`. SQL Server's count was
18 until the legacy `outbox.payload` was retired (below); the two server backends now carry the same
set. One asymmetry remains and is worth knowing: neither SQL Server nor Postgres sweeps
`attachment_chunk` in its *on-open* plaintext→cipher migration (only in `rotate-key`), which is
harmless today because `put_attachment` always seals on write, but means a legacy no-key→key
transition would not sweep chunks the way SQLite's does.

**The legacy SQL Server `outbox` table is gone (ASVS 14.2.7), and that closed two real gaps.** It was
recreated by the schema pass on every open and read by nothing, so a store upgraded from the
pre-staged-pipeline layout kept full outbound PHI bodies there that no purge on any backend reached —
while `messages.raw` blanked on its own window, so the message read as purged. It also sat outside
`reencrypt_to_active`, so a key rotation that retired the old key left those bodies undecryptable.
Both close the same way: a guarded statement in the SQL Server schema batch folds surviving rows into
`queue` as `stage='outbound'` — payload carried over verbatim, so encryption at rest is preserved —
and then `DROP`s the table. Migrated rows are ordinary outbound queue rows, bounded by
`[security].delete_message_bodies_after_days` / `[retention].dead_letter_days`, swept by the on-open
cipher migration and rotated by `reencrypt_to_active`, so the tier no longer needs its own row here.
SQLite already performed the equivalent migration (`_migrate_outbox_to_queue`); Postgres never had the
table.

**The body cipher `[BUILT]`.** Each backend routes the columns above through the store's `_cipher`
([store/crypto.py](../messagefoundry/store/crypto.py)) on write/read — **AES-256-GCM when a store key
is configured, identity otherwise** — so encryption is transparent to callers. Existing plaintext rows
are migrated in place on first start with a key. **§2 is the normative inventory**; §3 groups the same
cells by protection level rather than redefining the set, and `tests/test_phi_at_rest_inventory.py` pins **both** sections to the
store's cipher registry — derived from the `cell_aad(...)` call sites and each backend's own
`_CIPHER_COLUMNS` / migration / rotation passes — so they cannot diverge. See
[§3](#3-encryption-at-rest).

**Cell binding is ON by default** (`[store].aad_bind = true`, ADR 0148 GIVEN 1). Every write site
above passes a cell AAD and, on the shipped default, that AAD is **bound** — writes use the `mfenc:v4`
writer (`mfenc:v2` before ADR 0196). Setting `aad_bind = false` selects the frozen `mfenc:v1` writer, which binds no associated data
(the AAD is then computed and ignored), and is a **declared loosening** that `security_loosenings()`
names. The AAD is bound unconditionally under `[store].cipher_provider = "vault_transit"` (`mfenc:v3`,
where it is forwarded to Transit). See [§3](#3-encryption-at-rest).

**Body format is irrelevant to the at-rest tier — they all ride the same cipher.** The `raw`/`payload`
rows above are payload-agnostic, so non-HL7 PHI bodies are stored through the **same encrypting store
path** (no separate at-rest tier):

- **DICOM objects `[BUILT]` (ADR 0025).** A received DICOM object is **PHI** — the header carries
  PatientName / MRN / DOB — and is stored through the store cipher like any other body, never logged at
  INFO+, egress-allowlisted, and TLS off-loopback. Logs/errors carry only **routing-safe identifiers**
  (SOPClassUID / Modality / UIDs / AE title), never the dataset or element values. (Pixel data can carry
  *burned-in* PHI, but **pixel-data handling is out of scope.**)
- **Base64-carried binary bodies `[BUILT]` (ADR 0028).** A base64-encoded body is **still PHI** —
  encoding is not obfuscation — so the never-log rules (§7) apply unchanged. Base64 inflates size by
  ~33%, so **size/retention budgets (§8) measure the encoded size.**

**File permissions `[BUILT — SQLite only]`.** `MessageStore.open()` restricts the DB and its
`-wal`/`-shm` siblings on every open — POSIX `chmod 0600`; on Windows, SQLite store owner-only DACL via
`icacls` (inheritance off) through `_secure_file()`
([store/store.py](../messagefoundry/store/store.py)), **except** in a data directory hardened the way
`install-service.ps1` leaves it (the exact test is stated once, in the ADR 0163 note linked below).
There each file gets an explicit, protected DACL naming only the principals the directory allows, so
the service account and the operator running `provision-admin` can both open the store in either
order. What that widens and narrows, and why it was accepted, is stated once in the
[ADR 0163](adr/0163-first-run-provisioning-without-a-default-account-the-not-present-arm-via-an-engine-consumed-request.md)
note of 2026-09-24. It is best-effort and non-fatal: a skipped or
failed restriction is **logged** (STORE-2), with directory-level ACLs ([SERVICE.md](SERVICE.md)) as
the backstop. **This is the SQLite tier only.** On SQL Server / Postgres the engine creates no database
file and applies no ACL — permissions on `.mdf`/`.ldf`/tempdb/native backups are entirely the DBA's.
The `[store].uploads_dir` tier is weaker still: `uploads.py` uses `mkdir(0o700)` + `chmod(0o600)` under
a suppressed `OSError` and never calls the `icacls` enforcer, so **on Windows the uploads directory has
no engine-applied ACL at all**. The File-connector spill dirs likewise remain operator-owned — harden
all of these per [§10](#10-secure-deployment--operations-checklist).

**Key files `[BUILT]`.** A file that holds a key is not tightened after the fact. The engine
creates it restricted, in the call that creates it, and refuses to replace a file or link already at
that name. This covers the DPAPI store key file that `protect-key` writes and every TLS private key
the engine writes: the pair it mints for the API, `cert self-signed` and `cert import`. On POSIX the
file is created with mode `0600`. On Windows its access list names SYSTEM, Administrators and the
account that created it, plus read for the one account `protect-key --grant-account` names, and it
does not inherit from the directory. If the file cannot be created that way, the command fails and writes no file
([restricted_file.py](../messagefoundry/restricted_file.py)).

`serve` and `supervise` also check two of these files before they use them: the store key file,
when `[store].key_provider` loads it, and the TLS key the engine minted. If a broad group can read
or change the file, or its access cannot be read, the engine refuses to start under
`[security].enforcement = "enforce"` and warns under `"warn"`. Every other command that reads the
store key file, such as `provision-admin` and `rotate-key`, logs a warning and goes on.

**What this does not cover.** Know these before you rely on it:

- On Windows the check looks for known broad groups: at least Everyone, Authenticated Users, the
  local Users group and the logon classes such as INTERACTIVE. It is a list of known groups. It
  does not prove that only the accounts you meant can reach the file. `protect-key
  --grant-account` refuses the same list, and refuses a name that is a group or a domain.
- It does not vet the file's owner or an account you granted yourself. LOCAL SERVICE and NETWORK
  SERVICE are accounts that many services share, and the check does not report them.
- On POSIX the test is a group or other read or write bit, whoever is in the group. A volume that
  makes every file group-readable on each mount, such as a Kubernetes volume with `fsGroup`, lets
  the first start mint a key and makes every later start refuse it. Supply your own certificate
  there, as the shipped manifest does.
- The create has no warn mode. On a filesystem that cannot hold the restriction, such as a FAT
  volume or a mount that reports every file as mode `0777`, the engine cannot mint its TLS key and
  does not start, whatever `[security].enforcement` says. Put the store on a filesystem that holds
  permissions, or supply your own certificate.
- It does not look at an operator-supplied `[api].tls_key_file` or a connection's key file.
  Restrict those yourself.
- A key file is created for the account that creates it. `cert import` and `cert self-signed` have
  no grant option, so run them as the account that will read the key, or grant that account
  yourself. If an administrator runs `serve` by hand before the service first starts, the minted
  TLS key is readable by that administrator and not by the service account. Delete the pair and
  let the service mint its own.

**Git hygiene `[BUILT]`.** `.gitignore` excludes `*.db` / `-wal` / `-shm`, generated message corpora,
and logs, so runtime PHI is never committed. Keep it that way — never `git add -f` a database or a
real message file.

### The test harness's own at-rest data (`harness/`)

**`[MIXED]`** — the harness is a separately distributed wheel, and the owner ruling of 2026-10-02
put it inside the ASVS assessed scope. Its at-rest data is inventoried here, apart from the engine
table above, because the harness chooses where it lives, what protects it and how long it stays.
Most of it is ordinary files written with whatever mode the harness code chose. Two kinds are
databases: the engine stores the load rigs start, which hold the engine tiers above but which the
harness creates for a run and never removes, and the SQL Server tables the database scenarios
create. Each row is rated on the five-level scale above, at the level of the engine tier it
matches where there is one (the TLS private key has none and is rated PL-3 as an authentication
secret), and §3's per-level blocks list it. The census was taken from the code under `harness/` on 2026-10-03, and the rows below are
**at least** what the harness writes; a writer added later is not covered until it is added here.

**This table is the single statement of each harness store's facts.** §3, the threat matrix, §8,
§10 and §12 point here rather than restating them.

**Synthetic by default, and four stores are not.** Most harness commands generate their messages
(`messagefoundry.generators`), so on a developer box most bodies below are synthetic. Four take
whatever the operator feeds them: the reconcile capture and its compare report, which the
shadow-phase procedure runs against a migrating site's real outbound stream; the Corepoint export
that compare reads beside the capture; and the file drop, which the GUI's Compose tab feeds with
any text an operator pastes. On a deploying site that runs them against a real feed, those stores
**would hold PHI**. MessageFoundry has no production deployment today, so no harness file holds a
site's PHI now; the gaps below are defects in the shipped code, not live exposures.

**No harness store holds a password or a session token.** The rig Administrator's password lives
only in process environments (`harness/load/rigadmin.py` says so and writes no file), the `--token`
flag and the GUI's sign-in session are held in memory, and the SFTP share's and the database
scenarios' credentials are read from the environment. A rig engine's own store holds the rig
account's argon2id hash and hashed sessions, which are the engine's `users` / `sessions` tiers
above. The one harness-written secret is the TLS private key row below.

**Permissions, read once.** "Default mode" below means the file or directory was created by an
ordinary `open` / `write_text` / `write_bytes` / `mkdir` with no mode argument: the process umask
on POSIX (commonly `0644` for a file and `0755` for a directory) and the parent directory's
inherited ACL on Windows. `mkdtemp` makes a directory with mode `0700` on POSIX and, on Windows,
with the protected DACL Python writes for that mode, as the backup staging row above states; what
is created inside such a directory inherits that DACL on Windows. `mkstemp` makes a file with mode
`0600` on POSIX. No harness writer calls `restricted_file` or the engine's `icacls` enforcer.

**How the last column grades.** None of these stores has a cipher of its own, so a PL-1 or PL-3 row
is graded on the two controls the harness does or does not apply: access restricted to the account
that ran it, and a bound on how long the data stays. **Yes** means both, **Partly** one, **No**
neither. Whether the bodies are synthetic does not change the grade; it is stated in the Holds
column, because the same code would hold a real body on the paths an operator can feed. A PL-4 row
is graded against PL-4 instead, which asks for no cipher and accepts metadata kept indefinitely, so
it reads **Yes** when it holds metadata only.

| Harness store | Written by | Holds | Permissions as written | Retention | Protection level | Meets its level? |
|---|---|---|---|---|---|---|
| `reconcile capture --out` JSONL (`harness/reconcile/capture.py`, `CaptureSink`) | the reconcile capture subcommand | **Whole message bodies** — one JSON line per message an engine outbound delivered to the sink: `control_id`, the verbatim `raw` body, `received_at`. An unparseable delivery is captured too. Its docstring places it in the shadow phase, against the migrating site's real outbound stream | **Default mode**, for the file and the parent directory it creates. Opened in append mode, so a restart adds to it | **None** — never rotated, truncated or deleted by the harness. `compare` reads it and leaves it | **PL-1** | **No.** Default mode and no retention, over plaintext whole bodies. `CaptureSink` takes an `anonymizer` argument and fails closed when it raises, but the CLI passes none and has no flag for one, so the command line always writes raw bodies. The documented example path, `captures/<connection>.jsonl` relative to the working directory, is not matched by `.gitignore` (measured with `git check-ignore`), so a capture run from a checkout lands in an untracked, unignored file |
| `reconcile compare --report-json` (`harness/reconcile/report.py`, `render_json`) | the reconcile compare subcommand | **Body slices** — per mismatched pair, the match key (MSH-10 by default, any field under `--key`) and each difference's `left` / `right` values: a field value, or a whole verbatim segment for a segment present on one side only. Plus the key lists of unmatched and duplicate messages, which are MRNs under `--key PID-3`. `compare` also prints up to 20 mismatched messages' differences and up to 20 unmatched keys of each side to stdout on every run, report or not | **Default mode**, file and parent directory | **None** | **PL-1** | **No.** Default mode and no retention, over slices of the same real-feed messages as the capture. Its other input, the Corepoint export named by `--corepoint`, is written by the operator, not the harness, and is a PL-1 copy of its own; its documented example path, `exports/<connection>.hl7`, is not matched by `.gitignore` either |
| `MEFOR_BENCH_KEEP_NODE_LOGS` node logs (`harness/load/failover.py`, `EngineNode`; set per rung by the shardcert ladder's `--keep-logs-dir`, default `./shardcert-ladder-nodelogs`) | load rigs that start an engine node | The node engine's whole stdout and stderr: its application log, redacted as §7 describes and no further, over the rig's synthetic load corpus | **Kept mode:** `<dir>/<node_id>.log` at **default mode**, directory too. **Variable unset:** a `NamedTemporaryFile` in the OS temp dir, mode `0600` on POSIX | **Kept mode: none** — kept on purpose for post-run phase timing. Variable unset: unlinked at the node's `stop()`, so a harness crash or `SIGKILL` leaves it | **PL-1** | **No in kept mode**, where the engine's own log tier gets `[retention].app_log_days` and an installer ACL. **Partly** with the variable unset: restricted on POSIX, removed on a clean stop |
| `mefor-estate-*`, `mefor-connscale-*` and `mefor-ingress-probe-*` rig store dirs; the `--db` file of a SQLite multishard run; and a rig's server-DB store named by its `MEFOR_STORE_*` environment | the load rigs (estate, connscale, the ingress probe, multishard, failover, shardcert, the batch drive) | A whole engine store holding every tier in the engine table above for the run's synthetic traffic, plus, on a rig that signs in, the rig Administrator account | The temp dirs are made by `mkdtemp`, and the store file and its `-wal` / `-shm` get the engine's own SQLite `_secure_file` when the engine opens it. A `--db` path is wherever the operator names, and a server-DB store's permissions are the DBA's | **None after the run** — the harness never removes these dirs (connscale makes one per matrix cell) and never purges a server-DB store it drove. While a node runs, its engine's own retention settings apply | **PL-1** | **Partly** for a SQLite store: the file is restricted, but nothing bounds it. **No** for a server-DB store, which the harness neither restricts nor purges. No rig supplies a store key, so the bodies are plaintext in the file; a node started through `EngineNode` also defaults `MEFOR_SECURITY_ALLOW_UNENCRYPTED_PHI` to `true`, the audited escape that lets a keyless store start. While a rig runs, its engine serves the store over its API to whatever sign-in that rig configured |
| `dbo.mf_harness_inbox` / `dbo.mf_harness_outbox` (`harness/drivers/_database.py`) | the database scenarios (SQL Server only) | **Whole message bodies** in a `payload NVARCHAR(MAX)` column: the driver inserts each scenario message into the inbox, and the engine's DATABASE outbound writes its output into the outbox | The SQL Server's own grants, which are the DBA's; the harness applies none | **None** — the harness marks an inbox row `DONE` and never deletes a row from either table | **PL-1** | **No** — no harness control on access and no bound. Scenario bodies are generated |
| `mefor-harness-tls-*` dir (`harness/load/tlsmat.py`) | the load harness: every `EngineNode` start, and the engine poller when it reads a loopback `https` URL with no CA file named, so a load run against an engine the operator started mints one too | A self-signed API certificate and **its private key**, minted once per harness process and inherited by child harness processes through the environment | `mkdtemp` dir. The key file is written at default mode inside it and then `chmod 0600`, which sets the POSIX mode and changes nothing on Windows, where the file keeps the directory's DACL | **None** — never removed | **PL-3** | **Partly.** Restricted by its directory, but not created through `restricted_file` as the engine's key files are, and never deleted. It is a throwaway anchor for loopback rigs: disclosure lets a local reader impersonate a rig engine, not a deployed one |
| `harness-sftp-*` SFTP share root (`harness/sinks/_sftp_server.py`, `SftpShare`) | the remotefile scenarios | The bodies the engine's REMOTEFILE outbound delivers and the remotefile driver uploads, which are generated | `mkdtemp` root. Its two served directories are created at default mode inside it; a file a client creates is opened `0o600`, and a directory a client creates `0o700` | Removed by `SftpShare.stop()`, retried, then a WARNING naming the dir if it cannot be; a crash or `SIGKILL` leaves it | **PL-1** | **Partly.** Restricted by its root and removed on a clean stop; the crash residual is unbounded |
| `remotefile_known_hosts` file (default `./harness_io/remotefile/known_hosts`) | the SFTP share, on start | Public host keys pinned for the share's loopback address | Rewritten through `mkstemp`, keeping the previous file's mode; the first write gets `0600` on POSIX | **None** | **PL-4** | **Yes** — public keys, not secrets |
| Fuzz failing cases, `messagefoundry-harness-fuzz-*` or `--fuzz-out` (`harness/fuzz/campaign.py`) | the fuzz campaign | **Whole mutated message bodies**, one `.bin` per failing case, generated from the seed and iteration | The default dir is made by `mkdtemp`; each case file is written at **default mode**. A `--fuzz-out` dir is wherever the operator names | **None** | **PL-1** | **Partly** in the default dir, which restricts it; **No** under a `--fuzz-out` that does not |
| `drop_atomic` file drop dirs (`harness/drivers/file.py`, used by the scenario file driver and the GUI File tab) | the scenario file driver and the GUI | A whole message per file: a generated one, or the Compose tab's pasted text | Each file is created by `mkstemp` and hard-linked to its final name, so it keeps mode `0600` on POSIX; the dir is created at default mode | Consumed by the engine's File inbound, after which the engine's File-connector row above governs. A file no inbound polls stays indefinitely | **PL-1** | **Partly.** Restricted per file on POSIX, with no bound of its own |
| `pytest-of-<user>` basetemp dirs left by the acceptance runner's pytest child (`harness/acceptance/runner.py`) | the acceptance matrix | The backing test suites' temporary stores and synthetic messages | pytest's own: the parent dir is created mode `0700` | pytest keeps its most recent three runs by default | **PL-1** | **Yes** |
| `MEFOR_COORD_DIR` coord files (default `C:\mefor_coord`, `harness/load/coord.py`) | the two-box load rigs | `<run_id>.<name>.json` handshake messages: ports, shard ids, timestamps, counts and synthetic topology labels. The module's own rule is never a control id or a body | **Default mode**, file and directory; often a shared mount between two boxes | Cleared per message name when the next run with the same `run_id` starts; otherwise **none** | **PL-4** | **Yes** |
| `--report-json` / `--report-csv` / `--report-md` / `--report-compare` run reports, the acceptance `--xlsx` write-back and the `mefor-batch2box-*` per-process report dirs | the load, scenario, acceptance and batch commands | Counts, latencies, verdicts, ids and probe detail text; their writers state metadata only. **Except** the reconcile compare `--report-json`, which is PL-1 in its own row | **Default mode** (a batch report dir by `mkdtemp`) | **None** | **PL-4** | **Yes** |
| Qt `QSettings` (`harness/_console_widgets.py`) | the GUI | Table column layout | The platform's own settings store (the registry on Windows) | Kept until removed | **PL-4** | **Yes** — no message data |

Files the harness deletes in the same call are not listed: at least the acceptance runner's own
`TemporaryDirectory` and its `NamedTemporaryFile` write probe. The scenario sinks for the network
transports (MLLP, TCP, HTTP and the like under `harness/sinks/`) hold what they receive in memory;
the file sink reads a directory the engine writes, which is the engine's File-connector row, and
the database sink reads the scenario tables above.

### At-rest threat-coverage matrix

**`[MIXED]`** — which encryption layer covers which at-rest threat, per backend. The layers are
**distinct and complementary**: application-level **AEAD** (the `mfenc` column cipher, §3) protects
specific PHI columns *inside* the database engine; **whole-database / native encryption** — SQLCipher
for SQLite, **TDE** for SQL Server — protects the entire file/database including indexes and journals;
**FDE** (full-disk: BitLocker / LUKS) protects everything on the powered-off volume. They cover
different attackers, so the column below is "which threat does each layer answer," not a ranking.

| At-rest threat | App-level AEAD (`mfenc`, §3) | Whole-DB layer | FDE (BitLocker / LUKS) |
|---|---|---|---|
| Stolen powered-off disk / backup volume | Covers ciphered columns | Covers whole DB (incl. indexes, WAL) | **Covers everything** |
| Live file/backup copy from a running host | **Covers ciphered columns** (key not in the file) | Covers whole DB if its key isn't on the host | Does **not** help (volume is mounted/unlocked) |
| `summary`/`metadata` (MRN, patient name) | **Covered** (EF-3 — ciphered like `raw`) | Covered | Powered-off only |
| Plaintext residual columns (`control_id`, `message_type` — low-sensitivity routing/dedup keys) | **Not** covered (by design — these stay plaintext for indexing) | **Covered** | Powered-off only |
| Journals + version stores — SQLite `-wal`/`-shm`/temp; **SQL Server `.ldf` + tempdb version store**; Postgres `pg_wal` (**PL-5**) | Not covered (app cipher can't reach them) | **Covered** | Powered-off only |
| Test-harness stores ([harness table above](#the-test-harnesss-own-at-rest-data-harness)), at least the reconcile capture and its compare report | **Not covered. Known gap:** no harness file has a cipher, and the rig stores run with no store key | **Not covered** for the harness files, which are not a database, or for a rig's SQLite store, where no rig turns SQLCipher on. For a rig's server-DB store and the scenario tables it is the DBA's TDE, as for the engine's own server store | Powered-off only; a live copy reads them in the clear |

**Per-backend whole-DB layer.** SQLite = **SQLCipher** (the documented whole-DB alternative, §3) —
a native dependency that replaces the connect path. SQL Server = **TDE** (Transparent Data
Encryption), configured **at the database by a DBA**, *not* by MessageFoundry — it is the SQL Server
native whole-DB layer and is what covers the low-sensitivity plaintext columns (`control_id`/
`message_type`), indexes, the `.ldf` transaction log and the tempdb version store. Postgres = cluster
or filesystem-level encryption on the database host, likewise DBA-owned. (Do not conflate them:
SQLCipher is the SQLite layer; TDE is the SQL Server layer — there is no SQLCipher on SQL Server.)
**And note where the FDE has to live:** on a server backend the PL-5 surface is on the *database
host's* volumes, so BitLocker/LUKS on the **engine** host does not cover it. MessageFoundry's own
at-rest control is the app-level AEAD; the whole-DB and FDE layers are **deployment prerequisites**
(§3, §10) — and they are **unenforced prose**: there is no `[security].volume_encryption_declared`
setting at HEAD (only `memory_encryption_operator_declared` /
`require_memory_encryption_declaration`), so nothing in the engine checks that they are on.

---

## 3. Encryption at rest

**`[BUILT]` for message bodies; volume encryption for the remainder.**

**Layered: application-level AEAD through the store cipher, plus required volume encryption** — chosen
for defense-in-depth without swapping the `aiosqlite` connector.

1. **Application-level AES-256-GCM `[BUILT]`.** The store's `_cipher`
   ([store/crypto.py](../messagefoundry/store/crypto.py)) encrypts the cipher-covered columns.
   **[§2](#2-where-phi-lives--data-at-rest-inventory) is the normative list** — 18 `(table, column)`
   pairs on SQLite, 17 on SQL Server, 17 on Postgres, plus the two `uploaded_file` sidecar cells. The
   per-level blocks below group that same set; they do not redefine it, and CI pins the counts **and**
   the membership of both sections to the store's cipher registry, so they cannot diverge. Stored format
   `mfenc:v1 ‖ key_id ‖ base64(nonce ‖ ciphertext ‖ GCM tag)` — the GCM tag
   also satisfies the HIPAA *integrity* safeguard (tamper-evidence), and the prefix lets reads tell
   ciphertext from legacy plaintext (and from a retention-purged blank `''`, which is never ciphered).
   A one-time migration encrypts existing rows in place on first start with a key.
   **Crypto-agility (M9, additive — CRYPTO-1).** The cipher is **version/alg-dispatching**: it decodes
   `mfenc:v1:<key_id>:<b64>`, `mfenc:v2:<alg>:<key_id>:<b64>` and the current writer's
   `mfenc:v4:<alg>:<key_id>:<salt>:<b64>` (`alg` names the AEAD), and **fails closed** (`CipherError`)
   on an unknown marker version or an unknown/unsupported `alg` — never a silent pass-through or mis-decrypt. **AES-256-GCM is the only
   algorithm registered in the in-process cipher** and the **v1 writer is frozen byte-identical** (a
   frozen-fixture test pins it). The store's find-all/migration scans anchor on the
   version-agnostic `mfenc:` prefix (so every version is recognised as already-encrypted), and the
   rotation scan anchors on the cipher's active-format prefix through the key fingerprint and, for v4,
   the store salt (so a v4-active rotation matches its own rows and terminates).
   **Cell binding — `[store].aad_bind`, default ON (ASVS 11.3.3, ADR 0019 as amended by ADR 0148
   GIVEN 1).** Every store write site passes `cell_aad(table, column, *pk)` (the tuples are documented
   per row in §2), and on the shipped default new writes are **`mfenc:v4` with the cell AAD bound**
   (`mfenc:v2` before ADR 0196; the AAD is the same, and v2 values still read): a
   ciphertext cut-and-pasted from one cell into another fails the GCM tag (dead-lettered, never silently
   accepted). Setting `aad_bind = false` selects the **frozen `mfenc:v1` writer, which passes no
   associated data — the AAD is then computed and ignored, and at-rest values are NOT cell-bound**; that
   is a declared loosening, named by `security_loosenings()`. Legacy `v1` rows stay readable (dual-read)
   and **`messagefoundry rotate-key` upgrades them v1 to v4**, so the default is safe on an existing store
   and reversible. `aad_bind` has no effect without an encryption key (the identity cipher has nothing
   to bind).
   **Each store seals under its own data key (ASVS 11.3.4, [ADR 0196](adr/0196-a-fresh-or-rewound-store-must-not-restart-a-store-key-s-aes-gcm-invocation-count.md),
   BACKLOG #2070).** The cell-bound writer does not seal under the DEK itself. It seals under
   `HKDF-SHA256(DEK, info = "mefor/store-data-key/v1" || salt)`, where `salt` is 16 random bytes the store
   mints on its first keyed open (the one-row `store_salt` table) and `messagefoundry restore` replaces.
   The AES-GCM invocation bound (`cipher_meta`) counts that sub-key. So a store that is deleted and
   recreated, wiped, pointed at an empty server database, or restored from an archive is a new key, and
   its count starting at zero is true rather than a reset of a used key. Every `mfenc:v4` value names its
   salt, so an upload, a moved-aside store or a restored one opens with the DEK alone, and losing the
   salt row strands nothing. `.mfbak` archives (format version 2) are sealed under the same sub-key and
   record its salt in their header. **At least these limits remain.** A store copied or rolled back
   outside the engine (a file copy, a VM snapshot, a DBA restore of a server database, a staging copy
   given the production key) keeps its salt and its row, so its count can still read low; ADR 0196
   accepts that. And `aad_bind = false` keeps the frozen v1 writer, which has no salt field and seals
   under the DEK, so the old reset stays open on that setting.
   **An unmarked value is refused — `[store].allow_unmarked_ciphertext`, default OFF (ASVS 11.3.3,
   BACKLOG #1169).** A keyed store reads a cipher column only as `mfenc:` ciphertext. A non-blank value
   with no marker is refused with a `CipherError` and raises an `integrity_drift` alert under the
   `store-cipher` subject, which names the table and column and never the row or the value. It is a
   stripped marker or a planted row: cell binding catches a moved ciphertext because it has a tag to
   fail, and a downgrade to plaintext has no tag, so only this refusal protects it. A purged `''` is
   never refused. The keyed open still seals legacy plaintext, one `(table, column)` surface at a time,
   but only while that surface holds no ciphertext yet; each surface seals in one transaction, so a
   crash leaves it all sealed or all unsealed. Setting the switch `true` restores the old behaviour
   (unmarked values read back as plaintext, and the open seals every one) and is a declared loosening.
   **At least these limits remain.** The DIRECT S/MIME enveloped body is not covered. And the
   "sealed" evidence is the surface's own ciphertext, so a surface that holds none at the moment of a
   keyed open is treated as unsealed and a row planted into it is sealed as legacy data. That covers a
   table that can legally empty out (`queue.payload`, `state`, `alert_instance`) and any column that
   has not been written yet (`users.totp_secret` before the first MFA enrolment, for example). A planted
   row read before that open is still refused. Also note that a planted `state` or `reference` value
   on a sealed surface stops the store from opening, since the open reads those tables eagerly. `serve`
   arms the alert before the open, so that refusal alerts too, and so does a planted row the open
   finds and leaves in place. The retention document-strip pass skips a refused row and carries on.
   **A plaintext upload is refused until `rotate-key` seals it (owner ruling 2026-09-23, BACKLOG
   #1169).** The uploaded-file store under `[store].uploads_dir` shares the store's cipher. When a site
   first enables a key, the uploads it already holds are plaintext files. On a keyed AES-GCM store each
   one is refused on every read, and raises an `integrity_drift` alert
   under its own `upload-cipher` subject, naming only the `uploaded_file` surface and never a file. The
   subject is separate from `store-cipher` so that expected upload refusals cannot throttle or mute a
   planted store row. A refused upload drops out of the listing. A by-id route answers **HTTP 423**
   with the fix to a holder of `files:access_any`, and the same 404 as an absent id to everyone else,
   because the owner cannot be read to check ownership. To bring it back, stop the engine and run `messagefoundry rotate-key`, which seals it under the active key and
   prints how many plaintext uploads it sealed. The engine never seals them at startup, because a
   whole-directory crypto pass is unbounded boot-time work. Instead `serve` logs one WARNING at
   startup with the **count** of plaintext uploads and that instruction, and never a filename. This is
   fail-closed, like `[backup].allow_unencrypted`, which ships `false`.
   `[store].allow_unmarked_ciphertext = true` restores the upload passthrough too. **At least these
   upload limits remain.** `rotate-key` seals every plaintext upload it finds, a planted one included,
   because new sealed uploads sit beside legacy ones and this surface has no "already sealed" evidence
   to tell them apart. The refusal before it, its alert, and the startup count the operator checks
   against the sealed count are the controls. **Until it is sealed, a refused upload is also outside
   the retention prune and the per-uploader quota, and cannot be deleted through the API**, because
   each of those must read its metadata first. They refuse it on purpose: a plaintext sidecar is not
   bound to its path, so trusting it would let a planted one name another upload for the prune to
   delete, lift a quota with a negative size, or fail every save. `rotate-key` stamps the key's rotation date only when the key
   actually changed, so running it with the same key to seal uploads does not reset the key-age
   clock.
   **Under `cipher_provider = "vault_transit"` a plaintext upload still reads back as plaintext.**
   `rotate-key` refuses to run in that mode: it needs a local active key, and the store's own
   rotation raises there (BACKLOG #1165). So no command could ever seal the upload, and refusing it
   would strand the file for good. The transit cipher still refuses unmarked values in the store's own
   columns.
   **A third at-rest tier ships — `[store].cipher_provider = "vault_transit"` (`mfenc:v3`, ADR 0138).**
   This does not merely source the key: it **replaces the cipher object**
   ([store/crypto_transit.py](../messagefoundry/store/crypto_transit.py)), so every encrypt/decrypt runs
   **inside Vault/OpenBao Transit** and the data key never enters engine heap. Values carry a third
   marker, `mfenc:v3:` + Transit's own `vault:v1:` ciphertext; the cell AAD is forwarded as Transit's
   `associated_data`, so **`v3` is cell-bound regardless of `aad_bind`**; and the audit-chain MAC is
   computed inside Transit. Missing config or an unreachable/unknown Transit key **fails closed** at
   `open_store` (`serve` refuses to start) — never an in-process fallback. Caveat worth knowing: the
   Transit-backed audit MAC reaches **all three** backends (`audit_mac_fn`). This bullet previously said SQLite-only — that
   was the PRE-#301 state stated as current, and it was wrong in the direction that flatters nothing:
   `TransitCipher.audit_mac_key()` returns `None` **by design**, so a server backend given only
   `audit_mac_key` had no keying secret at all. #301 threads `audit_mac_fn` alongside it, which is
   what closed it: `open_store` in `store/base.py` hands both to `_open_backend`, and that function
   forwards both to each backend's `open`. This claim is a row in the backend-reach registry in
   `tests/test_phi_at_rest_inventory.py`. The test reads the path from the code: `_open_backend` must
   pass `audit_mac_fn` to each backend's `open`, that `open` must pass it to the constructor, and the
   constructor must store it as `self._audit_mac_fn`. It does not check that `open_store` passes a real
   function rather than `None`, nor that the audit append path reads the attribute. **So it binds only
   that the MAC is delivered to every backend.** What the GCM tag and the cell AAD protect, and what the
   audit MAC detects, are per-column and audit-chain integrity claims. The registry cannot express them,
   so it leaves them unbound. `docs/ASVS-L2-PHASE0-CHANGES.md`
   §"Audit chain" carries the accurate wording — the digest primitive is *"shared verbatim by all three
   backends"*. **What IS unkeyed is the KEYLESS posture, not a backend:** with no store key,
   `IdentityCipher.audit_mac_key()` in `store/crypto.py` returns `None` and the chain stays keyless
   SHA-256 — tamper-evident against a careless edit, not forgery-resistant against anyone who can write
   the table. That is not the shipped default, which refuses to `serve` without a store key (item 2
   below). A key alone still does not key a chain whose first row was written keyless; the
   `docs/ASVS-L2-PHASE0-CHANGES.md` §"Audit chain" row says when the chain is keyed.
2. **Key management + rotation `[BUILT]`.** The key is a base64 32-byte secret from the **environment**
   (`MEFOR_STORE_ENCRYPTION_KEY`), never the TOML file — reusing the existing secrets convention
   (cf. `MEFOR_STORE_PASSWORD`). Mint one with `messagefoundry gen-key`. On Windows it may instead live
   in a **DPAPI-protected key file** (WP-11d, ASVS 13.3.1) — `messagefoundry protect-key` writes a
   machine-bound ciphertext that `[store].encryption_key_file` is `CryptUnprotectData`'d from at
   startup, so no plaintext key sits in the service environment (see [SERVICE.md](SERVICE.md)
   §"Protect the store encryption key at rest"). With no key set, values are
   stored as-is (backward compatible). The cipher is a **keyring** (WP-5, ASVS 11.2.2): the embedded
   `key_id` is a SHA-256 fingerprint of the key, so it self-identifies; it encrypts with the **active**
   key and decrypts with whichever configured key matches (active + any decrypt-only keys in
   `MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`). **Rotation** = set the new active key, keep the prior key in
   `…_RETIRED`, run **`messagefoundry rotate-key`** (offline) to re-encrypt every value under the new
   key, then drop the retired key. `rotate-key` also opens a new range of the audit chain under the new
   key and verifies the chain first; do not drop the retired key until it has printed its audit line
   without an error ([ADR 0193](adr/0193-audit-chain-key-ranges-survive-a-store-key-rotation.md),
   BACKLOG #1904). The same command re-seals the uploaded-file store, and on a first key-enable it
   seals the plaintext uploads a keyed store refuses until then (BACKLOG #1169). An undecryptable
   value (corrupt blob / missing key) is contained —
   the row is dead-lettered, never crashes a worker.
   **The key-age clock restarts with a new store, and under ENFORCE that clears the expiry refusal
   (BACKLOG #1004, ADR 0196).** The DEK's age is stamped in the store's own `secret_rotation_meta`, as
   `tracked_since` and `last_rotated`. A store with no stamp gets today's date, which is a floor, not
   the key's true age. So recreating the store under the same DEK restarts the clock. So does
   restoring an archive taken before the last rotation: the archive's stamp names the old DEK, and the
   changed fingerprint reads as a rotation today. Under `[security].enforcement = ENFORCE`, either one
   clears the `store_key_max_age_days` refusal for a DEK that is really past it. ADR 0196 accepts this
   rather than refusing every fresh store. **To keep the true age, set
   `[secret_rotation].store_key_last_rotated`** to the date the DEK was made, and keep it through a
   recreate or a restore; the engine uses that date instead of its own stamp. The age is always keyed
   on the DEK's fingerprint, never on a store's derived key.
   **Fail-closed (secure-by-default; H3, OWASP *Fail Securely* / SDS §4.3 PW.9):** `serve` **refuses to
   start with no key on ANY instance** — the refusal is gated on **neither** a data class **nor** the
   environment label, so a custom-named dev/test box holding near-real PHI fails closed
   exactly like `prod`/`staging` (closing the EF-3 perception gap where non-prod only warned). Since
   [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 1) **all
   three built-in envs (`dev`/`staging`/`prod`) derive PHI**, so the default/CI path is key-required too — a
   key is required on **every** instance: [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md) retired the synthetic declaration, so no
   box can opt out of this gate as a class. Two further explicit overrides:
   `[store].require_encryption = true` forces the refusal past the audited opt-out below; `[security].allow_unencrypted_phi = true` is the loud, **audited** opt-out that
   lets a PHI instance start keyless anyway (it still emits the UNENCRYPTED-at-rest warning, and
   `require_encryption` wins over it) — and under **strict enforcement** (`[security].enforcement = enforce`,
   the default) keyless PHI additionally requires the second ack
   `[security].allow_unencrypted_phi_under_strict_enforcement = true` ([ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) / ADR 0148). The effective posture (encryption on/off, key **source**, key **fingerprint**,
   per-backend column coverage) is surfaced at the authenticated, `MONITORING_READ`-gated
   **`GET /security/posture`** route (M5) — never key bytes; every access is audited. The view carried a
   `data_class` field until ADR 0186 removed it with the declaration behind it.
3. **Pluggable key sourcing — the KeyProvider seam `[BUILT]` (ASVS 13.3.3; ADR 0019 amended 2026-06-18,
   PR #377).** Where the DEK *comes from* is now routed through a pluggable **KeyProvider** seam
   ([store/keyprovider.py](../messagefoundry/store/keyprovider.py)) selected by the `[store].key_provider`
   setting — built-in `auto`/`env`/`dpapi` (the default `auto` is **byte-identical** to the prior
   env-then-DPAPI ladder above) plus lazy `aws_kms`/`azure_kv`/`gcp_kms`/`vault`/`pkcs11` hooks that
   **envelope-decrypt** a wrapped DEK inside an **isolated security module** (HSM/KMS/Vault). The seam
   changes only *how* the key bytes are provisioned, never how they are used — the AES-256-GCM keyring,
   the `mfenc:v1` format, and `rotate-key` are unchanged. Selecting an unbuilt/unknown provider **fails
   closed** (`KeyProviderError` → `serve` won't start), never silently to the identity (plaintext) cipher.
   An operator **activates** an external module so the root **KEK** is managed **non-extractable** inside
   it (centralized rotation/revocation/per-call audit; the key bytes no longer sit in an env var or a
   machine-bound file). On the strength of this built seam + an operator-activated external module **ASVS
   13.3.3 is Pass *(conditional, operator-activated)*** — the same operator-activated shape as off-box
   logging (16.4.3) and transport TLS. **Residual:** on-prem `auto` (env/DPAPI) is the **managed residual**
   — in-process software crypto until a provider is activated; and even with a provider the unwrapped DEK
   lives in process heap during bulk AES-256-GCM, the separately-deferred **ASVS 11.7.1 / WP-BL3-28**
   residual (see the in-use limitation below). The cloud/HSM SDKs are optional extras — the base install
   pulls **zero** of them; external providers land per-provider in follow-on PRs.
4. **Required volume / whole-DB encryption (the PL-5 tier).** App-level AEAD **cannot** encrypt the
   PL-5 substrate or the plaintext `messages.control_id`/`messages.message_type` columns. **Where the
   cover has to live depends on the backend:**
   - **SQLite** — the `-wal`/`-shm`/temp files and the indexes: **BitLocker (Windows) / LUKS (Linux) on
     the engine host's data volume**, optionally SQLCipher for a whole-DB layer.
   - **SQL Server** — the `.ldf` transaction log, the **tempdb version store** (which the engine itself
     makes load-bearing by force-enabling `READ_COMMITTED_SNAPSHOT` / `ALLOW_SNAPSHOT_ISOLATION` at
     open), the indexes and the native backups: **SQL Server TDE at the database, plus FDE on the *SQL
     Server host's* volumes.** BitLocker on the engine host covers **none** of this.
   - **PostgreSQL** — `pg_wal`, the base files and the indexes: cluster/filesystem encryption on the
     **database host**.

   App-level + this layer together close both the "stolen file from a powered-off host" and the
   "live-host file copy" cases. **Honest status: this is a prerequisite in prose only.** There is no
   `[security].volume_encryption_declared` setting at HEAD, so the engine neither verifies nor requires
   a declaration that it is on — unlike the memory-encryption declaration
   (`[security].memory_encryption_operator_declared`), which does exist.

**Accepted residual:** `control_id` and `message_type` (MSH-10/MSH-9, low-sensitivity) stay plaintext
in the DB for dedup/routing/indexing; volume encryption is what protects them at rest. (`summary` and
`metadata` — the direct MRN/patient-name identifiers — are **no longer** in this residual: EF-3 routes
them through the store cipher like `raw`, since nothing SQL-searches `summary`.) If even that residual
is unacceptable, **SQLCipher** (whole-DB, including WAL) is the documented alternative — at the cost of
a native dependency and replacing the connect path.

**SQL Server backend:** `encrypt = true` secures the DB *connection* (TLS in transit),
**not** data at rest — at-rest there means SQL Server TDE, configured at the database, not by
MessageFoundry. TDE plus FDE on the SQL Server host's volumes is what covers the **PL-5** tier there
(the `.ldf` log, the tempdb version store the engine's own `READ_COMMITTED_SNAPSHOT` setting fills,
the indexes, and native `BACKUP DATABASE` output).

### Protection requirements per protection level (ASVS 14.1.2)

Each level from the [§2](#2-where-phi-lives--data-at-rest-inventory) inventory, with its **encryption,
integrity, retention, confidentiality/access and destruction** requirements. Every requirement below is
a statement about *what is built today*; where a control does not exist, it says so.

#### PL-1 · PHI body

**Applies to:** `messages.raw` · `queue.payload` · `shared_body.body` · `attachment_chunk.ciphertext` ·
`response.body` · `[store].uploads_dir` blobs
(`uploaded_file.body` / `uploaded_file.meta`) · `.mfbak` archives (SQLite) · `mefor-backup-*` /
`mefor-verify-*` staging dirs (a SQLite store's data dir, or `.mefor-staging` under the backup
destination, or for a standalone verify a private dir under the OS temp dir) · `mefor-restore-*` staging dirs (the
**destination** volume) · File-connector spill dirs · application log files (`[logging].log_dir`) ·
the off-box forwarder spool (`[logging].forward_spool_dir`) · and, from the
[test harness table](#the-test-harnesss-own-at-rest-data-harness), the `reconcile capture --out`
JSONL · the `reconcile compare --report-json` report · `MEFOR_BENCH_KEEP_NODE_LOGS` node logs · the
`mefor-estate-*` / `mefor-connscale-*` / `mefor-ingress-probe-*`, `--db` and server-DB rig stores ·
the `dbo.mf_harness_inbox` / `dbo.mf_harness_outbox` scenario tables · the `harness-sftp-*` share ·
`messagefoundry-harness-fuzz-*` cases · the `drop_atomic` file drops · `pytest-of-<user>` basetemp
dirs.

**The bullets below describe the engine's tiers. The harness tiers in that list get none of them
once a run ends**; a rig store gets the engine's access and retention controls only while its node
is running.
The level's requirement still applies to them: a body is encrypted at rest or kept on an encrypted,
restricted volume, read only by those entitled to it, and bounded in time. The harness table says
per tier which of those its code provides, and an operator carries the rest
([§10](#10-secure-deployment--operations-checklist)).

- **Encryption**, stated per tier rather than as one blanket rule:
  - *Database cells and the `[store].uploads_dir` sidecars* — the store cipher (AES-256-GCM, or
    Transit under `vault_transit`) with the per-cell AAD in §2, keyed by the store DEK — **bound on the
    shipped default (`[store].aad_bind = true` to `mfenc:v4`, `mfenc:v2` before ADR 0196) and unconditionally under
    `cipher_provider = "vault_transit"` (`mfenc:v3`); an operator who sets `aad_bind = false` selects the
    frozen `mfenc:v1` writer, and the AAD is then computed and ignored.**
  - *`.mfbak` archives* — **a separate streaming codec, NOT the store cipher**
    ([store/backup_codec.py](../messagefoundry/store/backup_codec.py), whose own docstring says the
    cipher *mechanism* is net-new): chunked AES-256-GCM under the store DEK resolved directly by
    `resolve_active_key`, with a per-chunk AAD of
    `header_sha256 ‖ frame_counter(uint64) ‖ final_flag(uint8)` — **not** a per-cell AAD. The archive's
    own seal is keyed by `resolve_active_key` and not `build_store_cipher`, so `cipher_provider =
    vault_transit` **never applies to sealing or unsealing a `.mfbak`**. It DOES apply one frame
    further in, and the distinction is the archive versus the cells inside it: `full_restore_verify`
    opens the extracted snapshot's cipher-covered cells through the **store** cipher
    (`build_store_cipher`, ADR 0049 AC-13) — the same cipher that wrote them — so under `vault_transit`
    that read runs in Transit exactly as a live cell read would. Two paths unseal an archive, and only
    one of them crosses that frame: the `restore` subcommand (ADR 0049, BACKLOG #1717) unseals with a
    raw DEK selected by the archive header's `key_id` from `resolve_decrypt_keys` — the active key **plus
    retired ones**, so an archive sealed before a rotation still restores (AC-5) — and then **stops at
    the seal**. It checks the extracted snapshot with
    `PRAGMA integrity_check` and a row count over a plain read-only `sqlite3` connection, decrypts no
    cell, and places the file. So a restore needs no store cipher at all, and under `vault_transit` it
    makes no Transit call; a full restore-verify is the only one of the two that does.
    And `[backup].allow_unencrypted = true`
    writes a **CLEARTEXT `.mfbak.plain`** — a plaintext PHI-body archive on disk.
  - *File-connector spill dirs* — **plaintext on disk**; there is no cipher on that path, only
    volume/share encryption and the directory ACL.
- **Integrity.** The per-value GCM tag is the tamper-evidence. For `attachment_chunk.ciphertext` each
  chunk carries its own tag and the attachment's `id` is the SHA-256 of the **verbatim plaintext**, so a
  re-seal (rotation) never changes the content address. `shared_body.body` is likewise addressed by the
  plaintext hash.
- **Confidentiality / access.** `messages.raw` is read through the audited
  `GET /messages/{id}/raw` path under `messages:view_raw` + `require_phi_read` (the PHI-read hop guard +
  per-actor pacing) + per-channel scope. That route writes a `record_view` and a `message_body_view`
  audit row naming the `surface` that asked. Opening a message, `GET /messages/{id}`, returns its
  metadata and no body, and writes `message_view` (BACKLOG #2345). The open returns `summary` and
  `metadata` masked, as the list does, unless the caller passes `reveal_summary=true`; the
  `message_view` row lists in `revealed` the properties it returned complete (BACKLOG #2346). The
  error text (`error`, each delivery's `last_error`, each event's `detail`) comes back as a fixed
  `****` mask unless the caller passes `reveal_errors=true`, a separate act (BACKLOG #2436); the
  scrubber that cleans that text is not de-identification. The message list and search mask
  `error`, and `GET /dead-letters` masks `last_error`, the same way, with no reveal of their own. A detached document is the **same PHI**, so
  `GET /messages/{message_id}/attachments/{attachment_id}` rides the *same* `messages:view_raw` gate and
  channel scope, **plus a `message_attachment` linkage check** — a guessed content address that is not
  linked to an in-scope message is a 404 — and writes a `record_view` **and** an `attachment_download`
  audit row **before** any byte leaves. `response.body` is exposed by `GET /messages/{id}/responses`
  only when the caller *also* holds `messages:view_raw` and `messages:view_summary` (vault BACKLOG
  #1187). `shared_body.body` has **no direct read API**
  (reachable only via the delivery deref and the resend source read). Uploaded-log blobs are `files:*`
  gated, step-up + PHI-hop-guarded on browse, and audited (metadata only).
  **Bulk egress is a separate, stronger gate:** `GET /messages/export` streams many raw bodies at
  once and requires a **fresh step-up over BOTH** `messages:export` **and** `messages:view_raw`,
  applies `enforce_phi_read_hop` and per-actor pacing explicitly, re-checks per-channel scope per
  id, and writes **one** `messages_export` audit row (actor, selection mode, filters, needle
  *shape*, body count) **before** streaming — the code calls it the largest PHI surface in the
  cluster. The transformed outbound payload (`queue.payload`, stage `outbound`) is read by its own
  route, `GET /messages/{message_id}/outbound`, under `messages:view_raw` + `messages:view_summary`
  + `require_phi_read` (the second since vault BACKLOG #1187), audited `outbound.read` — not by
  `GET /messages/{id}/raw`.
- **Retention / destruction.** `messages.raw` is blanked in place by `purge_message_bodies`;
  `queue.payload` is blanked for done/cancelled outbound rows in the same transaction, and for dead rows
  at **every** stage by `purge_dead_letters`; `response.body` is set to `NULL` in place by the same pass;
  `shared_body.body` is refcount-decremented and GC'd at 0 when its **last** referrer is purged;
  streaming attachments are decref'd + GC'd at 0 (plus a startup `sweep_orphan_attachments`).
  The legacy SQL Server `outbox.payload` no longer exists to be purged — its rows were folded into
  `queue` and the table DROPped ([§2](#2-where-phi-lives--data-at-rest-inventory)), so they now ride the
  same window as any other outbound row. `[store].uploads_dir` blobs auto-prune
  after `[store].uploads_retention_days` (default **30**) via an age-based sweep — a periodic
  `UploadRetentionRunner` plus an opportunistic pass at save time, a pruned pair audited `upload.prune`
  with the gaps stated in [§2](#2-where-phi-lives--data-at-rest-inventory) (ASVS 5.2.4, #291); an operator `DELETE` is an additional removal path. **`.mfbak` archives** are bounded
  by **keep-N** (`[backup].retention_keep`, `0` = keep all): the `BackupRunner` prunes older archives at
  the destination and nothing else expires them — there is no age window. **One archive is deliberately
  outside that bound:** a backup that fails its restore-verify keeps a `.failed` suffix instead of the
  canonical archive name, which is what stops it spending a retention slot and evicting a good copy — so the
  keep-N glob cannot match it either, **no engine path expires it**, and an operator clears it (ADR 0049,
  BACKLOG #1587). It is sealed under the store DEK exactly like a good archive, so the at-rest protection is
  identical and only the retention bound differs. **File-connector output /
  spill dirs have no engine-managed retention or destruction at all** — the File transport writes
  `.hl7`/`.processed`/`.error` files and an operator or infra job is the only removal path. Application
  log files are age-deleted by `[retention].app_log_days` (by **mtime**; content is never inspected)
  and, optionally, gzipped in place first by `[retention].app_log_compress_days` — the compressor reads a
  file's bytes to archive and verify them **in-process, never logged or exported**, leaves the archive on
  the same ACL'd volume, and inherits the source's mtime so the delete window still applies. The
  off-box forwarder spool is bounded by **size**, `[logging].forward_spool_max_bytes`, and a segment
  is deleted once every entry in it has been sent (BACKLOG #1966, ADR 0200).
  Full per-backend detail: [§8](#8-retention--purge).
- **Logging.** Bodies, detached-document bytes and base64 payloads are **never** logged at INFO or
  above and never appear in an exception line — the `safe_exc()` / `safe_text()` chokepoints and the
  never-log-bodies rule are the enforcement. Application log files are themselves a PL-1 tier (see the
  §2 row): the redaction is best-effort, so a single-token identifier can survive it. Full inventory:
  [§7](#7-logging--phi-redaction).

#### PL-2 · PHI identifier / free-text fragment

**Applies to:** `messages.summary` · `messages.metadata` · `messages.error` · `queue.last_error` ·
`message_events.detail` · `response.detail` · `response.resp_headers` · `state.value` ·
`reference.value` · `search_presets.criteria` · `connection_event.reason` · `alert_instance.reason`.

| Tier | Redaction before the cipher | Who may read it, and how | Retention today |
|---|---|---|---|
| `messages.summary` | none (composed from parsed fields) | `messages:view_summary` via the field-level `redact_unauthorized` gate; summary displays are audited | nulled by `purge_message_bodies` |
| `messages.metadata` | none | `messages:view_summary` (same gate) | **`[retention].messages_days`** — nulled by `purge_message_bodies` in the same statement as the body, on every backend ([§8](#8-retention--purge)) |
| `messages.error`, `queue.last_error` | `safe_exc()` chokepoint | `messages:view_summary`; a holder gets a fixed `****` mask on at least the message open, the message list and search, and the dead-letter list, until the per-message `reveal_errors` act on `GET /messages/{id}` (`messages:view_raw`), which the `message_view` audit row records (BACKLOG #2436) | nulled by `purge_message_bodies` / `purge_dead_letters` |
| `message_events.detail` | `safe_text()` | `GET /messages/{id}` (`messages:view_raw` + `require_phi_read`); the read itself writes a `viewed` event and a `message_view` audit row. `EventInfo.detail` is **additionally** nulled by `redact_unauthorized` for a caller lacking `messages:view_summary`, so a view_raw-without-view_summary role cannot read it; a holder gets it as a fixed `****` mask for every event kind until the `reveal_errors` act (BACKLOG #2436) | set to `NULL` by `purge_message_bodies` (inherits the body window) |
| `response.detail` | `safe_text()`, 200-char bound | `GET /messages/{id}/responses` under `messages:read` + `require_phi_read`; nulled by `redact_unauthorized` for a caller lacking `messages:view_summary`; every read writes a `response.read` audit row | set to `NULL` in place by `purge_message_bodies` |
| `response.resp_headers` | `safe_text()` | **no API surface** — it is not a field of `CapturedResponseInfo` and is never returned by `GET /messages/{id}/responses`; reachable only from a Handler via `response_get(destination)` (ADR 0013/0084) | set to `NULL` in place by `purge_message_bodies` |
| `state.value` | none (Handler-authored JSON) | **no read API** — Handler-only via `state_get` | age purge on `[retention].state_max_age_days` (DELETE) |
| `reference.value` | none | **no read API** — Handler-only via `reference()` | **none** — a snapshot is replaced only by the next sync's build-new-then-flip |
| `search_presets.criteria` | none (the operator's own needle) | **never returned by the API.** `GET /search/presets` returns names + timestamps only; create is `require_step_up(messages:read)` and audits the needle *shape* only; the needle is loaded **server-side** by `GET /search/layered` and never round-trips. Owner-scoped on every read | **`[retention].search_preset_days`** on every backend — whole-row `DELETE` by last-**used** (the later of `updated_at` and `last_used_at`, #306); `0` = keep forever (the default), so an owner `DELETE` remains the only removal until a window is set |
| `connection_event.reason` | `safe_exc()` at the source **and** `safe_text(…)[:200]` at the store | `GET /events` / `GET /connections/{name}/events` under **`monitoring:read`**, which is **not** a PHI permission. So `ConnectionEventInfo.reason` is gated separately on `messages:view_summary` (BACKLOG #2443, owner ruling R12): a caller without it gets `null`, and a holder gets a fixed `****` mask for every event kind until the per-event `reveal=<id>` act on either route. That act needs `messages:view_summary`, charges the PHI-read budget, and writes a `connection_event_reveal` audit row. The kind, connection, direction, peer and time stay readable under `monitoring:read` | age DELETE on `[retention].connection_event_retention_hours`, else inherits `[retention].messages_days` |
| `alert_instance.reason` | `safe_text(…)[:200]` | `GET /alerts/active` under **`monitoring:diagnose`**, again not a PHI permission. `AlertInstanceInfo.reason` is gated and masked the same way (BACKLOG #2443), including on the ack, resolve, suspend and resume replies, until the per-alert `reveal=<id>` act on `GET /alerts/active`, audited as `alert_reveal`. The alert's type, state and window stay readable | same window, **RESOLVED instances only** — an open or acknowledged alert is never aged out |

- **Encryption + integrity** for every row above: store cipher + per-value GCM tag, with the cell AAD in
  §2 (bound on the shipped `aad_bind = true` default and under `vault_transit`; unbound only where an
  operator has set `aad_bind = false`).
- **Privacy note.** The two `reason` columns are the one place where a *sensitive* free-text field is
  readable under a **monitoring-tier** permission rather than a PHI-tier one. That is why they are
  scrubbed **twice** before the cipher and bounded to 200 characters, and why the tables are documented
  **metadata-only** — a frame, body or HL7 field value must never be written to either.
- **Logging.** Every tier above passes a `safe_exc()` / `safe_text()` chokepoint **before** it is
  logged or stored, and the two `reason` columns are additionally bounded to 200 characters, so what
  reaches the rotating log is the same scrubbed value the store holds — never a body.
  [§7](#7-logging--phi-redaction).

#### PL-3 · Authentication secret

**Applies to:** `users.totp_secret` · and the test harness's TLS private key in its
`mefor-harness-tls-*` dir.

**Everything below this line is about `users.totp_secret` and none of it holds for the harness
key**, which is a plaintext PEM file with no cipher and no retention. Its handling is in the
[harness table](#the-test-harnesss-own-at-rest-data-harness).

Encrypted with the store cipher (AAD `("users","totp_secret",id)`); integrity from the GCM tag.

**Access.** The staged secret is returned **exactly once, to its own owner**, by `POST /me/mfa/enroll`
(`MfaEnrollResponse.secret`, plus the `otpauth://` QR URI that embeds the same base32 value) — behind a
fresh **password** step-up bound to that action (ADR 0077,
`require_reauth_only_action(STEP_UP_ACTION_MFA_ENROLL)`) and audited `auth.mfa_enroll_started`. That
reply is served `Cache-Control: no-store`. The web console's `POST /ui/account/mfa/enroll` calls the
same handler and renders the seed once into a `/ui` page, which is `no-store` too. It is
**never returned again**: no read route, no admin route, and the server-side TOTP verifier is the only
other consumer. **Logging:** never logged at any level.

No retention window: it lives and dies with the user row. Its siblings `users.password_hash` and
`users.totp_recovery_codes` are **argon2id one-way hashes** and are deliberately *not* ciphered — there
is no plaintext to protect.

#### PL-4 · Operational metadata (non-PHI)

**Applies to:** `audit_log.detail` · `audit_log.client` · `sessions.token_hash` / `client` · `processed_files` ·
`pending_approvals.params` · `delivered_keys` · `resend_log` · `queue.handler_name` / `destination_name` /
`channel_id` · `messages.control_id` / `message_type` · `webauthn_credentials.public_key` · `state.namespace` /
`state.key` · `reference.name` / `version` / `key` · `connection_event.peer_host` · `known_login_addresses` · the `attachment`
header row (`content_type`, `total_bytes`, `refcount`, `created_at`) + the `message_attachment`
linkage · `secret_rotation_meta` (all three backends) · `.mfbak` on the server backends · and,
from the [harness table](#the-test-harnesss-own-at-rest-data-harness), the `MEFOR_COORD_DIR` coord
files · the load, scenario and acceptance run reports (`--report-json` and its siblings, but **not**
the reconcile compare report, which is PL-1) · the `remotefile_known_hosts` pin file · the GUI's
`QSettings` layout.

Deliberately **not** ciphered, so that ids stay indexable and the audit trail stays greppable for
incident response. Integrity for `audit_log` comes from the **tamper-evident hash chain** (the `client`
address is folded *inside* it), not from a cipher. Its strength is **key-custody-dependent**: HMAC-SHA256 on a DEK-derived subkey or a Transit MAC when the chain is keyed, keyless SHA-256 when it is not. §3 item 1 says when each applies.

**Access, per tier — several of these ARE returned by an API, under RBAC:**

- `audit_log.detail` / `client` — `GET /audit` under `audit:read`; `GET /audit/export` under the
  separate `audit:export`.
- `messages.control_id` / `message_type` and `queue.channel_id` — returned on every `MessageSummary`
  (`GET /messages`, `/messages/{id}`, `/dead-letters`, `/messages/search`, `/messages/export`) under
  `messages:read` (detail: `messages:view_raw`) **plus per-channel scope**.
- `queue.destination_name` — returned on `OutboxInfo` and `DeadLetterRow`, same tier.
- `sessions.token_hash` (as `SessionInfo.id`) and `sessions.client` — returned to the session's **own
  owner** by `GET /me/sessions`; no cross-user read exists.
- `attachment` header (`content_type`, `total_bytes`) + the `message_attachment` linkage — returned as
  `MessageDetail.attachments` under the detail route's `messages:view_raw` + channel scope; the
  linkage row is what scopes the audited byte download to a message the caller may already read.
- `pending_approvals.params` — only through the approvals routes, under their own permission.
- `delivered_keys`, `resend_log`, `processed_files`, `webauthn_credentials.public_key`, `known_login_addresses`,
  `state.namespace`/`key`, `reference.name`/`version`/`key`, `connection_event.peer_host`'s siblings —
  **no API surface** (`connection_event.peer_host` itself is returned by `GET /events` under
  `monitoring:read`).

Confidentiality therefore rests on the **API's RBAC + per-channel scope** for the surfaced tiers, and
on the store-file ACL plus the volume/whole-DB layer for the rest.

**Retention differs per tier — the level does not have one window:**

- `audit_log`, `delivered_keys`, `resend_log` — **keep-forever by design**; `[retention].audit_days` is
  **reserved and not enforced**.
- `sessions` — expired rows are deleted by `purge_expired_sessions`, driven from the auth layer (idle
  30 min / absolute 12 h), not by the RetentionRunner.
- `processed_files` — an age/count prune driven from the wiring runner, also outside the RetentionRunner.
- `state.namespace` / `state.key` — removed with their value on `[retention].state_max_age_days`.
- `reference.*` — **no purge path**; replaced only by the next sync's build-new-then-flip.
- `queue` metadata columns — removed with their row; `messages.control_id` / `message_type` are kept for
  the life of the metadata row.
- `known_login_addresses` — each sign-in or step-up that records an address deletes that
  account's rows older than the sign-in signal's 90-day lookback, and `delete_user` deletes
  them all; an account that records nothing keeps its stale rows until it does or is deleted.
- `connection_event.peer_host` — removed with its row on
  `[retention].connection_event_retention_hours`.
- `attachment` header + `message_attachment` linkage — the join rows are `DELETE`d and the header's
  `refcount` decremented (GC at 0) inside `purge_message_bodies` / `purge_dead_letters`
  (`_release_message_attachments`), with a startup `sweep_orphan_attachments` reclaiming orphans.
- `secret_rotation_meta` — **no purge path on any backend**; one row per tracked secret, replaced in
  place by the watcher's upsert (all three backends since #1186).
- `.mfbak` — keep-N (`[backup].retention_keep`), as PL-1; the canonical name only, with `.failed` / `.part`
  archives unbounded as PL-1 records.
- The test harness's PL-4 files — each row of the
  [harness table](#the-test-harnesss-own-at-rest-data-harness) states its own retention.

**Logging.** Metadata only. Ids, counts, connection/destination names, client addresses and hashes may
appear in the rotating log and in audit rows by design — that is what makes an incident traceable —
and no tier at this level may ever carry a body or an HL7 field value.
[§7](#7-logging--phi-redaction).

#### PL-5 · Engine-unreachable substrate

**Applies to:** SQLite `-wal`/`-shm`/temp; SQL Server `.ldf` + tempdb version store; Postgres `pg_wal`;
every index on every backend; and the plaintext `messages.control_id`/`messages.message_type` columns.

No application control exists or can exist here — see item 4 above for the per-backend cover (SQLCipher
/ TDE / cluster encryption, plus FDE **on the host that owns the files**). Integrity, retention and
destruction for this tier are properties of the database engine and the platform, not of
MessageFoundry. **This level is an unenforced prerequisite**: nothing in the engine checks that the
cover is in place.

**Logging.** The engine writes nothing here and reads nothing back — journal, version-store and index
contents never reach an application log line. Whatever the database engine itself logs about them is
the platform's concern, not covered by the [§7](#7-logging--phi-redaction) inventory.

### Data minimization during processing (in-use posture, ASVS 11.7.2)

PHI is exposed for the **minimum window and surface** needed to route and transform it:

- **A tolerant parse at ingress; the strict model only on request.** Before the ACK, the listener
  parses an HL7 body with the tolerant `Peek` ([parsing/peek.py](../messagefoundry/parsing/peek.py)),
  which is a whole-message parse. The ingress row records only the control id, the message type
  and a summary, and the summary is PHI: the MRN and name, plus order numbers for ORM/ORU. The ACK
  echoes MSH header fields. The version-aware strict object model (hl7apy) is built only on a
  connection's opt-in strict path. **None of this narrows what a Router or Handler sees:** each
  receives the whole decrypted message, parsed (HL7) or verbatim (`RawMessage`), because routing and
  transformation are the site's own Python ([ADR 0202](adr/0202-a-handler-receives-the-whole-decrypted-message-so-asvs-11-7-2-is-recorded-as-partial.md)).
  An earlier version of this bullet said routing reads only the fields a Router asks for; that was
  not what the code does (BACKLOG #1174).
- **Encrypt-after-use at the boundary.** A decrypted body lives in heap only for the lifetime of one
  pipeline stage; the store cipher re-encrypts every PHI column the moment it is written back
  ([store/crypto.py](../messagefoundry/store/crypto.py)), so persisted data never lingers in plaintext
  at rest and the staged queue carries the message forward rather than holding it open.
- **Sealed correlation caches `[BUILT — #1174]`.** The transform-state and reference read-through
  caches, which a Handler reads through `state_get` and `reference(...)`, keep each value as AES-256-GCM
  ciphertext under a per-process key and decrypt it inside the read that asks for it
  ([store/sealed_cache.py](../messagefoundry/store/sealed_cache.py)), on all three backends. Before
  this, every live key's value sat decrypted in heap for the store's lifetime. The keys stay
  plaintext, as the `state.key` and `reference.key` columns do at rest. The cache key lives in the same
  process, so this raises the cost of a heap scrape; it does not protect against an attacker who can
  read process memory, and the value a Handler gets back is an ordinary Python object with no wipe
  hook.
- **`summary`/`metadata` ciphered like the body (EF-3).** The `summary` (MRN/name) and `metadata` are
  routed through the store cipher on write/read — there is no SQL search or index on `summary`, so
  encrypting it costs nothing — and decrypt only at the audited, RBAC-gated read paths.

**Best-effort in-use hygiene `[BUILT — #198]` (ASVS 13.3.3 partial).** Every secret buffer this module
*owns as a mutable `bytearray`* — the unwrapped DEK, each retired decrypt-only key, and the transient
plaintext buffers of `encrypt`/`decrypt` — is best-effort **memory-locked** (`VirtualLock`/`mlock`, so it
is not paged to swap) and **zeroized** (`ctypes.memset`) the instant the AEAD has copied the key/data
into its own buffer ([store/crypto.py](../messagefoundry/store/crypto.py) — `_lock_memory`/`_secure_zero`,
`_install_key`). Both are *best-effort*: they swallow every failure (no privilege, `rlimit` exhaustion,
an exported buffer) and never raise, log, or corrupt — hardening, not correctness. `mfenc:v1` ciphertext
stays byte-identical and the public cipher seam is unchanged. This shortens the window a decrypted secret
sits scrubbable in heap; it is a **documented partial of 13.3.3, not a full close.**

**Honest residual (heap lifetime — the copies we cannot reach):** the wipe reaches only the *mutable*
buffers above. The unavoidable residual is CPython's **immutable** `str`/`bytes`, which have no wipe hook:
the caller's plaintext `str`, the base64 marker `str` we return (ciphertext only — no plaintext PHI), the
`bytes` `cryptography` hands back from `decrypt`, and the transient `bytes(dek)`/`bytes(key)` copies the
`AESGCM`/HKDF constructors consume — plus **`cryptography`'s internal OpenSSL `EVP` key copy**, which we
cannot address. These linger in the interpreter heap until GC/reuse (they may surface in a heap dump or be
paged to swap), so the residual survives even when the KeyProvider seam is pointed at an external
HSM/KMS/Vault — envelope decryption protects the **root KEK**, not the unwrapped DEK the bulk AES-256-GCM
path holds. What we *do* enforce regardless: the DEK is never logged, never put into an exception message,
and never serialized — only its SHA-256 **fingerprint** (`key_id`) is ever surfaced (§3, §6). This is the
standing **ASVS 11.7.1 / CWE-316 / WP-BL3-28** residual: full in-use memory *encryption* is a host/OS
capability (Intel TME / AMD SEV / confidential VMs), not something an application library can provide, so
it is carried as a **stated deployment requirement** (§10) accepted via a signed risk-acceptance
(ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 5), not code.
The compensating controls are the documented restricted-service-account + volume-encryption posture (§10)
on a single-tenant host: keep the decrypted-secret window inside an OS-isolated process whose memory and
swap an attacker cannot reach without already owning the host. **CAUTION: both halves are
operator-asserted and engine-unchecked — say so whenever this is offered as compensating.** §2 records it directly: there
is **no** `[security].volume_encryption_declared` setting at HEAD and **nothing in the engine verifies
that FDE is on**. So this mitigates only where the operator actually applied it, and the engine cannot
tell you whether they did. *(Qualified 2026-08-02: the sentence previously read as though the posture
were a control the product supplies. A compensating control must not rest on a false premise —
`CLAUDE.md` §11 — and an unenforced prerequisite offered as a control is that premise.)*

**Since [ADR 0152](adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md)
the residual is *measured and surfaced*, not only asserted `[BUILT]`.** Three changes, none of which
alters the residual above: (a) `serve` suppresses Windows crash dumps of the engine process, closing the
path by which that heap — plaintext bodies, the unwrapped DEK — is written to a file outside this
document's inventory (machine-policy half: `install-service.ps1 -SuppressCrashDumps`, see
[SERVICE.md](SERVICE.md)); (b) `GET /security/posture` carries a **report-only** platform read-out
(`memory_encryption_self_reported_capability` / `_active`), which is a self-report and **satisfies
nothing** — the body carries its own `memory_encryption_note` saying exactly that; (c) an **exposed**
PHI instance that has not declared `[security].memory_encryption_operator_declared` **warns at every
start**, and refuses only if the estate opts in via `[security].require_memory_encryption_declaration`.
That turns the deployment requirement from prose into a declaration of record with a standing warning
where it is absent.

**This document does not pre-empt the scorecard.** 11.7.1 is scored **`na`**: the requirement's verb is
*"full memory encryption is in use"* — a property of the hosting substrate, which
[`ASVS-ASSESSMENT-METHOD.md`](ASVS-ASSESSMENT-METHOD.md) §2 places outside the assessed software, so
rule 1 takes it out of scope. Re-scoring remains an owner decision rather than a side effect of
shipping a build.

**NOTE: the record is the scorecard itself** — `docs/security/asvs-scorecard.toml`, rendered and CI-gated
([ADR 0156](adr/0156-asvs-scorecard-as-data-a-derived-count-verified-evidence-anchors-and-a-fail-closed-drift-gate.md))
— **never a prose assessment.** ADR 0156 replaced the dated-document lineage precisely because prose
asserts facts about code and the code moves; do not cite a dated assessment file as the verdict of
record. *(This paragraph previously did exactly that, naming a dated assessment and reporting a `Fail`
that the record no longer carried.)*

**An out-of-scope verdict buys nothing operationally**, which is the point of §2.1: the CPython-heap
residual above is unchanged either way, and a deployment still needs the host-side control. Rung 3
(SEV-SNP/TDX plus a verified CPU-signed quote) remains unbuilt.

### 3.x The cryptographic-agility seam — what may be swapped, and what may not

**Ruled 2026-08-11 (ASVS 11.2.2).** The requirement asks that cryptography be "reconfigured, upgraded,
or swapped at any time". That sentence has two readings and they cost very different things, so the
project commits to one of them **explicitly** rather than leaving a reader to infer it:

- **What is committed — RELEASE-swappability.** A *release* of MessageFoundry can change an at-rest
  algorithm without a data migration and without leaving unreadable ciphertext behind.
- **What is NOT committed — RUNTIME reconfiguration.** An *operator* cannot select an at-rest
  algorithm on a running instance, and this is a deliberate refusal, not an unbuilt feature. See
  "Why runtime selection is refused" below.

**The three properties that make release-swappability real** — each verified against the shipped code
rather than asserted:

| Property | Where | What it means for a swap |
|---|---|---|
| The stored value is **self-describing** | `mfenc:v2:<alg>:<key_id>:<b64>` (`store/crypto.py`) | A reader knows which algorithm produced a value without being told out of band, so old and new can coexist in one column during a rollover. |
| The reader **fails closed** on anything it does not know | `Cipher._parse` raises `CipherError` on an unknown version *or* an unknown `alg` | An unrecognised algorithm is refused, never silently mis-decrypted or skipped. A downgrade cannot pass as a read. |
| Re-encryption is **driven and resumable** | `messagefoundry rotate-key` | The swap has an executable migration path; an interrupted run accounts for what it already re-encrypted rather than starting over or double-counting. |

`mfenc:v4` is the **shipped default** writer (`[store].aad_bind` defaults `true`), so these properties
describe the format a new deployment actually writes — not an opt-in path. It carries the same `alg`
segment `mfenc:v2` introduced, and adds the store salt (ADR 0196). `mfenc:v2` is decode-only now, and
`mfenc:v1` remains the frozen writer that `aad_bind = false` selects.

**Why runtime selection is refused, stated as a cost rather than a gap.** An algorithm identifier in
this system is read from three places: configuration (the *operator* chooses), the wire (a token
*minter* chooses), and **stored data** — the `alg` segment `mfenc:v2` introduced and `mfenc:v4` keeps, which means *whoever can write a
store row* chooses. Registering a second at-rest algorithm puts a selector in that third and most
exposed class, converting a fail-closed one-way dispatch into a two-way one keyed on attacker-writable
data. The agility the requirement asks for would be bought by creating a downgrade surface, and on
this trade the project takes the refusal.

**THE HONEST LIMIT, and it is the part a reader should take away:** the seam covers the **at-rest
value core**. It does **not** cover the **audit MAC or its KDF**, which carry *no version
discriminator at all* — measured: zero `mfenc`-style markers anywhere on the audit-chain path. So
changing the audit MAC is not a swap along this seam; it means versioning the tamper-evidence chain
itself, which is undesigned. Any future claim that this project "has crypto agility" must exclude the
audit chain or be false.

---

## 4. Data in transit

**`[MIXED]`**

| Path | Today | Plan |
|---|---|---|
| MLLP inbound/outbound | Plaintext by default; **MLLP-over-TLS (TLS 1.2+, server-cert verify + hostname, opt-in mTLS) when `tls=true`** `[BUILT — WP-13b]`. A non-loopback plaintext MLLP listener is **refused at startup** (exposed-gate, ADR 0002 §0) unless `tls=true` or `serve --allow-insecure-bind`. | — |
| File connector | Plaintext `.hl7` on disk/share | Rely on volume/share encryption; SFTP later |
| Engine API ↔ console | Loopback HTTP by default; off-loopback requires TLS — **in-process** (`[api].tls_cert_file`, WP-13a) **or upstream** at a trusted reverse proxy (`tls_terminated_upstream` + `trusted_proxies`, WP-15) `[BUILT]`. Upstream, the proxy-to-engine hop is plaintext unless `tls_cert_file` is set; the site secures it, and `serve` requires `plaintext_upstream_hop_acknowledged` (BACKLOG #1179). HSTS engages on `https`; forwarded headers are trusted only from `trusted_proxies`. | — |
| AD / LDAP auth | **LDAPS** with cert verification (`ad_tls_verify`) `[BUILT]`. No LDAP referral is followed, so the bind credentials never leave this hop for a referred host; a referral refuses the sign-in (BACKLOG #2530, 2026-09-30). A multi-domain forest would need a global catalog or a search base in the bound controller's own domain. | — |
| PostgreSQL / SQL Server backend | TLS-to-DB on by default (`[store].encrypt`), server cert **validated** (`trust_server_certificate=false`) `[BUILT]`. Trust a private/internal DB CA without disabling validation via `[store].ssl_root_cert` file-pin (Postgres CA-bundle, SQL Server ODBC 18.1+ `ServerCertificate` leaf-pin) **or** a Windows machine-store (`LocalMachine\Root`) CA import. | — |

**Hard rule:** never bind the API to `0.0.0.0` (or any non-loopback interface) without TLS in front
of it. Bearer tokens and PHI would otherwise cross the network in cleartext.

**DB-TLS CA trust + rotation `[BUILT — runbook]` (NIST SP 800-52r2; HIPAA §164.312(e)(1); CWE-295).**
Validating the DB server certificate against a private/internal CA needs that CA trusted, and rotation
needs a make-before-break overlap so no connection fails validation mid-swap. The operator procedure —
machine-store CA import ([`scripts/service/import-db-ca.ps1`](../scripts/service/import-db-ca.ps1)) and
add-new-then-remove-old CA/cert rotation for both backends — is in
[`DEPLOY-SERVER-DB.md` §5](DEPLOY-SERVER-DB.md#5-db-tls-trust-import-the-db-ca--rotate-certificates).
Never remediate a chain-build failure with `TrustServerCertificate=true`.

**Phase 2 transport design `[ROADMAP]`.** In-process API/WebSocket TLS (P2-1), MLLP-over-TLS (P1-4),
and a reverse-proxy / forwarded-header alternative are designed in
[ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) (*Proposed* — build gated on a
scheduled off-loopback exposure).

**Key-exchange parameters `[PARTIAL — the 1.2+ floor and the cipher validator are enforced; the group
pin is INERT until Python 3.15]` (ASVS 11.6.2).** Every TLS context the engine
builds — the API/WebSocket listener ([api/tls.py](../messagefoundry/api/tls.py)) and the per-connection
MLLP server/client contexts ([transports/mllp.py](../messagefoundry/transports/mllp.py)) — enforces a
**TLS 1.2+ floor**, which constrains 1.2 to **(EC)DHE** key exchange and makes 1.3 ECDHE-only: forward-
secret key establishment, never static RSA/DH. **That floor is the enforced control.** Two further
controls in [config/tls_policy.py](../messagefoundry/config/tls_policy.py) address the *parameters* — and
only the second of them actually takes effect on today's interpreters:

- **Approved groups are *inherited*, not pinned — corrected 2026-07-29.** Built contexts call
  `harden_kex_groups`, which pins the approved ECDHE groups `X25519:secp384r1:secp256r1` via
  `SSLContext.set_groups` — an API that lands in **Python 3.15**. This bullet previously said "≥ 3.13",
  and the practical effect of the error is that on every interpreter this project currently runs on
  (measured: 3.14.6 / OpenSSL 3.5.7) the helper pins **nothing** and every built context inherits
  OpenSSL's default group list. That default *is* forward-secret — the property the TLS 1.2+ floor
  above exists to guarantee — but it is **wider than the approved list**: measured against the real API
  context, it also accepts `ffdhe2048`, `ffdhe3072` and `secp521r1`. It refuses `secp224r1` and
  `sect571r1`, so the gap is *wider than policy*, not *weak*. `harden_kex_groups` now **returns the
  list it actually pinned** — `None` today — and `tests/test_tls_policy.py` asserts that `None`
  unconditionally, so the first interpreter with the API turns the test red instead of letting the
  claim drift back.
- **`tls_ciphers` is validated, not trusted.** An operator `[api].tls_ciphers` string is rejected at
  config load if it would admit a **non-forward-secret** (static-RSA/DH) suite, so a misconfiguration
  cannot widen the key exchange below policy.

No static-DH parameter files are used, and at-rest key material is a pre-shared secret (§3), not
negotiated — so the only key exchange in the system is inside TLS, with the parameters above. Material
once the API/MLLP binds off-loopback (when the engine terminates TLS).

**Handshake signature schemes `[PARTIAL — the SHA-224 pin acts on Python 3.15 only]` (ASVS 11.4.1,
BACKLOG #1171).** By owner ruling of 2026-09-29, every context the engine narrows drops the three
SHA-224 signature schemes where the interpreter can: `narrow_signature_algorithms` in
[config/tls_policy.py](../messagefoundry/config/tls_policy.py). On Python 3.14 it changes nothing,
so those contexts still offer and accept SHA-224. On 3.15 they stop, unless the linked OpenSSL is
older than 3.4. The LDAPS hop is reached too, since BACKLOG #2494. That function's docstring is the one statement of
what it does, what else it changes, and what it cannot reach.

**Outbound destination allowlist `[BUILT]` (WP-11c).** The `[egress]` section
([CONFIGURATION.md](CONFIGURATION.md#egress)) is a **fail-closed** allowlist for where the engine
sends: `allowed_mllp` (host / host:port) and `allowed_file_dirs` (directory prefixes). Enforced at
config **load/reload + start** against the resolved (`env()`-substituted) destination — a non-allowed
destination is refused (`WiringError` → 422 / refused reload, logged), so a fat-fingered or hostile
destination can't exfiltrate PHI. Opt-in (empty = unrestricted). The webhook/SMTP alert sinks (no PHI
bodies) keep their own `[alerts]` host allowlists.

---

## 5. Access control, authentication & authorization

**`[BUILT]`**

Full model: **[SECURITY.md](SECURITY.md)**. PHI-relevant facts only here:

- **Authentication is required** for the running service; the only no-auth path is the in-process
  embedding factory used by tests, never reachable over `serve`.
- **RBAC, deny-by-default.** Viewing PHI is gated by dedicated permissions: `messages:view_raw`
  (raw body) and `messages:view_summary` (patient summaries). Holding neither means no PHI access.
- **Sessions** are opaque server-side tokens (store keeps only the SHA-256), with idle (30 min) and
  absolute (12 h) timeouts; a password change or a local disable revokes sessions at once. Some
  paths lag a revocation. A running bulk export keeps going. A change made in Active Directory, or
  to the AD group maps, can wait for the reconciler, the next login or the session cap. A user
  dropped from their last scope-mapped AD group would keep the old channel scope in live sessions,
  and any PHI view it carries. That would last until their next login, within the session cap. See
  [SECURITY.md](SECURITY.md#a-revoked-privilege-reaches-the-next-request-with-exceptions-asvs-832).
- **Local passwords** are argon2id; lockout after 5 failed attempts. AD users bind over LDAPS.

### Browser ops dashboard (`/ui`, ADR 0065) — `[M1: read-only; pending owner ASVS sign-off]`

The engine serves a same-origin, **read-only** browser ops dashboard under `/ui`. It is **on by default**
(`[security].serve_web_console`, ADR 0143 — the console is the operator UI, effectively core; disable with
`serve_web_console = false` to shrink to a JSON-only surface). Default-on applies to **local loopback**
binds; on an exposed instance a default-on console auto-degrades to JSON-only unless explicitly enabled
with TLS + a public origin. It is a client of the existing API and reuses every server-side PHI
control unchanged (`messages:view_raw`/`view_summary` RBAC, field-level redaction, the per-access
`message_view` and `message_body_view` audits, the `require_phi_read` throttle). The browser-specific PHI rules:

- **No PHI in browser storage.** The session token lives in an **HttpOnly + SameSite=Strict** cookie
  JS cannot read (`mf_session`). **One** thing is written to `localStorage`, deliberately and
  PHI-free: per-table column widths and visibility, under the `mfcols:v2:` prefix
  (`messagefoundry_webconsole/static/app.js`), keyed by pathname and table ordinal. They are
  operator display preferences, carry no message content, and are the reason
  `Clear-Site-Data` is sent as `"cache"` and not `"storage"` on logout
  (`messagefoundry_webconsole/_auth.py`). Nothing else is written to `localStorage`, and nothing
  at all to `sessionStorage` or `IndexedDB`; `tests/test_browser_storage_doc_drift.py` reds if
  the console writes a prefix this sentence does not name.
  **This bullet asserted the opposite until BACKLOG #1186 corrected it**, saying nothing was
  written to any of the three. The column preferences had shipped since 2026-07-07 and no test
  read this sentence, so the claim was false and nothing could red on it.
- **No operator-typed search term in a URL** (BACKLOG #1184, ASVS 14.2.1). `content` and `field_value` are declared on no GET signature — not `/messages/search`, `/messages/export`, `/uploads/{file_id}/messages`, nor either console twin — and travel in a POST body instead; `tests/test_content_search.py::test_no_get_or_head_route_declares_a_phi_needle_parameter` walks both planes' route tables and reds if either name is declared on a GET or HEAD again. What a `/ui` GET still declares is engine-minted ids, structural locators (`field_path`, an HL7 path such as `PID-3`, never a value), bounded enums, paging integers and the low-sensitivity `control_id`/`message_type` keys of §2. No *message body* is ever placed in a URL, and `Referrer-Policy: no-referrer` is set. **Retracted here, because this bullet asserted the opposite until #1184 landed:** until then the console's search and uploaded-log browse did take the needle as a query parameter, so a search URL could carry a patient identifier into history, bookmarks and `Referer`. What survives that removal is a log residual rather than a URL the product emits — §7 states it.
- **No caching.** Every `/ui` HTML response and every PHI JSON read is served `Cache-Control: no-store`,
  so a browser/proxy never retains a message body on disk. The covered set is the PHI-read route
  families — `/messages*`, `/dead-letters*`, `/search*`, `/logs*`, `/uploads*` (`_NO_STORE_PREFIXES` in
  `api/app.py`) — plus exact route templates in `_NO_STORE_ROUTE_PATHS`. Those are mostly responses
  that carry a rated field under a monitoring permission. At least these: the event log, the alert
  list and its four mutation replies, `GET /connections` and `GET /connections/{name}/metadata`.
  `tests/test_no_store_phi_coverage.py` walks every registered route. It fails when a PHI-gated route,
  or one whose response projects a PL-1/PL-2/PL-3 column, lands outside that set. That is what keeps
  a new PHI surface from shipping header-free, the way `/search/layered`, `/logs/tail` and
  `/uploads/{file_id}/messages` each did. Credential-bearing replies are served `no-store` by the
  auth routes themselves: a session token, a staged TOTP seed, recovery codes, a temporary password.
  `tests/test_credential_reply_no_store.py` drives each of those routes. **What the two tests cannot
  see.** The route test reads a field only when its name is a rated column's name. The credential
  test reads only the credential field names it lists. A route outside the prefix families with no
  response model is outside both. Those shapes rest on review.
- **Audited raw view only.** A raw message body is shown only via the same audited body fetch the
  JSON API serves at `GET /messages/{id}/raw` (record_view + a tamper-evident `message_body_view` audit
  row whose `surface` is `console`); there is no second, unaudited PHI render path.
- **The body and the summary appear only on an explicit act (BACKLOG #2346, ASVS 14.2.6).** Opening
  a message at `/ui/messages/{id}` shows its metadata with the summary masked and no body. That is
  where the dead-letter "view" link, the redirect after a replay or an edit-resend, and a typed bare
  URL land. The message list and content search link from the masked summary to
  `/ui/messages/{id}/summary`, which reveals the summary. The detail page's "Show raw message" link
  is `/ui/messages/{id}/body`, which shows the body and the summary. The parse-tree and edit pages
  exist to show the body. What each message route reveals is declared once, in
  `routes.core.UI_MESSAGE_REVEALS`. The console's body helper refuses a route that does not
  declare `body`, and a source test fails if a route handler calls the engine's open or body
  fetch around those helpers. A detached attachment has its own audited download route and no
  row in that table. The error text follows the same rule (BACKLOG #2436, owner ruling R12): the
  message's error, each delivery's last error and each event's detail show as `****` with a
  "Reveal" link to `/ui/messages/{id}/errors`, and the dead-letter list links each masked last
  error to the same route. No other console route in that table declares it, the body reveal
  included. The JSON plane is its own question: it masks the same text on the open and on the
  message and dead-letter lists, and at least `GET /messages/{id}/responses` (the captured
  reply's `detail`) can carry a similar string unmasked, under its own gate.
  **The event and alert reasons follow the same rule (BACKLOG #2443, owner ruling R12).** A
  delivery failure writes its `safe_exc()` text into a `connection_lost` event's reason and a
  `connection_error` alert's reason, and other `safe_exc` reasons (at least the MLLP listener's
  `handler_error` and the FILE source's quarantine events) share those columns. `/ui/events`,
  `/ui/connection/{name}` and `/ui/alerts` show each reason as `****` with a "Reveal" link to
  `/ui/events/{id}/reason`, `/ui/connection/{name}/events/{id}/reason` or
  `/ui/alerts/{id}/reason`. Each reveal returns that one reason whole and is audited. The next bare
  load is masked again. A role without `messages:view_summary` sees no reason and no link, but
  still sees each event's kind and each alert's type and state, so an operator can tell that a
  connection went down. For events that is the built-in Viewer, Deployment, Coding and Auditor
  roles, which hold `monitoring:read` and no PHI permission. The alert page and `GET /alerts/active`
  also need `monitoring:diagnose`, which only the built-in Operator and Administrator hold, and
  both hold `messages:view_summary`; so among alerts the mask binds a custom role granted
  `monitoring:diagnose` without it, and those four built-in roles do not reach alerts at all.
  **`CapturedResponseInfo.detail` is outside R12, and that is recorded, not overlooked.** R12
  covers console pages and leaves API-only fields out. No console page renders that field. It
  reaches only a caller of `GET /messages/{id}/responses`, which already requires
  `messages:read` + `require_phi_read`, nulls it without `messages:view_summary`, and audits
  every read as `response.read`. On the JSON plane the request is itself the act.
  A reveal is a request, never a setting, so it does not carry to the next page.
  The reveal addresses are ordinary GETs. Going back to one (history, a restored tab) is usually
  a new request, audited and charged like the first, but a browser may also redisplay the page
  from its back-forward cache without asking the engine, and then nothing is audited.
  The test harness does the same with a Show body button. It has no error-text reveal: it shows
  the mask, and the error text is read in the web console.
- **Attachments are neutralized at serve; the stored document is never rewritten.** A detached document (ADR 0105) is a
  verbatim clinical payload carrying its own attacker-influenced `OBX-5.2` MIME label, and the
  preserve-the-original invariant forbids editing the stored bytes — so the browser-safety control runs
  at *serve* time, not on the stored document. The served `Content-Type` comes from an **allow-list** of
  inert types matched case-folded and exactly (`api/app.py`); a browser-active label such as `text/html`,
  `image/svg+xml` or `application/hta` is simply not on it, so it is declared `application/octet-stream`,
  and the same table gives the download name a `.bin` extension instead of `.svg`/`.html`/`.hta`. The
  response carries `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: default-src 'none'; sandbox; frame-ancestors 'none'` on both the
  JSON route and the `/ui` delegate.
  No served representation can execute in the application origin, and
  none can be framed -- `frame-ancestors` is named in that policy rather than left to the API's
  header floor because it takes no fallback from `default-src` (ASVS 3.4.6). Trade-off: `svg`/`html` attachments no
  longer preview in the browser; the bytes are unchanged and still downloadable, since the allow-list
  governs the declared type and never whether the file is served. An SVG is the exception: the route
  serves a copy rebuilt from a tag and attribute allow-list, or refuses with HTTP 422 one it cannot
  vet, and the stored value stays verbatim either way. What counts as an SVG, and what is kept or
  refused, is recorded once, in ADR 0105's 2026-09-28 amendment.
- **XSS-safe rendering.** All HL7/message content is escaped by an autoescape-by-default renderer and a
  strict CSP (`script-src 'self'`, no `unsafe-*`); attacker-influenced HL7 cannot execute in the DOM.
- **Residual (documented, not a claimed control):** a shared clinical workstation, browser devtools, or a
  malicious browser extension can observe on-screen PHI while a session is open — the same physical/endpoint
  exposure any operator screen has. Restrict `/ui` to managed hosts; it never binds off-loopback without TLS
  (refused even under `--allow-insecure-bind`).

> **Scope:** M1 is read-only. Safe operator actions (replay, start/stop) + a CSRF token stack land in M2;
> the `/ws/stats` browser channel and any parse-tree endpoint are also M2. A full ASVS L3 re-assessment of
> the flipped cells (V3 session-mgmt, 14.3.2/14.3.3, 3.4.3) is pending owner sign-off (see ADR 0065).

---

## 6. Audit & accountability

**`[BUILT]`** (one cleanup)

Every PHI access is recorded in the append-only `audit_log` with the **acting user**:
`message_view` (opening one message, with `revealed` listing which of `summary` and `metadata`
that open returned complete), `message_body_view` (its raw body, with a `surface` naming
which client asked: `harness`, `apiclient` or `api` as the HTTP caller declares it, or `console`,
which the engine records itself for the web console), `summary_access` (patient summaries),
plus the auth and admin events
listed in [SECURITY.md](SECURITY.md). Each row carries actor, action, timestamp, channel, the
caller's `client` address, and a JSON `detail` (filters, counts, exposed control IDs — **not** the
bodies). Read the trail via `GET /audit` (`audit:read`).

`summary_access` rows differ from a single-request row like `message_view`:

- It is coalesced: one row per actor, channel scope and hour, carrying the count. Its sources
  include at least the message list, its content search, the dead-letter list and the message
  detail view.
- It is written late. The engine keeps the open hour's count in memory. It writes the row when a
  later access rolls into a new hour, or when the engine stops cleanly, so a crash would lose the
  open hour's count.
- It has no `client`. One row stands for many requests, so it records no single caller address.
  A few other writers leave `client` empty too; [ADR 0150](adr/0150-client-address-on-audit-entries.md)
  lists them.

**Credentials, tokens, and PHI bodies are never written to the audit log.**

**Attribution:** with auth built, the `audit_log.actor` is always populated — a real username, or
`system` for internal actions — so an audit row is never unattributed. (The schema comment was
corrected to say so.) Since [ADR 0150](adr/0150-client-address-on-audit-entries.md) the row also
records **where from**: `audit_log.client` is the caller's network address, stamped at write time
from the request. `NULL` means *no client was in scope* (an engine-internal or background write) —
never "unknown", and never a value inherited from some other caller. Do **not** attribute an action
by joining to `sessions.client` instead: that address was captured at **login**, so on a replayed
token it names the original victim's host — a confident wrong answer.

---

## 7. Logging & PHI redaction

**`[MIXED]`**

**Hard rule (enforced by convention today):** never log full message bodies at INFO or above. Full
payloads go only to the secured store, never the general log. Logging is stdlib today (stdout, NSSM
captures to rotating files); running a **`prod`** environment at `DEBUG` is **refused at startup**
(Gate #1 — DEBUG can surface bodies/raw fields; see below).

**Known leak surfaces — treat these as PHI sinks:**

| Surface | Risk | Guidance / plan |
|---|---|---|
| `messagefoundry dryrun` | At least: bodies (`raw`, every `deliveries[].payload`), the PHI `summary`, every `state_ops[]` key/value, and the `error` text a Router/Handler raised are **redacted/withheld by default** in its JSON output, on the plain and the `--trace` path alike ([__main__.py](../messagefoundry/__main__.py) `_redact_body`, [redaction.py](../messagefoundry/redaction.py) `safe_error` for the error, `_safe_value` for a traced local); `--show-phi` opts in `[BUILT]` (review H-12; the error text, BACKLOG #1668). A `print()` in a config module, Router or Handler goes to **stderr**, so stdout stays one JSON document (vault BACKLOG #1187) | Still: never run against real PHI, and never `--show-phi` into a committed file or CI log. Nothing redacts what an author's own `print()` writes, so stderr is no safer than stdout |
| `messagefoundry check` | Its `dryrun` check quotes the `error` a Router/Handler raised into the failure detail it prints | **`[BUILT]` (BACKLOG #1668):** that text goes through `safe_error` **unconditionally — this surface has no `--show-phi` and must never grow one**, because the gate's stdout lands in a commit hook and a CI log by design, so an opt-in here would put PHI in that log on request. Fixtures stay synthetic regardless (§9): the redaction bounds a mistake, it does not licence real PHI |
| `messagefoundry generate` | Prints the offending message to **stderr** only behind an opt-in flag, **off by default** ([generators/adt.py](../messagefoundry/generators/adt.py)) `[BUILT]` | Synthetic data, but keep the flag off whenever output is captured |
| Router/Handler exceptions | A user script doing `raise ValueError(f"...{raw}")` would put PHI into the stored `error`/`last_error`/`detail` and any log of it | **`[BUILT]` (WP-6c):** every exception rendered into a stored disposition or a log goes through the **`safe_exc()` chokepoint** ([redaction.py](../messagefoundry/redaction.py)) — it keeps the exception **type** and redacts HL7-shaped content; §3 also encrypts those columns (defense-in-depth) |
| Session mail ([scripts/coord/mail.ps1](../scripts/coord/mail.ps1)) — repo tooling, **not** a product surface: the wheel and sdist are package-only, so `scripts/` never ships | A developer pasting message content into a mail body **would** put PHI under `<git-common-dir>/mefor-coord/mail/`, which no `[retention]` window bounds; delivery **would** copy it again into the recipient session's transcript, which nothing in this repo can delete. The leak gate cannot see it either — `.git` is in `scan_forbidden.py`'s `SKIP_DIRS`, so a green `forbidden-content` run is not evidence about this path | **Never put message content in a mail body — mail the path instead.** The rule, and why it is a write-side content rule rather than a control on the queue, are in [SESSION-MAIL.md](SESSION-MAIL.md), "What may never go in a message body" |

**Exception-path redaction `[BUILT]` (WP-6c).** [`messagefoundry/redaction.py`](../messagefoundry/redaction.py)
provides `redact()` (scrubs HL7 segment/field content from free text, keeping segment IDs) and
`safe_exc()` (the chokepoint used at every exception→`last_error`/`detail`/log site in the
[wiring runner](../messagefoundry/pipeline/wiring_runner.py)). It is conservative redaction, **not**
de-identification (§9). Beyond HL7-shaped spans, `redact()` now also applies a **conservative free-text
heuristic** — date/DOB runs and multi-token name runs (e.g. `DOE JANE`) are scrubbed even without HL7
delimiters — so the prior free-text residual is **narrowed** to an adversarially-crafted *single-token*
or non-name-shaped identifier, still governed by the "never put PHI in an exception message" convention.
The HL7 delimiters are **read from the message's MSH header** rather than assumed to be `| ^ ~ &`
(BACKLOG #1572), so a feed declaring its own separators is covered; before that fix a custom-delimiter
message matched nothing and a deploying site would have logged its identifiers in full.
Reinforcing that convention, `messagefoundry check` ships an **advisory `raise-fstring` lint** that
AST-scans the config-dir Router/Handler modules and flags a `raise` whose message is built from a
variable — at least an f-string `raise ValueError(f"bad {x}")`, a `+` concatenation, a `%` format and
a `.format(...)` call, which carry the same free-text payload past redaction; it prints a heuristic
reminder and never blocks the gate. **It is a nudge, not a boundary, and does not narrow the residual
above.** It reads only the **first positional argument** of the `raise`, so a message assigned to a
local first (`m = f"bad {x}"`; `raise ValueError(m)`), one passed as a keyword or a later positional
(`raise FeedError("E01", f"bad {x}")`), and one wrapped in a call (`raise ValueError(str(x))`) all go
unflagged. The convention is what governs; `_check_raise_fstring` catalogues what the check itself
over- and under-flags. The existing controls — never log full bodies at
INFO+ and the CR/LF log-injection filter — remain in
[logging_setup.py](../messagefoundry/logging_setup.py). The engine used to silence python-hl7's
loggers, which wrote whole field values at ERROR on an unmapped escape. python-hl7 is retired and
the built-in parser logs no field value, so that silencer went with it (ADR 0054 amendment).

**Global log redaction + prod-DEBUG guard `[BUILT]` (Gate #1).** **Four** handler filters run, **on every record emitted by the engine process and by the ADR 0087 sandbox worker child**, in this
order, on **every** emitted record and on **every** handler — stdout *and* the off-box forwarder —
installed by `_install_phi_filters`, reached through `configure_logging` in the engine and
`configure_stderr_logging` in the child
([logging_setup.py](../messagefoundry/logging_setup.py)):

1. **`RedactionFilter`** — `redact()`-scrubs both the rendered **message** and the formatted **exception
   traceback — chained `__cause__`/`__context__` included** (and `stack_info`), then clears `exc_info`
   so no formatter can re-render the raw exception. Every `log.exception()` / `exc_info=` site (the
   delivery/router/transform catches, the `_on_*_worker_done` callbacks, the file/db/remotefile pollers,
   the cluster leader-sweep/heartbeat loops) is therefore redacted *by construction*, not per call site.
2. **`CredentialQueryScrubFilter`** (ADR 0142 AC-10) — redacts the **values** of credential-bearing
   query parameters (`code`, `state`, `id_token`, `access_token`, `token`, `session_state`). This is the
   only reason a live OIDC authorization code does not land in the access log. Until BACKLOG #1478
   it reached the rendered **message** only, so a `code` inside an exception traceback was
   scrubbed by nothing; all four filters now share one record walk covering `message`,
   `exc_text` and `stack_info`.
3. **`CredentialScrubFilter`** (BACKLOG #1478) — redacts credential **values** by LABEL, keeping
   the label so the line stays diagnosable: `password`/`secret`/`credential` pairs including the
   engine's own snake_case spellings (`ad_bind_password`, `tls_key_password`, `client_secret`),
   bearer/session/API tokens and a bare `Bearer <tok>`, key material (`private_key`,
   `encryption_key`, `encryption_keys_retired`, `intake_api_key_next`), a `MEFOR_*` value echo,
   and an inline DSN password. The vocabulary is
   [`secretscrub.py`](../messagefoundry/secretscrub.py), a stdlib-only neutral leaf; the
   **domain** is derived from the engine's own credential registries and every name in it must be
   scrubbed or carry a written reason
   (`tests/test_logging_credential_scrub.py`). **Usernames are deliberately out of scope** — see
   the residual note on stream 4 below.
4. **`ControlCharScrubFilter`** — escapes CR/LF and the rest of the log alphabet, which includes at
   least the C1 controls, the bidirectional controls and U+2028/U+2029 (log-injection defence, ASVS
   16.4.1). The alphabet is stated once, in `_escapes_in_a_log_line` in
   [`controlchars.py`](../messagefoundry/controlchars.py); read it there.

`redact()` rewrites only HL7-shaped spans plus date/DOB runs and multi-token name runs, so ordinary
operational lines are untouched. This makes `safe_exc()` (above) the explicit chokepoint and the global
filters the backstop for anything that reaches a handler un-redacted. `configure_logging` used to
silence python-hl7's PHI-prone loggers as well; python-hl7 is retired, and the built-in parser that
replaced it logs no field value.

**A second residual, from the same honesty rule (BACKLOG #1572):** the delimiter sniff reads MSH-1 and
MSH-2, so a **headerless** custom-delimiter fragment declares nothing and passes through — `mrn
MRN123$$$H$MR here` still survives. So does a message whose MSH-2 is shorter than its conformant width.
Neither is a completeness claim; the convention above remains the control for both.

**Residual, stated honestly:** `redact()` does **not** scrub a *single-token* identifier. An access line
carrying `?content=1234567` or `?field_value=MRN12345` would survive the whole filter chain unredacted:
one `&` is below the HL7 field-run threshold, and neither parameter name is in the credential list.
**What changed is who can produce such a line.** BACKLOG #1184 (ASVS 14.2.1) removed both names from
every GET signature, so no route, console form or shipped client puts them on a URL any more. Uvicorn,
though, builds its access line from the raw ASGI `query_string` rather than from the parameters a route
binds, so a hand-crafted URL still reaches the log intact while the route itself ignores the term.

**There is no control over that residual, and the filter chain is not one** — `redact()` leaves a
single-token identifier alone and neither parameter name is in the credential list, measured by
`tests/test_logging.py::test_an_undeclared_phi_needle_is_not_scrubbed_from_the_access_line`.

**This section is the record for why, and it is a ruling rather than an omission.** #1184 rejected
adding the two names to `_CREDENTIAL_QUERY_KEYS`: whoever hand-crafts such a URL also picks the
parameter name, so `?patient=` or `?q=` would pass an entry for `content` untouched, and the entry
would read as a protection this log does not have — a compensating control resting on a false premise.
The catchment is empty besides: no shipped client, bookmark or stored link can carry those names, since
the parameter was deleted before any first deployment. `tests/test_logging.py::test_the_phi_needle_names_stay_out_of_the_credential_scrub_list`
pins that edit at the tuple. **The ruling is against a name DENYLIST only** — it says nothing about a
different control, such as an allowlist scrubbing every non-allowlisted query value, and whoever builds
one should correct this section rather than work around those tests. That is why the engine still
classifies the general log as a PHI read surface (below).

**Prod-`DEBUG` refusal.** `serve` **refuses to start at `DEBUG` on a production instance** — derived
from `--env prod` or **`[security].production_instance = true`** (exit code 2). DEBUG can surface full
bodies / raw fields and real PHI flows there. Two qualifications: this is a **startup** gate only, and
`PATCH /logging/level` (permission `monitoring:diagnose`) can raise the **live** level to `DEBUG` on a
production instance with no posture check. That change is audited (`logging_level_change`, old→new +
actor) and is ephemeral — a restart re-asserts `[logging].level`, though a `/config/reload` does not
reset it.

**Gate #1 acceptance (v0.1)** — each criterion with its proving test:
- the global `RedactionFilter` is installed by `configure_logging` (`tests/test_logging.py`);
- a chained exception carrying an HL7 body yields no body fragment in any rendered traceback, while the
  exception **type** is kept (`tests/test_logging.py`);
- end-to-end across parse→route→transform→deliver, a synthetic ADT with a known patient name + MRN that
  hits a Handler exception **and** a delivery failure leaves **no record at WARNING+** carrying those
  values (`tests/test_wiring_engine.py`);
- `serve` refuses `DEBUG` in a `prod` environment (`tests/test_logging.py`).

**Structured logging + off-box forwarding `[BUILT, sec-offbox-log]`.** The general log can emit
**structured JSON** (one object per line, `[logging].format = "json"`; `text` is the stdout default) and
a **copy of every record can be forwarded off-box** to a syslog/SIEM collector. Forwarding is
**default-on-when-configured**: `[logging].forward_enabled` defaults to *unset* and is derived to
`(forward_host is not None)`, so **naming a collector turns forwarding on** and `forward_enabled =
false` is the explicit opt-out. The full knob set is `forward_host`/`_port`/`_protocol`/`_format`,
`forward_tls_ca_file`/`forward_tls_verify`/`forward_tls_client_cert`, and
`forward_hop_attested`/`forward_hop_attested_reason`. The forwarder is wired in
[`logging_setup.configure_logging`](../messagefoundry/logging_setup.py), and the **same four handler
filters** above are installed on **every** sink, so the forwarded stream carries the identical
PHI-redaction + log-injection guarantees as stdout. `json.dumps` additionally escapes the C0 controls
so a record can't break the one-line-per-record framing; it leaves the C1 controls and U+2028/U+2029
raw, which is why filter 4 escapes them first. JSON is therefore the recommended (and
default) off-box `forward_format`; the `text` format is best-effort framing (a multi-line traceback
spans lines).

**Transport `[BUILT — ADR 0080]`.** `forward_protocol` is `udp` (RFC 5426, the default, fire-and-forget)
| `tcp` (RFC 6587) | **`tls` — native syslog-over-TLS (RFC 5425)**, an `ssl`-wrapped TCP socket that
needs **no local agent**. TLS verification is on by default (`forward_tls_verify = true`, cert +
hostname); when `forward_tls_ca_file` is given, **only** that anchor is trusted (system roots are not
loaded), and a config-load validator **refuses** `protocol = "tls"` with verification on and no CA file.
`forward_tls_client_cert` adds a mutual-TLS client chain. `forward_tls_verify = false` is the documented
insecure opt-out (no cert or hostname check).

**Hop gate `[BUILT — #1163]`.** Because the forwarded stream is PHI-*redacted* but still carries
usernames, connection names, message ids, client addresses and the tamper-evident audit chain, `serve`
decides the forwarding hop through the **same shared `insecure_hop_disposition` authority every
transport cell consumes** — *before* `configure_logging` installs the handler, so a refused hop never
emits a single record. A hop counts as secure **only** when it is TLS with verification on. Everything
else goes to the gradient: **loopback collector → ALLOW** (the "point `udp`/`tcp` at `127.0.0.1` and let
a local rsyslog/Vector/SIEM agent add TLS" deployment is preserved byte-identically), **`forward_hop_attested`
→ ALLOW** (with a mandatory non-empty `forward_hop_attested_reason` — the `[logging]` sibling of a
connection's `tls_hop_attested`), **clamped global escape → WARN**,
**enforcing instance → REFUSE (`serve` exits 2)**, **non-enforcing → WARN**. The three named
remedies are therefore: native TLS, a loopback agent, or an attested hop.

> **Why this cell has no way to accept the risk, when a connection does.**
> [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) removed
> the `synthetic → ALLOW` arm from the shared cleartext-hop authority and kept it here, on its
> *Explicitly out of scope* table, **deliberately**: this forwarder is not a connection, so it has
> nowhere to carry a per-hop `cleartext_accepted` declaration, and refusing it outright would create a
> deviation the loosening registry cannot express.
> [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)
> then removed the data label itself, so that restated arm had no instance left to fire on and is gone
> from `forward_hop_disposition`. 0153's scope reasoning stands, and it now describes a **gap rather
> than an escape**: a `[logging]` sibling of `cleartext_accepted` is the recorded follow-up and the
> only way this cell could ever express an acceptance. Until it exists, the three remedies above are
> the whole list.

**Availability.** The forwarder never blocks the engine *indefinitely* — UDP is fire-and-forget; a `tcp`
**or `tls`** collector that is **unreachable at startup** (or whose certificate fails to verify —
`ssl.SSLError` is an `OSError` subclass) is skipped with a warning and the service starts without it,
and one that **stalls at runtime** is bounded by a 5-second socket timeout pinned on every reconnect —
including the TLS handshake — after which the record is dropped, so a wedged SIEM can't stall the
asyncio event loop. `configure_logging` reports whether the handler was actually installed, so the
"forwarding enabled" line never contradicts a skipped collector. The send is still synchronous, so for a
high-volume feed prefer UDP to a collector on another host, which the forwarding start gate allows only
under `enforcement = "warn"` (BACKLOG #1966).

The tamper-evident **`audit_log`** is **also tee'd off-box** (sec-offbox-log #361/#363): every committed
audit row is emitted as PHI-redacted metadata through the `messagefoundry.audit` logger to the same
handlers, across all three store backends
([`store/audit_tee.py`](../messagefoundry/store/audit_tee.py)). That logger is **pinned to `INFO`**, so
audit evidence is emitted even when `[logging].level` is `WARNING`. **Not used:** structlog (stdlib
`logging` only).

### Logging inventory (16.1.1 / 16.2.3)

Every log/event stream the product emits, with the facts ASVS 16.1.1 asks for: **what events are
logged, the format, where it is stored, how it is used, how access to it is controlled, and its
retention** — plus, because this system carries PHI, whether the stream can hold sensitive free text and
what redaction applies. Rows 1–4 are the *transient/off-box* streams; rows 5–9 are the *durable*,
store-backed ones; rows 10–13 are the alert fan-out; row 14 is the operator-invoked support bundle —
the one stream whose whole purpose is to leave the box. Streams 2 and 3 are sub-streams of stream 1
with materially different PHI profiles, so they get their own rows; stream 4 is the shared off-box
**transport** for 1–3.

| Stream | Events logged | Format | Where stored | How used | Access control | Retention | PHI / sensitive free text + redaction |
|---|---|---|---|---|---|---|---|
| **1. General application log** | operational events, worker/connection lifecycle, exception **types**, warnings, every alert that the `LoggingAlertSink` fallback implements when no `[alerts]` transport is configured (see row 13 for the two it does not) | single-line text (`[logging].format = "text"`, the default) or one JSON object per line (`"json"`); UTC `Z` timestamps in both | stdout by default — under NSSM the supervisor captures stdout/stderr to `<DataDir>\logs\service.out.log` / `service.err.log`; **plus** the opt-in engine-owned `[logging].file` when configured (#122, ADR 0162), which carries the identical filter chain and whose write failures roll it aside and, on a second failure, stop this process's connections | day-to-day operations, incident triage, and the source of the support-bundle tail in row 14 | at rest: the NSSM installer creates `<DataDir>\logs` and locks the whole DataDir with `icacls /inheritance:r` to SYSTEM + Administrators + the service account (best-effort — a failure warns, never aborts). Over the API: `GET /logs/tail` requires the dedicated **`logs:view`** permission **and** `require_phi_read`, and every served page writes a `logs_view` audit row (line **count** only, never content) | NSSM rotates by **size** (`AppRotateBytes` 10 MB) and never deletes by age; age deletion is `[retention].app_log_days` over `[logging].log_dir` (`.log`/`.txt`, by mtime, **content never read**), optionally preceded by in-place gzip on `[retention].app_log_compress_days` (integrity-validated before the original is removed; the archive keeps the source's mtime, so the same delete window ages it out). Both default 0 = keep forever, uncompressed | **Can contain PHI.** The engine's own permission catalog classifies this as a PHI read surface (`logs:view`: "best-effort redaction, residual single-token PHI possible"). Defence: never-log-bodies rule, `safe_exc()` at the source, the three handler filters, python-hl7 loggers silenced, and `safe_name()` at the FILE / REMOTEFILE sources, which log a derived label rather than the partner-chosen file name (BACKLOG #1748 — the filters cannot catch a name, so it is derived where the name is known). **Residual:** a single-token identifier is not scrubbed |
| **2. `uvicorn` request/access log** (sub-stream of 1) | one line per HTTP request — method, **full request line including the query string**, status, timing | inherits stream 1's format | inherits stream 1's sink | request tracing, latency and error triage | inherits stream 1's | inherits stream 1's | **Can contain PHI.** `configure_logging` clears uvicorn's own handlers and propagates to the root, so the four filters apply; `serve` passes `log_config=None` and never disables `access_log`, so at the default `INFO` level every request is logged. OIDC `code`/`state` **are** scrubbed. **Not** scrubbed: a `?content=…` / `?field_value=…` that arrives anyway — no route has declared either since BACKLOG #1184, but the access line is built from the raw `query_string` rather than from what a route binds (the single-token residual above) |
| **3. `messagefoundry.audit` off-box tee** (sub-stream of 1) | one JSON object per **committed** `audit_log` row: `event`/`ts`/`action`/`actor`/`channel_id`/`client`/`detail`, plus the `row_id`/`row_hash` anchor pair (BACKLOG #1198) that lets a collector tie the copy back to the row it came from and detect a gap in the chain | JSON | emitted after the row is durably committed and **outside** the store write lock; rides stream 1's handlers | shipping audit evidence to a SIEM so it survives a host compromise | inherits stream 1's | inherits stream 1's | `detail` is passed through the `safe_text` PHI chokepoint **before** it leaves the process; `client` is forwarded verbatim as a discrete field so a SIEM can index it. The `row_hash` anchor carries no PHI directly, but on a **keyless** store it is a plain SHA-256 whose other preimage members travel in the same record or the one before it, so a reader of the forwarded stream could test offline guesses at a span `safe_text` cut; it is a keyed MAC once the store cipher is active. Best-effort: a logging failure is caught, never raised into the audit write. **Pinned to `INFO`** — it is emitted even at `[logging].level = WARNING` |
| **4. Off-box syslog/SIEM forwarder** — the shared **transport** for 1–3 | a copy of every record from 1–3 | `forward_format`, default **JSON** (independent of the stdout format) | the operator's collector (`forward_host`/`_port`) | off-box evidence retention / SIEM correlation | **default-on when a collector is named.** Transport: `udp` (default) / `tcp` / **`tls`** (RFC 5425, CA-anchored, verified by default). `serve` gates the hop on the shared posture gradient before the handler is installed: verified TLS ungated; otherwise loopback / attested ALLOW, non-enforcing WARN, **enforcing REFUSE (exit 2)** — there is no synthetic arm, and [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md) left this cell with no per-hop way to accept the risk at all | the collector's, not the engine's | the identical four filters are installed on this handler, so the forwarded copy is PHI-redacted and credential-scrubbed — but it still carries usernames, connection names, message ids, client addresses and the audit chain. That is the engine's own stated reason for gating the hop |
| **5. `audit_log` table** (SQLite, Postgres, SQL Server) | who / what / **where-from** / when of auth + PHI *access* and admin actions — plus, while `[security].audit_all_authorization_decisions` is on (**default `true`** since BACKLOG #1277, 2026-09-02, which reversed the ADR 0118 §5 `false`; the internal field it desugars to is `audit_all_authz`, whose old `[diagnostics]` TOML spelling is **refused at load** — ADR 0118), an `authz` row for **every** authorization decision including successes. That is the shipped volume of this stream, not an opt-in addition to it: one row per authenticated request on each `require()`-gated route, and this row's retention cell records that **nothing prunes the table** — `actor`, `action`, `channel_id`, `client`, `detail`, `row_hash` | JSON `detail`; **tamper-evident hash chain** over `prev_hash` + the row (the `client` address is **inside** the chained payload — ADR 0150) | the store database | HIPAA §164.312(b) audit controls; incident response; `verify_audit_chain` integrity checks | `GET /audit` requires **`audit:read`**; `GET /audit/export` requires the separate **`audit:export`** and streams CSV with formula-injection neutralisation, recording its own `audit.export` row *before* streaming; `GET /me/security-events` is a per-user view of the same table | **`[retention].audit_days` is reserved and NOT enforced — keep-forever by design** (the audit-retention requirement, ~6 years — **not** chain-breakage; [§8](#8-retention--purge) states the position and cites its source of record) | `detail` is stored **in the clear** (it is not a cipher-covered column): its protection is that writers only ever store filter shapes, counts and ids — never bodies or credentials — plus the store ACL and the volume layer |
| **6. `message_events` table** | the per-message disposition timeline — the **complete** vocabulary is `received`, `routed`, `unrouted`, `filtered`, `transformed`, `delivered`, `failed`, `dead`, `error`, `replayed`, `resent`, `reingressed`, `passthrough`, `passthrough_dropped`, `cancelled`, `edit_resend`, `edit_resubmit`, `viewed`, `not_deployed`, and the ADR 0154 synchronous-reply pair `reply_returned` / `reply_timeout` (names, counts and `waited_ms` only — **never** a fragment of the partner's reply body) (CI asserts this list against the engine's own `MESSAGE_EVENT_KINDS`). `[diagnostics].message_events` can thin the set, but never below the compliance floor `viewed` / `dead` / `error` / `failed` / `not_deployed` / `reply_timeout` | rows: `message_id`, `ts`, `event`, `destination`, `detail` | the store database | operator timeline on the message-detail view; the `viewed` row is the HIPAA PHI-access record | `GET /messages/{id}` under **`messages:view_raw`** + `require_phi_read`; the read itself writes a `viewed` event **and** a `message_view` audit row | no dedicated window — `purge_message_bodies` sets `message_events.detail` to `NULL` in the same transaction that blanks the body, so it inherits `[retention].messages_days` | `detail` is `safe_text()`-scrubbed **then** cipher-encrypted (AAD `("message_events","detail",message_id,ts,event)`). Verbosity gate `[diagnostics].message_events` = `all` (default) / `errors` / `off`, with a **compliance floor that can never be thinned**: `viewed`, `dead`, `error`, `failed`, `not_deployed`, `reply_timeout` are retained at every level (`reply_timeout` is the one row that explains a "we called you and got a 504" complaint, so an instance that thinned its logs would lose exactly the record it is later asked for) |
| **7. `connection_event` table — DEFAULT ON** (`[diagnostics].connection_events = true`) | transport/lifecycle events per connection: `established`, `closed` (reason `eof`, `idle_timeout` or `frame_deadline` — a fixed vocabulary chosen by the listener, never free text), `idle_timeout`, `at_capacity`, `peer_not_allowlisted`, `frame_oversize`, `framing_error`, `peer_reset`, the MLLP listener's `handler_error` (BACKLOG #1619 -- the inbound handler faulted on a frame the listener read cleanly, such as a store outage at the ingress commit; the reason is scrubbed at the source like every other), the DATABASE poll source's `row_undecodable` (BACKLOG #1662 — a polled row the source cannot turn into a body; the reason is scrubbed at the source and names the exception type or the operator's own configured column, never a row value), the FILE poll source's quarantine kinds `file_oversize` / `file_decompress_failed` / `file_content_mismatch` / `file_scan_rejected` (BACKLOG #1621 — a drop moved to `.error`; the reason is a size, a content type or a scrubbed codec or scanner message, never the file name), the inbound-HTTP intake-auth refusals `intake_auth_failed` / `auth_subject_denied` / `auth_rate_limited` (ADR 0154 D6 — peer address and mode only; **never** the credential, a prefix of it, or its length. Each of these also writes a tamper-evident audit-log row — the copy that survives an operator turning this diagnostics stream off), plus the runner's `connection_lost` / `connection_restored`. That is the whole vocabulary, asserted in CI against the literal emit call sites in `transports/` and the pipeline runner **and** cross-checked against the console's own filter tuple. The MLLP, raw-TCP, X12 and HTTP listeners emit these; the **DATABASE poll source** emits `row_undecodable` and nothing else (it dials out, so there is no lifecycle to report and its rows carry a **NULL peer column**); the **FILE poll source** emits only its four quarantine kinds, also with a NULL peer column; the **DICOM inbound C-STORE SCP** emits none — the runner injects the sink onto **every** source (`wiring_runner.py`, over the base-class `on_connection_event` field), so that connector *has* the wiring and simply never calls it — so this stream covers those four listeners plus those poll-source events and the runner's outbound-lane transitions — not literally every connection. A DICOM association's connects and refusals are therefore **absent** from this stream. The **`ISA`/`IEA`-framed X12 inbound** was equally absent until BACKLOG #1665 and is not any more: it emits the same seven kinds as the raw-TCP listener | rows: `ts`, `connection`, `transport`, `direction`, `kind`, `peer_host`, `message_id` (correlation hint), `reason` | the store database, **all three backends** | Corepoint-style transport diagnostics — "did the sender connect, and why did it drop" | `GET /events` and `GET /connections/{name}/events` under **`monitoring:read`** (**not** a PHI permission) with per-channel RBAC — an out-of-scope `connection=` is 403'd *and* audited — server-clamped to ≤1000 rows. `reason` alone is gated on `messages:view_summary` and masked as `****` until the audited per-event `reveal=<id>` act (BACKLOG #2443; the `connection_event.reason` row of §3's PL-2 block says how) | `[retention].connection_event_retention_hours` (its own **hours** window); 0 inherits `[retention].messages_days`; both 0 = keep forever. Plain age `DELETE` (metadata-only) | **`reason` is free text that can carry sensitive fragments.** Defended twice — `safe_exc()` at the source, `safe_text(reason)[:200]` at the store — then cipher-encrypted (AAD `("connection_event","reason",connection,ts,kind)`). Every other column is config metadata; the table is documented **metadata-only** — never a frame, body or HL7 field value. Writes are a pure side observer: a bounded in-memory queue drained by a background task outside any handoff transaction, so a flood can never block a listener or pin a message disposition |
| **8. `alert_instance` table — default on wherever an `[alerts]` notifier exists** | resolvable operator alerts: `connection_stopped`, `queue_buildup`, `lane_stuck`, `message_stall`, `saturation`, `connection_error`, `storage_threshold`, `cert_expiry`, `secret_rotation`, `initial_credential_expiring` (an UNCLAIMED admin-issued temporary password nearing the instant the login gate stops accepting it -- ASVS 6.4.5, BACKLOG #1141; keyed on `user:<the holder's username>`, and the payload is the ISO deadline plus whole hours remaining, repeated in the reason column, never the password), `integrity_drift`, `update_available`, `backup_failed`, `store_privilege_warning` (the store privilege preflight found the store principal over-granted or could not read it -- BACKLOG #305; the payload is the finding, a count and the preflight's summary line, which names the login, the database and role names, never a password or message content), `leadership_acquired`, `dr_activated`, `log_write_failed` (an application-log sink was rolled after a write failure, or is UNWRITABLE and this process's connections were stopped -- BACKLOG #122, ADR 0162; the payload is the sink LABEL, the stage, a `safe_exc` reason and a count of connections stopped, never the record whose write failed), `gcm_invocations` (the per-key AES-GCM invocation bound crossing its 2^31 soft warn — ASVS 11.3.4; its payload carries a one-way `key_id` fingerprint plus counters, never key bytes), `approval_stale_requester` (a dual-control release refused because the requester no longer holds the authority the operation needs -- ASVS 8.3.2, BACKLOG #289; keyed on the approval id, and the payload is that id, the operation key and a closed-set reason slug, never the requester's name or the captured params), `approval_too_early` (a dual-control release refused because it arrived before `[approvals].min_dwell_seconds` -- ASVS 2.4.2, BACKLOG #287; keyed on `approval:<approval id>`, and the payload is that key, the operation key and a fixed reason string, never the approver's or requester's name or the captured params), `ad_reconcile_aborted` (the directory reconciler's mass-revoke breaker tripped and nothing was revoked; the payload is a fixed source label, the abort slug, the probed count and the latched operator explanation), `ad_reconcile_held` (the reconciler is holding accounts whose `userAccountControl` it cannot read, ADR 0195; the payload is the same fixed source label, a closed-set reason slug, the count of undetermined accounts and the latched operator explanation, never a username), `ad_session_revoked` (the reconciler revoked a directory principal's sessions; keyed on that operator account's username, with a `directory_absent`, `directory_disabled`, `directory_undetermined`, `roles_changed` or `scope_changed` reason), `approval_approver_provenance` (a dual-control release went ahead with an approver account created, re-passworded or TOTP-enrolled after the request -- BACKLOG #315; keyed on `approval:<approval id>`, and the payload is the operation key and the closed-set change slugs, never a username or the captured params), `administrator_granted` (the built-in Administrator role was granted by account creation, a role change, or a directory group newly mapped to it -- BACKLOG #315; keyed on `user:<username>` or `ad-group:<group>`, with the grant route and the granting administrator's username), `intake_paused` (the engine paused intake because the staged backlog went over `[inbound].max_staged_depth` or the SQLite volume fell below `[retention].min_free_disk_mb` -- BACKLOG #290; keyed on `intake:staged_depth` or `intake:disk_floor`, and the payload is the reason, a count or a MiB figure, its limit and the store backend's name, never message content), `config_changed` (a start loaded a config whose fingerprint differs from the store's baseline -- vault BACKLOG #2597; keyed on `config:<first 12 hex of the new digest>`, and the payload is the two digests, the node and engine shard labels, and the action, actor username and time of the row the older digest came from, never the config directory, a git commit or message content). The five reachable **inverse** signals — `connection_restored`, `leadership_lost`, `dr_released`, `store_privilege_clean`, `intake_resumed` — are never rows here: `_record_state` routes an inverse through `_AUTO_RESOLVE` to `resolve_alert_instances_for`, never to `upsert_alert_instance`. (A sixth mapped key, `connection_started`, is emitted by no code path today.) | rows: `event_type`, `connection`, `severity`, `status`, `first_seen`, `last_seen`, `count`, `reason`, `acked_by`, `acked_at`, `resolved_at`, `suspended_until`, `escalation_tier` | the store database, **all three backends** | the operator alert list — acknowledge / resolve / suspend. Durable state is recorded **before** any suppression or throttle return, so a muted alert still leaves a record | `GET /alerts/active` under **`monitoring:diagnose`** (**not** a PHI permission) with the same per-channel scope, and `reason` alone gated on `messages:view_summary` and masked as `****` until the audited per-alert `reveal=<id>` act (BACKLOG #2443; the `alert_instance.reason` row of §3's PL-2 block says how); ack/resolve/suspend/**resume** are POSTs on the same tier, and the separate read-only `GET /alerts/rules` view sits on its own gate | shares the connection-event window; **only RESOLVED instances are DELETEd**, by `resolved_at` — an open or acknowledged condition is never aged out from under an operator | **`reason` is free text** taken from the event's `detail`/`reason`: `safe_text(reason)[:200]` then cipher-encrypted (AAD `("alert_instance","reason",event_type,connection)` — the de-dup grain, so one AAD covers both the INSERT and the re-fire UPDATE). |
| **9. `response` rows with `kind='ack_sent'` — DEFAULT ON** (`[diagnostics].response_sent = true`) | the ACK/NAK the engine returned to an inbound sender, under a sentinel destination `\x1fack:<inbound>` | rows: `ack_code` (`AA`/`AE`/`AR`/`CA`/`CE`/`CR`), `ack_phase` (`decode`/`parse`/`strict`/`ingest`), `outcome`, `body`, `detail` | the store database | "what did we actually reply, and why" — the operator's answer to a sender disputing an ACK | `GET /messages/{id}/responses` under `messages:read` + `require_phi_read`; the `body` only for a caller who also holds `messages:view_raw` and `messages:view_summary`; every read writes a `response.read` audit row | `body`, `detail` and `resp_headers` are set to `NULL` in place by `purge_message_bodies` on the message-body window, on all three backends | **PHI fail-safe:** the ACK **body** is stored **only when the store cipher is active** — on a keyless store it is `NULL` rather than plaintext — and every NAK passes no body at all, so the offending field value is never persisted. The disposition metadata (`ack_code`/`ack_phase`/`outcome`) is non-PHI and always captured; `detail` is `safe_text`-scrubbed, 200-char bounded and encrypted |
| **10. `[alerts]` webhook transport** (off by default — `webhook_url` unset) | one HTTPS POST per alert, carrying every non-underscore event key as JSON | JSON | the operator's webhook endpoint (Slack/Teams/PagerDuty/custom) | operator notification | **`https` only** — a plaintext `http://` webhook URL is refused at construction unless the `MEFOR_ALLOW_INSECURE_TLS` escape is set (and then a warning is logged); since #329 this path routes that escape through the clamped `weakened_tls_escape_permitted(posture)` (the instance posture threaded from the API lifespan), so on an enforcing-PHI instance the escape is inert and a cleartext webhook POST stays refused — the same clamp as the connectors, no longer the raw escape. Redirects are refused; an optional `webhook_allowed_hosts` egress allowlist gates the host | the endpoint's | **carries the alert's `detail`/`reason` free text** (`safe_exc()`-scrubbed at the emit sites, but **not** re-run through `safe_text` on this path). Internal `_`-prefixed keys (per-rule recipients, rule id, cooldown) are stripped before send, so recipient addresses never cross the wire |
| **11. `[alerts]` SMTP transport — operator alert list** (off unless `email_smtp_host` + `email_from` + ≥1 `email_to`) | one email per alert; default subject `[MessageFoundry] <SEVERITY> <type> — <connection>`, default body every non-underscore event key as `k: v` | plain text (always kept — never HTML-only); optional HTML alternative | the operators' mailboxes | operator notification | `smtp_allowed_hosts` egress allowlist; the SMTP password comes from `MEFOR_ALERTS_EMAIL_PASSWORD` or a `[secrets]` provider, never the config file; per-send timeout `email_timeout` | the mail system's | carries the same `detail`/`reason` free text as the webhook. #138 operator templates are constrained to a **closed non-PHI variable allowlist** validated fail-closed at config load. **Transport posture:** `send_plain_email` builds an explicit **verifying** context (chain + hostname + strict RFC 5280, TLS 1.2 floor) via `tls_policy.build_smtp_tls_context()` and passes it to `starttls()`, anchored to the OS roots, `[alerts].email_tls_ca_file`, or `[tls].internal_ca_file` — the same factory the EMAIL and DIRECT *message destinations* use, so all three SMTP cells now share one policy ([#323](BACKLOG.md), closed 2026-08-02). Before that this call passed **no** context and Python's stdlib default applied (`ssl._create_stdlib_context` **is** `ssl._create_unverified_context` — `CERT_NONE`, `check_hostname = False`), leaving the hop encrypted but unauthenticated. There is still **no hop gradient or attestation on this path** — unlike the connectors, this cell is constructed outside the `active_hop_posture` scope, so its deviations (`email_use_tls = false`, or `email_tls_verify = false`) are gated by a `[security].allow_unverified_alert_smtp_tls` **acknowledgment switch at the serve gate** rather than by the clamped escape: on an enforcing PHI instance `serve` refuses to start without it, and permits + `AUDIT`-logs the start with it. Both deviations are named by `security_loosenings()` and reported by `messagefoundry check`'s `alert-smtp-tls` advisory |
| **12. Per-user security-event SMTP notifier** — **posture-mandatory on a PHI instance** | `account_locked`, `login_after_failures`, `password_changed`, `password_reset`, `email_changed`, `roles_changed`, `username_changed` (the directory renamed the account -- BACKLOG #2017), `temporary_credential_expiring` and `temporary_credential_expiring_issuer` (an unreplaced temporary password nears its deadline; the first goes to the holder, the second to the administrator who issued it -- BACKLOG #2007), `account_disabled`, `mfa_enabled`, `mfa_disabled`, `mfa_credential_removed`, `notify_email_set`, `admin_action_new_ip`, `login_new_ip` (a sign-in from a first-seen client address -- BACKLOG #288), `federated_identity_bound`, `federated_identity_unbound`, `first_administrator_takeover` (`provision-admin` took over an existing roleless account; sent to the address it held before -- BACKLOG #2019), `recovery_code_used`, `account_created` (an administrator created the account; sent to the address it was created with, carrying its role ids -- BACKLOG #315) | plain-text email | the **affected user's own** mailbox, except `temporary_credential_expiring_issuer`, which goes to the mailbox of the administrator who issued the password | ASVS 6.3.5 / 6.3.7 out-of-band notification of security-relevant account changes, and ASVS 6.4.5 reminders before a temporary password lapses | shares stream 11's SMTP transport and therefore its verifying context and its `[alerts].email_tls_*` knobs — note this is a **separate call site** (`pipeline/security_notify.py`), plumbed in its own right rather than inheriting by accident. On a PHI instance with auth enabled `serve` **refuses to start (exit 2) under `[security].enforcement = enforce`** when no effective channel exists; the explicit, **audited** opt-out is `[alerts].security_notifications_required = false` | the mail system's | the body carries the account username, a fixed description, optionally the failed-attempt count, the new email on file (or the new notification address, when an administrator or `provision-admin` moved it), the old and new username on a rename, a temporary password's deadline (and, in the issuer's copy, the holder's username), whether the change came from the directory, or the remaining recovery-code count, and the source IP — **no message data, no secrets**. Dispatch is a bounded background queue; a failed send is logged, never raised (the event is still in `audit_log`) |
| **13. `LoggingAlertSink` fallback** (when no `[alerts]` transport is configured) | every alert **this state-less sink implements**, at `WARNING` — `leadership_lost` / `dr_released` at `INFO`, `store_privilege_clean` at `DEBUG` (the preflight has already logged the clean read at `INFO`), and `connection_restored` is a **deliberate no-op** (a recovery needs no page and there is no instance to auto-resolve), so a lane recovery produces no record on this stream at all. `intake_paused` / `intake_resumed` are implemented here but never raised without a notifier: the intake monitor's own `intake PAUSED` WARNING and `intake RESUMED` INFO lines are the record on this stream (BACKLOG #290), so no `ALERT intake_*` line appears | — | folds into stream 1 | so alerts are never silent | inherits stream 1's | inherits stream 1's | includes the `detail`/`reason` free text, and therefore inherits stream 1's filters, ACL, forwarder and retention |

| **14. `messagefoundry support-bundle` archive** (operator-invoked CLI, never automatic) | `app-log.txt` — the trailing **500** lines (`DEFAULT_LOG_TAIL_LINES`) of the configured app log — plus a secret-free `config-summary.json` (counts/names only) and a metadata-only `status.json` | text members inside a `.zip` | the operator-supplied `--out` path — **outside** the store and outside the NSSM DataDir ACL | hand-off to support: this stream exists precisely to leave the box | **none once written.** Filesystem permissions on wherever `--out` points are the only control; the CLI carries no RBAC and writes no audit row | **none** — never swept by `[retention].app_log_days` or anything else; the operator owns the file | Inherits stream 1's residual and passes a **fourth** redactor, `support/redact.py::redact_log_line` — **not** the three handler filters. Treat a bundle as a copy of stream 1, at stream 1's PHI class. **That residual includes an operator USERNAME**, which this engine's own settings classifier (`config/wiring.py::_SECRET_SETTING_KEYS`) calls a credential — so a bundle is not "secret-free", and the CLI help states the residual rather than claiming it away (BACKLOG #1475; why the username class is deliberately not scrubbed is recorded in `tests/test_log_redaction_secret_domain.py`) |

**Not in this inventory, and why.** The **Windows tray** (`messagefoundry.tray`, ADR 0113) ships *inside* the wheel as the `messagefoundry-tray` gui-script, and its `_setup_logging` attaches a `RotatingFileHandler` to the **root** logger at `INFO` writing `%LOCALAPPDATA%\MessageFoundry\tray.log` (1 MB × 2 backups). It is a **separate client process** making tokenless `/health` + `/ui` probes, so by design it carries **no workload data, no PHI and no credentials** ([TRAY.md](TRAY.md)) — but note an exception it logs with a traceback can still quote engine reply text or a credential, which is why its handler has carried the engine's PHI, credential and control-character scrub since BACKLOG #2092 (`tray/logscrub.py`; it leaves out the OIDC query-string filter, since the tray holds no OIDC credential and keeps httpx's request-URL lines out), its access control is the interactive user's own profile ACL (it is **outside** the NSSM DataDir `icacls` lockdown), and **no `[retention]` window touches it** — size rotation only, never aged out. `GET /metrics` (Prometheus gauges/counters) and the `/ws/stats`
WebSocket are **live telemetry, not log records** — neither retains a per-event record. The standalone
**`tee` MLLP relay** is a separate application shipped in this repo with its own SQLite store and its own
logging (`relay_log` — direction/leg/control id/type/size/outcome/ack code + a sanitized 500-char detail,
never a body; and `relay_capture`, whose `raw` column holds the **full message** and is written only when
`--capture-bodies` is passed). Its process logging is a bare `logging.basicConfig` to stderr with **none**
of the filters above. It is **out of scope for this section** — but treat a
`--capture-bodies` capture store as a PHI-at-rest location on the terms of
[§2](#2-where-phi-lives--data-at-rest-inventory).

The **opt-in ADR 0087 sandbox worker** (`[sandbox].mode = "subprocess"`, default `"off"`) is **not** an
exclusion, and this paragraph is the single statement of how its output reaches stream 1 — the code
docstrings link here rather than restate it. Two independent mechanisms cover it:

- **Inside the child.** It calls `configure_stderr_logging`, which installs the same four filters on
  its own stderr handler (BACKLOG #1054), so a `WARNING`+ record emitted there by admin-authored
  Router/Handler code, or by a library it pulls, is redacted and CR/LF-scrubbed at the source.
  Redaction is a property of the **handler**, so this is a second installation of the chain rather
  than something the child inherits along with a file descriptor.
- **In the engine parent (ADR 0176, BACKLOG #343).** The child is spawned with
  `stderr=subprocess.PIPE` — it no longer *inherits* stream 1's sink — and a per-worker drain thread
  turns those bytes into engine log records attributed to the inbound, the child pid and the worker
  generation. **Content is relayed at `DEBUG` and only at `DEBUG`.** At `INFO` and above the engine
  emits an attributed, rate-limited `WARNING` notice carrying the identity and a line **count** and no
  content, so the never-log-bodies rule holds **by construction**: a Handler that `print()`s a message
  body cannot put that body on a default-level log, because no call site above `DEBUG` carries child
  stderr content at all. Suppressed lines are counted and reported by the next notice, never dropped
  silently. Relayed records ride stream 1's own handlers, so they are redacted and scrubbed on
  stream 1's terms; the relay additionally scrubs control characters itself, because "one child write
  is one log record" is the drain's own framing contract and cannot depend on the host process's
  logging configuration. **Residuals, stated rather than implied — at least these:** raising the service to `DEBUG`
  to read that content puts full Handler output on stream 1, at stream 1's PHI class — the same
  posture as any `DEBUG` run; and the child's own root logger is pinned at `WARNING` when the worker
  starts, so `DEBUG` shows every `print`/raw write plus the child's `WARNING`+ records, and never the
  child's own `DEBUG`/`INFO` records, which the child never emitted. **A byte-cap truncation was
  rejected, not overlooked:** truncating an HL7 v2 message to its first N bytes keeps MSH and PID and
  discards the clinically bulky remainder, so it preserves precisely the most identifying part of the
  record (ADR 0176).

---

## 8. Retention & purge

**`[BUILT]`** (except `audit_days`, reserved by design)

Enforced by the engine's async retention task
([pipeline/retention.py](../messagefoundry/pipeline/retention.py), `RetentionRunner`). It runs once per
process, independent of the message graph (so it survives config reloads), and never blocks the event
loop. **Every purge in the runner is backend-agnostic** — it is constructed with the `Store`
protocol and started by the Engine when `[retention]` is configured. Its one backend branch purges
nothing: the low-disk floor `[retention].min_free_disk_mb` (BACKLOG #290, default-on at 1024 MiB)
measures free space on a **SQLite** store's volume only, and is skipped on SQL Server and Postgres.
Because that floor ships on, a SQLite store starts the runner on stock settings. Config:
[CONFIGURATION.md](CONFIGURATION.md#retention).

**"Off by default" is no longer the whole truth on a PHI instance.** The raw `[retention]` fields do
still default to `0`, but `serve` applies a posture gate on top of them:

- On **any** PHI instance, under **both** `[security].enforcement` dials, each **unset** window that
  carries an auto-bound is **defaulted to 30 days** at startup, and the defaulted settings are named
  on stderr. The three are `[security].delete_message_bodies_after_days`,
  `[retention].dead_letter_days` and `[retention].reference_snapshot_days`, generated from
  [config/retention_classification.py](../messagefoundry/config/retention_classification.py)
  (`auto_bounded_windows`) rather than listed at the gate.
- These bullets used to say the auto-bound applied only to a *non-enforcing* PHI instance, and that a
  PHI instance under `enforcement = enforce` with a PHI-body window unbounded **refused to start (exit
  code 2)**. Both halves were wrong about the shipped code: the auto-bound in
  [`__main__.py`](../messagefoundry/__main__.py) is keyed on the retention opt-out alone
  (`if not settings.retention.allow_unbounded_phi:`), not on the enforcement dial. A site that read
  the old text and deliberately left a window unset — expecting the refusal to hold the boot until
  someone chose a number — would instead get a started instance that begins purging PHI bodies at 30
  days.
- What survives is the fail-closed path for an **explicit** `0`. An explicitly-zeroed window is not
  auto-bounded, and `serve` then **refuses to start (exit code 2)** under `enforcement = enforce`, or
  warns and continues under `warn`. So "unbounded by accident" is still prevented; "unbounded by
  inattention" becomes "30 days by inattention".
- The classified windows that carry **no** auto-bound are never silently defaulted.
  `[retention].state_max_age_days` is the clearest case: it keys on a timestamp that only moves on a
  **write**, so a silent default would delete data a Handler is still reading.
  `[retention].search_preset_days` sits under the same 2026-07-30 ruling, though it has keyed on last
  use since #306. The others are excluded for their own per-window reasons, recorded alongside the
  classification.
- They are not optional either (owner ruling R4 (b), 2026-09-24; BACKLOG #1967). Each such tier that
  is unbounded needs a window or its **own** audited acknowledgement, a `[security]` switch named
  per tier in [CONFIGURATION.md](CONFIGURATION.md#retention). Under `enforcement = enforce` a tier with
  neither **refuses to start (exit code 2)**. Under `warn` it warns. A start under an acknowledgement
  writes a WARNING-level `AUDIT:` line naming the tier. For transform state the acknowledgement is the
  safe answer, not a window, until state has an eviction key that a read moves (#1188).
- The explicit, **audited** opt-out is `[security].allow_keeping_phi_indefinitely = true`, which
  suppresses the auto-bound **and** downgrades the refusal to a loud audited warning.
- The canonical operator-facing home of the message-body window is now
  **`[security].delete_message_bodies_after_days`**; its *model* default is 30, but the desugar
  is **presence-gated** — only an EXPLICITLY-set switch is written through — so an **unset**
  switch leaves `[retention].messages_days` at **0**, and the posture gate above (auto-bound /
  refusal) is what actually bounds a PHI instance. An explicitly-set value writes through onto
  `[retention].messages_days`. `[retention].dead_letter_days` stays at its own home.

So a PHI instance cannot run with PHI-body retention "off" **by accident** — an unset window is
bounded for you. It can still be run that way deliberately: an explicit `0` plus the audited opt-out
under `enforce`, or an explicit `0` alone under `warn`, which warns and starts.

**Thirty days is the engine's floor against an accidentally unbounded window, not a retention
policy.** The engine picks that number; a deploying site with a retention obligation of its own must
set each window explicitly, because an auto-bounded window is a number nobody decided.

**The pass itself.** It is **leader-gated twice** — at entry and again immediately before the purges, so
a node demoted mid-pass never nulls PHI as a stale ex-leader. An optional between-phase wall-clock cap
(`[retention].max_pass_seconds`, default 0 = off) bounds one pass: once hit, the remaining phases are
**skipped and left due** (their last-run markers are not advanced), so work is deferred, never dropped;
a running `VACUUM` is never interrupted. **Each pass that does real work writes exactly one
`retention_purge` `audit_log` entry** with the cutoffs, counts and per-connection overrides — no message
content, no PHI.

### What each pass does, per backend

Every cell is one of **enforced** (the engine performs it on this backend), **no-op (DBA-owned)** (the
method exists for `Store`-protocol completeness and deliberately does nothing), or **DBA-delegated**
(the engine refuses and hands the operation to the DBA).

| Operation | Window setting | Mechanism | SQLite | SQL Server | Postgres |
|---|---|---|---|---|---|
| `purge_message_bodies` | `[security].delete_message_bodies_after_days` → `[retention].messages_days` (+ per-connection overrides) | NULL/blank **in place**, keeping the message **row** (counts/disposition/audit) while blanking its PHI columns — `metadata` included | enforced | **enforced** | **enforced** |
| `purge_dead_letters` | `[retention].dead_letter_days` (+ per-connection overrides, which key on `destination_name` and so apply to outbound rows only — an ingress/routed/response row takes the global window) | NULL/blank in place on DEAD rows at **every** stage, not only outbound: a dead `ingress`/`routed` row holds the full raw body and `replay` re-queues it from that payload, so it is replayable-until-purged in the same sense a dead outbound row is. The stage predicate is dropped rather than widened to a list, so a stage added later is covered by construction | enforced | **enforced** | **enforced** |
| `purge_state` (`state.value`) | `[retention].state_max_age_days` | `DELETE` by `set_at` | enforced | **enforced** | **enforced** |
| `purge_connection_events` (incl. `connection_event.reason`) | `[retention].connection_event_retention_hours`; 0 inherits `messages_days` | `DELETE` by `ts` (metadata-only) | enforced | **enforced** | **enforced** |
| `purge_search_presets` (`search_presets.criteria`) | `[retention].search_preset_days`; `0` = keep forever | `DELETE` by the null-safe greater of `updated_at` / `last_used_at` — whole row (the criteria *is* the payload). Keys on last-**used** (#306); a row predating `last_used_at` (NULL) ages out on `updated_at` alone | enforced | **enforced** | **enforced** |
| `purge_reference_snapshots` (`reference.value` + its key columns) | `[retention].reference_snapshot_days`; `0` = keep forever | `DELETE` of whole rows for a set config **no longer declares** whose `reference_version.synced_at` predates the cutoff — eligibility is re-asserted **inside** the delete (a config reload can commit a fresh snapshot between the decision and the statement). The `reference_version` pointer **survives** with its version bumped to `purged:<v>` and `row_count = 0`, which is what makes a cluster follower converge — `converge_reference_cache` only reloads a set whose version CHANGED, so leaving it would let a follower serve purged PHI from RAM until restart, and deleting the pointer is worse (converge only adds names present in a fresh read). **Orphan-only** — a declared set is never purged | enforced | **enforced** | **enforced** |
| `purge_alert_instances` (incl. `alert_instance.reason`) | same window as connection events | `DELETE` by `resolved_at`, **RESOLVED instances only** | enforced | **enforced** | **enforced** |
| `strip_embedded_documents` | per-inbound `prune_documents_after` + `prune_documents_min_bytes` (**no global default** — nothing is stripped without an override) | in-place strip of bulky base64 documents; sets `messages.documents_pruned` | enforced | **enforced** | **enforced** |
| Streaming-attachment release (`release_message_attachments`) | rides the two body windows | refcount decref + GC at 0, plus a startup `sweep_orphan_attachments` | enforced | **enforced** | **enforced** |
| Application **log-file** sweep + compression (`app_log_days`, `app_log_compress_days`) | `[retention].app_log_days` / `[retention].app_log_compress_days` over `[logging].log_dir` | `DELETE` of `.log`/`.txt` files by **mtime** (content never read), plus optional in-place **gzip** of aged files — free-space prechecked, and the archive is decompressed off disk and compared byte-for-byte **before** the original is removed (a failure keeps the original). Bytes are read to compress/verify but never logged or exported; the archive inherits the source mtime, so the delete window still ages it out | enforced | enforced | enforced |
| `wal_checkpoint` | `[retention].wal_checkpoint_seconds` | `PRAGMA wal_checkpoint(TRUNCATE)`; PASSIVE, which does not truncate, while a DR snapshot copy runs (BACKLOG #1937) | enforced | **no-op (DBA-owned)** — log management is `.ldf` backup / recovery model | **no-op (DBA-owned)** — checkpointer/autovacuum |
| `vacuum` | `[retention].vacuum_at` (a daily clock time, **not** a cron) | `VACUUM` — locks the whole DB, so off-peak; off by default | enforced | **no-op (DBA-owned)** — space reclamation is a DBA operation | **no-op (DBA-owned)** — autovacuum |
| Size threshold (advisory) (`db_status`) | `[retention].max_db_mb` | `storage_threshold` alert + `WARNING`; **never** auto-deletes | enforced | **enforced** — `db_status().size_bytes` is implemented (`SUM(size)` over `sys.database_files`) | **enforced** — `pg_database_size()` |
| DB-tier DR snapshot (`snapshot_to`) | `[backup].*` | `.mfbak` chunked-AEAD archive | enforced | **DBA-delegated** — `snapshot_to` raises `DbaDelegatedError`; the BackupRunner falls back to a **config-only** archive, or skips when `[backup].config_only_on_server_db = false` | **DBA-delegated** — same |

Three further prunes run **outside** the retention runner: `processed_files` (age/count prune, driven
from the wiring runner), expired sessions (`purge_expired_sessions`, driven from the auth layer), and
**uploaded files** (`uploaded_file.body` / `uploaded_file.meta`) — auto-pruned after
`[store].uploads_retention_days` (default **30**, `ge=1`; defaults-ON whenever `[store].uploads_dir` is
set) by a periodic `UploadRetentionRunner` plus an opportunistic save-time sweep, a pruned pair
`upload.prune`-audited with the gaps stated in [§2](#2-where-phi-lives--data-at-rest-inventory) (ASVS 5.2.4, #291).

**The only genuinely DBA-delegated half.** On the server backends, **WAL-checkpointing, space
reclamation (`VACUUM`) and the DB-tier backup** are DBA operations — the engine's methods are documented
no-ops or raise `DbaDelegatedError`. Setting `wal_checkpoint_seconds` / `vacuum_at` on SQL Server or
Postgres therefore does nothing. **Everything else above — every PHI purge the requirement cares about —
is enforced by the engine on all three backends.**

### What `purge_message_bodies` actually blanks

More than the historical "raw/summary/error". Eligibility is `received_at < ` the per-connection-or-global
cutoff **and** no `queue` row still `pending`/`inflight`, so at-least-once is preserved — a dead row
stays replayable (re-queueing its *own* stored payload) until `purge_dead_letters` takes it, which is why
the two windows are independent. In **one transaction** the pass:

- sets `messages.raw` to `''` and `messages.summary`, `messages.error` and `messages.metadata` to
  `NULL` — all four in **one** statement, so operator-attached metadata can never outlive the body it
  describes (ASVS 14.2.7). Its guard is `raw <> '' OR metadata IS NOT NULL`, so a message purged by a
  **pre-upgrade** engine — blank `raw`, metadata intact — is swept on the first pass after upgrade and
  **counted**, so that historical sweep lands in the `retention_purge` audit row like any other;
- blanks `queue.payload` and `queue.last_error` for **done/cancelled** outbound rows;
- sets `message_events.detail` to `NULL`;
- sets `response.body`, `response.detail` and `response.resp_headers` to `NULL`;
- releases `shared_body.body` refs (SQLite — decref, GC at 0) and decrefs the message's streaming
  `attachment_chunk.ciphertext` blobs (all three backends), so whichever purge blanks the **last**
  replayable row frees the shared body / attachment.

#### What nulling `messages.metadata` costs — three accepted consequences

`messages.metadata` carries the operator-attached `SetMeta` bag **and** the engine's correlation-lineage
keys, so blanking it degrades three paths that read it *after* the window. All three are **accepted, not
prevented**, and each is pinned by a regression test. The alternative — retaining PHI past its retention
window purely so a replay can be richer — is precisely the defect ASVS 14.2.7 exists to close.

1. **Lineage re-bases.** An edit-and-resend or passthrough re-ingress whose *origin* has been purged
   reads `parent_meta = {}`: `correlation_depth` restarts at 1 and `correlation_root_id` falls back to
   the origin id. `correlation_id` and `edited_from` still point at the origin, so the link is not lost —
   only the depth/root derivation re-bases. The depth cap still bounds any single live chain; it is not
   a lifetime bound *across* a purge.
2. **`dynamic_headers` vanish on a late replay.** A `dead` row replayed after its message was purged
   delivers with **no** `dynamic_headers` (#68) rather than the headers of its first attempt — `dead`
   rows stay replayable until `purge_dead_letters` takes them, which is a *later* window than the body.
3. **`response_view` empties on a late replay** — the sharper edge. A replayed `dead` **routed** row of a
   re-ingressed loopback message transforms with no captured partner replies, so the Handler can emit
   **different content**, not merely different headers. Operators replaying long-dead rows across a
   retention boundary should expect a re-derived, not a reproduced, message.

### Tiers with **no** retention today — the honest gaps

| Tier | Status |
|---|---|
| `reference.value` (a **declared** set), and the `reference.name` / `reference.version` / `reference.key` columns that key it | **orphan-only** coverage. `purge_reference_snapshots` bounds a set config has DROPPED; a set still declared is never purged whatever its age, because its snapshot is live data. The wired-set case remains unbounded — the honest gap. The key columns are named here because they ride the same delete and therefore inherit the same residual: §2 rates them **PL-4** and rates `value` **PL-2**, but a snapshot row may be patient-keyed, so the key column is where that identifier would sit |
| `queue.payload` (stage=`ingress`/`routed`/`response`, **permanently PENDING**) | **no purge reaches it, but the tier is now narrow.** The **DEAD** half was already closed: a dead ingress/routed row rides `[retention].dead_letter_days` on all three backends, because `replay` re-queues such a row from its own payload exactly as it does a dead outbound row. What is left is the row that never becomes dead and never drains. `purge_message_bodies` holds any message with a `pending`/`inflight` queue row ineligible — correctly, since at-least-once must not lose an undelivered body — so such a row pins **both** its own payload and its message's `messages.raw`, with no window. **The removed-inbound case is closed at bring-up (BACKLOG #1612).** `Engine._start_graph` now runs a third sweep, `dead_letter_missing_inbounds`, beside `dead_letter_missing_destinations` and `dead_letter_missing_handlers`: it dead-letters every pending/in-flight `channel_id`-keyed row whose inbound is absent from the whole deployment's config, which puts those bodies on the `dead_letter_days` window and leaves them replayable in the meantime. **What remains unbounded is the RELOAD window, deliberately.** A `reload()` that drops an inbound does not run `_start_graph`, and the runner's three missing-inbound arms (`_process_ingress_item`, `_process_routed_item`, `_process_response_item` in `pipeline/wiring_runner.py`) still re-pend with `RetryPolicy(max_attempts=None)` — retry forever — so an ACKed-but-never-attempted message is never dropped for outliving a reload that may restore its inbound. Those rows stay pending, and unpurgeable, until the next restart sweeps them. Distinguishing "the operator is mid-reload" from "this lane is never coming back" *without* a restart is the decision this row still does not pre-empt |
| `[backup].destination/*.failed` and `*.part` non-canonical archives | no window, and that is the price of the keep-N fix rather than an oversight. A backup is written to `<canonical>.part` and only renamed onto the canonical name once it has passed every configured check (ADR 0049, BACKLOG #1587), because the canonical name IS the keep-N candidate set — an archive that failed its restore-verify holding that name spent a retention slot and evicted an older **good** copy. So a `.failed` archive (kept deliberately, for diagnosis) and a `.part` (left by any abort between the write and the rename — a dropped UNC share, a verify cancelled when the engine stops mid-backup, a failed rename) are both invisible to the prune, which means **no engine path expires either**. On a box that restarts during its backup window the `.part` files accumulate at one full-size archive per incident. Each is sealed under the store DEK exactly like a good archive, so the at-rest protection is identical and only the retention bound differs; clearing them is the operator's. The predecessor was worse, not better: those same aborts used to leave a **truncated** file wearing the canonical name, which keep-N then counted as a good backup |
| `mefor-backup-*` / `mefor-verify-*` staging dirs | no window. Where these dirs live, what the engine applies to them, and how the next backup's lock-proven sweep removes what a crash leaves are stated once, in §2's row (BACKLOG #1174). That sweep runs only when a backup runs, so it is not a window, and §2's row lists what it leaves unbounded, at least. `verify_after_backup` (default `true`) still decrypts a full archive back out on **every** run. On a server-DB store each run's dir in `.mefor-staging` must be owner-only or the run refuses, but the blocks a removed file freed are still covered only by the operator's volume encryption: restrict the destination to the service account and encrypt its volume ([§10](#10-secure-deployment--operations-checklist)). A standalone verify stages in the OS temp dir instead, so there the cover is FDE on the temp volume ([§10](#10-secure-deployment--operations-checklist)) |
| `mefor-restore-*` staging dirs | no window on a clean exit — the `TemporaryDirectory` unlinks, and a restore is an operator-driven one-shot rather than a scheduled repeat, so nothing accumulates. It survives a crash or `SIGKILL`, and unlike the backup and verify staging above no sweep removes it. The engine applies its file ACL here (`_secure_file` on the staged tar and on the extracted store), so the operator's directory ACL is the backstop rather than the only control. If the teardown itself fails -- on Windows, a scanner or the indexer still holding the extracted store open -- `restore` exits non-zero as `restore failed (cleanup)`, names the directory, and leaves the restored store and bundle in place rather than rolling them back; the directory still holds the decrypted archive and store, and is the operator's to delete once nothing holds it open (BACKLOG #1717) |
| File-connector output / spill dirs (`.hl7`, `.processed`, `.error`) | no window, and no engine sweep of any kind — `pipeline/retention.py`'s only filesystem pass is `_sweep_app_logs`, which scans the log directory alone. These are operator-configured output paths, so the engine deleting from them would be deleting data an operator or a downstream system owns. On a first deployment they would accumulate plaintext **PL-1** bodies indefinitely; the cover is the operator's: volume or share encryption plus an ACL ([§10](#10-secure-deployment--operations-checklist)) |
| Test-harness stores (the [harness table](#the-test-harnesss-own-at-rest-data-harness) in §2) | no engine sweep removes them after a run, and that table states each one's retention. The stores an operator can feed real messages, and which would then accumulate them, are named there: at least the reconcile capture, its compare report and the Compose-fed file drop |
| `users.totp_secret` | no window by design — it lives and dies with the user row |
| `audit_log`, `delivered_keys`, `resend_log` | keep-forever by design (see below) |
| `messages.control_id`, `messages.message_type` | kept for the life of the message row by design (dedup/routing keys) |
| PL-5 substrate (SQLite `-wal`/`-shm`; SQL Server `.ldf` + tempdb; Postgres `pg_wal`) | not application-managed — database/platform lifecycle |

**`audit_days` is reserved / keep-forever by design.** The reason is the **audit-retention
requirement** — 45 CFR 164.316(b)(2)(i) expects ~6-year retention — so audit pruning is deliberately
**not** enforced. The value is accepted (not rejected) so a forward-looking config file still loads.

**This paragraph used to give chain-breakage as the reason, and that was half a fact.** Whether
deleting an `audit_log` row breaks `verify_audit_chain` (§6) depends on *which* rows go. Measured
2026-09-03 under [BACKLOG #1421](BACKLOG.md): an oldest-first delete — the shape an age window would
use — breaks the walk, while a newest-first truncation leaves a prefix that still verifies, which is
the blind spot the anchor exists to cover. So an in-place age window is closed on its own terms, and
archive-first pruning (export → delete → re-anchor the chain) is the path that stays open; it is a
tracked follow-up, and an archive has a contract it must meet.

**The full reasoning is stated ONCE and is not restated here**: the `audit_days` row in
[CONFIGURATION.md](CONFIGURATION.md#retention) is its source of record, and it carries the threat
model, the anchor's semantics, and the archive contract. This section carries the retention-window
inventory; read the reasoning there.

---

## 9. De-identification

**`[BUILT]`** (HL7 v2 first; ADR 0030, PR #440)

The de-identification framework is **built** and **centralized** — do **not** inline ad-hoc de-id
logic; route it through the framework. It lives in [`messagefoundry/anon/`](../messagefoundry/anon/)
and is vendored to `tee/anon/` for the standalone tee relay. The rule, keying and surrogate files
are byte-identical there; the other files are parallel copies, and `tests/test_anon_parity.py`
checks that the two give the same output on a golden and an adversarial corpus. It exists to build **test datasets from real traffic**. It adds
no new dependency.

Properties of the anonymizer:

- **Deterministic, salted keying.** A real value maps to a surrogate under a **secret, per-dataset
  salt**: the same real value yields the same surrogate **within a dataset** (referential integrity
  preserved), **different datasets use different salts** (no cross-dataset linkage), and the salt is
  secret (re-identification-resistant).
- **Width/shape-preserving surrogates** — a surrogate keeps the original's width/shape so the
  scrubbed dataset stays structurally realistic.
- **Field-anchored site-code scrub** — the site-code scrub is anchored to the field, not matched by
  loose string search.
- **Fail-closed contract.** A message with **no parseable MSH / malformed** is **REFUSED** (raises
  `AnonError`) — it never emits an un-scrubbed body.

Surfaces: the **`python -m tee anonymize-captures`** subcommand and the test-harness
`CaptureSink`/corpus hooks. [`scripts/security/scan_forbidden.py`](../scripts/security/scan_forbidden.py)
is now the **single leak-token source-of-truth** (a fail-closed leak gate). HL7 v2 is supported first;
X12/FHIR seams come later.

### What the leak-check refuses, and what it lets through

**A clean result from `anonymize_checked` does not prove the output is PHI-free.** The rule map
rewrites the fields it names. The leak-check then looks at the output, and it refuses in only
these cases:

| The leak-check refuses when | Where it looks |
| --- | --- |
| The message has no parseable MSH, or its structure cannot be parsed (`AnonError`) | The whole message |
| A known partner, vendor or site token, or a routable IP address, survives | The whole message |
| A dashed SSN (`NNN-NN-NNNN`) appears | Fields no rule maps |
| A punctuated US phone number (`NNN-NNN-NNNN` or `(NNN) NNN-NNNN`) appears | Fields no rule maps |
| A CX identifier typed `MR` or `MRN` appears | Fields no rule maps |
| A line no rule can reach: its first field is not a segment id (a lowercase second `msh` line included), or it has no field separator (a wrapped `LEE`, but also a legal empty segment such as `PV2`) | Every line after the MSH header |
| The denylist tables did not load, and the caller passed `require_live_denylist=True` | The token source |

**Everything else in a field no rule maps passes.** That includes a name, a date, an undashed SSN,
a bare ten-digit phone number, an account number and a free-text note. A Z-segment is the common
case, since no default rule names one. A name in `PV1-11`, the temporary location, passes the same
way. The detectors stay narrow on purpose: a broad digit search flags almost every HL7 body.

**A wrapped line can still look like a segment, but its id is never printed.** A line such as
`KIM|F` is read as a segment. Its fields are checked like any other. The report names a segment id
only when the message's HL7 version (MSH-12) defines it, when it starts with `Z`, or when a rule
names it. Any other id is shown as `(unknown segment)`, so `KIM|F` appears as
`(unknown segment)-1`. What still gets through:

- The wrapped text itself passes into the dataset, unless a detector refuses it.
- A fragment that is a real segment id for the message's version, such as `ROL` or `CON`, or that
  starts with `Z`, such as `ZOE`, is still printed.
- With no readable version in MSH-12, any id that some HL7 version defines is printed.
- `LEE|` with only empty fields passes and is not reported at all.

A second MSH line in capitals is checked, and its fields are numbered as MSH fields.

**The coverage report is the record of those fields.** It lists the address of every present
field that no rule mapped, never its value. A caller gets it through `on_report` on both paths, and
inside the `LeakError` on a refusal. `python -m tee anonymize-captures` logs it at INFO once per
run, after it has checked the captures, with a count per address. Read that list before you share
a dataset. Map any field that carries PHI in an `anon.toml` overlay, then run again.

### Dates and locations: mapped, and still NOT Safe Harbor de-identified

**The default rules map these Safe Harbor date and location fields. The output is NOT Safe Harbor
de-identified.** HIPAA Safe Harbor asks for every date element except the year to be removed. It
also asks for geographic units smaller than a state to be removed. The `date` rule kind keeps the year
and fills the rest of the value at the same width. BACKLOG #2248 added it.

| Field | What it holds | Rule |
| --- | --- | --- |
| `EVN-2`, `EVN-6` | Event recorded and event occurred times | `date` |
| `PID-29` | Death date and time | `date` |
| `PV1-44`, `PV1-45` | Admit and discharge times | `date` |
| `ORC-9` | Order transaction time | `date` |
| `OBR-7`, `OBX-14` | Observation times | `date` |
| `PID-12` | County code | `freetext`, the whole field becomes `[REDACTED]` |
| `PV1-3` | Assigned patient location | `freetext`, the whole field becomes `[REDACTED]` |

What the `date` kind does to a value:

- It keeps the four-digit year. Month and day become `01`, and the time and any fraction become
  zeros. An offset becomes `+0000`. So `20260315142233.12-0500` becomes `20260101000000.00+0000`.
- It does not convert the time to UTC. The `+0000` is a placeholder, and the kept year is the
  sender's local year. A real offset would show whether daylight saving time was in effect, and a
  `-0700` from Texas names a region smaller than the state.
- It fills month and day with `01`, not `00`, because strict hl7apy refuses a `00` month. A
  fixture must still replay through a connection that validates strictly.
- It uses no salt. Two sides anonymized apart still carry the same value, so they still match.
- It keeps a TS precision code such as `^S` in the second component.
- It scrubs a value that is not a valid HL7 timestamp to empty. Every group must be in range and
  in ASCII digits, and the year must fall in 1850 to 2199. So a US `03152026` is scrubbed rather
  than kept as the year `0315`. A date field that carries text is never passed through. Nothing
  records that a field was emptied.
- A six-digit `YYMMDD` whose first four digits happen to read as a year and a month, such as
  `201107`, still passes as `YYYYMM`. Its output keeps those four digits.
- It keeps the HL7 null `""` as it is.

**These gaps keep the output short of Safe Harbor, at least:**

- `MSH-7` keeps the full message time. ADR 0030 keeps it on purpose, because the tee uses it to
  match the two sides of a capture. An event time is usually close to it, so a filled `EVN-2` does
  not hide the day.
- The order and accession numbers `ORC-2`, `ORC-3`, `OBR-2` and `OBR-3` are not mapped. Safe
  Harbor counts an accession number as an identifier.
- Other date fields are not mapped. Over the generated corpus, full dates still come through in
  `AIS-4`, `RXA-3`, `RXA-4`, `PR1-5` and `FT1-4`. A date-typed `OBX-5` result, such as a last
  menstrual period, is kept whole by the `OBX-5` allowlist. `GT1-8`, `IN1-18` and `NK1-16` are
  dates of birth with no rule.
- When a site-code prefix of `19` or `20` is configured, the site-code pass rewrites a six-digit
  `YYYYMM` output with a salted code. That value then differs between datasets and is no longer a
  valid date.

Do not shift the dates to fix the `MSH-7` gap. The kept `MSH-7` minus a shifted `EVN-2` gives back
the shift.

### `require_full_coverage`: refuse a field nobody decided

**The switch asks whether every field was decided. It does not ask whether a value is safe.** It is
off by default. Turn it on with `anonymize_checked(..., require_full_coverage=True)` or
`python -m tee anonymize-captures --require-full-coverage`. When it is on, the leak-check refuses a
message that has a present field that meets all three of these:

1. No rule scrubs it.
2. No `anon.toml` `keep` names it.
3. It is not excused by the fixed list. The list holds every set id, `PID-8` (sex) and `PV1-2`
   (patient class). A set id is field 1 of a segment where HL7 2.5.1 types it `SI`, or where
   the newest version does for a segment 2.5.1 lacks. A set id is excused only when it holds
   one to four digits. `PID-8` and `PV1-2` are excused only when the whole value is a code of
   one or two characters, so a coded value with text components is not excused.

A `keep` is how you record a decision to leave a field as it is:

```toml
[hl7]
keep = ["EVN-1", "OBX-2"]
```

A kept field is still scanned for the shapes in the table above, so a dashed SSN in it still
refuses.

**A keep on a field the default rules scrub turns that scrub off.** Keeping `PID-5` to clear a
refusal leaves the patient name in the output as captured. `load_rules` logs a WARNING for each
such field. The line names the field and the kind of scrub it lost, never a value. A keep on a
field with no default rule logs nothing. `python -m tee anonymize-captures` also prints one
`warning:` line that lists those fields, and `--log-level` cannot hide it.

**The tee reads the overlay once, before the first message.** An overlay it cannot read or parse,
or one that breaks the schema, refuses the whole run with one `error:` line and writes no dataset.

**Expect it to refuse conformant traffic until the rule map is finished.** The measured corpus
came from `messagefoundry generate --count 2 --seed 1710`, run for every type: 186 messages. With
the switch on, all 186 refused. Mapping the dates and locations above did not change that count.
It removed 6 of the 72 undecided field addresses, and 553 of the 2,115 undecided fields across the
corpus. Every message still carries at least one coded field that needs a rule or a `keep`:

| Undecided field | Messages |
| --- | --- |
| `EVN-1` | 132 |
| `PV1-10` | 129 |
| `EVN-4` | 103 |
| `OBX-2`, `OBX-3`, `OBX-6`, `OBX-11` | 82 each |
| `PV2-3` | 77 |

Before the date rules, `EVN-2` and `EVN-6` (132 each) and `PV1-3` and `PV1-44` (129 each) topped
this list. Another seed gives other counts. An earlier design picked the benign set by HL7 datatype
instead. It also refused all 186, and it would have passed `PID-12`. That is the county code,
which HIPAA Safe Harbor counts as an identifier; a default rule now scrubs it.

**What the switch does not cover, at least:**

- It never looks at the first MSH line, the header. A kept `MSH-7` date there is never checked.
  A later MSH line is checked like any other segment.
- A blanket `keep` passes whatever it names. It at least leaves a record of that choice in
  `anon.toml`, where a reviewer can see it.
- A short value in a fixed-list field passes. A two-letter code in `PID-8` could still be
  initials.
- The tee applies no rule to an MSH field. A rule for a second MSH line's field counts as decided
  there, but the tee leaves that field as it was and does not scan it.

Note: encryption-at-rest (§3) and log redaction (§7) are **not** de-identification — do not conflate
"we encrypt" or "we redact logs" with "we de-identify."

### AI coding assistance

**`[BUILT]`** (code-only) / **`[ROADMAP]`** (anything beyond)

The IDE AI assistant attaches no message body **on its own** in the MVP; it builds prompts at the
`code_only` data scope. **That is the IDE's behaviour, not an engine guarantee**, and nothing stops a
person from putting a message body into a prompt. What the IDE sends, and what the engine checks,
are stated once, in
[AI.md](AI.md#the-ide-decides-what-the-assistant-sends-and-the-engine-checks-only-a-label).

The `phi` scope is **future** and only reachable over the planned **engine broker** with a **BAA +
zero-data-retention** provider connection; the `deidentified` scope builds on the de-id framework
above (§9). The assistant is RBAC-gated (`ai:assist`) and governed by a central,
environment-clamped policy — full model in [AI.md](AI.md), permission in [SECURITY.md](SECURITY.md).

---

## 10. Secure deployment & operations checklist

**`[MIXED]`**

For operators standing up the engine (see also [SERVICE.md](SERVICE.md)):

- [ ] **Run under a least-privileged service account**; the engine needs no admin rights.
- [ ] **Lock down the data directory** — **SQLite store only:** the engine sets owner-only perms on the DB + `-wal`/`-shm`
      on create (§2); on a **server-DB store this item is the DBA's** (the engine creates no database
      file). Either way, restrict the **directory**, the `[store].uploads_dir`, the `[backup]`
      destination (a server-DB store stages plaintext in its `.mefor-staging` subdirectory) and
      the File-connector dirs to the service account (the file ACL is best-effort,
      and the spill dirs aren't covered).
- [ ] **Enable volume encryption** (BitLocker / LUKS) on the data volume — the required at-rest layer
      under §3.
- [ ] **In-use memory protection is a host requirement (ASVS 11.7.1).** The engine best-effort
      locks + zeroizes the mutable key/plaintext buffers it owns (#198, §3), but full in-use memory
      *encryption* is host/hypervisor territory. **Disable or encrypt swap** on the engine host, and
      **restrict local administrator / debugger access** so no other principal can scrape process memory.
      Where a memory-forensics threat is in scope, deploy on a **confidential-compute / memory-encrypted
      host** (Intel TME/SGX/TDX, AMD SEV) — the stated deployment requirement accepted via
      ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 5.
- [ ] **Keep the API on `127.0.0.1`.** Never `0.0.0.0` without TLS + auth in front.
- [ ] **FastAPI docs are off by default** — `/docs`, `/redoc`, `/openapi.json` are disabled unless
      `[api] expose_docs = true` (they leak the schema, not data); leave them off for any non-localhost
      exposure.
- [ ] **Never run at `DEBUG`** in production.
- [ ] **Treat backups as PHI** — encrypt and access-control them; never copy `*.db` or File-connector
      output to source control, tickets, or shared drives.
- [ ] **Provision the first administrator at the host** with `messagefoundry provision-admin --email`; the engine creates no
      account on its own (see [SECURITY.md](SECURITY.md#provisioning-the-first-administrator-asvs-632)).
- [ ] **Supply secrets via env**, never the TOML (`MEFOR_STORE_PASSWORD`,
      `MEFOR_AUTH_AD_BIND_PASSWORD`, future `MEFOR_STORE_ENCRYPTION_KEY`).
- [ ] **Never feed real PHI to `dryrun`/`generate`** or redirect their output to shared locations (§7).
- [ ] **Treat the harness's real-feed files as PHI.** Before running `python -m harness.reconcile`
      against a real feed, put the capture (`--out`), the Corepoint export (`--corepoint`) and the
      compare report (`--report-json`) in a directory restricted to the account that runs it, on an
      encrypted volume, outside any source checkout, and delete all three once the connection is
      signed off. Do not redirect `compare`'s stdout to a file, ticket or CI log: it prints field
      values. Do not paste a real message into the harness GUI's Compose tab. The harness does none
      of this itself ([§2 harness table](#the-test-harnesss-own-at-rest-data-harness),
      [§12](#12-known-limitations-current-honest)).

---

## 11. Hardening roadmap

Phased by exposure and effort (S ≈ ≤1 day, M ≈ 2–4 days, L ≈ 1–2 weeks). Mappings are to HIPAA
§164.312 safeguards; the direction is aligned with the 2025 HIPAA
Security Rule NPRM, which moves encryption (at rest **and** in transit) and MFA from "addressable" to
mandatory.

> **Forward-alignment only — not a compliance claim.** The **2025 HIPAA Security Rule NPRM** (90 FR
> 898, published Jan 6 2025) is a **proposed** rule and, as of this writing (2026-06), is **not final**;
> its text and effective dates may change. We track it as *forward-alignment* — building toward the
> direction it signals (encryption at rest and in transit, MFA, network segmentation moving from
> *addressable* to *required*) **so we are not caught flat-footed if/when it finalizes** — **not** as a
> statement that MessageFoundry is, or makes its adopter, compliant with the NPRM, the current HIPAA
> Security Rule, or any other regulation. **Compliance is a property of a covered entity's whole
> deployment and program**, assessed by that entity and its counsel — this document is engineering
> guidance, **not** a certification or legal advice.

### Shipped (formerly P0 + P1-1)

Landed in the security-remediation pass and now reflected as built above — listed here only for
traceability:

- **DB + `-wal`/`-shm` owner-only permissions on create** (`_secure_file`, §2) — **SQLite store only**; on SQL Server / Postgres the engine creates no database file and calls `_secure_file` never. Was P0-1.
- **`dryrun`/`generate` redact bodies by default; `--show-phi` to opt in** (§7) — was P0-2.
- **`/docs` `/redoc` `/openapi.json` off by default (`[api] expose_docs`); non-loopback bind refused (unconditionally without auth; otherwise unless `serve --allow-insecure-bind` accepts the Phase-1 no-TLS cleartext risk)** (§10, [SECURITY.md](SECURITY.md)) — was P0-3.
- **At-rest body encryption (AES-256-GCM) + required volume encryption** (§3) — was P1-1.
- **Pluggable at-rest key sourcing — the KeyProvider seam** (`[store].key_provider`,
  [store/keyprovider.py](../messagefoundry/store/keyprovider.py); §3) — built-in `auto`/`env`/`dpapi`
  (default `auto` byte-identical to before) + lazy external HSM/KMS/Vault hooks that envelope-decrypt a
  wrapped DEK inside an isolated module; fails closed on an unbuilt/unknown provider. Flips **ASVS 13.3.3
  Fail → Pass *(conditional, operator-activated)*** on the built seam + an operator-activated external
  module (ADR 0019 amended 2026-06-18, PR #377). Residuals: on-prem `auto` is the managed residual, and
  the in-use DEK-in-heap is the separately-deferred ASVS 11.7.1 / WP-BL3-28. Cloud SDKs are optional
  extras (zero in the base install); external providers land per-provider in follow-on PRs.
- **Retention/purge enforcement — `[retention]` body-null (keep metadata) + dead-letter window + WAL/VACUUM, audited; `audit_days` reserved/keep-forever by design** (§8) — was P1-2.
- **Exception-path PHI redaction — the `safe_exc()` chokepoint (`redaction.py`) at every exception→`last_error`/`detail`/log site** (§7) — the security half of P1-3 (WP-6c). Structured-JSON logging + off-box (syslog/SIEM) forwarding + the cross-backend `audit_log` off-box tee are now **built** (sec-offbox-log #357/#361/#363), and **native RFC 5425 TLS-syslog shipped with ADR 0080** — the forwarding hop is gated on the shared posture gradient (§7).
- **Outbound/egress allowlist — fail-closed `[egress]` (MLLP host:port + File dirs) enforced at config load/reload/start; webhook/SMTP host allowlists in `[alerts]`** (§4) — the data-plane half of P1-4 (WP-11c). MLLP-over-TLS is **built** (WP-13b, §4) — a non-loopback plaintext MLLP listener is refused at startup.

P0-4 (doc corrections) is this reconciliation; remaining stale claims in ARCHITECTURE/README are a
separate follow-up.

### P1 — core safeguards (remaining)
| Item | Closes | Maps to | Effort |
|---|---|---|---|
| **P1-3′** Structured (JSON) logging + off-box (syslog/SIEM) forwarding (§7) — ✅ **Built (sec-offbox-log #357/#361/#363)**, incl. **native RFC 5425 TLS-syslog** (ADR 0080) and the #1163 hop gate; residual: off unless a collector is named | Off-box log shipping / tamper-resistance | §164.312(b) · AU-9/AU-4 | M |
| **P1-4′** MLLP-over-TLS (§4) — `[conditional]`, Phase 2 (the egress-allowlist half shipped — WP-11c, above) | Cleartext PHI on the wire | §164.312(e) Transmission · SC-8 (NIST 800-52r2) | L |

### P2 — remote / Phase-2 (deferrable while strictly localhost; each flips to mandatory on remote exposure)
| Item | Closes | Maps to | Effort |
|---|---|---|---|
| **P2-1** TLS on the engine API | Tokens + PHI cleartext over the network | §164.312(e) · SC-8 | M |
| **P2-2** MFA for console/API auth — ✅ **Built (WP-14 TOTP and WP-14b passkeys, local and directory accounts)** | Single-factor auth (mitigated: `[security].require_mfa` is an **access gate on every authorized route**, and its shipped `require_mfa_scope` is `every_local_account`, not the Administrator role alone. Directory accounts are not exempt; [SECURITY.md](SECURITY.md#multi-factor-authentication-totp-wp-14) states which sessions owe a factor) | §164.312(d) · IA-2(1) (NPRM-mandated) | M–L |
| **P2-3** Network-segmentation guidance + periodic integrity checks | Lateral movement; tamper detection | §164.312(c) · SC-7/SI-7 | S–M |
| **P2-4** Strict-parse CPU/time budget on the hl7apy path | Malformed input pinning a worker — message size/segment caps are built, but the opt-in strict parse itself has no time bound | NIST SC-5 (DoS; not a §164.312 safeguard) | S |

**Program controls (administrative/contingency, on the NPRM timeline).** Beyond the engineering items
above, the 2025 NPRM expects recurring **vulnerability scans** (≤6-month cadence — extends the advisory
`pip-audit`/`bandit` CI into a scheduled program), an **annual penetration test**, and a **tested 72-hour
disaster-recovery / backup-restore drill**. These are §164.308/§164.310 program controls (CA-8 / RA-5 /
CP-10), not §164.312 code changes — tracked here so the deployment bar stays visible; the engineering
prerequisite (encrypted, access-controlled backups) is the checklist item in
[§10](#10-secure-deployment--operations-checklist).

---

## 12. Known limitations (current, honest)

Retention is enforced (`[retention]`, §8) but `audit_days` audit-log pruning is **reserved/keep-forever
by design** (archive-first pruning is a follow-up) · the exception path is redacted (`safe_exc`, §7,
WP-6c); structured (JSON) logging + off-box (syslog/SIEM) forwarding + the cross-backend audit-tee are now **built** (sec-offbox-log #357/#361/#363), with **native RFC 5425 TLS-syslog** (ADR 0080) and a posture-gated forwarding hop (#1163) · the
searchable `summary` column stays outside the encryption seam by design (volume encryption covers it;
`error`/`last_error`/`detail` are now ciphered — WP-5) · a fail-closed outbound/egress allowlist is
enforced (`[egress]`, WP-11c) and **MLLP-over-TLS is built** (WP-13b, opt-in per connection; a non-loopback plaintext listener is refused) · no
strict-parse time budget · de-identification is **built** for HL7 v2 (the anonymizer, §9, ADR 0030)
with X12/FHIR seams still to come. Each is tracked in
[§11](#11-hardening-roadmap).

**The test harness's at-rest data falls short of its protection levels.** The harness is in the
ASVS assessed scope (owner ruling 2026-10-02); its stores, and how far each falls short, are in the
[harness table](#the-test-harnesss-own-at-rest-data-harness) of §2. The gap that matters is the
reconcile capture and its compare report: unencrypted, unrestricted and unbounded copies of
message bodies, with no command-line way to anonymize the capture. The shadow-phase procedure runs
them against a migrating site's real outbound stream, so a deploying site that follows it would
hold a second plaintext copy of its PHI bodies wherever the operator pointed them. Nothing is
deployed, so nothing holds such a copy today. Until the code changes, the operator's controls in
[§10](#10-secure-deployment--operations-checklist) are the only ones.

---

## 13. HIPAA §164.312 mapping (data safeguards)

Complements the access/audit mapping in [SECURITY.md](SECURITY.md#hipaa-164312-alignment).

| Safeguard | Status | Where |
|---|---|---|
| Access control (a) | Built (RBAC + owner-only DB/`-wal`/`-shm` ACL — **SQLite store only**; on SQL Server / Postgres the file permissions on `.mdf`/`.ldf`/tempdb/native backups are **DBA-owned**, see §2) | [SECURITY.md](SECURITY.md), §2 |
| Audit controls (b) | Built (PHI-access audit, tamper-evident chain, off-box tee) + global log redaction (three handler filters) | §6, §7 |
| Integrity (c) | Built (GCM AEAD tag on bodies; audit hash-chain) + periodic integrity checks planned | §3, §6 |
| Authentication (d) | Built (argon2id / AD); native TOTP and passkey MFA built for local and directory accounts (WP-14, WP-14b) | [SECURITY.md](SECURITY.md), §11 |
| Transmission security (e) | Built: LDAPS, MLLP-over-TLS, API/WebSocket TLS, DB TLS, TLS-syslog | §4, §7 |

---

## Responsible disclosure

Found a PHI-handling or security issue? Do **not** open a public issue with details or any real
message content. Report it privately to the maintainers (contact channel: TBD — to be added before
any external/remote deployment). Include reproduction steps with **synthetic** data only.

---

## Standards & references

The roadmap is aligned to these; they are the basis for the safeguard mappings above.

- **HIPAA Security Rule — Technical Safeguards**, 45 CFR §164.312 (access control, audit controls,
  integrity, person/entity authentication, transmission security).
- **2025 HIPAA Security Rule NPRM** (proposed; 90 FR 898, Jan 6 2025) — moves encryption (at rest
  **and** in transit) and MFA from *addressable* to *required*, and adds network-segmentation
  expectations. We design to it as **forward-alignment only** even though it is not yet final — this is
  **not** a compliance claim (see the §11 note).
  <https://www.federalregister.gov/documents/2025/01/06/2024-30983/>
- **OWASP ASVS v5 §11.7 / CWE-316** (cleartext storage of sensitive information in memory) — the basis
  for the honest in-use heap-lifetime limitation in [§3](#3-encryption-at-rest): neither decrypted PHI
  nor the unwrapped DEK can be reliably zeroized on CPython; full in-use memory encryption is a host/OS
  capability.
- **NIST SP 800-66 Rev. 2** — implementing the HIPAA Security Rule (maps standards → NIST controls).
- **NIST SP 800-52 Rev. 2** — TLS configuration (TLS 1.2+; basis for MLLP-over-TLS and API TLS).
- **SQLCipher** — the documented whole-DB at-rest alternative if the plaintext `summary`/index
  residual (§3) is unacceptable. <https://www.zetetic.net/sqlcipher/>
- **Peer parity** — Mirth Connect's *Data Pruner* (retention with metadata retention + archive) and
  per-channel content/encryption storage settings inform [§8](#8-retention--purge) and [§3](#3-encryption-at-rest).
