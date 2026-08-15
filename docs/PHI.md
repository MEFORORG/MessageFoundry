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

This is a statement about *trust*, not about the bind interface. Three planes sit at different exposure
levels:

- **Management plane** (console/IDE → API) — **loopback by default** (or a restricted management
  subnet); always **authenticated** (RBAC + audit). Smallest surface.
- **Data plane** (inbound MLLP / TCP / X12 / DB-poll feeds) — **network-bound in any real install**
  (feeds arrive from other systems on the LAN, not `127.0.0.1`), protected by **TLS on the wire**
  (MLLP-over-TLS, built), the ingress/`[egress]` allow-lists, and your network segmentation. PHI must
  not cross the LAN in cleartext — and can't accidentally: the bind-guard **refuses any non-loopback
  *plaintext* API/MLLP bind** (ADR 0002 §0).
- **Inbound web-service listener** (a partner calling *into* MEFOR) — **not built today**; a distinct
  surface needing its own auth/TLS when it lands (backlog).

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
| `queue.payload` (stage=`ingress`/`routed`) | all three | **Yes** — the raw body, **transient** | **Yes, when a key is set** — store cipher; AAD `("queue","payload",id)`; store DEK | **PL-1** | A second copy of the raw, held only across the route→transform window: the `ingress` row is consumed at `route_handoff`, each `routed` row at `transform_handoff` (deleted, never kept). A stalled router/transform stage can hold several briefly — surfaced by the `queue_buildup` alert | `UNBOUNDED — honest gap` |
| `queue.payload` (stage=`outbound`) | all three | **Yes** — transformed outbound body | **Yes, when a key is set** — store cipher; AAD `("queue","payload",id)`; store DEK | **PL-1** | One row per destination; the persistent footprint | `` `[retention].dead_letter_days` `` |
| `shared_body.body` (store-once-deliver-many) | schema on all three; **rows written on SQLite only** | **Yes** — one transformed outbound body shared by N destinations | **Yes, when a key is set** — store cipher; AAD `("shared_body","body",hash)`; store DEK | **PL-1** | `hash` is the SHA-256 of the **plaintext** body (the content address). Refcounted: GC'd the moment the last referencing outbound row's body is purged. On SQL Server and Postgres the table is schema-parity only — `queue.body_ref` stays `NULL`, so no row is ever written. **Both** server backends nonetheless keep a read-side `LEFT JOIN shared_body` deref in `resend_to` (with its own `cell_aad("shared_body","body",…)` decrypt branch), which is why the column stays **cipher-covered** on all three. It is **rotation-swept on SQLite only** — `shared_body` has a pass in `MessageStore.reencrypt_to_active` but appears in neither server backend's rotation. Harmless while `body_ref` stays `NULL` there, and recorded as a deliberate decision in `store/postgres.py`'s `_CIPHER_COLUMNS` note ("schema-only this increment … it needs no rotation pass here until the dedup insert is wired") | ``rides `[security].delete_message_bodies_after_days` `` |
| `attachment_chunk.ciphertext` (ADR 0105 / #149) | all three | **Yes** — one slice of a detached very-large document (e.g. a base64 PDF from OBX-5.5) | **Yes, when a key is set** — store cipher, **sealed per chunk on write**; AAD `("attachment_chunk","ciphertext",attachment_id,seq)`; store DEK | **PL-1** | The document is detached at ingress, content-addressed (`sha256` of the verbatim plaintext) and chunked; the message keeps only an `mfdoc:v1:ref:` handle. Read back via `GET /messages/{id}/attachments/{id}` (§3) | ``rides `[security].delete_message_bodies_after_days` `` |
| `attachment` header row (`content_type`, `total_bytes`, `refcount`, `created_at`) + `message_attachment` linkage | all three | **No** — size/type/linkage only | No (metadata, deliberately not ciphered) | **PL-4** | The linkage row is the security crux of the download route: it scopes a content address to a message the caller may already read | ``rides `[security].delete_message_bodies_after_days` `` |
| `response.body` (ADR 0013 captured replies; ADR 0021 `kind='ack_sent'`) | all three | **Yes** — the partner's reply body, or the ACK/NAK the engine returned | **Yes, when a key is set** — store cipher; AAD `("response","body",message_id,destination_name,response_seq)`; store DEK | **PL-1** | Composite PK, so it rides its own migration/rotation pass. An **ACK body is stored only when the store cipher is active** — on a keyless store it is `NULL` rather than plaintext (fail-safe), and a NAK never stores a body at all | ``rides `[security].delete_message_bodies_after_days` `` |
| `[store].uploads_dir/*.blob` + `*.meta` — the cipher cells `uploaded_file.body` / `uploaded_file.meta` (offline uploaded logs, ADR 0134) | all (filesystem, not the DB) | **Yes** — an operator-uploaded diagnostic message file, held for offline browsing decoupled from any connection | **Yes, when a key is set** — the **same store cipher** (`build_store_cipher`); AAD `("uploaded_file","body")` / `("uploaded_file","meta")` + `file_id`; store DEK. **identity/plaintext-on-disk otherwise** (the File-connector-spill tier below) | **PL-1** | A PHI-at-rest location **outside** the message store, opt-in (unset ⇒ the subsystem is disabled — no surface). On-disk identity is a random 32-hex `file_id` (path-traversal guard); the operator filename is display-only. Every access is `files:*`-gated, browse is step-up + PHI-hop-guarded, all audited (metadata only). **Not** re-encrypted by `rotate-key` (outside the store) — stays readable via the decrypt keyring. The dir is created `0o700` and the sidecar written `0o600` **best-effort, and both are no-ops on Windows** — the engine applies no ACL here (it does not call the `icacls` enforcer). **Retention + quotas (ASVS 5.2.4):** uploaded files auto-prune after `[store].uploads_retention_days` (default **30**) — swept opportunistically at save time and by a periodic task; every prune is audited (`upload.prune`, file_id + uploader only, never content). Per-uploader caps `[store].max_upload_files_per_user` (default **100**) / `[store].max_upload_total_bytes_per_user` (default **250 MiB**) bound the at-rest volume; a would-be over-quota upload is refused **HTTP 409** with an `upload.reject_quota` audit before anything is written (defaults-ON, `ge=1` floors). The quota is scoped to the **`uploads_dir`, not to the process** — the sidecar scan is uncached, so engine shards sharing one dir enforce **one** budget between them (measured 2026-08-10); shards given separate dirs get separate budgets by construction. The check and the write it authorizes are one critical section per process; the residual that survives it, and its bound, are stated once in `uploads.UploadQuotaError`. Harden the dir + volume encryption ([§10](#10-secure-deployment--operations-checklist)) | `` `[store].uploads_retention_days` `` |
| `[backup].destination/mefor-backup-*.mfbak` (ADR 0049 DR backup) | **SQLite only** carries bodies | **SQLite: Yes** — a consistent store snapshot (full inbound + outbound bodies) + the config bundle. **SQL Server / Postgres: No** — config bundle only | **Yes** — `.mfbak` chunked-AEAD codec under the **store DEK** (`resolve_active_key`); an identity-cipher (no-key) box is **refused** unless `[backup].allow_unencrypted` writes a `.mfbak.plain` | **PL-1** (SQLite) / **PL-4** (server backends) | On a **server-DB store `snapshot_to` raises `DbaDelegatedError`**, so the BackupRunner writes a **config-only** archive — or skips entirely when `[backup].config_only_on_server_db = false`. There is therefore **no `.mfbak` containing message bodies on SQL Server or Postgres**; the DB-tier backup there is `BACKUP DATABASE` / Always On / `pg_dump` / PITR, infra-owned. Where bodies *are* present it is a second at-rest PHI copy, bounded by keep-N retention; like `uploads_dir` it is **not** re-encrypted by `rotate-key`. The share's own ACLs are infra-owned | ``keep-N `[backup].retention_keep` `` |
| `mefor-backup-*` / `mefor-tar-*` / `mefor-verify-*` staging dirs (OS temp dir, ADR 0049) | SQLite carries bodies; server backends config-only | **Yes** — a full store snapshot, and on verify a **decrypted** archive | **No** — the snapshot keeps the store's own column cipher, but the staging tar and the verify extraction are **plaintext on disk**; no engine ACL (`_secure_file` is never called on these paths) | **PL-1** | `run_backup` snapshots the store to `<tmp>/store.db` and tars it **plaintext** before sealing it into the `.mfbak` (`pipeline/dr_backup.py`), and `[backup].verify_after_backup` (**default `true`**) decrypts the archive straight back out to a second temp dir on **every** run — independent of `full_restore_verify`. Transient (the `TemporaryDirectory` unlinks on exit) but **not** on a crash or `SIGKILL`. Lives under `%TEMP%` / `TMPDIR`, **not** the ACL'd data dir: cover the temp volume with FDE and point `TMP`/`TMPDIR` at an owner-only path ([§10](#10-secure-deployment--operations-checklist)) | `UNBOUNDED — honest gap` |
| File-connector output / spill dirs (`.hl7`, `.processed`, `.error`) | all | **Yes** — plaintext on disk | **No** — no cipher at all on this path | **PL-1** | Written by the File transport; treat the directory as PHI and cover it with volume/share encryption + an ACL | `UNBOUNDED — honest gap` |
| Application log files (`[logging].log_dir`; under NSSM, `<DataDir>\logs\service.out.log` and `service.err.log`) | all (filesystem, not the DB) | **Possibly** — redaction is best-effort; a single-token identifier can survive it | **No** — plaintext on disk, no app-level cipher | **PL-1** | The engine installs no file handler; NSSM captures stdout/stderr. The defence is the three handler filters + `safe_exc()`/`safe_text()` + the never-log-bodies rule ([§7](#7-logging--phi-redaction) row 1), and the residual is stated there. The directory ACL is the NSSM installer's **best-effort** `icacls /inheritance:r`; age deletion is `[retention].app_log_days` (files by **mtime** — content is never read, so nothing selective happens here) and optional in-place gzip is `[retention].app_log_compress_days` (the compressor **does** read a file's bytes to archive + integrity-verify them, but only in-process — nothing is logged, and the archive stays inside the same ACL'd directory at the source's mtime). A support bundle copies a 500-line tail of this file out of the ACL'd directory entirely ([§7](#7-logging--phi-redaction)). Cover the volume with FDE ([§10](#10-secure-deployment--operations-checklist)) | `` `[retention].app_log_days` `` |
| `messages.summary` | all three | **Yes** — MRN / patient name / order | **Yes, when a key is set** — store cipher; AAD `("messages","summary",id)`; store DEK (EF-3) | **PL-2** | Ingest-derived; no SQL search or index exists on it, so encrypting it costs nothing. NULL/blank stay as-is | ``rides `[security].delete_message_bodies_after_days` `` |
| `messages.metadata` | all three | **Yes** — operator/handler-attached values | **Yes, when a key is set** — store cipher; AAD `("messages","metadata",id)`; store DEK (EF-3) | **PL-2** | **Nulled by `purge_message_bodies` on the `[retention].messages_days` window, in the same statement as the body** (ASVS 14.2.7) — see [§8](#8-retention--purge) | ``rides `[security].delete_message_bodies_after_days` `` |
| `messages.error` | all three | **Possibly** — may embed raw fragments from exceptions | **Yes, when a key is set** — store cipher; AAD `("messages","error",id)`; store DEK (WP-5) | **PL-2** | Also `safe_exc()`-redacted **before** write. NULL/blank values stay as-is | ``rides `[security].delete_message_bodies_after_days` `` |
| `queue.last_error` | all three | **Possibly** — same | **Yes, when a key is set** — store cipher; AAD `("queue","last_error",id)`; store DEK (WP-5) | **PL-2** | Same double defence (`safe_exc()` then cipher) | ``rides `[security].delete_message_bodies_after_days` `` |
| `message_events.detail` | all three | **Possibly** — per-message disposition detail | **Yes, when a key is set** — store cipher; AAD `("message_events","detail",message_id,ts,event)`; store DEK | **PL-2** | `id` is AUTOINCREMENT/IDENTITY and unknown at INSERT, so the AAD binds the natural tuple and the column rides its own composite migration/rotation pass. `safe_text()`-scrubbed before write | ``rides `[security].delete_message_bodies_after_days` `` |
| `response.detail`, `response.resp_headers` | all three | **Possibly** — reply diagnostics / partner response headers | **Yes, when a key is set** — store cipher; AAD `("response","detail", …)` / `("response","resp_headers",message_id,destination_name,response_seq)`; store DEK | **PL-2** | `detail` is `safe_text()`-scrubbed and 200-char bounded before the cipher | ``rides `[security].delete_message_bodies_after_days` `` |
| `state.value` (ADR 0005 transform state) | all three | **Possibly** — a correlation map (e.g. MRN→surrogate) written by a Handler | **Yes, when a key is set** — JSON-encoded then store cipher; AAD `("state","value",namespace,key)`; store DEK | **PL-2** | Composite PK; own migration/rotation pass. **No read API** — reachable only from a Handler via `state_get`/`state_set` | `` `[retention].state_max_age_days` `` |
| `reference.value` (ADR 0006 versioned lookup snapshots) | all three | **Possibly** — a snapshot row may be patient-keyed | **Yes, when a key is set** — store cipher; AAD `("reference","value",name,version,key)`; store DEK | **PL-2** | Composite PK; own migration/rotation pass. **No read API.** **`[retention].reference_snapshot_days`** — `purge_reference_snapshots` DELETEs the rows of a set config **no longer declares** whose active version was synced before the cutoff (`0` = keep forever, the default) ([§8](#8-retention--purge)). **Orphan-only, and the limit is the point:** a set that IS still declared is never touched however old its `synced_at`, because its snapshot is live data the engine serves — so the normal case, a wired set holding live PHI, is still bounded by nothing. Do not restate this as a plain window over `reference.value` | ``orphan-only `[retention].reference_snapshot_days` `` |
| `search_presets.criteria` (ADR 0136 saved Log-Search filters) | all three | **Yes** — the operator's saved `content` / `field_value` needle is PHI-shaped by construction | **Yes, when a key is set** — store cipher; AAD `("search_presets","criteria",id)`; store DEK | **PL-2** | Never returned by the API: `GET /search/presets` lists names + timestamps only; the needle is loaded server-side by `GET /search/layered`. **`[retention].search_preset_days`** — `purge_search_presets` DELETEs the whole row past the window on every backend, keyed on last-**used** — the later of `updated_at` and `last_used_at`, #306 (`0` = keep forever, the default) ([§8](#8-retention--purge)) | `` `[retention].search_preset_days` `` |
| `connection_event.reason` (#46 transport/lifecycle log, **default on**) | all three | **Possibly** — a free-text diagnostic fragment | **Yes, when a key is set** — store cipher; AAD `("connection_event","reason",connection,ts,kind)`; store DEK | **PL-2** | Defended twice: the emit site passes a `safe_exc()`-scrubbed string and the store re-applies `safe_text(reason)[:200]`. IDENTITY `id`, so its own composite pass. Every other column is bounded engine/config metadata **except `peer_host`** (its own PL-4 row below) — the table carries no frame, body or HL7 field value. Read under `monitoring:read`, **not** a PHI permission ([§7](#7-logging--phi-redaction)) | `` `[retention].connection_event_retention_hours` `` |
| `connection_event.peer_host` | all three | **No** — a network address; identifies a *host*, not a patient | No (metadata, deliberately not ciphered) | **PL-4** | The connecting peer's IP, taken from the socket; `NULL` for outbound/unknown. Personal data, not PHI — the **same class and the same decision** as `audit_log.client` / `sessions.client`: plaintext so it stays greppable for incident response. Returned to operators by `GET /events` under `monitoring:read`. Purged with its row by `[retention].connection_event_retention_hours` | ``rides `[retention].connection_event_retention_hours` `` |
| `alert_instance.reason` (ADR 0044 operator alerts) | all three | **Possibly** — the alert's `detail`/`reason`/`label` free text | **Yes, when a key is set** — store cipher; AAD `("alert_instance","reason",event_type,connection)`; store DEK | **PL-2** | `safe_text(reason)[:200]` before the cipher. The AAD binds the de-dup grain, so the same AAD covers both the INSERT and the re-fire upsert UPDATE that never sees the `id`. Read under `monitoring:diagnose` ([§7](#7-logging--phi-redaction)) | ``rides `[retention].connection_event_retention_hours` `` |
| `users.totp_secret` | all three | **No** — not PHI | **Yes, when a key is set** — store cipher; AAD `("users","totp_secret",id)`; store DEK | **PL-3** | The base32 TOTP MFA seed. Never returned by any API response model. Its siblings `users.password_hash` and `users.totp_recovery_codes` are **argon2id one-way hashes** and are deliberately **not** ciphered | `keep-forever by design` — it lives and dies with the user row |
| `queue.handler_name` / `destination_name` / `channel_id` | all three | No — names, not bodies | No (metadata, deliberately not ciphered) | **PL-4** | The handler the transform worker runs; the destination the delivery worker drains | `n/a — not PHI` |
| `messages.control_id`, `messages.message_type` | all three | Low (MSH-10/MSH-9) | **No** — plaintext by design | **PL-4** | Needed plaintext for dedup/routing/indexes (`ix_messages_control`). Covered only by the whole-DB / volume layer | `keep-forever by design` — dedup/routing keys that live and die with the message row |
| `audit_log.detail` | all three | Low — exposed IDs/counts, not bodies | **No** — plaintext by design | **PL-4** | JSON metadata about PHI *access*, not the PHI itself. Its writers only ever store filter shapes, counts and ids | `keep-forever by design` — 45 CFR 164.316(b)(2)(i) six-year documentation retention; deleting rows would break the tamper-evident hash chain |
| `audit_log.client` (ADR 0150) | all three | **No** — a network address; identifies a *host*, not a patient | No (metadata, deliberately not ciphered) | **PL-4** | The caller's client address — the "from where" of an audited action; `NULL` for engine-internal/`system` writes. **Personal data, but not PHI**, and exactly what HIPAA §164.312(b) audit controls exist to capture. Plaintext by decision: it must stay greppable/indexable for incident response, it already appears in the clear in `sessions.client`, and it is folded **inside** the tamper-evident hash chain — so it carries **integrity** protection even without confidentiality. Widens a store-file compromise from *who did what* to *who did what from where*; volume encryption + owner-only ACLs on whichever host owns the files — the engine's own `_secure_file` covers the **SQLite** store only ([§10](#10-secure-deployment--operations-checklist)) — are the control | `keep-forever by design` — same `audit_log` row lifetime as `detail`; the value is folded **inside** the hash chain |
| `delivered_keys` (H2 idempotency ledger) | all three | **No** — hashes + ids only | No (deliberately not ciphered — nothing to protect) | **PL-4** | One row per completed outbound delivery: a SHA-256 `delivery_key` over non-PHI ids + a replay-stable seq, plus `outbox_id`/`message_id`/`destination_name`/`delivery_seq`. **Never a body or any PHI** — `control_id` is only *folded into the hash input*, never stored in the clear here. Lets the FIFO claim skip-and-complete a re-claimed already-delivered head without re-sending | `keep-forever by design` — the idempotency ledger a re-claimed already-delivered row checks instead of re-sending |
| `state.namespace` / `state.key` | all three | **Possibly** — a Handler that keys correlation state on a raw MRN stores that identifier here in the clear | **No** — plaintext by construction: the pair is the composite primary key **and** the AAD input for `state.value`, so it cannot be ciphered without losing the lookup | **PL-4** | Authors must key state on a **surrogate, never a raw identifier**. Covered only by the whole-DB / volume layer. Rides `[retention].state_max_age_days` with its value | ``rides `[retention].state_max_age_days` `` |
| `reference.name` / `reference.version` / `reference.key` | all three | **Possibly** — §2's `reference.value` row notes a snapshot row may be patient-keyed; the key column is where that identifier would sit | **No** — plaintext by construction, same reason as `state` | **PL-4** | Same rule: key reference sets on a surrogate. The key columns ride the same delete: `purge_reference_snapshots` removes whole rows of an **undeclared** set, so these go with the `value` they key. A **declared** set is never touched — same orphan-only limit as `reference.value` above | ``orphan-only `[retention].reference_snapshot_days` `` |
| `sessions.token_hash` / `client`, `resend_log`, `processed_files`, `pending_approvals.params`, `webauthn_credentials.public_key` | all three | **No** | No (deliberately not ciphered) | **PL-4** | Session tokens are stored as SHA-256 only; `processed_files` holds a hashed derived file key, never a path; approval params carry connection names / channel ids / a config dir by construction; COSE public keys (ADR 0068) are **verification material, not secrets** and are explicitly excluded from the cipher and from rekey | `n/a — not PHI` |
| `secret_rotation_meta` (`secret_key` / `fingerprint` / `tracked_since` / `last_rotated`) | **All three backends** (#1186 — SQLite `MessageStore`, `SqlServerStore` and `PostgresStore` each create the table at open and implement the `SecretRotationMetaStore` protocol) | **No** — non-secret rotation state: a **keyed MAC** (DEK-derived, one-way — never the secret value) + ISO dates only | No (deliberately not ciphered — it is neither PHI nor a secret; the MAC is one-way and un-guessable without the DEK) | **PL-4** | ASVS 13.3.4 rotation watcher (BACKLOG #282). `fingerprint` is a keyed MAC so obtaining the rows leaks no secret. Written on a keyed store; absent on a keyless one | `n/a — not PHI` |
| SQLite DB file + `-wal` / `-shm` / temp files, and every index | SQLite | **Yes** (mirror the above) | **No** — the app cipher cannot reach them | **PL-5** | WAL/shm hold recently-written PHI outside any app-level encryption. Cover: SQLCipher (whole-DB) and/or FDE on the engine host's data volume | `n/a — not PHI` |
| SQL Server `.ldf` **transaction log** + the **tempdb version store**, and every index | SQL Server | **Yes** (row images of `messages`/`queue`, ciphertext columns **plus** the always-plaintext `control_id`/`message_type`) | **No** — outside the app-level AEAD entirely | **PL-5** | The engine itself makes this load-bearing: it **force-enables `READ_COMMITTED_SNAPSHOT` and `ALLOW_SNAPSHOT_ISOLATION`** on the store database at open, so tempdb's version store holds row images for the lifetime of every open snapshot. The `.ldf` holds every row image for the same reason. Additional tempdb objects: the `#eligible` temp table used by `purge_message_bodies` and the FIFO-claim table variables (ids only, non-PHI). Cover: **SQL Server TDE at the database + FDE on the *SQL Server host's* volumes** — **not** BitLocker on the engine host | `n/a — not PHI` |
| PostgreSQL WAL (`pg_wal`), base files and every index | Postgres | **Yes** (mirror the above) | **No** — outside the app-level AEAD | **PL-5** | Cover: cluster-level / filesystem encryption on the database host, infra-owned | `n/a — not PHI` |

> **Retention column — vocabulary (ASVS 14.2.7).** Every cell is exactly one of seven forms. The serve
> gate's tier list and the §2↔§8 drift test are GENERATED from these, so there are no prose variants —
> a hand-typed tuple with a longer literal is the same defect this column exists to remove.
>
> - **`[section].window`** — bounded by its **own** named window, cited exactly as an operator types it.
> - **rides `[section].window`** — no window of its own; deleted or nulled by another tier's purge.
>   Valid **only** when §8's row for that window names this table/column in its Mechanism cell. This is
>   the form most likely to be wrong, because it asserts coverage that lives somewhere else.
> - **orphan-only `[retention].reference_snapshot_days`** — `reference.*` only: purged **only** when
>   config no longer declares the set. A **declared** set is never touched, whatever its age.
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
above passes a cell AAD and, on the shipped default, that AAD is **bound** — writes use the `mfenc:v2`
writer. Setting `aad_bind = false` selects the frozen `mfenc:v1` writer, which binds no associated data
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
`-wal`/`-shm` siblings to the owner on create — POSIX `chmod 0600`, Windows owner-only DACL via
`icacls` (inheritance off) — through `_secure_file()`
([store/store.py](../messagefoundry/store/store.py)). It is best-effort and non-fatal: a skipped or
failed restriction is **logged** (STORE-2), with directory-level ACLs ([SERVICE.md](SERVICE.md)) as
the backstop. **This is the SQLite tier only.** On SQL Server / Postgres the engine creates no database
file and applies no ACL — permissions on `.mdf`/`.ldf`/tempdb/native backups are entirely the DBA's.
The `[store].uploads_dir` tier is weaker still: `uploads.py` uses `mkdir(0o700)` + `chmod(0o600)` under
a suppressed `OSError` and never calls the `icacls` enforcer, so **on Windows the uploads directory has
no engine-applied ACL at all**. The File-connector spill dirs likewise remain operator-owned — harden
all of these per [§10](#10-secure-deployment--operations-checklist).

**Git hygiene `[BUILT]`.** `.gitignore` excludes `*.db` / `-wal` / `-shm`, generated message corpora,
and logs, so runtime PHI is never committed. Keep it that way — never `git add -f` a database or a
real message file.

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
   both `mfenc:v1:<key_id>:<b64>` and an additive, self-describing `mfenc:v2:<alg>:<key_id>:<b64>`
   (`alg` names the AEAD), and **fails closed** (`CipherError`) on an unknown marker version or an
   unknown/unsupported `alg` — never a silent pass-through or mis-decrypt. **AES-256-GCM is the only
   algorithm registered in the in-process cipher** and the **v1 writer is frozen byte-identical** (a
   frozen-fixture test pins it). The store's find-all/migration scans anchor on the
   version-agnostic `mfenc:` prefix (so a v2 row is recognised as already-encrypted), and the rotation
   scan anchors on the cipher's active-format prefix through the key fingerprint (so a v2-active rotation
   matches v2 rows and terminates).
   **Cell binding — `[store].aad_bind`, default ON (ASVS 11.3.3, ADR 0019 as amended by ADR 0148
   GIVEN 1).** Every store write site passes `cell_aad(table, column, *pk)` (the tuples are documented
   per row in §2), and on the shipped default new writes are **`mfenc:v2` with the cell AAD bound**: a
   ciphertext cut-and-pasted from one cell into another fails the GCM tag (dead-lettered, never silently
   accepted). Setting `aad_bind = false` selects the **frozen `mfenc:v1` writer, which passes no
   associated data — the AAD is then computed and ignored, and at-rest values are NOT cell-bound**; that
   is a declared loosening, named by `security_loosenings()`. Legacy `v1` rows stay readable (dual-read)
   and **`messagefoundry rotate-key` upgrades them v1→v2**, so the default is safe on an existing store
   and reversible. `aad_bind` has no effect without an encryption key (the identity cipher has nothing
   to bind).
   **A third at-rest tier ships — `[store].cipher_provider = "vault_transit"` (`mfenc:v3`, ADR 0138).**
   This does not merely source the key: it **replaces the cipher object**
   ([store/crypto_transit.py](../messagefoundry/store/crypto_transit.py)), so every encrypt/decrypt runs
   **inside Vault/OpenBao Transit** and the data key never enters engine heap. Values carry a third
   marker, `mfenc:v3:` + Transit's own `vault:v1:` ciphertext; the cell AAD is forwarded as Transit's
   `associated_data`, so **`v3` is cell-bound regardless of `aad_bind`**; and the audit-chain MAC is
   computed inside Transit. Missing config or an unreachable/unknown Transit key **fails closed** at
   `open_store` (`serve` refuses to start) — never an in-process fallback. Caveat worth knowing: the
   Transit-backed audit MAC reaches **all three** backends. This bullet previously said SQLite-only — that
   was the PRE-#301 state stated as current, and it was wrong in the direction that flatters nothing:
   `TransitCipher.audit_mac_key()` returns `None` **by design**, so a server backend given only
   `audit_mac_key` had no keying secret at all. #301 threads `audit_mac_fn` alongside it
   (`store/base.py:1817`, forwarded at `:1826`/`:1836`), which is what closed it. `docs/ASVS-L2-PHASE0-CHANGES.md`
   §"Audit chain" carries the accurate wording — the digest primitive is *"shared verbatim by all three
   backends"*. **What IS unkeyed is the KEYLESS posture, not a backend:** with no store key,
   `audit_mac_key()` returns `None` (`store/crypto.py:428`) and the chain stays keyless SHA-256 —
   tamper-evident against a careless edit, not forgery-resistant against anyone who can write the
   table. At-rest encryption is off by default, so that is the DEFAULT posture.
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
   key, then drop the retired key. An undecryptable value (corrupt blob / missing key) is contained —
   the row is dead-lettered, never crashes a worker.
   **Fail-closed (secure-by-default; H3, OWASP *Fail Securely* / SDS §4.3 PW.9):** `serve` **refuses to
   start with no key on ANY PHI instance** — the refusal is gated on the resolved **`[ai].data_class ==
   phi`**, *not* the environment label, so a custom-named dev/test box holding near-real PHI fails closed
   exactly like `prod`/`staging` (closing the EF-3 perception gap where non-prod only warned). Since
   [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 1) **all
   three built-in envs (`dev`/`staging`/`prod`) derive PHI**, so the default/CI path is key-required too — a
   **genuinely-synthetic** box (`data_class != phi`) stays **key-free** only when it declares
   `[security].handles_real_patient_data = false` **explicitly** (a loud, audited opt-out — it is no longer
   the `dev` default). Two further explicit overrides: `[store].require_encryption = true` forces the refusal
   even for a synthetic instance; `[store].allow_unencrypted_phi = true` is the loud, **audited** opt-out that
   lets a PHI instance start keyless anyway (it still emits the UNENCRYPTED-at-rest warning, and
   `require_encryption` wins over it) — and under **strict enforcement** (`[security].enforcement = enforce`,
   the default) keyless PHI additionally requires the second ack
   `[security].allow_unencrypted_phi_under_strict_enforcement = true` ([ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) / ADR 0148). The effective posture (encryption on/off, key **source**, key **fingerprint**,
   `data_class`, per-backend column coverage) is surfaced at the authenticated, `MONITORING_READ`-gated
   **`GET /security/posture`** route (M5) — never key bytes; every access is audited.
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
`mefor-tar-*` / `mefor-verify-*` staging dirs (OS temp dir) · File-connector spill dirs ·
application log files (`[logging].log_dir`).

- **Encryption**, stated per tier rather than as one blanket rule:
  - *Database cells and the `[store].uploads_dir` sidecars* — the store cipher (AES-256-GCM, or
    Transit under `vault_transit`) with the per-cell AAD in §2, keyed by the store DEK — **bound on the
    shipped default (`[store].aad_bind = true` → `mfenc:v2`) and unconditionally under
    `cipher_provider = "vault_transit"` (`mfenc:v3`); an operator who sets `aad_bind = false` selects the
    frozen `mfenc:v1` writer, and the AAD is then computed and ignored.**
  - *`.mfbak` archives* — **a separate streaming codec, NOT the store cipher**
    ([store/backup_codec.py](../messagefoundry/store/backup_codec.py), whose own docstring says the
    cipher *mechanism* is net-new): chunked AES-256-GCM under the store DEK resolved directly by
    `resolve_active_key`, with a per-chunk AAD of
    `header_sha256 ‖ frame_counter(uint64) ‖ final_flag(uint8)` — **not** a per-cell AAD. Because the
    key is resolved by `resolve_active_key` and not `build_store_cipher`, `cipher_provider =
    vault_transit` **never applies to a backup**. And `[backup].allow_unencrypted = true` writes a
    **CLEARTEXT `.mfbak.plain`** — a plaintext PHI-body archive on disk.
  - *File-connector spill dirs* — **plaintext on disk**; there is no cipher on that path, only
    volume/share encryption and the directory ACL.
- **Integrity.** The per-value GCM tag is the tamper-evidence. For `attachment_chunk.ciphertext` each
  chunk carries its own tag and the attachment's `id` is the SHA-256 of the **verbatim plaintext**, so a
  re-seal (rotation) never changes the content address. `shared_body.body` is likewise addressed by the
  plaintext hash.
- **Confidentiality / access.** `messages.raw` and `queue.payload` are read through the audited
  `GET /messages/{id}` path under `messages:view_raw` + `require_phi_read` (the PHI-read hop guard +
  per-actor pacing) + per-channel scope. A detached document is the **same PHI**, so
  `GET /messages/{message_id}/attachments/{attachment_id}` rides the *same* `messages:view_raw` gate and
  channel scope, **plus a `message_attachment` linkage check** — a guessed content address that is not
  linked to an in-scope message is a 404 — and writes a `record_view` **and** an `attachment_download`
  audit row **before** any byte leaves. `response.body` is exposed by `GET /messages/{id}/responses`
  only when the caller *also* holds `messages:view_raw`. `shared_body.body` has **no direct read API**
  (reachable only via the delivery deref and the resend source read). Uploaded-log blobs are `files:*`
  gated, step-up + PHI-hop-guarded on browse, and audited (metadata only).
  **Bulk egress is a separate, stronger gate:** `GET /messages/export` streams many raw bodies at
  once and requires a **fresh step-up over BOTH** `messages:export` **and** `messages:view_raw`,
  applies `enforce_phi_read_hop` and per-actor pacing explicitly, re-checks per-channel scope per
  id, and writes **one** `messages_export` audit row (actor, selection mode, filters, needle
  *shape*, body count) **before** streaming — the code calls it the largest PHI surface in the
  cluster. The transformed outbound payload (`queue.payload`, stage `outbound`) is read by its own
  route, `GET /messages/{message_id}/outbound`, under `messages:view_raw` + `require_phi_read`,
  audited `outbound.read` — not by `GET /messages/{id}`.
- **Retention / destruction.** `messages.raw` is blanked in place by `purge_message_bodies`;
  `queue.payload` is blanked for done/cancelled outbound rows in the same transaction, and for dead rows
  by `purge_dead_letters`; `response.body` is set to `NULL` in place by the same pass;
  `shared_body.body` is refcount-decremented and GC'd at 0 when its **last** referrer is purged;
  streaming attachments are decref'd + GC'd at 0 (plus a startup `sweep_orphan_attachments`).
  The legacy SQL Server `outbox.payload` no longer exists to be purged — its rows were folded into
  `queue` and the table DROPped ([§2](#2-where-phi-lives--data-at-rest-inventory)), so they now ride the
  same window as any other outbound row. `[store].uploads_dir` blobs auto-prune
  after `[store].uploads_retention_days` (default **30**) via an age-based sweep — a periodic
  `UploadRetentionRunner` plus an opportunistic pass at save time, each pruned pair audited `upload.prune`
  (ASVS 5.2.4, #291); an operator `DELETE` is an additional removal path. **`.mfbak` archives** are bounded
  by **keep-N** (`[backup].retention_keep`, `0` = keep all): the `BackupRunner` prunes older archives at
  the destination and nothing else expires them — there is no age window. **File-connector output /
  spill dirs have no engine-managed retention or destruction at all** — the File transport writes
  `.hl7`/`.processed`/`.error` files and an operator or infra job is the only removal path. Application
  log files are age-deleted by `[retention].app_log_days` (by **mtime**; content is never inspected)
  and, optionally, gzipped in place first by `[retention].app_log_compress_days` — the compressor reads a
  file's bytes to archive and verify them **in-process, never logged or exported**, leaves the archive on
  the same ACL'd volume, and inherits the source's mtime so the delete window still applies.
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
| `messages.error`, `queue.last_error` | `safe_exc()` chokepoint | `messages:view_summary` | nulled by `purge_message_bodies` / `purge_dead_letters` |
| `message_events.detail` | `safe_text()` | `GET /messages/{id}` (`messages:view_raw` + `require_phi_read`); the read itself writes a `viewed` event and a `message_view` audit row. `EventInfo.detail` is **additionally** nulled by `redact_unauthorized` for a caller lacking `messages:view_summary`, so a view_raw-without-view_summary role cannot read it | set to `NULL` by `purge_message_bodies` (inherits the body window) |
| `response.detail` | `safe_text()`, 200-char bound | `GET /messages/{id}/responses` under `messages:read` + `require_phi_read`; nulled by `redact_unauthorized` for a caller lacking `messages:view_summary`; every read writes a `response.read` audit row | set to `NULL` in place by `purge_message_bodies` |
| `response.resp_headers` | `safe_text()` | **no API surface** — it is not a field of `CapturedResponseInfo` and is never returned by `GET /messages/{id}/responses`; reachable only from a Handler via `response_get(destination)` (ADR 0013/0084) | set to `NULL` in place by `purge_message_bodies` |
| `state.value` | none (Handler-authored JSON) | **no read API** — Handler-only via `state_get` | age purge on `[retention].state_max_age_days` (DELETE) |
| `reference.value` | none | **no read API** — Handler-only via `reference()` | **none** — a snapshot is replaced only by the next sync's build-new-then-flip |
| `search_presets.criteria` | none (the operator's own needle) | **never returned by the API.** `GET /search/presets` returns names + timestamps only; create is `require_step_up(messages:read)` and audits the needle *shape* only; the needle is loaded **server-side** by `GET /search/layered` and never round-trips. Owner-scoped on every read | **`[retention].search_preset_days`** on every backend — whole-row `DELETE` by last-**used** (the later of `updated_at` and `last_used_at`, #306); `0` = keep forever (the default), so an owner `DELETE` remains the only removal until a window is set |
| `connection_event.reason` | `safe_exc()` at the source **and** `safe_text(…)[:200]` at the store | `GET /events` / `GET /connections/{name}/events` under **`monitoring:read`** — note this is **not** a PHI permission, so an operator with no PHI grant can read a scrubbed `reason` | age DELETE on `[retention].connection_event_retention_hours`, else inherits `[retention].messages_days` |
| `alert_instance.reason` | `safe_text(…)[:200]` | `GET /alerts/active` under **`monitoring:diagnose`** — again not a PHI permission | same window, **RESOLVED instances only** — an open or acknowledged alert is never aged out |

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

**Applies to:** `users.totp_secret`.

Encrypted with the store cipher (AAD `("users","totp_secret",id)`); integrity from the GCM tag.

**Access.** The staged secret is returned **exactly once, to its own owner**, by `POST /me/mfa/enroll`
(`MfaEnrollResponse.secret`, plus the `otpauth://` QR URI that embeds the same base32 value) — behind a
fresh **password** step-up bound to that action (ADR 0077,
`require_reauth_only_action(STEP_UP_ACTION_MFA_ENROLL)`) and audited `auth.mfa_enroll_started`. It is
**never returned again**: no read route, no admin route, and the server-side TOTP verifier is the only
other consumer. **Logging:** never logged at any level.

No retention window: it lives and dies with the user row. Its siblings `users.password_hash` and
`users.totp_recovery_codes` are **argon2id one-way hashes** and are deliberately *not* ciphered — there
is no plaintext to protect.

#### PL-4 · Operational metadata (non-PHI)

**Applies to:** `audit_log.detail` · `audit_log.client` · `sessions.token_hash` / `client` · `processed_files` ·
`pending_approvals.params` · `delivered_keys` · `resend_log` · `queue.handler_name` / `destination_name` /
`channel_id` · `messages.control_id` / `message_type` · `webauthn_credentials.public_key` · `state.namespace` /
`state.key` · `reference.name` / `version` / `key` · `connection_event.peer_host` · the `attachment`
header row (`content_type`, `total_bytes`, `refcount`, `created_at`) + the `message_attachment`
linkage · `secret_rotation_meta` (all three backends) · `.mfbak` on the server backends.

Deliberately **not** ciphered, so that ids stay indexable and the audit trail stays greppable for
incident response. Integrity for `audit_log` comes from the **tamper-evident hash chain** — *keyless SHA-256 in the default keyless posture, upgraded to HMAC-SHA256 on an HKDF-derived subkey of the store DEK only when a store key is set (#190), or an isolated-module Transit MAC under `cipher_provider=vault_transit`* — so its strength is **key-custody-dependent**, and the unqualified reading describes the non-default case (the `client`
address is folded *inside* it), not from a cipher.

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
- `delivered_keys`, `resend_log`, `processed_files`, `webauthn_credentials.public_key`,
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
- `connection_event.peer_host` — removed with its row on
  `[retention].connection_event_retention_hours`.
- `attachment` header + `message_attachment` linkage — the join rows are `DELETE`d and the header's
  `refcount` decremented (GC at 0) inside `purge_message_bodies` / `purge_dead_letters`
  (`_release_message_attachments`), with a startup `sweep_orphan_attachments` reclaiming orphans.
- `secret_rotation_meta` — **no purge path on any backend**; one row per tracked secret, replaced in
  place by the watcher's upsert (all three backends since #1186).
- `.mfbak` — keep-N (`[backup].retention_keep`), as PL-1.

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

- **Peek, not full-parse, on the hot path.** Routing/filtering reads only the specific HL7 fields a
  Router asks for via the tolerant `Peek` ([parsing/peek.py](../messagefoundry/parsing/peek.py)); the
  version-aware full object model (hl7apy) is built only on the opt-in strict path. The engine never
  materializes more of a message than the work requires.
- **Encrypt-after-use at the boundary.** A decrypted body lives in heap only for the lifetime of one
  pipeline stage; the store cipher re-encrypts every PHI column the moment it is written back
  ([store/crypto.py](../messagefoundry/store/crypto.py)), so persisted data never lingers in plaintext
  at rest and the staged queue carries the message forward rather than holding it open.
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
swap an attacker cannot reach without already owning the host. ⚠️ **Both halves are operator-asserted
and engine-unchecked — say so whenever this is offered as compensating.** §2 records it directly: there
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

⚠️ **The record is the scorecard itself** — `docs/security/asvs-scorecard.toml`, rendered and CI-gated
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

`mfenc:v2` is the **shipped default** writer (`[store].aad_bind` defaults `true`), so these properties
describe the format a new deployment actually writes — not an opt-in path. `mfenc:v1` remains
decode-only and frozen.

**Why runtime selection is refused, stated as a cost rather than a gap.** An algorithm identifier in
this system is read from three places: configuration (the *operator* chooses), the wire (a token
*minter* chooses), and **stored data** — `mfenc:v2`'s `alg` segment, which means *whoever can write a
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
| Engine API ↔ console | Loopback HTTP by default; off-loopback requires TLS — **in-process** (`[api].tls_cert_file`, WP-13a) **or upstream** at a trusted reverse proxy (`tls_terminated_upstream` + `trusted_proxies`, WP-15) `[BUILT]`. HSTS engages on `https`; forwarded headers are trusted only from `trusted_proxies`. | — |
| AD / LDAP auth | **LDAPS** with cert verification (`ad_tls_verify`) `[BUILT]` | — |
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
  absolute (12 h) timeouts; password change / disable revokes sessions immediately.
- **Local passwords** are argon2id; lockout after 5 failed attempts. AD users bind over LDAPS.

### Browser ops dashboard (`/ui`, ADR 0065) — `[M1: read-only; pending owner ASVS sign-off]`

The engine serves a same-origin, **read-only** browser ops dashboard under `/ui`. It is **on by default**
(`[security].serve_web_console`, ADR 0143 — the console is the operator UI, effectively core; disable with
`serve_web_console = false` to shrink to a JSON-only surface). Default-on applies to **local loopback**
binds; on an exposed instance a default-on console auto-degrades to JSON-only unless explicitly enabled
with TLS + a public origin. It is a client of the existing API and reuses every server-side PHI
control unchanged (`messages:view_raw`/`view_summary` RBAC, field-level redaction, the per-access
`message_view` audit, the `require_phi_read` throttle). The browser-specific PHI rules:

- **No PHI in browser storage.** The only stored item is the session token, in an **HttpOnly + SameSite=
  Strict** cookie JS cannot read (`mf_session`). Nothing is written to `localStorage`/`sessionStorage`/
  `IndexedDB`. **PHI in URLs — corrected 2026-07-30, and §7 was the accurate half:** this bullet used to claim no PHI is placed in a URL at all. The console's own search route takes the needle as a QUERY PARAMETER — `GET /ui/messages/search?content=…&field_value=…` (`messagefoundry_webconsole/routes/search.py`) — so a search URL can carry an MRN into history, bookmarks and `Referer`. What holds is narrower: no *message body* is ever placed in a URL, and `Referrer-Policy: no-referrer` is set. Note that `_security.py`'s comment justifies that header on the grounds that "/ui URLs carry opaque ids only (never PHI)" — the header is still right, its stated REASON is not. Moving the needle out of the URL is tracked separately (§7).
- **No caching.** Every `/ui` HTML response and every PHI JSON read is served `Cache-Control: no-store`,
  so a browser/proxy never retains a message body on disk. The covered set is the PHI-read route
  families — `/messages*`, `/dead-letters*`, `/search*`, `/logs*`, `/uploads*` (`_NO_STORE_PREFIXES` in
  `api/app.py`) — and a test walks every registered route and fails if a PHI read ever lands outside
  them, so a new PHI surface cannot ship header-free the way `/search/layered`, `/logs/tail` and
  `/uploads/{file_id}/messages` each did.
- **Audited raw view only.** A raw message body is shown only via the same audited `GET /messages/{id}`
  path as the desktop console (record_view + tamper-evident `message_view` audit); there is no second,
  unaudited PHI render path (no server-side parse-tree endpoint in M1).
- **Attachments are neutralized at serve, never rewritten.** A detached document (ADR 0105) is a
  verbatim clinical payload carrying its own attacker-influenced `OBX-5.2` MIME label, and the
  preserve-the-original invariant forbids editing the stored bytes — so the browser-safety control runs
  at *serve* time, not on the stored document: a browser-active label (`html`/`xml`/`script`/`svg`,
  case-folded) is downgraded to `application/octet-stream`, which also strips a `.svg`/`.html` download
  name, and the response carries `Content-Disposition: attachment`, `X-Content-Type-Options: nosniff`
  and `Content-Security-Policy: default-src 'none'; sandbox` on both the JSON route and the `/ui`
  delegate. No served representation can execute in the application origin. Trade-off: `svg`/`html`
  attachments no longer preview in the browser; the bytes are unchanged and still downloadable.
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
`message_view` (raw body), `summary_search_display` / `dead_letter_display` (patient summaries),
plus the auth and admin events listed in [SECURITY.md](SECURITY.md). Each row carries actor,
action, timestamp, channel, the caller's `client` address, and a JSON `detail` (filters, counts,
exposed control IDs — **not** the bodies). Read the trail via `GET /audit` (`audit:read`).
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
| `messagefoundry dryrun` | Bodies (`raw`, every `deliveries[].payload`, **and** the PHI `summary`) are **redacted/withheld by default** in its JSON output ([__main__.py](../messagefoundry/__main__.py), `_redact_body`); `--show-phi` opts in `[BUILT]` (review H-12) | Still: never run against real PHI, and never `--show-phi` into a committed file or CI log |
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
Reinforcing that convention, `messagefoundry check` ships an **advisory `raise-fstring` lint** that
AST-scans the config-dir Router/Handler modules and flags `raise <Exc>(f"...{var}...")` (an f-string
raise interpolating a variable — the pattern that can carry free-text PHI past redaction); it prints a
heuristic reminder and never blocks the gate. The existing controls — never log full bodies at
INFO+, the CR/LF log-injection filter, and silencing python-hl7's PHI-prone loggers — remain in
[logging_setup.py](../messagefoundry/logging_setup.py).

**Global log redaction + prod-DEBUG guard `[BUILT]` (Gate #1).** **Three** handler filters run, **on every record emitted by the engine process and by the ADR 0087 sandbox worker child**, in this
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
   only reason a live OIDC authorization code does not land in the access log.
3. **`ControlCharScrubFilter`** — CR/LF + C0/DEL escaping (log-injection defence, ASVS 16.4.1).

`redact()` rewrites only HL7-shaped spans plus date/DOB runs and multi-token name runs, so ordinary
operational lines are untouched. This makes `safe_exc()` (above) the explicit chokepoint and the global
filters the backstop for anything that reaches a handler un-redacted. `configure_logging` additionally
**silences python-hl7's PHI-prone loggers** (they are named by `__file__`, so they are matched by the
`hl7` package directory and pinned to `CRITICAL`).

**Residual, stated honestly:** `redact()` does **not** scrub a *single-token* identifier. An access line
carrying `?content=1234567` or `?field_value=MRN12345` survives the whole filter chain unredacted (one
`&` is below the HL7 field-run threshold, and those parameter names are not in the credential list).
That is why the engine classifies the general log as a PHI read surface (below) and why moving the
search needle out of the URL is tracked separately.

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
[`logging_setup.configure_logging`](../messagefoundry/logging_setup.py), and the **same three handler
filters** above are installed on **every** sink, so the forwarded stream carries the identical
PHI-redaction + log-injection guarantees as stdout; `json.dumps` additionally escapes control characters
so a record can't break the one-line-per-record framing — JSON is therefore the recommended (and
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
connection's `tls_hop_attested`), **synthetic instance → ALLOW**, **clamped global escape → WARN**,
**enforcing PHI instance → REFUSE (`serve` exits 2)**, **non-enforcing PHI → WARN**. The three named
remedies are therefore: native TLS, a loopback agent, or an attested hop.

> **Why this cell still reads the data label, when the transport cells no longer do.**
> [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) removed
> the `synthetic → ALLOW` arm from the shared cleartext-hop authority, and its *Explicitly out of scope*
> table keeps this forwarder on the old keying **deliberately**: it is not a connection, so it has
> nowhere to carry a per-hop `cleartext_accepted` declaration, and refusing it instead would create a
> deviation the loosening registry cannot express. The arm is therefore restated explicitly inside
> `forward_hop_disposition` rather than inherited from the authority. A `[logging]` sibling of
> `cleartext_accepted` is the recorded follow-up.

**Availability.** The forwarder never blocks the engine *indefinitely* — UDP is fire-and-forget; a `tcp`
**or `tls`** collector that is **unreachable at startup** (or whose certificate fails to verify —
`ssl.SSLError` is an `OSError` subclass) is skipped with a warning and the service starts without it,
and one that **stalls at runtime** is bounded by a 5-second socket timeout pinned on every reconnect —
including the TLS handshake — after which the record is dropped, so a wedged SIEM can't stall the
asyncio event loop. `configure_logging` reports whether the handler was actually installed, so the
"forwarding enabled" line never contradicts a skipped collector. The send is still synchronous, so for a
high-volume feed prefer UDP or a local agent.

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
| **1. General application log** | operational events, worker/connection lifecycle, exception **types**, warnings, every alert that the `LoggingAlertSink` fallback implements when no `[alerts]` transport is configured (see row 13 for the two it does not) | single-line text (`[logging].format = "text"`, the default) or one JSON object per line (`"json"`); UTC `Z` timestamps in both | stdout only — the engine installs **no file handler**; under NSSM the supervisor captures stdout/stderr to `<DataDir>\logs\service.out.log` / `service.err.log` | day-to-day operations, incident triage, and the source of the support-bundle tail in row 14 | at rest: the NSSM installer creates `<DataDir>\logs` and locks the whole DataDir with `icacls /inheritance:r` to SYSTEM + Administrators + the service account (best-effort — a failure warns, never aborts). Over the API: `GET /logs/tail` requires the dedicated **`logs:view`** permission **and** `require_phi_read`, and every served page writes a `logs_view` audit row (line **count** only, never content) | NSSM rotates by **size** (`AppRotateBytes` 10 MB) and never deletes by age; age deletion is `[retention].app_log_days` over `[logging].log_dir` (`.log`/`.txt`, by mtime, **content never read**), optionally preceded by in-place gzip on `[retention].app_log_compress_days` (integrity-validated before the original is removed; the archive keeps the source's mtime, so the same delete window ages it out). Both default 0 = keep forever, uncompressed | **Can contain PHI.** The engine's own permission catalog classifies this as a PHI read surface (`logs:view`: "best-effort redaction, residual single-token PHI possible"). Defence: never-log-bodies rule, `safe_exc()` at the source, the three handler filters, python-hl7 loggers silenced. **Residual:** a single-token identifier is not scrubbed |
| **2. `uvicorn` request/access log** (sub-stream of 1) | one line per HTTP request — method, **full request line including the query string**, status, timing | inherits stream 1's format | inherits stream 1's sink | request tracing, latency and error triage | inherits stream 1's | inherits stream 1's | **Can contain PHI.** `configure_logging` clears uvicorn's own handlers and propagates to the root, so the three filters apply; `serve` passes `log_config=None` and never disables `access_log`, so at the default `INFO` level every request is logged. OIDC `code`/`state` **are** scrubbed. **Not** scrubbed: PHI-shaped search needles on GET routes (`?content=…`, `?field_value=…`) — the single-token residual above |
| **3. `messagefoundry.audit` off-box tee** (sub-stream of 1) | one JSON object per **committed** `audit_log` row: `event`/`ts`/`action`/`actor`/`channel_id`/`client`/`detail` | JSON | emitted after the row is durably committed and **outside** the store write lock; rides stream 1's handlers | shipping audit evidence to a SIEM so it survives a host compromise | inherits stream 1's | inherits stream 1's | `detail` is passed through the `safe_text` PHI chokepoint **before** it leaves the process; `client` is forwarded verbatim as a discrete field so a SIEM can index it. Best-effort: a logging failure is caught, never raised into the audit write. **Pinned to `INFO`** — it is emitted even at `[logging].level = WARNING` |
| **4. Off-box syslog/SIEM forwarder** — the shared **transport** for 1–3 | a copy of every record from 1–3 | `forward_format`, default **JSON** (independent of the stdout format) | the operator's collector (`forward_host`/`_port`) | off-box evidence retention / SIEM correlation | **default-on when a collector is named.** Transport: `udp` (default) / `tcp` / **`tls`** (RFC 5425, CA-anchored, verified by default). `serve` gates the hop on the shared posture gradient before the handler is installed: verified TLS ungated; otherwise loopback / attested / synthetic ALLOW, non-enforcing PHI WARN, **enforcing PHI REFUSE (exit 2)** | the collector's, not the engine's | the identical three filters are installed on this handler, so the forwarded copy is PHI-redacted — but it still carries usernames, connection names, message ids, client addresses and the audit chain. That is the engine's own stated reason for gating the hop |
| **5. `audit_log` table** (SQLite, Postgres, SQL Server) | who / what / **where-from** / when of auth + PHI *access* and admin actions — plus, when the opt-in `[security].audit_all_authorization_decisions` is on (**default `false`**; the internal field it desugars to is `audit_all_authz`, whose old `[diagnostics]` TOML spelling is **refused at load** — ADR 0118), an `authz` row for **every** authorization decision including successes, which multiplies this stream's volume — `actor`, `action`, `channel_id`, `client`, `detail`, `row_hash` | JSON `detail`; **tamper-evident hash chain** over `prev_hash` + the row (the `client` address is **inside** the chained payload — ADR 0150) | the store database | HIPAA §164.312(b) audit controls; incident response; `verify_audit_chain` integrity checks | `GET /audit` requires **`audit:read`**; `GET /audit/export` requires the separate **`audit:export`** and streams CSV with formula-injection neutralisation, recording its own `audit.export` row *before* streaming; `GET /me/security-events` is a per-user view of the same table | **`[retention].audit_days` is reserved and NOT enforced — keep-forever by design** (deleting rows would break the chain; HIPAA expects ~6 years) | `detail` is stored **in the clear** (it is not a cipher-covered column): its protection is that writers only ever store filter shapes, counts and ids — never bodies or credentials — plus the store ACL and the volume layer |
| **6. `message_events` table** | the per-message disposition timeline — the **complete** vocabulary is `received`, `routed`, `unrouted`, `filtered`, `transformed`, `delivered`, `failed`, `dead`, `error`, `replayed`, `resent`, `reingressed`, `passthrough`, `passthrough_dropped`, `cancelled`, `edit_resend`, `edit_resubmit`, `viewed`, `not_deployed`, and the ADR 0154 synchronous-reply pair `reply_returned` / `reply_timeout` (names, counts and `waited_ms` only — **never** a fragment of the partner's reply body) (CI asserts this list against the engine's own `MESSAGE_EVENT_KINDS`). `[diagnostics].message_events` can thin the set, but never below the compliance floor `viewed` / `dead` / `error` / `failed` / `not_deployed` / `reply_timeout` | rows: `message_id`, `ts`, `event`, `destination`, `detail` | the store database | operator timeline on the message-detail view; the `viewed` row is the HIPAA PHI-access record | `GET /messages/{id}` under **`messages:view_raw`** + `require_phi_read`; the read itself writes a `viewed` event **and** a `message_view` audit row | no dedicated window — `purge_message_bodies` sets `message_events.detail` to `NULL` in the same transaction that blanks the body, so it inherits `[retention].messages_days` | `detail` is `safe_text()`-scrubbed **then** cipher-encrypted (AAD `("message_events","detail",message_id,ts,event)`). Verbosity gate `[diagnostics].message_events` = `all` (default) / `errors` / `off`, with a **compliance floor that can never be thinned**: `viewed`, `dead`, `error`, `failed`, `not_deployed`, `reply_timeout` are retained at every level (`reply_timeout` is the one row that explains a "we called you and got a 504" complaint, so an instance that thinned its logs would lose exactly the record it is later asked for) |
| **7. `connection_event` table — DEFAULT ON** (`[diagnostics].connection_events = true`) | transport/lifecycle events per connection: `established`, `closed` (reason `eof` or `idle_timeout` — no path produces any other), `idle_timeout`, `at_capacity`, `peer_not_allowlisted`, `frame_oversize`, `framing_error`, `peer_reset`, the inbound-HTTP intake-auth refusals `intake_auth_failed` / `auth_subject_denied` / `auth_rate_limited` (ADR 0154 D6 — peer address and mode only; **never** the credential, a prefix of it, or its length. Each of these also writes a tamper-evident audit-log row — the copy that survives an operator turning this diagnostics stream off), plus the runner's `connection_lost` / `connection_restored`. That is the whole vocabulary, asserted in CI against the literal emit call sites in `transports/` and the pipeline runner **and** cross-checked against the console's own filter tuple. The MLLP, raw-TCP and HTTP listeners emit these; the **DICOM inbound C-STORE SCP** and the **`ISA`/`IEA`-framed X12 inbound** emit none — the runner injects the sink onto **every** source (`wiring_runner.py`, over the base-class `on_connection_event` field), so both connectors *have* the wiring and simply never call it — so this stream covers those three listeners plus the runner's outbound-lane transitions — not literally every connection. An X12 feed's connects, allow-list refusals and at-capacity refusals are therefore **absent** from this stream | rows: `ts`, `connection`, `transport`, `direction`, `kind`, `peer_host`, `message_id` (correlation hint), `reason` | the store database, **all three backends** | Corepoint-style transport diagnostics — "did the sender connect, and why did it drop" | `GET /events` and `GET /connections/{name}/events` under **`monitoring:read`** (**not** a PHI permission) with per-channel RBAC — an out-of-scope `connection=` is 403'd *and* audited — server-clamped to ≤1000 rows | `[retention].connection_event_retention_hours` (its own **hours** window); 0 inherits `[retention].messages_days`; both 0 = keep forever. Plain age `DELETE` (metadata-only) | **`reason` is free text that can carry sensitive fragments.** Defended twice — `safe_exc()` at the source, `safe_text(reason)[:200]` at the store — then cipher-encrypted (AAD `("connection_event","reason",connection,ts,kind)`). Every other column is config metadata; the table is documented **metadata-only** — never a frame, body or HL7 field value. Writes are a pure side observer: a bounded in-memory queue drained by a background task outside any handoff transaction, so a flood can never block a listener or pin a message disposition |
| **8. `alert_instance` table — default on wherever an `[alerts]` notifier exists** | resolvable operator alerts: `connection_stopped`, `queue_buildup`, `lane_stuck`, `message_stall`, `saturation`, `connection_error`, `content_match`, `storage_threshold`, `cert_expiry`, `secret_rotation`, `bootstrap_admin_expiring` (the UNCLAIMED first-run bootstrap admin nearing its auto-disable deadline — ASVS 6.4.5; its payload carries only the ISO deadline plus whole hours remaining, never the password or any secret), `integrity_drift`, `update_available`, `backup_failed`, `rcsi_off_degraded`, `leadership_acquired`, `dr_activated`, `gcm_invocations` (the per-key AES-GCM invocation bound crossing its 2^31 soft warn — ASVS 11.3.4; its payload carries a one-way `key_id` fingerprint plus counters, never key bytes) The three reachable **inverse** signals — `connection_restored`, `leadership_lost`, `dr_released` — are never rows here: `_record_state` routes an inverse through `_AUTO_RESOLVE` to `resolve_alert_instances_for`, never to `upsert_alert_instance`. (A fourth mapped key, `connection_started`, is emitted by no code path today.) | rows: `event_type`, `connection`, `severity`, `status`, `first_seen`, `last_seen`, `count`, `reason`, `acked_by`, `acked_at`, `resolved_at`, `suspended_until`, `escalation_tier` | the store database, **all three backends** | the operator alert list — acknowledge / resolve / suspend. Durable state is recorded **before** any suppression or throttle return, so a muted alert still leaves a record | `GET /alerts/active` under **`monitoring:diagnose`** (**not** a PHI permission) with the same per-channel scope; ack/resolve/suspend/**resume** are POSTs on the same tier, and the separate read-only `GET /alerts/rules` view sits on its own gate | shares the connection-event window; **only RESOLVED instances are DELETEd**, by `resolved_at` — an open or acknowledged condition is never aged out from under an operator | **`reason` is free text** taken from the event's `detail`/`reason`/`label`: `safe_text(reason)[:200]` then cipher-encrypted (AAD `("alert_instance","reason",event_type,connection)` — the de-dup grain, so one AAD covers both the INSERT and the re-fire UPDATE). `content_match` is **PHI-free by contract**: the sink method takes no value parameter, only the connection, an operator label and an optional rule id |
| **9. `response` rows with `kind='ack_sent'` — DEFAULT ON** (`[diagnostics].response_sent = true`) | the ACK/NAK the engine returned to an inbound sender, under a sentinel destination `\x1fack:<inbound>` | rows: `ack_code` (`AA`/`AE`/`AR`/`CA`/`CE`/`CR`), `ack_phase` (`decode`/`parse`/`strict`/`ingest`), `outcome`, `body`, `detail` | the store database | "what did we actually reply, and why" — the operator's answer to a sender disputing an ACK | `GET /messages/{id}/responses` under `messages:read` + `require_phi_read`; the `body` only for a caller who also holds `messages:view_raw`; every read writes a `response.read` audit row | `body`, `detail` and `resp_headers` are set to `NULL` in place by `purge_message_bodies` on the message-body window, on all three backends | **PHI fail-safe:** the ACK **body** is stored **only when the store cipher is active** — on a keyless store it is `NULL` rather than plaintext — and every NAK passes no body at all, so the offending field value is never persisted. The disposition metadata (`ack_code`/`ack_phase`/`outcome`) is non-PHI and always captured; `detail` is `safe_text`-scrubbed, 200-char bounded and encrypted |
| **10. `[alerts]` webhook transport** (off by default — `webhook_url` unset) | one HTTPS POST per alert, carrying every non-underscore event key as JSON | JSON | the operator's webhook endpoint (Slack/Teams/PagerDuty/custom) | operator notification | **`https` only** — a plaintext `http://` webhook URL is refused at construction unless the `MEFOR_ALLOW_INSECURE_TLS` escape is set (and then a warning is logged); since #329 this path routes that escape through the clamped `weakened_tls_escape_permitted(posture)` (the instance posture threaded from the API lifespan), so on an enforcing-PHI instance the escape is inert and a cleartext webhook POST stays refused — the same clamp as the connectors, no longer the raw escape. Redirects are refused; an optional `webhook_allowed_hosts` egress allowlist gates the host | the endpoint's | **carries the alert's `detail`/`reason` free text** (`safe_exc()`-scrubbed at the emit sites, but **not** re-run through `safe_text` on this path). Internal `_`-prefixed keys (per-rule recipients, rule id, cooldown) are stripped before send, so recipient addresses never cross the wire |
| **11. `[alerts]` SMTP transport — operator alert list** (off unless `email_smtp_host` + `email_from` + ≥1 `email_to`) | one email per alert; default subject `[MessageFoundry] <SEVERITY> <type> — <connection>`, default body every non-underscore event key as `k: v` | plain text (always kept — never HTML-only); optional HTML alternative | the operators' mailboxes | operator notification | `smtp_allowed_hosts` egress allowlist; the SMTP password comes from `MEFOR_ALERTS_EMAIL_PASSWORD` or a `[secrets]` provider, never the config file; per-send timeout `email_timeout` | the mail system's | carries the same `detail`/`reason` free text as the webhook. #138 operator templates are constrained to a **closed non-PHI variable allowlist** validated fail-closed at config load. **Transport posture:** `send_plain_email` builds an explicit **verifying** context (chain + hostname + strict RFC 5280, TLS 1.2 floor) via `tls_policy.build_smtp_tls_context()` and passes it to `starttls()`, anchored to the OS roots, `[alerts].email_tls_ca_file`, or `[tls].internal_ca_file` — the same factory the EMAIL and DIRECT *message destinations* use, so all three SMTP cells now share one policy ([#323](archive/backlog/BACKLOG-CLOSED.md#323-smtp-tls-is-unverified-on-all-three-send-paths), closed 2026-08-02). Before that this call passed **no** context and Python's stdlib default applied (`ssl._create_stdlib_context` **is** `ssl._create_unverified_context` — `CERT_NONE`, `check_hostname = False`), leaving the hop encrypted but unauthenticated. There is still **no hop gradient or attestation on this path** — unlike the connectors, this cell is constructed outside the `active_hop_posture` scope, so its deviations (`email_use_tls = false`, or `email_tls_verify = false`) are gated by a `[security].allow_unverified_alert_smtp_tls` **acknowledgment switch at the serve gate** rather than by the clamped escape: on an enforcing PHI instance `serve` refuses to start without it, and permits + `AUDIT`-logs the start with it. Both deviations are named by `security_loosenings()` and reported by `messagefoundry check`'s `alert-smtp-tls` advisory |
| **12. Per-user security-event SMTP notifier** — **posture-mandatory on a PHI instance** | `account_locked`, `login_after_failures`, `password_changed`, `password_reset`, `email_changed`, `roles_changed`, `account_disabled`, `mfa_enabled`, `mfa_disabled`, `admin_action_new_ip` | plain-text email | the **affected user's own** mailbox | ASVS 6.3.5 / 6.3.7 out-of-band notification of security-relevant account changes | shares stream 11's SMTP transport and therefore its verifying context and its `[alerts].email_tls_*` knobs — note this is a **separate call site** (`pipeline/security_notify.py`), plumbed in its own right rather than inheriting by accident. On a PHI instance with auth enabled `serve` **refuses to start (exit 2) under `[security].enforcement = enforce`** when no effective channel exists; the explicit, **audited** opt-out is `[alerts].security_notifications_required = false` | the mail system's | the body carries the account username, a fixed description, optionally the failed-attempt count or the new email on file, and the source IP — **no message data, no secrets**. Dispatch is a bounded background queue; a failed send is logged, never raised (the event is still in `audit_log`) |
| **13. `LoggingAlertSink` fallback** (when no `[alerts]` transport is configured) | every alert **this state-less sink implements**, at `WARNING` — `leadership_lost` / `dr_released` at `INFO`, and `connection_restored` is a **deliberate no-op** (a recovery needs no page and there is no instance to auto-resolve), so a lane recovery produces no record on this stream at all. `content_match` exists only on `NotifierAlertSink` and has no fallback-path record | — | folds into stream 1 | so alerts are never silent | inherits stream 1's | inherits stream 1's | includes the `detail`/`reason` free text, and therefore inherits stream 1's filters, ACL, forwarder and retention |

| **14. `messagefoundry support-bundle` archive** (operator-invoked CLI, never automatic) | `app-log.txt` — the trailing **500** lines (`DEFAULT_LOG_TAIL_LINES`) of the configured app log — plus a secret-free `config-summary.json` (counts/names only) and a metadata-only `status.json` | text members inside a `.zip` | the operator-supplied `--out` path — **outside** the store and outside the NSSM DataDir ACL | hand-off to support: this stream exists precisely to leave the box | **none once written.** Filesystem permissions on wherever `--out` points are the only control; the CLI carries no RBAC and writes no audit row | **none** — never swept by `[retention].app_log_days` or anything else; the operator owns the file | Inherits stream 1's residual and passes a **fourth** redactor, `support/redact.py::redact_log_line` — **not** the three handler filters. Treat a bundle as a copy of stream 1, at stream 1's PHI class |

**Not in this inventory, and why.** The **Windows tray** (`messagefoundry.tray`, ADR 0113) ships *inside* the wheel as the `messagefoundry-tray` gui-script, and its `_setup_logging` attaches a `RotatingFileHandler` to the **root** logger at `INFO` writing `%LOCALAPPDATA%\MessageFoundry\tray.log` (1 MB × 2 backups). It is a **separate client process** making tokenless `/health` + `/ui` probes, so it carries **no workload data, no PHI and no credentials** ([TRAY.md](TRAY.md)) — but note it carries **none of the three handler filters**, its access control is the interactive user's own profile ACL (it is **outside** the NSSM DataDir `icacls` lockdown), and **no `[retention]` window touches it** — size rotation only, never aged out. `GET /metrics` (Prometheus gauges/counters) and the `/ws/stats`
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

- **Inside the child.** It calls `configure_stderr_logging`, which installs the same three filters on
  its own stderr handler (BACKLOG #1054), so a `WARNING`+ record emitted there by admin-authored
  Router/Handler code, or by a library it pulls, is redacted and CR/LF-scrubbed at the source.
  Redaction is a property of the **handler**, so this is a second installation of the chain rather
  than something the child inherits along with a file descriptor.
- **In the engine parent (ADR 0166, BACKLOG #343).** The child is spawned with
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
  record (ADR 0166).

---

## 8. Retention & purge

**`[BUILT]`** (except `audit_days`, reserved by design)

Enforced by the engine's async retention task
([pipeline/retention.py](../messagefoundry/pipeline/retention.py), `RetentionRunner`). It runs once per
process, independent of the message graph (so it survives config reloads), and never blocks the event
loop. **The runner is backend-agnostic** — it is constructed with the `Store` protocol, started
unconditionally by the Engine when `[retention]` is configured, and contains **no backend branch
anywhere**. Config: [CONFIGURATION.md](CONFIGURATION.md#retention).

**"Off by default" is no longer the whole truth on a PHI instance.** The raw `[retention]` fields do
still default to `0`, but `serve` applies a posture gate on top of them:

- On a **non-enforcing PHI instance**, each **unset** PHI-body window is **auto-bounded to 30 days**
  (secure-by-default) — an explicitly-set value, including an explicit `0`, is respected and only warns.
- On a **PHI instance under `[security].enforcement = enforce`** (the default) with either PHI-body
  window unbounded, `serve` **refuses to start (exit code 2)**.
- The explicit, **audited** opt-out is `[security].allow_keeping_phi_indefinitely = true`, which
  downgrades the refusal to a loud audited warning and suppresses the auto-bound.
- The canonical operator-facing home of the message-body window is now
  **`[security].delete_message_bodies_after_days`**; its *model* default is 30, but the desugar
  is **presence-gated** — only an EXPLICITLY-set switch is written through — so an **unset**
  switch leaves `[retention].messages_days` at **0**, and the posture gate above (auto-bound /
  refusal) is what actually bounds a PHI instance. An explicitly-set value writes through onto
  `[retention].messages_days`. `[retention].dead_letter_days` stays at its own home.

So a PHI instance cannot run with PHI-body retention "off" without a loud, audited opt-out.

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
| `purge_dead_letters` | `[retention].dead_letter_days` (+ per-connection overrides) | NULL/blank in place on DEAD outbound rows | enforced | **enforced** | **enforced** |
| `purge_state` (`state.value`) | `[retention].state_max_age_days` | `DELETE` by `set_at` | enforced | **enforced** | **enforced** |
| `purge_connection_events` (incl. `connection_event.reason`) | `[retention].connection_event_retention_hours`; 0 inherits `messages_days` | `DELETE` by `ts` (metadata-only) | enforced | **enforced** | **enforced** |
| `purge_search_presets` (`search_presets.criteria`) | `[retention].search_preset_days`; `0` = keep forever | `DELETE` by the null-safe greater of `updated_at` / `last_used_at` — whole row (the criteria *is* the payload). Keys on last-**used** (#306); a row predating `last_used_at` (NULL) ages out on `updated_at` alone | enforced | **enforced** | **enforced** |
| `purge_reference_snapshots` (`reference.value` + its key columns) | `[retention].reference_snapshot_days`; `0` = keep forever | `DELETE` of whole rows for a set config **no longer declares** whose `reference_version.synced_at` predates the cutoff — eligibility is re-asserted **inside** the delete (a config reload can commit a fresh snapshot between the decision and the statement). The `reference_version` pointer **survives** with its version bumped to `purged:<v>` and `row_count = 0`, which is what makes a cluster follower converge — `converge_reference_cache` only reloads a set whose version CHANGED, so leaving it would let a follower serve purged PHI from RAM until restart, and deleting the pointer is worse (converge only adds names present in a fresh read). **Orphan-only** — a declared set is never purged | enforced | **enforced** | **enforced** |
| `purge_alert_instances` (incl. `alert_instance.reason`) | same window as connection events | `DELETE` by `resolved_at`, **RESOLVED instances only** | enforced | **enforced** | **enforced** |
| `strip_embedded_documents` | per-inbound `prune_documents_after` + `prune_documents_min_bytes` (**no global default** — nothing is stripped without an override) | in-place strip of bulky base64 documents; sets `messages.documents_pruned` | enforced | **enforced** | **enforced** |
| Streaming-attachment release (`release_message_attachments`) | rides the two body windows | refcount decref + GC at 0, plus a startup `sweep_orphan_attachments` | enforced | **enforced** | **enforced** |
| Application **log-file** sweep + compression (`app_log_days`, `app_log_compress_days`) | `[retention].app_log_days` / `[retention].app_log_compress_days` over `[logging].log_dir` | `DELETE` of `.log`/`.txt` files by **mtime** (content never read), plus optional in-place **gzip** of aged files — free-space prechecked, and the archive is decompressed off disk and compared byte-for-byte **before** the original is removed (a failure keeps the original). Bytes are read to compress/verify but never logged or exported; the archive inherits the source mtime, so the delete window still ages it out | enforced | enforced | enforced |
| `wal_checkpoint` | `[retention].wal_checkpoint_seconds` | `PRAGMA wal_checkpoint(TRUNCATE)` | enforced | **no-op (DBA-owned)** — log management is `.ldf` backup / recovery model | **no-op (DBA-owned)** — checkpointer/autovacuum |
| `vacuum` | `[retention].vacuum_at` (a daily clock time, **not** a cron) | `VACUUM` — locks the whole DB, so off-peak; off by default | enforced | **no-op (DBA-owned)** — space reclamation is a DBA operation | **no-op (DBA-owned)** — autovacuum |
| Size threshold (advisory) (`db_status`) | `[retention].max_db_mb` | `storage_threshold` alert + `WARNING`; **never** auto-deletes | enforced | **enforced** — `db_status().size_bytes` is implemented (`SUM(size)` over `sys.database_files`) | **enforced** — `pg_database_size()` |
| DB-tier DR snapshot (`snapshot_to`) | `[backup].*` | `.mfbak` chunked-AEAD archive | enforced | **DBA-delegated** — `snapshot_to` raises `DbaDelegatedError`; the BackupRunner falls back to a **config-only** archive, or skips when `[backup].config_only_on_server_db = false` | **DBA-delegated** — same |

Three further prunes run **outside** the retention runner: `processed_files` (age/count prune, driven
from the wiring runner), expired sessions (`purge_expired_sessions`, driven from the auth layer), and
**uploaded files** (`uploaded_file.body` / `uploaded_file.meta`) — auto-pruned after
`[store].uploads_retention_days` (default **30**, `ge=1`; defaults-ON whenever `[store].uploads_dir` is
set) by a periodic `UploadRetentionRunner` plus an opportunistic save-time sweep, each pair
`upload.prune`-audited (ASVS 5.2.4, #291).

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
| `reference.value` (a **declared** set) | **orphan-only** coverage. `purge_reference_snapshots` bounds a set config has DROPPED; a set still declared is never purged whatever its age, because its snapshot is live data. The wired-set case remains unbounded — the honest gap |
| `queue.payload` (stage=`ingress`/`routed`, **DEAD**) | **no purge reaches it** — added 2026-07-30 by the ASVS 14.2.7 classification sweep, which is the only reason it was found. The happy path consumes these rows at `route_handoff`/`transform_handoff`, so they are documented as transient — but a router or handler content fault calls `dead_letter_now` (`pipeline/wiring_runner.py:4415`, `:4449`), which sets status/`last_error` and **never touches `payload`**, while both purges are scoped `Stage.OUTBOUND` (`store/store.py:8384`, `:8659`). So `messages.raw` blanks on its window and the message reads as purged while a **full raw PHI body survives here indefinitely**. Filed as its own defect; the likely fix is to let a DEAD ingress/routed row ride `[retention].dead_letter_days` exactly as a dead outbound row does |
| `mefor-backup-*` / `mefor-tar-*` / `mefor-verify-*` staging dirs | no window — a `TemporaryDirectory` unlinks on exit, but **not** on a crash or `SIGKILL`, and `verify_after_backup` (default `true`) decrypts a full archive back out to a second temp dir on **every** run. The engine applies **no ACL** on these paths (`_secure_file` is never called on them, and on a server-DB store — the deployed posture — it applies no file ACL at all), so the cover is the operator's: FDE on the temp volume plus `TMP`/`TMPDIR` pointed at a directory the OS restricts to the service account ([§10](#10-secure-deployment--operations-checklist)) |
| `users.totp_secret` | no window by design — it lives and dies with the user row |
| `audit_log`, `delivered_keys`, `resend_log` | keep-forever by design (see below) |
| `messages.control_id`, `messages.message_type` | kept for the life of the message row by design (dedup/routing keys) |
| PL-5 substrate (SQLite `-wal`/`-shm`; SQL Server `.ldf` + tempdb; Postgres `pg_wal`) | not application-managed — database/platform lifecycle |

**`audit_days` is reserved / keep-forever by design.** The `audit_log` is a tamper-evident hash chain
(deleting rows would break `verify_audit_chain`, §6) and HIPAA expects ~6-year audit retention, so audit
pruning is deliberately **not** enforced. The value is accepted (not rejected) so a forward-looking
config file still loads. Archive-first audit pruning (export → delete → re-anchor the chain) is a
tracked follow-up.

---

## 9. De-identification

**`[BUILT]`** (HL7 v2 first; ADR 0030, PR #440)

The de-identification framework is **built** and **centralized** — do **not** inline ad-hoc de-id
logic; route it through the framework. It lives in [`messagefoundry/anon/`](../messagefoundry/anon/)
(vendored **byte-identical** to `tee/anon/` for the standalone tee relay) and exists to build
**PHI-free test datasets from real traffic**. Pure stdlib — it adds no new dependency.

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

Surfaces: the **`messagefoundry tee anonymize-captures`** subcommand and the test-harness
`CaptureSink`/corpus hooks. [`scripts/security/scan_forbidden.py`](../scripts/security/scan_forbidden.py)
is now the **single leak-token source-of-truth** (a fail-closed leak gate). HL7 v2 is supported first;
X12/FHIR seams come later.

Note: encryption-at-rest (§3) and log redaction (§7) are **not** de-identification — do not conflate
"we encrypt" or "we redact logs" with "we de-identify."

### AI coding assistance

**`[BUILT]`** (code-only) / **`[ROADMAP]`** (anything beyond)

The IDE AI assistant **never sends message bodies in the MVP.** It is bounded to the `code_only`
data scope — the graph's connection/router/handler names and the active editor's code — and the chat
path carries an explicit guard against attaching anything more, **regardless of mode or provider**.
No patient data leaves the workstation through the assistant.

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
      destination and the File-connector dirs to the service account (the file ACL is best-effort,
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
- [ ] **Change the bootstrap admin password immediately** (see [SECURITY.md](SECURITY.md)).
- [ ] **Supply secrets via env**, never the TOML (`MEFOR_STORE_PASSWORD`,
      `MEFOR_AUTH_AD_BIND_PASSWORD`, future `MEFOR_STORE_ENCRYPTION_KEY`).
- [ ] **Never feed real PHI to `dryrun`/`generate`** or redirect their output to shared locations (§7).

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
| **P2-2** MFA for console/API auth — ✅ **Built (WP-14, native TOTP, local accounts)** | Single-factor auth (mitigated for local accounts: `[auth].require_mfa` gates **step-up / sensitive admin operations** for the Administrator role — not every PHI read; AD MFA delegated) | §164.312(d) · IA-2(1) (NPRM-mandated) | M–L |
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

---

## 13. HIPAA §164.312 mapping (data safeguards)

Complements the access/audit mapping in [SECURITY.md](SECURITY.md#hipaa-164312-alignment).

| Safeguard | Status | Where |
|---|---|---|
| Access control (a) | Built (RBAC + owner-only DB/`-wal`/`-shm` ACL — **SQLite store only**; on SQL Server / Postgres the file permissions on `.mdf`/`.ldf`/tempdb/native backups are **DBA-owned**, see §2) | [SECURITY.md](SECURITY.md), §2 |
| Audit controls (b) | Built (PHI-access audit, tamper-evident chain, off-box tee) + global log redaction (three handler filters) | §6, §7 |
| Integrity (c) | Built (GCM AEAD tag on bodies; audit hash-chain) + periodic integrity checks planned | §3, §6 |
| Authentication (d) | Built (argon2id / AD); native TOTP MFA built for local accounts (WP-14) | [SECURITY.md](SECURITY.md), §11 |
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
