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

**Phase 1 (today): single host, localhost-only, authenticated.** The engine API binds
`127.0.0.1` ([config default](CONFIGURATION.md#api)); the console reaches it over loopback HTTP.
The trust boundary is the **local machine and its OS accounts**: anyone with the engine's service
account, the DB file, or a backup of it can read PHI. Network attackers are out of scope *only as
long as the bind stays on loopback*.

**Phase 2 (later): network exposure.** The moment the API binds anything other than `127.0.0.1`,
the boundary becomes the network and TLS + (planned) MFA become mandatory, not optional — see
[§4](#4-data-in-transit) and [§11](#11-hardening-roadmap).

| Actor / vector | In scope Phase 1? | Mitigation |
|---|---|---|
| Local operator using the console/API | Yes | Auth + RBAC + audit (built — [SECURITY.md](SECURITY.md)) |
| Local user reading the DB file directly | Yes | Owner-only file ACL (built) + at-rest body encryption when a key is set (built — §3); volume encryption for the rest |
| Stolen DB file / backup | Yes | At-rest body encryption (built — §3) + required volume encryption for `summary`/WAL/temp |
| PHI in logs / CI output / shell redirects | **Yes** | "Never log bodies" rule (built) + redaction framework ([ROADMAP], §7) |
| Network eavesdropper on MLLP / API | Phase 2 | MLLP-over-TLS, API TLS ([ROADMAP], §4) |
| Misconfigured outbound destination | Yes | Destination allowlist ([ROADMAP], §4) |

**Correction to older docs:** the API is **localhost-only *and* authenticated** — not "no auth."
Auth/RBAC/audit are built (see [SECURITY.md](SECURITY.md)); only remote *exposure* is deferred.

---

## 2. Where PHI lives — data-at-rest inventory

**`[MIXED]`**

PHI is persisted in the SQLite message store ([store/store.py](../messagefoundry/store/store.py),
`_SCHEMA`). The store *is* the queue (one generic `queue` table, `stage` = `ingress` | `routed` |
`outbound`), so both the inbound message and the per-destination outbound copy are retained durably.

| Location | Holds PHI? | Encrypted at rest today? | Notes |
|---|---|---|---|
| `messages.raw` | **Yes** — full inbound body | **Yes, when a key is set** — AES-256-GCM (`MEFOR_STORE_ENCRYPTION_KEY`); identity otherwise | Preserved verbatim by design (operators must see what arrived) |
| `queue.payload` (stage=`ingress`/`routed`) | **Yes** — the raw body, **transient** | **Yes, when a key is set** — AES-256-GCM | A second copy of the raw, held only across the route→transform window: the `ingress` row is consumed at `route_handoff`, each `routed` row at `transform_handoff` (deleted, never kept). A stalled router/transform stage can hold several briefly — surfaced by the `queue_buildup` alert |
| `queue.payload` (stage=`outbound`) | **Yes** — transformed outbound body | **Yes, when a key is set** — AES-256-GCM | One row per destination; the persistent footprint |
| `queue.handler_name` (stage=`routed`) | No — a handler name, not a body | No (metadata, deliberately not ciphered) | The handler the transform worker runs |
| `messages.summary` | **Yes** — MRN / patient name / order | No (**not** routed through the cipher) | Ingest-derived, indexed for fast search; relies on volume encryption (see §3) |
| `messages.error`, `queue.last_error`, `message_events.detail` | **Possibly** — may embed raw fragments from exceptions | **Yes, when a key is set** — AES-256-GCM (WP-5) | Routed through the store cipher like `raw`/`payload`; NULL/blank values stay as-is. See [§3](#3-encryption-at-rest), [§7](#7-logging--phi-redaction) |
| `messages.control_id`, `message_type` | Low (MSH-10/MSH-9) | No | Needed plaintext for dedup/routing/indexes |
| `audit_log.detail` | Low — exposed IDs/counts, not bodies | No | JSON metadata about PHI *access*, not the PHI itself |
| SQLite file + `-wal` / `-shm` siblings | **Yes** (mirror the above) | No | WAL/shm hold recently-written PHI outside any app-level encryption |
| File-connector output / spill dirs (`.hl7`, `.processed`, `.error`) | **Yes** — plaintext on disk | No | Written by the File transport; treat the directory as PHI |

**The body cipher `[BUILT]`.** [store/store.py](../messagefoundry/store/store.py) routes message
bodies through the store's `_cipher` ([store/crypto.py](../messagefoundry/store/crypto.py)) on
write/read — **AES-256-GCM when `MEFOR_STORE_ENCRYPTION_KEY` is set, identity otherwise** — so
encryption is transparent to callers. Existing plaintext rows are migrated in place on first start
with a key. See [§3](#3-encryption-at-rest).

**File permissions `[BUILT]`.** `MessageStore.open()` restricts the DB and its `-wal`/`-shm` siblings
to the owner on create — POSIX `chmod 0600`, Windows owner-only DACL via `icacls` (inheritance off) —
through `_secure_file()` ([store/store.py](../messagefoundry/store/store.py)). It is best-effort and
non-fatal: a skipped or failed restriction is **logged** (STORE-2), with directory-level ACLs
([SERVICE.md](SERVICE.md)) as the backstop. The File-connector spill dirs remain operator-owned —
harden them per [§10](#10-secure-deployment--operations-checklist).

**Git hygiene `[BUILT]`.** `.gitignore` excludes `*.db` / `-wal` / `-shm`, generated message corpora,
and logs, so runtime PHI is never committed. Keep it that way — never `git add -f` a database or a
real message file.

---

## 3. Encryption at rest

**`[BUILT]` for message bodies; volume encryption for the remainder.**

**Layered: application-level AEAD through the store cipher, plus required volume encryption** — chosen
for defense-in-depth without swapping the `aiosqlite` connector.

1. **Application-level AES-256-GCM `[BUILT]`.** The store's `_cipher`
   ([store/crypto.py](../messagefoundry/store/crypto.py)) encrypts every PHI-bearing column:
   `messages.raw`, `queue.payload`, **and (WP-5) the nullable text columns `messages.error`,
   `queue.last_error`, and `message_events.detail`** — which can embed raw HL7 fragments from
   exceptions. Stored format `mfenc:v1 ‖ key_id ‖ base64(nonce ‖ ciphertext ‖ GCM tag)` — the GCM tag
   also satisfies the HIPAA *integrity* safeguard (tamper-evidence), and the prefix lets reads tell
   ciphertext from legacy plaintext (and from a retention-purged blank `''`, which is never ciphered).
   A one-time migration encrypts existing rows in place on first start with a key.
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
   **Fail-closed/warn:** `serve` warns loudly when no key is set in a `prod` environment, and **refuses
   to start** when `[store].require_encryption = true` and no key is configured.
3. **Required volume encryption.** App-level AEAD **cannot** encrypt the `-wal`/`-shm`/temp files or
   the searchable `summary`/index columns. **BitLocker (Windows) / LUKS (Linux) on the data volume is
   a documented deployment prerequisite** to cover those at rest. App-level + volume together close
   both the "stolen file from a powered-off host" and the "live-host file copy" cases.

**Accepted residual:** `summary`, `control_id`, and `message_type` stay plaintext in the DB (they
must be searchable/indexable); volume encryption is what protects them at rest. If that residual is
unacceptable for a deployment, **SQLCipher** (whole-DB, including WAL) is the documented alternative —
at the cost of a native dependency and replacing the connect path.

**SQL Server backend (experimental):** `encrypt = true` secures the DB *connection* (TLS in transit),
**not** data at rest — at-rest there means SQL Server TDE, configured at the database, not by
MessageFoundry.

---

## 4. Data in transit

**`[MIXED]`**

| Path | Today | Plan |
|---|---|---|
| MLLP inbound/outbound | **Plaintext** TCP (`asyncio.open_connection`) | MLLP-over-TLS (TLS 1.2+, cert verify on) — [P1-4](#11-hardening-roadmap) |
| File connector | Plaintext `.hl7` on disk/share | Rely on volume/share encryption; SFTP later |
| Engine API ↔ console | Loopback HTTP, **no TLS** (Phase 1 localhost-only) | API TLS when bound off-loopback — [P2-1](#11-hardening-roadmap) |
| AD / LDAP auth | **LDAPS** with cert verification (`ad_tls_verify`) `[BUILT]` | — |
| SQL Server backend | `Encrypt=yes` TLS-to-DB `[BUILT, experimental]` | — |

**Hard rule:** never bind the API to `0.0.0.0` (or any non-loopback interface) without TLS in front
of it. Bearer tokens and PHI would otherwise cross the network in cleartext.

**Phase 2 transport design `[ROADMAP]`.** In-process API/WebSocket TLS (P2-1), MLLP-over-TLS (P1-4),
and a reverse-proxy / forwarded-header alternative are designed in
[ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) (*Proposed* — build gated on a
scheduled off-loopback exposure).

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

---

## 6. Audit & accountability

**`[BUILT]`** (one cleanup)

Every PHI access is recorded in the append-only `audit_log` with the **acting user**:
`message_view` (raw body), `summary_search_display` / `dead_letter_display` (patient summaries),
plus the auth and admin events listed in [SECURITY.md](SECURITY.md). Each row carries actor,
action, timestamp, channel, and a JSON `detail` (filters, counts, exposed control IDs — **not** the
bodies). Read the trail via `GET /audit` (`audit:read`). **Credentials, tokens, and PHI bodies are
never written to the audit log.**

**Attribution:** with auth built, the `audit_log.actor` is always populated — a real username, or
`system` for internal actions — so an audit row is never unattributed. (The schema comment was
corrected to say so.)

---

## 7. Logging & PHI redaction

**`[MIXED]`**

**Hard rule (enforced by convention today):** never log full message bodies at INFO or above. Full
payloads go only to the secured store, never the general log. Logging is stdlib today (stdout, NSSM
captures to rotating files); **do not run production at `DEBUG`.**

**Known leak surfaces — treat these as PHI sinks:**

| Surface | Risk | Guidance / plan |
|---|---|---|
| `messagefoundry dryrun` | Bodies (`raw`, every `deliveries[].payload`, **and** the PHI `summary`) are **redacted/withheld by default** in its JSON output ([__main__.py](../messagefoundry/__main__.py), `_redact_body`); `--show-phi` opts in `[BUILT]` (review H-12) | Still: never run against real PHI, and never `--show-phi` into a committed file or CI log |
| `messagefoundry generate` | Prints the offending message to **stderr** only behind an opt-in flag, **off by default** ([generators/adt.py](../messagefoundry/generators/adt.py)) `[BUILT]` | Synthetic data, but keep the flag off whenever output is captured |
| Router/Handler exceptions | A user script doing `raise ValueError(f"...{raw}")` would put PHI into the stored `error`/`last_error`/`detail` and any log of it | **`[BUILT]` (WP-6c):** every exception rendered into a stored disposition or a log goes through the **`safe_exc()` chokepoint** ([redaction.py](../messagefoundry/redaction.py)) — it keeps the exception **type** and redacts HL7-shaped content; §3 also encrypts those columns (defense-in-depth) |

**Exception-path redaction `[BUILT]` (WP-6c).** [`messagefoundry/redaction.py`](../messagefoundry/redaction.py)
provides `redact()` (scrubs HL7 segment/field content from free text, keeping segment IDs) and
`safe_exc()` (the chokepoint used at every exception→`last_error`/`detail`/log site in the
[wiring runner](../messagefoundry/pipeline/wiring_runner.py)). It is conservative redaction, **not**
de-identification (§9); the residual control for free-text PHI a user script invents is the
"never put PHI in an exception message" convention. The existing controls — never log full bodies at
INFO+, the CR/LF log-injection filter, and silencing python-hl7's PHI-prone loggers — remain in
[logging_setup.py](../messagefoundry/logging_setup.py).

**Structured logging `[ROADMAP]`.** structlog/JSON log records + **off-box (syslog/SIEM) forwarding**
are deferred — their payoff is off-box ingestion, so they are bundled with the Phase-2 off-box
exposure work (P2-3, `[conditional]`). Until then, NSSM captures stdout to access-controlled rotating
files (harden the log dir per [SERVICE.md](SERVICE.md)).

### Logging inventory (16.1.1 / 16.2.3)

| Stream | Contents | Format / store | PHI controls |
|---|---|---|---|
| **General log** (stdout → NSSM rotating files) | operational events, exception **types**, redacted messages | single-line text, UTC `Z` timestamps | never-log-bodies rule; CR/LF + control-char scrub; `safe_exc()` on logged exceptions; python-hl7 PHI loggers silenced |
| **`audit_log`** (SQLite) | who/what/when of auth + PHI *access* (IDs/counts, not bodies) | structured JSON `detail`, tamper-evident hash chain | bodies/credentials never written; read via `GET /audit` |
| **`messages.error` / `queue.last_error` / `message_events.detail`** (SQLite) | per-message disposition detail | text, **AES-256-GCM at rest** (WP-5) + **`safe_exc()`-redacted** (WP-6c) | encrypted + redacted; volume encryption backstop |

---

## 8. Retention & purge

**`[BUILT]`** (except `audit_days`, reserved by design)

Enforced by the engine's async retention task
([pipeline/retention.py](../messagefoundry/pipeline/retention.py), `RetentionRunner`). It runs once per
process, independent of the message graph (so it survives config reloads), never blocks the event loop,
and is **off by default** — every `[retention]` window defaults to keep/off. Config:
[CONFIGURATION.md](CONFIGURATION.md#retention).

Past `messages_days` it **nulls inbound bodies (`raw`/`summary`/`error`) while keeping the metadata
row** (counts, disposition, and the audit trail stay intact — the Mirth Data-Pruner pattern), and only
for **fully-resolved** messages — never one with a delivery still `pending`/`inflight`, so at-least-once
is preserved. Dead-lettered outbound rows have their **own** window, `dead_letter_days` (a dead row
stays replayable, re-queueing its *own* stored payload, until its body is purged — which is why the two
windows are independent: nulling `messages.raw` never breaks a dead-row replay). It checkpoints the WAL
on `wal_checkpoint_seconds` and `VACUUM`s daily at `vacuum_at` (a clock time, **not** a cron — no new
dependency; VACUUM locks the whole DB, so it is off-peak and off by default). When the store exceeds
`max_db_mb` it raises an advisory `storage_threshold` alert (+ `WARNING` log) — it **never**
auto-deletes. **Each pass that does real work writes one `retention_purge` `audit_log` entry** with the
cutoffs + counts (no message content — no PHI).

**`audit_days` is reserved / keep-forever by design.** The `audit_log` is a tamper-evident hash chain
(deleting rows would break `verify_audit_chain`, §6) and HIPAA expects ~6-year audit retention, so audit
pruning is deliberately **not** enforced. Archive-first audit pruning (export → delete → re-anchor the
chain) is a tracked follow-up.

**SQLite-only.** On the experimental SQL Server backend, at-rest retention is a DBA concern (TDE + a SQL
Agent purge/shrink job); the engine's retention task targets the SQLite store.

---

## 9. De-identification

**`[ROADMAP]`**

There is **no de-identification framework in the repo**, and this doc does not reference one as if it
existed. When built, the rules will be **centralized**, not inlined ad-hoc. Note: encryption-at-rest
(§3) and log redaction (§7) are **not** de-identification — do not conflate "we encrypt" or "we
redact logs" with "we de-identify."

### AI coding assistance

**`[BUILT]`** (code-only) / **`[ROADMAP]`** (anything beyond)

The IDE AI assistant **never sends message bodies in the MVP.** It is bounded to the `code_only`
data scope — the graph's connection/router/handler names and the active editor's code — and the chat
path carries an explicit guard against attaching anything more, **regardless of mode or provider**.
No patient data leaves the workstation through the assistant.

The `phi` scope is **future** and only reachable over the planned **engine broker** with a **BAA +
zero-data-retention** provider connection; the `deidentified` scope depends on the **unbuilt** de-id
framework above. The assistant is RBAC-gated (`ai:assist`) and governed by a central,
environment-clamped policy — full model in [AI.md](AI.md), permission in [SECURITY.md](SECURITY.md).

---

## 10. Secure deployment & operations checklist

**`[MIXED]`**

For operators standing up the engine (see also [SERVICE.md](SERVICE.md)):

- [ ] **Run under a least-privileged service account**; the engine needs no admin rights.
- [ ] **Lock down the data directory** — the engine sets owner-only perms on the DB + `-wal`/`-shm`
      on create (§2); still restrict the **directory** and the File-connector dirs to the service
      account (the file ACL is best-effort, and the spill dirs aren't covered).
- [ ] **Enable volume encryption** (BitLocker / LUKS) on the data volume — the required at-rest layer
      under §3.
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
§164.312 safeguards and NIST SP 800-53 families; the direction is aligned with the 2025 HIPAA
Security Rule NPRM, which moves encryption (at rest **and** in transit) and MFA from "addressable" to
mandatory.

### Shipped (formerly P0 + P1-1)

Landed in the security-remediation pass and now reflected as built above — listed here only for
traceability:

- **DB + `-wal`/`-shm` owner-only permissions on create** (`_secure_file`, §2) — was P0-1.
- **`dryrun`/`generate` redact bodies by default; `--show-phi` to opt in** (§7) — was P0-2.
- **`/docs` `/redoc` `/openapi.json` off by default (`[api] expose_docs`); non-loopback bind refused (unconditionally without auth; otherwise unless `serve --allow-insecure-bind` accepts the Phase-1 no-TLS cleartext risk)** (§10, [SECURITY.md](SECURITY.md)) — was P0-3.
- **At-rest body encryption (AES-256-GCM) + required volume encryption** (§3) — was P1-1.
- **Retention/purge enforcement — `[retention]` body-null (keep metadata) + dead-letter window + WAL/VACUUM, audited; `audit_days` reserved/keep-forever by design** (§8) — was P1-2.
- **Exception-path PHI redaction — the `safe_exc()` chokepoint (`redaction.py`) at every exception→`last_error`/`detail`/log site** (§7) — the security half of P1-3 (WP-6c). Structlog/JSON + off-box forwarding remain deferred (below).
- **Outbound/egress allowlist — fail-closed `[egress]` (MLLP host:port + File dirs) enforced at config load/reload/start; webhook/SMTP host allowlists in `[alerts]`** (§4) — the data-plane half of P1-4 (WP-11c). MLLP-over-TLS remains deferred (Phase 2, off-loopback).

P0-4 (doc corrections) is this reconciliation; remaining stale claims in ARCHITECTURE/README are a
separate follow-up.

### P1 — core safeguards (remaining)
| Item | Closes | Maps to | Effort |
|---|---|---|---|
| **P1-3′** Structured (JSON) logging + off-box (syslog/SIEM) forwarding (§7) — `[conditional]`, bundles with P2-3 | Off-box log shipping / tamper-resistance | §164.312(b) · AU-9/AU-4 | M |
| **P1-4′** MLLP-over-TLS (§4) — `[conditional]`, Phase 2 (the egress-allowlist half shipped — WP-11c, above) | Cleartext PHI on the wire | §164.312(e) Transmission · SC-8 (NIST 800-52r2) | L |

### P2 — remote / Phase-2 (deferrable while strictly localhost; each flips to mandatory on remote exposure)
| Item | Closes | Maps to | Effort |
|---|---|---|---|
| **P2-1** TLS on the engine API | Tokens + PHI cleartext over the network | §164.312(e) · SC-8 | M |
| **P2-2** MFA for console/API auth | Single-factor PHI access | §164.312(d) · IA-2(1) (NPRM-mandated) | M–L |
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
WP-6c) but structured (JSON) logging + off-box forwarding are roadmap (bundled with P2-3) · the
searchable `summary` column stays outside the encryption seam by design (volume encryption covers it;
`error`/`last_error`/`detail` are now ciphered — WP-5) · a fail-closed outbound/egress allowlist is
enforced (`[egress]`, WP-11c) but **MLLP is still plaintext** (MLLP-over-TLS is Phase 2) · no
strict-parse time budget · de-identification not built. Each is tracked in
[§11](#11-hardening-roadmap).

---

## 13. HIPAA §164.312 mapping (data safeguards)

Complements the access/audit mapping in [SECURITY.md](SECURITY.md#hipaa-164312-alignment).

| Safeguard | Status | Where |
|---|---|---|
| Access control (a) | Built (RBAC + owner-only DB/WAL file ACL) | [SECURITY.md](SECURITY.md), §2 |
| Audit controls (b) | Built (PHI-access audit) + log redaction planned | §6, §7 |
| Integrity (c) | Built (GCM AEAD tag on bodies; audit hash-chain) + periodic integrity checks planned | §3, §6 |
| Authentication (d) | Built (argon2id / AD); MFA planned | [SECURITY.md](SECURITY.md), §11 |
| Transmission security (e) | LDAPS built; MLLP/API TLS planned | §4 |

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
- **2025 HIPAA Security Rule NPRM** (proposed) — moves encryption (at rest **and** in transit) and
  MFA from *addressable* to *required*, and adds network-segmentation expectations. We design to it
  even though it is not yet final.
  <https://www.federalregister.gov/documents/2025/01/06/2024-30983/>
- **NIST SP 800-66 Rev. 2** — implementing the HIPAA Security Rule (maps standards → NIST controls).
- **NIST SP 800-52 Rev. 2** — TLS configuration (TLS 1.2+; basis for MLLP-over-TLS and API TLS).
- **SQLCipher** — the documented whole-DB at-rest alternative if the plaintext `summary`/index
  residual (§3) is unacceptable. <https://www.zetetic.net/sqlcipher/>
- **Peer parity** — Mirth Connect's *Data Pruner* (retention with metadata retention + archive) and
  per-channel content/encryption storage settings inform [§8](#8-retention--purge) and [§3](#3-encryption-at-rest).
