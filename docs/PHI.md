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
| Local user reading the DB file directly | Yes | Owner-only file ACL (built) + at-rest body encryption when a key is set (built — §3); volume encryption for the rest |
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

PHI is persisted in the SQLite message store ([store/store.py](../messagefoundry/store/store.py),
`_SCHEMA`). The store *is* the queue (one generic `queue` table, `stage` = `ingress` | `routed` |
`outbound`), so both the inbound message and the per-destination outbound copy are retained durably.

| Location | Holds PHI? | Encrypted at rest today? | Notes |
|---|---|---|---|
| `messages.raw` | **Yes** — full inbound body | **Yes, when a key is set** — AES-256-GCM (`MEFOR_STORE_ENCRYPTION_KEY`); identity otherwise | Preserved verbatim by design (operators must see what arrived) |
| `queue.payload` (stage=`ingress`/`routed`) | **Yes** — the raw body, **transient** | **Yes, when a key is set** — AES-256-GCM | A second copy of the raw, held only across the route→transform window: the `ingress` row is consumed at `route_handoff`, each `routed` row at `transform_handoff` (deleted, never kept). A stalled router/transform stage can hold several briefly — surfaced by the `queue_buildup` alert |
| `queue.payload` (stage=`outbound`) | **Yes** — transformed outbound body | **Yes, when a key is set** — AES-256-GCM | One row per destination; the persistent footprint |
| `queue.handler_name` (stage=`routed`) | No — a handler name, not a body | No (metadata, deliberately not ciphered) | The handler the transform worker runs |
| `messages.summary`, `messages.metadata` | **Yes** — MRN / patient name / order; operator-attached values | **Yes, when a key is set** — AES-256-GCM (EF-3) | Ingest-derived; routed through the store cipher like `raw` (no SQL search/index exists on `summary`, so encrypting it costs nothing). NULL/blank stay as-is |
| `messages.error`, `queue.last_error`, `message_events.detail` | **Possibly** — may embed raw fragments from exceptions | **Yes, when a key is set** — AES-256-GCM (WP-5; **all three backends, incl. SQL Server as of H4** — the prior SQL Server plaintext residual is retired); also `safe_exc()`-redacted before write | Routed through the store cipher like `raw`/`payload`; NULL/blank values stay as-is. See [§3](#3-encryption-at-rest), [§7](#7-logging--phi-redaction) |
| `messages.control_id`, `message_type` | Low (MSH-10/MSH-9) | No | Needed plaintext for dedup/routing/indexes (`ix_messages_control`) |
| `audit_log.detail` | Low — exposed IDs/counts, not bodies | No | JSON metadata about PHI *access*, not the PHI itself |
| `delivered_keys` (H2 idempotency ledger) | **No** — hashes + ids only | No (deliberately not ciphered — nothing to protect) | One row per completed outbound delivery: a SHA-256 `delivery_key` over non-PHI ids + a replay-stable seq, plus `outbox_id`/`message_id`/`destination_name`/`delivery_seq`. **Never a body or any PHI** — `control_id` is only *folded into the hash input*, never stored in the clear here. Lets the FIFO claim skip-and-complete a re-claimed already-delivered head without re-sending |
| SQLite file + `-wal` / `-shm` siblings | **Yes** (mirror the above) | No | WAL/shm hold recently-written PHI outside any app-level encryption |
| File-connector output / spill dirs (`.hl7`, `.processed`, `.error`) | **Yes** — plaintext on disk | No | Written by the File transport; treat the directory as PHI |

**The body cipher `[BUILT]`.** [store/store.py](../messagefoundry/store/store.py) routes message
bodies through the store's `_cipher` ([store/crypto.py](../messagefoundry/store/crypto.py)) on
write/read — **AES-256-GCM when `MEFOR_STORE_ENCRYPTION_KEY` is set, identity otherwise** — so
encryption is transparent to callers. Existing plaintext rows are migrated in place on first start
with a key. See [§3](#3-encryption-at-rest).

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

**File permissions `[BUILT]`.** `MessageStore.open()` restricts the DB and its `-wal`/`-shm` siblings
to the owner on create — POSIX `chmod 0600`, Windows owner-only DACL via `icacls` (inheritance off) —
through `_secure_file()` ([store/store.py](../messagefoundry/store/store.py)). It is best-effort and
non-fatal: a skipped or failed restriction is **logged** (STORE-2), with directory-level ACLs
([SERVICE.md](SERVICE.md)) as the backstop. The File-connector spill dirs remain operator-owned —
harden them per [§10](#10-secure-deployment--operations-checklist).

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
| `-wal` / `-shm` / temp / journal files | Not covered (app cipher can't reach them) | **Covered** | Powered-off only |

**Per-backend whole-DB layer.** SQLite = **SQLCipher** (the documented whole-DB alternative, §3) —
a native dependency that replaces the connect path. SQL Server = **TDE** (Transparent Data
Encryption), configured **at the database by a DBA**, *not* by MessageFoundry — it is the SQL Server
native whole-DB layer and is what covers the low-sensitivity plaintext columns (`control_id`/
`message_type`), indexes, and journals. (Do not
conflate the two: SQLCipher is the SQLite layer; TDE is the SQL Server layer — there is no SQLCipher
on SQL Server.) MessageFoundry's own at-rest control is the app-level AEAD; the whole-DB and FDE
layers are **deployment prerequisites** (§3, §10).

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
   **Crypto-agility (M9, additive — CRYPTO-1).** The cipher is **version/alg-dispatching**: it decodes
   both `mfenc:v1:<key_id>:<b64>` and an additive, self-describing `mfenc:v2:<alg>:<key_id>:<b64>`
   (`alg` names the AEAD), and **fails closed** (`CipherError`) on an unknown marker version or an
   unknown/unsupported `alg` — never a silent pass-through or mis-decrypt. **AES-256-GCM is the only
   registered algorithm** and the **v1 writer is frozen byte-identical** (a frozen-fixture test pins it);
   v2 writing is **wired + tested but off by default**, so no at-rest format change ships — this is
   agility *infrastructure*, not a format migration. The store's find-all/migration scans anchor on the
   version-agnostic `mfenc:` prefix (so a v2 row is recognised as already-encrypted), and the rotation
   scan anchors on the cipher's active-format prefix through the key fingerprint (so a v2-active rotation
   matches v2 rows and terminates).
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
   exactly like `prod`/`staging` (closing the EF-3 perception gap where non-prod only warned). A
   **synthetic/non-PHI** instance (`data_class != phi`, e.g. `dev`) stays **key-free** for CI parity.
   Two explicit overrides: `[store].require_encryption = true` forces the refusal even for a synthetic
   instance; `[store].allow_unencrypted_phi = true` is the loud, **audited** opt-out that lets a PHI
   instance start keyless anyway (it still emits the UNENCRYPTED-at-rest warning, and `require_encryption`
   wins over it). The effective posture (encryption on/off, key **source**, key **fingerprint**,
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
4. **Required volume encryption.** App-level AEAD **cannot** encrypt the `-wal`/`-shm`/temp files or
   the indexed `control_id`/`message_type` columns. **BitLocker (Windows) / LUKS (Linux) on the data
   volume is a documented deployment prerequisite** to cover those at rest. App-level + volume together
   close both the "stolen file from a powered-off host" and the "live-host file copy" cases.

**Accepted residual:** `control_id` and `message_type` (MSH-10/MSH-9, low-sensitivity) stay plaintext
in the DB for dedup/routing/indexing; volume encryption is what protects them at rest. (`summary` and
`metadata` — the direct MRN/patient-name identifiers — are **no longer** in this residual: EF-3 routes
them through the store cipher like `raw`, since nothing SQL-searches `summary`.) If even that residual
is unacceptable, **SQLCipher** (whole-DB, including WAL) is the documented alternative — at the cost of
a native dependency and replacing the connect path.

**SQL Server backend:** `encrypt = true` secures the DB *connection* (TLS in transit),
**not** data at rest — at-rest there means SQL Server TDE, configured at the database, not by
MessageFoundry.

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

**Honest limitation (heap lifetime — decrypted PHI *and* the DEK):** decrypted PHI is ordinary Python
heap for the processing window and is **not zeroized after use** — CPython `str`/`bytes` are immutable
and not reliably wipeable (no `memset`-on-free guarantee; the GC may copy or retain the object, and an
in-memory secret can surface in a heap dump or be paged to a swap file). The **same applies to the
unwrapped DEK**: once the KeyProvider hands back the base64-decoded 32-byte key, it lives in an
immutable `bytes` for the cipher's lifetime — MessageFoundry **cannot** scrub it, and any "zeroize"
call would be best-effort theater on CPython. We are deliberately honest about this rather than
claiming a wipe we can't deliver. What we *do* enforce: the DEK is never logged, never put into an
exception message, and never serialized — only its SHA-256 **fingerprint** (`key_id`) is ever surfaced
(§3, §6), so the in-heap key bytes are the *only* place the secret exists in the process. This is the
standing **ASVS 11.7.1 / CWE-316 / WP-BL3-28** residual: full in-use memory encryption is a host/OS
capability (Intel TME / AMD SEV / confidential VMs), not something an application library can provide,
and it survives even when the KeyProvider seam is pointed at an external HSM/KMS/Vault — envelope
decryption protects the **root KEK**, not the unwrapped DEK the bulk AES-256-GCM path holds in process.
The compensating controls are the documented restricted-service-account + volume-encryption posture
(§10) on a single-tenant host: keep the decrypted-secret window inside an OS-isolated process whose
memory and swap an attacker cannot reach without already owning the host.

---

## 4. Data in transit

**`[MIXED]`**

| Path | Today | Plan |
|---|---|---|
| MLLP inbound/outbound | Plaintext by default; **MLLP-over-TLS (TLS 1.2+, server-cert verify + hostname, opt-in mTLS) when `tls=true`** `[BUILT — WP-13b]`. A non-loopback plaintext MLLP listener is **refused at startup** (exposed-gate, ADR 0002 §0) unless `tls=true` or `serve --allow-insecure-bind`. | — |
| File connector | Plaintext `.hl7` on disk/share | Rely on volume/share encryption; SFTP later |
| Engine API ↔ console | Loopback HTTP by default; off-loopback requires TLS — **in-process** (`[api].tls_cert_file`, WP-13a) **or upstream** at a trusted reverse proxy (`tls_terminated_upstream` + `trusted_proxies`, WP-15) `[BUILT]`. HSTS engages on `https`; forwarded headers are trusted only from `trusted_proxies`. | — |
| AD / LDAP auth | **LDAPS** with cert verification (`ad_tls_verify`) `[BUILT]` | — |
| PostgreSQL / SQL Server backend | TLS-to-DB on by default (`[store].encrypt`), server cert **validated** (`trust_server_certificate=false`) `[BUILT]`. Trust a private/internal DB CA without disabling validation: Postgres `[store].ssl_root_cert` file-pin **or** a Windows machine-store (`LocalMachine\Root`) CA import; SQL Server (ODBC 18) machine store only. | — |

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

**Key-exchange parameters `[BUILT — WP-L3-10 code half]` (ASVS 11.6.2).** Every TLS context the engine
builds — the API/WebSocket listener ([api/tls.py](../messagefoundry/api/tls.py)) and the per-connection
MLLP server/client contexts ([transports/mllp.py](../messagefoundry/transports/mllp.py)) — enforces a
**TLS 1.2+ floor**, which constrains 1.2 to **(EC)DHE** key exchange and makes 1.3 ECDHE-only: forward-
secret key establishment, never static RSA/DH. Two controls in
[config/tls_policy.py](../messagefoundry/config/tls_policy.py) pin the *parameters*:

- **Approved groups pinned where supported.** Built contexts call `harden_kex_groups`, which sets the
  approved ECDHE groups `X25519:secp384r1:secp256r1` via `SSLContext.set_groups` on Python ≥ 3.13. On
  3.11/3.12 there is no public group-pinning API and OpenSSL's defaults already lead with exactly these
  curves, so it is a deliberate no-op, not a downgrade.
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
captures to rotating files); running a **`prod`** environment at `DEBUG` is **refused at startup**
(Gate #1 — DEBUG can surface bodies/raw fields; see below).

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

**Global log redaction + prod-DEBUG guard `[BUILT]` (Gate #1).** Two handler filters run on **every**
emitted record ([logging_setup.py](../messagefoundry/logging_setup.py), installed by
`configure_logging`): a **`RedactionFilter`** that `redact()`-scrubs both the rendered **message** and
the formatted **exception traceback — chained `__cause__`/`__context__` included** — so every
`log.exception()` / `exc_info=` site (the delivery/router/transform catches, the `_on_*_worker_done`
callbacks, the file/db/remotefile pollers, and the cluster leader-sweep/heartbeat loops) is redacted
*by construction*, not per call site; then the **`ControlCharScrubFilter`** (CR/LF + control-char
scrub). `redact()` rewrites only HL7-shaped spans, so ordinary operational lines are untouched. This
makes `safe_exc()` (above) the explicit chokepoint and the global filter the backstop for anything that
reaches a handler un-redacted. Separately, **`serve` refuses to start at `DEBUG` on a production instance**
(`[ai].production = true`) — DEBUG can surface full bodies / raw fields and real PHI flows there.

**Gate #1 acceptance (v0.1)** — each criterion with its proving test:
- the global `RedactionFilter` is installed by `configure_logging` (`tests/test_logging.py`);
- a chained exception carrying an HL7 body yields no body fragment in any rendered traceback, while the
  exception **type** is kept (`tests/test_logging.py`);
- end-to-end across parse→route→transform→deliver, a synthetic ADT with a known patient name + MRN that
  hits a Handler exception **and** a delivery failure leaves **no record at WARNING+** carrying those
  values (`tests/test_wiring_engine.py`);
- `serve` refuses `DEBUG` in a `prod` environment (`tests/test_logging.py`).

**Structured logging + off-box forwarding `[BUILT, sec-offbox-log]`.** The general log can emit
**structured JSON** (one object per line, `[logging].format = "json"`) and a **copy of every record can
be forwarded off-box** to a syslog/SIEM collector (`[logging].forward_enabled` + `forward_host`/`_port`/
`_protocol`/`_format`) — so log evidence survives a host compromise rather than living only in NSSM's
local files. The forwarder is wired in [`logging_setup.configure_logging`](../messagefoundry/logging_setup.py),
and the **same two handler filters** (`RedactionFilter` then `ControlCharScrubFilter`) are installed on
**every** sink, so the forwarded stream carries the identical PHI-redaction + log-injection guarantees as
stdout; `json.dumps` additionally escapes control characters so a record can't break the one-line-per-
record framing — JSON is therefore the recommended (and default) off-box `forward_format`; the `text`
format is best-effort framing (a multi-line traceback spans lines). **Transport caveat:** the syslog
transport itself is **plaintext** — terminate it at a local TLS-forwarding agent (rsyslog/Vector/the
SIEM agent) or keep it on a trusted management network. **Availability:** the forwarder never blocks the
engine *indefinitely* — UDP is fire-and-forget; a TCP collector that is **unreachable at startup** is
skipped with a warning, and one that **stalls at runtime** is bounded by a socket timeout (the record is
dropped) so a wedged SIEM can't stall the asyncio event loop. The send is still synchronous, so for a
high-volume feed prefer UDP or a local agent. The tamper-evident **`audit_log`** is **also tee'd
off-box** (sec-offbox-log #361/#363): every committed audit row is emitted as PHI-redacted metadata
through the `messagefoundry.audit` logger to the same forwarder, across all three store backends
([`store/audit_tee.py`](../messagefoundry/store/audit_tee.py)). **Not used:** structlog (stdlib `logging` only).

### Logging inventory (16.1.1 / 16.2.3)

| Stream | Contents | Format / store | PHI controls |
|---|---|---|---|
| **General log** (stdout → NSSM rotating files; optional off-box **syslog/SIEM** copy — `[logging].forward_*`) | operational events, exception **types**, redacted messages | single-line text or structured **JSON** (`[logging].format`), UTC `Z` timestamps | never-log-bodies rule; CR/LF + control-char scrub; `safe_exc()` on logged exceptions; python-hl7 PHI loggers silenced — **same filters on the off-box forwarder**; syslog transport is plaintext (front with TLS — §7) |
| **`audit_log`** (SQLite) | who/what/when of auth + PHI *access* (IDs/counts, not bodies) | structured JSON `detail`, tamper-evident hash chain | bodies/credentials never written; read via `GET /audit` |
| **`messages.error` / `queue.last_error` / `message_events.detail`** (SQLite, Postgres, **and SQL Server as of H4**) | per-message disposition detail | text, **AES-256-GCM at rest** (WP-5; H4 brought SQL Server to parity) + **`safe_exc()`-redacted** (WP-6c) | encrypted + redacted; volume encryption backstop |

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

**SQLite-only.** On the SQL Server backend, at-rest retention is a DBA concern (TDE + a SQL
Agent purge/shrink job); the engine's retention task targets the SQLite store.

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
`CaptureSink`/corpus hooks. [`scripts/publish/scan_forbidden.py`](../scripts/publish/scan_forbidden.py)
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

- **DB + `-wal`/`-shm` owner-only permissions on create** (`_secure_file`, §2) — was P0-1.
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
- **Exception-path PHI redaction — the `safe_exc()` chokepoint (`redaction.py`) at every exception→`last_error`/`detail`/log site** (§7) — the security half of P1-3 (WP-6c). Structured-JSON logging + off-box (syslog/SIEM) forwarding + the cross-backend `audit_log` off-box tee are now **built** (sec-offbox-log #357/#361/#363; residual: native TLS-syslog).
- **Outbound/egress allowlist — fail-closed `[egress]` (MLLP host:port + File dirs) enforced at config load/reload/start; webhook/SMTP host allowlists in `[alerts]`** (§4) — the data-plane half of P1-4 (WP-11c). MLLP-over-TLS remains deferred (Phase 2, off-loopback).

P0-4 (doc corrections) is this reconciliation; remaining stale claims in ARCHITECTURE/README are a
separate follow-up.

### P1 — core safeguards (remaining)
| Item | Closes | Maps to | Effort |
|---|---|---|---|
| **P1-3′** Structured (JSON) logging + off-box (syslog/SIEM) forwarding (§7) — ✅ **Built (sec-offbox-log #357/#361/#363)**; residual: native TLS-syslog + default-off | Off-box log shipping / tamper-resistance | §164.312(b) · AU-9/AU-4 | M |
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
WP-6c); structured (JSON) logging + off-box (syslog/SIEM) forwarding + the cross-backend audit-tee are now **built** (sec-offbox-log #357/#361/#363; residual: native TLS-syslog) · the
searchable `summary` column stays outside the encryption seam by design (volume encryption covers it;
`error`/`last_error`/`detail` are now ciphered — WP-5) · a fail-closed outbound/egress allowlist is
enforced (`[egress]`, WP-11c) but **MLLP is still plaintext** (MLLP-over-TLS is Phase 2) · no
strict-parse time budget · de-identification is **built** for HL7 v2 (the anonymizer, §9, ADR 0030)
with X12/FHIR seams still to come. Each is tracked in
[§11](#11-hardening-roadmap).

---

## 13. HIPAA §164.312 mapping (data safeguards)

Complements the access/audit mapping in [SECURITY.md](SECURITY.md#hipaa-164312-alignment).

| Safeguard | Status | Where |
|---|---|---|
| Access control (a) | Built (RBAC + owner-only DB/WAL file ACL) | [SECURITY.md](SECURITY.md), §2 |
| Audit controls (b) | Built (PHI-access audit) + log redaction planned | §6, §7 |
| Integrity (c) | Built (GCM AEAD tag on bodies; audit hash-chain) + periodic integrity checks planned | §3, §6 |
| Authentication (d) | Built (argon2id / AD); native TOTP MFA built for local accounts (WP-14) | [SECURITY.md](SECURITY.md), §11 |
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
