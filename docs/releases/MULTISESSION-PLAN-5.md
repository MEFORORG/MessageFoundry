# MessageFoundry — Multisession Execution Plan 5 (2026-06-27)

> **Lineage.** This is the **fifth** MessageFoundry multisession plan, driven by a dedicated **coordinator
> lane** (the active session). Plan 1 = [`MULTISESSION-PLAN.md`](MULTISESSION-PLAN.md) (v0.1, shipped).
> Plan 2 = [`MULTISESSION-PLAN-v0.2.md`](MULTISESSION-PLAN-v0.2.md) (v0.2 board — merged; historical record).
> Plan 3 = [`MULTISESSION-PLAN-3.md`](MULTISESSION-PLAN-3.md) (connector/codec wave — landed). Plan 4 =
> [`MULTISESSION-PLAN-4.md`](MULTISESSION-PLAN-4.md) (post-throughput wave — **SHIPPED as 0.2.9**:
> #28/#29/#34/#47/#50/#53/#54/#55 all done). **Plan 5 supersedes Plan 4** as the living plan and targets the
> **next wave** (the **v0.3 candidate**): the deferred connector/codec completers (inbound HTTP listener, the
> `[xml]`/`[x12]` strict layers, SMTP-send), the **Corepoint-parity** gaps (custom RBAC roles, FHIR read
> lookup, alert-state, HL7 time helpers), and operator-facing ops (support bundle, content search, update
> check). Cut target: **0.3.0** (or a conservative **0.2.10** if the wave trims to the low-risk tier).
>
> **Header.** All lanes branch off **`origin/main` @ `4b2daa5`** (0.2.9 shipped). The **single-writer
> coordinator = the active session** (owns this plan, ADR numbering, and the shared AI project memory).
> **Autonomy = L1:** workers **build + verify the quartet** (`ruff format --check .` · `ruff check .` ·
> `mypy messagefoundry` strict · `pytest`, with `QT_QPA_PLATFORM=offscreen` for the console tests) and
> **commit locally**; the **OWNER merges/ratifies PRs** and ratifies ADRs (worker-authored ADRs stay
> `Proposed`).
>
> **Numbering state.** **Next free ADR file = `0043`** (0042 = embedded-document pruning, used). **But two
> pre-existing RESERVED ADR rows in [`docs/adr/README.md`](adr/README.md) must be consumed first, not
> re-numbered:** **`0023`** = Inbound HTTP listener (#7, README line 42, **Reserved**) and **`0029`** =
> Email/SMTP destination (#23, README line 48, **Reserved** — it "was earmarked 0024 before SMART claimed it").
> Additionally, **#30 already has an ADR**: **`0026`** (*Off-box egress posture for the MEFOR version
> update-check*, README line 45) is **Accepted (2026-06-19, owner go)** and already settles the no-network MVP,
> the `[update_check]`-style knob, the additive `/status` field, and the `update_available` AlertSink lockstep
> set — so **#30 builds an already-accepted design and needs NO new ADR**. Consuming those reservations:
> **#7 → 0023** · **#23 → 0029** · **#30 → existing 0026 (no new ADR)**. Only the genuinely-new parity/store
> items take the clean `0043+` block: **FHIR-read #58 → 0043** · **alert-state #56 → 0044** · **rbac #57 →
> 0045** · **content-search #51 → 0046**. **Next free BACKLOG item = `#56`** (highest landed heading is
> `## 55.`); the four NEW parity items below pre-reserve `#56`–`#59`; one new owner-only item pre-reserves
> `#60`. (Items **#9** and **#13** were **retired from the backlog 2026-06-27, PR #615** — out-of-repo docx
> deliverable + counsel-blocked legal item; their numbers stay vacant, no renumbering.)
>
> **Live siblings (do not edit).** **`pool-prewarm`** worktree = **STORE connection-pool pre-warming WIP**
> (the dominant `store/*.py` collision sibling, **no PR**) — any lane touching `store/` keeps its changes
> **additive** and **rebases over pool-prewarm**, never edits it. **`corepoint-recon`** = **dormant** —
> ignore. Never touch sibling worktrees.

---

## A. Wave items (all verified OPEN/PARTIAL on `origin/main` @ 4b2daa5)

The buildable set is large, so it is **tiered**. **Wave 1** = highest-value, lowest-risk, no hard cross-item
deps. **Wave 2** = follow-ons (mostly the inbound-HTTP substrate and the store-read-path items that must
queue behind the pool-prewarm sibling). **Deferred tail** = on-trigger / owner / hardware-gated (§G).

### Wave 1 (committed — the v0.3 cut)

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| **#59** *(new)* | HL7 timestamp / age / length-of-stay helpers on `Message` | none | **L1 hl7-time-helpers** | Pure `parsing/` library. **REUSE — `messagefoundry/timezone.py` already exists** (`_parse_hl7_timestamp`, `convert_hl7_timestamp`, `to_zone`); add only the NEW helpers (age-from-DOB, LOS), do NOT create a duplicate `parsing/timezone.py`. **Touches the shared `messagefoundry/__init__.py` / `parsing/__init__.py` export blocks** — serialize with L2/L4 (§D). |
| **#58** *(new)* | FHIR client read/search (+ CapabilityStatement) — `fhir_lookup`, read-only like `db_lookup` | **ADR 0043** (extends 0010; builds on 0022/0024) | **L2 fhir-read-lookup** | `transports/fhir.py` is write-only (`_INTERACTIONS = create/update/transaction/batch`). No store contention. **Exports `fhir_lookup` from `messagefoundry/__init__.py`** — serialize that export block with L1/L4 (§D). |
| **#32** | X12 strict IG validation via **pyx12** — completes ADR 0012's deferred SEF validator | none (under ADR 0012) | **L3 codecs** *(seq: #32 → #31)* | pyx12 sole runtime dep is `defusedxml` (**already in tree**) — net new weight ~zero. |
| **#31** | `[xml]` extra: `parsing/xml/` `XmlMessage` (lxml + XSD + signxml) structured layer | none (follows the x12/fhir optional-codec pattern) | **L3 codecs** *(seq after #32)* | Core `.xml()` shipped (PR #422). signxml trips the **crypto-inventory** gate. **Adds a `parsing/xml` re-export to `parsing/__init__.py`** (codec precedent) — serialize that file with L1 (§D). |
| **#23** | Email connectors — **SMTP-send outbound MVP** (IMAP/POP read deferred) | **ADR 0029** (consumes the reserved row; SMTP=Phase 1, IMAP/POP+XOAUTH2=Phase 2) | **L4 outbound-connectors** | New `transports/email.py` + `EMAIL` ConnectorType + `[egress].allowed_smtp`. Stdlib only. **Adds an `Email()`/`SMTP()` factory to `config/wiring.py` + the `messagefoundry/__init__.py` export block** — serialize both with L1/L2 (§D). |
| **#49** | Export-to-Support PHI-safe diagnostic bundle (CLI slice) | none | **L5 ops/diagnostics** *(seq: #49 → #30)* | `messagefoundry support-bundle`; **no raw bodies, no secrets**; redact log tail. Reads the real status models `EngineInfo`/`DbInfo`/`SystemStatus` (there is **no** `StatusResponse` class). |
| **#30** | Auto dependency + MeFor version-update check (console + IDE) | **existing ADR 0026** (Accepted — off-box egress posture; **no new ADR**) | **L5 ops/diagnostics** *(seq after #49)* | MEFOR-version half only; off-by-default; rides ADR 0014 alert + `/status`. ADR 0026 already settles the posture, the knob, the `/status` field, and the `update_available` AlertSink set — the worker only **builds** it. |

### Wave 2 (follow-on — gated on the substrate ADR or the pool-prewarm land-order)

| # | Item | ADR | Lane | Notes |
|---|---|---|---|---|
| **#7** | Inbound SOAP/REST listener — connector-owned HTTP source (substrate for #20/#24) | **ADR 0023** (consumes the reserved row — the long-deferred inbound-HTTP-listener design, ADR 0003 §3/§5) | **L6 transport-inbound-http** | **XL.** ADR 0023 **first**. Synchronous-response seam vs ACK-on-receipt is the hard part. |
| **#56** *(new)* | Operator alert-state — resolvable instances (ack/resolve/suspend) + real `alerts_active` | **ADR 0044** (refines ADR 0014) | **L7 alert-state** *(store-backed)* | New `alert_instance` table across x3 backends → **rebase over pool-prewarm**. `alerts_active` is stubbed `0` today on **`ConnectionRow`** (`api/models.py:250`), not on a status model. |
| **#57** *(new)* | User-definable custom RBAC roles — builder over the existing Permission catalog | **ADR 0045** (custom-role persistence + `roles`-table migration) | **L8 rbac-custom-roles** *(store migration)* | 6 fixed built-in `Role`s today; additive overlay, permission-subset only. **Coordinate the single `roles`-table migration with L7.** |
| **#51** | Message-content search — HL7 field-path / raw-content matching in Log Search | **ADR 0046** (scan-and-decrypt-per-row vs plaintext key-field index) | **L9 store/search** *(store read path)* | `raw` is **AES-GCM-encrypted at rest** → plain SQL `LIKE` impossible; decrypt-per-row, bounded, off-loop. **Hardest store-read collision with pool-prewarm.** |

### Deferred tail / non-lane (tracked, not agent-buildable) — see §G

| # | Item | Reason |
|---|---|---|
| **#45** | Per-store TLS CA-file knob — **SQL Server slice** | On-trigger (Postgres half already shipped); blocked on verifying ODBC Driver 18 `ServerCertificate` keyword support against a real install. |
| **#40** | Self-hosted CI leg: real Win Server 2025 + SQL Server 2025 box | Hardware-gated. |
| **#60** *(new)* | Turnkey DR — scheduled config/store backup + restore-verify (config-tier slice) | Owner decision (scope/retention posture). |
| **#23 Phase 2** | IMAP/POP inbound read (M365/Google XOAUTH2) | Carries the OAuth dep-vet; deferred behind the SMTP-send MVP. |

---

## B. Lane assignment (worktree per lane off `origin/main` @ 4b2daa5)

Grouping rule: **same subsystem → same lane (sequential); disjoint subsystems → parallel lanes.** Every
`store/*.py`-touching lane explicitly **rebases over `pool-prewarm`** and keeps edits additive.

### Lane 0 — COORD / ADR (pure docs; builds no product code)
**Owns ADR numbering + this plan + the shared memory (single-writer).** Gates the ADR-blocked lanes.
- **Consumes the reserved rows + uses the existing ADR:** **0023** (inbound HTTP listener, #7 — was already
  Reserved) and **0029** (email transport, #23 — was already Reserved) are *authored into existing reserved
  slots*; **#30 reuses the already-Accepted ADR 0026** (no new ADR). Authors (Proposed) only the genuinely-new
  ADRs: **0043** (FHIR read lookup), **0044** (alert-state, refines 0014), **0045** (custom-role persistence),
  **0046** (content-search encrypted-scan tradeoff). Owner ratifies → unblocks the dependent build lane.
- Pre-reserves BACKLOG **#56–#60** so the new items have stable numbers; **lands every `## N.` heading via a
  throwaway worktree off `origin/main`** (headings collide across worktrees — §F).
- Keeps this plan current (flips statuses, retires lanes), reconciles `BACKLOG.md` stale claims (§E). **Does
  NOT edit `docs/adr/README.md`** beyond flipping the two already-Reserved rows to authored once owner-ratified
  (the Registry phase owns it, single-writer).

### Lane L1 — HL7-TIME-HELPERS (#59) — *Wave 1, parallel, no ADR*
**Branch:** `hl7-time-helpers` · **Worktree:** off `origin/main`.
- Pure helpers on the `parsing/` library. **`messagefoundry/timezone.py` ALREADY EXISTS and already provides
  the tolerant HL7-TS→`datetime` parse** (`_parse_hl7_timestamp`, parsing `YYYYMMDD`..`HHMMSS.ssss±ZZZZ`),
  plus `convert_hl7_timestamp` / `to_zone` / `_offset_to_timedelta`, and is re-exported from
  `messagefoundry/__init__.py`. **REUSE/expose it — do NOT build a new TS parser and do NOT create
  `parsing/timezone.py` (it would duplicate the top-level module).** Add only the **new** helpers
  (`hl7_now()`/TS-format if not present, age-from-DOB, `LOS(admit, discharge)`), exposing the existing
  `_parse_hl7_timestamp` on the `Message` surface. MSH-encoding-aware, **no I/O**, console-importable per the
  §4 carve-out.
- **Real touched files:** `parsing/message.py`, `parsing/__init__.py`, `messagefoundry/__init__.py`, and
  `messagefoundry/timezone.py`. **NOT a zero-shared-files lane** — it edits the public-surface aggregators
  `messagefoundry/__init__.py` (shared with L2 + L4) and `parsing/__init__.py` (shared with L3). **Serialize
  those export-block edits per §D** (last-writer rebases). It is otherwise store-free → safe to run parallel to
  the store work / pool-prewarm.

### Lane L2 — FHIR-READ-LOOKUP (#58) — *Wave 1, parallel, ADR 0043*
**Branch:** `fhir-read-lookup` · **Worktree:** off `origin/main`.
- Read-only `fhir_lookup(connection, 'Patient?identifier=…')` / read-by-id GET against an allow-listed FHIR
  endpoint; reuses the SMART Backend bearer (ADR 0024) + `[egress].allowed_http`; runs **off the event loop**;
  unavailable on a Router / in dry-run (raises) — modeled exactly on the `db_lookup` carve-out (ADR 0010) so
  it does **not** break purity/at-least-once. CapabilityStatement = a connection-test probe.
- Touches `transports/fhir.py`, `config/db_lookup.py` (reuse the off-loop gating machinery),
  `parsing/fhir/resource.py`, **`config/wiring.py`** (shared DSL surface — `fhir()` factory at line 893,
  `db_lookup` connection at line 376; serialize with L4 per §D), **`messagefoundry/__init__.py`** (exports
  `fhir_lookup` mirroring `db_lookup` — serialize the export block with L1/L4 per §D), `pipeline/dryrun.py`.
  **No store contention** → orthogonal to all store-pool/retention work, an excellent parallel pick.
- **Needs ADR 0043 ratified** (extends ADR 0010 to FHIR).

### Lane L3 — CODECS (#32 → #31; sequential within lane) — *Wave 1, mostly parallel*
**Branch:** `codecs-x12-xml` · **Worktree:** off `origin/main`.
- **#32 first** (`codec-x12-strict`): add a `parsing/x12/` validate module wrapping **pyx12** as the opt-in
  strict slow path behind the tolerant `X12Peek`/`X12Message` (two-tier preserved); ship as
  `messagefoundry[x12]`. Yields free 997/999 ack generation. **No crypto-inventory trip** (pyx12/defusedxml
  import none of hashlib/hmac/secrets/ssl/cryptography).
- **#31 after** (`codec-xml`): new `parsing/xml/` package shipping `XmlMessage` (XPath read/set + ns-aware
  re-encode) over **hardened lxml** (`resolve_entities=False, no_network=True, huge_tree=False,
  load_dtd=False` — `defusedxml` does **not** cover lxml and `defusedxml.lxml` is deprecated, so harden the
  parser directly); optional `xmlschema` (disable remote `schemaLocation` fetch) + `signxml` companions;
  ship as `messagefoundry[xml]`. **Adds a `from messagefoundry.parsing.xml import XmlMessage` re-export +
  `__all__` entries to `parsing/__init__.py`** (the established x12/fhir/dicom codec pattern) — **serialize
  that file with L1 per §D.**
- **#32 and #31 each re-lock `pyproject.toml`/`requirements.lock`** → **serialize the two re-locks** (sequential
  within the lane handles this). **signxml imports cryptography/hashlib → register its module in
  `scripts/security/crypto_inventory_check.py` INVENTORY** or it reds the crypto-inventory leg + the
  `test_security_static` pytest (§F gotcha 1). **SPDX header on every new `.py`** in `parsing/xml/` and the
  new x12 validate module.

### Lane L4 — OUTBOUND-CONNECTORS (#23 SMTP-send MVP) — *Wave 1, parallel, ADR 0029*
**Branch:** `outbound-email` · **Worktree:** off `origin/main`.
- New `transports/email.py` SMTP `DestinationConnector` (stdlib `smtplib` + `email.message.EmailMessage`):
  `register_destination` + new `ConnectorType.EMAIL`; a code-first `Email()`/`SMTP()` factory **on the
  `config/wiring.py` surface** (following the `fhir()`/`MLLP()` precedent — **serialize the factory addition
  with L2 per §D**, or pin it to a separate module if serialization is awkward); STARTTLS-by-default + the
  existing `insecure_tls_allowed()` escape; `test_connection` = connect/EHLO/NOOP; `DeliveryError` on failure
  (staged-queue retries; transform stays pure — SMTP is the side effect; at-least-once accepted like other
  one-way destinations). **Also exports the `Email()`/`SMTP()` factory from `messagefoundry/__init__.py`** —
  serialize that export block with L1/L2 per §D.
- **Do NOT import `pipeline` from `transports`** — lift/duplicate the minimal SMTP logic from
  `pipeline/alert_sinks.py:send_plain_email`, don't import it.
- Adds a new **`[egress].allowed_smtp`** allowlist arm in `config/settings.py` (parity with
  `allowed_http`/`allowed_mllp`, deny-by-default) — **keep this lane off any other lane editing
  `EgressSettings`** to avoid an allowlist-arm merge.
- **Consumes the reserved ADR 0029** (email/SMTP, #23). **IMAP/POP read (Phase 2, XOAUTH2) is deferred** — its
  OAuth dep-vet is out of this wave. Note: `transports/smart.py` is a SMART Backend signed-JWT provider, a
  *structural* template (expiry-cached, off-loop, env()-held secret) but **not** a drop-in for the
  delegated-mailbox XOAUTH2 flow Phase 2 needs.

### Lane L5 — OPS/DIAGNOSTICS (#49 → #30; sequential) — *Wave 1, parallel; #30 uses existing ADR 0026*
**Branch:** `ops-diagnostics` · **Worktree:** off `origin/main`.
- **#49 first:** `messagefoundry support-bundle` CLI in `__main__.py` (+ new `messagefoundry/support/`) zips
  `__version__`, a **secret-free config summary** (Registry counts only — no settings values), a `/status`
  snapshot (the real status models — **`EngineInfo`** carries `version`/`uptime_seconds`, **`DbInfo`** carries
  db `size_bytes`/`disk_free_bytes`/row counts, **`SystemStatus`** is the envelope; there is **no**
  `StatusResponse` class), and a **redacted** app-log tail. **Hard rule: no raw bodies, no secrets** (skip
  `MEFOR_*`/`.env`/`*.db`); run log lines through the existing redaction (a lightweight regex pass — don't pull
  the full HL7-shaped `anon/` engine). Defer the admin-gated `POST /support/bundle` to a fast-follow.
- **#30 after:** engine-side version-check comparing running `__version__` against a configurable index
  (PyPI/internal mirror) **or, per the Accepted ADR 0026 MVP, the bundled `requirements.lock`/installed
  distribution metadata with zero egress**; **opt-in / off-by-default** `[update_check]` knob (air-gap posture,
  CLAUDE.md §9; ADR 0026 §1–§2); route the result through `pipeline/alerts.py` as an `update_available`
  ADR-0014 rule consumed off `/status`; non-blocking dismissible banner in `console/shell.py` +
  `ide/src/engineClient.ts`/`extension.ts`. **Any outbound call (future live path) lives engine-side only** —
  console/IDE never call PyPI. **#30 needs NO new ADR — ADR 0026 is already Accepted** and defines the posture,
  the knob, the `/status` field, and the `update_available` AlertSink lockstep set; the worker only builds it.
- **Sequential ordering resolves the `/status` + `pipeline/alerts.py` overlap** (#49 reads `/status`; #30 adds
  a new field to a concrete status model — **`EngineInfo` or `SystemStatus`** (the `update_available`/version
  fields), not a `StatusResponse` — plus an alerts rule).

### Lane L6 — TRANSPORT-INBOUND-HTTP (#7) — *Wave 2, ADR 0023; the substrate*
**Branch:** `transport-inbound-http` · **Worktree:** off `origin/main`.
- **ADR 0023 design FIRST** (the inbound-HTTP-listener follow-up ADR 0003 §3/§5 deferred — **authored into the
  already-Reserved 0023 slot**). Then a **connector-owned bound HTTP socket in `transports/`** (NOT `api/` —
  that breaks one-way dep direction): its own host/port/TLS/auth posture inheriting ADR 0002 off-loopback TLS +
  the ingress allowlist; hands the request body to payload-agnostic ingress (ADR 0004) as a `RawMessage`;
  reconciles the **synchronous-response seam** (respond-with-receipt, or block on a captured downstream reply
  via the **ADR 0013-query-response-orchestration** machinery — the *query-response* file, not the increment-2
  reingress one) with staged-pipeline + ACK-on-receipt + count-and-log.
- REST source (simple body POST) is the **cheaper first slice**; the SOAP-envelope response is the harder seam.
- **Unblocks** the inbound FHIR server facade (#20 deferred half) and inbound DICOMweb STOW-RS (#24) — both
  explicitly gated on this listener.
- Touches `transports/{base,rest,soap,framing}.py`, `config/models.py` (`ConnectorType` source keys),
  `pipeline/wiring_runner.py` (listener supervision / ACK path), `docs/CONNECTIONS.md`. **Keep off any lane
  editing `transports/base.py` registry simultaneously** (L3/L4 add connector types — **serialize enum +
  registry additions**, DICOM/SMART precedent).

### Lane L7 — ALERT-STATE (#56) — *Wave 2, ADR 0044, store-backed → rebase over pool-prewarm*
**Branch:** `alert-state` · **Worktree:** off `origin/main`.
- New `alert_instance` store table (open/acknowledged/resolved, first/last-seen, count), de-duped on the
  existing `_emit` throttle key; `GET /alerts/active` + ack/resolve endpoints (RBAC `MONITORING_DIAGNOSE`);
  wire the **stubbed `alerts_active` field on `ConnectionRow` (`api/models.py:250`)** to the real open count; a
  console Alerts-page tab (rides #22). **Metadata only — no new at-rest PHI tier.**
- Touches `pipeline/alert_sinks.py`, `store/{store,base,postgres,sqlserver}.py` (new table in `_SCHEMA`/
  `_migrate` x3), `api/{app,models}.py`, `console/alerts_page.py`. **Store-backend edits MUST rebase over
  pool-prewarm and be additive**, and **coordinate the single store migration with L8** (do not have two lanes
  add a store migration in the same release uncoordinated). **L7 edits `ConnectionRow` in `api/models.py`; L5
  adds a field to `EngineInfo`/`SystemStatus` in the same file — different classes, but sequence the two
  same-file edits (§D).**

### Lane L8 — RBAC-CUSTOM-ROLES (#57) — *Wave 2, ADR 0045, one store migration*
**Branch:** `rbac-custom-roles` · **Worktree:** off `origin/main`.
- Admin-defined named custom role = a chosen subset of existing `Permission`s, persisted in the existing
  `roles` table (the seeding path already writes there), gated by `USERS_MANAGE`, exposed via roles CRUD on
  the API + a console/IDE editor. Deny-by-default + the 6 fixed built-ins stay; custom roles are an overlay.
  **Permission-subset only — no new permission *kinds*.** Closes the named Corepoint security gap.
- Touches `auth/{permissions,service,identity}.py`, `api/{auth_routes,app}.py`, `store/store.py`
  (`roles`-table seed/migration). **Low pool-prewarm overlap except the shared store-migration file** —
  **coordinate the single `roles`-table migration with L7** so two lanes don't both add a store migration
  uncoordinated.

### Lane L9 — STORE/SEARCH (#51) — *Wave 2, ADR 0046; hardest store-read collision*
**Branch:** `store-search` · **Worktree:** off `origin/main`.
- **ADR 0046 first** — settle **scan-and-decrypt-per-row** (bounded, slow, works while the cipher is on) vs a
  **plaintext key-field index** (fast, but stores PID-3/etc. outside the cipher → its own PHI-at-rest
  exposure). `messages.raw`/summary/metadata are **AES-GCM-encrypted at rest** (`store/crypto.py`), so a SQL
  `LIKE` is impossible whenever the cipher is on. Minimal first slice: a bounded raw-substring scan with a
  hard row/result cap, decrypting per row **off the event loop**, behind the existing `messages:view_*`
  gate + step-up + an audit row; defer the structured HL7-path index to a second slice.
- Touches `store/{store,base,postgres,sqlserver}.py` (`list_messages`/`_message_filter`/`count_messages` x3),
  `api/{app,security}.py`, `console/{search,widgets}.py`. **DIRECT collision with the pool-prewarm
  store-read-path sibling + the decrypt-per-row read-pool load** → **MUST serialize behind / coordinate with
  the pool-prewarm STORE lane**; coordinate with the read-only WAL pool work.

---

## C. Land-order / wave sequence

```
(0) Lane 0 ADRs (consume reserved 0023/0029; reuse Accepted 0026; author NEW 0043/0044/0045/0046;
                 pre-reserve BACKLOG #56–#60) ────────────────────────────────────────────────┐ unblock dependents
                                                                                               │
WAVE 1 (parallel; non-store, low-risk):                                                        │
  L1 hl7-time-helpers (no ADR; REUSE timezone.py; SERIALIZE __init__.py exports w/ L2/L4) ───── parallel
  L2 fhir-read-lookup  (after ADR 0043; serialize wiring.py w/ L4 + __init__.py w/ L1/L4) ─────
  L3 codecs            (#32 → #31; serialize the two re-locks; signxml→crypto-inventory;
                        serialize parsing/__init__.py re-export w/ L1) ─────────────────────────
  L4 outbound-email    (after ADR 0029; serialize wiring.py factory w/ L2 + __init__.py + keep
                        off EgressSettings) ───────────────────────────────────────────────────
  L5 ops/diagnostics   (#49 → #30; #30 BUILDS the already-Accepted ADR 0026, no new ADR) ───────
                                                                                               │
  ── cut 0.3.0 (or a conservative 0.2.10) on Wave 1 ──                                          │
                                                                                               │
WAVE 2 (gated / store-serialized):                                                             │
  L6 inbound-http      (ADR 0023 — reserved slot — design FIRST; serialize transports/base.py w/ L3/L4)
  L7 alert-state       (ADR 0044; store table → rebase over pool-prewarm; migration coord w/ L8;
                        ConnectionRow vs L5's EngineInfo in api/models.py — sequence same-file)
  L8 rbac-custom-roles (ADR 0045; one roles-table migration; coord w/ L7)
  L9 store/search      (ADR 0046; SERIALIZE behind pool-prewarm store-read path)
```

1. **Lane 0 settles ADR numbering first:** consume the reserved **0023** (#7) and **0029** (#23) slots, reuse
   the already-Accepted **0026** (#30, no new ADR), and author the four genuinely-new ADRs **0043/0044/0045/0046**;
   pre-reserve #56–#60. Each dependent lane waits only for its own ADR to be ratified by the owner (worker ADRs
   stay `Proposed`).
2. **Wave 1 staffs immediately, parallel:** L1 (ungated — REUSE `timezone.py`), L2 (after 0043), L3 (codecs;
   internal sequence), L4 (after 0029), L5 (#30 builds Accepted 0026). **No two Wave-1 lanes touch the store
   backends** → no pool-prewarm collision in Wave 1. **The Wave-1 public-surface aggregators
   (`messagefoundry/__init__.py`, `parsing/__init__.py`, `config/wiring.py`) ARE shared across L1/L2/L3/L4 —
   serialize those edits per §D.**
3. **Cut the release on Wave 1** if Wave 2 isn't ready — Wave 1 alone is a coherent, shippable v0.3.
4. **Wave 2 is store-serialized + ADR-gated:** L6 designs ADR 0023 before any socket code and serializes
   `transports/base.py` with L3/L4; **L7/L8/L9 each rebase over pool-prewarm**, with L7↔L8 sharing one
   store migration and **L9 serialized behind the pool-prewarm read-path work** (the #1 store collision).

---

## D. Contention matrix

| File(s) | Items / lanes | Resolution |
|---|---|---|
| `store/{store,base,postgres,sqlserver}.py` (x3 backends) | **L7 (#56 table)** · **L8 (#57 migration)** · **L9 (#51 read path)** vs **`pool-prewarm` sibling** | **DOMINANT collision.** pool-prewarm = store-pool WIP, **no PR** → **#1 coordination risk**. Every store lane keeps edits **additive + rebases over pool-prewarm**, never edits it. **L9 serializes behind the pool-prewarm read path**; **L7 + L8 coordinate a single store migration** for the release. Parity test mandatory across all three backends. |
| **`messagefoundry/__init__.py`** (public-surface aggregator — re-exports the `config/wiring.py` DSL factories at lines 29–59 + `db_lookup` at line 24 + `timezone` helpers at line 63) | **L1 (#59 exposes the TS/age/LOS helpers + `timezone` surface)** · **L2 (#58 exports `fhir_lookup`)** · **L4 (#23 exports `Email()`/`SMTP()`)** | **UNFLAGGED parallel collision — three Wave-1 lanes each edit the import block + `__all__`.** **Serialize the `__all__`/import-block edits (last-writer rebases)**, or a single coordinator commit pre-adds the export stubs. **L1 is therefore NOT a "zero shared files" lane.** |
| **`parsing/__init__.py`** (re-exports every codec subpackage — x12 lines 33–39, fhir line 32, dicom line 31, each with `__all__` entries) | **L1 (#59 helper exports)** · **L3 (#31 adds a `parsing/xml` re-export + `__all__` entries, codec precedent)** · possibly **L2 (#58 if it re-exports a fhir read symbol)** | **UNFLAGGED parallel collision — L1 and L3 both touch this file in Wave 1.** Serialize the re-export edits (last-writer rebases). |
| **`config/wiring.py`** (shared code-first DSL surface — `fhir()` factory at line 893, `db_lookup` connection at line 376, `inbound`/`outbound`/`Send`) | **L2 (#58 reuse/extend)** · **L4 (#23 adds the `Email()`/`SMTP()` factory, following the `fhir()`/`MLLP()` precedent)** | **UNFLAGGED parallel collision — both are Wave-1 lanes.** **Serialize the factory additions**, or pin L4's `Email()`/`SMTP()` factory to a separate module to decouple. |
| `pyproject.toml` + `requirements.lock` | **L3 #32 (pyx12)** · **L3 #31 (lxml/xmlschema/signxml)** | DEP-1 drift gate — **serialize the two re-locks** (lane-internal #32 → #31 ordering handles it). Re-lock from **repo root** with the lock header's relative `uv export` cmd. |
| `scripts/security/crypto_inventory_check.py` INVENTORY | **L3 #31 (signxml → cryptography/hashlib)** | **Register the new crypto-importing `parsing/xml/` module** or it reds the **crypto-inventory required leg + `test_security_static` pytest** (§F gotcha 1). |
| `transports/base.py` (source/dest registry) + `config/models.py` `ConnectorType` enum | **L4 (#23 EMAIL)** · **L6 (#7 REST/SOAP source keys)** | **Serialize enum + registry additions** (DICOM/SMART precedent). Keep L4 and L6 off the registry file simultaneously. |
| `config/settings.py` `EgressSettings` allowlist | **L4 (#23 `allowed_smtp`)** | Sole toucher in this wave — keep any future egress-arm lane off it. Mirror `allowed_http`/`allowed_mllp` + deny-by-default. |
| `transports/rest.py` + `transports/soap.py` | **L6 (#7 adds source class)** vs **L3 (codec wiring, if any)** | L6 sole toucher of the *source* side; L3 touches `parsing/`, not these — low real overlap, but flag if L3 wires a codec into the transports. |
| `api/models.py` — **`ConnectionRow.alerts_active` (line 250, class starts line 232)** vs **`EngineInfo` (version 298, uptime 299) / `SystemStatus` (line 328)** + `pipeline/alerts.py` | **L7 (#56)** · **L5 (#30)** | **There is NO `StatusResponse` class.** L7 wires `ConnectionRow.alerts_active` (a per-connection stub, "stubbed 0 until the alerts feature exists"); L5/#30 adds a new `update_available`/version field to **`EngineInfo` or `SystemStatus`** + an `update_available` ADR-0014 alerts rule. **Same file, DIFFERENT classes — sequence the two edits; the claimed shared-status-model collision is illusory.** |
| `config/db_lookup.py` (off-loop lookup gating) | **L2 (#58 `fhir_lookup`)** | L2 sole toucher (reuse, don't re-derive, the off-loop gating). No other lane edits it. |
| `pipeline/wiring_runner.py` listener supervision / ACK path | **L6 (#7 sync-response seam)** | L6 sole toucher; touches the ingress/ACK path — re-check ACK-on-receipt + count-and-log invariants. |
| `console/` pages | **L7 (`alerts_page.py`)** · **L9 (`search.py`,`widgets.py`)** · **L5 (`shell.py`)** | Disjoint page files — no real collision; all ride the #22 console workstream coordination. |
| `docs/adr/` — NEW files **0043/0044/0045/0046**; reserved-slot authoring **0023/0029**; existing **0026** (no new file) + this plan | **Lane 0** | Coordinator-owned. **`docs/adr/README.md` row flips are Registry-phase, single-writer.** |

> **Sibling worktrees:** **`pool-prewarm`** (STORE connection-pool pre-warming WIP, **no PR** — #1
> coordination risk for L7/L8/L9; keep store edits additive + rebase over it, never edit it) ·
> **`corepoint-recon`** (dormant — ignore). **Never edit a sibling worktree.**

---

## E. Coordination rules

- **Single-writer coordinator** (active session) owns this plan, ADR numbering/authoring, and the shared AI
  project memory — records every ADR-status change + gating decision **before** a worker lane acts on it.
- **L1 autonomy:** workers build + verify the quartet + commit **locally**; the **owner** merges PRs and
  ratifies ADRs. **Worker-authored ADRs stay `Proposed`** until the owner flips them.
- **Verify quartet (every build lane):** `ruff format --check .` · `ruff check .` · `mypy messagefoundry`
  (strict) · `pytest` (`QT_QPA_PLATFORM=offscreen` for console tests). Re-check the **count-and-log /
  never-drop / one-way-dependency (no `api`/`console` import from the engine; no `pipeline` import from
  `transports`) / purity + at-least-once / ACK-on-receipt** invariants on any ingress/transport/store/lookup
  edit.
- **Worktree-per-lane** off `origin/main` @ `4b2daa5`; no two lanes share a working tree. Coordinate the named
  **file collisions** in §D before editing — store backends (L7/L8/L9 vs pool-prewarm), **the three shared
  public-surface aggregators (`messagefoundry/__init__.py` L1/L2/L4, `parsing/__init__.py` L1/L3,
  `config/wiring.py` L2/L4)**, the two re-locks (L3), the registry/enum (L4 vs L6), `api/models.py`
  `ConnectionRow` vs `EngineInfo` (L5 vs L7).
- **ADR numbering** is coordinator-owned: **0023** (#7) and **0029** (#23) consume their pre-existing reserved
  rows; **0026** (#30) is reused (already Accepted, no new ADR); **0043–0046** are the genuinely-new ADRs
  authored here; **`docs/adr/README.md` is edited by the Registry phase only** (do not touch from a worker
  lane).
- **BACKLOG `## N.` numbering:** pre-reserve **#56–#60** and land every heading via a **throwaway worktree off
  `origin/main`** — headings collide across parallel worktrees (§F gotcha 4).

---

## F. Build gotchas (checklist — apply on every lane)

1. **Crypto-inventory gate.** A **NEW `.py` importing `hashlib`/`hmac`/`secrets`/`ssl`/`cryptography`/`argon2`
   MUST be registered in `scripts/security/crypto_inventory_check.py` INVENTORY** or it reds the
   **crypto-inventory required CI leg AND the `test_security_static` pytest**. **Hits L3 (#31 signxml)** and
   any TLS/socket code (watch L6's HTTP-listener TLS + L4's STARTTLS path if it imports `ssl` in a new module).
2. **SPDX header on every NEW `.py`** (the #350 sweep only covered existing files). Hits L1 (any new helper
   module), L2, L3 (`parsing/xml/*`, x12 validate), L4 (`transports/email.py`), L5 (`messagefoundry/support/*`),
   L6, L7.
3. **Dep-adds.** Add to `pyproject.toml`, then **re-lock via `uv lock` / `uv export` from the repo root**
   (DEP-1 drift gate) using the lock header's **relative** export cmd. **`xml.etree` annotations need
   `# nosec B405`.** Hits L3 (pyx12, lxml, xmlschema, signxml) — **serialize the two re-locks**.
4. **BACKLOG `## N.` headings collide across worktrees** — **land #56–#60 via a throwaway worktree off
   `origin/main`** (check `origin/main`'s highest heading first; today it is `## 55.`).
5. **Required CI checks** = `test` ×3 (**py3.14** on `ubuntu` / `windows-2022` / `windows-2025`) + **bandit**
   + **pip-audit** + **cla** + **crypto-inventory**. `windows-service-smoke` is **push/dispatch-only** (not a
   required PR leg) — validate service/NSSM-touching changes via the dispatch leg, not a PR check.

---

## G. ADRs (Lane 0; coordinator-owned)

| ADR | Title (working) | For item | State / target |
|---|---|---|---|
| **0023** | Inbound HTTP listener (connector-owned bound socket; sync-response seam) — completes ADR 0003 §3/§5 | #7 (substrate for #20/#24) | **Pre-existing Reserved row (README line 42)** → author into the slot; Proposed → owner-ratified before L6 builds |
| **0029** | Email transport — SMTP-send (Phase 1) + deferred IMAP/POP XOAUTH2 (Phase 2); new `[egress].allowed_smtp` arm | #23 | **Pre-existing Reserved row (README line 48)** → author into the slot (was earmarked 0024 before SMART claimed it); Proposed → ratified before L4 builds |
| **0026** | Off-box egress posture for the MEFOR version update-check — no-network "pinned-vs-current lock diff" MVP + constrained future live path | #30 | **ALREADY EXISTS, Accepted (2026-06-19, owner go)** — **no new ADR**; L5 builds the accepted design |
| **0043** | FHIR read/search live lookup — extends ADR 0010 read-only carve-out to FHIR (builds on 0022/0024) | #58 | **NEW** — Proposed → ratified before L2 builds |
| **0044** | Operator alert-state — resolvable alert instances; refines ADR 0014 alerting scope | #56 | **NEW** — Proposed → ratified before L7 builds |
| **0045** | Custom RBAC roles — persistence + `roles`-table migration over the existing Permission catalog | #57 | **NEW** — Proposed → ratified before L8 builds |
| **0046** | Message-content search — encrypted-at-rest tradeoff (scan-and-decrypt-per-row vs plaintext key-field index) | #51 | **NEW** — Proposed → ratified before L9 builds |

> ADR 0023 reuses the **`0013-query-response-orchestration.md`** seam (not `0013-increment-2-reingress-design.md`
> — the citation is ambiguous in the tree, two `0013-*` files exist). ADRs **0015** (WS-SOAP outbound) and
> **0016** (sync X12 req/resp) already exist as committed files (the backlog still frames them as "in flight").

---

## H. Owner / hardware-gated / done callout (tracked, NOT agent-buildable this wave)

- **#16 / #46 — Corepoint event-log parity — ✅ SHIPPED (PR #541), NOT a build item.** **#46 is shipped and in
  the current 0.2.x tree** (commits under PR #541: `connection_event` + Response-Sent ACK **store layer**;
  `[diagnostics]` event-log switches + **per-connection overrides + retention**; the **`/events` read API** +
  the console **Event Log page** wired into the nav). The event taxonomy already covers BOTH the happy-path
  lifecycle (`established`/`closed`/`connecting`/`retrying`) **and** the **pre-message failure tier**
  (`peer_not_allowlisted`/`at_capacity`/`peer_reset`/`framing_error`) emitted with no `message_id`, **plus** the
  **ADR-0021 "Response Sent"** ACK/NAK capture. That delivers #16's buildable scope; **#16's only residual is
  ADR-0020 raw protocol-trace, which is Dropped-by-design.** So #16/#46 are excluded from the Plan-5 build set
  **because they are DONE/dropped, not deferred.** (This supersedes the scoping critic's stale-prose claim that
  #46 was "scoped, not shipped"; the auto-memory ledger was correct.)
- **#9 / #13 — RETIRED from the backlog 2026-06-27 (PR #615).** **#9** (regenerate the ASVS-L3 `.docx`
  reviewer deliverables) is an out-of-repo, on-demand pandoc/python-docx run against the OneDrive set — not a
  versioned backlog item. **#13** (licensing counsel review) is a legal/business decision, not engineering;
  `v0.1.0` already shipped the AGPL posture as a dated accepted-risk. Both numbered sections removed (numbers
  stay vacant, no renumbering).
- **#28 / #29 — load + throughput perf runs — ✅ DONE on the local boxes (PR #615), enterprise re-run gated.**
  Executed against 0.2.9 on the consumer-hardware floor (figures in `TUNING-BASELINE.md`); the enterprise
  re-measure is slated for **#40** (the self-hosted Win Server 2025 + SQL Server 2025 box, now the standing
  home for the recurring perf runs). Zero product code — not a build lane.
- **#8 — owner decision** — pending owner ruling; tracked, not staffed.
- **#45 — per-store TLS CA-file knob (SQL Server slice)** — **on-trigger + verification-gated.** Postgres half
  already shipped (`StoreSettings.ssl_root_cert` + `postgres._build_ssl`). The 0.2.9 code comment **asserts
  ODBC Driver 18 has NO connection-string CA-file keyword** and rejects `ssl_root_cert` for `sqlserver`
  (`_ssl_root_cert_postgres_only`) — **this contradicts the backlog's "emit `ServerCertificate=<pem>`"
  proposal**; resolve by **verifying real Driver-18 keyword support against an install** before scoping. Same
  files as the pool-prewarm/SQL-Server store-pool sibling → would have to serialize on `store/sqlserver.py` +
  `config/settings.py`. **Build only when a private-CA SQL Server estate is blocked.**
- **#40 — self-hosted CI leg (real Win Server 2025 + SQL Server 2025 box)** — **hardware-gated.**
- **#60 *(new, pre-reserved)* — Turnkey disaster recovery (config-tier slice): engine-managed scheduled
  config/store backup + restore-verify** — **owner-only decision** (backup cadence / retention / restore-verify
  posture). Tracked for a future wave, not staffed here.

---

## I. BACKLOG stale-claim reconciliation (Lane 0 fixes these)

- **#23** — heading still frames full "SMTP send + IMAP/POP (OAuth)" scope; Plan-3 trimmed the MVP to
  **SMTP-send-only, IMAP/POP read deferred** — record the trim. "No email transport (SMTP is wired for alerts
  only)" is **still accurate** vs 0.2.9. Cited reuse target `transports/smart.py` is a SMART-Backend signed-JWT
  provider, **not** the M365/Google XOAUTH2 delegated-mailbox flow Phase 2 needs (structural template only).
  **ADR number is the pre-reserved 0029** (README line 48), not a new number.
- **#30** — accurate; the opt-in off-box egress decision is **already recorded as Accepted ADR 0026** (README
  line 45) — the item builds that accepted design and needs **no new ADR**.
- **#31** — banner correct (core `.xml()` shipped PR #422; `[xml]` layer deferred); add `parsing/fhir/` as a
  **second optional-codec precedent** alongside `parsing/x12/`.
- **#32** — accurate; strengthen with the confirmed fact that **`defusedxml` (pyx12's sole runtime dep) is
  already in the tree** → "net new weight ~zero" confirmed; pyx12 is the only genuinely new package.
- **#45** — **materially stale** on two points: (1) describes `ssl_root_cert` as wholly unbuilt, but the
  **Postgres half already shipped**; only the SQL Server slice remains. (2) asserts ODBC Driver 18 exposes a
  `ServerCertificate=<pem>` keyword, but the 0.2.9 code comment now claims the **opposite** — resolve before
  scoping (§H).
- **#49** — accurate; `/status` row counts are indeed already exposed — but via **`EngineInfo`/`DbInfo`/
  `SystemStatus`** (`api/models.py:297/307/328`); **there is no `StatusResponse` class** — record the correct
  model names.
- **#51** — accurate but **understates the encryption blocker**: `raw` is **AES-GCM-encrypted at rest**, which
  is exactly why a plain SQL substring scan won't work — record the decrypt-per-row tradeoff (ADR 0046).
- **#56/#57/#58/#59 (new from #52's parity gaps)** — FEATURE-MAP presents Alerts page (§9), RBAC fixed roles
  (§7), FHIR destination (§1), and parsing (§2/§3) as **fully shipped with no gap markers**; the four gaps
  (stateless alerts / no custom-role builder / write-only FHIR client / no HL7 time helpers) are visible only
  inside #52. File them as **#56–#59**. **Note for #59:** the HL7-TS→`datetime` parse is **already built**
  (`messagefoundry/timezone.py:_parse_hl7_timestamp`); #59's real work is age-from-DOB / LOS + surfacing the
  existing parser, not a new parser.
- **#16 / #46** — **complementary, both ✅ SHIPPED via PR #541** (in the current 0.2.x tree): the
  `connection_event` store layer + `[diagnostics]` switches/overrides/retention + `/events` API + console Event
  Log page, the pre-message **failure-event tier** (`peer_not_allowlisted`/`at_capacity`/`peer_reset`/
  `framing_error`), and the **ADR-0021 "Response Sent"** capture. #16's only residual is **ADR-0020 raw
  protocol-trace (Dropped-by-design)**. Update any record (incl. the BACKLOG #46 banner that still reads
  "SCOPED FOR BUILD") to **DONE**.
- **#7** — framing accurate (still deferred/unbuilt; `rest.py`/`soap.py` are **destination-only** — confirmed,
  both end in `register_destination(...)`, no `register_source`). The "0023" reservation (README line 42) is now
  consumed by the authored ADR (Lane 0); ADRs 0015/0016 already exist as files.
- **#33 follow-ups A–E** — never filed as numbered items (they live only inside #33's note → invisible to the
  board); finding A (split-anchor) remains un-actioned. **#42/#43/#44/#48 are SHIPPED in 0.2.9** — close them
  (#43/#44 carry BUILT updates; the code matches).

---

> **This is a planning artifact, not a gate.** Update it as items land, ADRs ratify, and the pool-prewarm
> sibling lands. **No build starts until the owner says "go"** (CLAUDE.md §5: plan first, build on explicit go).
