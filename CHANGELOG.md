# Changelog

All notable changes to MessageFoundry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.14] — 2026-07-01 — Early Access

**Delta security-audit remediation.** A focused security audit of the surface added since the
2026-06-10 full review (v0.2.0 → v0.2.13) surfaced seven verified findings; this release fixes all of
them. No new critical, no SQL injection, no auth bypass, no RCE — the most serious was an
unauthenticated memory-exhaustion DoS in the new default HL7 parser. Each fix ships with a regression
test. See [`docs/reviews/DELTA-REVIEW-2026-07-01.md`](docs/reviews/DELTA-REVIEW-2026-07-01.md).

### Security
- **Bounded the built-in HL7 rich-text repetition escape** (DELTA-01/02;
  [`_builtin_hl7.py`](messagefoundry/parsing/_builtin_hl7.py)). The tolerant built-in parser (now the
  default hot-path backend, ADR 0054) expanded `\.inN\`-style repetition escapes with no cap, so a
  ~15-byte inbound field (`\.in2000000000\`) allocated gigabytes synchronously on the event loop
  **before the ACK** — an unauthenticated OOM/denial-of-service. The count is now clamped
  (`MAX_ESCAPE_REPEAT = 512`), and a malformed count no longer raises out of a field read — that had
  severed the connection and dropped a parseable message with **no disposition**, breaking the
  count-and-log invariant.
- **XML-DSig `verify()` now requires an explicit trust anchor** (DELTA-03;
  [`parsing/xml/signature.py`](messagefoundry/parsing/xml/signature.py)). Called with neither `x509_cert`
  nor `ca_pem_file`, it previously fell back to signxml's default of trusting **any** certificate that
  chains to the host's system CA store (origin-blind verification); it now raises `ValueError`.
  **Behavior change** for the opt-in `[xml]` codec — a caller must pin the expected signer or a partner
  CA. No in-repo caller relied on the old default.
- **FhirLookup SMART token endpoint is now egress-gated** (DELTA-04;
  [`[egress].allowed_http`](docs/CONFIGURATION.md)). A `fhir_lookup` connection composed with
  `with_smart_backend()` POSTs a signed `client_assertion` to its `smart_token_url`; that host was not
  checked against the egress allowlist (only the FHIR base host was), so a crafted `smart_token_url`
  could exfiltrate the assertion to an un-allowlisted host. The lookup and outbound arms now share one
  gate ([ADR 0043](docs/adr/0043-fhir-read-lookup.md) §D3).
- **Support bundle no longer discloses the store host/database; its log redaction was widened**
  (DELTA-05/07; [`support/`](messagefoundry/support/)). The offline support bundle's `status.json`
  carried the SQL Server `host/database` verbatim — it is now reduced to the backend kind (file basename
  only for SQLite). The bundled-log redactor previously used a fixed HL7-segment allowlist with no
  free-text name/DOB heuristics; it now delegates to the engine redactor
  ([`messagefoundry.redaction`](messagefoundry/redaction.py)) for parity with stored-error redaction.
- **Inbound HTTP listener rejects ambiguous framing** (DELTA-06;
  [`transports/http_listener.py`](messagefoundry/transports/http_listener.py)). A duplicate
  `Content-Length`, a duplicate `Transfer-Encoding`, or the two present together are now refused with
  `400` per RFC 7230 §3.3.3 — closing an HTTP request-smuggling / desync surface behind a fronting proxy.

## [0.2.13] — 2026-07-01 — Early Access

The **store connection-scale sizing** wave — right-size the server-DB connection pool to the measured
inverted-U optimum, guard against over-provisioning, and guarantee the message store stays unified. All
changes are **server-DB-only**; the single-node SQLite default is unaffected.

### Added
- **Soft store-pool over-provisioning warning** ([ADR 0062](docs/adr/0062-default-store-pool-size.md)) — a
  server-DB engine now logs an advisory `WARNING` at graph start if `[store].pool_size` is sized past the
  connection-pool inverted-U optimum: at/beyond the ~80 catastrophic cliff, or oversized for the engine's
  inbound-interface count (`~2.5 ×` interfaces). Advisory only — it never blocks startup; SQLite has no pool
  so it is skipped, and the default (40) never trips it. Guards the "set a huge pool for 1500 connections"
  footgun (which is a *sharding* problem, not a pool one).

### Changed
- **Default server-DB store connection pool size raised 5 → 40** ([`[store].pool_size`](docs/CONFIGURATION.md),
  env `MEFOR_STORE_POOL_SIZE`; [ADR 0062](docs/adr/0062-default-store-pool-size.md)). A three-sweep
  connection-scale study found the pool is an **inverted-U**: it helps up to ~40 per engine, and
  **over-provisioning is catastrophic** — past ~40 the extra connections thrash one shared SQL instance
  (WRITELOG serialization + per-message finalizer applocks), and ACK latency explodes 30–90×. 40 is the
  measured optimum — **do not set it higher to chase connection count.** **Server-DB backends only** (Postgres
  / SQL Server) — the default **single-node SQLite** backend is unaffected (fixed read pool + single writer;
  never reads `pool_size`). **Existing explicit `[store].pool_size` / `MEFOR_STORE_POOL_SIZE` values are
  unchanged** — only the unset default moves. Behavioral deltas on server-DB engines: ~**8×** the steady-state
  DB sessions per engine, and the startup pool pre-warm rises from ~2 to **~20 connections per engine**
  (bounded by `warm_pool_timeout`, off the intake path, self-releasing, never raises). **Connection-budget
  caution:** `pool_size` is **per engine**, so on a shared server DB `engines × pool_size` all count against
  one `max_connections` (Postgres default ~100 → ~2 engines at 40) — raise `max_connections`, front the DB
  with a pooler (PgBouncer), or use SQL Server; or size `pool_size` down. **Never split the store** to fit the
  budget ([ADR 0063](docs/adr/0063-no-split-store-unified-store-for-sharding.md)). See
  [`docs/DEPLOY-SERVER-DB.md`](docs/DEPLOY-SERVER-DB.md) §3.
- **No split data store: multi-shard engine sharding now requires a server DB** ([ADR 0063](docs/adr/0063-no-split-store-unified-store-for-sharding.md),
  amends [ADR 0037](docs/adr/0037-multi-process-sharding-l3.md)). `messagefoundry supervise` with **more than
  one shard** on a **SQLite** store is now **refused at startup** — the old SQLite-file-per-shard behavior
  split the message store into one database per shard, fragmenting search/reporting/audit/replay. A sharded
  deployment must share **one unified store**, so `>1` shard requires `[store].backend = 'postgres'` or
  `'sqlserver'` (every shard connects to the same database). **A single un-sharded engine on SQLite is
  unaffected** (byte-identical to `serve`). Migrating an existing SQLite-sharded deployment: drain each shard
  store to empty, then re-point `supervise` at one server DB (not an offline store merge).

## [0.2.12] — 2026-07-01 — Early Access

The **throughput & connection-scale wave.** The staged-queue per-message commit chain is shortened
(opt-in inline fast-path + batch-claim, plus a result-preserving seq-only FIFO ordering that drops a
per-handoff round-trip); a connection-scale measurement harness + read-only engine instrumentation lands;
**per-lane wake events** (opt-in) eliminate the thundering-herd empty-claim storm that dominates at high
connection counts; and ADR 0059's seq-only FIFO index re-key now reaches **upgraded** databases via a
one-time on-open migration. All new *runtime* behavior is opt-in / off-by-default unless noted — the
seq-only ordering (B3) and the index migration (B10) are result-preserving.

### Added
- **Inline Step-A fast-path** ([ADR 0057](docs/adr/0057-inline-step-a-fast-path.md)) — **opt-in per
  inbound via `inline`**: for the pure all-deliver message (no filter/state/pass-through), fuse
  route+transform+handoff into **one committed transaction**, cutting the per-message commit depth from 7
  to 5 durable round-trips. Off by default → byte-identical to the split path; ineligible messages fall
  back automatically.
- **Batch-claim** (#671, [ADR 0058](docs/adr/0058-batch-claim-fifo-prefix.md)) — **opt-in via
  `[store].fifo_claim_batch`** (>1): the INGRESS/ROUTED FIFO claim takes the contiguous due head-prefix in
  one commit instead of one row per commit, processed in strict FIFO order. Default `1` = off
  (byte-identical); preserves per-lane FIFO (#285) and at-least-once.
- **Per-lane wake events** (#678, [ADR 0061](docs/adr/0061-per-lane-wake-events.md)) — **opt-in via
  `[pipeline].per_lane_wake`**: a committed message wakes **only its own `(stage, lane)` worker** instead
  of every worker of that stage, eliminating the thundering-herd empty-claim storm at high **connection**
  counts (~1,500 inbounds). Default off + byte-identical; the FIFO claim and the lost-wakeup poll backstop
  are unchanged (a missed wake self-heals). Env override `MEFOR_PIPELINE_PER_LANE_WAKE` for the harness A/B.
- **Connection-scale measurement harness + read-only engine instrumentation** (#675) — a headless harness
  that spins N inbound connections at a low per-connection rate and reads the connection-scale walls
  (executor saturation, server-store pool wait, idle-poll storm, FD/socket count, config-reload + ACK
  latency) vs connection count. The supporting engine instrumentation is **additive + read-only**, surfaced
  via `/stats` + `/status`: empty-claim counters split into idle-poll vs per-commit wake-fanout, and (on a
  server store) connection-pool acquire-wait percentiles + size/idle occupancy. Counters default to 0 /
  `None` — byte-identical when unused.

### Changed
- **Seq-only per-lane FIFO ordering** (#673, [ADR 0059](docs/adr/0059-seq-only-fifo-ordering.md)) — the
  per-lane FIFO claim now orders by the DB-assigned `seq` (rowid on SQLite) **alone** instead of
  `(created_at, seq)`, and the per-insert `SELECT MAX(created_at)` clamp is removed from **every stage
  handoff** (one fewer round-trip per produced row). **Result-preserving** (proven order-isomorphic to the
  prior clamped ordering) and strictly more robust under clock skew / failover (`seq` has no wall-clock
  dependence). `created_at` stays a real ingest-time/metrics timestamp — it is simply no longer an ordering
  key. The FIFO covering indexes re-key to trail in `seq` (see the migration below).
- **Rename-based FIFO covering-index migration** (#676, [ADR 0060](docs/adr/0060-rename-based-fifo-index-migration.md)) —
  ADR 0059 re-keyed the per-lane FIFO indexes to trail in `seq` for the seq-only claim, but kept their names
  under `IF NOT EXISTS` guards, so **only fresh databases** adopted the new index — an upgraded DB silently
  kept its old `created_at`-trailing index and never got ADR 0059's throughput win. The seq-trailing indexes
  are now named `ix_queue_fifo_in_seq` / `ix_queue_fifo_out_seq`, and a one-time, idempotent **on-open
  migration drops the old-named index and builds the new one** on all three backends, so upgraded databases
  adopt it. Correctness is unchanged (the claim orders by `seq`/`rowid` and names no index, so the migration
  only restores speed). Operational notes: the first open after upgrade pays a **one-time index rebuild** on
  the `queue` table (SQLite/Postgres blocking, SQL Server offline — bounded by live queue depth, at cold start
  before serving); on a very large SQLite queue a *concurrent* second opener may hit a transient, non-corrupting
  open failure during the rebuild; the shared-DB backends (SQL Server / Postgres) should upgrade **stop-the-world
  / under a drain window** (a mixed-version fleet or a live rejoin can re-create or contend on the index); a
  downgrade re-creates the old-named index (drop `ix_queue_fifo_in/out` manually if downgrading permanently).
- **`/status` DB observability** — the SQLite journal mode and `synchronous` durability setting are now
  surfaced in the DB status (`synchronous=NORMAL` remains the crash-safe-under-WAL default).

## [0.2.11] — 2026-06-29 — Early Access

The **Plan-6 disaster-recovery + cloud/HA wave** — turnkey DR backup/restore-verify and a third-tier DR
standby, Kubernetes/cloud HA deployment packaging, and a frozen zero-Python Windows console installer —
alongside the free-threading-keystone built-ins HL7 parser and the first SQLite durable-write group-commit
lever. All on-prem and code-first; new behavior is opt-in / off-by-default unless noted.

### Added
- **Turnkey DR backup + restore-verify** (#60, [ADR 0049](docs/adr/0049-turnkey-dr-backup-restore-verify.md)) —
  an engine-managed scheduled/on-demand backup that bundles the loaded `--config` dir + a consistent SQLite store
  snapshot into one AES-256-GCM-encrypted `.mfbak` archive (chunked-AEAD, fail-closed on tamper/truncate/reorder,
  keyed by the existing store DEK — no new key), to an operator-set **local/UNC path (no cloud target)** under
  keep-N retention. The snapshot runs read-only off the event loop and never touches a staged-queue row; each run
  restore-verifies the archive (decrypt → `integrity_check` → row-count) and audits a PHI-free `dr_backup` row.
  New `messagefoundry backup` / `restore-verify` CLI. **Off by default** (`[backup].enabled = false`); SQLite-only
  (server-DB stores are DBA-delegated, backed up config-only); leader-gated under HA; a keyless PHI instance
  refuses to write a cleartext archive unless the audited `[backup].allow_unencrypted` escape is set.
- **Third-tier DR standby** (#61, [ADR 0048](docs/adr/0048-third-tier-disaster-recovery-standby.md)) —
  a right-sized disaster-recovery box that activates **only** when the whole active-passive HA pair/site (or its
  shared store) is gone, running a reduced high-priority feed set in an accepted degraded mode. Adds: a
  per-connection **`priority` tier** (`critical`/`normal`/`low`, `[delivery].priority` default `normal` +
  per-connection override); a startup **DR run-profile** (`[dr]`) that starts only connections at/above
  `priority_threshold` (default `critical`), the rest reporting `status:"filtered"`, behind an acquire-VIP-or-abort
  takeover; and a **cold seed** from #60's encrypted `.mfbak` (restore-verify, local/UNC only). Activation is
  **manual only** — audited `POST /dr/activate` / `/dr/release` gated by a new `dr:operate` permission;
  `activation_mode='auto'` is rejected at config load. No `[dr]` section = a no-op, unaffected.
- **Cloud / Kubernetes HA deployment packaging** (#41, [ADR 0047](docs/adr/0047-cloud-kubernetes-ha-deployment-packaging.md)) —
  packages the already-shipped active-passive HA into a copyable cloud target. **Packaging + docs only — no engine
  code changed.** Adds a Postgres-backed multi-replica k8s reference manifest (`docker/k8s/ha-postgres.yaml`:
  `replicas: 3`, `[cluster].enabled`, a PodDisruptionBudget, `terminationGracePeriodSeconds` > `leader_lease_ttl_seconds`
  so a drained leader releases its lease before SIGKILL, hardened `securityContext`, secrets via `secretKeyRef`) — no
  PVC, since durability lives in external Postgres. The default `compose.yaml` stays single-node SQLite; a new `ha`
  profile runs Postgres + warm standby locally. New `docs/CLOUD-DEPLOYMENT.md` (primary-only L4 NLB MLLP recipe; no
  L7/HPA for MLLP; SQL Server AG variant) and `docs/CLOUD-PHI-HIPAA.md` (BAA, KMS CMEK layered with the engine's own
  AES-256-GCM, PrivateLink). Active-passive only; demand-gated.
- **Frozen zero-Python Windows console installer** (#39, [ADR 0032 Phase B](docs/adr/0032-console-desktop-launch.md)) —
  the PySide6 admin **console** now ships as a self-contained Windows installer (a PyInstaller `--onedir` freeze
  wrapped in an Inno Setup `.exe`) with Desktop/Start-Menu shortcuts and an Add/Remove-Programs uninstall entry —
  **no Python, venv, or `pip install` on the box**. **Per-user / no-elevation by default** (opt-in all-users via
  `/ALLUSERS`); this packages the **console client only** — the engine NSSM service and the `127.0.0.1:8765` API
  boundary are unchanged. Frozen from the same wheel the release publishes, by an isolated job that never reds an
  engine release. **Authenticode signing is gated on an owner-provisioned cert** — until that secret lands the
  installer ships **unsigned** (SmartScreen "Unknown publisher"). Windows-only; no MSIX/Store, no auto-update.
- **SQLite app-side group-commit committer** (#64, [ADR 0055](docs/adr/0055-group-commit-durable-write.md)) —
  an opt-in durable-write lever for the single-writer SQLite backend: a committer coroutine coalesces the grouped
  staged-queue handoffs into one commit under the writer lock, amortizing fsyncs/msg, while the claim /
  reference-snapshot / audit writes stay standalone and every staged-queue invariant (count-and-log, at-least-once,
  FIFO) is preserved. **Off by default** — `[store].group_commit_window_ms = 0.0` builds no committer and is
  byte-identical to today; set it (with `group_commit_max_batch`, default 64) to enable. The win is largest under
  `synchronous=FULL` and muted under the default NORMAL. **SQLite only** — the server-DB backends ignore these knobs
  (native concurrent-pool group-commit is a later increment); the absolute enterprise throughput figure stays
  pending hardware-matched measurement.
- **Background store connection-pool pre-warm** (#661) — on graph start/promotion the engine fires a best-effort
  background task that pre-opens pooled connections on the **server-DB backends** (Postgres / SQL Server), so a
  connection burst — the post-promotion delivery workers in active-passive HA, or a cold start — finds them warm
  instead of paying cold connects (TCP+TLS+login). **On by default** via `[store].warm_pool` (+ `warm_pool_timeout`
  / `warm_pool_target`), capped to ≤ half the pool; a **no-op on SQLite**. Cancellation- and shutdown-safe — it
  never strands or hangs the engine on a failover to a dead node.
- **Single project-root config anchoring** (#33-A, [ADR 0050](docs/adr/0050-single-project-root-config-anchoring.md)) —
  one opt-in `--project-root` (= `[environments].base_dir`) anchors the whole config bundle (the `--config`
  graph, `environments/<env>.toml`, `messagefoundry.toml`, and `[store].path`) under one root with a single
  precedence (explicit-absolute > project-root > CWD), so a `serve` launched from a non-repo CWD (the NSSM
  case) no longer silently reads empty `env()` values or creates the DB in the wrong place. Three PHI-safe
  startup diagnostics: a hard-fail when an explicit root + an `env()`-referencing graph is missing its
  `<env>.toml`, a WARNING when CWD differs from the root, and a WARNING for the NSSM silent-miss. The
  `--project-root` / `--env` / `--service-config` flags are extended to the offline `validate` / `graph` /
  `dryrun` / `check` subcommands (value resolution only — not `serve`'s required-env / posture refusal), and
  `check` suppresses its `messagefoundry.toml` upward-walk when those flags are passed.

### Changed
- **Tolerant HL7 parser re-backed by a low-allocation built-ins model** (#88, [ADR 0054](docs/adr/0054-low-allocation-builtins-hl7-parser.md)) —
  the hot-path `Peek`/`Message` tolerant tier now parses over native `dict`/`list`/`str` instead of python-hl7, a
  **behaviour-identical drop-in** (public API, field-path semantics, escape rules, MSH-1/2 raw handling, and
  `encode()` round-trips all byte-parity-verified against python-hl7 over the golden corpus). MSH parses eagerly,
  other segments lazily on first field-path touch. **On by default**, with a per-parse python-hl7 fallback kept for
  this release — a contract `HL7PeekError` still raises and dead-letters, while an unexpected internal error falls
  back to python-hl7 and is logged, never crashing a connection. The free-threading keystone for
  [ADR 0053](docs/adr/0053-free-threaded-multicore-engine.md) and a large single-thread parse win; the strict hl7apy
  `validate()` tier and `parse_tree` / `RawMessage` are untouched. python-hl7 stays a dependency for the fallback
  window (removal is a follow-up release).
- **A set project root (`--project-root` or `[environments].base_dir`) now anchors the store DB too, not
  just `environments/`.** A deployment that runs `serve`/`supervise` with a project root **and** a relative
  `--db` / `[store].path` (or relies on the default relative `messagefoundry.db`) will now find/create the DB
  under the root instead of the process CWD — including each shard's `<stem>_<shard>.db`. `--project-root`
  additionally anchors a relative `--config` / `--service-config` (a file-only `[environments].base_dir`
  anchors the DB + env values but not those two, since they are resolved before the settings load). This is
  the intended fix for the split-store footgun, but it **relocates an existing relative DB**: pass an
  **absolute** `[store].path` / `--db` to keep the DB where it is (absolute paths bypass the root), or accept
  the new location. Deployments with no project root, or with an absolute DB path, are unaffected. The new
  CWD-mismatch WARNING surfaces any move at startup.

## [0.2.10] — 2026-06-27 — Early Access

The **Plan-5 "v0.3 candidate" wave** — completing the deferred connector/codec set and the Corepoint
parity gaps, built across two multisession waves (L1–L9) and adversarially reviewed. All on-prem,
code-first, no behavior change to existing graphs.

### Added
- **Inbound HTTP / REST listener** (#7, [ADR 0023](docs/adr/0023-inbound-http-listener.md)) — a
  connector-owned bound `asyncio` HTTP/1.1 socket **source** in `transports/` (not `api/`), feeding the
  payload-agnostic ingress (ADR 0004) as a `RawMessage`. ACK-on-receipt (respond-with-receipt **after** the
  raw is durably committed), with oversize/malformed/slow-loris hardening surfaced as `connection_event`s;
  new `ConnectorType.HTTP`. The substrate for the future inbound FHIR facade (#20) / DICOMweb receiver (#24).
  *(SOAP-envelope sync-reply, intake-socket auth, and method/path routing metadata are deferred follow-ons.)*
- **`fhir_lookup(connection, query)`** (#58, [ADR 0043](docs/adr/0043-fhir-read-lookup.md)) — a Handler-callable,
  **read-only** FHIR read/search that extends the ADR 0010 `db_lookup` carve-out to FHIR: off the event loop,
  raises on a Router / in dry-run, reuses the SMART Backend bearer (ADR 0024) + `[egress].allowed_http`, GET-only.
- **Email / SMTP outbound destination** (#23, [ADR 0029](docs/adr/0029-email-smtp-destination.md)) — a stdlib
  `Email()`/`SMTP()` connector; STARTTLS-by-default, AUTH-over-TLS-only, a new deny-by-default
  `[egress].allowed_smtp` arm. (IMAP/POP read + XOAUTH2 is a deferred Phase 2.)
- **X12 strict implementation-guide validation** via `pyx12` (#32) behind the tolerant `X12Peek`/`X12Message`
  hot path (`messagefoundry[x12]`; yields 997/999 acks), and a **structured `[xml]` codec layer** (#31) —
  `XmlMessage` (XPath read/set + ns-aware re-encode) over **hardened lxml** + optional `xmlschema`/`signxml`
  (`messagefoundry[xml]`; XXE / entity-expansion / external-DTD refused).
- **Operator alert-state** (#56, [ADR 0044](docs/adr/0044-operator-alert-state.md)) — a new `alert_instance`
  store table (open / acknowledged / resolved + first/last-seen + count) across all three backends, de-duped on
  the ADR-0014 throttle key; `GET /alerts/active` + ack/resolve (RBAC `MONITORING_DIAGNOSE`); the per-connection
  `alerts_active` count is now real; a console Alerts tab. Metadata-only.
- **User-definable custom RBAC roles** (#57, [ADR 0045](docs/adr/0045-custom-rbac-roles.md)) — an admin-defined
  named role = a chosen **subset** of the existing Permission catalog (no new permission kinds), persisted via an
  additive `roles` migration (3 backends), gated by `USERS_MANAGE`; the six built-ins stay; narrowing revokes on
  live sessions.
- **Message-content search** (#51, [ADR 0046](docs/adr/0046-message-content-search.md)) — HL7 field-path /
  raw-content matching by **scan-and-decrypt-per-row** (the store is AES-GCM-encrypted at rest, so a plain `LIKE`
  is impossible): metadata-pre-filtered, hard row/result caps (truncate-and-tell), decrypt off the event loop,
  behind `messages:view_*` + **step-up** + a `message_search` audit row that never logs the search needle.
- **HL7 timestamp helpers on `Message`** (#59) — `age`-from-DOB, length-of-stay, and the tolerant HL7-TS parse
  surfaced on the `Message` API (reusing `timezone.py`; no duplicate parser).
- **`messagefoundry support-bundle`** CLI (#49) — a PHI-safe diagnostic zip (no message bodies, no secrets;
  redacted log tail) — and a **zero-egress version update-check** (#30,
  [ADR 0026](docs/adr/0026-off-box-egress-update-check.md)): a no-network pinned-vs-current diff surfaced as a
  `/status` field + an `update_available` alert + a console banner (on by default; `mode=live` rejected at load).

### Changed
- `[egress]` gains `allowed_smtp` (email); the read-only-lookup carve-out (CLAUDE.md §2/§8) now names
  `fhir_lookup` alongside `db_lookup`.
- New connectors/codecs are documented in [`docs/CONNECTIONS.md`](docs/CONNECTIONS.md) and the update-check in
  [`docs/CONFIGURATION.md`](docs/CONFIGURATION.md) (`[update_check]`).

### Security
- All new live-lookup / search paths stay on-prem and gated: `fhir_lookup` and the update-check are zero-/
  allow-listed-egress; content search is step-up-gated + audited and never weakens at-rest encryption (the
  cleartext key-field index was **declined**; a keyed-token index is a deferred 2nd slice). New crypto sites
  (`transports/http_listener.py` TLS) are registered in the ASVS-11.1.3 crypto inventory.

### Dependencies
- New optional extras only: `messagefoundry[x12]` (`pyx12`) and `messagefoundry[xml]`
  (`lxml`/`xmlschema`/`signxml`); the base install is unchanged. Lockfile re-exported.

## [0.2.9] — 2026-06-27 — Early Access

A retention + security-hardening + observability release: per-connection retention and
embedded-document pruning windows, dual-control config reloads with startup code-attestation,
operational-health metrics, and a fix for the intermittent Windows listener-teardown / CI hang.

### Added
- **Per-connection retention windows (ADR 0027).** Optional `messages_days` (inbound) and
  `dead_letter_days` (outbound) on a connection, layered over the global `[retention]` window and
  authored on the connection spec or `connections.toml` (the same override idiom as the delivery
  knobs): `None` inherits the global window, `0` keeps forever. The `RetentionRunner` threads a
  per-connection cutoff through the body and dead-letter purge on **all three** store backends; the
  never-purge-an-in-flight-body guard and the single per-pass audit row (now recording the overrides)
  are unchanged. (#34)
- **Embedded-document pruning (ADR 0042).** Optional `prune_documents_after` (+ a size threshold)
  per inbound connection: after the window, bulky **base64 embedded documents** — HL7 **OBX-5 ED**
  and the generic `mfb64:v1:` carriage — are stripped **in place** to a small size/content-type
  tombstone (via the parsed model / codec, **never** string-slicing HL7), keeping the rest of the
  message parseable; the row is never deleted and a `documents_pruned` flag is set. All three
  backends. (The ingest-time offload variant remains deferred.) (#47)
- **Dual-control `config:reload` (ADR 0041 D2).** `config_reload` is now a gateable
  `[approvals].operations` op — a **distinct** second approver must release a live config reload
  (the requester can never self-approve; both identities land in the hash-chained audit). Opt-in /
  deny-by-default, so single-operator deployments are unchanged. (#53)
- **Startup code self-attestation (ADR 0041 D3).** At startup the engine hashes its loaded modules
  against the wheel's `dist-info/RECORD`; on drift it records a hash-chained, off-box-teed
  `startup_integrity` audit row and raises an alert (**alert-only by default**; opt-in
  `[integrity].fail_closed_on_drift` refuses to start). A no-op on an editable (`pip install -e .`)
  install, so development is never bricked. (#54)
- **Operational-health metrics.** `GET /status` now meters the app-log directory's disk usage
  alongside the database, and a per-connection **message-stall** alert rule fires when a connection's
  oldest-undelivered age crosses a configurable threshold. (#50)

### Changed
- **Non-editable, hash-locked wheel is the enforced production default (ADR 0017 amendment).** The
  prior recommendation is now the default for production deployments; editable installs remain a
  no-op for development. (#54)

### Fixed
- **Intermittent Windows listener-teardown hang.** `MLLPSource` / `TcpSource` / `X12Source` no longer
  `await server.wait_closed()` / `writer.wait_closed()` **unbounded** on the Windows Proactor loop
  during teardown — a wait that never completes can no longer stall a shared event loop (the same
  class as the resolved py3.11 hang). Added CI guards (a per-test `faulthandler` stack dump and a
  step-level watchdog) so a future hang fails fast and names itself instead of silently timing out. (#55)

### Docs
- Refreshed `benchmarks/TUNING-BASELINE.md` with measured multi-process sharding throughput from the
  Windows Server 2025 box (η ≈ 0.85 speedup shape; per-shard E_core ≈ 42 msg/s — a test-box SQLite
  floor), plus the still-unmeasured hardware-gated follow-ups (enterprise E_core, the shared-DB
  commit-wall sweep). (#28, #29)
- Authored **ADR 0027** (per-connection retention) and **ADR 0042** (embedded-document pruning); added
  EARS acceptance criteria to **ADR 0041** D2/D3; amended **ADR 0017** for the enforced wheel.

### CI
- Locked the smoke job's config directory (#603) and skipped a mirror-only Dependabot guardrail test
  on the OSS mirror (#606), greening `main` CI post-0.2.8.

## [0.2.8] — 2026-06-27 — Early Access

A tooling/ops release: the load harness gains a **multi-shard driver** so one harness can drive a
`supervise` cluster (unblocking the multi-core throughput measurement), `supervise` resolves
`--env` files for its shards, and a prominent upgrade note for the config-directory permission
guard introduced in 0.2.6.

> ### ⚠ Upgrading from ≤ 0.2.5 — tighten config-dir ACLs first
> The config-directory permission guard (SEC-003 / ADR 0036), added in **0.2.6**, refuses to load a
> `--config` directory that is **writable by a broad principal** (e.g. `Authenticated Users` /
> `S-1-5-11`). A deployment whose config dir inherits that write — common under `C:\srv\…` — will
> **fail to start on first upgrade to ≥ 0.2.6** with *"refusing to load config from writable-by-others
> path …"*. **Before upgrading**, tighten the directory (elevated):
> ```powershell
> icacls "<config-dir>" /inheritance:d /T
> icacls "<config-dir>" /remove:g *S-1-5-11 /T          # drop Authenticated Users
> icacls "<config-dir>" /grant *S-1-5-18:(OI)(CI)F /grant *S-1-5-32-544:(OI)(CI)F /T  # SYSTEM + Admins
> ```
> See [`docs/SERVICE.md`](docs/SERVICE.md) → *Update to a new build* and *Lock down the config
> directory (CONFIG-2)*.

### Added
- **Multi-shard load driving (`messagefoundry-harness`).** `python -m harness` gains
  **`--skip-preflight`** (drive shard MLLP ports that no single `--engine` owns) and a repeatable
  **`--shard-engine <url>`**: the engine poller now takes a list of shard APIs and **sums** each
  shard's `/stats` (read/written/backlog/in_pipeline/queue_depth/dead) into one cluster sample, so
  the no-loss reconcile and drain are **cluster-aggregate** — a healthy K-shard run reports pass,
  not a false "lost on intake". With no `--shard-engine` the behavior is byte-identical to before.
  Two sample graphs ship for the throughput suite: `harness/config/store_once` (the
  dedup-triggering one-handler-`list[Send]`-of-identical-body shape for store-once) and
  `harness/config/passthrough` (an internal `PassThrough()` re-ingress hop); the load graph
  (`harness/config/load`) is now shard-taggable via `MEFOR_LOAD_SHARD_ADT`/`_RESULTS`/`_OTHER`. (#604)

### Fixed
- **`supervise --project-root`.** `supervise` now accepts `--project-root` and forwards it to each
  spawned `serve --shard`, so `supervise --config <dir> --env <env>` resolves each shard's
  `environments/<env>.toml` (previously the shards resolved nothing from their spawned cwd and
  required an explicit `--service-config` posture). Backward compatible — no `--project-root` is
  unchanged. (#602)

## [0.2.7] — 2026-06-27 — Early Access

A docs/packaging release that fixes the broken badge images on the PyPI project page
and adds a config-check pre-commit hook.

### Fixed
- **Broken badge images in the PyPI project description.** The CI and Security status
  badges in the README pointed at the **private** source repo, so they rendered as
  broken images on the public PyPI page — an anonymous viewer can't fetch a private
  repo's GitHub Actions badge SVG (it 404s). The README now points at the public
  mirror (`MEFORORG/MessageFoundry`), and the release build additionally rewrites any
  remaining `wshallwshall`→`MEFORORG` repo slug in the README before it is embedded as
  the PyPI `long_description`, so the rendered badges resolve anonymously. (#568)

### Added
- **`messagefoundry check` pre-commit hook.** A VS Code-extension-generated
  `.mefor-hooks/pre-commit` runs `messagefoundry check` so a commit can't introduce a
  broken config (skips cleanly if python or the package isn't importable; bypass with
  `--no-verify`). (#568)

### Docs
- Backlog **#47** — base64 embedded-document (attachment) pruning (Mirth
  attachment-handler / data-pruner parity); and a Changelog link in the README. (#568)

## [0.2.6] — 2026-06-27 — Early Access

A large release: the **throughput-maximization build** (high-fan-out store-once, multi-process
sharding, and internal pass-through connectors with full Postgres/SQL Server parity), a console +
IDE **"fleet" tier** for managing multiple engine shards, and a broad **security-hardening wave**
from the 2026-06 audit.

### Added
- **Multi-process sharding (L3).** An inbound connection can carry an optional `shard` tag;
  `serve --shard <id>` runs an engine process that owns only that shard's inbound connections
  (outbound + routing/handlers are shared), and a new `supervise` command spawns, monitors, and
  restarts one `serve` subprocess per shard (each with its own SQLite db file and API port).
  Per-connection sharding parallelizes intake across CPU cores; per-channel FIFO is preserved
  within a shard. (#584)
- **Internal pass-through (PT) connectors (L4).** A Handler may `Send` into an internal
  `PassThrough()` inbound that carries its own router; the message re-ingresses as a new
  content-addressed child message inside the same transaction (at-least-once, count-and-log, and
  single-finalizer authority all preserved), bounded by a correlation-depth loop guard. This
  generalizes the ADR 0013 re-ingress primitive. Implemented on **all three store backends** —
  SQLite, plus full **Postgres and SQL Server parity** for the atomic re-ingress. (#585, #590)
- **Store-once-deliver-many (L2b).** A high-fan-out outbound now stores the message body **once**
  (content-addressed, reference-counted `shared_body`) instead of once per destination;
  single-destination delivery is unchanged (inline, byte-identical). (#580)
- **Fleet tier — manage multiple engine shards.** The console can register and switch between
  multiple engine endpoints (#582); the IDE promote flow can target a specific engine
  instance/shard (#583).
- **IDE editor productivity.** A MessageFoundry build toolbar + CodeLens on config files (#593),
  an "Insert Element" quick-pick with expanded transform-idiom snippets (#595), a Wizards group
  with collapsible Home groups (#578), and a `vsce` VSIX packaging script (#577).
- **Config-fingerprint attestation.** Config reloads record a config fingerprint in the reload
  audit (ADR 0041 load-path attestation). (#597)

### Changed
- **Faster fan-out.** On a fan-out the engine parses the per-message payload once where it is
  value-identical, avoiding redundant re-parsing. (#581)

### Fixed
- **Fail-fast pass-through guard.** A graph with a PT inbound on a store backend that does not
  implement PT re-ingress is now rejected at startup *and* on reload/dry-run (a clear configuration
  error, HTTP 422) — before any listener binds — instead of failing at the first `Send`. (#587)
- **Auth hardening.** Tighter field-level authorization, a last-admin guard, a corrected TOTP
  window, and rate-limit documentation fixes. (#563)
- **API / store.** Channel-scoped event and topology reads, faster WebSocket session revocation,
  and atomic bootstrap-secret creation. (#565)
- **IDE.** Workspace-trust gating, machine-scoped promote targets, and a fail-closed AI-assist
  policy (SEC-004/005/022). (#561)

### Security
The 2026-06 security-audit remediation wave (in-repo remediation ledger, #566):
- **Transport TLS / SSRF / injection:** FTPS TLS verification, an FHIR-path SSRF guard, and
  read-only enforcement on `db_lookup` (SEC-001/010/009). (#560)
- **Listener hardening:** a cleartext-bind guard plus source-IP allowlist for the raw-TCP/X12
  listeners. (#558)
- **DICOM:** fail-closed C-STORE SCP peer controls (calling-AE + peer-IP) and a passphrase-key
  callback (SEC-012/016). (#559)
- **Pipeline:** off-event-loop router/transform execution and a non-HL7 ingress size cap
  (SEC-013/017). (#562)
- **Config trust:** enforce Windows config-source trust and scope the sibling-helper finder
  (SEC-003/019). (#564)
- **PHI redaction:** narrowed a free-text PHI residual and added an advisory raise-fstring lint
  (SEC-023). (#557)
- **Supply chain:** Dependabot security-track guardrails and adopter-scaffold hash-pinning. (#556)
- **Static analysis:** resolved two real CodeQL findings (webview HTML attribute escaping;
  owner-only file-delivery fallback) (#554) and adopted a CodeQL triage policy + accepted-risk
  register (ADR 0034). (#567)

### Docs
- ADRs 0037–0040 record the throughput-build decisions (multi-process sharding, pass-through
  connectors, the shelved L5 DB-sharding design, and the not-adopted free-threading assessment)
  (#591); design notes for L5 DB-sharding (#588) and cp314t readiness (#589); and the Secure
  AI-Assisted Development Standards updated with the audit lessons (#576).

## [0.2.5] — 2026-06-26 — Early Access

A bug-fix release hardening SQL Server cluster cold-start.

### Fixed
- **SQL Server: concurrent schema-init race on a virgin DB (HA cold start).** Two cluster nodes starting
  simultaneously against an empty database both ran the `IF OBJECT_ID(...) IS NULL CREATE TABLE` guards
  with no cross-node lock, so both issued `CREATE` and the loser died at startup on a `2714` ("There is
  already an object named ..."). `_ensure_schema` now takes an exclusive `sp_getapplock`
  (`mefor:schema_init`) around the DDL — the T-SQL analog of the PostgreSQL store's existing schema
  advisory lock — so the second node serializes and runs the now-no-op guarded CREATEs cleanly. Single-node
  and pre-created schema are unaffected; SQLite and PostgreSQL were already race-safe. (#553)

### Changed
- Docs: the `[cluster]` settings docstring and the pool-size validation error now name both `postgres` and
  `sqlserver` (the cross-section validator already admitted both). (#553)

## [0.2.4] — 2026-06-26 — Early Access

A bug-fix release that completes the EF-6 SQL Server fix shipped in 0.2.3.

### Fixed
- **SQL Server: EF-6 "Connection is busy with results for another command" fully resolved (0.2.3's fix
  was incomplete).** v0.2.3 (#543) switched the FIFO claim read to `fetchall`, but draining the
  `UPDATE...OUTPUT` *rows* does not free the *statement handle* — without MARS the pooled connection was
  still returned to the aioodbc pool busy, so the error reproduced at every cold start. All pooled cursor
  sites now close the cursor (`SQLFreeStmt`/`SQLCloseCursor`) via a new `_cursor` context manager before
  the connection is released, on both the success and exception paths; `claim_ready` (another
  `UPDATE...OUTPUT`) and the `DELETE...OUTPUT` handoffs had the same latent gap and are covered too. A
  driver-free unit test now asserts the close-before-release invariant so the regression can't recur.
  SQLite and PostgreSQL were unaffected. (#550)

## [0.2.3] — 2026-06-26 — Early Access

A bug-fix + feature release: the SQL Server store no longer raises "connection busy" errors under
concurrent load, plus connection/transport event logging, GUI-managed translation tables, and inbound
listener port-conflict detection.

### Fixed
- **SQL Server: "Connection is busy with results for another command" under concurrent load (EF-6).**
  `claim_next_fifo` — and three sibling sites (`_maybe_finalize`, `consume_recovery_code_hash`,
  `consume_totp_step`) — read a result-set-returning statement with a lone `fetchone()` and could return
  the pooled connection to the pool with the result set still pending, so the next borrower's first
  command raced an `HY000` busy error (ODBC Driver 18, no MARS). All affected sites now fully drain the
  result set (`fetchall`) before commit/release. SQLite and PostgreSQL were unaffected (asyncpg
  materializes rows; SQLite has no shared pooled-connection single-result-set constraint). (#543)

### Added
- **Connection/transport event log + "Response Sent" ACK capture** (ADR 0020 / ADR 0021). A new id-keyed,
  metadata-only `connection_event` table records inbound connection lifecycle, pre-ingress failures, and
  outbound lane transitions, with a `[diagnostics]` config block (per-connection overrides + retention),
  a `GET /events` read API, and a console **Event Log** page. Event reasons are scrubbed and encrypted at
  rest. (#541)
- **GUI-managed translation tables (code sets)** (ADR 0033). A code-set CLI + writer and a VS Code
  extension grid editor / **Translation Tables** view for maintaining code-set mappings. (#540)
- **Inbound listener port-conflict detection** — static + runtime checks that flag two inbound
  connections bound to the same host:port before they collide at startup. (#538)

### Changed
- Docs: README install instructions are now version-agnostic and link the website docs; the roadmap
  section is replaced with a features summary. (#542, #544)

## [0.2.2] — 2026-06-24 — Early Access

A security-hardening release: PHI-at-rest encryption is closed across every backend, the active-passive
cluster gains a store-checked split-brain fence, outbound delivery is effectively-once, and the at-rest
cipher becomes crypto-agile — all additive, with the on-disk `mfenc:v1` format byte-identical.

### Changed
- **BREAKING — Python 3.14 is now the only supported runtime.** `requires-python` is raised to `>=3.14`
  (was `>=3.11`), and the ruff/mypy targets, CI matrix (Linux + Windows Server 2022/2025, all on 3.14),
  Docker base image, lockfiles, and adopter scaffold move with it. **Adopters and engine hosts must be on
  Python 3.14** — a 3.11/3.12/3.13 host will refuse to install the wheel. The 3.11/3.12/3.13-specific test
  apparatus is retired with this change (the `MEFOR_PY311_QUARANTINE` conftest lever, the `py3.11 store
  soak` CI job, and `scripts/soak/store_soak.py`; the underlying BACKLOG #17 asyncio↔aiosqlite concern is
  still mitigated by the shared session loop in `pyproject.toml`).

### Security
- **PHI-at-rest encryption closed across all three backends.** The patient `summary` (MRN + name) and
  `metadata` columns are now encrypted at rest (previously cleartext even with encryption enabled), and the
  SQL Server `error` / `last_error` / `message_events.detail` columns are brought to parity with SQLite and
  Postgres — every cipher column is now AES-256-GCM at rest. Coverage is surfaced by a new authenticated,
  audited `GET /security/posture` route (reports the active-key fingerprint + per-backend column coverage;
  never key bytes).
- **Fail-closed for PHI without a key.** An instance declared `data_class = phi` now **refuses to start**
  without an encryption key (previously it started in cleartext with a warning), unless explicitly overridden
  by the new, audited `[store].allow_unencrypted_phi`.
- **Crypto-agility marker (additive).** The at-rest cipher marker is now version/algorithm-aware
  (`mfenc:v2:<alg>:…`) so a future algorithm can be introduced without a data migration. The `mfenc:v1`
  format is byte-identical and AES-256-GCM remains the only algorithm; decryption fails closed on an unknown
  marker version or algorithm.
- **Database-TLS hardening.** A new `[store].ssl_root_cert` pins a private database CA (Postgres), with
  machine-store CA-import and certificate-rotation operator runbooks. The DPAPI key file's ACL now grants the
  service account read access without broadening exposure.

### Added
- **Active-passive split-brain fence.** A monotonic leader-epoch fencing token on the leadership lease,
  validated inside the FIFO claim transaction, so a superseded or paused ex-leader that resumes is fenced out
  (it claims nothing) — backed by continuous "at most one leader" SLO checks and a real-handover failover
  test. SQLite (single-node) behavior is unchanged.
- **Effectively-once outbound delivery.** A same-transaction idempotency ledger skips re-delivery of an
  already-delivered message after a failover or crash-recovery re-claim, without re-ordering a lane; an
  operator-initiated replay still re-sends.
- **Pre-side-effect leadership re-checks** so a node that loses leadership between claiming and sending
  re-queues the work rather than emitting it as a stale leader.
- `messagefoundry verify --check-disposition` for post-deploy disposition validation.

### Fixed
- CycloneDX SBOM generation on Python 3.14.
- PyPI long-description rendering (version pins, links).
- De-flaked several intermittent CI tests (failover-load timeouts, a harness server port-bind race, the
  startup fault-isolation recovery assertion, and the docker-smoke shutdown-marker check).

## [0.2.1] — 2026-06-23 — Early Access

### Fixed
- **Windows: `messagefoundry --help` crashed on a legacy codepage** — the top-level help rendered a
  non-cp1252 character (a `->` arrow in the `adr-analyze` subcommand help, new in 0.2.0), so `--help`
  aborted with `UnicodeEncodeError` on a cp1252/charmap console (cmd, PowerShell, or any redirected
  stdout). `main()` now reconfigures stdout/stderr with `errors="replace"` and the help text is ASCII;
  the machine-read JSON introspection subcommands are unaffected (`json.dumps(ensure_ascii=True)`).
- **`verify --section host` crashed without the `[console]` extra** — `check_console_no_window()`
  resolved a console submodule via `find_spec`, which imported the console package and its eager `httpx`
  dependency, so a `[sqlserver]`-only install aborted with `ModuleNotFoundError: No module named 'httpx'`
  instead of skipping the console check. The console package now imports its API client lazily (PEP 562
  `__getattr__`), so resolving a submodule no longer requires `httpx`, and the check degrades to SKIP if a
  console dependency is absent.

## [0.2.0] — 2026-06-23 — Early Access

### Added
- **One-click console launch** — a windowed `messagefoundry-console` launcher (`[project.gui-scripts]`, no
  flashing console window) carrying the MessageFoundry badge as the window/taskbar icon, plus
  `scripts/console/install-console-shortcut.ps1` to drop Desktop / Start-Menu shortcuts (per-user, or
  `-AllUsers` for machine-wide). Operators open the admin console by double-clicking an icon instead of
  running a Python command. See [ADR 0032](docs/adr/0032-console-desktop-launch.md).
- **SQL Server 2025 support** — the SQL Server store + Database connector are now validated against SQL
  Server 2025 (17.x) in addition to 2022 (16.x): both majors are exercised by the gated CI legs (store,
  coordinator, failover, and load smoke). No schema or T-SQL change was needed — ODBC Driver 18 (18.5+)
  covers both. The supported-version matrix moves from 2019/2022 to **2022/2025**. Note: SQL Server 2025
  requires an AVX-capable CPU.

### Security
- **Dependency fast-response program** — a KEV→EPSS→CVSS triage policy with a **≤72h fast lane** for
  actively-exploited dependency CVEs ([`.github/SECURITY.md`](.github/SECURITY.md),
  [`docs/security/DEP-CVE-RUNBOOK.md`](docs/security/DEP-CVE-RUNBOOK.md)); a **daily** SCA cron;
  Dependabot moved to the native `uv` ecosystem with **automatic hashed-lock re-export**; **scoped
  auto-merge** of safe patches with a **supply-chain cooldown**; weekly **RV.2 metrics**
  ([`docs/security/DEPENDENCY-METRICS.md`](docs/security/DEPENDENCY-METRICS.md)); and an adopter
  remediation SLA + advisory process ([`docs/SUPPORT-POLICY.md`](docs/SUPPORT-POLICY.md),
  [`docs/security/ADVISORY-PROCESS.md`](docs/security/ADVISORY-PROCESS.md)).
- **Adopter "vulnerable pin" tripwire** — `messagefoundry init`'s scaffolded CI gains an `audit-pin` job
  that reds an adopter's build when their pinned engine or its dependencies have a known published
  advisory ([`docs/ADOPTER-CI.md`](docs/ADOPTER-CI.md)).
- **Release-sync drift guard** — a tag/PyPI/public-mirror version-consistency tripwire + a publish-time
  version guard, so the git tag, the PyPI wheel, and the OSS mirror can't silently diverge.

## [0.1.0] — 2026-06-18 — Early Access

First public **Early Access** release: the feature set is complete and validated by the project's own
tests, but the external code review + penetration test (the bar for a security-certified **v1.0**) happen
*after* launch — so this is not yet "GA / independently security-reviewed". See
[`docs/EARLY-ADOPTER-GUIDE.md`](docs/EARLY-ADOPTER-GUIDE.md).

### Added
- **Engine + staged pipeline** — code-first Connection / Router / Handler model on a durable staged queue
  (ingress → routed → outbound) with at-least-once handoff, retry/backoff, dead-letter, and replay.
  Count-and-log: every received message is persisted with its disposition before the ACK.
- **Transports** — MLLP and File (source & destination); REST, SOAP, and Database destinations; a Database
  poll source. Payload-agnostic ingress (HL7 v2.x by default; JSON / XML-SOAP / X12 / DB records).
- **Server-DB store backends (production)** — PostgreSQL and Microsoft SQL Server, alongside the
  zero-config single-node SQLite (WAL) default. Byte-identical single-node behaviour on every backend.
- **Active-passive high availability** — self-fencing leadership lease, leader-gated message graph,
  claim-time per-lane FIFO across nodes, cross-node convergence, and read-only `/cluster/*` observability
  (surfaced as a leader/role/lease + node-roster view on the console's Engine Status page), on **both**
  PostgreSQL and SQL Server. A two-node failover-load test harness (SIGKILL-the-primary under load) proves
  recovery + no acknowledged loss + preserved per-lane ordering.
- **Security** — authentication + RBAC (local and AD: LDAP/Kerberos), deny-by-default per-route
  permissions, opaque sessions, a user-attributed tamper-evident (hash-chained) audit log, AES-256-GCM
  body encryption at rest with key rotation, native transport TLS (API HTTPS/WSS + MLLP-over-TLS) with an
  off-loopback bind guard and a certificate-expiry monitor, deny-by-default egress controls, PHI log
  redaction, and a centrally-governed, PHI-safe AI-assist policy.
- **Operability & tooling** — a localhost HTTP/WebSocket API; a PySide6 admin console; the `messagefoundry`
  CLI (`serve` / `validate` / `graph` / `dryrun` / `check` / `connection` / `generate` / …); a VS Code
  extension (setup, promote, test bench); a headless load + failover test harness; and a published
  throughput + active-passive failover **baseline** ([`docs/benchmarks/TUNING-BASELINE.md`](docs/benchmarks/TUNING-BASELINE.md)).
- **Alerting** — a logging sink plus a webhook/email notifier; queue-buildup and certificate-expiry alerts.
- **Deployment** — runs as a Windows service via NSSM; a channel × TLS-posture deployment matrix
  ([`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)); a staged Lab → Shadow → Limited → Full early-adopter guide.

### Notes
- Throughput is **hardware-dependent** (a durable-write-bound path); the published numbers are "as measured
  on a reference config", not a guarantee — re-run the method on your hardware. See
  [`docs/benchmarks/TUNING-BASELINE.md`](docs/benchmarks/TUNING-BASELINE.md).
- Releases are built, SBOM'd (CycloneDX), and signed with [Sigstore](https://www.sigstore.dev/) — see the
  `release` workflow.

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.10...HEAD
[0.2.10]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.9...v0.2.10
[0.2.9]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.8...v0.2.9
[0.2.8]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.7...v0.2.8
[0.2.7]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MEFORORG/MessageFoundry/releases/tag/v0.1.0
