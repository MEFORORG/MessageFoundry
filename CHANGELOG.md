# Changelog

All notable changes to MessageFoundry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.7...HEAD
[0.2.7]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.6...v0.2.7
[0.2.6]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.5...v0.2.6
[0.2.5]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.4...v0.2.5
[0.2.4]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.3...v0.2.4
[0.2.3]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MEFORORG/MessageFoundry/releases/tag/v0.1.0
