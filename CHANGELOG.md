# Changelog

All notable changes to MessageFoundry are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **BREAKING — Python 3.14 is now the only supported runtime.** `requires-python` is raised to `>=3.14`
  (was `>=3.11`), and the ruff/mypy targets, CI matrix (Linux + Windows Server 2022/2025, all on 3.14),
  Docker base image, lockfiles, and adopter scaffold move with it. **Adopters and engine hosts must be on
  Python 3.14** — a 3.11/3.12/3.13 host will refuse to install the wheel. The 3.11/3.12/3.13-specific test
  apparatus is retired with this change (the `MEFOR_PY311_QUARANTINE` conftest lever, the `py3.11 store
  soak` CI job, and `scripts/soak/store_soak.py`; the underlying BACKLOG #17 asyncio↔aiosqlite concern is
  still mitigated by the shared session loop in `pyproject.toml`).

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

[Unreleased]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/MEFORORG/MessageFoundry/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/MEFORORG/MessageFoundry/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/MEFORORG/MessageFoundry/releases/tag/v0.1.0
