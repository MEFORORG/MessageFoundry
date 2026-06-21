# MessageFoundry

[![CI](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml)
[![Security](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

MessageFoundry is an **open-source integration engine for healthcare**. It connects clinical and
business systems — routing, transforming, and validating messages across many formats (HL7 v2, JSON,
XML/SOAP, X12, database records) and connection types (MLLP, TCP, HTTP/REST, SOAP, database, files,
SFTP/FTP). Configure it with guided tooling or extend it in Python; it runs on SQLite or PostgreSQL
with authentication, RBAC, audit, and encryption-at-rest built in.

> Python import package: `messagefoundry`. Built with **hl7apy** + **python-hl7** (HL7 parsing/
> validation), **FastAPI** (engine API), and **PySide6** (admin console).

## What it is

A modern alternative to engines like Mirth and Corepoint. Messages flow through a graph you
wire by name: an inbound **Connection** hands off to a **Router**, which forwards to one or more
**Handlers** (filter → transform), which deliver to outbound Connections — all backed by durable
queuing, automatic retries, and replay. Build that graph with guided wizards, or in Python for full
control; either way the configuration is version-controlled and yours.

## Architecture

**Engine-as-library + localhost API.** The engine is an importable Python package.
The PySide6 console talks to it over a localhost HTTP + WebSocket API — the same way
whether the engine runs in-process, as a local daemon, or (later) on a remote host.
No hand-rolled IPC; the deployment split is a config choice, not an architectural fork.

See **[docs/architecture-diagram.md](docs/architecture-diagram.md)** for the rendered diagrams —
system topology, runtime message flow through the staged queue, and the config wiring graph (Mermaid,
renders on GitHub and in the VS Code preview). The prose source of truth is
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

### Key decisions
- **Reliable by default.** A durable, transactional pipeline gives at-least-once delivery,
  automatic retries, replay, and dead-lettering — no separate message broker to run.
- **Async core.** asyncio with per-connection workers for listeners, pollers, retries.
- **Tolerant parsing first.** `python-hl7` for fast routing/peek; `hl7apy` for deep,
  version-aware validation and profiles on demand (real-world HL7 is often non-conformant).
- **Configure visually or in code.** Author connections and routes with guided wizards, or in
  Python (`inbound`/`outbound`/`@router`/`@handler`) for full control — always version-controlled.
  The database holds runtime state and messages only, never configuration.
- **PHI is first-class.** Authentication, RBAC, a user-attributed audit log of message
  views/replays, and **encryption-at-rest** for message bodies (AES-256-GCM) are **built**; log
  redaction and MLLPS/TLS are on the roadmap. See [docs/PHI.md](docs/PHI.md) for the built-vs-planned
  data-protection map.

## Roadmap

**Phase 1 — minimum reliable engine**
- [x] Connection/Router/Handler model + config-module loader
- [x] Durable message store / queue (SQLite WAL, outbox pattern)
- [x] Parse / validate (tolerant peek + opt-in strict validation)
- [x] MLLP source + destination (correct `0x0B … 0x1C 0x0D` framing, ACK/NACK)
- [x] File source + destination
- [x] Pipeline: source → parse/validate/filter/transform → outbox → per-dest workers,
      with retry/backoff, dead-letter, and replay
- [x] localhost API (connections start/stop, message track/search/detail, replay, stats,
      live WebSocket feed) + `python -m messagefoundry serve`
- [x] PySide6 console: connection dashboard, message browser, HL7 parse-tree viewer,
      delivery/audit trail, replay (`python -m messagefoundry.console`)

**Phase 1 complete.**

**Since Phase 1 — now built**
- [x] Staged pipeline (ingress → routed → outbound): at-least-once handoff, dead-letter, replay
- [x] Authentication, RBAC, user-attributed audit log, at-rest body encryption (AES-256-GCM)
- [x] **PostgreSQL** store backend (production, single-node)
- [x] **Microsoft SQL Server** store backend (production, single-node)
- [x] REST, SOAP, and Database destinations
- [x] Database poll source
- [x] Reference / lookup tables (`code_set`) for enrichment
- [x] Alerting — logging sink + webhook/email notifier
- [x] Connections-as-data (`connections.toml`) editable by hand or a VS Code GUI
- [x] **Active-passive high availability** — self-fencing leadership lease, leader-gated graph, and a
      failover-load test harness (kill-the-primary-under-load), on **both** PostgreSQL and SQL Server
- [x] **Native transport TLS** — in-process API TLS (HTTPS/WSS) and MLLP-over-TLS, with an off-loopback
      bind guard and a certificate-expiry monitor
- [x] Published throughput + active-passive failover **baseline** ([docs/benchmarks/TUNING-BASELINE.md](docs/benchmarks/TUNING-BASELINE.md))
- [x] **SMART Backend Services token provider** — OAuth2 `client_credentials` + signed-JWT
      `client_assertion` (RS384/ES384) authenticating the FHIR/REST outbound against real SMART-secured
      servers (Epic, Oracle Health); a `with_smart_backend()` composer over `FHIR()`/`Rest()` that mints,
      caches, and re-mints (on 401) a short-lived bearer, token endpoint gated by `[egress].allowed_http`
      ([ADR 0024](docs/adr/0024-smart-backend-services-token-provider.md))
- [x] **base64 binary-carriage codec** — an `mfb64:v1:` marker carries arbitrary NUL-safe **bytes** over
      the str/TEXT ingress + store (`RawMessage.from_bytes()`/`.raw_bytes`/`.binary()`/`.is_binary`), plus
      HL7 OBX-5 ED (Encapsulated Data) embedding helpers ([ADR 0028](docs/adr/0028-base64-binary-carriage-codec.md))
- [x] **DICOM codec + C-STORE SCP** (Phase 1) — a pure codec (routing peek, headers/Structured Report,
      code-first SR→HL7 mapping helpers; **headers + SR only, no pixel data**) on `content_type=dicom`
      payload-agnostic ingress, plus an inbound C-STORE SCP listener (`DICOM()`) ([ADR 0025](docs/adr/0025-dicom-codec-store-connectors.md))
- [x] **Anonymizer / de-identification** — builds PHI-free test datasets from real traffic with
      deterministic secret-per-dataset pseudonymization, field-anchored site-code scrub, and fail-closed
      emission (never an un-scrubbed body), via a `tee anonymize-captures` subcommand and test-harness
      hooks ([ADR 0030](docs/adr/0030-anonymization-test-harness-tee.md))

**Later** — higher-throughput delivery (a pooled/persistent MLLP connector); a read-only **component
SDK** (fork-to-customize); DICOM Phase 2 (C-STORE SCU + C-ECHO + DICOMweb STOW-RS, designed); MFA and
off-box log shipping. See [docs/EARLY-ADOPTER-GUIDE.md](docs/EARLY-ADOPTER-GUIDE.md) §2 for the current
built-vs-experimental map.

Horizontal **active-active** scale-out (the multi-node cluster path) was **dropped on 2026-06-18 and
its code removed** — it is not a planned milestone; single-leader **active-passive** HA (above) is the
supported HA model.

## Installing & rolling out

**The recommended way to deploy MessageFoundry is to install the published package from
[PyPI](https://pypi.org/project/messagefoundry/)** — a signed, version-pinned wheel is the
supported production artifact, with no source checkout required. Install it as a **pinned
dependency**, then scaffold your own config repo ([ADR 0017](docs/adr/0017-consumer-deployment-model.md)):

```bash
pip install "messagefoundry==0.1.0"   # pin the exact engine version (core runtime, SQLite store)
messagefoundry init ./my-config-repo     # scaffold a standalone config repo
cd ./my-config-repo
messagefoundry serve --config config --env dev
```

`0.1.0` is the current **Early Access** release on PyPI. Always **pin the exact version** so
upgrades stay deliberate. Add the extras your deployment needs (each is opt-in and lazy-imported):

```bash
pip install "messagefoundry[postgres]==0.1.0"    # PostgreSQL store backend (production server DB)
pip install "messagefoundry[sqlserver]==0.1.0"   # SQL Server store backend (+ OS-level ODBC Driver 18)
pip install "messagefoundry[console]==0.1.0"     # PySide6 admin console
pip install "messagefoundry[sftp]==0.1.0"        # SFTP transport for the REMOTEFILE connector
pip install "messagefoundry[dicom]==0.1.0"       # DICOM codec + C-STORE SCP (pydicom + pynetdicom)
```

> **Verify before you install (supply chain).** Every release is built by a GitHub Actions workflow,
> Sigstore-signed, and carries SLSA build-provenance + PEP 740 attestations. Verify a downloaded
> wheel against its source commit with
> `gh attestation verify <wheel> --repo MEFORORG/MessageFoundry`, or pull the signed wheel + SBOM
> from the [GitHub Release assets](https://github.com/MEFORORG/MessageFoundry/releases). For an
> air-gapped site, mirror the wheel to a private index.
>
> *(Engine developers install from a checkout instead — see [Development](#development).)*

Piloting MessageFoundry? The **[Early-Adopter Installation & Rollout Guide](docs/EARLY-ADOPTER-GUIDE.md)**
takes you from first install through a staged, go/no-go-gated path to full production
(Lab → Shadow/Parallel → Limited → Full). It leads with an honest built-vs-experimental
maturity map and covers prerequisites, install, security/PHI hardening, reliability
configuration, validation, load testing, backup/DR, day-2 operations, and upgrade/rollback.

## Development

**Working on the engine itself?** Install from a source checkout — **editable**, with the dev tools.
(This is the contributor path; deployments install the pinned wheel, [above](#installing--rolling-out).)

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Run the engine + localhost API (loads the bundled sample config, which ships only in a checkout):

```bash
python -m messagefoundry serve --config samples/config --db messagefoundry.db --env dev
# API on http://127.0.0.1:8765 — GET /connections, /messages, /stats, WS /ws/stats
```

Then open the admin console (needs the `console` extra: `pip install -e ".[console]"`):

```bash
python -m messagefoundry.console --url http://127.0.0.1:8765
```

### VS Code extension & test harness

- **VS Code extension** ([`ide/`](ide/)) — author and test interfaces in your editor: a New Route
  Wizard, validate-on-save, a Test Bench (dry-run `.hl7` files with before/after diffs), Stage →
  Promote to a running engine, and an HL7-aware `@messagefoundry` chat participant. Open the `ide/`
  folder in VS Code and press **F5**, or see [ide/README.md](ide/README.md).
- **Test harness** — a standalone PySide6 send/receive MLLP tool for exercising the engine with
  synthetic, PHI-free traffic: `python -m harness`.

## License

MessageFoundry is licensed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`) — see [LICENSE](LICENSE). Running a modified version as a network service
triggers the AGPL's §13 source-offer obligation. A separately-licensed commercial edition is planned
by **MessageFoundry Organization** under the standard open-core model — see
[COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md) (terms pending legal review). See [NOTICE](NOTICE)
for copyright and attribution.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md), our
[Code of Conduct](CODE_OF_CONDUCT.md), and how the project is governed in [GOVERNANCE.md](GOVERNANCE.md).
A signed [Contributor License Agreement](CLA.md) is required before a pull request can be merged.
