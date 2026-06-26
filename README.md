# MessageFoundry

[![CI](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml)
[![Security](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://github.com/MEFORORG/MessageFoundry/blob/main/LICENSE)
[![Python 3.14+](https://img.shields.io/badge/python-3.14%2B-blue.svg)](https://github.com/MEFORORG/MessageFoundry/blob/main/pyproject.toml)

MessageFoundry is an **open-source healthcare integration engine** — a modern, Python-native HL7
interface engine. It connects clinical and business systems by routing, transforming, and validating
messages across many formats (HL7 v2, JSON, XML/SOAP, X12, database records) and connection types
(MLLP, MLLP-over-TLS, TCP, HTTP/REST, SOAP, FHIR, DICOM, database, files, SFTP/FTP). Configure it with
guided tooling or extend it in Python; it runs on SQLite, PostgreSQL, or SQL Server with
authentication, RBAC, audit logging, and encryption-at-rest built in.

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

See **[docs/architecture-diagram.md](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/architecture-diagram.md)** for the rendered diagrams —
system topology, runtime message flow through the staged queue, and the config wiring graph (Mermaid,
renders on GitHub and in the VS Code preview). The prose source of truth is
[docs/ARCHITECTURE.md](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/ARCHITECTURE.md).

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
  views/replays, **encryption-at-rest** for message bodies (AES-256-GCM), **global PHI log redaction**,
  and **transport TLS** (HTTPS/WSS for the API plus MLLP-over-TLS) are **built**; MFA and off-box log
  shipping remain on the roadmap. See [docs/PHI.md](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/PHI.md) for the full data-protection map.

## Features

MessageFoundry ships a reliable, PHI-aware engine today: the Connection/Router/Handler graph
over a durable staged pipeline (at-least-once delivery, retries, dead-letter, replay), backed by
SQLite, PostgreSQL, or SQL Server. It speaks MLLP (plain and over TLS), file/SFTP, REST, SOAP,
FHIR, database, and DICOM (C-STORE SCP), parses HL7 v2 tolerantly (with opt-in strict validation)
and carries other formats payload-agnostically (JSON, XML/SOAP, X12, binary). Security is
first-class — authentication, RBAC, a user-attributed audit log, at-rest body encryption, and
transport TLS — and it runs single-node or in active-passive high availability.

**See the full, up-to-date feature breakdown — built vs. planned — at
[messagefoundry.org/features-table.html](https://messagefoundry.org/features-table.html).**

## Documentation

Full documentation lives on **[messagefoundry.org](https://messagefoundry.org/)**:

- **[Mental map](https://messagefoundry.org/assets/docs/MessageFoundry-Mental-Model.pdf)** — a one-page
  picture of how the pieces fit: Connections → Router → Handlers → Connections, with the headless
  engine and the console/IDE that drive it.
- **[Install Guide](https://messagefoundry.org/assets/docs/MessageFoundry-Install-Guide.pdf)** — install,
  configure, secure, and roll out to production.
- **[User Guide](https://messagefoundry.org/assets/docs/MessageFoundry-User-Guide.pdf)** — author and
  operate interfaces day to day.

**Get started:** [Quickstart](https://messagefoundry.org/getting-started.html) ·
[Guides](https://messagefoundry.org/guides/) ·
[Documents](https://messagefoundry.org/documents.html)

## Installing & rolling out

**The recommended way to deploy MessageFoundry is to install the published package from
[PyPI](https://pypi.org/project/messagefoundry/)** — a signed, version-pinned wheel is the
supported production artifact, with no source checkout required. Install it as a **pinned
dependency**, then scaffold your own config repo ([ADR 0017](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/adr/0017-consumer-deployment-model.md)):

```bash
pip install "messagefoundry==<version>"   # pin the exact engine version (core runtime, SQLite store)
messagefoundry init ./my-config-repo      # scaffold a standalone config repo
cd ./my-config-repo
messagefoundry serve --config config --env dev
```

MessageFoundry is in **Early Access**. Always **pin the exact version** so upgrades stay
deliberate — replace `<version>` with the current release shown at the top of the
[PyPI project page](https://pypi.org/project/messagefoundry/). Add the extras your deployment
needs (each is opt-in and lazy-imported):

```bash
pip install "messagefoundry[console]==<version>"     # admin console (PySide6 GUI) — the operator UI; most operators want this
pip install "messagefoundry[postgres]==<version>"    # PostgreSQL store backend (production server DB)
pip install "messagefoundry[sqlserver]==<version>"   # SQL Server store backend (+ OS-level ODBC Driver 18)
pip install "messagefoundry[sftp]==<version>"        # SFTP transport for the REMOTEFILE connector
pip install "messagefoundry[dicom]==<version>"       # DICOM codec + C-STORE SCP (pydicom + pynetdicom)
```

**What's in the `messagefoundry` package — and what isn't.** It is the **engine plus the admin
console**: the console ships in the same wheel, with its PySide6/GUI dependencies as the opt-in
`[console]` extra, so a headless server, container, or adopter install stays lean — the console is one
flag away (`messagefoundry[console]`) when you want the operator UI. The **VS Code extension is a
separate product, not on PyPI** (a VS Code extension is a different ecosystem); see *VS Code extension &
test harness* below for where to get it.

> **Verify before you install (supply chain).** Every release is built by a GitHub Actions workflow,
> Sigstore-signed, and carries SLSA build-provenance + PEP 740 attestations. Verify a downloaded
> wheel against its source commit with
> `gh attestation verify <wheel> --repo MEFORORG/MessageFoundry`, or pull the signed wheel + SBOM
> from the [GitHub Release assets](https://github.com/MEFORORG/MessageFoundry/releases). For an
> air-gapped site, mirror the wheel to a private index.
>
> *(Engine developers install from a checkout instead — see [Development](#development).)*

Piloting MessageFoundry? The **[Install Guide](https://messagefoundry.org/assets/docs/MessageFoundry-Install-Guide.pdf)**
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

- **VS Code extension** ([`ide/`](https://github.com/MEFORORG/MessageFoundry/tree/main/ide/)) — author and test interfaces in your editor: a New Route
  Wizard, validate-on-save, a Test Bench (dry-run `.hl7` files with before/after diffs), Stage →
  Promote to a running engine, and an HL7-aware `@messagefoundry` chat participant. **It is not on PyPI**
  (a VS Code extension is a different ecosystem) **and not yet on the VS Code Marketplace** — Marketplace
  + Open VSX publishing is **planned** (see [the backlog](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/BACKLOG.md)). Until then, get it from
  this repo: open the `ide/` folder in VS Code and press **F5** (Extension Development Host), or build the
  VSIX (`cd ide && npm install && npx @vscode/vsce package`) and install the `.vsix`. See
  [ide/README.md](https://github.com/MEFORORG/MessageFoundry/blob/main/ide/README.md).
- **Test harness** — synthetic-only send/receive (MLLP), load, and failover tooling for exercising a
  running engine. It ships as a **separate distribution, `messagefoundry-harness`**, released in lockstep
  with the engine (it is *not* in the engine wheel): `pip install messagefoundry-harness`, then
  `python -m harness`. From a checkout, run `python -m harness` directly. Synthetic, PHI-free traffic only.

## License

MessageFoundry is licensed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`) — see [LICENSE](https://github.com/MEFORORG/MessageFoundry/blob/main/LICENSE). Running a modified version as a network service
triggers the AGPL's §13 source-offer obligation. A separately-licensed commercial edition is planned
by **MessageFoundry Organization** under the standard open-core model — see
[COMMERCIAL-LICENSE.md](https://github.com/MEFORORG/MessageFoundry/blob/main/COMMERCIAL-LICENSE.md) (terms pending legal review). See [NOTICE](https://github.com/MEFORORG/MessageFoundry/blob/main/NOTICE)
for copyright and attribution.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](https://github.com/MEFORORG/MessageFoundry/blob/main/CONTRIBUTING.md), our
[Code of Conduct](https://github.com/MEFORORG/MessageFoundry/blob/main/CODE_OF_CONDUCT.md), and how the project is governed in [GOVERNANCE.md](https://github.com/MEFORORG/MessageFoundry/blob/main/GOVERNANCE.md).
A signed [Contributor License Agreement](https://github.com/MEFORORG/MessageFoundry/blob/main/CLA.md) is required before a pull request can be merged.
