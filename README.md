# MessageFoundry

[![CI](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/ci.yml)
[![Security](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml/badge.svg)](https://github.com/MEFORORG/MessageFoundry/actions/workflows/security.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](pyproject.toml)

A lightweight, open-source **HL7 v2 integration engine** for healthcare IT — message
validation, parsing, transformation, and routing — with a desktop admin console.

> Built with **hl7apy** + **python-hl7** (parsing/validation) and **PySide6**
> (admin console). Python import package: `messagefoundry`.

## What it is

A focused, reliable alternative to heavyweight engines for simple point-to-point
interfaces (ADT, ORU, SIU, DFT). Message flow is a **graph wired by name, authored as
Python**: an inbound **Connection** names a **Router**, which forwards to one or more
**Handlers** (filter → transform), which send to outbound Connections — all backed by
durable queuing, retries, and replay. There's no monolithic "channel" object bundling
the graph; the configuration *is* the graph, version-controlled as plain Python modules.

## Architecture (Phase 1)

**Engine-as-library + localhost API.** The engine is an importable Python package.
The PySide6 console talks to it over a localhost HTTP + WebSocket API — the same way
whether the engine runs in-process, as a local daemon, or (later) on a remote host.
No hand-rolled IPC; the deployment split is a config choice, not an architectural fork.

```
┌────────────────────┐      HTTP + WebSocket       ┌────────────────────┐
│  PySide6 console   │ ──────(localhost)─────────▶ │   engine runtime   │
│  (design / monitor)│                              │  (asyncio core)    │
└────────────────────┘                              └─────────┬──────────┘
                                                              │
                  config (Python modules, git-friendly)    ◀───┤
                  message store / queue (SQLite WAL) ◀─────────┘
```

### Key decisions
- **The message store *is* the queue.** Transactional inbox/outbox → at-least-once
  delivery, retries, and replay come for free. This is the reliability backbone.
- **Async core.** asyncio with per-connection workers for listeners, pollers, retries.
- **Tolerant parsing first.** `python-hl7` for fast routing/peek; `hl7apy` for deep,
  version-aware validation and profiles on demand (real-world HL7 is often non-conformant).
- **Config is code** — named **Connections** wired by **Router**/**Handler** Python scripts
  (`inbound`/`outbound`/`@router`/`@handler`), version-controlled. The DB holds runtime state
  and messages only — never config.
- **PHI is first-class.** Authentication, RBAC, a user-attributed audit log of message
  views/replays, and **encryption-at-rest** for message bodies (AES-256-GCM) are **built**; log
  redaction and MLLPS/TLS are on the roadmap. See [docs/PHI.md](docs/PHI.md) for the built-vs-planned
  data-protection map.

## Roadmap

**Phase 1 — minimum reliable engine**
- [x] Code-first Connection/Router/Handler model + config-module loader
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

**Phase 1 complete.** Next: see "Later" below.

**Later** — plugin layer, PostgreSQL, REST/FHIR destinations, DB poller, transformer
code steps (sandboxed), enrichment/lookup tables, alerting.

## Development

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

Run the engine + localhost API (loads the sample config):

```bash
python -m messagefoundry serve --config samples/config --db messagefoundry.db
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
triggers the AGPL's §13 source-offer obligation. A separately-licensed commercial edition may be
available from the maintainer.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). A signed
[Contributor License Agreement](CLA.md) is required before a pull request can be merged.
