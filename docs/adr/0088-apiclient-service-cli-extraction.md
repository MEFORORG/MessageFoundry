# 0088 — Extract a Qt-free `apiclient/` library + a `messagefoundry service` CLI

- **Status:** Accepted
- **Date:** 2026-07-10
- **Related:** [ADR 0032](0032-console-desktop-launch.md) · [CLAUDE.md §2 / §10](../../CLAUDE.md) · BACKLOG #103 · [MULTISESSION-PLAN-9](../releases/MULTISESSION-PLAN-9.md)

---

## Context

BACKLOG #103 ("retire the PySide6 desktop console") was scoped as a large cross-cutting refactor:
delete `console/`, extract a Qt-free client, rehome shared widgets to `harness/`, and move service
control to a CLI. The owner **narrowed** it: extract the **reusable core** (the engine client + the
Windows service control) but **keep** the console. The full retire (deleting `console/`, rehoming the
Qt widgets, dropping the `[console]` extra) remains **deferred**.

Two engine-adjacent pieces already lived under `console/` yet are wholly Qt-free:

- `console/client.py` — `EngineClient`, the synchronous typed wrapper over the localhost REST API.
  CLAUDE.md §10 records the boundary verbatim: the console *"may import the pure `parsing/` library …
  and `api/`'s Pydantic models"* and *"reaches the engine **only through the HTTP API client**"*. The
  headless load/acceptance **harness** already depends on this client (`harness/monitor.py`,
  `harness/load/…`, `harness/scenarios.py`), so a GUI-package home is a false coupling: a headless
  runner should not import from `console/`.
- `console/service_control.py` — Windows SCM control (`sc query` / elevated `net start|stop` /
  install). Stdlib-only; the engine cannot control its **own** hosting service through the API
  (stopping it kills the API), so this is inherently an out-of-band, local operation that belongs on
  the CLI, not only behind the GUI's Engine-Status page.

The client also underpins the CLAUDE.md §2 client/server split — *"The console never imports the
engine or touches the DB directly — it uses the API client."* Making that client a first-class,
independently-importable library strengthens the boundary rather than weakening it.

## Decision

Extract the reusable core; keep the console.

- **`messagefoundry/apiclient/`** is the canonical, **Qt-free and FastAPI-free** engine-client
  library. `apiclient/client.py` is the verbatim former `console/client.py` body (deps: `httpx` +
  the lazy `truststore`, plus the pure pydantic models in `api/models.py` / `api/auth_models.py`).
  `apiclient/__init__` re-exports `EngineClient` + `ApiError`. It is reusable by the console, the
  harness, and any future client.
- **`messagefoundry/service.py`** is the verbatim former `console/service_control.py` body
  (stdlib-only; keeps `CREATE_NO_WINDOW` and the `sys.platform != "win32"` guards so it type-checks on
  the Linux mypy leg). It is surfaced as `messagefoundry service {install,start,stop,status}`.
- `console/client.py` and `console/service_control.py` become **thin re-export shims** so every
  existing console import and widget keeps working with **no behaviour change**.
- The harness client imports repoint to `messagefoundry.apiclient`; the Qt-widget imports stay on
  `console/`.

**This is explicitly the reusable-core half of #103.** It does **not** supersede ADR 0032, does not
delete `console/`, does not rehome the Qt widgets to `harness/`, and does not retire the `[console]`
extra. #103 stays an honest partial. It must not break the CLAUDE.md client/server split (the engine
packages still never import PySide6/FastAPI) or the count-and-log / reliability invariants (no
pipeline code is touched).

## Acceptance Criteria

- **AC-1** — WHEN a fresh interpreter imports `messagefoundry.apiclient`, THE SYSTEM SHALL load
  neither `PySide6` nor `fastapi` (checked via `sys.modules` in a subprocess).
  → `tests/test_apiclient.py::test_import_pulls_in_no_pyside6_or_fastapi`
- **AC-2** — THE SYSTEM SHALL expose `EngineClient`/`ApiError` from `messagefoundry.apiclient` as the
  same objects the `messagefoundry.console.client` shim re-exports.
  → `tests/test_apiclient.py::test_public_surface_is_reexported`
- **AC-3** — WHEN `messagefoundry service {status,start,stop,install}` is invoked, THE SYSTEM SHALL
  dispatch to `messagefoundry.service`; IF `install` is given without `--env`, THEN it SHALL refuse
  (exit 2), never accept a partial install.
  → `tests/test_service_cli.py::test_service_status_dispatch` ·
  `tests/test_service_cli.py::test_service_install_requires_env`
- **AC-4** — THE SYSTEM SHALL keep the console's service-control shim working (state parse + guarded
  elevated actions) via `messagefoundry.service`.
  → `tests/test_service_control.py::test_parse_service_state`

## Options considered

1. **Extract `apiclient/` + `service.py`, keep `console/` as shims — CHOSEN.** Frees the reusable core
   from the GUI package, gives the harness an honest headless dependency, and adds the CLI, while the
   desktop console stays fully supported. Minimal blast radius: verbatim body moves + shims.
2. **Full #103 retire (delete `console/`, rehome widgets to `harness/`, drop `[console]`).** Rejected
   for now: owner keeps the desktop console; the parity-loss acceptance the full retire needs is not
   granted. Deferred, not cancelled.
3. **Leave the client under `console/` and let the harness keep importing it there.** Rejected: bakes
   a GUI-package dependency into headless runners and hides a genuinely reusable library inside the
   console.

## Consequences

**Positive** — A first-class Qt-free/FastAPI-free client library; the harness no longer imports from
`console/`; service control is scriptable (`messagefoundry service …`) without opening the GUI; the
client/server boundary is sharper. No new dependency; `[console]`, `[project.scripts]`, and
`[project.gui-scripts]` are unchanged.

**Negative / risks** — Two extra shim modules to maintain until the full retire; monkeypatch-based
unit tests that reached into module internals had to target the new home (`messagefoundry.apiclient.client`
/ `messagefoundry.service`) where name resolution actually happens.

**Out of scope** — Deleting `console/`, rehoming the Qt widgets, retiring the `[console]` extra
(the deferred remainder of #103); any behaviour change to the client or service control.
