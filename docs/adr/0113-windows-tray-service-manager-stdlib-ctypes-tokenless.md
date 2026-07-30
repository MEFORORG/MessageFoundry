# ADR 0113 — Windows tray service-manager: stdlib ctypes, tokenless

- **Status:** Accepted (2026-07-16) — owner-directed this session ("go"); owner chose the **no-Qt
  stdlib-ctypes** spine over a PySide6 tray (below) and accepted the §6 CLAUDE.md §10 clarification. Build
  authorized; phased (one coherent commit per layer), pushes/PR owner-approved.
- **Deciders:** owner (explicit toolkit choice: "No-Qt ctypes spine") + a 25-agent research→design→judge→verify
  workflow (three competing designs scored by a governance / correctness / security judge panel; the no-Qt
  design won 251–242, the count-showing signed-in design was eliminated).
- **Related:** BACKLOG [#239](../BACKLOG.md); [#103](../BACKLOG.md) (retired the PySide6 desktop console —
  and named "a tiny standalone tray/service-manager" as the sanctioned home for out-of-band service control);
  [ADR 0032](0032-console-desktop-launch.md) (retired); [ADR 0065](0065-web-ops-dashboard.md)
  (the web console is the sole operator UI); [ADR 0088](0088-apiclient-service-cli-extraction.md) (Qt-free/FastAPI-free
  engine client; service control is inherently out-of-band); [ADR 0110](0110-ide-engine-link-doctor-the-status-bar-tells-the-truth-about-the-promote-target.md)
  / [ADR 0112](0112-ide-engine-lifecycle-from-the-status-bar-pill-guarded-start-stop-restart.md) (the IDE pill —
  tokenless poll, the earned/decaying green, the LINK-not-WORKLOAD boundary, the frozen `ENGINE_LINK_FIELDS`
  allowlist — all mirrored here); **CLAUDE.md §10**.

---

## Context

Operators run the engine as an **NSSM Windows service** ([`docs/SERVICE.md`](../SERVICE.md)). On the host box
they want three things the browser console cannot give them: engine status **at a glance** without opening a
tab; a **one-click** hop to the console (`/ui`), the repo (VS Code), and the log; and **start / stop / restart**
of the service. The last is structurally impossible from the web console — stopping the service kills the very
API the console talks to. [ADR 0088](0088-apiclient-service-cli-extraction.md) records this: *"the engine cannot control its
own hosting service through the API,"* so it is *"inherently an out-of-band, local operation."* The API therefore
ships `GET /service/status` **read-only** and **no** start/stop/restart (verified: `settings.py` comments the cut —
*"start/stop/restart is cut — the engine can't restart its own host over the API"*).

The governing constraint is **CLAUDE.md §10**, quoted verbatim:

> The **operator console is the web console** (`messagefoundry_webconsole`, served same-origin at `/ui`; ADR
> 0065) — the **PySide6 desktop console was retired** (BACKLOG #103, ADR 0032 retired). Do **not** add new
> PySide6 operator surfaces. **PySide6** (LGPL …) now backs only the **standalone test harness** …

Two facts make a tray the *completion* of that rule, not a breach of it:

1. **BACKLOG #103** — the very item that retired the desktop console — names the sanctioned home for
   browser-impossible service control as *"the CLI … **or a tiny standalone tray/service-manager**."* A tray that
   controls the service is the thing #103 explicitly left room for.
2. This design uses **no PySide6 — no Qt at all** — so §10's letter ("new PySide6 operator surfaces") is never
   triggered. The owner chose this spine precisely so the tray needs an ADR **ratification**, not a §10
   amendment.

The **spirit** of §10 ("one operator console") is held by construction: the tray authenticates **never**, holds
**no token**, and displays **no** message body, queue depth, connection row, or throughput number. Its only two
inputs are the **tokenless** `GET /health` and the **local SCM** service state — everything operational
deep-links to `/ui`. This is the tray analogue of the IDE's frozen `ENGINE_LINK_FIELDS` doctrine (ADR
0110 §4 / ADR 0112 §5): the boundary is enforced by *having no credentials at all*.

Verified during design (workflow adversarial pass, cited in BACKLOG #239):
`GET /health` is tokenless, returns `200 {"status":"ok","version":null}`, and is **un-rate-limited**; the
`apiclient` HTTP path pulls **only httpx** (no Qt/FastAPI), so a `[tray]` extra adds **zero** new locked
packages; a tokenless `GET /ui` returns **404** when `[api].serve_ui` is off (the default) and **303 →
`/ui/login`** when on (drives menu-item enablement); NSSM 2.24 stores the engine host/port (`AppParameters`) and
repo root (`AppDirectory`) under a registry key **readable unelevated**; and a UAC-cancelled `ShellExecuteExW`
runas returns **FALSE** with `GetLastError() == ERROR_CANCELLED (1223)`, distinguishable from other failures.

## Decision

Ship a **new top-level package `tray/`** (sibling to `harness/`; launched `pythonw -m tray`) — a Windows
notification-area app built on **stdlib `ctypes`** (`Shell_NotifyIcon` + an owned message pump) and the sanctioned
**`messagefoundry.apiclient`**, with **no GUI-toolkit dependency**. It shows engine status as an icon + tooltip,
opens `/ui` / VS Code / the service log, and start/stop/restarts the NSSM service via **per-action UAC
elevation**. What it must **not** become: a second operator console, a credential holder, or a surface that
renders workload data.

### 1. Placement & import contract

> **Superseded by the 2026-07-17 wheel-packaging amendment (below):** the package now ships **inside** the
> `messagefoundry` wheel as `messagefoundry.tray` (launched `messagefoundry-tray` / `pythonw -m
> messagefoundry.tray`), available on every install. The original placement (below) and its rationale are
> kept for the record; the **import rules are unchanged** and still binding.

`tray/` lives at the repo root, not in `messagefoundry/` (the engine stays GUI-free) and not as a second
published wheel (the `harness/` precedent: top-level package + optional extra, checkout-only distribution —
which is exactly the tray's audience, since an NSSM install *is* a repo + `.venv`). Import rules:

- **May import** `messagefoundry.apiclient` (the only engine contact) and the two **neutral, stdlib-only**
  service modules — `messagefoundry.service_status` (read: `is_safe_service_name`, `query_service_state`) and
  `messagefoundry.service` (the elevated `control_service`). This ADR **ratifies** those two modules as
  client-importable; neither pulls `pipeline`/`store`/`transports`/`config`/`api` or Qt/FastAPI.
- **Must never import** `pipeline/ store/ transports/ config/ api/` (beyond the Pydantic models `apiclient`
  already returns), PySide6, or FastAPI.

### 2. The not-a-console boundary (frozen contract)

The tray reads **only** `GET /health` (tokenless) and **local SCM** state. **Adding any authenticated API call,
or any message / queue / connection / count / rate field, requires a new ADR.** A CI test freezes this: the
tray's status-snapshot dataclass is asserted to carry **no** such field (mirroring the IDE's `ENGINE_LINK_FIELDS`
allowlist), and a test asserts `GET /health` answers `200` with **no** `Authorization` header so a future
auth-hardening change cannot silently break every deployed tray.

### 3. Status model — two credential-free probes, one pure state machine

- **SCM state (unelevated):** direct ctypes `QueryServiceStatusEx` → `currentState` + `dwCheckPoint` /
  `dwWaitHint` (true stuck-pending detection). An interactively-logged-on standard user holds
  `SERVICE_QUERY_STATUS` via the **Interactive SID** with no setup (the tray targets an interactive desktop).
  Async `service_status.query_service_state` is a documented fallback (noted locale-sensitive → ctypes is
  primary).
- **Liveness:** `EngineClient(url, timeout=2).health()` — tokenless.

The pure reducer `(scm, checkpoint_progress, health, ui_probe, now) → TrayState` yields:
`NOT_INSTALLED · STOPPED · STARTING · RUNNING · RUNNING_UNMANAGED` (a dev `serve` on the port, not the service)
`· STOPPING · WEDGED` (service RUNNING but /health dead past a boot grace) `· FOREIGN` (a non-MessageFoundry
responder on the port) `· UNKNOWN` (SCM unavailable). Grace / deadline windows use a **monotonic** clock
(laptop-resume safe) keyed to *when SCM entered RUNNING* (so a normal boot / NSSM auto-restart does not flash
"API not responding"). Poll 5 s; tighten to `clamp(dwWaitHint/10, 1 s, 10 s)` while pending. Rendering: pre-baked
`.ico` variants per state × light/dark taskbar, theme read from `SystemUsesLightTheme` (the documented
not-`AppsUseLightTheme` trap) with live `WM_SETTINGCHANGE` flips and a High-Contrast treatment. Transitions emit
**rate-limited**, transition-only toasts (an NSSM crash-loop cannot spam).

### 4. Service control & elevation — no new privileged code, System32-only, outcome-aware

The read path is **always unelevated**. Start / Stop / Restart **reuse the shipped, injection-hardened
`messagefoundry.service.control_service`** — which runs `net start/stop` (a **System32** binary; restart =
`net stop "X" & net start "X"` under **one** elevated `cmd.exe /c`, a single UAC prompt) with the service name
validated by `_is_safe_service_name`. So the tray writes **no new privileged code**, and the only thing elevated
is a signed System32 binary — never the user-writable venv interpreter or checkout (the security ding every judge
raised against a self-elevating `pythonw -m tray`).

Outcome-awareness ships as an **additive sibling** `control_service_ex(action, name) -> ServiceControlOutcome`
(rather than mutating `control_service`, whose one production caller — the `messagefoundry service` CLI — and
its tests keep their exact fire-and-forget `bool` contract). The sibling elevates the **same** System32-only
command via `ShellExecuteExW` + `SEE_MASK_NOCLOSEPROCESS`, treats `FALSE` + `GetLastError()==ERROR_CANCELLED
(1223)` as a distinct **CANCELLED** outcome, and otherwise waits on the child and reads `GetExitCodeProcess`
(DISPATCHED vs FAILED); off Windows it returns UNSUPPORTED. No standing service-ACL grant is added on a
PHI-carrying engine (a `sc sdset` operators-group
installer flag is recorded below as the sanctioned future opt-in if per-click prompt fatigue is real). Stop /
Restart require a confirm dialog ("halts message flow"). **Exit quits the tray only** — there is no code path
from Exit to service control.

### 5. Discovery, actions, lifecycle

Config in `%LOCALAPPDATA%\MessageFoundry\tray.toml` (`tomllib`, read-only); defaults `http://127.0.0.1:8765`
and service `MessageFoundry`, with `repo_path` / URL cross-checked from the world-readable NSSM registry keys
(treated as **untrusted data** — validated, never executed). **Scope is the local single box**: if `engine_url`
is remote the tray degrades to **monitor-only** (service control + Open-Repo disabled) — *amended 2026-07-22;
this originally read "remote/https", see the amendment below*. Multi-shard /
`supervise` is **unsupported-and-detected**. Open Console = `os.startfile(url + "/ui")`, gated by the /ui probe;
Open Repo = the resolved `code` CLI on `repo_path`; both disable cleanly when unavailable. Launch / autostart pin
the **absolute repo-venv `pythonw.exe`** (the real risk is the *wrong interpreter*, not cwd — the editable
install exposes the repo root on `sys.path`), self-healing a stale Run-key value; autostart is **opt-in**. Single
instance via a `Local\` mutex; `NIM_DELETE` in `finally` and on `WM_ENDSESSION`; a top-level crash handler that
logs, removes the icon, and exits nonzero; `TaskbarCreated` re-add.

### 6. §10 clarification (owner to accept or strike)

Add one sentence to CLAUDE.md §10: *"A non-Qt tray service-manager per ADR 0113 (tokenless `/health` + SCM state
only, no workload data) is not a barred operator surface."* This makes the boundary explicit in the doc that
readers hit first.

## Acceptance Criteria

- **AC-1** — WHILE the engine service is stopped and nothing answers `/health`, THE SYSTEM SHALL render `STOPPED`;
  WHILE SCM reports RUNNING but `/health` fails past the boot grace, it SHALL render `WEDGED`; WHILE a
  non-MessageFoundry responder answers the port, it SHALL render `FOREIGN`. → `tests/test_tray_state.py` ✅
- **AC-2** — THE SYSTEM SHALL poll only tokenless `GET /health` and local SCM; it SHALL make no authenticated API
  call and its status snapshot SHALL carry no message/queue/connection/count/rate field. →
  `tests/test_tray_boundary.py` (snapshot-field allowlist) ✅ + `tests/test_api_health_tokenless.py`
  (`/health` 200 with no `Authorization`, stays open while `require()` routes 503) ✅.
- **AC-3** — WHEN the operator invokes Start/Stop/Restart, THE SYSTEM SHALL elevate only a **System32** binary
  (`cmd`/`net`) with a regex-validated service name, never the venv interpreter or checkout code. →
  `tests/test_service_control_outcome.py` (elevated command shape + guard ordering) ✅ + `tests/test_tray_control.py`
  (confirm/outcome wrapper) ✅.
- **AC-4** — IF the operator cancels the UAC prompt, THEN THE SYSTEM SHALL report a distinct **cancelled** outcome
  (`ERROR_CANCELLED` 1223), make no state change, and log it — never a crash or a false "done". →
  `tests/test_service_control_outcome.py` (outcome passthrough) ✅; real-UAC cancel on the manual QA matrix.
- **AC-5** — WHEN `[api].serve_ui` is off (tokenless `/ui` → 404), THE SYSTEM SHALL disable "Open Monitor Console"
  with an explanatory caption; WHEN on (`/ui` → 303 `/ui/login`), it SHALL enable it. → `tests/test_tray_menu.py`
  (console-enabled → menu-enable) ✅ + the `/ui` probe (Phase 4).
- **AC-6** — WHEN the operator selects Exit, THE SYSTEM SHALL remove the icon and quit the tray only, never
  touching the engine service. → `tests/test_tray_menu.py` (no Exit→control action id) ✅.
- **AC-7** — WHERE `engine_url` names a **remote** host, THE SYSTEM SHALL degrade to monitor-only (service control
  and Open-Repo disabled); WHERE it names a **loopback** host, the tray SHALL stay fully managed **whether the
  scheme is `http` or `https`**. → `tests/test_tray_config.py` (scope gating) ✅
  *(Amended 2026-07-22 — the original AC read "remote/https", which greyed out service control on a
  TLS-hardened loopback engine. See the amendment below.)*.

## Options considered

1. **No-Qt stdlib `ctypes` + `apiclient`, tokenless** — **CHOSEN** (owner). Does not trigger §10 (no PySide6);
   best status fidelity (`dwCheckPoint`/`dwWaitHint`); `[tray]` extra adds zero locked packages; pure state
   machine + menu builder are fully headless-testable. Cost: an owned ~400-line Win32 message pump (a **pywin32**
   swap is the pre-planned escape hatch if it misbehaves). Won the judge panel (governance 86 / correctness 87 /
   security 78).
2. **Reuse-first PySide6 `QSystemTrayIcon`** — Rejected (owner). Lowest build risk (Qt owns the pump / DPI /
   `TaskbarCreated`; reuses harness poller patterns; zero new deps since `psutil` is core), but it **is** a
   PySide6 operator surface — it would **require amending §10** via the #26-precedent carve-out. The owner chose
   to keep §10 intact. Held as the fallback if the ctypes pump proves too costly.
3. **UX-polish PySide6 with an opt-in signed-in plane** — Rejected. Best UX on paper, but it holds a **bearer
   token on a 30 s timer** (CWE-613, the exact anti-pattern the IDE's CI-frozen `POLL_PLAN` forbids) and
   displays **queue / dead-letter counts** — crossing the ADR 0065 console boundary. Needs the broadest waiver
   of the three; eliminated on rule + security grounds (panel 62–68).
4. **pystray / infi.systray** — Rejected: pystray is dormant (no 3.14 classifiers, drags in Pillow) and still
   would not expose the pump hooks the UX needs; infi.systray has static menus.
5. **Standing service-ACL grant (`sc sdset` operators group)** — Rejected for v1: a standing grant to interactive
   users of start/stop on a PHI-carrying interface engine is a documented persistence/LPE surface. Recorded as
   the sanctioned escalation if prompt fatigue becomes real; per-action UAC ties every stop to a live admin token
   and the OS audit trail.

## Consequences

**Positive** — Operators get at-a-glance status + one-click console/VS Code/log/service-control on the box, with
§10 **untouched** (ratification, not amendment). PHI-free and credential-free **by construction**. No new
privileged code — the one elevated path is the shared, hardened, now outcome-aware `control_service` (a fix that
also benefits its existing callers). Zero new locked dependencies.

**Negative / risks** — An owned Win32 message pump is the classic home of subtle ghost-icon / menu-dismissal
bugs (mitigations: documented decades-stable patterns; a manual QA matrix; the pywin32 escape hatch). Per-action
UAC prompts can fatigue NOC users (mitigation: the recorded `sc sdset` opt-in). A wrong `engine_url` renders as
`WEDGED` (self-diagnosing via the registry `AppParameters` cross-check logged as a hint). `mypy --strict` over
ctypes prototypes is real work (typed `WINFUNCTYPE` signatures + `sys.platform` guards keep non-Windows legs
green).

**Out of scope** — Multi-shard / `supervise` rollups; remote engines (monitor-only degrade — *amended 2026-07-22:
a **local TLS** engine is now in scope and fully managed*); a flyout window;
any authenticated call, WebSocket, or workload data; a packaged (wheel/installer) tray; toast AUMID registration.

## To resolve on acceptance

- [x] Owner accepts the CLAUDE.md §10 clarification sentence (§6) — **accepted 2026-07-16**, added to §10.
- [x] Preserve every current caller's boolean contract — **done (Phase 5)**: outcome-awareness ships as the
      additive `control_service_ex`; `control_service` (its sole caller, the CLI, + its tests) is byte-for-byte
      unchanged. One caller enumerated: `__main__.py` `service start/stop`.
- [x] Restart stays a **single** UAC prompt — **done**: `control_service_ex` elevates the same `net stop "X" &
      net start "X"` chain under one `cmd /c`; the child-wait reads that chained process's exit code. Real-UAC
      confirmation is on the manual QA matrix (ADR §11).
- [x] Ratify the `messagefoundry.service` / `service_status` client-import carve-out — **done 2026-07-16** in
      CLAUDE.md §4 (a second, narrow carve-out mirroring `parsing/`).

## Amendment (2026-07-17) — branded launcher + settings template (post-QA follow-ups)

Two owner-reported findings from the manual QA pass, built + verified live on a Windows 11 box:

**1. The tray was listed as "Python" in Settings → Taskbar → Other system tray icons.** Windows keys
that list on the process **executable's** version `FileDescription` (verified against the live
`HKCU\Control Panel\NotifyIconSettings` entries, which record `ExecutablePath`), not the tooltip.
Launched as `pythonw -m tray`, the image is Python's `pythonw.exe` → "Python". **Decision:** `tray/branding.py`
creates `MessageFoundryTray.exe` in the venv `Scripts\` — a copy of the **base** interpreter's `pythonw.exe`
(NOT the venv's, which is a redirector stub that spawns the base interpreter as a child that would own the
icon) with its top-level runtime DLLs staged beside it (`python3XX.dll` et al., ~7 MB, since a standalone
interpreter's runtime is app-local) and its `RT_VERSION` resource rewritten (a fresh `VS_VERSIONINFO` built in
pure stdlib) to `FileDescription="MessageFoundry Tray"`. `tray.__main__` re-execs through it (before the mutex),
so the process image — and thus the Settings name — is the branded exe. Autostart still pins plain `pythonw`
and lets the runtime re-exec apply branding, so it never depends on the derived exe surviving between logins.
**Entirely fail-soft:** any failure (AV block, read-only dir, resource-API error, a base interpreter without
app-local DLLs) → the tray runs unbranded (listed as "Python"), nothing else changes. Verified live: Windows'
own version API reads the branded `FileDescription` back; the branded exe runs **in-process** with the venv
active; and after a real launch the `NotifyIconSettings` entry records `ExecutablePath = MessageFoundryTray.exe`.
Adversarially reviewed (a 4-dimension workflow: 9 confirmed findings fixed — fail-soft breadth, version-string
overflow/pre-release parsing, relaunch child-death fallback, log-handler overlap).

**2. "Open Repo in VS Code" opened the engine repo, not the operator's estate.** `repo_path` in `tray.toml`
already controls this, but with no file present it fell back to the service's NSSM `AppDirectory` (the engine
checkout), and the setting wasn't discoverable. **Decision:** "Edit Tray Settings" now writes a commented,
self-documenting `tray.toml` template (`ensure_tray_toml`) on first use, with `repo_path` explained, then opens
it — no behaviour change beyond discoverability (all keys stay commented/inert until the operator sets one).

Neither touches the §2 not-a-console boundary, the elevation model, or any dependency (branding is stdlib
ctypes; the template is a static string). Out of scope stays out: still no packaged/PyInstaller exe — the
branded launcher is a copy of the interpreter already present, created at runtime.

## Amendment (2026-07-17) — ship the tray in the wheel (`messagefoundry.tray`), reversing §1's placement

Owner request: *"I want this installed as part of the wheel. I want it to be available on any system that is
going to run mefor."* The original §1 kept `tray/` at the repo root, checkout-only (the `harness/` precedent).
That is exactly wrong for **this** component's audience: the tray runs on the box where the engine runs, and an
engine box may be a `pip install messagefoundry` + NSSM service with **no repo checkout** at all. Keeping it
outside the wheel meant the operator tool wasn't present where the operator is.

**Decision.** The tray moves `tray/` → **`messagefoundry/tray/`** and ships inside the one published wheel:

- **Entry point** `[project.gui-scripts]` `messagefoundry-tray = "messagefoundry.tray.__main__:main"` — a *GUI*
  script (a `pythonw.exe` launcher, no console window, right for a background tray). Equivalent invocation:
  `pythonw -m messagefoundry.tray`. Both re-exec through the branded launcher exactly as before.
- **Dependencies.** `httpx` + `truststore` (the tray's only third-party needs, via the shared
  `messagefoundry.apiclient`) move from the `[harness]`/`[dev]`/(removed) `[tray]` extras into the **base**
  `dependencies`, so a bare `pip install messagefoundry` yields a working tray. They were already in the locked
  set via those extras, so `requirements.lock` (all-extras) is byte-unchanged; the two `docker/locks/` **core**
  locks gain httpx/truststore + transitive (certifi/httpcore). The `[tray]` extra is **removed** (it would now
  add nothing). The `harness/` package stays at the repo root (its audience genuinely *is* checkout-only, and it
  drags PySide6 — kept an extra).
- **Assets.** The status `.ico` set ships automatically: hatchling packages every file under the
  `messagefoundry/` package, data included (a build-guard test already depends on this for the auth corpus).
- **The import contract (§1) is unchanged and still binding.** The tray imports only `messagefoundry.apiclient`
  + the two neutral service modules; it imports no `pipeline`/`store`/`transports`/`config`/`api`, no PySide6,
  no FastAPI. It is **not** an "engine package" under CLAUDE.md §4's one-way rule (that rule names
  `pipeline/transports/parsing/store/config`), and the dependency-boundary test is unaffected. The engine stays
  GUI-free: the tray is Qt-free stdlib ctypes, and `messagefoundry/__init__` does not import it, so importing the
  engine never pulls the tray (or httpx) in.
- **CI.** `messagefoundry/tray` is win32-only ctypes, so the Linux mypy leg **excludes** it
  (`--exclude 'messagefoundry/tray/'`) while the `--platform win32` leg types it (now covered by the plain
  `messagefoundry` argument). Ruff drops the standalone `tray` path (now inside `messagefoundry`).

Out of scope is unchanged: still no PyInstaller/frozen exe; the branded launcher is still a runtime copy of the
already-present interpreter. The §2 boundary, status model, and elevation model are all untouched.

## Amendment (2026-07-22) — a **local TLS** engine is fully managed: scheme is not locality

**The bug.** `[api].tls_cert_file` makes the engine terminate TLS in uvicorn on the *same* bind (WP-13a,
[ADR 0002](0002-phase2-transport-security-and-strong-auth.md)) — including the default `127.0.0.1` one. The tray's scope test read
`monitor_only = not is_local_http(engine_url)`, and `is_local_http` required `scheme == "http"` **and** a loopback
host. So the moment an operator hardened the loopback API with TLS, the tray:

1. probed `http://127.0.0.1:8765` (its `build_engine_url` hardcoded `f"http://{host}:{port}"`, so NSSM discovery
   could never yield an https URL), got nothing, and rendered a healthy engine as `STOPPED`/`WEDGED`; and
2. even with `engine_url` hand-set to https in `tray.toml`, greyed out Start/Stop/Restart and Open-Repo, because
   `https` alone tripped the "remote" degrade.

The tray therefore **punished the safer configuration**, and the original AC-7 ("remote/https") wrote that
conflation into the contract. `probe.py` compounded it: a bare `httpx.Client` with no `verify=`, i.e. certifi-only
trust, which cannot verify an internal-CA or operator-installed engine cert.

**Decision — separate the two concepts.**

- `is_local_http` → **`is_local_engine`**, true for a loopback host on `http` **or** `https`; `monitor_only` keys
  on that alone. Locality is what actually gates the degraded features (Start/Stop/Restart drive the *local* SCM;
  Open-Repo opens a *local* folder), and TLS-on-loopback changes neither. A remote host stays monitor-only
  regardless of scheme — unchanged, and still the reason the degrade exists.
- `build_engine_url(host, port, *, tls=...)` emits the scheme instead of hardcoding `http` (and brackets a bare
  IPv6 literal, so `serve --host ::1` no longer yields the unparseable `http://::1:8765`).
- **Discovery learns the scheme.** There is no `serve` TLS *flag* to sniff — TLS is configured in the engine's
  service-settings TOML — so `load_config` now also reads that file, resolved exactly as `serve` resolves it
  (`--service-config`, relative paths against NSSM `AppDirectory`; else `<AppDirectory>/messagefoundry.toml`), and
  takes **one boolean** from it: is `[api].tls_cert_file` set. Read-only, **fail-soft** (any missing/malformed
  file → "no TLS hint", never an exception into tray startup), and deliberately narrow — no hosts, paths, or
  secrets are lifted out of an operator file reached via an untrusted registry hint. An explicit `engine_url` in
  `tray.toml` carries its own scheme and still wins.
- **The probe verifies.** `make_probe_client` builds `verify=` from the URL: plain `True` for http (httpx ignores
  it there, and an http-only tray must not import `truststore` for nothing), and a **`truststore.SSLContext`** —
  the **OS trust store** — for https, mirroring `apiclient`'s default posture. On a domain-joined box an
  AD-CS/internal-CA engine cert verifies with no per-machine wrangling; a self-signed one verifies once the
  operator installs it under **Trusted Root Certification Authorities**. The tray is Windows-only, so that store
  *is* the supported pin.

**No `verify=False`, and no `cacert` knob.** A failed verification surfaces as an `httpx.HTTPError` → `DOWN` /
`UNKNOWN`, never a silent downgrade. A `--cacert`-style pin was **declined**: on the tray's only platform the
machine trust store already covers the self-signed case, and adding an insecure-escape-adjacent surface to a
component whose entire job is *"tell the truth about which server answered"* is the wrong trade. An AST-based
test freezes this (`verify=False` / `check_hostname=False` / `ssl.CERT_NONE` / any assignment to a context's
`verify_mode` are all rejected in `tray/probe.py`), so a future "just make my self-signed cert work" edit fails
the build.

**Boundary untouched.** Still tokenless `GET /health` + `GET /ui` and local SCM state; no `Authorization` header,
no new workload field, no new dependency (`truststore` has been a **base** dependency since the wheel-packaging
amendment above, precisely so "the tray/monitor need no per-PC CA wrangling"). `messagefoundry/tray/probe.py`
gains an `ssl` import and is registered in the ASVS 11.1.3 crypto inventory
(`scripts/security/crypto_inventory_check.py` + [`docs/ASVS-L2-PHASE0-CHANGES.md`](../ASVS-L2-PHASE0-CHANGES.md) §4).
**AC-7 is amended** (above) to state locality, not scheme.
