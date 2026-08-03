[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 13. Tray App, Windows Service, Distribution & Test Harness

**ID prefix:** `TRAY` · **Surface:** four separable parts, tested and reported separately so the operator-facing GUIs do not compete with infrastructure packaging for attention —
**13a** the tray application (`messagefoundry/tray/`) · **13b** the Windows service (NSSM) · **13c** distribution & install (wheel, lock, container, k8s, upgrade/rollback) · **13d** the standalone PySide6 **test harness** GUI (`harness/`, shipped as the separate `messagefoundry-harness` wheel).
The matrix in §13.4 is split the same way (**13.4a**/**13.4b**/**13.4c**/**13.4d**) so the tray and the harness are read and signed off on their own, not buried among container/k8s packaging rows. The split is a *grouping* only — **no row was renumbered**; IDs are stable and remain in ascending order within each part.
· **Primary risk:** the tray's Win32/shell layer and the entire privileged install path (`scripts/service/*.ps1`) can both regress and merge green — the one CI leg that exercises NSSM is nightly **and** `github.repository == 'MEFORORG/MessageFoundry'`-gated (`.github/workflows/ci.yml:1087`), and the tray's Win32 half has no behavioural test on any platform.

**Cross-document ID prefixes.** Other documents use ID spaces that collide with this plan's, so every foreign ID here carries a prefix: **`FCP:`** = `docs/testing/FEATURE-COVERAGE-PLAN.md` (e.g. `FCP:DEPLOY-8`), **`W25:`** = the WIN2025 test plan/matrix (e.g. `W25:S2.5`, `W25:G1`), **`ACC:`** = the on-box acceptance matrix `harness/acceptance/matrix.py` (e.g. `ACC:A7`). A bare `TRAY-nn` always means a row of this chapter. One more foreign identifier appears below and is *not* a plan ID: **`SEC-003`** is the engine's own source-trust control (the config-dir write-permission refusal at service start), unrelated to this plan's SEC chapter rows.

**Row class (`Cls`) in §13.4.** **T** = *Test* — a falsifiable assertion with an observable pass criterion; **only T rows count toward the release gate**. **C** = *Characterisation* — produces a recorded measurement, finding or dated owner decision with no threshold yet; legitimate work, but it cannot fail, so it never gates a release, and it becomes a T row the day its threshold or decision is recorded. **A** = *Assurance* — an external engagement (pen test, third-party review, DAST); blocking only for an off-loopback / production-exposure release, advisory otherwise, and excluded from the ordinary P0 count.

### 13.1 Scope & objectives

**In scope — 13a, the tray (`messagefoundry/tray/`, ADR 0113 + its 2026-07-17 wheel-packaging and 2026-07-22 TLS-locality amendments):**
icon state rendering and light/dark iconset (`theme.py`, `iconset.py`, 18 `.ico` files under `messagefoundry/tray/assets/`), the pure 9-state reducer (`state.py:117-163`), the tokenless `GET /health` + `GET /ui` probes (`probe.py:88-103`), the unelevated ctypes SCM read (`winsvc.py:83-138` — the tray's *own* advapi32 path, distinct from the `sc.exe`-based `messagefoundry/service_status.py` that the CLI and `verify` use; TRAY-14's allowlist deliberately permits the latter), the context-menu builder and per-state enablement (`menu.py:71-149`), guarded elevation via `control_service_ex` (`control.py:46-48` → `messagefoundry/service.py:220-239`), the hand-rolled Win32 message pump (`winshell.py`), single-instance enforcement (`instance.py`), HKCU autostart (`autostart.py`), the branded `MessageFoundryTray.exe` launcher (`branding.py`), config/discovery (`config.py`), notifications (`state.py:184-199`, `poller.py:194-207`), the rotating `%LOCALAPPDATA%\MessageFoundry\tray.log` (`__main__.py:23-31`), no-console-flash (`CREATE_NO_WINDOW`, `messagefoundry/service.py:35`), and everything the tray shows when the service is stopped / unreachable / unqueryable / foreign.

**In scope — 13b, the Windows service:** NSSM install/reconfigure/uninstall (`scripts/service/install-service.ps1`, `uninstall-service.ps1`), service identity (virtual account default at `install-service.ps1:472-477`, gMSA preflight `:283-314`, `SeServiceLogonRight` grant `:316-375`), the S4-ordered ACL lockdown (`:119-177`, applied at `:526-548`), WER crash-dump suppression (`:194-267`), crash restart / autostart / drain / log rotation (`:450-464`), `import-db-ca.ps1`, `messagefoundry service {install,start,stop,status}` (`messagefoundry/service.py:242-271`), and the read-only unprivileged SCM query the engine and tray both lean on — `messagefoundry/service_status.py` (`is_safe_service_name`, `parse_service_state`, `query_service_state`; stdlib-only, `sc.exe` pinned to System32, no shell, no elevation, off the event loop).

**In scope — 13c, distribution & install:** wheel+sdist build and release pipeline (`.github/workflows/release.yml`), hash-verified `requirements.lock` install, extras, the Docker image (`docker/Dockerfile`) and k8s manifests (`docker/k8s/`, ADR 0047), offline install, upgrade/rollback, uninstall cleanliness, AV/firewall interaction (`docs/ANTIVIRUS-FIREWALL.md`), signed artifacts + SBOM + reproducibility, and `messagefoundry verify` as on-box acceptance.

**In scope — 13d, the standalone PySide6 test harness (`harness/`):** the window and its five tabs (`window.py`, `send.py`, `compose.py`, `receive.py`, `file_panel.py`, `monitor.py`), the console-rehomed view widgets and sign-in dialog (`_console_widgets.py`, `_login.py`), and the separate `messagefoundry-harness` distribution (`packaging/messagefoundry-harness/pyproject.toml`, force-including `harness/` from the repo root; built and version-checked in lockstep with the engine by the `release-harness` job, `.github/workflows/release.yml:477+`, PyPI publish gated on the `PUBLISH_HARNESS` repo variable). **This chapter takes ownership of the harness GUI because no other chapter did**, and because it is the plan's *only* route to two things nothing else exercises: **hostile-input injection** (the Compose tab's presets — "No MSH segment", "Bad version (2.3)" — hand-edited and sent over MLLP with an explicit ACK expectation; presets at `compose.py:74-77`, their seed strings at `:50-54`, applied by `_apply_preset` at `:123-127`) and **outbound-fault injection** (the Receive tab's `REPLY_MODES` = AA/AE/AR/none plus `DELAY_AA`, `CLOSE`, `FAIL_THEN_AA`, `harness/mllp.py:40`, with per-control-id duplicate counting that surfaces the engine's at-least-once retries). PySide6 lives here and only here — the desktop operator console was retired (BACKLOG #103, ADR 0032 retired); the web console is the IDE/WEB chapters' business, not this one.

**Explicitly NOT in scope here — owned elsewhere, cited not restated:**

| Area | Owner artifact |
|---|---|
| The subsystem coverage-gap audit for deployment (`FCP:DEPLOY-1`..`FCP:DEPLOY-27`, per-dimension gaps, risk/effort, prioritised close list) | `docs/testing/FEATURE-COVERAGE-PLAN.md` §24, lines 1519-1564 |
| The phased plan (entry/exit criteria, method column) that schedules those closures | `docs/testing/FEATURE-COVERAGE-PLAN.md` `FCP:P6`, lines 303-352 |
| On-box Windows Server 2025 host/service-identity acceptance procedure, incl. the NSSM reboot/crash MANUAL row | `W25:S2.5` (`docs/testing/WIN2025-TEST-PLAN.md`); `W25:G1` (`docs/testing/WIN2025-TEST-MATRIX.md:90`) |
| The `messagefoundry verify` contract itself (five sections, exit codes, what green does/doesn't prove) | `docs/testing/VERIFY.md` |
| Store/DB parity, DPAPI key provisioning, engine throughput, HA leader lease | the store, crypto and HA chapters of this plan |
| The VS Code IDE extension (`ide/`) | the IDE chapter |
| The web console (`messagefoundry_webconsole`, `/ui`) — the operator console | the WEB chapter. This chapter owns only the *tray's* `/ui` probe and its double-click-to-console action |
| The harness's **non-GUI** halves — `harness/load/`, `harness/reconcile/`, `harness/scenarios.py`, `harness/acceptance/` scoring, the `harness/__main__.py` CLI (2 266 lines) | the PERF chapter (load/soak), the STORE chapter (reconcile). This chapter owns the **GUI** modules, the sign-in dialog, the harness wheel, and the `ACC:A7` retirement |
| Frozen PyInstaller installer, toast AUMID registration, standing `sc sdset` ACL grant, tray support for engine shards / `supervise` | **declined by design** — ADR 0113 "Out of scope" + Options considered #5; ADR 0113 §5 |

**Owned here by ruling (duplicated deliverables).** Two items that other chapters also touch resolve to this chapter and are scoped here in full; MIG-18 and WEB-58 are pointers to these rows, not separate work:
- **The `[console]` extra / `check_console_importable` provenance** — the retired PySide6 desktop console still has three shipped references to a `[console]` extra that `pyproject.toml` does not define (its real name is `harness`): `messagefoundry/verify/checks.py:187`, `harness/acceptance/probes.py:173`, and the prose form at `docs/SYSTEM-REQUIREMENTS.md:121`. Covered by **TRAY-67** and **TRAY-70**.
- **The `harness/acceptance/matrix.py` `ACC:A7` retirement** — row `ACC:A7` ("Console runs (Desktop Experience, PySide6)", `matrix.py:153-160`) and its `probe_console_gui` (`harness/acceptance/probes.py:170-179`). Covered by **TRAY-69**.

**Objectives.** (1) Make a privileged-install regression fail *before* merge, not on a customer box. (2) Give the tray — a shipped, always-running, operator-facing process — its first end-to-end and behavioural coverage, at **P0**, because it is the part of this chapter an operator actually looks at. (3) Give the tray's Windows-shell behaviours an **owned** manual matrix with a cadence and a sign-off, instead of an unowned checklist inside a user doc (`docs/TRAY.md:173-190`). (4) Prove the distribution chain (wheel, lock, container, offline, upgrade, rollback, uninstall) on the platform the docs actually prescribe. (5) Give the shipped test harness GUI an owner, so the plan's only hostile-input and fault-injection instrument is itself tested.

**PHI discipline for this chapter.** Every message used anywhere below is synthetic (`samples/messages/adt_a01.hl7`, or `messagefoundry generate`). The tray is PHI-free *by construction* — `StatusSnapshot` (`state.py:94-107`) carries no message/queue/count field and `tests/test_tray_boundary.py` freezes that — so no tray test may introduce one. The harness is synthetic-only by charter (`packaging/messagefoundry-harness/pyproject.toml` describes it as "synthetic-only send/receive"); a harness test may never load a real capture, and the Compose tab's hostile presets are malformed *synthetic* HL7, never real PHI made malformed. NSSM's captured stdout under `C:\ProgramData\MessageFoundry\logs\` **is** a PHI sink; tests may assert *absence* of bodies and may upload logs from a synthetic-only run, never from a box that has seen real traffic. Reports from every row below carry metrics and metadata only — never a message body.

---

### 13.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_tray_state.py` (133 lines) | `derive_state` over all SCM × health combinations, the 30 s `BOOT_GRACE_S`, stuck-pending → `WEDGED`, `next_poll_seconds` clamps, tooltips, transition-toast selection. Pure; runs on every OS. |
| `tests/test_tray_poller.py` (148) | Pure `advance()` timing (running-since anchor, checkpoint progress, monotonic elapsed) plus `StatusPoller` toast rate-limiting and snapshot composition with injected probes. |
| `tests/test_tray_probe.py` (180) | `classify_health` / `classify_ui`, probe behaviour over `MockTransport`, and an AST guard (`:137`) that `probe.py` contains no `verify=False` / `check_hostname=False` / `CERT_NONE`. |
| `tests/test_tray_config.py` (330) | `parse_serve_args`, `build_engine_url` (IPv6 bracketing + tls scheme), `is_local_engine` / `is_tls_url`, compose precedence, hostile-hint rejection, service-TOML TLS discovery, fail-soft on malformed TOML, `ensure_tray_toml` idempotency. |
| `tests/test_tray_menu.py` (149) | Menu order and default item, per-state Start/Stop/Restart enablement, monitor-only blanket disable, `NOT_INSTALLED` install hint, console-disabled caption, autostart checkbox, Exit never maps to a control action. |
| `tests/test_tray_boundary.py` (61) | `StatusSnapshot`'s field set equals the ADR 0113 §2 allowlist and carries no message/queue/count/token/session-shaped field. |
| `tests/test_api_health_tokenless.py` | `GET /health` stays 200 with no `Authorization` header even under the fail-closed default — the tray's only liveness contract. |
| `tests/test_tray_control.py` (53) | `needs_confirm(stop/restart)`, confirm text, outcome→toast mapping, `DISPATCHED` is silent, `perform()` delegates to `control_service_ex`. |
| `tests/test_tray_winsvc.py` (61) | `_map_current_state` code mapping; off-Windows `UNAVAILABLE`; a real `NOT_INSTALLED` and a real live-service query on win32 legs. |
| `tests/test_tray_iconset.py` (40) | `theme_from_registry_value` mapping, icon filename shape, and that all 18 (state × theme) `.ico` files exist **in the repo**. |
| `tests/test_tray_actions.py` (82) | `console_url` always appends `/ui`, VS Code CLI resolution incl. unexpanded-`%VAR%` rejection, repo/log availability predicates, list-argv (no shell) `open_repo`. |
| `tests/test_tray_branding.py` (112) | `VS_VERSIONINFO` builder self-consistency, version normalisation/overflow, `is_branded_process`, off-Windows fail-soft, relaunch child-death fallback, and a live round-trip where Windows reads `FileDescription` back. |
| `tests/test_tray_shell.py` (104) | `assign_command_ids` round-trip, disabled items not dispatchable, `launcher_command` quoting, `winshell`/`app`/`__main__` import + ctypes struct construction, named-mutex second-acquire on win32. |
| `tests/test_service_control_outcome.py` (89) | `control_service_ex` guard ordering (unsafe name/action rejected before the platform check), the exact System32 `cmd`/`net` command shape, outcome passthrough, `control_service`'s bool contract. |
| `tests/test_service_control.py` (284) | `sc` output parsing, `CREATE_NO_WINDOW` on the state poll, `ShellExecuteW` argv for start/stop/restart/install, service-name and environment-name injection guards, install-script static guards (`AppStopMethodConsole 15000`, no `AppStopMethodSkip`, `AppExit Restart`, `AppThrottle`). |
| `tests/test_service_install_manifest.py` (161) | Static policy shape of `install-service.ps1`: NSSM SHA-256 pin well-formed, mismatch branch **throws** (not warns) and deletes, `Tls12` + `win64` extract, virtual-account default branch present, `-AllowLocalSystem` opt-out, gMSA preflight + `SeServiceLogonRight` wired. |
| `tests/test_service_status.py` (136) / `tests/test_service_cli.py` (73) | `is_safe_service_name`, `parse_service_state`, settings rejection of an unsafe `[service].service_name`; `messagefoundry service {status,start,stop,install}` dispatch, `--env` requirement, missing-script exit 2. |
| `tests/test_release_pipeline.py` (508) | sdist `only-include` ↔ leak-gate regex cross-check, tag-gated PyPI publish is last, Trusted Publishing (no token), repo gating, idempotent release step, PEP 440 version-vs-tag in both wheel smokes, console/engine tag-namespace separation. |
| `tests/test_sbom_finalize.py` (131) | `sbom_finalize.py` lifecycle/version backfill and structural failure modes. |
| `tests/test_install_instruction_provenance.py` | ASVS 15.2.4: no shipped text names an **undeclared extra in `messagefoundry[...]` literal form**, and no shipped text index-installs an unpublished distribution. |
| `tests/test_verify.py` (451) | Every host check returns a `CheckResult` and never ERRORs; store/smoke paths; report rendering; exit codes; CLI wiring. |
| `.github/workflows/ci.yml` `test` matrix (ubuntu + windows-2022 + windows-2025, py3.14) | The whole tray pytest suite runs on both Windows Server SKUs, so the win32-guarded mutex and live-SCM-query tests actually execute. |
| `.github/workflows/ci.yml:187-199` | mypy strict types `messagefoundry/tray` under a dedicated `--platform win32` pass (excluded from the linux pass), so the ctypes prototypes stay strict-clean. |
| `.github/workflows/ci.yml:1082-1262` `windows-service-smoke` | Real `install-service.ps1 -LockConfigDir` under Windows PowerShell 5.1 on Server 2022 + 2025, virtual-account default, service start, `/health`, a synthetic MLLP ADT recorded, graceful `nssm stop`, `uninstall-service.ps1`, log upload. **Nightly/dispatch + MEFORORG only.** |
| `.github/workflows/ci.yml:1274+` `docker-smoke` | slim + `-sqlserver` image builds; baked-config synthetic MLLP ADT reaches `PROCESSED` (not merely `RECEIVED`); tini → SIGTERM graceful shutdown. |
| `.github/workflows/manifest-lint.yml:80-113` | `kubeconform -strict` over `docker/k8s/*.yaml` plus ADR 0047 AC-4/AC-5 (replicas 3, PDB `maxUnavailable: 1`, `terminationGracePeriodSeconds` > lease TTL, no HPA, no Ingress). Path-gated, deliberately **not** a required check. |
| `.github/workflows/security.yml:53-77` (DEP-1) | `uv lock --check`, re-export drift gate over `requirements.lock` + both docker locks + `constraints.lock`, and a real `pip install --require-hashes -r requirements.lock`. **ubuntu-latest only.** |
| `.github/workflows/security.yml:230-256` | Trivy image SBOM + fixable HIGH/CRITICAL gate with OpenVEX suppression; Dockerfile misconfig lint (informational). |
| `.github/workflows/release.yml:97-180` | Package-only sdist allowlist + leak gate; clean-venv wheel install → import + PEP 440 version==tag; tag-only `py.typed`-in-wheel assertion. **Linux only.** |
| `.github/workflows/release.yml:191-292` | CycloneDX SBOM (license-complete, built from the core lock) + OpenVEX + sbomqs; Sigstore keyless signing; SLSA provenance; PyPI Trusted Publishing. |
| `scripts/security/crypto_inventory_check.py:239-245` | `messagefoundry/tray/probe.py` is a registered crypto site allowed exactly `{ssl, truststore}` — an added crypto import fails the gate. |
| ADR 0113 AC-1..AC-7 | Each acceptance criterion names its covering test and is marked ✅; AC-4 explicitly defers real-UAC cancel to manual QA; AC-7 amended 2026-07-22 for TLS-on-loopback. |
| **13d** `tests/test_harness.py` (145) | `HarnessWindow` constructs under `QT_QPA_PLATFORM=offscreen`; `SendWorker` → real `MllpReceiver` round trip with the engine's own `MLLPDecoder`/`build_ack`/`frame`. |
| **13d** `tests/test_harness_compose.py` (130) | Compose presets seed the editor, fire-and-forget send skips the ACK wait, and the `_ACCEPT`/`_REJECT`/`_NONE` expectation-match logic classifies results. |
| **13d** `tests/test_harness_faults.py` (114) | Every `REPLY_MODES` entry driven through the `QTcpServer` receiver with a raw client socket: `DELAY_AA`, `CLOSE`, `FAIL_THEN_AA`, plus per-control-id duplicate counting. |
| **13d** `tests/test_harness_file.py` (77) / `tests/test_harness_config.py` (72) | `FilePanel` behaviour; harness config load/precedence. |
| **13d** `tests/test_harness_monitor.py` (249) | `MonitorPanel` builds disconnected, then observes a **real** managed engine + API (auth disabled) in a background uvicorn thread: the off-thread poller populates the connections table and the message list shows dispositions. |
| **13d** `tests/test_console_messages_refresh.py` | The rehomed `MessagesPanel` / `_MessagesSnapshot` refresh path in `harness/_console_widgets.py` — the one console-rehomed widget with dedicated coverage. |
| **13d** `tests/test_harness_invariants.py` (203) / `tests/test_harness_scenarios.py` (195) | The harness's own bug-class guards (every derived timeout strictly dominates the interval it bounds) and scenario definitions. |
| **13d** `.github/workflows/ci.yml:218-231` | The engine `pytest` step runs with `QT_QPA_PLATFORM: offscreen` on ubuntu + windows-2022 + windows-2025, so every harness GUI test above actually executes on all three. |

**Done — do not re-plan.** The tray's **pure core** is genuinely well covered and needs no new work: the state reducer, poll-cadence maths, probe classifiers, config composition and hostile-hint rejection, the menu enablement matrix, the not-a-console field allowlist, the tokenless-`/health` server contract, the elevation command shape and its injection guards, and the version-resource builder. The **static shape** of `install-service.ps1` (NSSM hash pin, fail-closed mismatch, virtual-account default branch, gMSA wiring, `AppExit Restart`, the 15 s `AppStopMethodConsole`) is covered by `tests/test_service_install_manifest.py` + `tests/test_service_control.py` — do not re-assert the regexes; the gap is *executing* those branches. The **release pipeline's structure** (leak gate, publish ordering, Trusted Publishing, SBOM finalisation) is covered by `tests/test_release_pipeline.py` + `tests/test_sbom_finalize.py`. The **container runtime** (build, MLLP → `PROCESSED`, SIGTERM drain) is covered by `docker-smoke`. Do not restate `FCP:DEPLOY-1`..`FCP:DEPLOY-27` — cite `FEATURE-COVERAGE-PLAN.md` §24. For **13d**, the harness's *transport* halves (MLLP send, receive, fault modes, Compose expectation matching) and the monitor's engine round trip are genuinely covered — the gaps are the launch/teardown path, the sign-in dialog, the file panel's engine-facing half, and the wheel.

**Three recon corrections carried into this chapter.** (a) `tests/test_install_instruction_provenance.py` *does* guard extras (`test_every_extra_named_in_shipped_text_is_declared`), but only where the text spells `messagefoundry[extra]` literally — the prose forms at `docs/SYSTEM-REQUIREMENTS.md:121` ("install with the `console` extra"), `messagefoundry/verify/checks.py:187` and `harness/acceptance/probes.py:173` (both "install the `[console]` extra") evade the `_EXTRA_REF` regex, so the defect is real but the fix is a regex/prose-form extension, not a new guard. There is **no `[console]` extra** in `pyproject.toml` — the only PySide6 extra is `harness` (`pyproject.toml:86-88`), and there is deliberately no `[tray]` extra either (`:89-92`). (b) `TrayShell.__init__` *does* accept `on_session_end` (`winshell.py:131`) and `_wnd_proc` *does* call it on `WM_ENDSESSION` (`:423`); the dead code is that `TrayApp` never supplies it (`app.py:57-62`), so the hook is unreachable while `_remove_icon()` still runs. (c) `ACC:F7` ("No console-window flash on service poll (CREATE_NO_WINDOW)", `matrix.py:414-420`) is **not** a stale reference to the retired PySide6 console — its probe reads `messagefoundry/service.py` for `CREATE_NO_WINDOW` (`probes.py:182-196`) and is current. Only `ACC:A7` is stale. An earlier draft of this chapter claimed F7 needed recaptioning; that claim is withdrawn.

---

### 13.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| `install-service.ps1` privilege/ACL regression merges green | A `.ps1` edit drops the virtual-account default (`:472-477`), mis-orders the S4 ACL grants (`:516-548`), breaks `Resolve-Nssm`, or removes `AppExit Restart` | Every new install on every customer box; discovered at go-live | **No** — only `windows-service-smoke`, `(schedule \|\| workflow_dispatch) && github.repository == 'MEFORORG/MessageFoundry'` (`ci.yml:1087`); never on a PR, never in a fork/mirror. Static regexes only | **P0** |
| Silent regression to LocalSystem, or a world-readable log dir | Nothing queries `nssm get MessageFoundry ObjectName`, `Start`, or `icacls` on DataDir/logs/config after install | NSSM captures engine stdout to `C:\ProgramData\MessageFoundry\logs` — a PHI sink (`install-service.ps1:119-137` exists precisely for this). A lost `/inheritance:r` re-exposes it; a lost ObjectName widens compromise blast radius | **No** — `FCP:DEPLOY-8` / `FCP:DEPLOY-11` rated high-risk, partial/none in `docs/testing/FEATURE-COVERAGE-PLAN.md` §24 (rows at `:332`, `:334`) | **P0** |
| Engine does not come back after host reboot or engine crash | `Start SERVICE_AUTO_START` (`:450`) or `AppExit Default Restart` + `AppThrottle` (`:463-464`) silently ineffective | A silent clinical outage: feeds stop, senders queue or drop, nothing alerts because the engine simply is not running | **No** — static regex (`test_service_control.py:118`) + a MANUAL row (`ACC:G1`, `harness/acceptance/matrix.py:430-437`; `W25:S2.5`) | **P0** |
| The tray's shipped launch path is unverified end to end | A hatchling change drops `tray/assets`, or the `gui-scripts` entry (`pyproject.toml:202-203`) typos | `docs/TRAY.md:22-37` promises "present on every `pip install messagefoundry`". A tray that starts with no icon, or does not start, on every fresh install | **No** — `release.yml:127-180` installs the wheel on **Linux** and asserts only import/version/`py.typed`; `test_tray_iconset.py` reads `ASSETS_DIR` from `__file__` (the repo); `windows-service-smoke` installs `-e .` | **P1** |
| ADR 0113 §1's import contract unenforced | A future edit imports `messagefoundry.config.settings` into the tray to "read TLS properly" | Pulls the engine + pydantic into an unprivileged, always-running process; breaches the boundary the whole ADR rests on | **No** — `tests/test_dependency_boundaries.py:14` lists only `pipeline/transports/parsing/store/config`; nothing scans `messagefoundry/tray/` | **P1** |
| `tray.log` destroyed by httpx per-tick noise | `_setup_logging` attaches the handler to the **root** logger at INFO (`__main__.py:29-31`); nothing raises the `httpx` logger, which logs one INFO line per request — two requests every 5 s | ~34k lines/day churn a 1 MB × 3 rotation, so transitions, user actions and elevation outcomes rotate out within hours — destroying the only forensic record of who stopped a clinical interface. Contradicts `docs/TRAY.md:162` ("state transitions, never per-tick") | **No** | **P1** |
| `poll_seconds` is inert | Parsed and clamped (`config.py:257-259`), documented (`config.py:359-360`, `docs/TRAY.md:89`), but `StatusPoller._run` (`poller.py:169`) always calls `next_poll_seconds()`, which returns the hardcoded `POLL_BASE_S = 5.0` (`state.py:24,166-172`) | An operator throttling a busy interface box sees no change and gets no signal the setting was ignored | **No** — tests assert only that the value lands in `TrayConfig` (`test_tray_config.py:126,236`) | **P1** |
| The tray's Win32 layer is behaviourally untested | `TrayApp` (154 lines) and the pump (`winshell.py:299-451`) decide which icon paints, whether a toast fires, whether Exit tears down, whether the icon is removed on `WM_DESTROY`/`WM_ENDSESSION` | A ghost icon after logoff, a frozen icon on a state change, an action routed to the wrong handler — the exact failure class ADR 0113 named as the design's main risk | **No** — `test_tray_shell.py` only asserts imports + non-zero struct sizes | **P0** — the design's *named* main risk cannot be priced below the install rows it sits beside; closed by TRAY-19, TRAY-20 and TRAY-22 |
| Autostart writes are untested | `set_autostart` / `is_autostart_enabled` (`autostart.py:34-64`) write and read the real `HKCU\…\Run` value; only the pure `launcher_command` helper is covered | A stale or wrong-interpreter command silently breaks Start-at-Login (no tray after reboot) or strands a value pointing at a deleted venv; the menu checkbox reads the same untested getter | **No** | **P1** |
| Hardened box + non-admin operator = a lying tray | Under `-LockConfigDir`, a standard user cannot read the engine's settings TOML, so `service_toml_uses_tls` sees nothing, `build_engine_url` yields `http://`, the https probe fails, and a healthy engine renders `WEDGED`/`STOPPED` | The 2026-07-22 amendment's bug, resurfacing for the least-privileged user on the most-hardened box, with no on-screen path to the fix — a healthy clinical interface rendered as down, on the exact configuration the security guidance prescribes | **No** — the fail-soft-to-http behaviour is asserted as *correct* (`test_tray_config.py:274-287`); the operational consequence is untested and undocumented | **P0** — a tray that lies about a healthy engine is worse than no tray; closed by TRAY-27 (+ TRAY-43 on the box) |
| Windows-only lock resolution failure | `pip install --require-hashes -r requirements.lock` — prescribed for Windows production at `docs/SERVICE.md:26-33` — runs only on ubuntu (`security.yml:71-77`) | A platform-marker gap, an sdist-only transitive, or a missing `win_amd64` wheel breaks the documented production install on the primary supported platform | **No** | **P1** |
| Uninstall leaves user-scope tray artifacts | `uninstall-service.ps1` touches only the service. Nothing removes the `HKCU\…\Run` value `MessageFoundryTray` (`autostart.py:19`), `%LOCALAPPDATA%\MessageFoundry` (tray.toml + tray.log), or `Scripts\MessageFoundryTray.exe` + the ~7 MB staged DLLs (`branding.py:280-290`) | After `pip uninstall messagefoundry` the Run key fires at every login and fails silently; a branded exe lingers indefinitely | **No** — no doc, no test, no mention in `docs/SERVICE.md` or `docs/TRAY.md` | **P1** |
| AV/EDR quarantines the branded launcher | `branding.ensure_branded_launcher` copies an interpreter, rewrites its `RT_VERSION` and stages DLLs into `Scripts\` — textbook EDR heuristic bait | Design is fail-soft (tray runs unbranded), but an EDR that quarantines the *source* `pythonw.exe` can break the tray **and** the engine. `docs/ANTIVIRUS-FIREWALL.md` process-exclusion table lists `python.exe`, `messagefoundry.exe`, `nssm.exe` — no `pythonw.exe`, no `MessageFoundryTray.exe` | **No** | **P1** |
| Upgrade/rollback never rehearsed | `docs/EARLY-ADOPTER-GUIDE.md:672-698` is doc-only and warns store-level changes are not reversible; the ≤0.2.5→≥0.2.6 config-ACL migration is exactly the class of upgrade break nothing catches | Data-loss path on an unrehearsed rollback against a populated store | **No** | **P1** |
| Windows graceful drain unverified | Nothing pushes in-flight MLLP then `nssm stop` to prove the 15 s `AppStopMethodConsole` window drains | A shortened/bypassed drain cuts in-flight messages mid-stage on every operator restart — the reliability invariant's Windows half. `FCP:DEPLOY-5` "partial" | Container SIGTERM only (`docker-smoke`) | **P1** |
| `messagefoundry verify` misleads the operator | `check_console_importable` (`verify/checks.py:180-194`, wired at `:249`) probes the **retired** PySide6 console and says "install the `[console]` extra" — an extra `pyproject.toml` does not define. No tray section exists (`verify/runner.py:22`) | The one tool meant to answer "is this box set up right" recommends a nonexistent install and reports nothing about the tray | **No** | **P1** |
| NSSM auto-provision never executes | `Resolve-Nssm`'s download/verify/extract branch (`install-service.ps1:95-116`) is skipped because CI runners have `nssm` on PATH | This is the supply-chain integrity path for the binary that supervises the service; it fires on **every first-time install**. `FCP:DEPLOY-7` rated med/none | **No** — static shape only (`test_service_install_manifest.py:50-101`) | **P1** |
| Tray probe client could gain a credential | `make_probe_client` (`probe.py:141-146`) constructs the client; nothing asserts it carries no `Authorization` | A bearer token on a 5-second timer is the CWE-613 anti-pattern ADR 0113 rejected outright; the client-construction half of the boundary is unguarded | Partly — server side (`test_api_health_tokenless.py`) and render model (`test_tray_boundary.py`) are frozen | **P2** |
| Slow-but-successful stop reported as failure | `control_service_ex` waits 60 s (`service.py:146`) and treats `WAIT_TIMEOUT` as `FAILED` (`:210-215`) | A legitimate 15 s drain + busy store + slow start over 60 s toasts "Service stop failed" for an action that succeeded, prompting a re-issued stop on a clinical interface | **No** — the timeout branch has no test | **P2** |
| DPI / High Contrast unimplemented | No `SetProcessDpiAwarenessContext`, no `WM_DPICHANGED`, no manifest; icons load `LR_DEFAULTSIZE` and are cached by path forever (`winshell.py:280-290`). `theme.py:18-33` has only LIGHT/DARK and never reads `SPI_GETHIGHCONTRAST`, though ADR 0113 §3 states a High-Contrast treatment is part of the shipped rendering model | Blurry/wrong-sized icon on mixed-DPI; a High-Contrast operator can get an effectively invisible status icon — an accessibility regression against a written ADR commitment | **No** — and no tracking item records the ADR-vs-code divergence | **P2** |
| The always-running tray leaks memory or Win32 handles | `_load_icon` (`winshell.py:280-290`) caches every `LoadImageW` handle in `self._icon_cache` for the **whole process lifetime** — the only `DestroyIcon` sweep is in `_remove_icon` (`:343-346`), i.e. at teardown, never during a multi-day session. `_apply_update` (`:314-323`) rebuilds a `_NOTIFYICONDATAW` and re-loads the icon on **every** update, and the poller ticks every 5 s | The tray is the one MessageFoundry process that runs for weeks on an operator's clinical workstation. If the cached path set is ever unbounded (a themed/per-DPI variant, a state added without an asset, a path that differs by case or separator), GDI/USER handle exhaustion — the 10 000 per-process default — shows up days in as a vanished icon or a failed `LoadImageW`, exactly when the operator most needs engine state. Today the set is 18 files; **nothing asserts it stays bounded, and nothing measures RSS over time** | **No** — no soak, no handle-count assertion; every tray test is a sub-second unit run | **P1** — closed by TRAY-71 |
| Log rotation / INFO-body leak untested | `AppRotateBytes 10485760` + `AppRotateOnline 1` (`:456-458`) asserted only as text; nothing fills a log past 10 MB, nothing asserts INFO output carries no message body | Rotation failure fills the data volume and stops the engine; an INFO body leak puts PHI in a file that (absent the ACL assertion) may be broadly readable. `FCP:DEPLOY-6` "partial" | **No** | **P2** |
| Reproducible build claimed but absent | `docs/FEATURE-MAP.md:211` bundles "signed tag (Sigstore) + **reproducible wheel/sdist** + SBOM" into one 🔨 row whose other two thirds are shipped. No `SOURCE_DATE_EPOCH`, no rebuild-and-compare in `release.yml` | A supply-chain claim in the capability catalog that no artifact backs; Sigstore + SLSA prove *who* built it, not that a third party can rebuild it bit-for-bit | **No** | **P2** |
| Second-instance UX cannot be honestly ticked | `docs/TRAY.md:186` lists "shows 'already running' and exits", but `__main__.py:56-58` only writes the line to `tray.log` | A manual-QA checkbox that can never be honestly ticked erodes the whole checklist; a user double-clicking the launcher gets silent nothing | **No** | **P2** |
| Acceptance matrix scores a retired surface | `harness/acceptance/matrix.py:153-160` row `ACC:A7` still probes "Console runs (Desktop Experience, PySide6)" via `probe_console_gui`; no tray row exists at all (`ACC:F7`, `:414-421`, is **current** — its probe reads `messagefoundry/service.py`, see the recon corrections above) | A box that "passes acceptance" has had its actual operator-adjacent desktop tool tested zero times | **No** | **P2** |
| Container image never published; k8s never applied | No `docker push` / ghcr / `build-push-action` in any of the 16 workflows; `manifest-lint.yml` is path-gated and non-required and only shape-checks | An operator copying `ha-postgres.yaml` with a grace period below the lease TTL gets split-brain-adjacent rollout behaviour; branch-protection drift could drop the lint entirely | Lint only | **P2** |
| Air-gapped install is a two-line recipe | `docs/INSTALL-GUIDE.md:114` and `docs/EARLY-ADOPTER-GUIDE.md:193` give `--no-index --find-links`; no wheelhouse builder, no NSSM pre-stage runbook, no CI leg | Air-gapped hospitals are explicitly courted; a missing transitive in the mirrored set is discovered at cutover, at a site with no way to fetch it | **No** | **P2** |
| Branded launcher overwrites venv DLLs | `_stage_runtime` (`branding.py:284-290`) replaces any same-named DLL in `Scripts\` whenever the base interpreter's copy is newer, with no INFO log on the happy path | An unrequested write into a shared install directory as a side effect of cosmetic branding | **No** | **P2** |
| `import-db-ca.ps1` untested | Writes to the LocalMachine Root store; no malformed-cert rejection test, no thumbprint-keyed idempotency, no `-WhatIf` no-op | A bad import fails the TLS store connection at service start, or installs an unintended machine-wide trust anchor. `FCP:DEPLOY-13` "none" | **No** | **P2** |
| **13d** The plan's only hostile-input instrument is itself unowned end to end | The Compose presets and the Receive fault modes have unit coverage, but nothing exercises the shipped **launch** path (`python -m harness` / the `messagefoundry-harness` console script), the sign-in dialog against a real authenticating engine, or the harness **wheel** (`packaging/messagefoundry-harness`, built every release by `release-harness`, `release.yml:477`) | A harness that will not start, or cannot sign in, on the test box is discovered at the moment a tester needs it — and it is the only route the plan has to malformed-HL7 injection and to `DELAY_AA`/`CLOSE`/`FAIL_THEN_AA` outbound faults. A broken lockstep wheel ships silently: its version is read from the engine's `__init__.py`, and its PyPI publish is gated off by default (`PUBLISH_HARNESS`) | Partly — `tests/test_harness*.py` cover panels and transports in-process; nothing covers launch, sign-in or the wheel | **P1** — closed by TRAY-72, TRAY-76, TRAY-77 |

---

### 13.4 Test matrix

**Row class.** 78 rows: **72 T**, **6 C**, **0 A**. The six **C** rows are TRAY-36 and TRAY-37 (High Contrast, DPI), TRAY-57 and TRAY-58 (AV/EDR, firewall), TRAY-61 (rollback rehearsal) and TRAY-63 (reproducible build) — each produces a recorded finding, a published number or a dated owner decision rather than a threshold that can fail, so **none of them gates a release**; each converts to **T** the day its decision or threshold is recorded (Q5, Q7, Q8, Q9 in §13.9 are the four that unblock five of them). There are **no A rows**: this chapter commissions no external engagement — TRAY-57 exercises a third-party EDR product but is run by the team, which makes it C, not A.

**P0 count: 12 rows, all of them T** — the eight NSSM/service install rows (TRAY-01..TRAY-08) **plus four tray rows promoted in this revision: TRAY-19, TRAY-20, TRAY-22 and TRAY-27.** Until now the tray application held **zero** P0 rows while eight sat on the install scripts, even though ADR 0113 names the untested Win32/`TrayApp` layer as the design's main risk and the chapter's own risk table (corrected above) now prices it P0. A tray that paints the wrong icon, routes an action to the wrong handler, or reports a healthy engine as `WEDGED` for a standard user on a hardened box is a clinical-visibility defect, not a cosmetic one.

#### 13.4a — Part 13a: the tray application (`messagefoundry/tray/`)

*34 rows — 32 T, 2 C; 4 P0 (TRAY-19, TRAY-20, TRAY-22, TRAY-27).*

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| TRAY-14 | ADR 0113 §1 import contract is machine-enforced | Negative/Security | pytest | any | n/a | T | P1 | An AST scan of every `messagefoundry/tray/**/*.py` finds no import of `messagefoundry.pipeline`, `.store`, `.transports`, `.config`, `.api`, `fastapi`, or `PySide6`; the allowed engine imports are exactly `messagefoundry.service`, `messagefoundry.service_status`, `messagefoundry.apiclient`, `messagefoundry.tray.*`; adding `from messagefoundry.config.settings import ServiceSettings` to `tray/config.py` turns it red |
| TRAY-15 | `poll_seconds` either drives the cadence or is removed | Functional | pytest | any | n/a | T | P1 | **If wired (owner decision A):** a `StatusPoller` built from a `TrayConfig(poll_seconds=60)` with an injected clock waits ~60 s (not 5 s) between non-pending ticks, and still tightens to `waitHint/10` while STARTING/STOPPING. **If retired (decision B):** the key is absent from `TrayConfig`, from `TRAY_TOML_TEMPLATE` (`config.py:359-360`) and from `docs/TRAY.md:89`, and a test asserts no shipped text documents it |
| TRAY-16 | `tray.log` is not flooded by per-tick httpx INFO lines | Functional | pytest | any | n/a | T | P1 | After `_setup_logging`, `logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING`; a simulated 60-tick poll run writes **zero** lines matching `HTTP Request:` to the log file, and still writes the state-transition lines `docs/TRAY.md:160-164` promises |
| TRAY-17 | HKCU autostart write/read round trip | Functional | pytest | dev-PC (win32-guarded) | n/a | T | P1 | With the Run key redirected to a scratch subkey: `set_autostart(True)` returns True, the value equals `launcher_command()` verbatim (quoted, absolute, ends `-m messagefoundry.tray`), `is_autostart_enabled()` is True; `set_autostart(False)` returns False and the value is gone; calling `set_autostart(False)` twice does not raise (the `contextlib.suppress(OSError)` path) |
| TRAY-18 | Enabling autostart self-heals a stale value | Functional | pytest | dev-PC (win32-guarded) | n/a | T | P2 | Seed the Run value with `"C:\gone\pythonw.exe" -m messagefoundry.tray`; `set_autostart(True)` overwrites it with the *current* interpreter's absolute path |
| TRAY-19 | `TrayApp` maps state → icon + tooltip and emits toasts exactly once | Functional | pytest | any | n/a | T | **P0** | With a fake shell recording calls: a `PollResult` for each of the 9 `TrayState`s produces `request_update` with `icon_path(state, detect_theme())` and `tooltip(state)`; a result carrying a `Toast` produces exactly one `request_notify(title, body)`; a result with `toast=None` produces none |
| TRAY-20 | `TrayApp` action routing | Functional | pytest | any | n/a | T | **P0** | Each `Action` reaches exactly its collaborator: `OPEN_CONSOLE`→`actions.open_console(engine_url)`, `OPEN_REPO`→`actions.open_repo` only when both `repo_path` and a resolved VS Code exist, `START/STOP/RESTART`→`control.perform`, `VIEW_LOG`→`actions.open_log`, `TOGGLE_AUTOSTART`→`autostart.set_autostart(not current)`, `EDIT_SETTINGS`→`ensure_tray_toml`, `EXIT`→`shell.request_quit` **and no service call** |
| TRAY-21 | Stop/Restart confirm gate blocks the elevation | Negative/Security | pytest | any | n/a | T | P1 | With `_confirm` patched to return False, `_service_action("stop")` makes **no** call to `control.perform` and emits no toast; with True, exactly one `control_service_ex("stop", name)` call is made |
| TRAY-22 | Message-pump dispatch table | Functional | pytest | dev-PC (win32-guarded) | n/a | T | **P0** | Driving `TrayShell._wnd_proc` directly: `WM_TRAYICON` with `lparam & 0xFFFF` in `{0x007B, 0x0400, 0x0401}` calls `on_menu`; `0x0203` calls `on_double_click`; the registered `TaskbarCreated` message resets `_added` and re-adds; `WM_QUERYENDSESSION` returns 1; `WM_ENDSESSION` calls `on_session_end` then `_remove_icon`; `WM_DESTROY` calls `_remove_icon` then `PostQuitMessage`; a callback that raises does **not** propagate out of `_wnd_proc` |
| TRAY-23 | `on_session_end` is either wired or removed | Functional | pytest | any | n/a | T | P2 | Either `TrayApp` passes an `on_session_end` to `TrayShell` (`app.py:57-62`) and a test asserts it runs on `WM_ENDSESSION`, or the parameter is deleted from `TrayShell.__init__` — no dead hook remains |
| TRAY-24 | Probe client is constructed credential-free | Negative/Security | pytest | any | n/a | T | P2 | `make_probe_client("http://127.0.0.1:8765").headers` contains no `authorization`/`cookie`/`x-api-key` key (case-insensitive), and `follow_redirects is False`; adding a default `Authorization` header turns it red |
| TRAY-25 | https probe verifies; a bad cert reads DOWN, never a downgrade | Negative/Security | pytest | any | n/a | T | P2 | `build_verify("https://127.0.0.1:8765")` returns a `truststore.SSLContext` (a fresh object per call — two calls are not the same instance); a probe against a server with an untrusted cert yields `HealthProbe.DOWN`, and no code path yields `verify=False` (the existing AST guard stays) |
| TRAY-26 | Slow-but-successful stop is not reported as a failure | Functional | pytest | any | n/a | T | P2 | With `WaitForSingleObject` faked to return `WAIT_TIMEOUT` (258) and `GetExitCodeProcess` yielding `STILL_ACTIVE` (259), `control_service_ex` returns an outcome the tray renders as *in progress*, not `FAILED`; today it returns `FAILED` and toasts "Service stop failed" — the fix and its test land together |
| TRAY-27 | Hardened box, standard user: TLS discovery failure is visible ("the lying tray") | Usability | pytest | any | n/a | T | **P0** | With the service TOML unreadable (simulated `PermissionError`) and the registry hint pointing at an https engine, the tray does **not** silently render `WEDGED`: the tooltip/status line names the discovery failure (e.g. "engine URL not discoverable — set `engine_url` in tray.toml") and `tray.log` records it at WARNING. Today the fail-soft-to-http path is asserted correct at `tests/test_tray_config.py:274-287` with no operator-facing signal |
| TRAY-28 | `_stage_runtime` never silently replaces a differently-versioned DLL | Negative/Security | pytest | dev-PC (win32-guarded) | n/a | T | P2 | Seed `Scripts\` with a same-named, older-mtime file whose bytes differ from the base interpreter's; after `ensure_branded_launcher`, the replacement is logged at INFO with both paths (today it is silent on the happy path — `branding.py:284-290`) |
| TRAY-29 | Second-instance launch gives visible feedback | Usability | pytest + manual | dev-PC / W2025-box | n/a | T | P2 | With the mutex already held, `main()` returns 0 **and** produces an operator-visible signal (a balloon or a `MessageBoxW`) — or, if the owner declines the UX, `docs/TRAY.md:186` is amended to say "exits silently; see `tray.log`" so the checklist is honest |
| TRAY-30 | Non-Windows launch is a clean refusal | Compat | pytest | any | n/a | T | P2 | On a non-win32 platform `messagefoundry.tray.__main__.main()` prints the Windows-only note and returns 1, without importing `winshell`, taking the mutex, or creating `%LOCALAPPDATA%`-equivalent files |
| TRAY-31 | Icon and tooltip track the real service state | Functional | manual | W2025-box + Win11 client | SQLite | T | P1 | With the tray running: `nssm stop` → icon becomes the `stopped_*` art and the tooltip reads "MessageFoundry – engine stopped" within 10 s; `nssm start` → `starting_*` then `running_*` and "engine running"; block the API port while the service stays RUNNING → after 30 s (`BOOT_GRACE_S`) the icon becomes `wedged_*` and the tooltip reads "service up, API not responding" |
| TRAY-32 | Exactly one UAC prompt per action; Restart is one prompt | Negative/Security | manual | W2025-box | n/a | T | P1 | Start, Stop and Restart each raise exactly one UAC dialog; the dialog's publisher/path is `C:\Windows\System32\cmd.exe` (never the venv interpreter); Restart does **not** raise two. ADR 0113 AC-4 defers this to manual QA by design |
| TRAY-33 | Cancelled UAC prompt is distinguished from failure | Negative/Security | manual | W2025-box | n/a | T | P1 | Cancelling the prompt produces the "Action cancelled" balloon (not "Service stop failed"), the service state is unchanged, and `tray.log` records the CANCELLED outcome |
| TRAY-34 | Confirm dialog precedes elevation and is reachable | Usability | manual | W2025-box | n/a | T | P1 | Stop and Restart show the confirm text from `control.confirm_text` **before** any UAC prompt; the `MessageBoxW` (hwnd NULL — `app.py:39`) appears in front of other windows or is reachable from the taskbar; answering No performs no action |
| TRAY-35 | Live taskbar light↔dark theme switch | Usability | manual | Win11 client | n/a | T | P1 | Toggling Settings → Personalization → Colors between Light and Dark flips the icon within one poll tick with no blank/invisible intermediate state (`WM_SETTINGCHANGE`/`ImmersiveColorSet`, `winshell.py:412-415`) |
| TRAY-36 | High Contrast: characterise the current behaviour | Usability | manual | Win11 client | n/a | **C** | P2 | With each of the four High Contrast themes active, record whether the status icon remains distinguishable from the taskbar. Outcome is a written finding that either closes ADR 0113 §3's "High-Contrast treatment" claim or triggers an ADR amendment recording it as not built (`theme.py:18-33` reads only `SystemUsesLightTheme`) |
| TRAY-37 | DPI: crispness at 100 / 150 / 200 % and across mixed-DPI monitors | Usability | manual | Win11 client, 2 monitors at mismatched scaling | n/a | **C** | P2 | Screenshot the notification area at each scale; record whether the icon is scaled/blurred. Move the taskbar between the two monitors mid-session and record whether the icon reselects. Expected today: no reselect (`LR_DEFAULTSIZE`, cached forever — `winshell.py:280-290`). Outcome is a documented DPI posture, not a silent gap |
| TRAY-38 | Explorer restart re-adds the icon | HA/Resilience | manual | W2025-box | n/a | T | P1 | `taskkill /f /im explorer.exe`; after Explorer relaunches, the icon reappears with the correct state art and the menu still works (`TaskbarCreated`, `winshell.py:416-419`) |
| TRAY-39 | Windows 11 tray-icon list names it "MessageFoundry Tray" | Usability | manual | Win11 client | n/a | T | P2 | Settings → Personalization → Taskbar → Other system tray icons lists **MessageFoundry Tray**, not "Python"; the process image in Task Manager is `MessageFoundryTray.exe`; promoting it out of the overflow flyout keeps it pinned across a logoff |
| TRAY-40 | Branding failure degrades to an unbranded, working tray | HA/Resilience | manual | W2025-box | n/a | T | P2 | Make `Scripts\` read-only (or pre-place a corrupt `MessageFoundryTray.exe`); the tray still starts, is listed as "Python", and `tray.log` records the fail-soft path — no crash, no missing icon |
| TRAY-41 | Log-off / shutdown / fast-user-switch leaves no ghost icon | Functional | manual | W2025-box with two interactive accounts | n/a | T | P1 | Log off with the tray running and log back in: no orphaned icon, no duplicate. Fast-user-switch to a second account, start the tray there: both sessions show their own icon (per-session `Local\` mutex, `instance.py:14`) and neither blocks the other |
| TRAY-42 | Session lock/unlock during an in-flight service transition | Functional | manual | W2025-box | n/a | T | P2 | Trigger Restart, lock the session mid-transition (Win+L), unlock after ~30 s: the icon shows the correct settled state, no duplicate toast fires, and `tray.log` shows one continuous poll sequence (no crash/restart of the pump) |
| TRAY-43 | Standard (non-admin) operator on a `-LockConfigDir` box | Negative/Security | manual | W2025-box + a separate standard account | SQLite | T | P1 | Logged on as the standard user: the SCM read succeeds (Interactive SID grants `SERVICE_QUERY_STATUS`), the NSSM `Parameters` registry hints are readable, and the rendered state matches reality. If the engine serves https and the settings TOML is unreadable, TRAY-27's operator-visible signal appears instead of a false `STOPPED`/`WEDGED` |
| TRAY-44 | No console window flashes on any action or poll tick | Usability | manual | W2025-box | n/a | T | P1 | Watch the desktop for 3 minutes with the tray polling every 5 s, then invoke each menu action: no `conhost`/`cmd` window flashes (`CREATE_NO_WINDOW`, `messagefoundry/service.py:35`; `SW_HIDE` in `_runas_wait`, `:191`). This is the visual half of acceptance row `ACC:F7` |
| TRAY-45 | Double-click opens `<engine_url>/ui`; Open Repo degrades cleanly | Usability | manual | W2025-box (with VS Code) + a second box (without) | n/a | T | P2 | Double-click opens the default browser at exactly `<engine_url>/ui`; with `serve_ui` off the menu item is disabled and captioned "(console not enabled)"; on the box with no VS Code, Open Repo is disabled and captioned "(unavailable)" and clicking nothing happens (no error dialog) |
| TRAY-55 | Tray uninstall cleanliness | Functional | manual | W2025-box | n/a | T | P1 | Following the (to-be-written) tray uninstall step: the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` value `MessageFoundryTray` is gone, `%LOCALAPPDATA%\MessageFoundry` is disposed of exactly as Q6 decided (removed, or retained with the decision written into `docs/TRAY.md`), and `Scripts\MessageFoundryTray.exe` plus the staged runtime DLLs are gone; after a reboot no failed-launch entry appears in the Application event log |
| TRAY-71 | Tray process is flat in RSS and Win32 handles over a multi-hour run | Performance | manual + script | W2025-box or Win11 client (≥4 h session) | SQLite | T | P1 | With the tray running against a real service and a driver script forcing ≥200 state transitions (`nssm start`/`stop`/blocked API port, so every one of the 9 states and both themes are painted repeatedly), sample every 5 min via `Get-Process -Name MessageFoundryTray,pythonw` → `WorkingSet64`, `Handles`, `GetGuiResources` GDI + USER counts. Pass: **GDI and USER handle counts return to their first-hour band and never trend upward** (the icon cache is bounded by the 18-file asset set — `winshell.py:280-290`; a rising count means a path variant escaped it or `_apply_update` leaked), and **RSS growth over the run is < 10 MB** with no monotonic climb. The same sampler over a run that also fires ≥50 toasts must show no additional growth. A rising trend is a fail, not an observation — this process is expected to run for weeks |

#### 13.4b — Part 13b: the Windows service (NSSM)

*19 rows — 19 T, 0 C; 8 P0 (TRAY-01..TRAY-08).*

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| TRAY-01 | `windows-service-smoke` promoted to a per-PR **required** check for PRs touching `scripts/service/**`, `messagefoundry/service*.py`, `messagefoundry/tray/**` | Functional | CI-leg | container-CI (windows-2022 + windows-2025 runners) | SQLite | T | P0 | The leg's `if:` no longer contains `github.repository == 'MEFORORG/MessageFoundry'` for the path-gated PR trigger; a PR editing `install-service.ps1` shows the leg as a run, not "skipped"; a deliberate mutation (delete `Invoke-Nssm set $ServiceName Start SERVICE_AUTO_START`) turns the PR red |
| TRAY-02 | Post-install run-as identity assertion | Negative/Security | CI-leg | container-CI | SQLite | T | P0 | After the default install (no `-ServiceAccount`, no `-AllowLocalSystem`): `nssm get MessageFoundry ObjectName` returns exactly `NT SERVICE\MessageFoundry`; the string `LocalSystem` appears nowhere in the output; `sc.exe qc MessageFoundry` reports `SERVICE_START_NAME : NT SERVICE\MessageFoundry` |
| TRAY-03 | Post-install boot-start assertion | Functional | CI-leg | container-CI | SQLite | T | P0 | `sc.exe qc MessageFoundry` reports `START_TYPE : 2 AUTO_START`; `nssm get MessageFoundry Start` returns `SERVICE_AUTO_START` |
| TRAY-04 | Post-install ACL assertion on the PHI log sink | PHI | CI-leg | container-CI | SQLite | T | P0 | `icacls C:\ProgramData\MessageFoundry` output contains ACEs for **only** `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators` and `NT SERVICE\MessageFoundry`; it contains no `BUILTIN\Users`, no `Authenticated Users`, no `Everyone`; the same holds for `...\logs`; the step fails if `/inheritance:r` was not applied (any inherited `(I)` ACE naming a broad principal) |
| TRAY-05 | Post-install config-dir ACL assertion (`-LockConfigDir`) | Negative/Security | CI-leg | container-CI | SQLite | T | P0 | `icacls <config dir>` shows `NT SERVICE\MessageFoundry:(OI)(CI)(RX)` and no write/modify grant to any non-admin principal; the engine starts (proving the SEC-003 source-trust guard is satisfied, not bypassed) |
| TRAY-06 | Crash restart: kill the engine process, service returns to RUNNING | HA/Resilience | CI-leg | container-CI | SQLite | T | P0 | With the service RUNNING, `Stop-Process -Id <engine pid> -Force`; within 30 s `sc.exe query MessageFoundry` reports `RUNNING` again and `GET /health` returns 200; `service.out.log` shows a fresh startup banner |
| TRAY-07 | Crash-loop is throttled, not hot-looped | HA/Resilience | CI-leg | container-CI | SQLite | T | P0 | With a deliberately fatal config (e.g. `--config` pointed at a nonexistent dir via `nssm set … AppParameters`), the service is restarted at intervals ≥ the `AppThrottle 5000` window and reaches `SERVICE_PAUSED` rather than restarting more than 4 times in 10 s |
| TRAY-08 | Autostart after a real host reboot | HA/Resilience | manual | W2025-box (snapshot-capable VM) | x3 | T | P0 | After `Restart-Computer`, with no interactive login, `sc.exe query MessageFoundry` reports RUNNING within 120 s of boot and `GET /health` returns 200 from another host on the LAN or from a scheduled local probe |
| TRAY-09 | Graceful drain on `nssm stop` with in-flight MLLP | HA/Resilience | CI-leg | container-CI | SQLite | T | P1 | Push N=200 synthetic ADTs, then `nssm stop MessageFoundry` while the outbound lane is still draining; after restart, `GET /messages` totals equal N with zero `ERROR` dispositions attributable to the stop, and `service.out.log` shows the lifespan shutdown line — not a `nssm` kill-escalation line |
| TRAY-46 | `Resolve-Nssm` auto-download executes end to end | Negative/Security | manual | W2025-box with no `nssm` on PATH and no `<DataDir>\bin\nssm.exe`, outbound HTTPS allowed | n/a | T | P1 | `install-service.ps1` downloads `https://nssm.cc/release/nssm-2.24.zip`, the SHA-256 matches the pin at `install-service.ps1:79`, `win64\nssm.exe` is extracted to `<DataDir>\bin\nssm.exe`, and the install completes. Then, with a deliberately corrupted cached zip, the script **throws** (does not warn) and deletes the file (`:103-106`) |
| TRAY-47 | `SeServiceLogonRight` exact-SID-token match (RID-prefix regression) | Negative/Security | pytest (Pester-style static/behavioural harness) | dev-PC | n/a | T | P1 | Given a `secedit` export where `SeServiceLogonRight` already lists `*S-1-5-21-…-1100`, granting `*S-1-5-21-…-110` is **not** skipped as already-held (the exact-token split at `install-service.ps1:349-357`); given the SID already present, the script reports "already holds" and re-imports nothing |
| TRAY-48 | gMSA install on a domain-joined host | Functional | manual | AD-lab (domain-joined W2025 + RSAT + provisioned gMSA) | x2 | T | P1 | `install-service.ps1 -ServiceAccount 'DOMAIN\svc$'` runs `Test-ADServiceAccount` → OK, grants `SeServiceLogonRight`, sets `ObjectName` with no password, and the service **starts** (error 1069 does not occur); `icacls` shows the gMSA holds `(OI)(CI)M` on DataDir and `(OI)(CI)RX` on the config dir |
| TRAY-49 | `-AllowLocalSystem` opt-out branch | Negative/Security | CI-leg | container-CI | SQLite | T | P2 | With `-AllowLocalSystem`, `ObjectName` is unset/LocalSystem, the script emits the documented warning (`install-service.ps1:510-513`), and the DataDir ACL locks to SYSTEM + Administrators only |
| TRAY-50 | Idempotent reinstall/reconfigure | Functional | CI-leg | container-CI | SQLite | T | P2 | Running `install-service.ps1` twice with different `-Port` values leaves exactly one service; `nssm get MessageFoundry AppParameters` reflects the second port; no duplicate NSSM registration and no ACL drift (a second `icacls` snapshot equals the first except for the expected grants) |
| TRAY-51 | `-SuppressCrashDumps` never *enables* LocalDumps | PHI | CI-leg | container-CI | n/a | T | P2 | On a host with **no** `HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps` key, running with `-SuppressCrashDumps` leaves that key absent and writes only the `ExcludedApplications` values; on a host where LocalDumps exists, the per-image subkey gets `DumpType=0` + `CustomDumpFlags=0` (`install-service.ps1:237-251`) |
| TRAY-52 | Log rotation actually fires at ~10 MB | Functional | CI-leg | container-CI | SQLite | T | P2 | Drive enough synthetic traffic (or emit synthetic INFO lines) to pass 10 485 760 bytes on `service.out.log`; a rotated sibling appears and the live file restarts below the threshold; the service stays RUNNING throughout (`AppRotateOnline 1`) |
| TRAY-53 | Captured service log carries no message body at INFO | PHI | CI-leg | container-CI | SQLite | T | P2 | After the synthetic MLLP run, `service.out.log` contains no `MSH\|`, no `PID\|`, and no segment-delimiter run — i.e. the INFO-level capture is body-free, matching CLAUDE.md §9 |
| TRAY-54 | `uninstall-service.ps1` removal + fallback + no-op branches | Functional | CI-leg | container-CI | SQLite | T | P2 | After uninstall, `Get-Service MessageFoundry` errors (service gone) and the DataDir/logs remain (documented behaviour); running it again prints "not installed – nothing to do" and exits 0; with `nssm.exe` absent from PATH and cache, the `sc.exe delete` fallback (`uninstall-service.ps1:50-53`) removes the service |
| TRAY-56 | `import-db-ca.ps1` behaviour | Negative/Security | pytest (static + behavioural harness) | dev-PC | n/a | T | P2 | A malformed/non-certificate file is rejected without touching the LocalMachine Root store, and a second import of the same certificate is a no-op keyed on thumbprint — both assertions are unconditional. The `-WhatIf` half is conditional on the script declaring `SupportsShouldProcess`: if it does, `-WhatIf` must perform no write; if it does not, that is filed as a defect against the script (it writes to a machine-wide trust store with no dry run), **not** waived inside this row |

#### 13.4c — Part 13c: distribution & install

*18 rows — 14 T, 4 C; 0 P0.*

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| TRAY-10 | Windows hash-verified locked install | Functional | CI-leg | container-CI (windows-2025) | n/a | T | P1 | On a clean venv: `python -m pip install --require-hashes -r requirements.lock` exits 0, then `pip install -e . --no-deps` exits 0 and `messagefoundry --version` runs — i.e. the exact command pair `docs/SERVICE.md:26-33` prescribes |
| TRAY-11 | Built wheel carries the tray package, gui-script and all 18 icons | Compat | pytest | any | n/a | T | P1 | Over the built `dist/*.whl`: the zip listing contains `messagefoundry/tray/__main__.py`, all 18 names from `all_icon_filenames()` under `messagefoundry/tray/assets/`, and `messagefoundry-<v>.dist-info/entry_points.txt` contains a `[gui_scripts]` section with `messagefoundry-tray = messagefoundry.tray.__main__:main` (`pyproject.toml:202-203`) |
| TRAY-12 | Windows wheel install → tray launcher resolves and starts | Functional | CI-leg | container-CI (windows-2025) | n/a | T | P1 | In a clean venv from the built wheel: `Scripts\messagefoundry-tray.exe` exists; `python -c "import messagefoundry.tray.iconset as i, pathlib; assert all((i.ASSETS_DIR/n).is_file() for n in i.all_icon_filenames())"` exits 0 **from the installed package, not the repo**; launching `pythonw.exe -m messagefoundry.tray` produces a process that is still alive after 15 s and has written a `MessageFoundry tray … starting` line to `%LOCALAPPDATA%\MessageFoundry\tray.log`; `taskkill` exits it without a Windows error dialog |
| TRAY-13 | Icon assets resolve from the *installed* package, not `__file__` in the repo | Compat | pytest | any | n/a | T | P1 | A test that resolves the icon set through `importlib.resources` (mirroring `tests/test_packaging.py`'s `py.typed` approach) finds all 18 files; the existing repo-relative assertion in `tests/test_tray_iconset.py` is retained but no longer the only evidence |
| TRAY-57 | AV/EDR interaction with the branded launcher and interpreters | Compat | manual | W2025-box with Defender enforcing (+ one third-party EDR if available) | n/a | **C** | P1 | Record whether `ensure_branded_launcher` (copy interpreter → rewrite `RT_VERSION` → stage ~7 MB of DLLs) is blocked, delayed or quarantined; whether `pythonw.exe` or `MessageFoundryTray.exe` is quarantined; and the engine's own `python.exe`/`messagefoundry.exe`/`nssm.exe` behaviour. Outcome: `docs/ANTIVIRUS-FIREWALL.md` gains a tray section naming `pythonw.exe`, `MessageFoundryTray.exe`, `%LOCALAPPDATA%\MessageFoundry\` and the launcher-creation behaviour — or an explicit statement that the tray is out of scope for the endpoint-security handover |
| TRAY-58 | Windows Firewall prompts on first bind under the service identity | Compat | manual | W2025-box | SQLite | **C** | P2 | On first service start after install, record which listeners raise a Windows Defender Firewall prompt (or are silently blocked, since a service has no interactive prompt): API 8765, MLLP 2575, and any other configured inbound. Outcome is a firewall pre-stage step in `docs/SERVICE.md`/`docs/ANTIVIRUS-FIREWALL.md` |
| TRAY-59 | Offline / air-gapped install from a mirrored wheelhouse | Functional | manual + CI-leg | air-gapped W2025-box; container-CI for the resolve half | n/a | T | P2 | CI half: `pip download` the full extras set on a networked runner, then `pip install --no-index --find-links <dir> "messagefoundry[fhir,dicom,sqlserver,postgres,sftp,harness]"` in a fresh venv resolves with **zero** index hits (assert via `--no-index` succeeding, not by inspection). Box half: the same wheelhouse plus a pre-staged `nssm.exe` (`-NssmPath`) completes an install and a `/health` check on a host with no egress |
| TRAY-60 | Upgrade N → N+1 against a populated store | Upgrade | CI-leg + manual | container-CI; W2025-box for the service half | x3 | T | P1 | Install version N, drive ≥100 synthetic messages to `PROCESSED`, stop, install N+1, restart: the service starts, `GET /health` is 200, the pre-existing message count is unchanged, and no message moved to `ERROR` as a result of the upgrade |
| TRAY-61 | Rollback N+1 → N against the same populated store | Upgrade | manual | W2025-box (snapshot VM) | x3 | **C** | P1 | Following `docs/EARLY-ADOPTER-GUIDE.md:672-698`: re-pin the prior version, restart, and record precisely what works and what does not. Expected non-reversible store-level changes are enumerated in the run record rather than discovered at a customer. A green result means "documented, rehearsed and bounded", not "lossless" — which is exactly why this row is **C**: it yields a run record, not a threshold, so it cannot gate a release (TRAY-60 and TRAY-62 are the gating T rows beside it). It converts to **T** the day the owner records *which* store-level changes must be reversible |
| TRAY-62 | ≤0.2.5 → ≥0.2.6 config-ACL migration | Upgrade | manual | W2025-box | SQLite | T | P1 | An install created under ≤0.2.5 (config dir with inherited `BUILTIN\Users` write) upgraded to ≥0.2.6 either starts, or fails to start with the SEC-003 refusal message **and** the `docs/SERVICE.md` migration note resolves it via `-LockConfigDir`; a silent crash-loop to `SERVICE_PAUSED` with no actionable message is a fail |
| TRAY-63 | Reproducible wheel + sdist | Functional | CI-leg | container-CI | n/a | **C** | P2 | With `SOURCE_DATE_EPOCH` set from the tag's commit date, two independent `python -m build` runs in clean containers produce byte-identical `dist/*.whl` and `dist/*.tar.gz` (compare SHA-256). **C until Q5 is answered** — the row today carries an escape hatch (if reproducibility is deferred it becomes a doc fix splitting `docs/FEATURE-MAP.md:211` so Sigstore/SBOM read ✅ and reproducibility reads deferred), and a row that can discharge itself by editing a doc cannot gate a release. Answer Q5 "still committed" and it becomes **T** at the byte-identical criterion above |
| TRAY-64 | Consumer verification flow rehearsal | Functional | manual | dev-PC with Sigstore CLI + `gh` | n/a | T | P2 | The exact commands in `docs/INSTALL-GUIDE.md:105-120` succeed against a real pre-release tag: `gh attestation verify <wheel> --repo MEFORORG/MessageFoundry` passes, a relabelled/substituted file fails, and `pip install --no-index --find-links` of the verified wheel installs |
| TRAY-65 | Container image runtime posture assertions | Negative/Security | CI-leg | container-CI | SQLite | T | P2 | Against the built image: `docker inspect` shows `User` = `10001` and a `Healthcheck`; `docker run` with a non-loopback bind and auth off is **refused** by the startup bind guard; `PID 1` is `tini` (extends `docker-smoke`, `.github/workflows/ci.yml:1274+`) |
| TRAY-66 | k8s manifests apply to a real cluster | HA/Resilience | CI-leg | cloud (kind or k3s in CI) | x2 (Postgres for HA) | T | P2 | `kubectl apply -f docker/k8s/statefulset.yaml` reaches Ready and `/health` answers through the Service; `ha-postgres.yaml` reaches 3/3 Ready against a Postgres backend and a rolling restart never drops below `replicas - PDB.maxUnavailable`. Complements the shape-only `manifest-lint.yml:80-113`; does not replace it |
| TRAY-67 | `messagefoundry verify` gains a tray section and drops the retired-console rows | Functional | pytest + verify | any (pytest); W2025-box (verify) | n/a | T | P1 | `verify/runner.py:22 ALL_SECTIONS` includes a tray section; `--section tray` reports: tray package importable, all 18 assets resolvable, `messagefoundry-tray` on PATH, autostart on/off, the configured `engine_url` and whether the SCM read succeeded — and **no** PHI/workload field. `check_console_importable` (`checks.py:180-194`) no longer references PySide6 or a `[console]` extra; `tests/test_verify.py` covers both |
| TRAY-68 | Post-install service-identity checks in `verify` | Negative/Security | verify | W2025-box | x3 | T | P1 | On a real box, `messagefoundry verify` reports the service's `ObjectName`, `Start` type, and whether DataDir/logs/config ACLs exclude broad principals — as PASS/FAIL rows, not MANUAL. This closes the gap `docs/testing/VERIFY.md` names explicitly (store opens as the interactive user, not the service account) |
| TRAY-69 | Acceptance-matrix hygiene: retire `ACC:A7`, add tray rows | Functional | acceptance-probe | dev-PC | n/a | T | P2 | `harness/acceptance/matrix.py` row `ACC:A7` ("Console runs (Desktop Experience, PySide6)", `:153-160`) is removed or replaced by a tray row; `probe_console_gui` (`harness/acceptance/probes.py:170-179`) is retired or repointed and its `install the [console] extra` SKIP message (`:173`) is gone with it; new tray rows exist for launch, icon-set presence and autostart state, wired into `PROBES` (`probes.py:200-208`). **`ACC:F7` is deliberately untouched** — recon confirmed its probe reads `messagefoundry/service.py` for `CREATE_NO_WINDOW` and is current (§13.2's correction (c)); a row that "recaptions F7" would be churn |
| TRAY-70 | Shipped install docs name only real extras and real security posture | Negative/Security | pytest | any | n/a | T | P1 | `docs/SYSTEM-REQUIREMENTS.md:121` no longer says "install with the `console` extra" / "**Not browser-based**" for the operator console, `:129-130`'s "No native transport TLS" / "no MLLP-over-TLS" statements are corrected against shipped controls, `messagefoundry/verify/checks.py:187` and `harness/acceptance/probes.py:173` no longer name `[console]`, and `tests/test_install_instruction_provenance.py`'s `_EXTRA_REF` is widened to catch the prose form ``the `X` extra`` / `[X] extra` so the class cannot recur. The only PySide6 extra that exists is `harness` (`pyproject.toml:86-88`); there is deliberately no `[tray]` extra (`:89-92`) |

#### 13.4d — Part 13d: the standalone PySide6 test harness GUI (`harness/`)

*7 rows — 7 T, 0 C; 0 P0.* This part is new: the harness GUI is a **shipped distribution** (`packaging/messagefoundry-harness`, built every release by `release-harness`, `.github/workflows/release.yml:477`) and the plan's **only** instrument for hostile-input and outbound-fault injection, yet no chapter owned it. The panels' in-process behaviour is already well covered (§13.2's 13d block); these rows close the launch path, the sign-in dialog, the tabs' engine-facing halves and the wheel.
**Deliberately not scoped, with reasons:** (a) *pure-Qt layout and cosmetics* — widget placement, column widths, the `_spreadsheet.py` export formatting — perceptual, zero clinical consequence, and `QT_QPA_PLATFORM=offscreen` cannot judge them; (b) `harness/_async.py`, `harness/mllp.py` and `harness/file_transport.py` — the transport halves, already covered by `tests/test_harness.py` / `test_harness_faults.py` / `test_harness_file.py`; (c) the harness's **non-GUI** subpackages (`load/`, `reconcile/`, `acceptance/` scoring, the 2 266-line `__main__.py` CLI) — owned by PERF and STORE, see §13.1.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| TRAY-72 | Harness launches and tears down cleanly under `QT_QPA_PLATFORM=offscreen` | Functional | pytest | any (ubuntu + windows-2022 + windows-2025) | n/a | T | P1 | `python -m harness` (and the installed `messagefoundry-harness` console script) reaches a constructed `HarnessWindow` with **all five** tabs present in order — Send, Receive, File, Compose, Monitor (`harness/window.py:31-35`) — then a programmatic `close()` runs `shutdown()` on **every** panel (`window.py:41-50`) and the process exits 0 with **no** `QThread: Destroyed while thread is still running` on stderr and no non-daemon thread left alive. Deleting one panel from the shutdown tuple must turn the test red |
| TRAY-73 | Send and File tabs drive a real engine end to end | Functional | pytest | any | SQLite | T | P2 | Against a managed engine + API in a background thread (the `tests/test_harness_monitor.py` fixture pattern): a generator-seeded batch from the Send tab reaches `PROCESSED`, and a `FilePanel` drop into a watched inbound directory is picked up and dispositioned — the file panel's engine-facing half, which `tests/test_harness_file.py` (panel behaviour only) does not reach. Result rows in each tab match the engine's disposition counts |
| TRAY-74 | Compose hostile-input presets, end to end against a real engine | Negative/Security | pytest | any | SQLite | T | P1 | Both malformed presets — `_NO_MSH` and `_BAD_VERSION` (`harness/compose.py:50-54`, seeded via `_apply_preset` `:123-127`) — sent over MLLP with expectation **Reject**: the engine NAKs (AR for no-MSH, AE for the 2.3 message into a `validation.strict` inbound), the harness classifies the result as matching the expectation, and the store records `ERROR` with the **raw message preserved** — the count-and-log invariant holds for input that never parses. Both payloads are malformed *synthetic* HL7; no real capture may be used |
| TRAY-75 | Receive fault modes exercise the engine's at-least-once retry path | HA/Resilience | pytest | any | SQLite | T | P1 | With the engine's outbound pointed at the harness receiver, each `REPLY_MODES` entry (`harness/mllp.py:40` — AA/AE/AR/none plus `DELAY_AA`, `CLOSE`, `FAIL_THEN_AA`) produces the engine-side behaviour the reliability invariant promises: `CLOSE` and `AR` retry rather than dropping, `DELAY_AA` past the send timeout produces a **duplicate** the receiver's per-control-id counter sees (proving at-least-once, not exactly-once), `FAIL_THEN_AA` settles to `PROCESSED` after N failures, and nothing lands in dead-letter before the retry budget is spent. `tests/test_harness_faults.py` proves the receiver's half; this row proves the **engine's** |
| TRAY-76 | Sign-in dialog authenticates against a real engine | Functional | pytest | any | SQLite | T | P1 | Against an engine with auth **enabled**: `LoginDialog` (`harness/_login.py`) with valid local credentials calls `EngineClient.login`, `accept()`s, and the Monitor tab then populates; a 401 renders "Sign-in failed." and does **not** accept; `must_change_password` and `mfa_required` are surfaced on the dialog (`_login.py:88-107`) rather than swallowed; the provider list offers Active Directory only when `providers().ad` is true. No credential is written to any log or report |
| TRAY-77 | The `messagefoundry-harness` wheel builds, installs and runs | Compat | pytest + CI-leg | any (pytest over `harness-dist/*.whl`); windows-2025 for the install half | n/a | T | P1 | The `release-harness` build (`release.yml:477-530`) produces a wheel whose version **equals the engine's** `__version__` (lockstep, read from `messagefoundry/__init__.py` by `packaging/messagefoundry-harness/pyproject.toml`); the zip contains the whole `harness/` tree via the `force-include`, including `_console_widgets.py` and `_login.py`; `entry_points.txt` declares `messagefoundry-harness = harness.__main__:main`. In a clean venv, installing it pulls `messagefoundry[harness]` and `messagefoundry-harness --help` exits 0. A version skew between the two distributions is a fail |
| TRAY-78 | Rehomed console widgets construct and refresh | Functional | pytest | any | n/a | T | P2 | Every widget class exported from `harness/_console_widgets.py` (621 lines, rehomed from the retired desktop console — only `MessagesPanel` has coverage today, `tests/test_console_messages_refresh.py`) constructs offscreen and survives one refresh driven by a stubbed API snapshot, including the empty and error snapshots. This is dead-code detection as much as regression cover: a rehomed widget no tab instantiates should be deleted, not tested |

---

### 13.5 Detailed scenarios

#### S1 — TRAY-02/03/04/05: post-install security-posture assertions (new CI steps inside `windows-service-smoke`)

**Why narrative:** four P0 rows share one install; running them separately multiplies 2×-billed Windows minutes, and the ACL assertion is easy to write in a way that passes vacuously.

**Preconditions.** The existing `windows-service-smoke` job (`.github/workflows/ci.yml:1082-1262`) up to and including "Install the service". No change to the install invocation: `.\scripts\service\install-service.ps1 -AppExe $exe -LogLevel INFO -Environment prod -LockConfigDir` — i.e. the **default** run-as (no `-ServiceAccount`, no `-AllowLocalSystem`), which is what makes this the gate for the #224 virtual-account flip.

**Steps** (a new step inserted immediately after "Install the service", before "Start and verify /health"):

1. `$obj = (& nssm get MessageFoundry ObjectName)` — assert it equals `NT SERVICE\MessageFoundry` exactly. Fail on any other value, and fail explicitly if it matches `LocalSystem` or `.\LocalSystem`.
2. `$qc = & sc.exe qc MessageFoundry` — assert `$qc` matches `START_TYPE\s*:\s*2\s+AUTO_START` and `SERVICE_START_NAME\s*:\s*NT SERVICE\\MessageFoundry`.
3. For each of `C:\ProgramData\MessageFoundry` and `C:\ProgramData\MessageFoundry\logs`: `$acl = & icacls $path`. Assert the output contains `NT AUTHORITY\SYSTEM:`, `BUILTIN\Administrators:` and `NT SERVICE\MessageFoundry:`; assert it contains **none** of `BUILTIN\Users`, `Authenticated Users`, `Everyone`, `NT AUTHORITY\INTERACTIVE`; and assert no line carries the inherited marker `(I)` for a principal outside the allowed three (proving `/inheritance:r` at `install-service.ps1:132` ran).
4. For the config dir the install locked: `icacls <config>` must show `NT SERVICE\MessageFoundry:(OI)(CI)(RX)` and no `(W)`/`(M)`/`(F)` grant to a non-admin principal.
5. **Anti-vacuity receipt** — the step must fail if `icacls` returned nothing, if `$obj` is empty, or if `sc.exe qc` exited non-zero. A grep over empty output is the classic way this assertion silently stops testing.

**Observation point.** The step's own exit code. Do not infer posture from a later `/health` success — a LocalSystem service also answers `/health`.

**Expected result.** Green today (the code paths at `install-service.ps1:472-477` and `:526-548` are believed correct); the value is that a future `.ps1` edit turns it red. Verify that by mutating `install-service.ps1` on a scratch branch — remove the `-not $AllowLocalSystem` default block — and confirming step 1 fails.

**Cleanup.** None beyond the job's existing "Uninstall the service" step; the runner is ephemeral. Do **not** add a DataDir delete — the log-upload step (`:1250-1262`) depends on it.

---

#### S2 — TRAY-06/07/08: crash restart, throttle, and reboot persistence (destructive; snapshot VM for the reboot half)

**Why narrative:** two of these belong in CI, one cannot (a hosted runner will not survive a reboot), and the throttle test deliberately wedges the service.

**Preconditions.** *CI half:* the `windows-service-smoke` job with the service RUNNING and `/health` green. *Box half:* a disposable Windows Server 2025 VM with Desktop Experience, snapshot taken **after** a clean install and a green `/health`, so every rollback returns to a known state.

**Steps — TRAY-06 (CI, non-destructive):**
1. `$pid = (Get-CimInstance Win32_Service -Filter "Name='MessageFoundry'").ProcessId` — this is NSSM's PID; the engine is its child. Take the child: `$child = (Get-CimInstance Win32_Process -Filter "ParentProcessId=$pid").ProcessId`.
2. `Stop-Process -Id $child -Force`.
3. Poll `sc.exe query MessageFoundry` every second for 30 s; require `RUNNING`.
4. Poll `Invoke-RestMethod http://127.0.0.1:8765/health` for a further 30 s; require a 200.
5. Assert `service.out.log` gained a second startup banner after the kill (compare line counts before/after, or match the banner twice).

**Steps — TRAY-07 (CI, deliberately wedging; must be the *last* service step before uninstall):**
1. `nssm set MessageFoundry AppParameters "serve --config C:\does-not-exist --db … --env prod"`.
2. `nssm restart MessageFoundry`; sample `sc.exe query` every 500 ms for 30 s and record the transition timestamps.
3. Assert the gap between consecutive restart attempts is ≥ 5 s (the `AppThrottle 5000` at `install-service.ps1:464`) and that the service settles into `PAUSED` rather than looping faster.
4. Restore the original `AppParameters` before the uninstall step so the log-upload artefact is coherent.

**Steps — TRAY-08 (box, reboot):**
1. From the snapshot state, confirm `sc.exe qc MessageFoundry` shows `AUTO_START`.
2. `Restart-Computer -Force`.
3. Do **not** log in. From a second host: poll `http://<box>:8765/health` (only if the API is bound off-loopback for the test) **or** use a pre-created scheduled task at boot that writes `sc.exe query MessageFoundry` output to a file, then log in and read it.
4. Require RUNNING within 120 s of the OS reporting boot complete.

**Observation point.** `sc.exe query` state transitions and `/health`, never the tray icon — the tray is a *consumer* of this fact and must not be the instrument that proves it.

**Expected result.** RUNNING after both a crash and a reboot; throttled (not hot-looping) under a fatal config.

**Cleanup/rollback.** CI: restore `AppParameters`, then the job's existing uninstall runs. Box: restore the VM snapshot — do **not** attempt to hand-repair a `PAUSED` service on a shared box. PHI: the box carries synthetic traffic only; no store is exported.

---

#### S3 — TRAY-11/12/13: Windows wheel-install + tray-launch leg

**Why narrative:** it is the only proof that the tray's documented launch path (`docs/TRAY.md:22-37`) works, and it needs an interactive-ish Windows session plus a careful "did the process actually stay up" assertion.

**Preconditions.** A `windows-2025` runner (GitHub-hosted runners do have a station/desktop sufficient for `Shell_NotifyIcon` to return; the assertion below deliberately does not depend on a *visible* icon). The wheel built by the same workflow run (`python -m build`), not a PyPI download.

**Steps:**
1. `python -m venv $env:RUNNER_TEMP\wheelsmoke`; `& $env:RUNNER_TEMP\wheelsmoke\Scripts\pip.exe install (Get-ChildItem dist\*.whl).FullName`.
2. **Entry point:** assert `Test-Path "$env:RUNNER_TEMP\wheelsmoke\Scripts\messagefoundry-tray.exe"`. Assert the `dist-info` `entry_points.txt` inside the wheel zip declares it under `[gui_scripts]` (TRAY-11 can run as a pytest over `dist/*.whl` on any OS; this step is the Windows confirmation).
3. **Assets from the installed package:** `& …\Scripts\python.exe -c "import messagefoundry.tray.iconset as i; missing=[n for n in i.all_icon_filenames() if not (i.ASSETS_DIR/n).is_file()]; assert not missing, missing; print(i.ASSETS_DIR)"` — and assert the printed path is under `site-packages`, **not** the repo checkout. Without that second assertion the test can pass against the source tree and prove nothing.
4. **Launch:** `$p = Start-Process -FilePath "$env:RUNNER_TEMP\wheelsmoke\Scripts\pythonw.exe" -ArgumentList "-m","messagefoundry.tray" -PassThru`; `Start-Sleep 15`; assert `-not $p.HasExited`.
5. **Evidence of a real start:** assert `%LOCALAPPDATA%\MessageFoundry\tray.log` exists and contains `MessageFoundry tray` and `engine_url=` (the two lines `__main__.py:53` and `:66-71` write). If branding succeeded, the surviving process image will be `MessageFoundryTray.exe` — so resolve the *live* process by mutex-holder or by log evidence rather than by `$p.Id` alone (`__main__.py:47-50` re-execs and the parent returns 0).
6. **Teardown:** `Stop-Process` the tray process(es); assert the run left no non-zero exit recorded in `tray.log` (`log.exception("tray crashed")` absent).

**Observation point.** Steps 3, 4 and 5 together. Step 4 alone is insufficient — a tray that starts and immediately fails to load an icon can still be alive.

**Expected result.** All assertions pass. A hatchling change dropping `messagefoundry/tray/assets` fails step 3; a `gui-scripts` typo fails step 2; a `winshell` regression that raises fails step 5 (the `tray crashed` line).

**Cleanup.** Delete `$env:RUNNER_TEMP\wheelsmoke` and `%LOCALAPPDATA%\MessageFoundry`; the runner is ephemeral regardless.

---

#### S4 — TRAY-09: graceful drain on `nssm stop` with in-flight MLLP

**Why narrative:** timing-dependent and easy to run so that it proves nothing (stopping an idle engine always looks graceful).

**Preconditions.** `windows-service-smoke` at the point where `/health` is green and one synthetic ADT has already been recorded. The samples graph is the one the leg already serves.

**Steps:**
1. Start a background sender pushing synthetic ADTs continuously: repeat `python samples\send_mllp.py samples\messages\adt_a01.hl7` in a loop for ~10 s, counting sends. (Synthetic only — this file is the repo's own sample.)
2. While the loop is still running, record `$before = (Invoke-RestMethod http://127.0.0.1:8765/messages).total`.
3. Issue `nssm stop MessageFoundry` and time it. NSSM sends Ctrl+C and allows 15 s (`AppStopMethodConsole 15000`, `install-service.ps1:462`).
4. Assert the stop returned in **under** 15 s (a stop that consumes the whole window and then escalates is the failure mode) and that `service.out.log` ends with the uvicorn/lifespan shutdown lines, with no NSSM "terminating" escalation line.
5. `nssm start MessageFoundry`; wait for `/health`; assert `(Invoke-RestMethod .../messages).total -ge $before` and that no message carries an `ERROR` disposition attributable to the stop (query the disposition breakdown rather than eyeballing).

**Observation point.** Step 4's timing + log tail, and step 5's disposition breakdown. Total-count alone is not enough: the count-and-log invariant means a killed in-flight message would still be *counted*, just not `PROCESSED`.

**Expected result.** Clean drain, no `ERROR` rows, totals conserved.

**Cleanup.** The job's existing stop/uninstall/log-upload steps. Ensure the sender loop is terminated before the uninstall step so it does not hold the MLLP port.

---

#### S5 — TRAY-27/43: standard (non-admin) operator on a hardened, TLS-enabled box

**Why narrative:** this is the highest-value tray scenario and the easiest to mis-run — it requires *two* accounts and a TLS engine, and the current behaviour is asserted as correct by a passing test.

**Preconditions.** A W2025 box with: the service installed with `-LockConfigDir` and running under `NT SERVICE\MessageFoundry`; `[api].tls_cert_file` set in the engine's settings TOML so the loopback bind serves https; the engine certificate installed in **Local Computer → Trusted Root** (so the tray's `truststore` context can verify it); and a **separate standard (non-admin) interactive account**.

**Steps:**
1. Log on as the standard user. Launch `messagefoundry-tray`.
2. Confirm the unelevated SCM read works: the menu's status line names the service and a state other than `UNKNOWN` (this exercises `winsvc.query_scm_state` via the Interactive SID).
3. Confirm the registry hint read works: `%LOCALAPPDATA%\MessageFoundry\tray.log` records an `engine_url=` line derived from `AppParameters`.
4. **The trap:** because `-LockConfigDir` stripped inheritance, the standard user cannot read the engine's settings TOML, so `service_toml_uses_tls` (`config.py:204-218`) returns False and `build_engine_url` yields `http://…` (`config.py:241`). Observe what the tray renders while the engine is demonstrably healthy over https (confirm independently with `Invoke-RestMethod https://127.0.0.1:8765/health` from an elevated shell).
5. Record the rendered state, the tooltip and the menu enablement.
6. Apply the documented workaround: set `engine_url = "https://127.0.0.1:8765"` in `%LOCALAPPDATA%\MessageFoundry\tray.toml` (via the menu's Edit Tray Settings, which writes the commented template — `config.py:364-374`), Exit and relaunch. Confirm the tray now renders `RUNNING`.

**Observation point.** Step 4's rendered state versus ground truth from step 4's independent probe.

**Expected result today.** The tray shows `WEDGED` (SCM RUNNING, `/health` unreachable past the boot grace) with the tooltip "service up, API not responding" and **no hint** about the URL scheme — a false alarm on a healthy clinical interface. **Expected after TRAY-27 lands:** a distinguishable status naming the discovery failure and pointing at `tray.toml`.

**Cleanup.** Remove the `tray.toml` override if the box is a shared fixture; log off the standard account. No PHI is involved — the engine carries synthetic traffic only.

---

#### S6 — TRAY-60/61/62: upgrade → rollback rehearsal against a populated store

**Why narrative:** destructive, explicitly warned to be non-reversible at store level (`docs/EARLY-ADOPTER-GUIDE.md:695-697`), and the only way to find out what "rollback" actually means before a customer does.

**Preconditions.** A snapshot-capable W2025 VM. Two released versions N and N+1 available (wheel or tag). A full backup of the store **and** the encryption key taken as step 3 of the documented runbook — this is not optional, it is the runbook.

**Steps:**
1. Install version N per `docs/SERVICE.md`; start; confirm `/health`.
2. Drive ≥100 synthetic ADTs to `PROCESSED` (`python samples\send_mllp.py …` in a loop, or `messagefoundry generate` output — never redirect generate/dryrun output into a committed file or CI log; it can contain full bodies).
3. Record: message total, disposition breakdown, and `messagefoundry verify --section store,smoke --smoke self` output.
4. **Snapshot the VM.**
5. Follow the documented upgrade runbook: drain → `nssm stop` → back up store + key → `pip install "messagefoundry==<N+1>"` → `messagefoundry check` against the config → `nssm start` → verify.
6. Re-record the three metrics from step 3; assert the totals and dispositions are unchanged and `/health` is green.
7. **Rollback:** `nssm stop` → `pip install "messagefoundry==<N>"` → `nssm start`. Record precisely what happens: startup success/failure, any schema complaint, any message the engine refuses to read.
8. Write the outcome into the run record: what rolled back cleanly, what did not, and the exact recovery step used (config rollback via the audited `POST /config/reload`, or restore-from-backup).

**Observation point.** Steps 6 and 7's recorded metrics, plus the engine's startup log at each transition.

**Expected result.** Step 6 green. Step 7's result is *whatever it is* — the deliverable is the honest, bounded record, not a pass. A "pass" for this scenario means the rollback path is documented and rehearsed with its limits stated, not that it is lossless.

**Cleanup/rollback.** Restore the VM snapshot from step 4. Retain the run record. The store and its key never leave the box; both are synthetic.

---

#### S7 — TRAY-57: AV/EDR interaction with the branded-launcher creation

**Why narrative:** the behaviour under test (copy an interpreter, rewrite its version resource, stage 7 MB of DLLs into a shared `Scripts\` directory) is exactly what heuristic EDR flags, and the failure can take out the *engine*, not just the tray.

**Preconditions.** A W2025 box (or Win11 client) with Microsoft Defender real-time protection **enforcing** and no MessageFoundry exclusions applied. Optionally a second box with a third-party EDR. Delete any existing `Scripts\MessageFoundryTray.exe` and its staged DLLs so the creation path actually runs.

**Steps:**
1. Clear the Defender protection history (`Get-MpThreatDetection` baseline).
2. Launch `messagefoundry-tray` and let it complete the re-exec (`__main__.py:47-50` → `branding.relaunch_branded`).
3. Immediately record `Get-MpThreatDetection`, `Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational'` for the launch window, and whether `Scripts\MessageFoundryTray.exe` exists.
4. Check the engine's own binaries are untouched: `Test-Path .venv\Scripts\python.exe`, `pythonw.exe`, `messagefoundry.exe`, and `<DataDir>\bin\nssm.exe`.
5. Confirm the tray is running either branded (Task Manager image `MessageFoundryTray.exe`) or unbranded (`pythonw.exe`) — the fail-soft contract is that *one* of these is true, never neither.
6. Repeat with the exclusions from `docs/ANTIVIRUS-FIREWALL.md` applied plus the proposed tray additions, and record the difference.

**Observation point.** The Defender operational log for the launch window, plus step 4 and 5.

**Expected result.** Either no detection, or a detection on the *copy* with the tray degrading to unbranded and the engine binaries intact. A detection that quarantines the source `pythonw.exe` or `python.exe` escalates immediately to a docs change plus a decision on whether branding stays opt-in. **Note the row's class:** TRAY-57 is **C** — its deliverable is the recorded EDR behaviour and the resulting `docs/ANTIVIRUS-FIREWALL.md` change, so it does not gate a release; the single hard-fail condition above (an EDR that takes out the *engine's* interpreter) is escalated as a defect against the branding feature, not scored as a red test row. Answering Q9 converts it to **T**.

**Cleanup.** Restore any quarantined file from Defender history, remove the test exclusions if the box is shared, delete `Scripts\MessageFoundryTray.exe` and the staged DLLs.

---

#### S8 — TRAY-46: `Resolve-Nssm` auto-download and its fail-closed branch

**Why narrative:** it is the supply-chain integrity path for the binary that supervises a PHI-carrying service, it fires on every first-time install, and it has never executed under test (CI runners have `nssm` on PATH).

**Preconditions.** A clean W2025 box with **no** `nssm` on PATH and **no** `C:\ProgramData\MessageFoundry\bin\nssm.exe`; outbound HTTPS to `nssm.cc` permitted; elevated PowerShell.

**Steps (happy path):**
1. `Get-Command nssm -ErrorAction SilentlyContinue` returns nothing; `Test-Path C:\ProgramData\MessageFoundry\bin\nssm.exe` is False.
2. Run `.\scripts\service\install-service.ps1 -Environment prod -LockConfigDir` (plus whatever `-AppExe`/`-Config` the box needs).
3. Assert the console shows "NSSM not found - downloading https://nssm.cc/release/nssm-2.24.zip".
4. Assert `C:\ProgramData\MessageFoundry\bin\nssm.exe` now exists and that `(Get-FileHash -Algorithm SHA256 <the downloaded zip>)` matched the pin `727D1E42…6743` (`install-service.ps1:79`) — the script deletes the zip on success, so capture this by re-downloading and hashing separately, or by asserting the script did not throw.
5. Assert the install completed and the service registers.

**Steps (fail-closed path):**
6. Remove the cached `nssm.exe`. Pre-place a **corrupted** zip at `$env:TEMP\nssm-mefor-download.zip` — note the script overwrites it via `Invoke-WebRequest`, so instead simulate by temporarily editing `$NssmSha256` to a wrong value on a scratch copy of the script.
7. Run the scratch script. Assert it **throws** with "NSSM download failed integrity check", that the zip was deleted (`:104`), and that **no** service was registered.

**Observation point.** Steps 3-5 and 7. Step 7 is the one that matters: a fail-*open* here would install an unverified supervisor binary.

**Expected result.** Happy path installs; tampered path throws and leaves the box unchanged.

**Cleanup.** `.\scripts\service\uninstall-service.ps1`; delete `C:\ProgramData\MessageFoundry\bin\nssm.exe` and the scratch script copy; restore the box snapshot if one exists.

---

#### S9 — TRAY-74/75: the harness as the plan's hostile-input and outbound-fault instrument (13d)

**Why narrative:** these two rows are the only place in the whole plan where deliberately malformed HL7 enters a *running* engine and where a *misbehaving* outbound peer is simulated. Both are easy to run so they prove the harness rather than the engine — the trap is asserting the harness's own classification and stopping there.

**Preconditions.** A managed engine + API in a background thread (the fixture pattern `tests/test_harness_monitor.py` already establishes, auth disabled), with: one MLLP inbound at 2575 that has `validation.strict` on and a declared version of 2.5.1 (so the 2.3 preset is rejected on version, not on parse), and one outbound connection pointed at the harness's `MllpReceiver`. `QT_QPA_PLATFORM=offscreen`. All payloads synthetic.

**Steps — TRAY-74 (hostile input):**
1. Seed the Compose editor from the `No MSH segment` preset (`_NO_MSH`, `harness/compose.py:54`), expectation **Reject (AE/AR)**, transport MLLP; send.
2. Assert on **both** sides: the harness classifies OK (the reply code is in `_REJECT_CODES`), **and** the engine recorded the message with disposition `ERROR` and the raw preserved verbatim — a malformed message is counted and logged, never accepted-and-dropped.
3. Repeat with `Bad version (2.3)` (`_BAD_VERSION`, `:50-53`): expect AE from the strict inbound, `ERROR` in the store, and — this is the assertion that matters — **no** routed or outbound row was created for it.
4. Send the `Valid ADT^A01` preset with expectation **Accept** as the control; it must reach `PROCESSED`. Without the control, a globally-broken listener would make steps 2-3 pass for the wrong reason.

**Steps — TRAY-75 (outbound faults):**
5. Set the receiver's reply mode to `CLOSE` (`harness/mllp.py:238`); push one message; assert the engine retries rather than dropping, and that the outbound row is still pending (not dead-lettered) before the retry budget is spent.
6. `DELAY_AA` with `delay_seconds` above the engine's send timeout: assert the receiver's **per-control-id counter reaches 2** for a single sent message — the visible proof of at-least-once, and the reason routers/transforms must be pure.
7. `FAIL_THEN_AA` with `fail_first=2`: assert the message settles to `PROCESSED` after exactly three delivery attempts.
8. Confirm the engine's inbound totals are unchanged throughout — an outbound fault must never alter the received count.

**Observation point.** The **engine's** store dispositions and the receiver's duplicate counter together. The harness's own result table is corroboration, never the sole evidence: `tests/test_harness_faults.py` already proves the receiver behaves; these rows exist to prove the engine does.

**Expected result.** Malformed input → `ERROR` + NAK + raw preserved, with no downstream rows; outbound faults → retry, observable duplicate, eventual `PROCESSED`, inbound counts conserved.

**Cleanup.** The fixture tears the engine down; the harness window is closed through `HarnessWindow.closeEvent` so every panel's `shutdown()` runs (this is also TRAY-72's assertion). Nothing is written outside the pytest tmp path; all traffic is synthetic.

---

### 13.6 Automation disposition

**New pytest modules** *(all run on the existing ubuntu + windows-2022 + windows-2025 `test` matrix; win32-only bodies guarded like `tests/test_tray_winsvc.py` already does)*

| Module | Covers | Effort |
|---|---|---|
| `tests/test_tray_app.py` | TRAY-19 **(P0)**, TRAY-20 **(P0)**, TRAY-21, TRAY-23 — `TrayApp` wiring against a recording fake shell and stubbed `actions`/`control`/`autostart` | **M** |
| `tests/test_tray_pump.py` | TRAY-22 **(P0)** — `TrayShell._wnd_proc` dispatch table driven directly with synthetic `(msg, wparam, lparam)` tuples; a raising callback must not escape | **M** |
| `tests/test_tray_autostart_registry.py` | TRAY-17, TRAY-18 — real `winreg` writes against a scratch subkey, win32-guarded | **S** |
| `tests/test_tray_logging.py` | TRAY-16 — `_setup_logging` leaves `httpx` at ≥ WARNING; a simulated tick run writes no `HTTP Request:` lines | **S** |
| `tests/test_tray_wheel_contents.py` | TRAY-11, TRAY-13 — inspect `dist/*.whl` (skip if absent) for the tray tree, the 18 assets and the `[gui_scripts]` entry; plus an `importlib.resources` asset resolution mirroring `tests/test_packaging.py` | **S** |
| `tests/test_service_ps1_helpers.py` | TRAY-47, TRAY-56 — the pure PowerShell helper semantics (`SeServiceLogonRight` exact-SID token match, `Test-LooksLikeGmsa`, `import-db-ca.ps1` malformed/idempotent behaviour) driven through `pwsh -NoProfile -Command` with the script dot-sourced, win32-guarded and skipped where `pwsh` is absent | **M** |
| **13d** `tests/test_harness_launch.py` | TRAY-72 — `python -m harness` / `HarnessWindow` construct-and-close under offscreen; all five tabs in order; every panel's `shutdown()` runs; no surviving thread, no `QThread: Destroyed…` on stderr | **S** |
| **13d** `tests/test_harness_engine_flows.py` | TRAY-73, TRAY-74, TRAY-75 — the S9 scenario: Send/File tabs to `PROCESSED`, both Compose hostile presets to `ERROR` + NAK with the raw preserved, and every `REPLY_MODES` fault driven against a **real** engine outbound (reusing the managed-engine fixture from `tests/test_harness_monitor.py`) | **L** |
| **13d** `tests/test_harness_login.py` | TRAY-76 — `LoginDialog` against an auth-enabled engine: success, 401, `must_change_password`, `mfa_required`, AD-provider visibility | **M** |
| **13d** `tests/test_harness_wheel.py` | TRAY-77 — inspect `harness-dist/*.whl` (skip if absent): version == engine `__version__`, whole `harness/` tree force-included, `messagefoundry-harness` console script declared | **S** |
| **13d** `tests/test_console_widgets.py` | TRAY-78 — every widget exported from `harness/_console_widgets.py` constructs offscreen and survives a stubbed refresh (empty / populated / error snapshots); extends the single existing `tests/test_console_messages_refresh.py` | **M** |

**Extensions to existing modules**

| Module | Added | Effort |
|---|---|---|
| `tests/test_dependency_boundaries.py` | TRAY-14 — a second scan with a tray-specific allowlist (`messagefoundry.service`, `messagefoundry.service_status`, `messagefoundry.apiclient`, `messagefoundry.tray.*`) | **S** |
| `tests/test_tray_probe.py` | TRAY-24, TRAY-25 — no-credential client construction; fresh-context-per-call | **S** |
| `tests/test_tray_poller.py` | TRAY-15 — `poll_seconds` actually drives the non-pending cadence (or is gone) | **S** |
| `tests/test_tray_config.py` | TRAY-27 **(P0)** — unreadable-service-TOML path produces the operator-visible signal, replacing today's assertion that the silent http fallback is *correct* (`:274-287`) | **S** |
| `tests/test_tray_branding.py` | TRAY-28 — `_stage_runtime` logs a replacement | **S** |
| `tests/test_service_control_outcome.py` | TRAY-26 — the `WAIT_TIMEOUT`/`STILL_ACTIVE` branch | **S** |
| `tests/test_tray_shell.py` | TRAY-29, TRAY-30 — second-instance feedback; non-Windows clean refusal | **S** |
| `tests/test_verify.py` | TRAY-67 — the new tray section; the retired console rows | **M** |
| `tests/test_install_instruction_provenance.py` | TRAY-70 — widen `_EXTRA_REF` to the prose forms | **S** |
| `tests/test_release_pipeline.py` | TRAY-63 (if reproducibility is accepted) — assert `SOURCE_DATE_EPOCH` + a rebuild-and-compare step exist in `release.yml` | **S** |

**CI legs**

| Leg | Rows | Change | Effort |
|---|---|---|---|
| `windows-service-smoke` (`ci.yml:1082`) | TRAY-01..07, TRAY-09, TRAY-49..54 | Add the posture/crash/drain/rotation steps from S1, S2, S4; **and** re-gate so PRs touching `scripts/service/**`, `messagefoundry/service*.py`, `messagefoundry/tray/**` run it without the `MEFORORG` repository guard (nightly full-matrix stays) | **L** |
| **New** `windows-wheel-tray-smoke` | TRAY-10, TRAY-12 | windows-2025: build → clean-venv wheel install → entry point + assets + launch/exit (S3); plus the `--require-hashes -r requirements.lock` install currently ubuntu-only (`security.yml:71-77`) | **M** |
| `docker-smoke` (`ci.yml:1274+`) | TRAY-65 | Add `docker inspect` USER/HEALTHCHECK/tini assertions and the non-loopback-auth-off refusal | **S** |
| **New** `k8s-apply` (kind/k3s) | TRAY-66 | Apply both manifests to an ephemeral cluster; complements, does not replace, `manifest-lint.yml` | **L** |
| **New** `offline-wheelhouse` | TRAY-59 (CI half) | `pip download` all extras, then `--no-index --find-links` install in a clean venv | **M** |
| **New** upgrade leg inside `windows-service-smoke` or its own job | TRAY-60 (CI half) | Install N, populate, upgrade to N+1, assert counts/dispositions | **M** |
| `release.yml` | TRAY-63 (**C**) | `SOURCE_DATE_EPOCH` + rebuild-and-compare — **only if** 13.9 Q5 answers "still committed"; until then the row records a decision, it does not gate | **M** |
| `release-harness` (`release.yml:477`) | TRAY-77 | Extend the existing lockstep build with a clean-venv install of the harness wheel on windows-2025 and `messagefoundry-harness --help`; the version-equality check already exists (`:526`) and is asserted, not added | **S** |

**Harness / acceptance-probe capability**

| Change | Rows | Effort |
|---|---|---|
| Retire or repoint `probe_console_gui` (`harness/acceptance/probes.py:170-179`) and remove/replace matrix row `ACC:A7` (`matrix.py:153-160`). **`ACC:F7` is left alone** — its probe is current (§13.2 correction (c)) | TRAY-69 | **S** |
| New probes registered in `PROBES` (`probes.py:200-208`): `tray_installed` (package importable + all 18 assets resolvable + `messagefoundry-tray` on PATH), `tray_autostart` (Run value present/absent), `service_identity` (ObjectName + Start type), `service_acls` (broad-principal absence) | TRAY-67, TRAY-68, TRAY-69 | **M** |
| New matrix section rows for the tray so the acceptance runner scores it | TRAY-31..45 sign-off tracking | **S** |

**Stays manual — and why**

| Rows | Why it cannot be automated |
|---|---|
| TRAY-08 (reboot), TRAY-61 (**C**) / TRAY-62 (rollback, ACL migration) | Requires a real host reboot and snapshot/restore; a hosted runner cannot survive either. Effort **M** per rehearsal |
| TRAY-32/33/34 (real UAC prompt, count, cancel, z-order) | The consent prompt is a secure-desktop UI; ADR 0113 AC-4 defers it to manual QA by design. The *outcome* is already mockable and covered (`tests/test_tray_control.py`) — only the prompt itself is manual. **S** |
| TRAY-35/36/37/39 (live theme flip, High Contrast, DPI, Win11 tray-icon list name) | Visual/perceptual judgements about a notification-area icon; no headless assertion exists. TRAY-36 and TRAY-37 are **C** — they produce a written finding and a documented posture, and convert to **T** when Q7/Q8 are answered. **M** |
| TRAY-71 (multi-hour RSS + GDI/USER handle soak) | The leak only appears over hours of real `Shell_NotifyIcon` traffic on a real desktop session; a headless run never calls `LoadImageW`. Semi-automatable: a `Get-Process`/`GetGuiResources` sampler script plus a state-transition driver, run unattended on a box and its CSV attached to the release. Still **T** — the pass criteria are numeric. **M** |
| TRAY-38, TRAY-41, TRAY-42 (Explorer restart, logoff/FUS, session lock) | Shell and session-lifecycle events on a real interactive desktop with real user sessions. **M** |
| TRAY-43 (standard-user posture), TRAY-48 (gMSA), TRAY-46 (NSSM download) | Need a second interactive account, an AD domain with a provisioned gMSA, and a box with no `nssm` — none reproducible on a hosted runner. **M/L** |
| TRAY-55 (uninstall cleanliness), TRAY-57 (AV/EDR, **C**), TRAY-58 (firewall, **C**) | Endpoint-security products and per-user registry/profile state; automation would only test the automation. TRAY-57/58 record what a real Defender/EDR and the Windows firewall actually do and feed `docs/ANTIVIRUS-FIREWALL.md`; neither has a threshold, so neither gates a release (they are still team-run, so **C**, not **A**). **M** |
| TRAY-64 (Sigstore consumer flow) | Needs a real published pre-release tag and an external verifier's toolchain. **S** |

**Total rough effort:** pytest bucket **L** (11 new modules — 6 tray/service + 5 for part 13d — plus 10 extensions), CI bucket **L** (one re-gate + three new legs + three extensions, one of them on `release-harness`), acceptance-probe bucket **M**, manual bucket **L** (a ~25-item matrix run per release candidate, ~1.5 days on a prepared box, plus one unattended multi-hour soak for TRAY-71).

---

### 13.7 Environment, data & prerequisites

**Hosts**

| Host | Purpose | Must be procured / stood up |
|---|---|---|
| Windows Server 2022 **and** 2025, Desktop Experience, snapshot-capable VMs | NSSM install/identity/ACL, reboot + crash chaos, drain, upgrade/rollback, standard-user tray. Server Core **cannot** host the tray (no notification area) | Snapshot/restore is a hard requirement — TRAY-07 and TRAY-61/62 deliberately wedge or downgrade the box |
| Windows 11 client | The tray's real-world host: taskbar overflow promotion, per-monitor DPI, live theme switching, High Contrast, Win11 tray-icon list naming | Yes — a Server SKU's taskbar is not the surface operators use |
| A Windows box that can be left logged on, undisturbed, for ≥4 h | TRAY-71's RSS / GDI+USER handle soak with a state-transition driver | No new hardware — but it must be a box nobody logs off, and the sampler CSV is a release artifact |
| A host with **no** `nssm` on PATH and no `<DataDir>\bin\nssm.exe`, with egress to `nssm.cc` | TRAY-46 `Resolve-Nssm` | Can be a fresh snapshot of the W2025 VM |
| Air-gapped (no-egress) Windows host | TRAY-59 offline install | Yes — plus a mirrored wheelhouse built on a networked box |
| Kubernetes: kind/k3s in CI **plus** a real multi-node cluster for the HA manifest | TRAY-66 | The multi-node cluster is new; kind in CI is cheap |
| GitHub-hosted `windows-2022` / `windows-2025` runners | TRAY-01..07, 09, 10, 12, 49..54, and the install half of TRAY-77 | Already in use; the change is **budget** to run the service leg per-PR (path-gated) and to add a wheel/tray leg |
| **13d** No new host — the existing ubuntu + windows `test` matrix under `QT_QPA_PLATFORM=offscreen` (`ci.yml:218-231`) | TRAY-72..76, TRAY-78; TRAY-77's build half rides `release-harness` | Nothing to procure. What is needed is an **auth-enabled** managed-engine fixture (a local account with a known password, and one with `must_change_password`/MFA set) for TRAY-76 — today's harness fixtures run with auth disabled |

**Accounts & directory**

- **Local administrator** on each Windows host (service registration, `icacls`, `secedit`, HKLM WER keys).
- **A separate standard (non-admin) interactive account** on the same box — TRAY-43, and the only way to exercise the unelevated SCM/registry reads and a real UAC elevation.
- **An Active Directory domain + RSAT + a provisioned gMSA** (name ending `$`, host in `PrincipalsAllowedToRetrieveManagedPassword`) — TRAY-48. This is the error-1069 hunt.

**Devices & display**

- A multi-monitor setup with **mismatched** DPI scaling (e.g. 100 % + 200 %) and the ability to toggle **High Contrast** — TRAY-36, TRAY-37.
- VS Code installed on one box and absent on another — TRAY-45's two branches.

**Certificates**

- An internal-CA / AD-CS issued engine certificate **and** a self-signed one, plus the ability to install into **Local Computer → Trusted Root** — TRAY-25, TRAY-27, TRAY-43 (the tray verifies against the Windows trust store via `truststore`; there is no `verify=False` path).
- A throwaway client cert/key for the samples graph's mutual-TLS SOAP feed, as the existing CI leg already mints with `openssl req -x509 -newkey rsa:2048 …`.

**Security products**

- Microsoft Defender in **enforcing** mode, and ideally one third-party EDR (CrowdStrike / SentinelOne / Defender for Endpoint) — TRAY-57. Access to the Defender operational event log and protection history.

**Stores**

- SQL Server 2022/2025 and PostgreSQL instances for the store-backed halves of TRAY-60/61/62 and TRAY-66. **`docs/testing/WIN2025-TEST-PLAN.md` already owns provisioning these** — reuse, do not duplicate.

**Release/verification toolchain**

- PyPI Trusted Publishing OIDC configuration plus a pre-release tag path for TRAY-63/64 rehearsals.
- Sigstore CLI + `gh attestation` on the *verifying* side — TRAY-64.

**Synthetic data & generator commands** *(all PHI-free; never redirect `generate`/`dryrun` output to a committed file, ticket or CI log)*

```powershell
# The single-message sender the CI leg already uses.
python samples\send_mllp.py samples\messages\adt_a01.hl7

# Bulk synthetic ADTs for the drain (TRAY-09) and upgrade (TRAY-60) scenarios.
messagefoundry generate --help          # confirm flags on the installed wheel before scripting a loop

# Store encryption key + auth/egress/retention posture for a `prod`-environment service
# (the smoke leg's exact prerequisites — a prod PHI instance fail-closes without them):
$storeKey = (& messagefoundry gen-key).Trim()
nssm set MessageFoundry AppEnvironmentExtra `
  "MEFOR_STORE_ENCRYPTION_KEY=$storeKey" `
  "MEFOR_SECURITY_DELETE_MESSAGE_BODIES_AFTER_DAYS=30" `
  "MEFOR_RETENTION_DEAD_LETTER_DAYS=30" `
  "MEFOR_SECURITY_BLOCK_UNLISTED_OUTBOUND=true"
  # ...plus the MEFOR_EGRESS_ALLOWED_* allowlists the samples graph needs (see ci.yml:1160-1190)

# Regenerate the tray icon set (needs Pillow; only when the art changes).
python scripts\tray\make_icons.py

# On-box acceptance.
messagefoundry verify --config <config dir> --report-md verify.md --report-json verify.json
```

**Note on the `prod` environment.** Every on-box service scenario in this chapter installs with `-Environment prod`, matching the CI leg. That environment fail-closes without a store encryption key, bounded retention, and an egress allowlist — those are *prerequisites*, not test steps, and getting them wrong produces a crash-loop to `SERVICE_PAUSED` that looks like a service defect.

---

### 13.8 Exit criteria

This area is signed off for release when **all** of the following hold.

**Only T rows gate.** The six **C** rows (TRAY-36, 37, 57, 58, 61, 63) are complete when their finding, number or dated decision is **recorded and attached to the release**; a C row may never block a release, and may never be counted as coverage. Any C row whose threshold or decision has since been recorded must be re-classed **T** before the next release, not left as C to dodge the gate. There are no **A** rows in this chapter, so nothing here is deferred to an off-loopback release.

1. **Every P0 row is green — twelve of them, not eight:** the service/install set TRAY-01..TRAY-08 **and** the tray set **TRAY-19, TRAY-20, TRAY-22, TRAY-27**. TRAY-01's re-gate is demonstrated by a deliberate mutation to `install-service.ps1` on a scratch branch turning a PR red; the tray four are demonstrated by mutation too (swap two entries in the state→icon map, point one `Action` at the wrong collaborator, drop a `WM_` case from `_wnd_proc`, and make the service TOML unreadable — each must turn a test red).
2. **`windows-service-smoke` runs on every PR** that touches `scripts/service/**`, `messagefoundry/service*.py` or `messagefoundry/tray/**`, on at least one Windows Server SKU, in this repository and in any mirror — no `github.repository` guard on that trigger. The nightly two-SKU matrix is retained.
3. **The post-install posture step asserts, on every run:** `ObjectName == NT SERVICE\MessageFoundry`, `START_TYPE == AUTO_START`, and the absence of `BUILTIN\Users` / `Authenticated Users` / `Everyone` from DataDir, logs and the config dir — with the anti-vacuity receipt from S1 step 5.
4. **A Windows wheel-install + tray-launch leg exists and is green** (TRAY-10, TRAY-11, TRAY-12, TRAY-13), including the `site-packages` assertion that the asset check did not silently read the repo.
5. **The tray import contract is machine-enforced** (TRAY-14) and a deliberate `messagefoundry.config` import turns it red.
6. **Zero of these three doc/code disagreements remain open:** `poll_seconds` (wired or removed — TRAY-15); `tray.log` per-tick flooding versus `docs/TRAY.md:162` (TRAY-16); the second-instance "shows already running" checklist item versus `__main__.py:56-58` (TRAY-29). Each is closed by code **or** by an amended doc — never left contradictory.
7. **`messagefoundry verify` has a tray section and no retired-console rows** (TRAY-67), and `tests/test_verify.py` covers both. No shipped text names a `[console]` extra (TRAY-70).
8. **The tray manual-QA matrix has an owner, a home under `docs/testing/`, and a recorded run** against a release candidate covering TRAY-31..TRAY-45 with a per-item pass/fail/waived verdict and a named signer. The twelve items currently at `docs/TRAY.md:173-190` (the file's last line) are the seed, not the destination.
9. **Reboot + crash chaos rehearsed on a real box** (TRAY-06/07/08) with the run record attached to the release, and `ACC:G1` (`harness/acceptance/matrix.py:430-437`) stamped from that run rather than left permanently MANUAL.
10. **The upgrade → rollback rehearsal (TRAY-60/61/62) has been performed once** against a populated synthetic store, and `docs/EARLY-ADOPTER-GUIDE.md` §13 is updated with the *observed* limits — not only the predicted ones.
11. **The acceptance matrix scores the shipped surface:** `ACC:A7` no longer probes the retired PySide6 console, no shipped probe message names a `[console]` extra, and at least one tray row is present (TRAY-69). `ACC:F7` is verified current and deliberately unchanged.
12. **A decision is recorded (not necessarily implemented) for every open question in 13.9**, each either resolved or explicitly deferred with an owner and a date. Q1 (manual-matrix ownership), Q5 (reproducible build), Q6 (tray uninstall story) and Q13 (part 13d ownership + the auth-enabled harness fixture) block sign-off if left unanswered — the first three because each has a shipped artifact making a claim nothing backs, the fourth because it decides whether criterion 15 applies at all.
13. **No new PHI surface introduced:** `tests/test_tray_boundary.py` still passes unchanged, the tray still holds no credential (TRAY-24), and TRAY-53 shows the captured service log carries no message body at INFO.
14. **The tray does not leak** (TRAY-71): one multi-hour soak with forced state transitions is on record for the release candidate, with flat GDI/USER handle counts and RSS growth inside the stated bound. A soak that was not run is not a pass.
15. **Part 13d is owned and green:** the harness launches and tears down cleanly under offscreen (TRAY-72), the two Compose hostile presets reach `ERROR` + NAK with the raw preserved and the Receive fault modes produce the engine's retry/duplicate behaviour (TRAY-74, TRAY-75), the sign-in dialog works against an auth-enabled engine (TRAY-76), and the `messagefoundry-harness` wheel builds in lockstep and installs (TRAY-77). Until these hold, the plan's only hostile-input and fault-injection instrument is itself unverified — which would silently weaken every chapter that leans on it.

---

### 13.9 Open questions

1. **Who owns the tray's manual-QA matrix, and where does it live?** It exists only as a twelve-item checklist inside a user-facing document (`docs/TRAY.md:173-190`), is absent from `docs/testing/*`, and has no cadence, no sign-off record and no acceptance-matrix row. Should it become a section of `WIN2025-TEST-MATRIX.md`, or its own `docs/testing/TRAY-QA-MATRIX.md`? — *Blocks:* exit criterion 8, and whether TRAY-31..45 can be scheduled at all.

2. **Is `poll_seconds` a bug to fix or documentation to delete?** It is parsed, clamped, tested and documented, and never consumed (`poller.py:169` → `next_poll_seconds()` → hardcoded `POLL_BASE_S = 5.0`). — *Blocks:* TRAY-15's pass criteria (branch A versus branch B) and whether `TRAY_TOML_TEMPLATE` and `docs/TRAY.md:89` need edits.

3. **Does `windows-service-smoke` become a required per-PR check for the paths that change it, accepting the 2×-billed Windows minutes — or does the nightly stay the accepted risk with the mirror-only gap documented?** — *Blocks:* TRAY-01, and by extension exit criterion 2 and the credibility of every other service row (a green CI that never runs on a PR is not a gate).

4. **Is a Windows wheel-install + tray-launch leg in scope, or is the tray accepted as manual-verification-only forever?** The tray's only documented launch path is currently unverified end to end on any platform. — *Blocks:* TRAY-10/11/12/13 and exit criterion 4.

5. **Is "reproducible wheel/sdist" still a committed deliverable?** `docs/FEATURE-MAP.md:211` bundles it into one 🔨 row with Sigstore and SBOM, both of which are shipped and tested. Either add `SOURCE_DATE_EPOCH` + rebuild-and-compare, or split the row so the catalog stops making a claim no artifact backs. — *Blocks:* TRAY-63 and exit criterion 12.

6. **Does the product commit to an uninstall story for the tray's user-scope artifacts?** The `HKCU\…\Run` value, `%LOCALAPPDATA%\MessageFoundry`, and `Scripts\MessageFoundryTray.exe` + ~7 MB of staged DLLs all survive `pip uninstall messagefoundry` and `uninstall-service.ps1`. Options: a documented manual step, a `messagefoundry-tray --uninstall` flag, or an installer responsibility. — *Blocks:* TRAY-55 and whether it is a test row or a feature request.

7. **Is High Contrast an accessibility commitment?** ADR 0113 §3 states the shipped rendering model includes "a High-Contrast treatment"; `theme.py:18-33` exposes only LIGHT/DARK and never reads `SPI_GETHIGHCONTRAST`. Either build it or amend the ADR. — *Blocks:* whether TRAY-36 is a characterisation exercise or a defect.

8. **What is the supported DPI posture?** Is the tray declared DPI-unaware-and-OS-scaled (a documented limitation), or should it become per-monitor-v2 aware with icon reselection on `WM_DPICHANGED`? Today there is no manifest, no awareness call, and icons are cached by path forever (`winshell.py:280-290`). — *Blocks:* whether TRAY-37 can have a pass criterion at all.

9. **Should `docs/ANTIVIRUS-FIREWALL.md` gain a tray section?** Its process-exclusion table names `python.exe`, `messagefoundry.exe` and `nssm.exe` — not `pythonw.exe`, not `MessageFoundryTray.exe`, and it never describes the copy-interpreter-and-rewrite-version-resource behaviour that EDR heuristics target. — *Blocks:* TRAY-57's remediation half and TRAY-58's firewall pre-stage step; answering it converts both from **C** to **T**.

10. **Is air-gapped install a supported, tested configuration or a best-effort recipe?** Three shipped documents court air-gapped sites; the install path is two lines with no wheelhouse builder, no NSSM pre-stage runbook and no CI leg. — *Blocks:* TRAY-59's priority (P2 as written; P1 if supported).

11. **Should the container image be published to a registry (e.g. ghcr.io) with its own signature and SBOM, or does build-from-source remain the only supported container path?** No workflow contains a `docker push` / `build-push-action`. — *Blocks:* whether TRAY-65 needs a publish/verify half and whether ADR 0047 needs an amendment.

12. **Is `messagefoundry verify` the right home for tray and service-identity assertions** (a `--section tray`, plus post-install ACL/ObjectName checks), and can its stale PySide6-console rows be retired in the same pass? — *Blocks:* TRAY-67 and TRAY-68, and whether TRAY-69's probes duplicate them.

13. **Is part 13d's ownership ratified, and does the harness get an auth-enabled test fixture?** This chapter claims the harness GUI because no other chapter did, and because Compose/Receive are the plan's only hostile-input and outbound-fault instruments. Two consequences need a yes/no: (a) the harness GUI's rows sit in the TRAY release gate rather than PERF's, and (b) TRAY-76 needs a managed-engine fixture with **authentication on** (a local account, plus one with `must_change_password` and one MFA-enrolled) — every harness fixture today runs with auth disabled. — *Blocks:* TRAY-72..78 and exit criterion 15.

14. **Does `control_service_ex`'s 60 s wait need lengthening, or should a timeout render as "still in progress"?** Today a legitimately slow stop (15 s drain + busy store) over 60 s toasts "Service stop failed" for an action that succeeded — inviting an operator to re-issue a stop on a clinical interface. — *Blocks:* TRAY-26's expected result (fix versus document).
