# ADR 0032 — Console desktop launch: a windowed gui-script + shortcut, not a command line

- **Status:** **RETIRED (2026-07-13) — the PySide6 desktop console is removed.** Superseded by the
  browser web console (`/ui`, `messagefoundry_webconsole`; [ADR 0065](0065-web-ops-dashboard.md),
  [BACKLOG #75](../BACKLOG.md)) as the sole operator UI, and by [ADR 0088](0088-apiclient-service-cli-extraction.md)
  (which extracted the Qt-free `apiclient/` + the `messagefoundry service` CLI). [BACKLOG #103](../BACKLOG.md)
  completed the deferred remainder — `messagefoundry/console/` deleted, the reusable Qt view widgets
  rehomed to `harness/`, the `[console]` extra renamed to `[harness]` (keyring dropped), and the
  `[project.gui-scripts]` windowed launcher + `scripts/console/` shortcut tooling removed. Everything
  below (Phase A's gui-script/icon/shortcut launch, and the retired Phase B frozen installer) is kept as
  the **historical record** — it no longer describes shipped code. See the *Amendment (2026-07-13) —
  desktop console retired* section at the end.

- **Superseded status (historical):** *Accepted (2026-06-20) — built (Phase A).* Phase A (the windowed
  `gui-script` entry point + the shortcut scripts) was the console's distribution path (`pip install
  messagefoundry[console]` + a clickable icon). Phase B (a frozen, zero-Python installer) was ratified
  Accepted (2026-06-28) and built, then **retired (2026-07-01) — superseded**, and its packaging assets
  + CI leg were removed — see the *Amendment (2026-07-01) — Phase B retired* section below (rationale:
  zero uptake, and the zero-install audience it targeted is now served by the browser ops dashboard,
  [BACKLOG #75](../BACKLOG.md)). The earlier *Amendment (2026-06-28) — Phase B* section is retained
  below **as the historical record of a now-superseded decision** — it no longer describes shipped code.
- **Built:** the `[project.gui-scripts]` `messagefoundry-console` entry point
  ([pyproject.toml](../../pyproject.toml)); the window/taskbar icon
  ([messagefoundry/console/__main__.py](../../messagefoundry/console/__main__.py) `_app_icon()` +
  `app.setWindowIcon`); the shipped badge
  ([messagefoundry/console/resources/app.ico](../../messagefoundry/console/resources/app.ico) +
  `app.svg` source + a stdlib packer [scripts/console/pack_ico.py](../../scripts/console/pack_ico.py));
  and the per-user/`-AllUsers` shortcut scripts
  ([scripts/console/install-console-shortcut.ps1](../../scripts/console/install-console-shortcut.ps1) +
  `uninstall-console-shortcut.ps1`).
- **Builds on (must not redesign):** the consumer deployment model — engine as a pinned, read-only
  installed wheel ([ADR 0017](0017-consumer-deployment-model.md)); the engine as a boot-start Windows
  service via NSSM ([docs/SERVICE.md](../SERVICE.md)); the console as a **separate process** reaching the
  engine only over the localhost HTTP API ([CLAUDE.md §2/§10](../../CLAUDE.md)); the console's existing
  `main()` entrypoint, login dialog, and OS-keyring token cache.

## Context

The engine is already invisible to operators: it runs headless as a boot-start NSSM service, so there is
nothing for a person to "launch" there. The one command-line wart is the **console** — today the only way
to open it is `python -m messagefoundry.console`, which assumes a developer who knows about venvs and
Python. [pyproject.toml](../../pyproject.toml) registered only a `[project.scripts]` CLI (`messagefoundry`),
no GUI launcher; there was no app icon, no shortcut, no installer.

The console is otherwise ready for a one-click launch: it defaults to the engine at `127.0.0.1:8765` (the
service), handles authentication in a sign-in dialog, and confirms engine health before showing a window.
So "make it easy" reduces to one well-scoped problem — **turn the console into a clickable icon** — without
touching the engine, the API boundary, or the deployment model.

## Decision

Ship **Phase A**: a windowed desktop launcher plus shortcuts, reusing the existing install flow's audience.

1. **Windowed entry point.** Add `[project.gui-scripts] messagefoundry-console = "messagefoundry.console.__main__:main"`.
   On Windows, `gui-scripts` produces a `pythonw`-backed `messagefoundry-console.exe` — **no flashing
   console window**, unlike `[project.scripts]`. `main()` already has the right shape (`argv=None` →
   `int`), so no entrypoint change.
2. **Branded window/taskbar.** Set `app.setWindowIcon()` from a multi-resolution `app.ico` shipped in the
   wheel (hatchling already packages everything under `messagefoundry/`). A missing/unreadable icon
   degrades to a null `QIcon` — it must never stop the console opening.
3. **Shortcuts.** `install-console-shortcut.ps1` drops Desktop + Start-Menu `.lnk`s pointing at the
   gui-script exe, carrying the badge. **Per-user by default (no elevation)**; `-AllUsers` writes
   machine-wide shortcuts and requires elevation (mirroring the service install). It auto-resolves the exe
   (repo `.venv`, then PATH) and the icon (packaged resource via the venv interpreter, then the repo copy).
4. **Python prerequisite stays.** Whoever sets up the box still installs Python + `pip install
   messagefoundry[console]` once — but that is the same operator who already runs the elevated NSSM service
   install, so it adds nothing to the end user's burden, and the end user never sees a terminal.

Shortcuts are **per-user** because a console shortcut is a per-user convenience that needs no
admin rights — unlike the machine-wide service, whose install is necessarily elevated.

## Options considered

- **A — gui-script + shortcut (CHOSEN).** Days of work; reuses the IT-assisted setup that already installs
  the service. ~90% of the "it's just an app" UX at a fraction of B's cost. The gui-script entry point is
  the exact thing B would wrap, so nothing here is throwaway.
- **B — frozen standalone installer** (PyInstaller/Nuitka/briefcase + Inno Setup/MSIX). True zero-Python:
  download an installer, click an icon. But ~150 MB+ bundle (PySide6 is large), **code-signing** to avoid
  SmartScreen/AV warnings, a new Windows CI build/sign leg, and **PySide6 LGPL relinking obligations** for a
  frozen binary. Weeks of work and risk for a step beyond what current adopters (who have IT + Python on the
  box) need. **Deferred to BACKLOG #39**, layered on top of A when a no-Python/no-IT site appears.
- **C — leave it as `python -m messagefoundry.console`.** Rejected: it is the command-line UX we are
  removing.

## Consequences

- A double-click icon opens the console; it connects to the local engine and prompts for sign-in with **zero
  arguments** in the common case. A non-default engine is `-Url` on the installer (off-loopback requires TLS,
  per the client's plaintext-to-remote guard).
- The wheel grows by one small `.ico` (~17 KB). The icon is regenerable from `app.svg` via Inkscape + the
  committed stdlib packer (see [resources/README.md](../../messagefoundry/console/resources/README.md)).
- `messagefoundry-console.exe` only appears after a (re)install that picks up the new entry point; the
  shortcut script fails clearly if it is absent.
- **Deferred (Phase B):** a frozen, signed, zero-Python installer — BACKLOG #39. Related future niceties
  (auto-create the shortcut from the service installer; a "start the engine for me" prompt when the service
  is absent) are also deferred, not built here.

## Non-goals

No frozen executable, MSI/MSIX, or code-signing (that is Phase B). No change to the engine, the localhost
API boundary, RBAC/auth, or the consumer deployment model. No "console as a service" — the console is and
remains an interactive, per-user desktop app.

## Amendment (2026-06-28) — Phase B: frozen, zero-Python console installer

- **Status (this amendment):** **Accepted (2026-06-28) — built (Phase B).** Ratified per the
  *Ratification decisions (2026-06-28)* below; the freeze spec + Inno Setup script + Windows CI leg +
  LGPL NOTICE are built under `packaging/console-installer/`, and the build leg is the
  `release-console-installer` job in `.github/workflows/release.yml` (`needs: release`, like
  `release-harness`).
  <!-- Proposed (no code yet) → Accepted (built) -->
- **Note on the AC-linked test references below:** the `→ tests/…` targets are the Lane-L2 stubs that
  ship with this build (`tests/test_release_console_installer.py`, `tests/test_license_notice.py`,
  `tests/test_frozen_launch_smoke.py`); the frozen-launch checks (AC-B4/AC-B5) run **only on the Windows
  installer CI leg** and skip elsewhere, as noted on each.
- **Date:** 2026-06-28
- **Related:** [ADR 0032](0032-console-desktop-launch.md) (Phase A, Accepted) · [BACKLOG #39](../BACKLOG.md) · [CLAUDE.md §2/§10](../../CLAUDE.md) · [release.yml](../../.github/workflows/release.yml) · [NOTICE](../../NOTICE) · MULTISESSION-PLAN-6 Lane L2

> This is a **Proposed amendment**, not a status change. Phase A of ADR 0032 stays **Accepted/built** and
> nothing in it is discarded — the `[project.gui-scripts]` `messagefoundry-console` entry point is exactly
> what the freezer wraps, `app.ico` is reused as-is, and the per-user/`-AllUsers` shortcut scripts remain.
> Phase B itself is a **new, unbuilt** distribution channel (freeze + installer + signing + a Windows CI
> leg + LGPL bundling) carrying open questions, so it cannot ride Phase A's Accepted status; it flips to
> Accepted only once the residual questions below are settled. **On ratification, update the file header's
> "Phase B is deferred — see *Consequences → Deferred (Phase B)*" pointer (lines 3–5) to point here**, so a
> reader does not hit a stale "deferred" line above this decision. (Note: `adr-analyze` reads ADR status
> from the *first* `Status:` line in the file — the Phase-A header — so until that header is reconciled the
> tool reports 0032 as `Accepted`; that is a documentation reconciliation, separate from this Phase-B gate.)

### Context

Phase A reduced the console to a clickable icon but kept one prerequisite: whoever sets up the box runs
`pip install messagefoundry[console]` once, which assumes Python + a venv on the machine. That is fine for
today's adopters (IT already touches the box for the elevated NSSM service install). Phase B is pulled
forward only for a site with **no Python and no IT involvement**, where the only acceptable UX is *download
an installer, click Next, get a Start-Menu icon*. The console is the one human-facing surface; the engine
stays invisible (a boot-start NSSM service), so this amendment concerns the console **only**.

**Invariants in play (must not break), and how freezing preserves them.** Freezing changes only *packaging*,
not imports or process topology, so the load-bearing CLAUDE.md rules survive untouched:

- **§2/§10 — console is PySide6, a separate process, and reaches the engine only via the HTTP API client.**
  Verbatim (§10): *"The console is **PySide6** (LGPL — chosen for OSS distribution; do **not** switch to
  PyQt). It is a separate process and reaches the engine **only through the HTTP API client**, never via
  in-process calls or the DB."* The frozen binary is still PySide6, still its own process, still API-only —
  a freezer wraps the existing `main()`; it does not change what the console imports or how it talks to the
  engine.
- **§4 — one-way dependency direction.** Engine packages (`pipeline/`, `transports/`, `parsing/`, `store/`,
  `config/`) never import `api/` or `console/`. Packaging the console touches none of those imports, so the
  rule is structurally unaffected (a GUI binary cannot reach into the pipeline).
- **§5/§9 — secrets come from the environment, never the repo.** The signing certificate lives only in CI
  secrets (see (c)), consistent with the engine's no-credential-in-repo posture.

The project is licensed **AGPL-3.0-or-later** ([pyproject.toml](../../pyproject.toml) `license`); the
existing [NOTICE](../../NOTICE) already invokes **AGPL §13** (network-use source offer). Both facts are
load-bearing for the LGPL analysis in (e).

### Decision

Freeze `messagefoundry.console` into a self-contained, **no-Python-required** Windows application and ship it
as a signed installer, built and signed by a Windows CI leg that attaches the installer as a release asset.
Five sub-decisions.

#### (a) Freeze toolchain — **PyInstaller** (`--onedir`)

- **PyInstaller, single-*folder* (`--onedir`), CHOSEN.** Most mature, best-documented PySide6 bundling (the
  Qt-for-Python docs treat PyInstaller as the reference path; its PySide6 hook pulls the right Qt
  plugins/`platforms\qwindows.dll`, ICU, and the `keyring` Windows backend). A single-folder layout keeps the
  **Qt DLLs as discrete, user-replaceable files** — the cleanest way to satisfy the LGPL relink expectation
  (see (e)) — and avoids the one-file variant's temp-dir self-extraction (slower start, more AV heuristic
  noise). Reproducibility: pin PyInstaller in the build leg and build from the same hash-locked deps as the
  wheel.
- **Nuitka — rejected (for now).** Smaller/faster, but the PySide6 story is finicky across versions, and
  compiling the application *into* the same binary as the LGPL Qt muddies the "relink against your own Qt"
  story `--onedir`'s loose-DLL layout makes obvious. Revisit only if startup/size becomes a real complaint.
- **briefcase — rejected.** Targets Toga + a cross-platform story we don't need; for a Windows-only PySide6
  console it adds abstraction without payoff.
- **Size posture:** ~150 MB+ (Qt6 core + widgets + platform/style plugins), accepted as the cost of "no
  Python on the box"; trimmed only by excluding unused Qt modules (QtWebEngine, QtMultimedia, Qt3D, …) via
  the spec file — **not** by switching away from PySide6 (§10).

#### (b) Installer — **Inno Setup**

- **Inno Setup, CHOSEN.** One `.iss` script wraps the `--onedir` output into a single `.exe` installer that
  (1) creates **Desktop + Start-Menu** shortcuts to the frozen `messagefoundry-console.exe` (same `app.ico`
  as Phase A's `.lnk`s) and (2) registers a proper **Add/Remove Programs** uninstall entry. It supports
  per-user (no-elevation) *and* per-machine installs, mirroring Phase A's per-user-default / `-AllUsers`
  posture. Free, scriptable in CI (`ISCC.exe`), no Store/packaging-identity ceremony.
- **MSIX — rejected (for now).** Clean install/uninstall + Store distribution, but it runs the app in a
  packaging container with filesystem/registry virtualization that complicates the **OS-keyring token cache**
  (Windows Credential Manager via `keyring`) the sign-in flow depends on (`_load_token`/`_save_token`,
  console/`__main__.py`), adds a packaging-identity/sideload-trust burden, and still needs its own signing.
  Deferred until that virtualization is proven harmless to the keyring.

#### (c) Authenticode signing — **sign both the frozen `.exe` and the installer**

- **Sign both artifacts** (the frozen `messagefoundry-console.exe` *and* the Inno Setup installer `.exe`)
  with an **Authenticode** code-signing certificate. An unsigned freshly-downloaded installer is the classic
  SmartScreen "Unknown publisher" + AV-false-positive trap; signing is what makes "download and run" work for
  the no-IT site this phase targets.
- **Certificate handling (hard rule, §5/§9).** The signing cert + key live **only in CI secrets**, never in
  the repo; the build leg imports the cert from a secret at sign time and never writes it to the workspace.
  An **EV/OV cert from a reputable CA** (ideally with SmartScreen reputation) is preferred; until one is
  provisioned the leg is wired but **signing is gated on the secret being present**, so the build still
  produces an (unsigned) installer artifact without failing.
- **Sidestep the crypto-inventory gate.** Do the signing in **pure CI tooling** (`signtool` invoked from the
  workflow), so **no Python helper imports `ssl`/`hashlib`/`hmac`/`secrets`/`cryptography`/`argon2`** — a new
  `.py` that did would trip the ASVS 11.1.3 crypto-inventory gate (a *required* CI leg AND a pytest test;
  `scripts/security/crypto_inventory_check.py` `INVENTORY`) and red CI until registered. Any new Python under
  `packaging/console-installer/` (e.g. a thin PyInstaller-spec helper) must still carry the
  `SPDX-License-Identifier: AGPL-3.0-or-later` header; if one ever must import a crypto module, register it in
  the inventory in the same change.
- Timestamp every signature (RFC-3161 TSA) so signatures outlive the cert's validity window.

#### (d) Windows CI **build + sign** leg → release asset

- Add a **Windows runner** leg (its own job; [release.yml](../../.github/workflows/release.yml) is
  `ubuntu-latest`-only) that: sets up Python 3.14, installs the package + `[console]` extra from the
  just-built wheel, **installs Inno Setup** (ISCC.exe is **not** pre-installed on `windows-latest` — install
  it via a pinned step/version) and ensures **signtool** is on PATH (Windows SDK), runs **PyInstaller**
  `--onedir`, runs **Inno Setup** (`ISCC.exe`), **Authenticode-signs** the exe + installer from the CI secret,
  and **uploads the installer as a release asset** (`gh release upload`), as the harness wheel is today.
- **Match the repo's CI conventions** (mirroring `release` / `release-harness`): workflow-level
  `permissions: {}` with least-privilege per job, pinned action SHAs, `persist-credentials: false`. Gated like
  the harness publish — the installer **builds every release** (artifact for inspection on
  `workflow_dispatch`), the **signing step is conditioned on the cert secret**, and **asset upload is
  tag-gated**. A Windows-leg failure is isolated (`needs: release`, like `release-harness`), so it never reds
  an engine release.
- **Reproducibility hole to close:** PyInstaller is pinned, but ISCC.exe and signtool are runner-provided
  external binaries; pin their install (version + source) in the leg so "reproducible alongside the wheel"
  holds for the installer, not just for PyInstaller.
- The leg is **additive** — the wheel + sdist + Sigstore + PyPI Trusted Publishing flow is untouched; the
  installer is a *fourth* artifact.

#### (e) PySide6 LGPL compliance for a frozen binary

The bundle combines an **AGPL-3.0-or-later application** (the console) with **LGPL-3.0 Qt** (PySide6 + the
Qt6 DLLs). LGPL-3.0 permits conveying the combined work under the GPL/AGPL, so the combination is licit; the
surviving LGPL obligation is that a recipient can **relink** the application against a modified/replacement
copy of the LGPL library. We satisfy it as follows:

1. **Loose Qt DLLs (relinking).** `--onedir` keeps `PySide6` and the Qt6 `.dll`s as separate, replaceable
   files in the install folder — a user can drop in their own compatible Qt build. (The concrete reason
   `--onedir` beat one-file and beat compiling Qt into a Nuitka binary.)
2. **Corresponding source / written offer.** The console source is already public under AGPL, and the
   existing [NOTICE](../../NOTICE) (shipped via `license-files = ["LICENSE", "NOTICE"]`) is **extended for the
   installer** to (a) name PySide6/Qt as **LGPL-3.0** components, (b) reproduce the **LGPL-3.0 + GPL-3.0**
   texts (LGPL is additional permissions over GPL) **and** the app's own **AGPL-3.0-or-later** text — an
   installer that shipped GPL-but-not-AGPL would mis-state the app's own license — and (c) carry a **written
   offer** for the Qt corresponding source. The installer **bundles this NOTICE + the three license texts**
   (an Inno Setup `[Files]` entry + a license page), so the obligation travels with the binary, not just the
   wheel. The existing NOTICE's **AGPL §13** clause binds the **engine service**, not this frozen *console
   client* (a client does not "run as a network-accessible service"), so the installer does not itself
   trigger a §13 source-offer beyond what the wheel already carries.
3. **No static-link trap.** We **keep PySide6** (§10) and do **not** statically link Qt; dynamic linking to
   the loose DLLs keeps the relink path open. A future Nuitka move would have to preserve this — flagged as a
   residual, not adopted.

### Acceptance Criteria

> EARS form; each links (`→`) to a `tests/…` file `adr-analyze` can resolve (its ref regex only matches
> `tests|fixtures|samples|harness` paths — workflow/`.iss`/README paths are named in prose for humans but are
> **not** `→` targets). The Windows-only frozen-launch checks run on the Windows CI leg (a frozen exe can't be
> exercised in the headless `pytest` suite); the static workflow/license assertions run in the normal suite.
> The linked test files are **net-new stubs to land in the same Lane L2 PR before this flips to Accepted**;
> until they exist `adr-analyze` will (correctly, advisory-only) report them as coverage gaps for a Proposed
> ADR.

- **AC-B1** — WHEN the release workflow runs on a Windows runner, THE SYSTEM SHALL produce a frozen
  `messagefoundry-console.exe` via PyInstaller `--onedir`.
  → `tests/test_release_console_installer.py::test_release_yml_runs_pyinstaller_onedir`
- **AC-B2** — WHEN the release workflow runs on a Windows runner, THE SYSTEM SHALL wrap the frozen output
  into an Inno Setup installer and upload it as a release asset.
  → `tests/test_release_console_installer.py::test_release_yml_builds_and_uploads_installer`
- **AC-B3** — IF the Authenticode signing secret is absent, THEN THE SYSTEM SHALL still build the unsigned
  installer artifact and SHALL NOT fail the release (the signing step is `if:`-gated on the secret).
  → `tests/test_release_console_installer.py::test_signing_step_is_secret_gated`
- **AC-B4** — WHEN the frozen exe is launched and the engine is unreachable, THE SYSTEM SHALL open the
  console window and surface the connection error rather than crash. (Mechanism: `_authenticate()` returns
  `True` on the unreachable probe — `client.providers()` raises `ApiError` with `status is None`, console/`__main__.py`
  ~L113–116, so the sign-in `LoginDialog` is *skipped* for an unreachable engine — then `client.health()`
  fails and `window._show_error("Cannot reach engine: …")` runs, ~L347–349; this offline path must survive
  freezing.)
  → `tests/test_frozen_launch_smoke.py::test_frozen_exe_opens_offline`  <!-- Windows CI leg only -->
- **AC-B5** — WHEN the frozen exe loads its window icon, THE SYSTEM SHALL resolve the bundled `app.ico` via
  `_app_icon()` (including its zip/odd-install bytes fallback, console/`__main__.py` ~L49–61) without raising,
  so the freeze layout does not silently lose the badge the wheel ships.
  → `tests/test_frozen_launch_smoke.py::test_frozen_exe_loads_app_icon`  <!-- Windows CI leg only -->
- **AC-B6** — THE SYSTEM SHALL exclude QtWebEngine, QtMultimedia, and Qt3D from the bundle (via the
  PyInstaller spec), bounding the ~150 MB size posture.
  → `tests/test_release_console_installer.py::test_pyinstaller_spec_excludes_heavy_qt_modules`
- **AC-B7** — THE SYSTEM SHALL bundle, inside the installer, the LGPL-3.0 + GPL-3.0 + AGPL-3.0-or-later
  license texts and a NOTICE naming PySide6/Qt as LGPL with a written offer for Qt corresponding source.
  → `tests/test_license_notice.py::test_installer_ships_lgpl_gpl_agpl_and_written_offer`
- **AC-B8** — WHEN the installer runs, THE SYSTEM SHALL declare Desktop + Start-Menu shortcuts and an
  Add/Remove-Programs uninstall entry. (Verified statically against the `.iss` `[Icons]`/`[Setup]`
  `Uninstall*` directives; live install/uninstall is a manual runner check documented in
  `packaging/console-installer/README.md`.)
  → `tests/test_release_console_installer.py::test_iss_declares_shortcuts_and_uninstall`

### Options considered

1. **Phase-B freeze: PyInstaller `--onedir` + Inno Setup + Authenticode, signed in a gated Windows CI leg
   (CHOSEN).** Mature PySide6 bundling, loose Qt DLLs that make the LGPL relink path obvious, a free
   scriptable installer with a real ARP uninstall entry, and a CI leg that mirrors `release-harness`'s
   isolation so it never reds an engine release.
2. **Nuitka / briefcase / MSIX — Rejected (for now).** Nuitka: finicky PySide6 + compiling Qt in muddies
   relink. briefcase: Toga/cross-platform abstraction we don't need. MSIX: container virtualization
   complicates the keyring token cache the sign-in flow depends on. Revisit per (a)/(b).
3. **Stay pip-only (Phase A only) — Rejected for the target site.** Fine where IT + Python already exist; it
   is exactly the prerequisite the no-Python/no-IT site cannot meet.

### Consequences

**Positive**
- A no-Python/no-IT site installs the console from one signed installer: Desktop + Start-Menu icons, a real
  Add/Remove-Programs uninstall, no SmartScreen "unknown publisher".
- Phase A is fully preserved and reused (gui-script entry, `app.ico`, shortcut model); the wheel/PyPI path is
  untouched. Pip-on-the-box adopters are unaffected.

**Negative / risks**
- A ~150 MB+ download and a Windows-only build leg with new tooling (PyInstaller, Inno Setup, signtool) to
  maintain and keep reproducible alongside the wheel — including pinning the **runner-provided** ISCC.exe +
  signtool, not just PyInstaller.
- A **code-signing certificate** is a real procurement + secret-rotation cost; until one exists the installer
  ships unsigned (and trips SmartScreen), so the no-IT value isn't fully realized until the cert lands.
- **Two distribution channels** (wheel + frozen installer) to version in lockstep and test; the frozen build
  can mask import/resource bugs the wheel wouldn't (e.g. `importlib.resources` path assumptions in
  `_app_icon()`), hence the launch + icon smoke tests on the runner (AC-B4/AC-B5).
- LGPL compliance is an ongoing obligation (the bundled NOTICE + written offer must stay current with the
  pinned Qt version), not a one-time checkbox.

**Out of scope** (unchanged from Phase A's Non-goals, plus Phase B specifics)
- No change to the engine, the localhost API boundary, RBAC/auth, or the consumer deployment model. The
  **engine NSSM install stays separate** — the installer ships the console only.
- No switch away from PySide6 (§10); no static Qt linking; no MSIX/Store packaging; no auto-update channel; no
  macOS/Linux frozen builds (Windows-only, matching the deployment target).
- Phase A's still-deferred nice-to-haves (auto-create the shortcut from the service installer; a "start the
  engine for me" prompt) remain deferred.

### Forward-reference artifacts (net-new; created by the Lane L2 build, must exist before Accepted)

- `packaging/console-installer/messagefoundry-console.iss` — the Inno Setup script (`[Files]` license bundle,
  `[Icons]` shortcuts, `[Setup]` uninstall).
- `packaging/console-installer/README.md` — runner verification + manual install/uninstall steps.
- The PyInstaller spec (under `packaging/console-installer/`) with the QtWebEngine/QtMultimedia/Qt3D excludes;
  any `.py` there carries the `SPDX-License-Identifier: AGPL-3.0-or-later` header.
- `tests/test_release_console_installer.py`, `tests/test_frozen_launch_smoke.py`,
  `tests/test_license_notice.py` — the AC-linked tests above.
- A new `release-console-installer` job in `.github/workflows/release.yml`.


---

## Ratification decisions (2026-06-28) — Phase B accepted

- **Freeze tool: PyInstaller** (most mature PySide6 bundling). **Installer: Inno Setup**, **per-user** default (no elevation, matching Phase A) with an opt-in all-users mode.
- **Authenticode: OV certificate minimum** (EV preferred for SmartScreen reputation). **The owner provisions the cert** — until then the CI build+sign leg produces an **unsigned** installer (clearly marked). This cert is the sole remaining gate on a fully-signed release asset.
- **CI runner:** pin the `ISCC.exe` (Inno) + `signtool` install steps so the installer is reproducible alongside the wheel; pin the bundled PySide6/Qt version for the **LGPL** NOTICE + written-offer accuracy.
- On the build lane, reconcile ADR 0032's Phase-A header pointer to reference this amendment (so `adr-analyze` reflects Phase B's state).

---

## Amendment (2026-07-01) — Phase B retired (frozen installer removed)

- **Status (this amendment):** **Accepted (2026-07-01) — Phase B retired / superseded.** Phase A stays
  **Accepted/built** and is unaffected. The frozen-installer channel (Phase B) — its packaging assets,
  CI leg, and AC-linked tests — has been **removed from the tree**. The *Amendment (2026-06-28) — Phase
  B* section above is kept as the historical record; it no longer describes shipped code.
- **Date:** 2026-07-01
- **Related:** [BACKLOG #39](../BACKLOG.md) (retired) · [BACKLOG #75](../BACKLOG.md) (browser ops
  dashboard — the successor for the zero-install audience) · [CLAUDE.md §2/§10](../../CLAUDE.md)

### Why retire it

A structured evaluation (2026-07-01) of expanding the console to a web app weighed the frozen installer
and found the channel is a maintained liability with no evidenced user:

- **No uptake.** The `release-console-installer` job **failed on every tag release since it merged**
  (v0.2.11–v0.2.14); exactly one `.exe` ever existed (v0.2.14, attached out-of-band, **0 downloads** on
  a private repo). It never delivered an artifact in-band.
- **Its demand gate never fired.** Phase B was reserved for a site with *no Python and no IT*
  (§Context above; [BACKLOG #39](../BACKLOG.md) "Why P3"). No such site materialized; current adopters
  are pip + IT-covered (IT already runs the elevated NSSM engine install), and the WIN2025 customer-test
  plan installs the console via `pip`, never the installer.
- **Its value gate was never met.** The OV/EV Authenticode cert was never provisioned, so every built
  installer shipped **unsigned** (SmartScreen "Unknown publisher") — the no-IT value in *Ratification
  decisions* was never realized.
- **Ongoing carrying cost.** Freezing on hosted runners drifts (runner-image Inno version, `signtool`,
  frozen-exe smoke) — two independent breakage modes across four releases — and the job's failures red
  the release workflow's run-level signal every time, even though the engine + harness ship fine.
- **The audience moved to the web.** [BACKLOG #75](../BACKLOG.md) (scheduled) serves the exact
  "viewable without a Python/desktop install" audience from the engine's own FastAPI app, so the
  installer's strategic rationale transfers to the browser dashboard rather than being lost.

### What was removed vs. what stays

- **Removed:** `packaging/console-installer/` (the PyInstaller `--onedir` spec + `console_launcher.py`,
  the Inno Setup `.iss`, `THIRD-PARTY-NOTICES.md`/`.txt`, and `licenses/`), the `release-console-installer`
  job in `.github/workflows/release.yml`, and the AC-linked tests (`tests/test_release_console_installer.py`,
  `tests/test_license_notice.py`, `tests/test_frozen_launch_smoke.py`). With the frozen binary gone, the
  Qt **LGPL** written-offer / bundled-license apparatus and the pending code-signing-cert procurement go
  with it.
- **Stays (untouched):** **Phase A** in full — the `[project.gui-scripts] messagefoundry-console` entry
  point, `app.ico`, and the per-user/`-AllUsers` shortcut scripts — and the `pip install
  messagefoundry[console]` distribution channel. The desktop console remains fully installable and
  supported; only the *frozen, zero-Python* conveyance is retired. PySide6 continues to be pulled from
  PyPI as an optional dependency (no bundled Qt), so no frozen-binary LGPL obligation remains.

### Reversibility

The freeze recipe survives in git history (this ADR + the removed files) and can be restored as a
one-off if a genuine no-Python/no-IT site appears before [#75](../BACKLOG.md) covers its needs.

---

## Amendment (2026-07-13) — desktop console retired (this ADR is RETIRED)

- **Status (this amendment):** **RETIRED (2026-07-13).** The whole PySide6 desktop console is removed;
  everything this ADR describes (Phase A's windowed gui-script launch + icon + shortcut installer) no
  longer describes shipped code. This ADR is kept as the historical record of the desktop console's
  launch model.
- **Date:** 2026-07-13
- **Related:** [BACKLOG #103](../BACKLOG.md) (the retirement) · [ADR 0065](0065-web-ops-dashboard.md)
  (the browser web console — the successor operator UI) · [ADR 0088](0088-apiclient-service-cli-extraction.md)
  (the reusable-core extraction: Qt-free `apiclient/` + `messagefoundry service` CLI) ·
  [BACKLOG #75](../BACKLOG.md) · [CLAUDE.md §2/§10](../../CLAUDE.md)

### Why retire it

Two operator clients (a PySide6 desktop app + the `/ui` browser console) doubled the maintenance,
parity, and security surface. The web console ([ADR 0065](0065-web-ops-dashboard.md), BACKLOG #75)
reached operator parity and is zero-install; the one genuinely browser-impossible capability — local
Windows service control — is CLI-shaped and already moved to `messagefoundry service {install,start,
stop,status}` (ADR 0088). Retiring the desktop app leaves **one** operator UI to build, test, and secure.

### What was removed vs. what stays

- **Removed:** the `messagefoundry/console/` package in full (all pages/widgets/icons/resources), the
  desktop-console tests (`tests/test_console_*.py`), the `[project.gui-scripts]` `messagefoundry-console`
  windowed launcher, `scripts/console/` (the shortcut installer + `pack_ico.py`), and the `[console]`
  optional-dependency group (renamed to `[harness]`, with `keyring` — the launcher-only OS-token cache —
  dropped).
- **Stays:** the browser **web console** as the sole operator UI; the Qt-free **`apiclient/`** client and
  the **`messagefoundry service`** CLI (ADR 0088); and **PySide6**, now scoped to the standalone **test
  harness** (`harness/`), into which the reusable Qt view widgets (`ConfigurableTable` / `MessagesPanel` /
  `MessageDetailPanel` / `LoginDialog`) were rehomed verbatim (`harness/_console_widgets.py`,
  `harness/_login.py`, `harness/_async.py`).

### Accepted parity losses

The desktop-only affordances that do **not** carry to the web console are accepted as retired: the
OS-keyring session-token custody, the interactive self-signed/mTLS trust prompt, the multi-shard
fan-out desktop view, and per-machine `QSettings` UI preferences. Local Windows service control is not
a loss — it moved to the CLI (ADR 0088).

### Reversibility

The desktop console survives in git history and can be restored if a concrete need reappears, but the
strategic direction is a single browser UI; no revival is planned.
