# MessageFoundry Console — frozen Windows installer (ADR 0032 Phase B)

A **zero-Python**, standalone Windows installer for the MessageFoundry admin console. The console is
frozen with **PyInstaller** (`--onedir`) and wrapped in an **Inno Setup** installer that drops Desktop +
Start-Menu shortcuts and a real Add/Remove-Programs uninstall entry. No Python, venv, or `pip install`
is needed on the target machine.

This **layers on top of Phase A** (the `messagefoundry-console` gui-script + the
`scripts/console/install-console-shortcut.ps1` shortcut installer) and does not replace it. The pip-on-the-
box path is unchanged; this is for sites with **no Python and no IT** on the box. The engine NSSM install
is **separate** — this installer ships the **console client only** (it reaches the engine over the
localhost HTTP API at `127.0.0.1:8765`, exactly like the wheel-installed console).

## What's in this folder

| File | Role |
| --- | --- |
| `messagefoundry-console.spec` | PyInstaller spec — windowed `--onedir` freeze; icon = the Phase-A `app.ico`; bundles `console/resources/*` (badge) **and** `console/icons/*` (nav icons + brand lockup); excludes heavy Qt modules + engine-only deps. |
| `console_launcher.py` | Tiny SPDX-headed entry point the spec freezes (calls `messagefoundry.console.__main__:main`). |
| `messagefoundry-console.iss` | Inno Setup script — per-user default (opt-in all-users), shortcuts, uninstall, bundles the license texts. |
| `THIRD-PARTY-NOTICES.md` | LGPL/GPL/AGPL notices + the Qt-via-PySide6 written offer (LGPL compliance) — the authoritative copy installed next to the binary. |
| `THIRD-PARTY-NOTICES.txt` | Plain-text rendering of the notices, shown on the installer's license **wizard page** (Inno Setup's `LicenseFile` control renders only plain text / RTF, not Markdown). Kept in lockstep with the `.md`. |
| `licenses/` | Full `LGPL-3.0.txt` + `GPL-3.0.txt` (the project's AGPL `LICENSE` + `NOTICE` are added by the installer). |

The version is **single-sourced** from `messagefoundry/__init__.py` `__version__`; never hard-code it in
the `.iss` (the CI leg reads it and passes `/DAppVersion=...`).

## Build locally

Prereqs: Python 3.14 on PATH, and **Inno Setup 6** installed (so `ISCC.exe` exists). Run from the
**repo root**:

```powershell
# 1. Install the console + the freezer into a clean venv.
python -m venv .venv-freeze
.\.venv-freeze\Scripts\Activate.ps1
pip install ".[console]" pyinstaller

# 2. Freeze the console -> dist\messagefoundry-console\ (a ~150 MB folder: exe + Qt6 DLLs).
pyinstaller --noconfirm --clean packaging\console-installer\messagefoundry-console.spec

# 3. Read the single-sourced version and build the installer -> dist\messagefoundry-console-setup-<ver>.exe
$ver = python -c "import messagefoundry; print(messagefoundry.__version__)"
$iscc = "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe"
& $iscc "/DAppVersion=$ver" packaging\console-installer\messagefoundry-console.iss
```

`dist\messagefoundry-console-setup-<ver>.exe` is the installer. Double-click it to install; the wizard
shows the combined AGPL (app) + LGPL/GPL (Qt) license page, then offers a Desktop shortcut and a launch.

### Per-user vs. all-users

- **Default: per-user, no elevation** (matches Phase A's shortcut posture). Installs to the per-user app
  dir, per-user shortcuts.
- **All-users (per-machine):** run the setup with `/ALLUSERS` (or pick the scope in the wizard). Writes to
  Program Files + All-Users shortcuts and **prompts for elevation**.

## Signing — what's signed vs. unsigned

The CI leg (the `release-console-installer` job in `.github/workflows/release.yml`) **conditionally**
Authenticode-signs both the frozen `messagefoundry-console.exe` and the installer `.exe`:

- **Signed** when the repo secret `WINDOWS_SIGN_CERT_BASE64` (a base64 PFX; optional
  `WINDOWS_SIGN_CERT_PASSWORD`) is configured. signtool signs with a timestamp (RFC-3161) so signatures
  outlive the cert window.
- **Unsigned** (the default today) when that secret is absent — the leg **does not fail**; it produces an
  installer clearly marked UNSIGNED. An unsigned freshly-downloaded installer trips SmartScreen "Unknown
  publisher" / AV false positives, so this is a stop-gap.

**The signing cert is owner-provisioned.** Until the owner provisions an OV (EV preferred for SmartScreen
reputation) Authenticode certificate and adds it to CI secrets, releases ship the **unsigned** installer.
The cert lives only in CI secrets — never in the repo (CLAUDE.md §5/§9).

## CI / release

The installer is built by the **`release-console-installer` job in `.github/workflows/release.yml`** — a
job INSIDE the release workflow (a `windows-2025` runner; the rest of `release.yml` is Ubuntu), not a
standalone workflow. It has **`needs: release`**, mirroring `release-harness`, so the engine ships first
and the GitHub release (created by the `release` job's `gh release create`) **provably exists** before
this job's `gh release upload` attaches the installer to it — a standalone workflow on the same tag would
race release creation. It runs on:

- **`workflow_dispatch`** — builds the installer as an inspectable workflow artifact (no release upload).
- **a `vX.Y.Z` tag push** — builds the installer, signs it if the cert secret is present, and attaches it
  to that tag's GitHub release.

The console is **frozen from the same wheel** the `release` job built + smoke-checked (downloaded via the
`release-artifacts` upload and `pip install`ed with the `[console]` extra), so the frozen console and the
published PyPI wheel are byte-identical packaging — a source-vs-wheel resource bug can't slip through.

It is **additive and isolated**: it does not run on every PR (a ~150 MB freeze is expensive) and a failure
here cannot block the engine wheel/PyPI flow (that all completes in the `release` job before this starts).

To dispatch a dry-run build: **Actions → release → Run workflow** (the `release-console-installer` job
produces the `console-installer` artifact; the upload step is tag-gated and skipped on a dispatch).

## Manual install/uninstall verification (runner / reviewer checklist)

A frozen GUI exe can't be exercised in the headless `pytest` suite; verify these by hand (or on the
Windows CI leg / a test box) after a build:

1. **Install (per-user):** double-click `messagefoundry-console-setup-<ver>.exe`, accept the license,
   keep the Desktop-shortcut task. It installs without a UAC prompt.
2. **Launch:** the Start-Menu **and** Desktop shortcuts both open the console window (the badge icon
   shows in the title bar + taskbar). With no engine running, the window opens and surfaces
   "Cannot reach engine: …" rather than crashing (AC-B4).
3. **Add/Remove Programs:** "MessageFoundry Console" appears with the right version, publisher
   (MessageFoundry Organization), and badge icon; Uninstall removes the app + shortcuts cleanly (AC-B8).
4. **All-users:** re-run with `/ALLUSERS`; confirm it elevates, installs to Program Files, and creates
   All-Users shortcuts.
5. **License page + bundle:** the wizard's license page renders cleanly (plain text, not raw Markdown —
   it points at `THIRD-PARTY-NOTICES.txt`). `<install-dir>\licenses\` contains `LGPL-3.0.txt`,
   `GPL-3.0.txt`, `LICENSE-MessageFoundry-AGPL-3.0.txt`, `NOTICE-MessageFoundry.txt`, and both
   `THIRD-PARTY-NOTICES.md` (authoritative) + `THIRD-PARTY-NOTICES.txt` are next to the exe (AC-B7).
7. **Nav icons + brand:** the left-nav items all show their line icons and the header shows the brand
   logo-lockup (not the plain-text fallback) — confirms the spec bundled `console/icons/*`, not just
   `resources/*`.
6. **Signature (once a cert exists):** right-click the installer → Properties → Digital Signatures shows
   a valid, timestamped signature; SmartScreen does not flag it.

## Keeping the LGPL NOTICE current

`THIRD-PARTY-NOTICES.md` pins the bundled **PySide6/Qt version** (currently **6.11.1**, from
`requirements.lock`). The LGPL written offer is accurate only for the Qt version actually frozen — when
the PySide6 pin changes in `requirements.lock`, update the version and written offer in
`THIRD-PARTY-NOTICES.md` in the same change.
