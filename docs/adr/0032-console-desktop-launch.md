# ADR 0032 — Console desktop launch: a windowed gui-script + shortcut, not a command line

- **Status:** **Accepted (2026-06-20) — built.** Phase A (this ADR's only build) ships the windowed
  entry point + the shortcut installer. Phase B (a frozen, zero-Python installer) is **deferred** — see
  *Consequences → Deferred (Phase B)* and [BACKLOG #39](../BACKLOG.md).
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
