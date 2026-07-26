# MessageFoundry tray (Windows notification-area service-manager)

A tiny, unprivileged Windows tray app for the box running the engine as a
[Windows service](SERVICE.md). It shows engine status at a glance and gives you one-click access to
the things the browser console can't do from inside itself — **start / stop / restart the service**,
open the monitor console, open the repo in VS Code, and view the service log.

Design + rationale: [ADR 0113](adr/0113-windows-tray-service-manager-stdlib-ctypes-tokenless.md).
It is built on stdlib `ctypes` (no PySide6, no Qt) and the Qt-free `messagefoundry.apiclient`.

## It is not a second operator console

The tray reads exactly two credential-free signals — the local **service state** (Windows SCM) and
the **tokenless** `GET /health` — and deep-links to `/ui` for everything else. It **never** signs in,
holds a token, or shows a message body, queue depth, connection row, or throughput number. The
operator console remains the web console (`/ui`, [ADR 0065](adr/0065-zero-install-same-origin-browser-ops-dashboard.md)).
This boundary is frozen by a test (`tests/test_tray_boundary.py`) and by the tokenless-`/health`
guard (`tests/test_api_health_tokenless.py`) — widening it needs a new ADR.

## Launch

The tray ships **inside the `messagefoundry` wheel** — it is present on every `pip install
messagefoundry`, no repo checkout and no extra required. Installing the package puts a
`messagefoundry-tray` launcher on `PATH` (a `pythonw.exe`-backed GUI script → no console window):

```powershell
# any environment (or box) with `messagefoundry` installed:
messagefoundry-tray

# equivalent, if you prefer to be explicit about the interpreter:
pythonw -m messagefoundry.tray

# from a repo checkout, using the project's virtual environment:
.\.venv\Scripts\pythonw.exe -m messagefoundry.tray
```

`pythonw.exe` (not `python.exe`) launches with no console window — the `messagefoundry-tray` entry
point already resolves to it. The tray needs no elevation to run (service control prompts for
elevation per-action — see below). It is Windows-only at runtime; on any other OS `main()` prints a
friendly note and exits.

To **start it automatically at login**, use the tray's **Start at Login** menu item (opt-in, off by
default). It writes an `HKCU\…\Run` entry pinning the absolute `pythonw.exe` you launched with, so it
keeps resolving after a reboot.

## What the icon shows

A status-coloured disc, themed to your taskbar (light/dark), one per engine state:

| Icon | State | Meaning |
|---|---|---|
| 🟢 green | `RUNNING` | Service running and `/health` answering |
| 🟢 green (dev) | `RUNNING_UNMANAGED` | A dev `serve` is answering on the port, not the Windows service |
| 🟡 amber | `STARTING` / `STOPPING` | A service transition is in flight |
| ⚪ gray | `STOPPED` / `NOT_INSTALLED` | Service stopped, or not installed |
| 🔴 red | `WEDGED` | Service reports running but `/health` is not answering |
| 🟣 violet | `FOREIGN` | Something that isn't MessageFoundry answers on the port |
| ◻ slate | `UNKNOWN` | The service state could not be read |

Hover for a tooltip; the tray raises a brief balloon only on meaningful transitions (engine
came up, stopped unexpectedly, went unreachable), rate-limited so a crash-loop can't spam you.

- **Right-click / left-click** → the menu.
- **Double-click** → open the monitor console.

## Menu

- **Open Monitor Console** — opens `<engine_url>/ui` in your browser (disabled, with a hint, when the
  console isn't enabled — set `[api].serve_ui = true` in the service settings).
- **Open Repo in VS Code** — opens the engine repo folder via the `code` CLI.
- **Start / Stop / Restart Service** — drives the NSSM service; **Stop** and **Restart** ask for
  confirmation first (they halt message flow), then raise a single Windows **UAC prompt**. Cancelling
  the prompt is handled cleanly ("Action cancelled"). No standing admin rights are granted.
- **View Service Log** — opens the service's stdout log in your default viewer.
- **Start at Login** — the opt-in autostart toggle.
- **Edit Tray Settings** — writes a commented `tray.toml` template on first use (so the keys are
  self-documenting), then opens it in your default editor.
- **Exit** — quits the **tray only**; it never stops the engine.

## Configuration

Optional file at `%LOCALAPPDATA%\MessageFoundry\tray.toml` (all keys optional) — **"Edit Tray
Settings" creates a commented template here on first use**:

```toml
engine_url   = "http://127.0.0.1:8765"       # the engine's API base URL
service_name = "MessageFoundry"              # the NSSM service name
repo_path    = 'C:\Users\me\Code\MyEstate'   # the folder "Open Repo in VS Code" opens
poll_seconds = 5
```

When a key is absent the tray fills it in from sensible defaults and from the service's own NSSM
registry entry (`AppDirectory` → repo path, `AppParameters` → host/port), which a standard
interactively-logged-on user can read without elevation. Registry values are treated as untrusted
hints (validated, never executed).

**"Open Repo in VS Code" opens the wrong folder?** By default `repo_path` falls back to the *engine
service's* install directory (its NSSM `AppDirectory`). To open your own config/conversion estate
instead, set `repo_path` in `tray.toml` (edit it via the menu) and restart the tray.

## Why the icon is named "MessageFoundry Tray"

Windows names a notification-area icon in **Settings → Taskbar → Other system tray icons** after its
owning **process executable's** version info — not the tooltip. Launched as `pythonw -m
messagefoundry.tray` that would read "Python". So on first run the tray creates a branded launcher,
`MessageFoundryTray.exe`,
in the venv `Scripts\` directory (a copy of the base interpreter with its `FileDescription` rewritten
to "MessageFoundry Tray" and its runtime DLLs staged beside it, ~7 MB) and re-executes itself through
it. This is entirely **fail-soft**: if the branded launcher can't be created (AV block, read-only dir),
the tray just runs unbranded and is listed as "Python" — nothing else changes.

**Scope: the local single box.** If `engine_url` points at a **remote** engine, the tray degrades to
**monitor-only** — service control and Open-Repo are disabled (they are meaningless against a remote
host). Multiple engine shards / `supervise` are not supported by the tray.

## TLS engines (`[api].tls_cert_file`)

A loopback engine that terminates TLS is **fully managed** — https is not remoteness, and only the
host decides whether the tray offers Start/Stop/Restart and Open-Repo. (This was a bug before
2026-07-22: enabling TLS on the loopback bind used to grey those out and report the running engine
as down. See the ADR 0113 amendment.)

The tray discovers the scheme the same way it discovers host and port — from the service's NSSM
registry entry. There is no `serve` TLS flag, so it also reads the engine's own settings TOML
(`serve --service-config`, or `messagefoundry.toml` under the service's `AppDirectory`) and takes
exactly one fact from it: whether `[api].tls_cert_file` is set. That read is read-only and
fail-soft — a missing or malformed file just means "no TLS hint". Setting `engine_url` in
`tray.toml` overrides all of it.

The engine's certificate **is verified**, against the **Windows trust store**. So:

- an **internal-CA / AD-CS** engine cert works on a domain-joined box with no extra setup;
- a **self-signed** engine cert works once you import it into **Local Computer → Trusted Root
  Certification Authorities** on this machine.

There is no option to skip verification. If the certificate does not verify, the probe fails and the
tray reports the engine as down rather than trusting an unidentified responder — check the cert's
trust chain and that its subject matches the host in `engine_url` (`127.0.0.1` and `localhost` are
different SANs).

## Windows 11: promoting the icon out of the overflow

New tray icons land in the **overflow flyout** (the `^` chevron) by default. Only you can pin it to
the always-visible area: **Settings → Personalization → Taskbar → Other system tray icons** (or run
`ms-settings:taskbar`) and turn **MessageFoundry Tray** on. There is no API to do this for you.

## Regenerating the icons

The `.ico` assets under `messagefoundry/tray/assets/` are checked in and generated by a pure-stdlib script (no
Pillow needed at runtime or to regenerate):

```powershell
python scripts\tray\make_icons.py
```

The current art is a functional status-colour disc; a later pass can render richer glyphs without
any runtime change (the app only *loads* the files).

## Logs

The tray logs to `%LOCALAPPDATA%\MessageFoundry\tray.log` (rotating, INFO). It records startup, the
resolved config, state **transitions** (never per-tick), user actions, and elevation outcomes — and
never a message body, a token, or PHI (it has none by construction).

## Dependencies

The tray's only third-party dependency is `httpx` (via the shared `messagefoundry.apiclient`), with
`truststore` lazily imported only for an https engine URL. Both are **base** dependencies of the
`messagefoundry` wheel — the wheel-packaging change moved them out of the `[harness]`/`[dev]` extras,
and there is **no** `[tray]` extra — so the tray is present and runnable on every
`pip install messagefoundry`, no extra required (ADR 0113 wheel-packaging amendment; BACKLOG #239).

## Manual QA checklist (Windows-only behaviours)

The pure logic (state machine, menu, config, probe classification, elevation command shape) is
unit-tested and runs in CI; the interactive Windows-shell behaviours below need a desktop + an
installed `MessageFoundry` service and are verified by hand:

- [ ] Icon appears; tooltip + colour track the real service state (stop/start the service and watch).
- [ ] Start / Stop / Restart each raise **one** UAC prompt; **Restart** is a single prompt.
- [ ] Cancelling the UAC prompt → "Action cancelled", no state change.
- [ ] `Stop` / `Restart` show the confirm dialog first.
- [ ] Live taskbar light↔dark theme switch flips the icon (no invisible icon).
- [ ] `taskkill /f /im explorer.exe` then relaunch → the icon re-adds itself (`TaskbarCreated`).
- [ ] Launching a second instance shows "already running" and exits; the first keeps its icon.
- [ ] **Start at Login** toggles the `HKCU\…\Run` value; survives a reboot.
- [ ] Open Monitor Console is disabled (with a hint) when `serve_ui = false`; enabled when true.
- [ ] A dev `python -m messagefoundry serve` on the port with the service stopped → `RUNNING_UNMANAGED`.
- [ ] **Exit** removes the icon and leaves the engine service running.
- [ ] Log-off / shutdown removes the icon cleanly (no ghost after re-login).
