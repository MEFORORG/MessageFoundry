# Operator console + PySide6 harness Conventions

Moved verbatim from the root `CLAUDE.md` §10. A nested `CLAUDE.md` loads when Claude reads files
under `harness/`, so these Qt conventions no longer cost context in every session. Nothing changed
in the move.

The **operator console is the web console** (`messagefoundry_webconsole`, served same-origin at
`/ui`; ADR 0065) — the **PySide6 desktop console was retired** (BACKLOG #103, ADR 0032 retired). Do
**not** add new PySide6 operator surfaces. **PySide6** (LGPL — chosen for OSS distribution; do **not**
switch to PyQt) now backs only the **standalone test harness** (`harness/`), which is a separate
process reaching the engine **only through the HTTP API client** (`apiclient/`), never via in-process
calls or the DB. It may import the pure `parsing/` library for client-side HL7 rendering (see the root
`CLAUDE.md` §4 carve-out) and `api/`'s Pydantic models (which `api/__init__` exposes lazily so importing
them doesn't pull FastAPI or the engine into the GUI process).

The Qt conventions below apply to the **harness** GUI (and any Qt view code, e.g. the widgets rehomed
from the old console into `harness/_console_widgets.py` / `_login.py`):

- **GUI on the main thread only.** Background work (HTTP calls + periodic polling) runs off the main
  thread and updates widgets via **`Signal`/`Slot`** (PySide6 names, imported from `PySide6.QtCore`).
- Keep widget classes **thin** (view + wiring). Operational logic lives behind the engine API,
  not in slots.
- Headless Qt tests require `QT_QPA_PLATFORM=offscreen`.

(The engine's own concurrency is **asyncio**, not Qt threads — Qt threading applies to the
harness process only.)
