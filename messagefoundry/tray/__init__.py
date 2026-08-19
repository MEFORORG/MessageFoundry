# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MessageFoundry Windows tray service-manager (ADR 0113).

A tiny, unprivileged Windows notification-area app for the box running the engine as an
NSSM service: it shows engine status at a glance, opens the monitor console (``/ui``),
opens VS Code at the local repo, and start/stop/restarts the service.

It is **not** a second operator console (CLAUDE.md §10 / ADR 0065). It reads exactly two
credential-free signals — the local SCM service state and the **tokenless** ``GET /health`` —
and deep-links to ``/ui`` for everything else. It authenticates never, holds no token, and
renders no message body, queue depth, connection row, or throughput number. The boundary is
enforced by having no credentials at all.

Layering (ADR 0113 §1): this package may import only ``messagefoundry.apiclient`` and the
neutral, stdlib-only NSSM helpers ``messagefoundry.service_status`` (read) and
``messagefoundry.service`` (elevated control). It must never import ``pipeline``/``store``/
``transports``/``config``/``api`` (beyond the Pydantic models the apiclient returns), PySide6,
or FastAPI.

This module (``state``/``menu``/``config``) is the **pure** core — no I/O, no ctypes, no Qt —
so it is fully unit-testable on any OS. The Windows shell (message pump, SCM read, elevation)
lives in the sibling ``winshell``/``winsvc``/``poller``/``elevate`` modules.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.1.0"
