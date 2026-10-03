# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
neutral, stdlib-only engine modules ADR 0113 ratifies: the NSSM helpers
``messagefoundry.service_status`` (read) and ``messagefoundry.service`` (elevated control), and
the log backoff ``messagefoundry.log_backoff`` (amendment 2026-09-26), and the three log-scrub leaves
``messagefoundry.redaction``, ``messagefoundry.secretscrub`` and ``messagefoundry.controlchars``
that ``tray/logscrub.py`` composes for ``tray.log`` (amendment 2026-09-27), and
``messagefoundry.childenv``, which ``tray/branding.py`` starts its relaunch through and
``tray/autostart.py`` builds the login command with (amendment 2026-10-02). ``tray/config.py`` also
imports the stdlib-only ``messagefoundry.api_tls_source``, which the ADR does not list. The
package must never import ``pipeline``/``store``/``transports``/``config``/``api`` (beyond the
Pydantic models the apiclient returns), PySide6, or FastAPI.

This module (``state``/``menu``/``config``) is the **pure** core — no I/O, no ctypes, no Qt —
so it is fully unit-testable on any OS. The Windows shell (message pump, SCM read, elevation)
lives in the sibling ``winshell``/``winsvc``/``poller``/``elevate`` modules.
"""

from __future__ import annotations

__all__ = ["ENTRY_MODULE", "__version__"]

__version__ = "0.1.0"

#: The module that runs the tray. The login command (``autostart``) and the branded relaunch
#: (``branding``) both start it, so they name it from here.
ENTRY_MODULE = "messagefoundry.tray"
