# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Same-origin, read-only browser ops dashboard served under /ui (ADR 0065, BACKLOG #75).

A thin, zero-new-dependency surface: a stdlib autoescaping renderer (:mod:`._html`), page builders
(:mod:`.pages`), and cookie-based auth confined to /ui (:mod:`._auth`). The /ui routes are registered
by ``create_app`` (so they reuse the JSON route handlers + the single audited PHI path directly); this
package owns only rendering + the confined cookie session. It imports nothing from ``pipeline``/
``store``/``transports``/``config`` — only ``fastapi``, ``api.security``/``api.models``, and the pure
``parsing`` lib — preserving the one-way dependency rule (CLAUDE.md §4).
"""

from __future__ import annotations

from pathlib import Path

from . import pages
from ._auth import (
    COOKIE_NAME,
    UI_CSP,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_CHANGED_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    UiWriteAction,
    assert_same_origin,
    authorize_ui_ws,
    clear_session_cookie,
    is_safe_ui_action,
    is_unlock_action,
    lookup_ui_action,
    register_ui_action,
    require_ui,
    require_ui_reauth_only,
    require_ui_step_up,
    set_session_cookie,
    webauthn_rp,
)

__all__ = [
    "COOKIE_NAME",
    "STATIC_DIR",
    "UI_CSP",
    "WEBAUTHN_EXTRA_MISSING_NOTICE",
    "WEBAUTHN_RP_CHANGED_NOTICE",
    "WEBAUTHN_RP_MISSING_NOTICE",
    "UiWriteAction",
    "assert_same_origin",
    "authorize_ui_ws",
    "clear_session_cookie",
    "is_safe_ui_action",
    "is_unlock_action",
    "lookup_ui_action",
    "pages",
    "register_ui_action",
    "require_ui",
    "require_ui_reauth_only",
    "require_ui_step_up",
    "set_session_cookie",
    "webauthn_rp",
]

# The vendored static assets shipped in the wheel (mounted at /ui/static when serve_ui is on).
STATIC_DIR = Path(__file__).parent / "static"
