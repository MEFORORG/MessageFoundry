# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""MessageFoundry web console — the same-origin browser ops dashboard, mounted onto the engine.

A separately-versioned second distribution (``messagefoundry-webconsole``) that the engine MOUNTS
in-process, same-origin, via one :func:`mount_ui` call from ``create_app``'s ``serve_ui`` tail (Option
B, ADR 0065). It owns the entire ``/ui`` surface — rendering, the confined ``mf_session`` cookie auth,
the write-action registry, and every ``/ui`` route — and reaches the reused JSON handlers through the
typed :class:`~messagefoundry.api._ui_seam.UiDeps` bundle the engine injects. It imports only
``fastapi``, ``messagefoundry.api.security``/``.models``/``.auth_models``/``._ui_seam``, ``messagefoundry.auth``,
and the pure ``messagefoundry.parsing`` lib — never ``pipeline``/``store``/``transports``/``config``
(CLAUDE.md §4).

The console pins itself against the engine's :data:`~messagefoundry.api._ui_seam.ENGINE_UI_SEAM` via
:data:`SUPPORTED_ENGINE_SEAMS` + :func:`assert_engine_seam`, so an out-of-range engine fails LOUD at
startup (:class:`UiSeamMismatch`) rather than a raw ``TypeError`` from building the deps bundle.
"""

from __future__ import annotations

from pathlib import Path

#: Independent version root (NOT lockstep with the engine — that is the departure from
#: ``messagefoundry-harness``); its own tag / changelog / PyPI cadence. Starts matched to the engine.
__version__ = "0.2.15"

#: The engine contract versions this console build supports (``api._ui_seam.ENGINE_UI_SEAM``). A pair
#: outside this set is refused at startup — the runtime backstop behind the PEP 508 compat range.
SUPPORTED_ENGINE_SEAMS: frozenset[int] = frozenset({1})

#: The vendored static assets shipped in THIS wheel (mounted at /ui/static by :func:`mount_ui`).
STATIC_DIR = Path(__file__).parent / "static"


class UiSeamMismatch(RuntimeError):
    """Raised when the mounted console does not support the engine's ``ENGINE_UI_SEAM``."""


def assert_engine_seam(engine_seam: int) -> None:
    """Fail LOUD if the engine's seam is not one this console supports (called BEFORE the engine
    builds :class:`~messagefoundry.api._ui_seam.UiDeps`, so a skew never surfaces as a raw kwargs
    ``TypeError``). A second identical assert runs inside :func:`mount_ui` (belt-and-suspenders)."""
    if engine_seam not in SUPPORTED_ENGINE_SEAMS:
        raise UiSeamMismatch(
            f"web console {__version__} supports engine UI seam(s) "
            f"{sorted(SUPPORTED_ENGINE_SEAMS)}, but the engine provides {engine_seam}; install a "
            "matching messagefoundry-webconsole (see the messagefoundry compat range)."
        )


# Re-export the security/rendering surface at the package root (the old ``api.webui`` __init__ shape),
# so callers/tests reach it as ``messagefoundry_webconsole.{is_safe_ui_action, authorize_ui_ws, ...}``
# and ``messagefoundry_webconsole.pages``. Both are leaf modules (no cycle with :mod:`.mount`).
from . import pages  # noqa: E402
from ._auth import (  # noqa: E402
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

# Bottom import breaks the __init__ <-> mount cycle: STATIC_DIR / assert_engine_seam above are already
# bound when mount.py imports them, and mount.py's eager route-module imports fire every
# register_ui_action so the write-action registry is authoritative before serving.
from .mount import mount_ui  # noqa: E402

__all__ = [
    "COOKIE_NAME",
    "STATIC_DIR",
    "SUPPORTED_ENGINE_SEAMS",
    "UI_CSP",
    "WEBAUTHN_EXTRA_MISSING_NOTICE",
    "WEBAUTHN_RP_CHANGED_NOTICE",
    "WEBAUTHN_RP_MISSING_NOTICE",
    "UiSeamMismatch",
    "UiWriteAction",
    "__version__",
    "assert_engine_seam",
    "assert_same_origin",
    "authorize_ui_ws",
    "clear_session_cookie",
    "is_safe_ui_action",
    "is_unlock_action",
    "lookup_ui_action",
    "mount_ui",
    "pages",
    "register_ui_action",
    "require_ui",
    "require_ui_reauth_only",
    "require_ui_step_up",
    "set_session_cookie",
    "webauthn_rp",
]
