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
:data:`SUPPORTED_ENGINE_SEAMS` + :func:`assert_engine_seam`, so a NON-MATCHING engine fails LOUD at
startup (:class:`UiSeamMismatch`) rather than a raw ``TypeError`` from building the deps bundle.
"""

from __future__ import annotations

from pathlib import Path

#: Independent version root (NOT lockstep with the engine — that is the departure from
#: ``messagefoundry-harness``); its own tag / changelog / PyPI cadence. Starts matched to the engine.
__version__ = "0.2.15"

#: The engine seam this console build supports (``api._ui_seam.ENGINE_UI_SEAM``). Any other engine is
#: refused at startup — the runtime backstop behind the PEP 508 compat range.
# The console supports EXACTLY the engine seam it was built against — deliberately a single value,
# not a range (BACKLOG #279, resolved 2026-07-21 in favour of option (b)).
#
# It used to accept {2..N}, justified by "every new field has a default, so an older engine still
# renders on this console". That claim was never tested: CI installs ONE engine (HEAD) and runs the
# package suite against it, so N-1 of the N accepted seams were exercised by nothing. Worse, the two
# ways it silently stops being true — a new field WITHOUT a default, or a bare read of a new engine
# attribute where getattr-with-default was needed — do NOT trip this handshake, because the older
# engine's seam IS in the accepted set. The failure surfaced as a runtime AttributeError/TypeError on
# a live console instead of a loud refusal at startup, which is the opposite of what this gate exists
# for.
#
# Narrowing costs no extra per-bump work: a NEW seam was never in the old set either, so a bump has
# always required editing BOTH constants. It drops only the untested tail.
#
# If cross-seam support is ever genuinely wanted, re-widen this set AND add the CI matrix that
# installs the MIN and MAX supported engine builds — the claim and its test land together, or not
# at all.
SUPPORTED_ENGINE_SEAMS: frozenset[str] = frozenset({"266cbfd342b22819"})

#: The vendored static assets shipped in THIS wheel (mounted at /ui/static by :func:`mount_ui`).
STATIC_DIR = Path(__file__).parent / "static"


class UiSeamMismatch(RuntimeError):
    """Raised when the mounted console does not support the engine's ``ENGINE_UI_SEAM``."""


def assert_engine_seam(engine_seam: str) -> None:
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
    BROWSER_HARDENING_OPT_OUT_ENV,
    COOKIE_NAME,
    UI_CSP,
    WEBAUTHN_EXTRA_MISSING_NOTICE,
    WEBAUTHN_RP_CHANGED_NOTICE,
    WEBAUTHN_RP_MISSING_NOTICE,
    UiWriteAction,
    assert_not_cross_site,
    assert_same_origin,
    authorize_ui_ws,
    browser_hardening_enabled,
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
    "BROWSER_HARDENING_OPT_OUT_ENV",
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
    "assert_not_cross_site",
    "assert_same_origin",
    "authorize_ui_ws",
    "browser_hardening_enabled",
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
