# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Emit a STABLE, deterministic text snapshot of the engine-side seam contract the web console
(``messagefoundry-webconsole``, Option B / ADR 0065) depends on.

This is the enforced version-skew HANDSHAKE. The console is separately versioned and pins itself
against ``api._ui_seam.ENGINE_UI_SEAM``; a silent, incompatible change to the injected contract
(a renamed handler field, a re-signatured ``api.security`` dep, a DTO field the console renders that
was renamed) would break the console at RUNTIME within a supported seam — mypy at the engine's
``deps = UiDeps(...)`` site catches builder-signature drift, but NOT a Pydantic DTO field rename
(that breaks render, not import). The engine test ``tests/test_webconsole_seam_snapshot.py``
regenerates this snapshot and diffs it against the golden ``tests/golden/webconsole_seam.snapshot``,
failing CI on any unbumped incompatible change.

The snapshot captures four things:
  1. ``ENGINE_UI_SEAM`` (the integer both sides pin against);
  2. the ``api._ui_seam`` dataclass field names (``UiDeps`` / ``CoreHandlers`` / ``AdminHandlers``)
     via ``dataclasses.fields`` — the injected handler/reference bundle shape;
  3. a CURATED, explicit list (kept below) of the cross-seam surface the console consumes OUTSIDE the
     injected bundle: the ``api.security`` deps it imports (names + signatures), the ``AuthService``
     methods it calls (names + signatures), and the ``app.state`` attributes it sets/reads;
  4. the ``api.models`` / ``api.auth_models`` DTO FIELD SETS the console renders (introspected live,
     so a field rename on exactly those DTOs changes the snapshot).

Run ``python scripts/webconsole_seam_snapshot.py`` to print the current snapshot; redirect it over the
golden to refresh it after an intentional, seam-bumped contract change.
"""

from __future__ import annotations

import dataclasses
import inspect
from typing import Any

from pydantic import BaseModel

from messagefoundry.api import auth_models, models, security
from messagefoundry.api._ui_seam import (
    ENGINE_UI_SEAM,
    AdminHandlers,
    CoreHandlers,
    UiDeps,
)
from messagefoundry.auth.service import AuthService

# --- CURATED seam surface (item 3) -------------------------------------------------------------
# These lists are the explicit, reviewed contract the console consumes OUTSIDE the injected UiDeps
# bundle. Adding/removing an entry here is itself a deliberate seam change (bump ENGINE_UI_SEAM +
# SUPPORTED_ENGINE_SEAMS, refresh the golden). Kept in sync with the package's actual imports/usage.

# api.security's public dep surface the console imports DIRECTLY (not via UiDeps) — a re-signature
# here breaks the console outside the type-checked construction site, so it is seam-scoped.
_API_SECURITY_SYMBOLS: tuple[str, ...] = (
    "authorize_ws",
    "get_auth",
    "require",
    "require_reauth_only",
    "require_step_up",
    "ws_token",
)

# AuthService methods the console calls on the service returned by get_auth(request) / require_ui*.
_AUTH_SERVICE_METHODS: tuple[str, ...] = (
    "allow_login_attempt",
    "allow_phi_read",
    "audit_kerberos_reject",
    "audit_permission_denied",
    "authenticate_kerberos",
    "begin_webauthn_assertion",
    "begin_webauthn_registration",
    "confirm_mfa_enrollment",
    "delete_webauthn_credential",
    "finish_webauthn_assertion",
    "finish_webauthn_registration",
    "flag_new_client_ip",
    "has_recent_step_up",
    "identity_for_token",
    "list_sessions",
    "login",
    "logout",
    "mfa_satisfied",
    "mfa_status",
    "reauth",
    "revoke_other_sessions",
    "revoke_own_session",
    "verify_mfa",
    "webauthn_available",
)

# app.state attributes the console SETS in mount_ui (ui_*) and READS via get_auth / _auth.py.
# ``exposure_protected`` is a READ-ONLY, backward-compatible SOFT dependency: the console reads it
# via ``getattr(app.state, "exposure_protected", False)`` in ``_auth.effective_https`` (proxy-TLS
# cookie-name + /ui hardening keying), so an engine lacking it degrades gracefully rather than
# breaking. It is curated here so a future engine RENAME becomes a reviewed seam change — but it
# does NOT bump ``ENGINE_UI_SEAM``: a graceful-default read stays compatible with every seam, and a
# bump would make a newer engine REFUSE an older console wheel (``SUPPORTED_ENGINE_SEAMS == {1}``).
_APP_STATE_ATTRS: tuple[str, ...] = (
    "auth",
    "exposure_protected",
    "public_origin",
    "ui_connections_render",
    "ui_csp",
    "ui_ws_authorize",
    "webauthn_rp_from_request",
)

# api.models DTOs the console renders (import sites in messagefoundry_webconsole/**). Field sets are
# introspected live below, so a rename on one of these breaks the snapshot (the silent-drift guard).
_API_MODELS_DTOS: tuple[str, ...] = (
    "AlertInstanceInfo",
    "AlertInstanceList",
    "AlertsConfig",
    "AttachmentInfo",
    "ClusterNodeList",
    "ClusterStatus",
    "ConfigProvenance",
    "ConnectionEventInfo",
    "ConnectionRow",
    "DeadLetterList",
    "DeadLetterReplayRequest",
    "DrStatus",
    "IntegrityResult",
    "MessageDetail",
    "MessageList",
    "MessageSearchResults",
    "PendingApprovalResponse",
    "ReloadRequest",
    "ReloadResult",
    "SecurityPosture",
    "ServiceStatusInfo",
    "StatsResetRequest",
    "StatsResetTarget",
    "SystemStatus",
)

# api.auth_models DTOs the console renders.
_API_AUTH_MODELS_DTOS: tuple[str, ...] = (
    "AdGroupMap",
    "AdGroupMapEntry",
    "AdGroupScopeEntry",
    "AdGroupScopeMap",
    "AuditList",
    "ChannelScope",
    "CurrentUser",
    "CustomRoleInfo",
    "CustomRoleRequest",
    "MfaStatusResponse",
    "PasswordChangeRequest",
    "RoleInfo",
    "RolesUpdateRequest",
    "SecurityEventsList",
    "UserCreateRequest",
    "UserSummary",
    "UserUpdateRequest",
)

_HEADER = (
    "# messagefoundry-webconsole ENGINE SEAM CONTRACT SNAPSHOT",
    "#",
    "# Deterministic serialization of the engine-side contract the web console depends on (ADR 0065).",
    "# Regenerate with: python scripts/webconsole_seam_snapshot.py",
    "# This is a GOLDEN gate: any diff means the seam contract changed - see the test's failure hint.",
)


def _dataclass_fields(dc: type) -> list[str]:
    """Field names in declaration order (the injected bundle shape)."""
    return [f.name for f in dataclasses.fields(dc)]


def _dto_fields(dto: type) -> list[str]:
    """Sorted field names of a rendered DTO (Pydantic model or dataclass)."""
    if isinstance(dto, type) and issubclass(dto, BaseModel):
        return sorted(dto.model_fields)
    if dataclasses.is_dataclass(dto):
        return sorted(f.name for f in dataclasses.fields(dto))
    raise TypeError(f"unsupported DTO type for {dto!r}: not a Pydantic model or dataclass")


def _signature(obj: Any) -> str:
    return str(inspect.signature(obj))


def build_snapshot() -> str:
    """Assemble the full deterministic snapshot text (newline-terminated)."""
    lines: list[str] = list(_HEADER)

    lines += ["", "## ENGINE_UI_SEAM", str(ENGINE_UI_SEAM)]

    for name, dc in (
        ("UiDeps", UiDeps),
        ("CoreHandlers", CoreHandlers),
        ("AdminHandlers", AdminHandlers),
    ):
        lines += ["", f"## dataclass messagefoundry.api._ui_seam.{name}"]
        lines += _dataclass_fields(dc)

    lines += ["", "## api.security surface (imported directly by the console, outside UiDeps)"]
    for symbol in _API_SECURITY_SYMBOLS:
        lines.append(f"{symbol}: {_signature(getattr(security, symbol))}")

    lines += ["", "## AuthService methods called by the console"]
    for method in _AUTH_SERVICE_METHODS:
        lines.append(f"{method}: {_signature(getattr(AuthService, method))}")

    lines += ["", "## app.state attributes the console sets/reads"]
    lines += list(_APP_STATE_ATTRS)

    lines += ["", "## api.models DTO fields rendered by the console"]
    for name in _API_MODELS_DTOS:
        fields = ", ".join(_dto_fields(getattr(models, name)))
        lines.append(f"{name}: {fields}")

    lines += ["", "## api.auth_models DTO fields rendered by the console"]
    for name in _API_AUTH_MODELS_DTOS:
        fields = ", ".join(_dto_fields(getattr(auth_models, name)))
        lines.append(f"{name}: {fields}")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(build_snapshot(), end="")
