# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The engine-side contract for the mounted web console (Option B, ADR 0065).

This is a **leaf** module: it imports NO engine core and NO console package, so
``import messagefoundry.api.app`` still succeeds with ``messagefoundry-webconsole`` uninstalled
(``add_auth_routes`` — which runs unconditionally — returns an :class:`AdminHandlers` built from
this module, so its concrete type must live engine-side). The console package imports these
dataclasses for typing (package → engine-api-leaf is the allowed direction) and pins itself against
:data:`ENGINE_UI_SEAM`.

The handler fields are typed ``Callable[..., Awaitable[Any]]`` (or ``Callable[..., Any]`` for the
sync presentation helpers): the real runtime objects are ``create_app`` / ``add_auth_routes`` nested
closures, and the engine/gate parameters inside their signatures are ``Any`` here — the console never
imports :class:`~messagefoundry.pipeline.Engine` / :class:`~messagefoundry.api.approvals.ApprovalGate`
(both pull ``store``/``pipeline``). ``mypy --strict`` at the ``deps = UiDeps(...)`` construction site
still catches a builder-signature drift within a supported seam; a shape change across seams trips the
version handshake (``assert_engine_seam`` + the PEP 508 range), never a silent runtime error.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

#: The contract version the engine ships. Bump on ANY incompatible change to the injected surface
#: (a CoreHandlers/AdminHandlers field, a rendered DTO field set, the app.state attributes the
#: console reads, the ``api.security`` deps it imports directly, or the ``/ws`` push shape). The
#: console declares ``SUPPORTED_ENGINE_SEAMS`` and refuses a skew at startup (``assert_engine_seam``).
#: seam v4: MessageDetail gained the additive `attachments` list + a `download_attachment` handler
#: (the streaming-attachment operator read surface, BACKLOG #149 / ADR 0105 Phase 3b).
ENGINE_UI_SEAM: int = 4


@dataclass(frozen=True, slots=True)
class CoreHandlers:
    """The ``create_app``-nested JSON handlers the moved ``/ui`` routes call directly.

    Each is the exact in-process handler the JSON API registers, reached by reference so the console
    reuses the single audited PHI path (its own ``Depends`` gate is skipped — the ``/ui`` route
    re-asserts the equivalent permission via ``require_ui*``). Async unless noted.
    """

    list_connections: Callable[..., Awaitable[Any]]
    list_messages: Callable[..., Awaitable[Any]]
    get_message: Callable[..., Awaitable[Any]]
    download_attachment: Callable[
        ..., Awaitable[Any]
    ]  # streaming-attachment download (#149, seam v4)
    list_dead_letters: Callable[..., Awaitable[Any]]
    start_connection: Callable[..., Awaitable[Any]]
    stop_connection: Callable[..., Awaitable[Any]]
    restart_connection: Callable[..., Awaitable[Any]]
    replay_message: Callable[..., Awaitable[Any]]
    edit_resend_message: Callable[..., Awaitable[Any]]  # edit-and-resubmit (ADR 0090 §9, seam v2)
    replay_dead_letters: Callable[..., Awaitable[Any]]
    list_active_alerts: Callable[..., Awaitable[Any]]
    alerts_rules: Callable[..., Awaitable[Any]]
    list_connection_events: Callable[..., Awaitable[Any]]
    system_status: Callable[..., Awaitable[Any]]
    security_posture: Callable[..., Awaitable[Any]]
    cluster_status: Callable[..., Awaitable[Any]]
    cluster_nodes: Callable[..., Awaitable[Any]]
    dr_status: Callable[..., Awaitable[Any]]
    service_status: Callable[..., Awaitable[Any]]
    ack_alert: Callable[..., Awaitable[Any]]
    resolve_alert: Callable[..., Awaitable[Any]]
    reset_statistics: Callable[..., Awaitable[Any]]
    integrity_check: Callable[..., Awaitable[Any]]
    dr_activate: Callable[..., Awaitable[Any]]
    dr_release: Callable[..., Awaitable[Any]]
    dual_role_control: Callable[..., Awaitable[Any]]
    purge_connection: Callable[..., Awaitable[Any]]
    config_provenance: Callable[..., Awaitable[Any]]
    reload_config: Callable[..., Awaitable[Any]]
    search_messages: Callable[..., Awaitable[Any]]
    audit_channel_denied: Callable[..., Awaitable[Any]]


@dataclass(frozen=True, slots=True)
class AdminHandlers:
    """The ``add_auth_routes``-nested JSON handlers the moved ``/ui`` admin/account/audit routes call,
    plus the two sync presentation helpers that project store/identity records into DTOs.

    Returned by :func:`~messagefoundry.api.auth_routes.add_auth_routes` (which runs before
    ``create_app``'s own handlers exist, so the bundle is the only way the console reaches them).
    """

    list_roles: Callable[..., Awaitable[Any]]
    list_users: Callable[..., Awaitable[Any]]
    list_custom_roles: Callable[..., Awaitable[Any]]
    create_user: Callable[..., Awaitable[Any]]
    update_user: Callable[..., Awaitable[Any]]
    set_user_roles: Callable[..., Awaitable[Any]]
    set_channel_scope: Callable[..., Awaitable[Any]]
    reset_user_password: Callable[..., Awaitable[Any]]
    reset_user_mfa: Callable[..., Awaitable[Any]]
    admin_revoke_user_sessions: Callable[..., Awaitable[Any]]
    delete_user: Callable[..., Awaitable[Any]]
    create_custom_role: Callable[..., Awaitable[Any]]
    update_custom_role: Callable[..., Awaitable[Any]]
    delete_custom_role: Callable[..., Awaitable[Any]]
    get_ad_group_map: Callable[..., Awaitable[Any]]
    get_ad_group_scope_map: Callable[..., Awaitable[Any]]
    set_ad_group_map: Callable[..., Awaitable[Any]]
    set_ad_group_scope_map: Callable[..., Awaitable[Any]]
    my_mfa: Callable[..., Awaitable[Any]]
    change_password: Callable[..., Awaitable[Any]]
    enroll_mfa: Callable[..., Awaitable[Any]]
    disable_my_mfa: Callable[..., Awaitable[Any]]
    list_audit: Callable[..., Awaitable[Any]]
    my_security_events: Callable[..., Awaitable[Any]]
    # Sync DTO projections (kept engine-side so the console never imports store.UserRecord — the
    # ``user`` arg stays opaque/Any across the seam).
    user_summary: Callable[..., Any]
    current_user: Callable[..., Any]


@dataclass(frozen=True, slots=True)
class UiDeps:
    """The single typed bundle ``create_app`` injects into ``mount_ui(app, deps)``.

    The auth dep factories (``require`` / ``require_step_up`` / ``require_reauth_only`` / ``get_auth``
    / ``authorize_ws`` / ``ws_token``) are NOT here — the console imports those directly from
    :mod:`messagefoundry.api.security` (leaf-safe). Their public surface is part of the seam's compat
    scope even so (a re-signature there is seam-bumping).
    """

    engine_seam: int
    get_engine: Callable[..., Any]
    get_gate: Callable[..., Any]
    cookie_secure: Callable[..., Any]
    default_scan_limit: int
    core: CoreHandlers
    admin: AdminHandlers
