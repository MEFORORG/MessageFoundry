# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Every way the web console reaches the engine, classified (ADR 0215 slice 1, vault BACKLOG #2603).

ADR 0215 moves the console off its in-process seam: each ``/ui`` route will send a sub-request to a
JSON route, so one gate family authorizes both planes. Its first slice is this inventory. It
classifies every ``/ui`` route by the JSON route that carries its authority, and every handle the
console holds on the engine: the 86 handler fields of ``CoreHandlers`` and ``AdminHandlers``, the
other ``UiDeps`` fields with ``get_engine`` and ``get_gate`` among them, and the ``AuthService``
members and auth-store reads the console makes. Slices 2 to 6 work from these tables.

THE TABLES ARE DATA, AND THE LIVE APP IS CHECKED AGAINST THEM. Each test derives the same fact from
``create_app(serve_ui=True)`` and fails when the two differ, so a new seam field, a new ``/ui``
route, a new ``AuthService`` read, or a route that starts reaching a different handler fails until
somebody classifies it here. The planted tests at the end show each comparison fails on a removed
entry and on an unclassified addition.

HOW A FIELD IS CLASSED. ``endpoint``: the field is, by object identity, the endpoint of the JSON
routes named. ``core``: no JSON route has it as its endpoint, but each named route's endpoint reaches
it through a closure cell or a global name, so the route runs it past its own gate. ``shared``: the
field and each named route's endpoint both reach one engine helper, named in ``via``. ``helper``: no
JSON route carries the console's use of it, and the entry says what slice 2 or slice 5 does instead:
``ADD <METHOD> <path>`` names a JSON route to add, and ``MOVE``, ``DROP`` or ``KEEP`` say why no route
is needed. An ``ADD`` route that comes to exist fails :func:`test_every_seam_field_is_classified_as_the_app_holds`,
so the slice that adds it reclassifies the field in the same change.

HOW A ``/ui`` ROUTE IS CLASSED. Its pinned tokens are what its endpoint reaches, read from bytecode:
the seam fields it calls or passes by reference (an ``is`` comparison against a field is not a
reach), ``get_engine``, ``get_gate``, ``AuthService`` (its ``_service`` dependency or a
``get_auth`` read), and each ``AuthService`` read the member table classes ``read``. Its authority is
then computed: the carriers of those tokens. A route with no authority is one of the ADR's reviewed
sets: ``public`` (declared with ``public_route``), ``confinement`` (section 2's set),
``ceremony`` (a sign-in, factor, re-authentication, OIDC or passkey leg, out of the ADR's scope), or
``check`` (it shows no engine data, so slice 2's ``GET /auth/check/<permission>`` carries it).

WHAT THE READING CANNOT SEE. The reach is followed through console functions by closure cell, global
name and console-module attribute. A seam field passed to a console function under a name other than
``core``, ``admin`` or ``deps``, or an ``AuthService`` under a name other than ``service`` or
``auth``, is not read. :func:`test_the_reach_reading_sees_every_seam_field_the_console_names` is the
calibration: every field the console's source names must be reached by some route.
"""

from __future__ import annotations

import ast
import dataclasses
import dis
import functools
import inspect
import types
from collections import Counter
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Literal, NamedTuple

import pytest
from fastapi import FastAPI
from fastapi.routing import APIRoute

import messagefoundry_webconsole
from messagefoundry.api._ui_seam import UiDeps
from messagefoundry.api.app import create_app
from messagefoundry.api.security import route_declaration_of
from messagefoundry.auth.service import AuthService
from messagefoundry_webconsole._service import _service
from scripts import seam_discovery
from scripts.security.route_gates import route_rows
from tests._ast_sites import package_trees

_ROOT = Path(__file__).resolve().parent.parent
_CONSOLE_DIR = _ROOT / "messagefoundry_webconsole"
_CONSOLE_PACKAGE = "messagefoundry_webconsole"
_ENGINE_PACKAGE = "messagefoundry"
_SYNTHETIC_METHODS = frozenset({"HEAD", "OPTIONS"})


# =====================================================================================================
# The live app, and the bundle create_app hands the console
# =====================================================================================================


class _Live(NamedTuple):
    app: FastAPI
    deps: UiDeps


def _build_live() -> _Live:
    """``create_app(serve_ui=True, oidc_enabled=True)`` and the ``UiDeps`` it passed to
    ``mount_ui``. OIDC on, so its four legs are on the table too; it adds no JSON route.

    ``create_app`` imports ``mount_ui`` from the package at call time, so wrapping the package
    attribute sees the real bundle and still mounts the console.
    """
    captured: list[UiDeps] = []
    real = messagefoundry_webconsole.mount_ui

    def spy(app: FastAPI, deps: UiDeps) -> None:
        captured.append(deps)
        real(app, deps)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(messagefoundry_webconsole, "mount_ui", spy)
        app = create_app(serve_ui=True, oidc_enabled=True)
    assert len(captured) == 1, "create_app(serve_ui=True) must call mount_ui exactly once"
    return _Live(app, captured[0])


@pytest.fixture(scope="module")
def live() -> _Live:
    return _build_live()


def _ops(route: APIRoute) -> list[str]:
    return [f"{m} {route.path}" for m in sorted((route.methods or set()) - _SYNTHETIC_METHODS)]


def _json_routes(app: FastAPI) -> dict[str, APIRoute]:
    return {
        op: r
        for r in app.routes
        if isinstance(r, APIRoute) and not r.path.startswith("/ui")
        for op in _ops(r)
    }


def _ui_routes(app: FastAPI) -> dict[str, APIRoute]:
    return {
        op: r
        for r in app.routes
        if isinstance(r, APIRoute) and r.path.startswith("/ui")
        for op in _ops(r)
    }


def _seam_fields(deps: UiDeps) -> dict[str, Any]:
    """``core.<name>`` and ``admin.<name>`` to the object the engine injected."""
    out: dict[str, Any] = {}
    for prefix, bundle in (("core", deps.core), ("admin", deps.admin)):
        for f in dataclasses.fields(bundle):
            out[f"{prefix}.{f.name}"] = getattr(bundle, f.name)
    return out


# =====================================================================================================
# Reach: what a function gets to through closure cells and global names
# =====================================================================================================


def _code_objects(code: types.CodeType) -> Iterator[types.CodeType]:
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _code_objects(const)


def _layers(fn: Any) -> list[Any]:
    """``fn`` and every function a ``functools.wraps`` chain on it wraps."""
    out = [fn]
    while inspect.isfunction(getattr(out[-1], "__wrapped__", None)):
        out.append(out[-1].__wrapped__)
    return out


def _cells(fn: Any) -> list[Any]:
    values = []
    for cell in fn.__closure__ or ():
        try:
            values.append(cell.cell_contents)
        except ValueError:  # an unfilled cell: a name the closure has not bound yet
            continue
    return values


def _named(fn: Any) -> list[Any]:
    """Every value ``fn`` reaches directly: closure cells, then globals its code names."""
    values = _cells(fn)
    for code in _code_objects(fn.__code__):
        values += [fn.__globals__[n] for n in code.co_names if n in fn.__globals__]
    return values


@functools.cache
def _engine_reach(fn: Any) -> Mapping[int, Any]:
    """Every engine function ``fn`` reaches, transitively, by closure cell or global name. Cached,
    since one endpoint is walked for several fields."""
    found: dict[int, Any] = {}
    stack = [fn]
    while stack:
        current = stack.pop()
        if not inspect.isfunction(current) or id(current) in found:
            continue
        if current.__module__.partition(".")[0] != _ENGINE_PACKAGE:
            continue
        found[id(current)] = current
        for layer in _layers(current):
            stack += _named(layer)
    return found


#: Loads that put a name on the stack a following ``LOAD_ATTR`` chain reads from.
_SINGLE_LOADS = frozenset(
    {"LOAD_FAST", "LOAD_FAST_BORROW", "LOAD_FAST_CHECK", "LOAD_DEREF", "LOAD_GLOBAL", "LOAD_NAME"}
)
_PAIR_LOADS = frozenset({"LOAD_FAST_LOAD_FAST", "LOAD_FAST_BORROW_LOAD_FAST_BORROW"})


@functools.cache
def _attribute_chains(code: types.CodeType) -> tuple[tuple[tuple[str, ...], str], ...]:
    """``(receiver, attr, attr...)`` for each attribute chain in ``code``, with the opcode after it.

    A pair load puts two names on the stack, and a following ``LOAD_ATTR`` reads the second.
    Cached, because shared console helpers are reached from many routes."""
    return tuple(_chains_in(code))


def _chains_in(code: types.CodeType) -> Iterator[tuple[tuple[str, ...], str]]:
    for sub in _code_objects(code):
        ins = list(dis.get_instructions(sub))
        for i, instr in enumerate(ins):
            if instr.opname in _SINGLE_LOADS:
                receiver = instr.argval
            elif instr.opname in _PAIR_LOADS:
                receiver = instr.argval[1]
            else:
                continue
            chain = [receiver]
            j = i + 1
            while j < len(ins) and ins[j].opname == "LOAD_ATTR":
                chain.append(ins[j].argval)
                j += 1
            if len(chain) > 1:
                yield tuple(chain), ins[j].opname if j < len(ins) else ""


def _console_functions(fn: Any) -> list[Any]:
    """Every console function ``fn`` reaches, transitively, ``fn`` included.

    Followed by closure cell, by global name, and by an attribute of a console module (``pages.x``,
    ``_common.y``)."""
    found: dict[int, Any] = {}
    stack = [fn]
    while stack:
        current = stack.pop()
        if not inspect.isfunction(current) or id(current) in found:
            continue
        if current.__module__.partition(".")[0] != _CONSOLE_PACKAGE:
            continue
        found[id(current)] = current
        for layer in _layers(current):
            stack += _named(layer)
            for chain, _next in _attribute_chains(layer.__code__):
                module = layer.__globals__.get(chain[0])
                if isinstance(module, types.ModuleType) and module.__name__.startswith(
                    _CONSOLE_PACKAGE
                ):
                    stack.append(getattr(module, chain[1], None))
    return list(found.values())


def _dependency_calls(route: APIRoute) -> list[Any]:
    calls: list[Any] = []
    pending = list(route.dependant.dependencies)
    while pending:
        dep = pending.pop()
        calls.append(dep.call)
        pending += dep.dependencies
    return calls


#: The receiver names the reading follows for an ``AuthService`` (see the module docstring).
_AUTH_RECEIVERS = frozenset({"service", "auth"})
#: The names the console gives what ``get_engine`` and ``get_gate`` return. An attribute read off
#: one is the console reading the engine object itself, not a handler.
_ENGINE_RECEIVERS = frozenset({"engine", "gate"})


def _code_names(code: types.CodeType) -> set[str]:
    return {n for sub in _code_objects(code) for n in sub.co_names}


def _ui_reach(route: APIRoute, deps: UiDeps, reads: frozenset[str]) -> frozenset[str]:
    """The tokens one ``/ui`` route reaches; the module docstring says which tokens there are.

    ``reads`` is the set of ``AuthService`` tokens (``service.<member>``, ``service.store.<name>``)
    worth recording; every other ``AuthService`` member is the console's gate or a ceremony leg."""
    tokens: set[str] = set()
    for fn in _console_functions(route.endpoint):
        for layer in _layers(fn):
            if (
                "get_auth" in _code_names(layer.__code__)
                and layer.__globals__.get("get_auth") is not None
            ):
                tokens.add("AuthService")
            for chain, after in _attribute_chains(layer.__code__):
                head, rest = chain[0], chain[1:]
                if head == "deps" and rest[0] in ("core", "admin"):
                    head, rest = rest[0], rest[1:]
                elif head == "deps" and rest[0] in ("get_engine", "get_gate"):
                    tokens.add(rest[0])
                    continue
                if not rest:
                    continue
                handler = head in ("core", "admin") and after != "IS_OP"
                if handler or head in _ENGINE_RECEIVERS:
                    tokens.add(f"{head}.{rest[0]}")
                elif head in _AUTH_RECEIVERS:
                    token = "service." + ".".join(rest[:2] if rest[0] == "store" else rest[:1])
                    if token in reads:
                        tokens.add(token)
    calls = _dependency_calls(route)
    if any(c is deps.get_engine for c in calls):
        tokens.add("get_engine")
    if any(c is deps.get_gate for c in calls):
        tokens.add("get_gate")
    if any(c is _service for c in calls):
        tokens.add("AuthService")
    return frozenset(tokens)


# =====================================================================================================
# The tables
# =====================================================================================================

FieldKind = Literal["endpoint", "core", "shared", "helper"]


class Field(NamedTuple):
    """One seam field's class. ``carrier`` is what carries the console's use once it sub-requests:
    JSON operations, or for a ``helper`` an ``ADD``, ``MOVE``, ``DROP`` or ``KEEP`` line."""

    kind: FieldKind
    carrier: tuple[str, ...]
    via: str = ""


def _endpoint(*ops: str) -> Field:
    return Field("endpoint", ops)


def _core(*ops: str) -> Field:
    return Field("core", ops)


#: Every ``CoreHandlers`` and ``AdminHandlers`` field. 66 endpoints by identity, as ADR 0215
#: slice 1 measured, 15 cores a JSON route runs past its gate, 2 sharing a helper with a JSON
#: route, and 3 with no JSON route that carries the console's use.
_SEAM_FIELDS: dict[str, Field] = {
    "core.list_connections": _endpoint("GET /connections"),
    "core.list_messages": _endpoint("GET /messages"),
    "core.get_message": _endpoint("GET /messages/{message_id}"),
    "core.get_message_body": _endpoint("GET /messages/{message_id}/raw"),
    "core.download_attachment": _endpoint("GET /messages/{message_id}/attachments/{attachment_id}"),
    "core.list_dead_letters": _endpoint("GET /dead-letters"),
    "core.start_connection": _endpoint("POST /connections/{name}/start"),
    "core.stop_connection": _endpoint("POST /connections/{name}/stop"),
    "core.restart_connection": _endpoint("POST /connections/{name}/restart"),
    "core.replay_message": _endpoint("POST /messages/{message_id}/replay"),
    "core.resend_message": _endpoint("POST /messages/{message_id}/resend"),
    "core.edit_resend_message": _core("POST /messages/{message_id}/edit-resend"),
    # The repeat lookup the resend routes ask before they demand a proof (vault BACKLOG #2625).
    # Read-only and gated by nothing on the JSON plane, so slice 2 adds a route for it, under the
    # resend's own permission.
    "core.prior_resend": Field("helper", ("ADD GET /messages/{message_id}/prior-resend",)),
    "core.replay_dead_letters": _endpoint("POST /dead-letters/replay"),
    "core.list_active_alerts": _endpoint("GET /alerts/active"),
    "core.alerts_rules": _endpoint("GET /alerts/rules"),
    # The connection page's unpaged read, under the gates GET /events applies.
    "core.list_connection_events": Field("shared", ("GET /events",), via="_admit_event_read"),
    "core.system_status": _endpoint("GET /status"),
    "core.security_posture": _endpoint("GET /security/posture"),
    "core.cluster_status": _endpoint("GET /cluster/status"),
    "core.cluster_nodes": _endpoint("GET /cluster/nodes"),
    "core.cluster_stepdown": _endpoint("POST /cluster/stepdown"),
    "core.dr_status": _endpoint("GET /dr/status"),
    "core.service_status": _endpoint("GET /service/status"),
    "core.ack_alert": _endpoint("POST /alerts/{alert_id}/ack"),
    "core.resolve_alert": _endpoint("POST /alerts/{alert_id}/resolve"),
    "core.suspend_alert": _endpoint("POST /alerts/{alert_id}/suspend"),
    "core.resume_alert": _endpoint("POST /alerts/{alert_id}/resume"),
    "core.reset_statistics": _endpoint("POST /statistics/reset"),
    "core.integrity_check": _endpoint("POST /status/integrity-check"),
    "core.dr_activate": _endpoint("POST /dr/activate"),
    "core.dr_release": _endpoint("POST /dr/release"),
    # The bulk-control loop's per-connection call, one of the three verbs each time.
    "core.dual_role_control": _core(
        "POST /connections/{name}/start",
        "POST /connections/{name}/stop",
        "POST /connections/{name}/restart",
    ),
    "core.purge_connection": _core("POST /connections/{name}/purge"),
    "core.config_provenance": _endpoint("GET /config/provenance"),
    "core.reload_config": _core("POST /config/reload"),
    # The console's composite search: the implementation both JSON search routes share.
    "core.search_messages": _core("GET /messages/search", "POST /messages/search"),
    # The channel-denied audit row. Every JSON route that refuses a scoped caller writes it itself.
    "core.audit_channel_denied": Field(
        "helper",
        ("DROP: each JSON route the console sub-requests writes its own channel-denied row",),
    ),
    "core.upload_file": _endpoint("POST /uploads"),
    "core.list_uploaded_files": _endpoint("GET /uploads"),
    "core.browse_uploaded_file": _core(
        "GET /uploads/{file_id}/messages", "POST /uploads/{file_id}/messages/search"
    ),
    "core.resend_uploaded_message": _endpoint("POST /uploads/{file_id}/resend"),
    "core.delete_uploaded_file": _endpoint("DELETE /uploads/{file_id}"),
    "core.list_search_presets": _endpoint("GET /search/presets"),
    "core.create_search_preset": _endpoint("POST /search/presets"),
    "core.delete_search_preset": _endpoint("DELETE /search/presets/{preset_id}"),
    "core.layered_search": _endpoint("GET /search/layered"),
    "core.metrics_history": _endpoint("GET /metrics/history"),
    "core.graph_edges": _endpoint("GET /graph/edges"),
    "core.set_connection_flag": _endpoint("POST /connections/{name}/flag"),
    "core.list_approvals": _endpoint("GET /approvals"),
    "core.approve_action": _endpoint("POST /approvals/{approval_id}/approve"),
    "core.reject_action": _endpoint("POST /approvals/{approval_id}/reject"),
    "core.connection_event_page": _core("GET /events"),
    "core.resolve_action": _endpoint("POST /approvals/{approval_id}/resolve"),
    "admin.list_roles": _endpoint("GET /roles"),
    "admin.list_users": _endpoint("GET /users"),
    "admin.list_custom_roles": _endpoint("GET /roles/custom"),
    "admin.create_user": _endpoint("POST /users"),
    "admin.update_user": _endpoint("PATCH /users/{user_id}"),
    "admin.set_user_roles": _endpoint("PUT /users/{user_id}/roles"),
    "admin.set_channel_scope": _endpoint("PUT /users/{user_id}/channel-scope"),
    "admin.refuse_own_channel_scope": _core("PUT /users/{user_id}/channel-scope"),
    "admin.reset_user_password": _endpoint("POST /users/{user_id}/reset-password"),
    "admin.reset_user_mfa": _endpoint("POST /users/{user_id}/reset-mfa"),
    "admin.bind_user_federated_identity": _endpoint("PUT /users/{user_id}/federated-identity"),
    "admin.unbind_user_federated_identity": _endpoint("DELETE /users/{user_id}/federated-identity"),
    "admin.admin_revoke_user_sessions": _endpoint("DELETE /users/{user_id}/sessions"),
    "admin.delete_user": _endpoint("DELETE /users/{user_id}"),
    "admin.create_custom_role": _endpoint("POST /roles/custom"),
    "admin.update_custom_role": _core("PUT /roles/custom/{role_id}"),
    "admin.delete_custom_role": _core("DELETE /roles/custom/{role_id}"),
    "admin.get_ad_group_map": _endpoint("GET /ad-group-map"),
    "admin.get_ad_group_scope_map": _endpoint("GET /ad-group-scope-map"),
    "admin.set_ad_group_map": _core("PUT /ad-group-map"),
    "admin.set_ad_group_scope_map": _core("PUT /ad-group-scope-map"),
    "admin.my_mfa": _endpoint("GET /me/mfa"),
    "admin.change_password": _endpoint("POST /me/password"),
    "admin.enroll_mfa": _endpoint("POST /me/mfa/enroll"),
    "admin.disable_my_mfa": _core("DELETE /me/mfa"),
    # The audit page's read, which shares the trail read with GET /audit.
    "admin.list_audit": Field("shared", ("GET /audit",), via="_audit_list"),
    "admin.export_audit": _endpoint("GET /audit/export"),
    "admin.my_security_events": _endpoint("GET /me/security-events"),
    # The presentation helpers. GET /users and the user writes project through user_summary, but
    # no JSON route returns one account, which the user page shows.
    "admin.user_summary": Field("helper", ("ADD GET /users/{user_id}",)),
    "admin.current_user": _core("GET /auth/me"),
    "admin.federated_identity_view": _core("GET /users/{user_id}/federated-identity"),
}

#: Every other ``UiDeps`` field, by what slice 6 makes of it.
_UI_DEPS_FIELDS: dict[str, str] = {
    "engine_seam": "KEEP: the handshake value; slice 6 moves the digest to the OpenAPI operations",
    "get_engine": "REMOVE in slice 6: the engine accessor",
    "get_gate": "REMOVE in slice 6: the approval-gate accessor",
    "cookie_secure": "KEEP: reads the request scheme and app.state.exposure_protected, no engine",
    "default_scan_limit": "DROP in slice 5: the JSON search routes apply their own default",
    "core": "REMOVE in slice 6: its fields are classified in _SEAM_FIELDS",
    "admin": "REMOVE in slice 6: its fields are classified in _SEAM_FIELDS",
    "oidc_enabled": "KEEP: configuration, which decides whether the OIDC legs register",
    "organization_domains": "KEEP: configuration for the external-link interstitial",
    "external_link_interstitial": "KEEP: configuration for the external-link interstitial",
    "external_link_allowlist": "KEEP: configuration for the external-link interstitial",
    "oidc_authorization_host": "KEEP: configuration the interstitial displays",
}

AuthKind = Literal["ceremony", "step1", "gate", "read", "store"]


class AuthUse(NamedTuple):
    """One ``AuthService`` member the console reaches. ``ceremony``: a sign-in, sign-out, factor,
    re-authentication, OIDC or passkey leg, or the configuration they read, which ADR 0215 keeps on
    ``AuthService``. ``step1``: ``require_ui``'s read-only session resolution, which stays.
    ``gate``: the console's own gate family, which goes when the JSON gate decides instead (slices
    4 to 6). ``read``: a route body reading or writing account data, which a JSON route carries.
    ``store``: the auth store itself; its reads are classified in :data:`_STORE_READS`."""

    kind: AuthKind
    carrier: tuple[str, ...] = ()


_C = AuthUse("ceremony")
_G = AuthUse("gate")

#: Every ``AuthService`` member the console reaches, as ``scripts/seam_discovery.py`` finds them.
_AUTH_SERVICE: dict[str, AuthUse] = {
    "abandon_oidc_login": _C,
    "abandon_oidc_step_up": _C,
    "action_step_up_required": _G,
    "admin_write_retry_after": _G,
    "allow_admin_write": _G,
    "allow_login_attempt": _C,
    "allow_phi_read": _G,
    "allow_reauth_attempt": _C,
    "allow_step_up_return_audit": _C,
    "audit_kerberos_reject": _C,
    "audit_mfa_denied": _G,
    "audit_oidc_reject": _C,
    "audit_permission_denied": _G,
    "authenticate_kerberos": _C,
    "begin_oidc_login": _C,
    "begin_oidc_step_up": _C,
    "begin_passkey_sign_in": _C,
    "begin_webauthn_assertion": _C,
    "begin_webauthn_registration": _C,
    "complete_oidc_login": _C,
    "complete_oidc_step_up": _C,
    "confirm_mfa_enrollment": AuthUse("read", ("POST /me/mfa/confirm",)),
    "count_other_sessions": AuthUse("read", ("GET /me/sessions",)),
    "delete_webauthn_credential": _C,
    "factor_binding_is_blocked": _G,
    "fill_own_notify_email": AuthUse("read", ("POST /me/notify-email",)),
    "finish_webauthn_assertion": _C,
    "finish_webauthn_registration": _C,
    "flag_new_client_ip": _G,
    "has_action_step_up": _G,
    "has_recent_step_up": _G,
    "holds_action_step_up": _G,
    "identity_for_token": AuthUse("step1"),
    "kerberos_available": _C,
    "list_sessions": AuthUse("read", ("GET /me/sessions",)),
    "login": _C,
    "login_retry_after": _C,
    "logout": _C,
    "mfa_satisfied": _G,
    "mfa_status": _C,
    "must_enrol_before_rotating": _G,
    "oidc_enabled": _C,
    "oidc_flow_ttl_seconds": _C,
    "oidc_step_up_flow": _C,
    "passkeys_count_as_way_past": _C,
    "password_change_owes_factor": _G,
    "phi_read_retry_after": _G,
    "reauth": _C,
    "revoke_other_sessions": AuthUse("read", ("DELETE /me/sessions",)),
    "revoke_own_session": AuthUse("read", ("DELETE /me/sessions/{session_id}",)),
    "session_steps_up_at_idp": _C,
    "sessions_ended_by_ad_map_save": _G,
    "sessions_ended_by_custom_role_save": _G,
    "store": AuthUse("store"),
    # The notification-address form's pre-fill, which slice 2 serves with the address it suggests.
    "suggested_notify_email": AuthUse("read", ("ADD GET /me/notify-email",)),
    "take_passkey_challenge": _C,
    "verify_mfa": _C,
    "webauthn_available": _C,
}

#: Every ``service.store.<name>`` read the console makes, by what carries it.
_STORE_READS: dict[str, tuple[str, ...]] = {
    # The admin user pages read the target account; the notification-address form reads the
    # caller's own profile email, which its slice 2 route returns.
    "get_user": ("ADD GET /users/{user_id}", "ADD GET /me/notify-email"),
    "get_user_role_ids": ("ADD GET /users/{user_id}",),
    "list_webauthn_credentials": ("ADD GET /me/webauthn",),
    # The heartbeat is in the confinement set and makes no sub-request (ADR 0215 section 3).
    "get_session": (
        "KEEP: the /ui/session-status heartbeat's deadline read; AC-1's reviewed list must name "
        "it, or step 1 must return the session deadline",
    ),
}

#: Every attribute the console reads off the engine or the approval gate object itself.
_ENGINE_READS: dict[str, tuple[str, ...]] = {
    # The bulk purge confirmation re-derives eligibility from live quiescence; GET /connections
    # reports it as status "stopped" on a paused outbound.
    "engine.registry_runner": ("GET /connections",),
}

#: Every ``app.state`` attribute the console sets or reads, as ``scripts/seam_discovery.py`` finds
#: them. AC-1's static guard (slice 6) refuses a read of the engine, the gate or the auth store.
_APP_STATE: dict[str, str] = {
    "auth": "AuthService: its members are classified in _AUTH_SERVICE",
    "exposure_protected": "KEEP: configuration, the declared browser-facing scheme",
    "loopback": "KEEP: configuration, whether the bind is loopback",
    "public_origin": "KEEP: configuration, the same-origin check's origin",
    "ui_connections_render": "KEEP: a hook the console installs for /ws/stats",
    "ui_csp": "KEEP: a hook the console installs",
    "ui_ws_authorize": "KEEP: a hook the console installs; slice 6 shrinks authorize_ui_ws",
    "webauthn_rp_from_request": "KEEP: configuration the passkey legs read",
}

UiKind = Literal["json", "public", "confinement", "ceremony", "check"]


class Ui(NamedTuple):
    """One ``/ui`` operation: its class, the JSON operations carrying its authority, and the
    tokens its endpoint reaches (both space-separated in the table, for one line per route)."""

    kind: UiKind
    authority: str
    reach: str


def _J(authority: str, reach: str) -> Ui:
    return Ui("json", authority, reach)


_AS = "AuthService"
_E = "get_engine"

#: Every ``/ui`` operation of ``create_app(serve_ui=True, oidc_enabled=True)``: 127 with OIDC off,
#: as ADR 0215 measured, and the 4 OIDC legs. A write's authority is its write route alone: under
#: ADR 0215 section 2 a write makes one sub-request and redirects, and the page it re-renders on an
#: error today is read on the following GET.
_UI_ROUTES: dict[str, Ui] = {
    "GET /ui/users": _J("GET /users", f"{_AS} admin.list_users"),
    "GET /ui/users/new": _J("GET /roles", f"{_AS} admin.list_roles"),
    "GET /ui/users/{user_id}": _J(
        "ADD GET /users/{user_id};GET /roles;GET /users/{user_id}/federated-identity",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.user_summary "
        "service.store.get_user service.store.get_user_role_ids",
    ),
    "POST /ui/users": _J("POST /users", f"{_AS} admin.create_user admin.list_roles"),
    "POST /ui/users/{user_id}/update": _J(
        "PATCH /users/{user_id}",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.update_user admin.user_summary "
        "service.store.get_user service.store.get_user_role_ids",
    ),
    "POST /ui/users/{user_id}/roles": _J(
        "PUT /users/{user_id}/roles",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.set_user_roles "
        "admin.user_summary service.store.get_user service.store.get_user_role_ids",
    ),
    "POST /ui/users/{user_id}/channel-scope": _J(
        "PUT /users/{user_id}/channel-scope",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.refuse_own_channel_scope "
        "admin.set_channel_scope admin.user_summary service.store.get_user "
        "service.store.get_user_role_ids",
    ),
    "POST /ui/users/{user_id}/reset-password": _J(
        "POST /users/{user_id}/reset-password",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.reset_user_password "
        "admin.user_summary service.store.get_user service.store.get_user_role_ids",
    ),
    "POST /ui/users/{user_id}/reset-mfa": _J(
        "POST /users/{user_id}/reset-mfa",
        f"{_AS} admin.federated_identity_view admin.list_roles admin.reset_user_mfa "
        "admin.user_summary service.store.get_user service.store.get_user_role_ids",
    ),
    "GET /ui/users/{user_id}/federated-identity": _J(
        "GET /users/{user_id}/federated-identity;ADD GET /users/{user_id}",
        f"{_AS} admin.federated_identity_view service.store.get_user",
    ),
    "POST /ui/users/{user_id}/federated-identity/link": _J(
        "PUT /users/{user_id}/federated-identity",
        f"{_AS} admin.bind_user_federated_identity admin.federated_identity_view "
        "service.store.get_user",
    ),
    "GET /ui/users/{user_id}/federated-identity/unlink-confirm": _J(
        "GET /users/{user_id}/federated-identity;ADD GET /users/{user_id}",
        f"{_AS} admin.federated_identity_view service.store.get_user",
    ),
    "POST /ui/users/{user_id}/federated-identity/unlink": _J(
        "DELETE /users/{user_id}/federated-identity",
        f"{_AS} admin.federated_identity_view admin.unbind_user_federated_identity "
        "service.store.get_user",
    ),
    "POST /ui/users/{user_id}/revoke-sessions": _J(
        "DELETE /users/{user_id}/sessions",
        f"{_AS} admin.admin_revoke_user_sessions admin.federated_identity_view admin.list_roles "
        "admin.user_summary service.store.get_user service.store.get_user_role_ids",
    ),
    "POST /ui/users/{user_id}/delete": _J(
        "DELETE /users/{user_id}",
        f"{_AS} admin.delete_user admin.federated_identity_view admin.list_roles "
        "admin.user_summary service.store.get_user service.store.get_user_role_ids",
    ),
    "GET /ui/roles": _J("GET /roles", f"{_AS} admin.list_roles"),
    "GET /ui/roles/new": Ui("check", "ADD GET /auth/check/users:manage", ""),
    "GET /ui/roles/{role_id}/edit": _J("GET /roles/custom", f"{_AS} admin.list_custom_roles"),
    "POST /ui/roles/custom": _J("POST /roles/custom", f"{_AS} admin.create_custom_role"),
    "POST /ui/roles/custom/{role_id}/update": _J(
        "PUT /roles/custom/{role_id}", f"{_AS} admin.update_custom_role"
    ),
    "POST /ui/roles/custom/{role_id}/delete": _J(
        "DELETE /roles/custom/{role_id}", f"{_AS} admin.delete_custom_role"
    ),
    "GET /ui/ad-groups": _J(
        "GET /ad-group-map;GET /ad-group-scope-map;GET /roles",
        f"{_AS} admin.get_ad_group_map admin.get_ad_group_scope_map admin.list_roles",
    ),
    "POST /ui/ad-groups/map": _J(
        "PUT /ad-group-map",
        f"{_AS} admin.get_ad_group_map admin.get_ad_group_scope_map admin.list_roles "
        "admin.set_ad_group_map",
    ),
    "POST /ui/ad-groups/scope-map": _J(
        "PUT /ad-group-scope-map",
        f"{_AS} admin.get_ad_group_map admin.get_ad_group_scope_map admin.list_roles "
        "admin.set_ad_group_scope_map",
    ),
    "GET /ui/account": _J(
        "GET /auth/me;GET /me/mfa;GET /me/sessions;ADD GET /me/webauthn",
        f"{_AS} admin.current_user admin.my_mfa service.count_other_sessions "
        "service.store.list_webauthn_credentials",
    ),
    "GET /ui/account/password": Ui("confinement", "", _AS),
    "POST /ui/account/password": _J("POST /me/password", f"{_AS} admin.change_password"),
    "GET /ui/account/notify-address": _J(
        "ADD GET /me/notify-email",
        f"{_AS} service.store.get_user service.suggested_notify_email",
    ),
    "POST /ui/account/notify-address": _J(
        "POST /me/notify-email", f"{_AS} service.fill_own_notify_email"
    ),
    "POST /ui/account/mfa/enroll": _J(
        "POST /me/mfa/enroll",
        f"{_AS} admin.current_user admin.enroll_mfa admin.my_mfa "
        "service.store.list_webauthn_credentials",
    ),
    "GET /ui/account/mfa/confirm": Ui("confinement", "", ""),
    "POST /ui/account/mfa/verify": _J(
        "POST /me/mfa/confirm",
        f"{_AS} admin.current_user admin.my_mfa service.confirm_mfa_enrollment "
        "service.count_other_sessions service.store.list_webauthn_credentials",
    ),
    "POST /ui/account/mfa/disable": _J(
        "DELETE /me/mfa",
        f"{_AS} admin.current_user admin.disable_my_mfa admin.my_mfa "
        "service.store.list_webauthn_credentials",
    ),
    "GET /ui/account/sessions": _J("GET /me/sessions", f"{_AS} service.list_sessions"),
    "POST /ui/account/sessions/{session_id}/revoke": _J(
        "DELETE /me/sessions/{session_id}", f"{_AS} service.revoke_own_session"
    ),
    "POST /ui/account/sessions/revoke-others": _J(
        "DELETE /me/sessions", f"{_AS} service.revoke_other_sessions"
    ),
    "POST /ui/account/webauthn/enroll": Ui(
        "ceremony",
        "",
        f"{_AS} admin.current_user admin.my_mfa service.store.list_webauthn_credentials",
    ),
    "POST /ui/account/webauthn/verify": Ui("ceremony", "", _AS),
    "POST /ui/account/webauthn/{credential_id_hash}/delete": Ui(
        "ceremony",
        "",
        f"{_AS} admin.current_user admin.my_mfa service.store.list_webauthn_credentials",
    ),
    "GET /ui/audit": _J("GET /audit", f"{_AS} admin.list_audit"),
    "GET /ui/audit/export": _J("GET /audit/export", f"{_AS} admin.export_audit"),
    "GET /ui/security-events": _J("GET /me/security-events", f"{_AS} admin.my_security_events"),
    "GET /ui/messages/search": _J(
        "GET /messages/search;GET /search/presets",
        f"core.list_search_presets core.search_messages {_E}",
    ),
    "POST /ui/messages/search/run": _J(
        "POST /messages/search", f"core.list_search_presets core.search_messages {_E}"
    ),
    "POST /ui/messages/search/presets": _J(
        "POST /search/presets", f"core.create_search_preset core.list_search_presets {_E}"
    ),
    "POST /ui/messages/search/presets/{preset_id}/delete": _J(
        "DELETE /search/presets/{preset_id}", f"core.delete_search_preset {_E}"
    ),
    "GET /ui/messages/search/layered": _J(
        "GET /search/layered;GET /search/presets",
        f"core.layered_search core.list_search_presets {_E}",
    ),
    "GET /ui/session-status": Ui("confinement", "", f"{_AS} service.store.get_session"),
    "GET /ui/login": Ui("public", "", _AS),
    "POST /ui/login/passkey": Ui("public", "", _AS),
    "POST /ui/login": Ui("public", "", _AS),
    "POST /ui/logout": Ui("public", "", _AS),
    "GET /ui": _J("GET /connections", f"core.list_connections {_E}"),
    "GET /ui/connections": _J("GET /connections", f"core.list_connections {_E}"),
    "GET /ui/connection/{name}": _J(
        "GET /connections;GET /events", f"core.list_connection_events core.list_connections {_E}"
    ),
    "GET /ui/connection/{name}/events/{event_id}/reason": _J(
        "GET /connections;GET /events", f"core.list_connection_events core.list_connections {_E}"
    ),
    "GET /ui/messages": _J("GET /messages", f"core.list_messages {_E}"),
    "GET /ui/messages/{message_id}": _J(
        "GET /messages/{message_id};GET /messages/{message_id}/raw",
        f"core.get_message core.get_message_body {_E}",
    ),
    "GET /ui/messages/{message_id}/summary": _J(
        "GET /messages/{message_id};GET /messages/{message_id}/raw",
        f"core.get_message core.get_message_body {_E}",
    ),
    "GET /ui/messages/{message_id}/body": _J(
        "GET /messages/{message_id};GET /messages/{message_id}/raw",
        f"core.get_message core.get_message_body {_E}",
    ),
    "GET /ui/messages/{message_id}/errors": _J(
        "GET /messages/{message_id};GET /messages/{message_id}/raw",
        f"core.get_message core.get_message_body {_E}",
    ),
    "GET /ui/messages/{message_id}/parse-tree": _J(
        "GET /messages/{message_id}/raw", f"core.get_message_body {_E}"
    ),
    "GET /ui/messages/{message_id}/attachments/{attachment_id}": _J(
        "GET /messages/{message_id}/attachments/{attachment_id}", f"core.download_attachment {_E}"
    ),
    "GET /ui/dead-letters": _J("GET /dead-letters", f"core.list_dead_letters {_E}"),
    "POST /ui/connections/{name}/start": _J(
        "POST /connections/{name}/start", f"core.start_connection {_E}"
    ),
    "POST /ui/connections/{name}/stop": _J(
        "POST /connections/{name}/stop", f"core.stop_connection {_E}"
    ),
    "POST /ui/connections/{name}/restart": _J(
        "POST /connections/{name}/restart", f"core.restart_connection {_E}"
    ),
    "POST /ui/messages/{message_id}/replay": _J(
        "POST /messages/{message_id}/replay", f"core.replay_message {_E}"
    ),
    "GET /ui/messages/{message_id}/resend-confirm": Ui(
        "check", "ADD GET /auth/check/messages:resend", ""
    ),
    "GET /ui/messages/{message_id}/resend-done": _J(
        "ADD GET /messages/{message_id}/prior-resend", f"core.prior_resend {_E}"
    ),
    "POST /ui/messages/{message_id}/resend": _J(
        "POST /messages/{message_id}/resend",
        f"{_AS} core.prior_resend core.resend_message {_E}",
    ),
    "GET /ui/messages/{message_id}/edit": _J(
        "GET /messages/{message_id};GET /messages/{message_id}/raw",
        f"core.get_message core.get_message_body {_E}",
    ),
    "POST /ui/messages/{message_id}/edit-resend": _J(
        "POST /messages/{message_id}/edit-resend",
        f"{_AS} core.edit_resend_message core.get_message core.get_message_body {_E}",
    ),
    "GET /ui/mfa": Ui("public", "", _AS),
    "POST /ui/mfa": Ui("public", "", _AS),
    "GET /ui/reauth": Ui("public", "", _AS),
    "POST /ui/reauth": Ui("public", "", _AS),
    "POST /ui/reauth/webauthn": Ui("public", "", _AS),
    "POST /ui/dead-letters/replay-all": _J(
        "POST /dead-letters/replay", f"core.replay_dead_letters {_E} get_gate"
    ),
    "POST /ui/dead-letters/{channel_id}/replay": _J(
        "POST /dead-letters/replay", f"core.replay_dead_letters {_E} get_gate"
    ),
    "POST /ui/dead-letters/{channel_id}/{destination_name}/replay": _J(
        "POST /dead-letters/replay", f"core.replay_dead_letters {_E} get_gate"
    ),
    "POST /ui/csp-report": Ui("public", "", ""),
    "GET /ui/uploaded-logs": _J("GET /uploads", f"core.list_uploaded_files {_E}"),
    "GET /ui/uploaded-logs/upload-form": Ui("check", "ADD GET /auth/check/files:upload", ""),
    "POST /ui/uploaded-logs/upload": _J("POST /uploads", f"core.upload_file {_E}"),
    "GET /ui/uploaded-logs/file/{file_id}": _J(
        "GET /uploads/{file_id}/messages", f"core.browse_uploaded_file {_E}"
    ),
    "POST /ui/uploaded-logs/file/{file_id}/filter": _J(
        "POST /uploads/{file_id}/messages/search", f"core.browse_uploaded_file {_E}"
    ),
    "POST /ui/uploaded-logs/file/{file_id}/resend": _J(
        "POST /uploads/{file_id}/resend", f"core.resend_uploaded_message {_E}"
    ),
    "GET /ui/uploaded-logs/file/{file_id}/resend-confirm": _J(
        "GET /uploads", f"core.list_uploaded_files {_E}"
    ),
    "GET /ui/uploaded-logs/file/{file_id}/delete-confirm": _J(
        "GET /uploads", f"core.list_uploaded_files {_E}"
    ),
    "POST /ui/uploaded-logs/file/{file_id}/delete": _J(
        "DELETE /uploads/{file_id}", f"core.delete_uploaded_file {_E}"
    ),
    "GET /ui/alerts": _J(
        "GET /alerts/active;GET /alerts/rules", f"core.alerts_rules core.list_active_alerts {_E}"
    ),
    "GET /ui/alerts/{alert_id}/reason": _J(
        "GET /alerts/active;GET /alerts/rules", f"core.alerts_rules core.list_active_alerts {_E}"
    ),
    "GET /ui/events": _J("GET /events", f"core.connection_event_page {_E}"),
    "GET /ui/events/{event_id}/reason": _J("GET /events", f"core.connection_event_page {_E}"),
    "GET /ui/monitoring": _J(
        "GET /graph/edges;GET /metrics/history", f"core.graph_edges core.metrics_history {_E}"
    ),
    "GET /ui/monitoring/live": _J(
        "GET /graph/edges;GET /metrics/history", f"core.graph_edges core.metrics_history {_E}"
    ),
    "GET /ui/status": _J(
        "GET /cluster/nodes;GET /cluster/status;GET /dr/status;GET /security/posture;"
        "GET /service/status;GET /status",
        "core.cluster_nodes core.cluster_status core.dr_status core.security_posture "
        f"core.service_status core.system_status {_E}",
    ),
    "GET /ui/nav-status": _J(
        "GET /alerts/active;GET /cluster/nodes;GET /cluster/status;GET /dr/status;GET /status",
        "core.cluster_nodes core.cluster_status core.dr_status core.list_active_alerts "
        f"core.system_status {_E}",
    ),
    "GET /ui/cluster": _J(
        "GET /cluster/nodes;GET /cluster/status", f"core.cluster_nodes core.cluster_status {_E}"
    ),
    "GET /ui/cluster/live": _J(
        "GET /cluster/nodes;GET /cluster/status", f"core.cluster_nodes core.cluster_status {_E}"
    ),
    "GET /ui/cluster/stepdown-confirm": _J(
        "GET /cluster/nodes;GET /cluster/status", f"core.cluster_nodes core.cluster_status {_E}"
    ),
    "GET /ui/cluster/force-stepdown-confirm": _J(
        "GET /cluster/nodes;GET /cluster/status", f"core.cluster_nodes core.cluster_status {_E}"
    ),
    "POST /ui/cluster/stepdown": _J("POST /cluster/stepdown", f"core.cluster_stepdown {_E}"),
    "POST /ui/cluster/force-stepdown": _J("POST /cluster/stepdown", f"core.cluster_stepdown {_E}"),
    "GET /ui/approvals": _J("GET /approvals", "core.list_approvals get_gate"),
    "POST /ui/approvals/{approval_id}/approve": _J(
        "POST /approvals/{approval_id}/approve", "core.approve_action get_gate"
    ),
    "POST /ui/approvals/{approval_id}/reject": _J(
        "POST /approvals/{approval_id}/reject", "core.reject_action get_gate"
    ),
    "POST /ui/approvals/{approval_id}/resolve/{outcome}": _J(
        "POST /approvals/{approval_id}/resolve", "core.resolve_action get_gate"
    ),
    "POST /ui/alerts/{alert_id}/ack": _J("POST /alerts/{alert_id}/ack", f"core.ack_alert {_E}"),
    "POST /ui/alerts/{alert_id}/resolve": _J(
        "POST /alerts/{alert_id}/resolve", f"core.resolve_alert {_E}"
    ),
    "POST /ui/alerts/{alert_id}/suspend": _J(
        "POST /alerts/{alert_id}/suspend",
        f"core.alerts_rules core.list_active_alerts core.suspend_alert {_E}",
    ),
    "POST /ui/alerts/{alert_id}/resume": _J(
        "POST /alerts/{alert_id}/resume", f"core.resume_alert {_E}"
    ),
    "POST /ui/statistics/reset": _J("POST /statistics/reset", f"core.reset_statistics {_E}"),
    "POST /ui/statistics/reset-one": _J("POST /statistics/reset", f"core.reset_statistics {_E}"),
    "POST /ui/statistics/reset-many": _J("POST /statistics/reset", f"core.reset_statistics {_E}"),
    "POST /ui/status/integrity-check": _J(
        "POST /status/integrity-check", f"core.integrity_check {_E}"
    ),
    "POST /ui/dr/activate": _J("POST /dr/activate", f"core.dr_activate {_E}"),
    "POST /ui/dr/release": _J("POST /dr/release", f"core.dr_release {_E}"),
    "POST /ui/connections/bulk-control": _J(
        "POST /connections/{name}/restart;POST /connections/{name}/start;"
        "POST /connections/{name}/stop",
        f"core.audit_channel_denied core.dual_role_control {_E}",
    ),
    "POST /ui/connections/{name}/flag": _J(
        "POST /connections/{name}/flag", f"core.audit_channel_denied core.set_connection_flag {_E}"
    ),
    "GET /ui/connections/purge-confirm": _J(
        "GET /connections", f"core.audit_channel_denied {_E} engine.registry_runner"
    ),
    "POST /ui/connections/purge-bulk": _J(
        "POST /connections/{name}/purge",
        f"core.audit_channel_denied core.purge_connection {_E} get_gate",
    ),
    "POST /ui/connections/{name}/purge/{scope}": _J(
        "POST /connections/{name}/purge", f"core.purge_connection {_E} get_gate"
    ),
    "GET /ui/config": _J("GET /config/provenance", f"core.config_provenance {_E}"),
    "POST /ui/config/reload": _J("POST /config/reload", f"core.reload_config {_E} get_gate"),
    "GET /ui/sso": Ui("public", "", _AS),
    "GET /ui/oidc/start": Ui("public", "", _AS),
    "POST /ui/oidc/start": Ui("public", "", _AS),
    "POST /ui/reauth/oidc": Ui("public", "", _AS),
    "GET /ui/oidc/callback": Ui("public", "", _AS),
}

#: The four ``/ui`` legs ``oidc.register`` adds only when ``[auth].oidc_enabled`` is set.
_OIDC_ONLY = frozenset(
    {"GET /ui/oidc/start", "POST /ui/oidc/start", "POST /ui/reauth/oidc", "GET /ui/oidc/callback"}
)


# =====================================================================================================
# The comparisons, as functions a planted table can be run through
# =====================================================================================================

_PROSE_CARRIERS = ("MOVE", "DROP", "KEEP")
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})


def _is_op(text: str) -> bool:
    method, _, path = text.partition(" ")
    return method in _HTTP_METHODS and path.startswith("/")


def _carrier_problems(where: str, carriers: tuple[str, ...], json: Mapping[str, Any]) -> list[str]:
    """A carrier is a JSON operation the app serves, an ``ADD`` of one it does not serve yet, or a
    ``MOVE``/``DROP``/``KEEP`` line."""
    problems = []
    for carrier in carriers:
        if carrier.startswith("ADD "):
            op = carrier.removeprefix("ADD ")
            if not _is_op(op):
                problems.append(f"{where}: {carrier!r} names no METHOD /path")
            elif op in json:
                problems.append(
                    f"{where}: {op} now exists, so reclassify the entry that adds it ({carrier!r})"
                )
        elif carrier.startswith(_PROSE_CARRIERS):
            continue
        elif carrier not in json:
            problems.append(f"{where}: carrier {carrier!r} is not a JSON operation of the app")
    return problems


def _routable(carriers: tuple[str, ...]) -> tuple[str, ...]:
    """The carriers a sub-request can go to, now or once slice 2 adds them."""
    return tuple(c.removeprefix("ADD ") for c in carriers if not c.startswith(_PROSE_CARRIERS))


def _set_problems(what: str, found: set[str], table: Mapping[str, object]) -> list[str]:
    """The live set and a table's keys agree: nothing unclassified, nothing stale."""
    return [f"unclassified {what} {n}" for n in sorted(found - set(table))] + [
        f"{n} is classified but is no {what} of the app" for n in sorted(set(table) - found)
    ]


def _named_function(found: Mapping[int, Any], name: str) -> Any | None:
    return next((fn for fn in found.values() if fn.__name__ == name), None)


def _field_problems(
    fields: Mapping[str, Any], json: Mapping[str, APIRoute], table: Mapping[str, Field]
) -> list[str]:
    """Each seam field is classified, and its class is what the live objects show."""
    problems = _set_problems("seam field", set(fields), table)
    endpoint_ops: dict[int, set[str]] = {}
    for op, route in json.items():
        endpoint_ops.setdefault(id(route.endpoint), set()).add(op)
    for name in sorted(set(fields) & set(table)):
        obj, entry = fields[name], table[name]
        problems += _carrier_problems(name, entry.carrier, json)
        is_endpoint_of = endpoint_ops.get(id(obj), set())
        if entry.kind == "endpoint":
            if is_endpoint_of != set(entry.carrier):
                problems.append(
                    f"{name}: classed endpoint of {sorted(entry.carrier)}, but it is the endpoint "
                    f"of {sorted(is_endpoint_of) or 'no JSON route'}"
                )
            continue
        if is_endpoint_of:
            problems.append(
                f"{name}: classed {entry.kind}, but it is the endpoint of {sorted(is_endpoint_of)}"
            )
            continue
        reaching = [op for op in entry.carrier if op in json]
        if entry.kind == "core":
            for op in reaching:
                if id(obj) not in _engine_reach(json[op].endpoint):
                    problems.append(
                        f"{name}: classed core of {op}, whose endpoint does not reach it"
                    )
            if not reaching:
                problems.append(f"{name}: classed core, but names no JSON route")
        elif entry.kind == "shared":
            helper = _named_function(_engine_reach(obj), entry.via)
            if helper is None:
                problems.append(f"{name}: does not reach {entry.via}")
            for op in reaching:
                reach = _engine_reach(json[op].endpoint)
                if id(obj) in reach:
                    problems.append(f"{name}: {op} reaches it, so it is core, not shared")
                if helper is not None and id(helper) not in reach:
                    problems.append(f"{name}: {op} does not reach {entry.via}")
            if not reaching:
                problems.append(f"{name}: classed shared, but names no JSON route")
        elif any(_is_op(c) for c in entry.carrier):
            problems.append(f"{name}: a helper carries ADD, MOVE, DROP or KEEP lines only")
    return problems


def _token_carriers(token: str, fields: Mapping[str, Field]) -> tuple[str, ...] | None:
    """What carries one reach token, or None for a token that names no engine data."""
    if token in fields:
        return fields[token].carrier
    if token.startswith("service.store."):
        return _STORE_READS.get(token.removeprefix("service.store."))
    if token.startswith("service."):
        use = _AUTH_SERVICE.get(token.removeprefix("service."))
        return use.carrier if use is not None else None
    if token.startswith(("engine.", "gate.")):
        return _ENGINE_READS.get(token)
    return None


def _ui_problems(
    ui: Mapping[str, APIRoute],
    derived: Mapping[str, frozenset[str]],
    permissions: Mapping[str, tuple[str, ...]],
    json: Mapping[str, APIRoute],
    table: Mapping[str, Ui],
    fields: Mapping[str, Field],
) -> list[str]:
    """Each ``/ui`` operation is classified, its reach is the pinned one, and its authority holds
    together with what it reaches."""
    problems = _set_problems("/ui route", set(ui), table)
    for op in sorted(set(ui) & set(table)):
        entry = table[op]
        reach = derived[op]
        pinned = frozenset(entry.reach.split())
        if reach != pinned:
            problems.append(
                f"{op}: reaches {sorted(reach)}, but the table pins {sorted(pinned)}; "
                f"new {sorted(reach - pinned)}, gone {sorted(pinned - reach)}"
            )
        authority = tuple(a for a in entry.authority.split(";") if a)
        problems += _carrier_problems(op, authority, json)
        bare = {a.removeprefix("ADD ") for a in authority}
        is_public = route_declaration_of(ui[op].endpoint) is not None
        if is_public != (entry.kind == "public"):
            problems.append(f"{op}: classed {entry.kind}, but public_route says {is_public}")
        carried: dict[str, tuple[str, ...]] = {}
        for token in reach:
            routable = _routable(_token_carriers(token, fields) or ())
            if routable:
                carried[token] = routable
        if entry.kind == "json":
            if not authority:
                problems.append(f"{op}: classed json with no authority")
            offered = {c for routes in carried.values() for c in routes}
            for a in sorted(bare - offered):
                problems.append(f"{op}: authority {a} carries nothing the route reaches")
            # A GET page needs every read it shows. A write needs each write it reaches; the page
            # it re-renders is read on the following GET (ADR 0215 section 2, one write per POST).
            is_get = op.startswith("GET ")
            for token, routes in sorted(carried.items()):
                writes = any(not r.startswith("GET ") for r in routes)
                if (is_get or writes) and not bare & set(routes):
                    problems.append(f"{op}: reaches {token}, which none of its authority carries")
        elif entry.kind == "check":
            needed = {f"GET /auth/check/{p}" for p in permissions.get(op, ())}
            if not authority or bare != needed:
                problems.append(
                    f"{op}: a check route's authority is its gate's check routes {sorted(needed)}, "
                    f"not {sorted(bare)}"
                )
            if carried:
                problems.append(f"{op}: classed check, but reads {sorted(carried)}")
        elif authority:
            problems.append(f"{op}: classed {entry.kind}, which carries no authority")
    return problems


# =====================================================================================================
# Readings of the live app the tests share
# =====================================================================================================


def _read_tokens() -> frozenset[str]:
    """The ``AuthService`` tokens a route's reach records: the ``read`` members and the store
    reads. Every other member is the console's gate or a ceremony leg (see ``AuthUse``)."""
    members = {f"service.{m}" for m, use in _AUTH_SERVICE.items() if use.kind == "read"}
    return frozenset(members | {f"service.store.{n}" for n in _STORE_READS})


@pytest.fixture(scope="module")
def derived(live: _Live) -> dict[str, frozenset[str]]:
    reads = _read_tokens()
    return {op: _ui_reach(r, live.deps, reads) for op, r in _ui_routes(live.app).items()}


@pytest.fixture(scope="module")
def ui_permissions(live: _Live) -> dict[str, tuple[str, ...]]:
    return {
        f"{row.method} {row.path}": row.permissions
        for row in route_rows(live.app)
        if row.path.startswith("/ui")
    }


@pytest.fixture(scope="module")
def surface() -> Any:
    return seam_discovery.discover(_CONSOLE_DIR, _ROOT / "messagefoundry")


def _source_attributes(receivers: frozenset[str], *, through: str | None = None) -> set[str]:
    """Attribute names the console source reads off a name in ``receivers``, or with ``through``
    off ``<receiver>.<through>``. Read from the AST, so a comment or a string never counts."""
    found: set[str] = set()
    trees = package_trees()
    for tree in (t for path, t in trees.items() if path.startswith(f"{_CONSOLE_PACKAGE}/")):
        for node in ast.walk(tree):
            if not isinstance(node, ast.Attribute):
                continue
            value = node.value
            if through is not None:
                if not (isinstance(value, ast.Attribute) and value.attr == through):
                    continue
                value = value.value
            if isinstance(value, ast.Name) and value.id in receivers:
                found.add(node.attr)
    return found


# =====================================================================================================
# The tests
# =====================================================================================================


def test_every_seam_field_is_classified_as_the_app_holds(live: _Live) -> None:
    problems = _field_problems(_seam_fields(live.deps), _json_routes(live.app), _SEAM_FIELDS)
    assert not problems, "\n".join(problems)


def test_the_seam_field_counts_are_the_measured_ones() -> None:
    """ADR 0215 slice 1 measured 86 fields, 66 of them a JSON route's endpoint by identity."""
    counts = Counter(f.kind for f in _SEAM_FIELDS.values())
    assert counts == {"endpoint": 66, "core": 15, "shared": 2, "helper": 3}, counts


def test_every_ui_deps_field_is_classified() -> None:
    problems = _set_problems(
        "UiDeps field", {f.name for f in dataclasses.fields(UiDeps)}, _UI_DEPS_FIELDS
    )
    assert not problems, "\n".join(problems)


def test_every_auth_service_member_the_console_reaches_is_classified(
    live: _Live, surface: Any
) -> None:
    problems = _set_problems("AuthService member", set(surface.auth_service_methods), _AUTH_SERVICE)
    json = _json_routes(live.app)
    for member, use in sorted(_AUTH_SERVICE.items()):
        assert hasattr(AuthService, member), member
        if use.kind == "read":
            problems += _carrier_problems(f"AuthService.{member}", use.carrier, json)
            if not use.carrier:
                problems.append(f"AuthService.{member}: a read with no carrier")
        elif use.carrier:
            problems.append(f"AuthService.{member}: only a read names a carrier")
    assert not problems, "\n".join(problems)


def test_every_store_and_engine_object_read_is_classified(live: _Live) -> None:
    """The auth store's reads and the attributes read off the engine or gate object itself."""
    store = _source_attributes(_AUTH_RECEIVERS, through="store")
    engine = {f"{r}.{a}" for r in _ENGINE_RECEIVERS for a in _source_attributes(frozenset({r}))}
    problems = _set_problems("auth-store read", store, _STORE_READS)
    problems += _set_problems("engine-object read", engine, _ENGINE_READS)
    json = _json_routes(live.app)
    problems += [p for name, c in _STORE_READS.items() for p in _carrier_problems(name, c, json)]
    problems += [p for name, c in _ENGINE_READS.items() for p in _carrier_problems(name, c, json)]
    assert not problems, "\n".join(problems)


def test_every_app_state_attribute_is_classified(surface: Any) -> None:
    problems = _set_problems("app.state attribute", set(surface.app_state_attrs), _APP_STATE)
    assert not problems, "\n".join(problems)


def test_every_ui_route_is_classified_by_the_json_route_carrying_its_authority(
    live: _Live,
    derived: dict[str, frozenset[str]],
    ui_permissions: dict[str, tuple[str, ...]],
) -> None:
    problems = _ui_problems(
        _ui_routes(live.app),
        derived,
        ui_permissions,
        _json_routes(live.app),
        _UI_ROUTES,
        _SEAM_FIELDS,
    )
    assert not problems, "\n".join(problems)


def test_the_ui_route_counts_are_the_measured_ones() -> None:
    """127 ``/ui`` operations with OIDC off, as ADR 0215 measured, and 4 OIDC legs."""
    default = set(_ui_routes(create_app(serve_ui=True)))
    assert len(default) == 127
    assert set(_UI_ROUTES) == default | _OIDC_ONLY
    counts = Counter(u.kind for u in _UI_ROUTES.values())
    assert counts == {"json": 107, "public": 15, "confinement": 3, "ceremony": 3, "check": 3}, (
        counts
    )


def test_the_reach_reading_sees_every_seam_field_the_console_names(
    derived: dict[str, frozenset[str]],
) -> None:
    """The calibration. A field the console's source names that no route's reach records is a
    path the bytecode reading does not follow, so every route table above would be blind to it."""
    names = {n.partition(".")[2] for n in _SEAM_FIELDS}
    named = {
        f"{r}.{a}"
        for r in ("core", "admin")
        for a in _source_attributes(frozenset({r}))
        | _source_attributes(frozenset({"deps"}), through=r)
        if a in names
    }
    reached = {t for tokens in derived.values() for t in tokens if t in _SEAM_FIELDS}
    assert named - reached == set(), (
        f"named in the source, reached by no route: {sorted(named - reached)}"
    )
    assert len(reached) >= 80, (
        f"only {len(reached)} seam fields reached: the reading has gone blind"
    )


# =====================================================================================================
# Positive controls: each comparison fails on a removed entry and on an unclassified addition
# =====================================================================================================


def test_a_removed_or_added_seam_field_is_reported(live: _Live) -> None:
    fields = _seam_fields(live.deps)
    json = _json_routes(live.app)
    removed = {k: v for k, v in _SEAM_FIELDS.items() if k != "core.get_message_body"}
    assert "unclassified seam field core.get_message_body" in _field_problems(fields, json, removed)

    async def planted() -> None:
        return None

    added = {**fields, "core.planted_handler": planted}
    assert "unclassified seam field core.planted_handler" in _field_problems(
        added, json, _SEAM_FIELDS
    )


def test_a_wrong_seam_field_class_is_reported(live: _Live) -> None:
    fields = _seam_fields(live.deps)
    json = _json_routes(live.app)
    planted = {
        **_SEAM_FIELDS,
        # An endpoint classed as a core, a core classed as an endpoint, and a shared helper
        # named wrong.
        "core.get_message": _core("GET /messages/{message_id}"),
        "core.reload_config": _endpoint("POST /config/reload"),
        "admin.list_audit": Field("shared", ("GET /audit",), via="_not_a_helper"),
        # A route to add that the app already serves.
        "core.prior_resend": Field("helper", ("ADD GET /connections",)),
    }
    problems = "\n".join(_field_problems(fields, json, planted))
    assert "core.get_message: classed core, but it is the endpoint" in problems
    assert "core.reload_config: classed endpoint" in problems
    assert "admin.list_audit: does not reach _not_a_helper" in problems
    assert "GET /connections now exists" in problems


def test_a_removed_or_added_ui_route_is_reported(
    live: _Live,
    derived: dict[str, frozenset[str]],
    ui_permissions: dict[str, tuple[str, ...]],
) -> None:
    ui = _ui_routes(live.app)
    json = _json_routes(live.app)
    removed = {k: v for k, v in _UI_ROUTES.items() if k != "GET /ui/config"}
    assert "unclassified /ui route GET /ui/config" in _ui_problems(
        ui, derived, ui_permissions, json, removed, _SEAM_FIELDS
    )
    added_ui = {**ui, "GET /ui/planted": ui["GET /ui/config"]}
    added_derived = {**derived, "GET /ui/planted": derived["GET /ui/config"]}
    assert "unclassified /ui route GET /ui/planted" in _ui_problems(
        added_ui, added_derived, ui_permissions, json, _UI_ROUTES, _SEAM_FIELDS
    )


def test_a_changed_ui_reach_or_authority_is_reported(
    live: _Live,
    derived: dict[str, frozenset[str]],
    ui_permissions: dict[str, tuple[str, ...]],
) -> None:
    ui = _ui_routes(live.app)
    json = _json_routes(live.app)
    # The route starts reaching a handler nobody classified it for.
    grown = {**derived, "GET /ui/config": derived["GET /ui/config"] | {"core.get_message_body"}}
    problems = "\n".join(_ui_problems(ui, grown, ui_permissions, json, _UI_ROUTES, _SEAM_FIELDS))
    assert "GET /ui/config: reaches" in problems and "new ['core.get_message_body']" in problems
    planted = {
        **_UI_ROUTES,
        # A PHI page that drops its body read from its authority, and a check page given a
        # permission its gate does not name.
        "GET /ui/messages/{message_id}": _J(
            "GET /messages/{message_id}", f"core.get_message core.get_message_body {_E}"
        ),
        "GET /ui/roles/new": Ui("check", "ADD GET /auth/check/monitoring:read", ""),
    }
    problems = "\n".join(_ui_problems(ui, derived, ui_permissions, json, planted, _SEAM_FIELDS))
    assert "GET /ui/messages/{message_id}: reaches core.get_message_body" in problems
    assert "GET /ui/roles/new: a check route's authority" in problems
