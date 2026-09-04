# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Permission catalog and the fixed built-in roles for RBAC.

Authorization is **deny-by-default**: an action is allowed only when one of the caller's roles grants
the matching :class:`Permission`. This version ships a *fixed* set of built-in :class:`Role` s (no
custom-role builder yet), so ``BUILTIN_ROLE_PERMISSIONS`` below is the single source of truth — it is
seeded into the ``roles`` table on store open and consulted when resolving an
:class:`~messagefoundry.auth.identity.Identity`.

A few permissions (``config:deploy``, ``config:validate``, ``code:edit``, ``service:configure``) have
no API endpoint yet; they are defined now so the Deployment/Coding roles are complete and those
endpoints can be gated the moment they land, without a roles migration.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from enum import Enum


class Permission(str, Enum):  # noqa: UP042
    """A single capability a role may grant. The value is the wire/storage string."""

    MONITORING_READ = "monitoring:read"
    MONITORING_DIAGNOSE = "monitoring:diagnose"
    MESSAGES_READ = "messages:read"
    MESSAGES_VIEW_SUMMARY = "messages:view_summary"  # PHI: patient identifiers in list summaries
    MESSAGES_VIEW_RAW = "messages:view_raw"  # PHI: the full message body
    MESSAGES_REPLAY = "messages:replay"
    MESSAGES_RESEND = "messages:resend"  # resend a stored body to an ALTERNATE outbound (ADR 0090)
    # Edit a stored message and resubmit the edited body (ADR 0090 §9, BACKLOG #153). The edited body IS
    # PHI, so this IMPLIES messages:view_raw — every built-in role granting it also grants view_raw (the
    # client fetches the editable copy over the view_raw seam). Deny-by-default: no role gets it for free.
    MESSAGES_EDIT = "messages:edit"
    # Bulk-export raw message bodies from a search result to a file (BACKLOG #124, ADR 0131). The LARGEST
    # PHI egress surface, so it is a DISTINCT capability from messages:view_raw (bulk ≠ opening one
    # message); the export route also requires messages:view_raw + step-up. Deny-by-default.
    MESSAGES_EXPORT = "messages:export"
    MESSAGES_PURGE = "messages:purge"
    CONNECTIONS_CONTROL = "connections:control"
    CONNECTIONS_TEST = (
        "connections:test"  # probe a connection's reachability (POST /connections/{name}/test)
    )
    DR_OPERATE = "dr:operate"  # promote/release a third-tier DR standby (POST /dr/activate|release, ADR 0048)
    CONFIG_DEPLOY = "config:deploy"  # endpoint lands in a later effort
    CONFIG_VALIDATE = "config:validate"  # endpoint lands in a later effort
    CODE_EDIT = "code:edit"  # endpoint lands in a later effort
    AI_ASSIST = "ai:assist"  # use AI coding assistance (IDE), gated by /ai/policy
    SERVICE_CONFIGURE = "service:configure"  # endpoint lands in a later effort
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"  # download a filtered audit report (CSV export, BACKLOG #170)
    # PHI: the redacted application-log tail (best-effort redaction, residual single-token PHI possible).
    # Gates GET /logs/tail (BACKLOG #171, ADR 0130) — a genuine PHI read surface, so audited + hop-guarded
    # like a message view, not treated as free operational text.
    LOGS_VIEW = "logs:view"
    # Offline uploaded-logs (BACKLOG #125/#126, ADR 0134). Three deny-by-default capabilities over the
    # connection-decoupled uploaded-file subsystem. FILES_BROWSE reads real HL7 PHI at rest, so its
    # routes also require step-up + the PHI-read hop guard (like content search); FILES_DELETE is a
    # destructive, audited cleanup. None is granted for free.
    FILES_UPLOAD = "files:upload"  # import an external message file (writes PHI at rest)
    FILES_BROWSE = "files:browse"  # list/browse/resend an uploaded file's messages (PHI read)
    FILES_DELETE = "files:delete"  # delete an uploaded file from the server (destructive)
    # Object-level override for the uploaded-file subsystem (ASVS 8.2.2). Uploaded files are OWNER-ONLY:
    # `files:browse`/`files:delete` reach only the files the caller uploaded. The channel axis cannot do
    # this job at all -- an uploaded file is decoupled from any connection and so carries no channel to
    # scope by, which is why ownership is the resource attribute (ADR 0134 Amendment A, owner-ratified).
    # The rejection was ALSO argued at the time from `Identity.allowed_channels` defaulting to every
    # channel; BACKLOG #1152 has since made that default DENY, so only the first reason still stands and
    # the owner-only decision is unchanged by the flip. This permission widens that object scope to every
    # uploader's files, for administrative
    # oversight and cleanup after a departed operator. It is NOT a capability of its own — a holder
    # still needs `files:browse` / `files:delete` for the route itself — and no built-in role but
    # ADMINISTRATOR (which is the whole catalogue) grants it. Never assignable to a custom role
    # (CUSTOM_ROLE_FORBIDDEN_PERMISSIONS), so "Administrator only" is enforced on every minting path
    # rather than only observed of the built-ins.
    FILES_ACCESS_ANY = "files:access_any"  # reach ANOTHER operator's uploaded files
    APPROVALS_APPROVE = (
        "approvals:approve"  # release a pending high-value action (dual-control, 2.3.5)
    )


class Role(str, Enum):  # noqa: UP042
    """A fixed built-in role. The role->permission policy lives in ``BUILTIN_ROLE_PERMISSIONS``."""

    ADMINISTRATOR = "administrator"
    OPERATOR = "operator"
    DEPLOYMENT = "deployment"
    CODING = "coding"
    VIEWER = "viewer"
    AUDITOR = "auditor"


#: Human-facing (label, description) per role — seeded into the ``roles`` table for listing/admin UI.
ROLE_METADATA: dict[Role, tuple[str, str]] = {
    Role.ADMINISTRATOR: (
        "Administrator",
        "Full control, including user and service administration.",
    ),
    Role.OPERATOR: (
        "Operator",
        "Day-to-day monitoring and message operations, including PHI viewing.",
    ),
    Role.DEPLOYMENT: ("Deployment", "Deploy and validate the connection/router/handler graph."),
    Role.CODING: ("Coding", "Author and validate Router/Handler code."),
    Role.VIEWER: (
        "Viewer",
        "Read-only dashboards and message list metadata (PHI fields withheld).",
    ),
    Role.AUDITOR: ("Auditor", "Read the audit trail (separation of duties)."),
}

_OPERATOR_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.MONITORING_READ,
        Permission.MONITORING_DIAGNOSE,
        Permission.MESSAGES_READ,
        Permission.MESSAGES_VIEW_SUMMARY,
        Permission.MESSAGES_VIEW_RAW,
        Permission.MESSAGES_REPLAY,
        Permission.MESSAGES_RESEND,
        Permission.MESSAGES_EDIT,  # implies view_raw (co-granted above) — ADR 0090 §9 / BACKLOG #153
        Permission.MESSAGES_EXPORT,  # bulk body export (BACKLOG #124) — operator already holds view_raw
        Permission.MESSAGES_PURGE,
        Permission.CONNECTIONS_CONTROL,
        Permission.CONNECTIONS_TEST,
        # Read the redacted application-log tail during an incident (BACKLOG #171) — the operator already
        # holds messages:view_raw, so the redacted log is a strictly-lesser PHI surface for the same role.
        Permission.LOGS_VIEW,
        # Offline uploaded-logs (BACKLOG #125/#126) — inspecting a partner-supplied file is an operator
        # troubleshooting action; the operator already holds messages:view_raw, so browsing an uploaded
        # body is a same-tier PHI surface for the same role. These three reach the operator's OWN
        # uploads only (ASVS 8.2.2): FILES_ACCESS_ANY, the cross-operator override, is deliberately NOT
        # granted here — one operator troubleshooting their own file is not a reason to read, re-inject
        # or delete another operator's.
        Permission.FILES_UPLOAD,
        Permission.FILES_BROWSE,
        Permission.FILES_DELETE,
    }
)

#: The fixed built-in RBAC policy — which permissions each role grants. Holding multiple roles unions.
BUILTIN_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMINISTRATOR: frozenset(Permission),  # every permission
    Role.OPERATOR: _OPERATOR_PERMISSIONS,
    Role.DEPLOYMENT: frozenset(
        {
            Permission.MONITORING_READ,
            Permission.CONFIG_DEPLOY,
            Permission.CONFIG_VALIDATE,
            Permission.CONNECTIONS_TEST,
        }
    ),
    Role.CODING: frozenset(
        {
            Permission.MONITORING_READ,
            Permission.CODE_EDIT,
            Permission.CONFIG_VALIDATE,
            Permission.AI_ASSIST,
        }
    ),
    Role.VIEWER: frozenset({Permission.MONITORING_READ, Permission.MESSAGES_READ}),
    Role.AUDITOR: frozenset(
        {Permission.MONITORING_READ, Permission.AUDIT_READ, Permission.AUDIT_EXPORT}
    ),
}


def permissions_for_roles(roles: Iterable[Role]) -> frozenset[Permission]:
    """Union of the permissions granted by ``roles`` (deny-by-default: unknown roles grant nothing)."""
    granted: set[Permission] = set()
    for role in roles:
        granted |= BUILTIN_ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


# --- custom (admin-defined) roles (ADR 0045) ---------------------------------
# A custom role is an admin-defined named SUBSET of the EXISTING Permission catalog (no new permission
# kinds). It is an *additive overlay*: the six fixed built-ins above stay verbatim; a custom role can
# only ever grant capabilities the catalog already defines. These helpers are the single resolver +
# validator for that subset so deny-by-default is enforced in exactly one place.

#: Prefix a custom role id must carry, so it can never collide with a built-in :class:`Role` value and
#: be mis-routed to the built-in resolver (ADR 0045 "Built-in id collision").
CUSTOM_ROLE_ID_PREFIX = "custom:"

#: Permissions a custom role may **not** grant — privilege-escalation primitives the fixed
#: ``ADMINISTRATOR`` deliberately gates (ADR 0045 D1). ``USERS_MANAGE`` is the permission that mints
#: roles (a custom role holding it could grant itself admin-equivalent power); ``APPROVALS_APPROVE`` is
#: dual-control release; ``DR_OPERATE`` (ADR 0048) promotes/releases a whole third-tier DR standby box
#: (a site-failover-grade action); ``FILES_ACCESS_ANY`` (ASVS 8.2.2) is the override that defeats
#: owner-only on every uploaded file, so leaving it mintable would let a custom role read, re-inject
#: and delete every operator's uploaded PHI while docs/SECURITY.md says it is Administrator-only.
#: All stay admin-only.
CUSTOM_ROLE_FORBIDDEN_PERMISSIONS: frozenset[Permission] = frozenset(
    {
        Permission.USERS_MANAGE,
        Permission.APPROVALS_APPROVE,
        Permission.DR_OPERATE,
        Permission.FILES_ACCESS_ANY,
    }
)


def is_custom_role_id(role_id: str) -> bool:
    """True iff ``role_id`` is a custom-role id (carries :data:`CUSTOM_ROLE_ID_PREFIX`) and is therefore
    resolved from the persisted ``roles.permissions`` set rather than :data:`BUILTIN_ROLE_PERMISSIONS`."""
    return role_id.startswith(CUSTOM_ROLE_ID_PREFIX)


class CustomRoleError(ValueError):
    """A proposed custom-role permission set is invalid (empty, unknown, or a carved-out capability)."""


def validate_custom_role_permissions(values: Iterable[str]) -> list[Permission]:
    """Validate an admin-proposed custom-role permission set and return it as sorted ``Permission``s.

    Enforces the ADR 0045 D1 rules on write (the API gates this behind ``USERS_MANAGE``):
    every value must be a recognized catalog ``Permission`` (no new permission kinds), the set may
    not be empty, and it may not contain a carved-out escalation primitive
    (:data:`CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`). Raises :class:`CustomRoleError` otherwise.
    """
    perms: set[Permission] = set()
    unknown: list[str] = []
    for value in values:
        try:
            perms.add(Permission(value))
        except ValueError:
            unknown.append(value)
    if unknown:
        raise CustomRoleError(f"unknown permission(s): {', '.join(sorted(set(unknown)))}")
    if not perms:
        raise CustomRoleError("a custom role must grant at least one permission")
    forbidden = perms & CUSTOM_ROLE_FORBIDDEN_PERMISSIONS
    if forbidden:
        raise CustomRoleError(
            "permission(s) not assignable to a custom role: "
            + ", ".join(sorted(p.value for p in forbidden))
        )
    return sorted(perms, key=lambda p: p.value)


def decode_custom_role_permissions(raw: str | None) -> frozenset[Permission]:
    """Decode a persisted ``roles.permissions`` JSON array into a deny-by-default ``Permission`` set.

    Defensive against an untrusted/hand-edited DB row (ADR 0045 D3): a missing/malformed/non-list JSON
    yields the empty set, and any value not in the current ``Permission`` catalog — or a carved-out
    escalation primitive that somehow reached storage — is **dropped** (grants nothing). A custom role
    is never trusted to widen the trust surface, only to re-bundle existing capabilities.
    """
    if not raw:
        return frozenset()
    try:
        values = json.loads(raw)
    except (ValueError, TypeError):
        return frozenset()
    if not isinstance(values, list):
        return frozenset()
    granted: set[Permission] = set()
    for value in values:
        try:
            perm = Permission(value)
        except ValueError:
            continue
        if perm in CUSTOM_ROLE_FORBIDDEN_PERMISSIONS:
            continue  # belt-and-braces: a forbidden perm in storage still grants nothing
        granted.add(perm)
    return frozenset(granted)
