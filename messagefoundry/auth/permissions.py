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

from collections.abc import Iterable
from enum import Enum


class Permission(str, Enum):
    """A single capability a role may grant. The value is the wire/storage string."""

    MONITORING_READ = "monitoring:read"
    MONITORING_DIAGNOSE = "monitoring:diagnose"
    MESSAGES_READ = "messages:read"
    MESSAGES_VIEW_SUMMARY = "messages:view_summary"  # PHI: patient identifiers in list summaries
    MESSAGES_VIEW_RAW = "messages:view_raw"  # PHI: the full message body
    MESSAGES_REPLAY = "messages:replay"
    MESSAGES_PURGE = "messages:purge"
    CONNECTIONS_CONTROL = "connections:control"
    CONFIG_DEPLOY = "config:deploy"  # endpoint lands in a later effort
    CONFIG_VALIDATE = "config:validate"  # endpoint lands in a later effort
    CODE_EDIT = "code:edit"  # endpoint lands in a later effort
    AI_ASSIST = "ai:assist"  # use AI coding assistance (IDE), gated by /ai/policy
    SERVICE_CONFIGURE = "service:configure"  # endpoint lands in a later effort
    USERS_READ = "users:read"
    USERS_MANAGE = "users:manage"
    AUDIT_READ = "audit:read"


class Role(str, Enum):
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
    Role.VIEWER: ("Viewer", "Read-only dashboards and non-PHI message metadata."),
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
        Permission.MESSAGES_PURGE,
        Permission.CONNECTIONS_CONTROL,
    }
)

#: The fixed built-in RBAC policy — which permissions each role grants. Holding multiple roles unions.
BUILTIN_ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.ADMINISTRATOR: frozenset(Permission),  # every permission
    Role.OPERATOR: _OPERATOR_PERMISSIONS,
    Role.DEPLOYMENT: frozenset(
        {Permission.MONITORING_READ, Permission.CONFIG_DEPLOY, Permission.CONFIG_VALIDATE}
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
    Role.AUDITOR: frozenset({Permission.MONITORING_READ, Permission.AUDIT_READ}),
}


def permissions_for_roles(roles: Iterable[Role]) -> frozenset[Permission]:
    """Union of the permissions granted by ``roles`` (deny-by-default: unknown roles grant nothing)."""
    granted: set[Permission] = set()
    for role in roles:
        granted |= BUILTIN_ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)
