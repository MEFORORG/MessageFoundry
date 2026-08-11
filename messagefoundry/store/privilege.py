# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Startup preflight on the **effective privileges of the store principal** (BACKLOG #1008, ASVS 13.2.2).

Both server-DB runbooks prescribe a least-privilege grant for the engine's database principal
(``docs/DEPLOY-SERVER-DB.md`` §1.1 for SQL Server, §1.2 for Postgres). Until this module the engine
could not **observe** whether the principal it actually connects as matches that prescription: no
fixed-server-role probe and no database-role-membership probe existed anywhere in the four packages
the ASVS scorecard scans, and ``[store].require_managed_identity`` constrains the credential's *kind*
(Windows Integrated / Entra vs a static SQL login), never its privilege — a ``sysadmin`` gMSA
satisfies it clean. So on a first deployment an over-granted store principal **would** go unobserved.
Nothing is over-granted today: MessageFoundry is a not-deployed beta with zero instances.

**The shape, and it is the whole design: OBSERVE AND WARN LOUDLY FIRST.**

* The **WARN** arm ships **ON**. It is a log line plus an audit row plus a
  :func:`~messagefoundry.config.settings.security_loosenings` entry; it cannot block any install.
* The **REFUSE** arm is gated behind operator-declared ``[store].require_least_privilege`` (default
  ``False``) — a preflight that refused on over-grant by default could block a legitimate deployment
  mid-setup, which is not this control's job. Like the ``require_managed_identity`` gate it copies,
  the declared refusal downgrades to a warning under ``[security].enforcement = warn``.
* It must not fail **open** either. A probe that cannot run — permission denied, an unsupported
  backend, a store handle with no probe at all — reports :attr:`StorePrivilegeStatus.UNOBSERVABLE`,
  which is a distinct, named, loud condition everywhere it surfaces: a different log line, a
  different audit ``status``, and its own posture entry. *"Could not observe"* and *"observed, and
  it is fine"* are never the same output. Under a declared ``require_least_privilege`` an
  unobservable probe **refuses**, because a control that cannot see is exactly the fail-open shape
  the setting was turned on to prevent.
* SQLite reports :attr:`StorePrivilegeStatus.NOT_APPLICABLE` and says what it did instead of
  pretending it ran: a local file has no server principal, and its access control is the filesystem's.

**This module names ``IS_SRVROLEMEMBER`` / ``IS_ROLEMEMBER`` / ``db_owner`` / ``sysadmin`` on
purpose, and that flips ASVS cell 13.2.2's absence claim** (``pattern =
"IS_SRVROLEMEMBER|IS_ROLEMEMBER|db_owner|sysadmin"``, scanned over ``messagefoundry``,
``messagefoundry_webconsole``, ``harness`` and ``scripts`` — see
``tests/test_docs_db_grants.py``). That is the scorecard correctly noticing the code changed, not a
lint failure to be worked around by obfuscating the SQL. The paired vault-side re-score is a separate,
deliberate act; do not hide these tokens to keep an absence claim green that is no longer true.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from messagefoundry.config.settings import (
    StoreBackend,
    StorePrivilegePosture,
    StorePrivilegeStatus,
)
from messagefoundry.support.redact import redact_log_line

if TYPE_CHECKING:  # pragma: no cover - typing only
    from messagefoundry.store.base import Store

log = logging.getLogger(__name__)

__all__ = [
    "POSTGRES_EXCESSIVE_ROLES",
    "SQLSERVER_DOCUMENTED_DATABASE_ROLES",
    "SQLSERVER_FIXED_DATABASE_ROLES",
    "SQLSERVER_FIXED_SERVER_ROLES",
    "PostgresRoleFacts",
    "PrivilegeProbeStore",
    "StorePrivilegeError",
    "StorePrivilegeReport",
    "postgres_excess",
    "probe_failure",
    "run_store_privilege_preflight",
    "sqlserver_excess",
]


class StorePrivilegeError(RuntimeError):
    """Raised by the preflight when ``[store].require_least_privilege`` is declared and the principal
    is over-granted (or could not be observed) — the caller refuses to start before any listener binds."""


# --- SQL Server -------------------------------------------------------------------------------
#: The closed set of SQL Server FIXED SERVER roles, probed by name rather than enumerated from
#: ``sys.server_principals``: catalog visibility is permission-filtered, so an enumeration that comes
#: back empty is indistinguishable from "a member of nothing" — the false-clean this control exists to
#: prevent. ``IS_SRVROLEMEMBER`` answers for the CURRENT login and needs no catalog permission.
SQLSERVER_FIXED_SERVER_ROLES: tuple[str, ...] = (
    "sysadmin",
    "securityadmin",
    "serveradmin",
    "setupadmin",
    "processadmin",
    "diskadmin",
    "dbcreator",
    "bulkadmin",
)

#: The closed set of SQL Server FIXED DATABASE roles, probed by name for the same reason.
SQLSERVER_FIXED_DATABASE_ROLES: tuple[str, ...] = (
    "db_owner",
    "db_securityadmin",
    "db_accessadmin",
    "db_backupoperator",
    "db_ddladmin",
    "db_datareader",
    "db_datawriter",
    "db_denydatareader",
    "db_denydatawriter",
)

#: The grant both runbooks prescribe (``docs/DEPLOY-SERVER-DB.md`` §1.1) and the engine's store
#: actually needs: row CRUD plus the schema DDL the ADR 0064 bootstrap issues on a moved schema.
#: The documented SERVER-role set is EMPTY — the engine needs no fixed server role at all.
SQLSERVER_DOCUMENTED_DATABASE_ROLES: frozenset[str] = frozenset(
    {"db_datareader", "db_datawriter", "db_ddladmin"}
)

#: ``db_deny*`` memberships REMOVE access. They are reported as observed but are never "excess" — a
#: control that flagged a restriction as an over-grant would train an operator to ignore it.
_SQLSERVER_DENY_ROLES: frozenset[str] = frozenset({"db_denydatareader", "db_denydatawriter"})


def sqlserver_excess(
    *,
    server_roles: Sequence[str],
    database_roles: Sequence[str],
    control_server: bool,
    control_database: bool,
    database: str,
) -> tuple[str, ...]:
    """What an observed SQL Server principal holds BEYOND the documented least-privilege grant.

    Pure — no I/O — so both directions (over-granted and correctly-granted) are unit-testable without
    a database, and the live server legs assert the same function against a real login.

    A membership that IMPLIES a permission suppresses the implied one, so the list reads as a set of
    distinct grants rather than one grant restated: ``sysadmin`` already carries ``CONTROL SERVER``,
    and ``db_owner`` already carries ``CONTROL`` on the database."""
    out: list[str] = []
    for role in server_roles:
        out.append(f"server role {role}")
    for role in database_roles:
        if role in SQLSERVER_DOCUMENTED_DATABASE_ROLES or role in _SQLSERVER_DENY_ROLES:
            continue
        out.append(f"database role {role}")
    if control_server and "sysadmin" not in server_roles:
        out.append("CONTROL SERVER")
    if control_database and "db_owner" not in database_roles:
        out.append(f"CONTROL on database {database}")
    return tuple(out)


# --- Postgres ---------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PostgresRoleFacts:
    """One role the store principal can assume, with the ATTRIBUTES that role carries.

    Attributes are read per role rather than only for the principal itself, so a user-defined wrapper
    role is caught by what it grants rather than by whether its name happens to be on a list. A
    denylist of role NAMES cannot see that; this can.

    **Why a role the principal is merely a MEMBER of still counts.** Measured on PostgreSQL 16.14: a
    member of a ``CREATEROLE`` role is refused ``CREATE ROLE`` outright — attributes are never
    inherited — and succeeds immediately after ``SET ROLE`` to that role. ``pg_has_role(current_user,
    oid, 'MEMBER')``, the predicate the probe reads with, is exactly "may ``SET ROLE`` to it", so an
    attribute on any assumable role is one the principal can exercise at will."""

    name: str
    is_self: bool
    superuser: bool
    createrole: bool
    createdb: bool
    replication: bool
    bypassrls: bool


#: Predefined Postgres roles that reach beyond the engine's own schema — cross-schema data access,
#: host file/program reach, or administrative control. Membership in any is more than the documented
#: grant. Cloud-managed superuser umbrella roles are included because they are superuser in all but
#: the ``rolsuper`` bit (which managed providers withhold), so the attribute check alone misses them.
POSTGRES_EXCESSIVE_ROLES: frozenset[str] = frozenset(
    {
        "pg_read_all_data",
        "pg_write_all_data",
        "pg_read_server_files",
        "pg_write_server_files",
        "pg_execute_server_program",
        "pg_signal_backend",
        "pg_checkpoint",
        "pg_maintain",
        "pg_create_subscription",
        "rds_superuser",
        "cloudsqlsuperuser",
        "azure_pg_admin",
    }
)


def _attribute_finding(label: str, holders: Sequence[PostgresRoleFacts]) -> str:
    """``LABEL`` when the principal carries the attribute on its own row, else ``LABEL via role x``.

    The wrapper is NAMED because it is the object an operator has to change: a bare ``CREATEROLE``
    against a principal whose own attributes are all clean sends them looking in the wrong place."""
    if any(r.is_self for r in holders):
        return label
    return f"{label} via role {', '.join(sorted(r.name for r in holders))}"


def postgres_excess(
    *,
    roles: Sequence[PostgresRoleFacts],
    owns_database: bool,
    create_on_database: bool,
    database: str,
) -> tuple[str, ...]:
    """What an observed Postgres principal holds BEYOND the documented least-privilege grant.

    Pure, like :func:`sqlserver_excess`.

    **Every attribute is read across every assumable role, not only the principal's own row** — see
    :class:`PostgresRoleFacts` for the measurement that settles why membership is enough. Reading the
    four non-superuser attributes on the principal alone let a wrapper role carrying ``CREATEROLE`` /
    ``CREATEDB`` / ``REPLICATION`` / ``BYPASSRLS`` read as a clean least-privilege role. Mere
    membership is still silent: a wrapper with no attribute and no ``pg_*`` name produces nothing, or
    every site that groups its grants behind a role would carry a finding it cannot act on.

    ``SUPERUSER`` short-circuits the rest: a superuser is implicitly a member of every role and holds
    every database privilege, so enumerating them would bury the one finding that matters under a
    dozen restatements of it. The role attributes are still listed — they say *how* the identity is
    configured, which is what an operator has to change."""
    out: list[str] = []
    superusers = [r for r in roles if r.superuser]
    if superusers:
        out.append(_attribute_finding("SUPERUSER", superusers))
    for attr, label in (
        ("createrole", "CREATEROLE"),
        ("createdb", "CREATEDB"),
        ("replication", "REPLICATION"),
        ("bypassrls", "BYPASSRLS"),
    ):
        holders = [r for r in roles if getattr(r, attr)]
        if holders:
            out.append(_attribute_finding(label, holders))
    if superusers:
        return tuple(out)
    for role in roles:
        if role.name in POSTGRES_EXCESSIVE_ROLES:
            out.append(f"role {role.name}")
    if owns_database:
        out.append(f"OWNER of database {database}")
    elif create_on_database:
        # Only when it is NOT the owner: ownership already carries CREATE, so reporting both would
        # restate one grant as two.
        out.append(f"CREATE on database {database}")
    return tuple(out)


# --- the report -------------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class StorePrivilegeReport:
    """What the probe ACTUALLY observed — never what it assumes.

    ``status`` is the load-bearing field: :attr:`StorePrivilegeStatus.OBSERVED` with an empty
    :attr:`excess` is a clean bill of health, and it is a DIFFERENT value from
    :attr:`StorePrivilegeStatus.UNOBSERVABLE`, which is the absence of one."""

    backend: StoreBackend
    status: StorePrivilegeStatus
    principal: str = ""
    database: str = ""
    server_roles: tuple[str, ...] = ()
    database_roles: tuple[str, ...] = ()
    excess: tuple[str, ...] = ()
    detail: str = ""

    def posture(self) -> StorePrivilegePosture:
        """The settings-layer view :func:`security_loosenings` consumes (a plain data type, so
        ``config.settings`` never has to know the store package — the same reason the connection-scoped
        deviations arrive there as plain names)."""
        return StorePrivilegePosture(status=self.status, excess=self.excess, detail=self.detail)

    def summary(self) -> str:
        """One operator-readable line. The three statuses read differently ON PURPOSE."""
        if self.status is StorePrivilegeStatus.NOT_APPLICABLE:
            return (
                f"store privilege preflight: NOT APPLICABLE on {self.backend.value} — {self.detail}"
            )
        if self.status is StorePrivilegeStatus.UNOBSERVABLE:
            return (
                f"store privilege preflight: COULD NOT OBSERVE the {self.backend.value} store "
                f"principal's effective privileges — {self.detail}. This is NOT a clean result: the "
                "documented least-privilege grant is UNVERIFIED on this instance"
            )
        if self.excess:
            return (
                f"store privilege preflight: the {self.backend.value} store principal "
                f"{self.principal!r} on {self.database!r} holds {len(self.excess)} privilege(s) "
                f"BEYOND the documented least-privilege grant: {', '.join(self.excess)}"
            )
        return (
            f"store privilege preflight: OBSERVED the {self.backend.value} store principal "
            f"{self.principal!r} on {self.database!r} — no privilege beyond the documented grant "
            f"(server roles: {', '.join(self.server_roles) or 'none'}; database roles: "
            f"{', '.join(self.database_roles) or 'none'})"
        )

    def audit_detail(self) -> dict[str, object]:
        """The non-secret, PHI-free audit payload: a status, principal/role NAMES and the excess list."""
        return {
            "backend": self.backend.value,
            "status": self.status.value,
            "principal": self.principal,
            "database": self.database,
            "server_roles": list(self.server_roles),
            "database_roles": list(self.database_roles),
            "excess": list(self.excess),
            "detail": self.detail,
        }


@runtime_checkable
class PrivilegeProbeStore(Protocol):
    """The narrow store slice this preflight uses. A SEPARATE protocol (not part of
    :class:`~messagefoundry.store.base.Store`) so a backend opts in structurally — the SQLite
    ``MessageStore``, ``SqlServerStore`` and ``PostgresStore`` all implement it. A handle that does
    not is reported UNOBSERVABLE rather than skipped: an unimplemented probe is a thing the engine
    could not observe, which is precisely what that status means."""

    async def probe_principal_privileges(self) -> StorePrivilegeReport: ...


def probe_failure(backend: StoreBackend, exc: BaseException) -> StorePrivilegeReport:
    """An UNOBSERVABLE report built from a probe exception, with the driver text redacted.

    The message goes through the shared secret/PHI redactor before it reaches a log or an audit row:
    a driver diagnostic can echo connection parameters, and this text lands in a durable audit table
    an operator reads. Over-redaction is the correct direction here — the NAMED condition ("could not
    observe") is the load-bearing part, not the driver's wording."""
    return StorePrivilegeReport(
        backend=backend,
        status=StorePrivilegeStatus.UNOBSERVABLE,
        detail=f"{type(exc).__name__}: {redact_log_line(str(exc))[:300]}",
    )


async def run_store_privilege_preflight(
    store: Store,
    *,
    require_least_privilege: bool,
    enforcing: bool,
) -> StorePrivilegeReport:
    """Probe the store principal's effective privileges, report what was observed, and — only under a
    declared ``[store].require_least_privilege`` on an enforcing instance — refuse.

    Wire it into serve startup **after** the store opens and **before** any listener binds (the ADR
    0041 attestation / ASVS 6.7.1 trust-anchor preflights sit in the same place, for the same reason).
    The audit write is best-effort and never masks the finding.

    Raises :class:`StorePrivilegeError` when the operator declared ``require_least_privilege``,
    ``[security].enforcement`` is ``enforce``, and the principal is either over-granted or
    UNOBSERVABLE."""
    backend = getattr(store, "backend", StoreBackend.SQLITE)
    if isinstance(store, PrivilegeProbeStore):
        try:
            report = await store.probe_principal_privileges()
        except Exception as exc:  # noqa: BLE001 — any probe failure is UNOBSERVABLE, never a silent pass
            report = probe_failure(backend, exc)
    else:
        report = StorePrivilegeReport(
            backend=backend,
            status=StorePrivilegeStatus.UNOBSERVABLE,
            detail=(
                f"this {backend.value} store handle ({type(store).__name__}) implements no "
                "privilege probe, so the principal's effective privileges were never read"
            ),
        )

    # NOT_APPLICABLE is not "unclean": SQLite genuinely has no principal to over-grant, so folding it
    # into the warning arm would put a permanent, unactionable warning on every single-node install —
    # and a permanently-true warning is read as noise, which costs this control its readers.
    unclean = report.status is StorePrivilegeStatus.UNOBSERVABLE or bool(report.excess)
    refusing = unclean and require_least_privilege and enforcing
    if not unclean:
        log.info("%s", report.summary())
    else:
        log.warning(
            "%s — [store].require_least_privilege=%s, enforcing=%s%s",
            report.summary(),
            require_least_privilege,
            enforcing,
            "; REFUSING to start" if refusing else "",
        )

    # NOT_APPLICABLE writes no audit row: SQLite has no principal, so there is no observation to
    # record and a row saying so on every start would be noise that dilutes the ones that matter.
    if report.status is not StorePrivilegeStatus.NOT_APPLICABLE:
        detail = report.audit_detail()
        detail["require_least_privilege"] = require_least_privilege
        detail["refused"] = refusing
        try:
            await store.record_audit(
                "store_privilege_preflight", actor=None, detail=json.dumps(detail)
            )
        except Exception:  # noqa: BLE001 — auditing is best-effort; never mask the finding
            log.exception("store privilege preflight: failed to record the audit row")

    if refusing:
        raise StorePrivilegeError(
            f"{report.summary()} — [store].require_least_privilege is set and "
            "[security].enforcement is 'enforce'; refusing to start"
        )
    return report
