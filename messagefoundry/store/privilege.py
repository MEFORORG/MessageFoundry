# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
  :func:`~messagefoundry.config.settings.security_loosenings` entry.
* An **OBSERVED over-grant REFUSES under ``[security].enforcement = enforce``, by default** (ADR 0199,
  owner ruling 2026-09-27; it narrows the 2026-09-14 ratification, which put every refusal behind
  ``[store].require_least_privilege``). The escape is the audited opt-out
  ``[security].allow_over_granted_store_principal``: it lifts this one refusal, logs an ``AUDIT:``
  line, marks the preflight's audit row ``over_grant_accepted`` and is named by
  :func:`~messagefoundry.config.settings.security_loosenings`. Under ``enforcement = warn`` the
  refusal downgrades to a warning, like every other ADR 0148 serve gate. The key is the dial alone:
  ADR 0186 removed the data class, so every instance is a PHI instance and there is no second key.
* It must not fail **open** either. A probe that cannot run — permission denied, an unsupported
  backend, a store handle with no probe at all — reports :attr:`StorePrivilegeStatus.UNOBSERVABLE`,
  which is a distinct, named, loud condition everywhere it surfaces: a different log line, a
  different audit ``status``, and its own posture entry. *"Could not observe"* and *"observed, and
  it is fine"* are never the same output. By owner choice (ADR 0199) an unobservable probe only
  WARNS by default. Under a declared ``[store].require_least_privilege`` it **refuses**, because a
  control that cannot see is exactly the fail-open shape the setting was turned on to prevent; that
  declaration also outranks the opt-out, so with both set an over-grant still refuses.
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from messagefoundry.audit_write import write_audit_soft
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
    "AUDIT_APPEND_ONLY_TABLES",
    "POSTGRES_AUDIT_WRITE_PRIVILEGES",
    "POSTGRES_EXCESSIVE_ROLES",
    "SQLSERVER_AUDIT_WRITE_PRIVILEGES",
    "SQLSERVER_DOCUMENTED_DATABASE_ROLES",
    "SQLSERVER_FIXED_DATABASE_ROLES",
    "SQLSERVER_FIXED_SERVER_ROLES",
    "SQLSERVER_RUNTIME_DATABASE_ROLES",
    "STORE_PRIVILEGE_ALERT_SUBJECT",
    "OVER_GRANT_OPT_OUT",
    "PostgresRoleFacts",
    "PreflightOutcome",
    "PrivilegeAlertSink",
    "PrivilegeProbeStore",
    "StorePrivilegeError",
    "StorePrivilegeReport",
    "audit_write_alias",
    "audit_write_grant",
    "classify_audit_writes",
    "postgres_excess",
    "preflight_outcome",
    "probe_failure",
    "refusal_reason",
    "run_store_privilege_preflight",
    "sqlite_not_applicable",
    "sqlserver_excess",
    "store_privilege_alert_subject",
]


class StorePrivilegeError(RuntimeError):
    """Raised by the preflight when it refuses: an observed over-grant under ``enforce`` with no
    accepted opt-out, or an unobservable probe under a declared ``[store].require_least_privilege``.
    The caller refuses to start before any listener binds."""


#: The audited opt-out that lets an enforcing instance start on an OBSERVED over-grant (ADR 0199).
OVER_GRANT_OPT_OUT = "[security].allow_over_granted_store_principal"


class PreflightOutcome(str, Enum):  # noqa: UP042 - the repo's str-enum convention (see config.settings)
    """What ``serve`` does with one probe result. Stated once, so the preflight and
    ``check-privileges`` cannot disagree about it."""

    CLEAN = "clean"  # no finding: a clean OBSERVED read, or SQLite's NOT_APPLICABLE
    WARN = "warn"  # a finding that starts with a warning
    ACCEPTED = "accepted"  # an over-grant the audited opt-out lets start
    REFUSE = "refuse"  # serve refuses to start


def preflight_outcome(
    report: StorePrivilegeReport,
    *,
    require_least_privilege: bool,
    enforcing: bool,
    over_grant_accepted: bool,
) -> PreflightOutcome:
    """The refuse/warn decision for one probe report (ADR 0199).

    ``enforcing`` is ``[security].enforcement is ENFORCE`` and nothing else: that dial is the only
    refuse/warn key the ADR 0148 serve gates read, and ADR 0186 left no data class to key on."""
    if report.finding is None:
        return PreflightOutcome.CLEAN
    if not enforcing:
        return PreflightOutcome.WARN
    if require_least_privilege:
        # The declared requirement is the stricter setting, so it outranks the opt-out and it refuses
        # an unobservable probe too.
        return PreflightOutcome.REFUSE
    if report.status is StorePrivilegeStatus.UNOBSERVABLE:
        return PreflightOutcome.WARN  # owner choice, ADR 0199: warn-only unless declared
    return PreflightOutcome.ACCEPTED if over_grant_accepted else PreflightOutcome.REFUSE


def refusal_reason(*, require_least_privilege: bool) -> str:
    """Why :attr:`PreflightOutcome.REFUSE` applies, in the words the refusal and ``check-privileges``
    both print. Only meaningful under ``enforce``, the one dial a refusal can come from."""
    if require_least_privilege:
        return "[store].require_least_privilege is set and [security].enforcement is 'enforce'"
    return (
        "an over-granted store principal under [security].enforcement = 'enforce'. Reduce the grant "
        "to the one docs/DEPLOY-SERVER-DB.md prescribes, or set "
        f"{OVER_GRANT_OPT_OUT} = true to accept it (audited)"
    )


# --- the audit table is append-only for the runtime login (owner ruling R16, ASVS 16.4.2) -------
#: The tables the runtime login may only INSERT into and SELECT from. ``audit_log`` is the hash chain,
#: and it is the whole of the audit record: the genesis row that names the first key, and every later
#: key range, are rows inside it (BACKLOG #1904, vault BACKLOG #2594). R16 as first ruled also listed
#: ``audit_chain_meta``; the owner amended the ruling on 2026-10-01 when that table was removed. So the
#: engine's own write paths need no UPDATE or DELETE here, and a login that holds one could rewrite or
#: drop audit rows on a first deployment. Under ``[store].schema_management = external`` each such
#: right is excess. Under ``auto`` it is not counted: the Postgres login OWNS the table there and may
#: grant itself any right back, and the SQL Server login holds ``db_ddladmin``. A tuple, so a later
#: append-only table joins the probe by being named here.
AUDIT_APPEND_ONLY_TABLES: tuple[str, ...] = ("audit_log",)

#: The row-changing rights probed on each append-only table. This is at least the direct routes, not
#: every route: Postgres ``TRUNCATE`` empties a table without ``DELETE``, and ``TRIGGER`` lets a role
#: attach a trigger that rewrites each row as it is inserted; SQL Server's ``TRUNCATE TABLE`` and a
#: trigger both need ``ALTER`` on it, and ``CONTROL`` or ``TAKE OWNERSHIP`` lets a login undo a ``DENY``.
#: Postgres table ownership is the probe's separate ``OWNER of`` finding. ``UPDATE`` is read column by
#: column too, since a column grant changes row content as well as a table grant does.
POSTGRES_AUDIT_WRITE_PRIVILEGES: tuple[str, ...] = ("UPDATE", "DELETE", "TRUNCATE", "TRIGGER")
SQLSERVER_AUDIT_WRITE_PRIVILEGES: tuple[str, ...] = (
    "UPDATE",
    "DELETE",
    "ALTER",
    "CONTROL",
    "TAKE OWNERSHIP",
)


def audit_write_grant(privilege: str, table: str) -> str:
    """The one wording both backends use for a row-changing right on an append-only audit table.

    A two-word right is lower-cased: the log redaction scrubs two adjacent ALL-CAPS words as a
    possible patient name, so ``TAKE OWNERSHIP`` would log as ``[redacted]``. The probe still passes
    the exact T-SQL name from the tuple above. The SQL Server OBSERVED detail spells the list out by
    hand, so a change here needs the same change there."""
    label = privilege.lower() if " " in privilege else privilege
    return f"{label} on table {table}"


def audit_write_alias(table: str, privilege: str) -> str:
    """The probe column that reads ``privilege`` on ``table``. Both come from the closed tuples above,
    never from input, so the alias is a fixed identifier."""
    return f"aw_{table}_{privilege.lower().replace(' ', '_')}"


def classify_audit_writes(
    row: Mapping[str, object], privileges: Sequence[str]
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Read the probe's audit-table columns THREE ways, as ``_probed_grant`` reads a role: ``(held,
    unread)``, each in :func:`audit_write_grant` wording. A NULL is a table the login cannot resolve,
    so it is NOT READ and never folds into "not held". ``== 1`` accepts a driver's ``True`` or ``1``."""
    held: list[str] = []
    unread: list[str] = []
    for table in AUDIT_APPEND_ONLY_TABLES:
        for privilege in privileges:
            value = row[audit_write_alias(table, privilege)]
            if value is None:
                unread.append(audit_write_grant(privilege, table))
            elif value == 1:
                held.append(audit_write_grant(privilege, table))
    return tuple(held), tuple(unread)


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

#: The grant the runbooks prescribe (``docs/DEPLOY-SERVER-DB.md`` §1.1) for an engine login that runs
#: its OWN schema DDL (``[store].schema_management = auto``): row CRUD plus the schema DDL the ADR 0064
#: bootstrap issues on a moved schema. The documented SERVER-role set is EMPTY — the engine needs no
#: fixed server role at all.
SQLSERVER_DOCUMENTED_DATABASE_ROLES: frozenset[str] = frozenset(
    {"db_datareader", "db_datawriter", "db_ddladmin"}
)

#: The RUNTIME login's grant under ``[store].schema_management = external`` (#305, the server-DB
#: default): row CRUD only. ``provision-schema`` runs the DDL as a separate principal, so here
#: ``db_ddladmin`` is a standing schema-change right the runtime never uses, and it counts as excess.
SQLSERVER_RUNTIME_DATABASE_ROLES: frozenset[str] = frozenset({"db_datareader", "db_datawriter"})

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
    external: bool = False,
    create_table: bool = False,
    alter_schema: str | None = None,
    audit_writes: Sequence[str] = (),
) -> tuple[str, ...]:
    """What an observed SQL Server principal holds BEYOND the documented least-privilege grant.

    ``external`` selects the grant for ``[store].schema_management = external`` (#305), under which
    the runtime login holds row CRUD only, so ``db_ddladmin`` is reported as excess, and so are the
    same rights granted directly rather than by role: ``create_table`` (``CREATE TABLE`` on the
    database) and ``alter_schema`` (the name of the default schema, when the login holds ``ALTER`` on
    it). Both are suppressed when ``db_ddladmin`` or ``db_owner`` is already named, since that role
    carries them. ``False`` keeps the auto-mode grant, where the login runs its own schema DDL.

    ``audit_writes`` names the row-changing rights the login holds on the append-only audit tables
    (:func:`audit_write_grant` wording, owner ruling R16). ``db_datawriter`` grants them on every table,
    so the runbook takes them back with ``DENY``. Counted under ``external`` only, and suppressed when
    ``sysadmin``, ``db_owner``, ``CONTROL SERVER`` or database ``CONTROL`` is already named: each one
    already lets the login lift a ``DENY``, so naming it names the fix. Another server role does not
    suppress them, because it carries no right on a user table. ``ALTER`` on a table is also
    suppressed when ``db_ddladmin`` is named, since that role carries it on every table.

    Pure — no I/O — so both directions (over-granted and correctly-granted) are unit-testable without
    a database, and the live server legs assert the same function against a real login.

    A membership that IMPLIES a permission suppresses the implied one, so the list reads as a set of
    distinct grants rather than one grant restated: ``sysadmin`` already carries ``CONTROL SERVER``,
    and ``db_owner`` already carries ``CONTROL`` on the database."""
    documented = (
        SQLSERVER_RUNTIME_DATABASE_ROLES if external else SQLSERVER_DOCUMENTED_DATABASE_ROLES
    )
    out: list[str] = []
    for role in server_roles:
        out.append(f"server role {role}")
    for role in database_roles:
        if role in documented or role in _SQLSERVER_DENY_ROLES:
            continue
        out.append(f"database role {role}")
    if control_server and "sysadmin" not in server_roles:
        out.append("control server")
    if control_database and "db_owner" not in database_roles:
        out.append(f"CONTROL on database {database}")
    ddl_role_named = bool({"db_ddladmin", "db_owner"} & set(database_roles)) or bool(server_roles)
    if external and not ddl_role_named and not control_database:
        if create_table:
            out.append(f"create table on database {database}")
        if alter_schema:
            out.append(f"ALTER on schema {alter_schema}")
    owner_named = (
        "db_owner" in database_roles
        or "sysadmin" in server_roles
        or control_database
        or control_server
    )
    if external and not owner_named:
        # ALTER on every table rides db_ddladmin, named above. ALTER on the default schema is not
        # folded in: the audit tables may resolve to dbo instead, so it may not be the same grant.
        ddladmin = "db_ddladmin" in database_roles
        out.extend(w for w in audit_writes if not (ddladmin and w.startswith("ALTER ")))
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
    external: bool = False,
    schema: str = "",
    create_on_schema: bool = False,
    owned_in_schema: int = 0,
    audit_writes: Sequence[str] = (),
) -> tuple[str, ...]:
    """What an observed Postgres principal holds BEYOND the documented least-privilege grant.

    Pure, like :func:`sqlserver_excess`.

    ``external`` (``[store].schema_management = external``, #305) adds the schema-DDL rights to the
    excess: ``CREATE`` on the store's schema, and OWNERSHIP of objects in it (an owner may ``ALTER`` and
    ``DROP`` its tables whatever the schema ACL says). Under auto mode the role runs its own DDL, so
    both are prescribed and neither is reported.

    ``audit_writes`` names the row-changing rights the role holds on the append-only audit tables
    (:func:`audit_write_grant` wording, owner ruling R16), counted under ``external`` only. Under
    ``auto`` the role owns those tables and can grant itself any right back, so no reading of its
    grants there could show the tables are append-only.

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
    if external:
        if create_on_schema:
            out.append(f"CREATE on schema {schema}")
        if owned_in_schema:
            out.append(f"OWNER of {owned_in_schema} object(s) in schema {schema}")
        out.extend(audit_writes)
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

    @property
    def finding(self) -> str | None:
        """``"over_granted"``, ``"unobservable"``, or ``None`` for a clean or NOT_APPLICABLE read — the
        ONE classification the preflight's WARN arm, its alert and ``check-privileges`` all use."""
        if self.status is StorePrivilegeStatus.UNOBSERVABLE:
            return "unobservable"
        return "over_granted" if self.excess else None

    def posture(self) -> StorePrivilegePosture:
        """The settings-layer view :func:`security_loosenings` consumes (a plain data type, so
        ``config.settings`` never has to know the store package — the same reason the connection-scoped
        deviations arrive there as plain names)."""
        return StorePrivilegePosture(status=self.status, excess=self.excess, detail=self.detail)

    def summary(self) -> str:
        """One operator-readable line. The three statuses read differently ON PURPOSE."""
        if self.status is StorePrivilegeStatus.NOT_APPLICABLE:
            return (
                f"store privilege preflight: not applicable on {self.backend.value} — {self.detail}"
            )
        if self.status is StorePrivilegeStatus.UNOBSERVABLE:
            return (
                f"store privilege preflight: could not observe the {self.backend.value} store "
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


class PrivilegeAlertSink(Protocol):
    """The one :class:`~messagefoundry.pipeline.alerts.AlertSink` method this preflight calls. Named
    here as its own protocol so ``store/`` does not import ``pipeline/``; every ``AlertSink`` satisfies
    it structurally."""

    def store_privilege_warning(
        self, name: str, *, finding: str, excess_count: int, detail: str
    ) -> None: ...

    def store_privilege_clean(self, name: str) -> None: ...


#: The alert subject's prefix (the ``connection`` key the notifier throttles and keys durable state on).
STORE_PRIVILEGE_ALERT_SUBJECT = "store"


def store_privilege_alert_subject(report: StorePrivilegeReport) -> str:
    """``store:<principal>@<database>``, or bare ``store`` when the probe named no principal.

    Keyed by principal, not fixed, because several processes share one store (HA nodes, engine
    shards) and may log in as different principals: a clean start by one must not resolve the open
    warning another still earns. A re-alert from the same principal folds into the same instance."""
    if not report.principal:
        return STORE_PRIVILEGE_ALERT_SUBJECT
    return f"{STORE_PRIVILEGE_ALERT_SUBJECT}:{report.principal}@{report.database}"


def sqlite_not_applicable(path: str) -> StorePrivilegeReport:
    """NOT_APPLICABLE for a SQLite store at ``path``, and it says what it did instead of pretending it ran.

    SQLite has no login, no fixed-server-role tier and no database-role tier: this process opens a
    file. Returning ``OBSERVED`` with an empty excess list would be a clean bill of health for a
    check that never happened, which is the one thing this preflight must never emit, so the status
    is its own value and the detail names the control that DOES govern access here. Built without
    opening the store, so ``check-privileges`` can report it without creating the file."""
    return StorePrivilegeReport(
        backend=StoreBackend.SQLITE,
        status=StorePrivilegeStatus.NOT_APPLICABLE,
        database=path,
        detail=(
            "the SQLite store is a local file this process opens directly — there is no server "
            "principal, no fixed-server-role tier and no database-role tier to read. Access to the "
            "store is governed by the filesystem ACL on the database file and its -wal/-shm "
            "sidecars, which is an OS-level control the engine does not probe"
        ),
    )


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
    over_grant_accepted: bool = False,
    alert_sink: PrivilegeAlertSink | None = None,
) -> StorePrivilegeReport:
    """Probe the store principal's effective privileges, report what was observed, and refuse where
    :func:`preflight_outcome` says so.

    Wire it into serve startup **after** the store opens and **before** any listener binds (the ADR
    0041 attestation / ASVS 6.7.1 trust-anchor preflights sit in the same place, for the same reason).
    The audit write is best-effort and never masks the finding.

    On the WARN arm (an over-grant or an UNOBSERVABLE probe) it also fires ``alert_sink``'s
    ``store_privilege_warning`` (#305), BEFORE any refusal, so a refused start still pages. The alert
    is best-effort like the audit row: a sink that raises is logged and never masks the finding.
    SQLite's NOT_APPLICABLE and a clean read raise no alert; a clean OBSERVED read calls
    ``store_privilege_clean`` instead, which auto-resolves an open warning and pages nobody.

    ``over_grant_accepted`` is ``[security].allow_over_granted_store_principal``. When it lifts a
    refusal, the preflight logs an ``AUDIT:`` line and its audit row carries
    ``over_grant_accepted: true``.

    Raises :class:`StorePrivilegeError` on :attr:`PreflightOutcome.REFUSE`: under ``enforce``, an
    over-grant with no accepted opt-out, or any finding under a declared ``require_least_privilege``."""
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
    finding = report.finding
    outcome = preflight_outcome(
        report,
        require_least_privilege=require_least_privilege,
        enforcing=enforcing,
        over_grant_accepted=over_grant_accepted,
    )
    refusing = outcome is PreflightOutcome.REFUSE
    summary = report.summary()
    if finding is None:
        log.info("%s", summary)
        if alert_sink is not None and report.status is StorePrivilegeStatus.OBSERVED:
            # The inverse: a clean OBSERVED read resolves an open warning from an earlier start, so a
            # fixed grant clears GET /alerts/active without a hand resolve. SQLite has nothing to clear.
            try:
                alert_sink.store_privilege_clean(store_privilege_alert_subject(report))
            except Exception:  # noqa: BLE001 — best-effort, like the warning
                log.exception("store privilege preflight: the alert sink raised")
    else:
        log.warning(
            "%s — [store].require_least_privilege=%s, enforcing=%s%s",
            summary,
            require_least_privilege,
            enforcing,
            "; REFUSING to start" if refusing else "",
        )
        if outcome is PreflightOutcome.ACCEPTED:
            log.warning(
                "AUDIT: starting an enforcing instance on an over-granted store principal because "
                "%s=true — the store credential holds more than the documented least-privilege "
                "grant (store privilege opt-out override)",
                OVER_GRANT_OPT_OUT,
            )
        if alert_sink is not None:
            try:
                alert_sink.store_privilege_warning(
                    store_privilege_alert_subject(report),
                    finding=finding,
                    excess_count=len(report.excess),
                    detail=summary,
                )
            except Exception:  # noqa: BLE001 — alerting is best-effort; never mask the finding
                log.exception("store privilege preflight: the alert sink raised")

    # NOT_APPLICABLE writes no audit row: SQLite has no principal, so there is no observation to
    # record and a row saying so on every start would be noise that dilutes the ones that matter.
    if report.status is not StorePrivilegeStatus.NOT_APPLICABLE:
        detail = report.audit_detail()
        detail["require_least_privilege"] = require_least_privilege
        detail["refused"] = refusing
        detail["over_grant_accepted"] = outcome is PreflightOutcome.ACCEPTED
        # Best effort, and ``defects=()``: a raise here would mask the refusal below (vault
        # BACKLOG #2260).
        await write_audit_soft(
            lambda: store.record_audit(
                "store_privilege_preflight", actor=None, detail=json.dumps(detail)
            ),
            log=log,
            message="store privilege preflight: failed to record the audit row",
            defects=(),
        )

    if refusing:
        why = refusal_reason(require_least_privilege=require_least_privilege)
        raise StorePrivilegeError(f"{summary} — {why}; refusing to start")
    return report
