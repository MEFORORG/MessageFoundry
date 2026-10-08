# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #305 (ASVS 13.2.2): the provision/runtime split on the server-DB store principal.

``[store].schema_management = external`` is the server-DB default. The engine then runs no schema
DDL at open: it reads the ``schema_meta`` marker and refuses on a mismatch, naming
``messagefoundry store provision-schema``, which a DBA runs as a DDL-capable principal. The runtime
login needs row access only, and the privilege probe counts schema-DDL rights as excess.

The SQL Server ``_ensure_schema`` contract lives beside its fake cursor in
``tests/test_sqlserver_schema_init.py``; this file carries the settings, the probe comparators, the
Postgres open path, the provisioning seam, the CLI, and the live legs.

**The live legs run against real servers** (``MEFOR_TEST_SQLSERVER`` / ``MEFOR_TEST_POSTGRES``) and are
gated PER TEST, so everything else here runs in the default local suite. They are the only place the
refusal is shown to leave a real database EMPTY, and the only place a real row-only login is shown
to open a provisioned store. Their CI steps are the store-privilege steps of the sqlserver-store and
postgres-store jobs; ``test_the_live_legs_of_this_file_are_run_by_a_server_db_ci_step`` pins that.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import sys
import types
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.settings import (
    AlertsSettings,
    ApiSettings,
    ApprovalsSettings,
    AuthSettings,
    CertMonitorSettings,
    SchemaManagement,
    SecretRotationSettings,
    SecuritySettings,
    SqlAuth,
    StoreBackend,
    StorePrivilegeStatus,
    StoreSettings,
    load_settings,
    security_loosenings,
)
from messagefoundry.store.base import (
    PROVISION_SCHEMA_COMMAND,
    SchemaNotProvisionedError,
    SchemaProvisionResult,
    provision_store_schema,
)
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.privilege import (
    AUDIT_APPEND_ONLY_TABLES,
    POSTGRES_AUDIT_WRITE_PRIVILEGES,
    SQLSERVER_AUDIT_WRITE_PRIVILEGES,
    SQLSERVER_DOCUMENTED_DATABASE_ROLES,
    SQLSERVER_RUNTIME_DATABASE_ROLES,
    PostgresRoleFacts,
    audit_write_alias,
    audit_write_grant,
    postgres_excess,
    sqlserver_excess,
)
from tests._live_scratch import (
    SqlServerAdmin,
    bounded,
    postgres_teardown,
    scratch_name,
    sqlserver_admin,
    throwaway_password,
)

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))
_THIS_FILE = "tests/test_store_privilege_schema_split.py"
_ROOT = Path(__file__).resolve().parent.parent


def _server(backend: StoreBackend, **extra: Any) -> StoreSettings:
    """A server-DB StoreSettings with no credential-shaped literal (Windows Integrated on SQL Server)."""
    if backend is StoreBackend.SQLSERVER:
        return StoreSettings(
            backend=backend,
            auth=SqlAuth.INTEGRATED,
            server="db.invalid",
            database="MessageFoundry",
            **extra,
        )
    return StoreSettings(
        backend=backend, server="db.invalid", database="messagefoundry", username="mefor", **extra
    )


# --- the setting ------------------------------------------------------------------------------


@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
def test_server_backends_default_to_external(backend: StoreBackend) -> None:
    settings = _server(backend)
    assert settings.schema_management is None
    assert settings.resolved_schema_management() is SchemaManagement.EXTERNAL


@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
def test_server_backends_honour_an_explicit_auto(backend: StoreBackend) -> None:
    settings = _server(backend, schema_management=SchemaManagement.AUTO)
    assert settings.resolved_schema_management() is SchemaManagement.AUTO


def test_sqlite_is_always_auto() -> None:
    assert StoreSettings().resolved_schema_management() is SchemaManagement.AUTO
    explicit = StoreSettings(schema_management=SchemaManagement.AUTO)
    assert explicit.resolved_schema_management() is SchemaManagement.AUTO


def test_an_explicit_external_on_sqlite_is_refused() -> None:
    """Ignoring it would let an operator believe a runtime that CAN run DDL cannot."""
    with pytest.raises(ValueError, match="sqlserver and postgres backends only"):
        StoreSettings(schema_management=SchemaManagement.EXTERNAL)


def test_the_setting_loads_from_the_environment() -> None:
    env = {
        "MEFOR_STORE_BACKEND": "postgres",
        "MEFOR_STORE_SERVER": "db.invalid",
        "MEFOR_STORE_DATABASE": "messagefoundry",
        "MEFOR_STORE_USERNAME": "mefor",
        "MEFOR_STORE_SCHEMA_MANAGEMENT": "auto",
    }
    store = load_settings(environ=env).store
    assert store.resolved_schema_management() is SchemaManagement.AUTO


# --- the posture registry ---------------------------------------------------------------------


def _loosening_names(store: StoreSettings) -> set[str]:
    return {
        name
        for name, _ in security_loosenings(
            SecuritySettings(),
            store,
            AuthSettings(),
            AlertsSettings(),
            SecretRotationSettings(),
            cleartext_hops=(),
            expiry_relaxed_hops=(),
            hostname_unchecked_hops=(),
            query_credential_hops=(),
            unverified_db_hops=(),
            attested_hops=(),
            revocation_attested_hops=(),
            api=ApiSettings(),
            approvals=ApprovalsSettings(),
            cert_monitor=CertMonitorSettings(),
            store_privilege=None,
            audit_chain_unkeyed=None,
            remote_debug=None,
            startup=None,
        )
    }


@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
def test_auto_on_a_server_backend_is_a_named_loosening(backend: StoreBackend) -> None:
    assert "schema_management" in _loosening_names(
        _server(backend, schema_management=SchemaManagement.AUTO)
    )


@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
def test_the_external_default_is_not_a_loosening(backend: StoreBackend) -> None:
    assert "schema_management" not in _loosening_names(_server(backend))


def test_sqlite_auto_is_not_a_loosening() -> None:
    """SQLite is auto by construction: reporting it would be a permanent, unactionable entry."""
    assert "schema_management" not in _loosening_names(StoreSettings())


# --- the comparators --------------------------------------------------------------------------


def test_sqlserver_runtime_set_is_the_documented_set_minus_ddladmin() -> None:
    dropped = SQLSERVER_DOCUMENTED_DATABASE_ROLES - SQLSERVER_RUNTIME_DATABASE_ROLES
    assert dropped == {"db_ddladmin"}
    assert SQLSERVER_RUNTIME_DATABASE_ROLES < SQLSERVER_DOCUMENTED_DATABASE_ROLES


@pytest.mark.parametrize(
    ("external", "expected"),
    [(True, ("database role db_ddladmin",)), (False, ())],
)
def test_sqlserver_ddladmin_is_excess_in_external_mode_only(
    external: bool, expected: tuple[str, ...]
) -> None:
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=("db_datareader", "db_datawriter", "db_ddladmin"),
            control_server=False,
            control_database=False,
            database="MessageFoundry",
            external=external,
        )
        == expected
    )


_PLAIN_ROLE = (PostgresRoleFacts("mefor", True, False, False, False, False, False),)


@pytest.mark.parametrize(
    ("external", "expected"),
    [
        (True, ("CREATE on schema mefor", "OWNER of 3 object(s) in schema mefor")),
        (False, ()),
    ],
)
def test_postgres_schema_ddl_is_excess_in_external_mode_only(
    external: bool, expected: tuple[str, ...]
) -> None:
    """Posture A (the role owns its schema and every table in it) is the auto-mode grant, and exactly
    the two schema-DDL findings under external."""
    assert (
        postgres_excess(
            roles=_PLAIN_ROLE,
            owns_database=False,
            create_on_database=False,
            database="messagefoundry",
            external=external,
            schema="mefor",
            create_on_schema=True,
            owned_in_schema=3,
        )
        == expected
    )


def test_postgres_row_only_role_is_clean_in_external_mode() -> None:
    assert (
        postgres_excess(
            roles=_PLAIN_ROLE,
            owns_database=False,
            create_on_database=False,
            database="messagefoundry",
            external=True,
            schema="mefor",
            create_on_schema=False,
            owned_in_schema=0,
        )
        == ()
    )


@pytest.mark.parametrize(
    ("roles", "expected"),
    [
        (
            ("db_datareader", "db_datawriter"),
            ("create table on database MessageFoundry", "ALTER on schema dbo"),
        ),
        (("db_datareader", "db_datawriter", "db_ddladmin"), ("database role db_ddladmin",)),
    ],
    ids=["direct-grants", "via-role"],
)
def test_sqlserver_direct_ddl_grants_are_excess_under_external(
    roles: tuple[str, ...], expected: tuple[str, ...]
) -> None:
    """A runtime login given CREATE TABLE and ALTER on its schema directly, instead of db_ddladmin,
    can still change the schema, so under external it is named. When db_ddladmin is held the role is
    the one finding, not restated as its parts."""
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=roles,
            control_server=False,
            control_database=False,
            database="MessageFoundry",
            external=True,
            create_table=True,
            alter_schema="dbo",
        )
        == expected
    )


def test_sqlserver_direct_ddl_grants_are_prescribed_under_auto() -> None:
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=("db_datareader", "db_datawriter"),
            control_server=False,
            control_database=False,
            database="MessageFoundry",
            external=False,
            create_table=True,
            alter_schema="dbo",
        )
        == ()
    )


# --- the Postgres probe, through a stubbed read ------------------------------------------------


def _postgres_probe(
    monkeypatch: pytest.MonkeyPatch,
    *,
    mode: SchemaManagement | None,
    create_on_schema: bool | None,
    audit_writes: tuple[str, ...] | None = (),
) -> Any:
    """A real :class:`PostgresStore` over stubbed reads. ``audit_writes=None`` reads every audit-table
    grant as NULL, which is what a role that cannot resolve the tables gets back."""
    from messagefoundry.store.postgres import PostgresStore

    store = PostgresStore(None, _server(StoreBackend.POSTGRES, schema_management=mode))

    async def _fetchall(sql: str, *params: Any) -> list[dict[str, Any]]:
        return [
            {
                "rolname": "mefor",
                "is_self": True,
                "rolsuper": False,
                "rolcreaterole": False,
                "rolcreatedb": False,
                "rolreplication": False,
                "rolbypassrls": False,
            }
        ]

    async def _fetchone(sql: str, *params: Any) -> dict[str, Any]:
        return {
            "principal": "mefor",
            "db_name": "messagefoundry",
            "owns_database": False,
            "create_on_database": False,
            "store_schema": "mefor",
            "create_on_schema": create_on_schema,
            "owned_in_schema": 0,
            # Owner ruling R16: the append-only audit tables. ``audit_writes`` names the held rights.
            **{
                audit_write_alias(table, privilege): (
                    None
                    if audit_writes is None
                    else audit_write_grant(privilege, table) in audit_writes
                )
                for table in AUDIT_APPEND_ONLY_TABLES
                for privilege in POSTGRES_AUDIT_WRITE_PRIVILEGES
            },
        }

    monkeypatch.setattr(store, "_fetchall", _fetchall)
    monkeypatch.setattr(store, "_fetchone", _fetchone)
    return store


async def test_postgres_probe_names_schema_create_under_external(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _postgres_probe(monkeypatch, mode=None, create_on_schema=True)
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess == ("CREATE on schema mefor",)


async def test_postgres_probe_expects_schema_create_under_auto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _postgres_probe(monkeypatch, mode=SchemaManagement.AUTO, create_on_schema=True)
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess == ()


async def test_postgres_probe_with_no_current_schema_is_unobserved_under_external(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The schema-DDL half is the whole point of external mode, so a NULL read of it is not clean."""
    store = _postgres_probe(monkeypatch, mode=None, create_on_schema=None)
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.UNOBSERVABLE
    assert "not read" in report.detail


# --- the Postgres open path, through a fake connection -----------------------------------------


class _FakePgConn:
    """Answers the external-mode reads and records anything that would write.

    ``usage`` is whether the role holds USAGE on ``db_schema``; ``ungranted`` names objects the role
    cannot use, as the runtime-grants check would find them."""

    def __init__(
        self,
        *,
        present: bool,
        schema_hash: str | None,
        usage: bool = True,
        ungranted: tuple[str, ...] = (),
    ) -> None:
        self._present = present
        self._hash = schema_hash
        self._usage = usage
        self._ungranted = ungranted
        self.reads: list[str] = []
        self.writes: list[str] = []
        self.fetch_args: list[tuple[Any, ...]] = []

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        self.reads.append(sql)
        if "to_regclass" in sql:
            return {"present": self._present}
        if "has_schema_privilege" in sql:
            return {"usage": self._usage}
        if "current_schema()" in sql:
            return {"schema_name": "public"}
        return None if self._hash is None else {"schema_hash": self._hash}

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        self.reads.append(sql)
        self.fetch_args.append(args)
        return [{"relname": name, "relkind": "r"} for name in self._ungranted]

    async def execute(self, sql: str, *args: Any, **kwargs: Any) -> None:
        self.writes.append(sql)

    def transaction(self) -> Any:
        raise AssertionError("external mode must never open a DDL transaction")


def _postgres_store_over(
    conn: _FakePgConn, mode: SchemaManagement | None, *, db_schema: str | None = None
) -> Any:
    from messagefoundry.store.postgres import PostgresStore

    store = PostgresStore(
        None, _server(StoreBackend.POSTGRES, schema_management=mode, db_schema=db_schema)
    )

    @contextlib.asynccontextmanager
    async def _timed_acquire(*, record: bool = True) -> AsyncIterator[Any]:
        yield conn

    store._timed_acquire = _timed_acquire  # type: ignore[method-assign]
    return store


@pytest.mark.parametrize(
    ("present", "schema_hash"), [(False, None), (True, "an-older-build")], ids=["virgin", "stale"]
)
async def test_postgres_external_refuses_without_ddl(
    present: bool, schema_hash: str | None
) -> None:
    conn = _FakePgConn(present=present, schema_hash=schema_hash)
    store = _postgres_store_over(conn, None)
    with pytest.raises(SchemaNotProvisionedError) as info:
        await store._ensure_schema()
    assert PROVISION_SCHEMA_COMMAND in str(info.value)
    assert conn.reads, "the marker must actually have been read"
    assert conn.writes == []


async def test_postgres_refusal_names_a_missing_usage_grant() -> None:
    """``to_regclass`` skips a schema the role cannot use, so a missing USAGE reads as an absent marker.
    The refusal must name the grant, because re-running provision-schema would say "already current"."""
    conn = _FakePgConn(present=False, schema_hash=None, usage=False)
    store = _postgres_store_over(conn, None, db_schema="mefor")
    with pytest.raises(SchemaNotProvisionedError) as info:
        await store._ensure_schema()
    assert "no USAGE on schema 'mefor'" in str(info.value)
    assert "grant usage on schema mefor" in str(info.value)
    assert conn.writes == []


async def test_postgres_refusal_with_usage_does_not_blame_the_grant() -> None:
    """The control for the case above: with USAGE held, the hint must not name a grant."""
    conn = _FakePgConn(present=False, schema_hash=None, usage=True)
    store = _postgres_store_over(conn, None, db_schema="mefor")
    with pytest.raises(SchemaNotProvisionedError) as info:
        await store._ensure_schema()
    assert "USAGE" not in str(info.value)


async def test_postgres_external_opens_a_provisioned_schema() -> None:
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash())
    store = _postgres_store_over(conn, None)
    assert await store._ensure_schema() is False
    assert conn.writes == []


async def test_postgres_external_refuses_a_current_schema_the_role_cannot_use() -> None:
    """A table owned by a role the default privileges do not cover has no runtime grant. The marker
    cannot tell, so the start must refuse and name it, rather than fail the first pipeline path."""
    from messagefoundry.store.base import StoreGrantsMissingError
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash(), ungranted=("messages",))
    store = _postgres_store_over(conn, None)
    with pytest.raises(StoreGrantsMissingError, match="lacks row access to 1 object"):
        await store._ensure_schema()
    assert conn.writes == []


async def test_postgres_grants_are_checked_before_the_marker_is_read() -> None:
    """Reading schema_hash needs SELECT on schema_meta. Checked first, a role without it gets the full
    list of what it cannot use rather than a raw permission error naming one table."""
    from messagefoundry.store.base import StoreGrantsMissingError

    conn = _FakePgConn(present=True, schema_hash=None, ungranted=("messages", "schema_meta"))
    store = _postgres_store_over(conn, None)
    with pytest.raises(StoreGrantsMissingError, match="2 object"):
        await store._ensure_schema()
    assert not any("schema_hash" in sql for sql in conn.reads)


async def test_postgres_auto_does_not_check_runtime_grants() -> None:
    """Under auto the role owns what it created, so the grants check is external-only."""
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash(), ungranted=("messages",))
    store = _postgres_store_over(conn, SchemaManagement.AUTO)
    assert await store._ensure_schema() is False


async def test_postgres_auto_on_the_same_stale_marker_reaches_the_ddl_transaction() -> None:
    """The control: the refusal above is the mode's doing. Auto on the same state goes on to open the
    DDL transaction (the fake refuses it, which is how this test sees it was reached)."""
    conn = _FakePgConn(present=True, schema_hash="an-older-build")
    store = _postgres_store_over(conn, SchemaManagement.AUTO)
    with pytest.raises(AssertionError, match="DDL transaction"):
        await store._ensure_schema()


# --- BACKLOG #1780: an auto open that must not build ---------------------------------------------


async def test_postgres_auto_without_create_refuses_a_database_with_no_store() -> None:
    """``create=False`` under auto: no ``schema_meta`` means no store, so nothing is built. The fake
    refuses a DDL transaction, so reaching one would fail with a different error."""
    from messagefoundry.store.base import StoreNotFoundError

    conn = _FakePgConn(present=False, schema_hash=None)
    store = _postgres_store_over(conn, SchemaManagement.AUTO)
    with pytest.raises(StoreNotFoundError, match="no schema_meta table"):
        await store._ensure_schema(create=False)
    assert conn.writes == []


async def test_postgres_auto_without_create_still_upgrades_a_store_that_is_there() -> None:
    """The control: a stale marker is a store, so the same open goes on to the DDL transaction."""
    conn = _FakePgConn(present=True, schema_hash="an-older-build")
    store = _postgres_store_over(conn, SchemaManagement.AUTO)
    with pytest.raises(AssertionError, match="DDL transaction"):
        await store._ensure_schema(create=False)


@pytest.mark.parametrize("mode", [SchemaManagement.AUTO, None], ids=["auto", "external"])
async def test_postgres_read_only_opens_a_stale_marker_as_it_is_and_says_so(
    mode: SchemaManagement | None, caplog: pytest.LogCaptureFixture
) -> None:
    """Never an upgrade (the fake refuses a DDL transaction) and never a refusal of the inspection."""
    conn = _FakePgConn(present=True, schema_hash="an-older-build")
    store = _postgres_store_over(conn, mode)
    with caplog.at_level("WARNING"):
        assert await store._ensure_schema(read_only=True) is False
    assert conn.writes == []
    assert "not current for this build; opened read-only" in caplog.text


@pytest.mark.parametrize("mode", [SchemaManagement.AUTO, None], ids=["auto", "external"])
async def test_postgres_read_only_refuses_a_database_with_no_store(
    mode: SchemaManagement | None,
) -> None:
    from messagefoundry.store.base import StoreNotFoundError

    conn = _FakePgConn(present=False, schema_hash=None)
    store = _postgres_store_over(conn, mode)
    with pytest.raises(StoreNotFoundError, match="no schema_meta table"):
        await store._ensure_schema(read_only=True)
    assert conn.writes == []


async def test_postgres_read_only_external_open_needs_no_write_grants() -> None:
    """An inspecting login should hold SELECT only; the runtime-grants check demands writes, so a
    read-only open skips it. The control is the ordinary external open refusing the same role."""
    from messagefoundry.store.base import StoreGrantsMissingError
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash(), ungranted=("messages",))
    assert await _postgres_store_over(conn, None)._ensure_schema(read_only=True) is False
    with pytest.raises(StoreGrantsMissingError):
        await _postgres_store_over(conn, None)._ensure_schema()


async def test_postgres_read_only_opens_a_current_store_under_auto() -> None:
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash())
    store = _postgres_store_over(conn, SchemaManagement.AUTO)
    assert await store._ensure_schema(read_only=True) is False
    assert conn.writes == []


# --- #1927's users.channel_scope_source column is provisioned, never added at runtime ------------


class _ProvisioningPgConn:
    """A virgin database for the provisioning run: no marker, no columns, every write recorded."""

    def __init__(self) -> None:
        self.writes: list[str] = []

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        return {"present": False} if "to_regclass" in sql else None

    async def fetch(self, sql: str, *args: Any) -> list[dict[str, Any]]:
        return []  # information_schema: nothing present yet, so every gated ADD fires

    async def execute(self, sql: str, *args: Any, **kwargs: Any) -> None:
        self.writes.append(" ".join(sql.split()))

    def transaction(self) -> Any:
        return contextlib.nullcontext()


async def test_postgres_provisioning_adds_the_channel_scope_source_column() -> None:
    """Under external mode (ADR 0192) the runtime role runs no DDL, so provision-schema is the ONLY
    thing that can add #1927's column to a pre-existing ``users`` table. On PostgreSQL that ADD lives
    in ``_migrate_lease_columns``, outside ``_SCHEMA``, so this proves the provisioning run reaches it."""
    conn = _ProvisioningPgConn()
    store = _postgres_store_over(conn, None)  # type: ignore[arg-type]
    assert await store._ensure_schema(provisioning=True) is True
    assert "ALTER TABLE users ADD COLUMN channel_scope_source TEXT" in conn.writes
    assert any(sql.startswith("INSERT INTO schema_meta") for sql in conn.writes)


async def test_postgres_external_refuses_a_marker_from_before_channel_scope_source() -> None:
    """The column's ADD is invisible to the content hash (it is Python, not ``_SCHEMA``), so
    ``_MIGRATION_REV`` carries it: 4 since #1927. A marker written at revision 3 must therefore be
    refused under external mode rather than open onto a table missing the column."""
    import hashlib

    from messagefoundry.store import postgres

    assert postgres._MIGRATION_REV >= 4
    rev3 = hashlib.sha256(("\n".join(postgres._SCHEMA) + "\nmigration_rev=3").encode()).hexdigest()
    assert rev3 != postgres._schema_hash()
    conn = _FakePgConn(present=True, schema_hash=rev3)
    store = _postgres_store_over(conn, None)
    with pytest.raises(SchemaNotProvisionedError):
        await store._ensure_schema()
    assert conn.writes == []


# --- the cluster coordinator's tables ride the batch ---------------------------------------------


def test_both_batches_carry_the_cluster_tables() -> None:
    """Under external the runtime login runs no DDL, so the coordinator's tables must be created by
    the batch provision-schema runs. Stated once, and appended to the batch, on both backends."""
    from messagefoundry.store import postgres, sqlserver

    for module in (postgres, sqlserver):
        batch = module._SCHEMA
        cluster = list(module.CLUSTER_SCHEMA)
        assert cluster, module.__name__
        start = batch.index(cluster[0])
        assert batch[start : start + len(cluster)] == cluster, module.__name__
        joined = "\n".join(module.CLUSTER_SCHEMA)
        assert "nodes" in joined and "leader_lease" in joined, module.__name__


@pytest.mark.parametrize(
    ("mode", "expected"), [(None, False), (SchemaManagement.AUTO, True)], ids=["external", "auto"]
)
@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
def test_the_coordinator_runs_its_ddl_under_auto_only(
    backend: StoreBackend, mode: SchemaManagement | None, expected: bool
) -> None:
    from messagefoundry.pipeline.cluster import build_coordinator

    store = types.SimpleNamespace(
        _pool=object(), _owner="node-1", _settings=_server(backend, schema_management=mode)
    )
    coordinator = build_coordinator(store, types.SimpleNamespace(enabled=True))
    assert coordinator._run_schema_ddl is expected  # type: ignore[attr-defined]


async def test_an_external_coordinator_start_issues_no_ddl(monkeypatch: pytest.MonkeyPatch) -> None:
    """The coordinator's own DDL is skipped outright under external, not merely made idempotent."""
    from messagefoundry.pipeline.cluster import DbCoordinator

    called: list[str] = []

    async def _ensure(self: DbCoordinator) -> None:
        called.append("ddl")

    async def _register(self: DbCoordinator) -> None:
        called.append("register")

    monkeypatch.setattr(DbCoordinator, "_ensure_nodes_table", _ensure)
    monkeypatch.setattr(DbCoordinator, "_register", _register)
    coordinator = DbCoordinator(object(), "node-1", run_schema_ddl=False)
    await coordinator.start()
    try:
        assert called == ["register"]
    finally:
        await coordinator.stop()


# --- the provisioning seam --------------------------------------------------------------------


async def test_provisioning_refuses_sqlite_and_creates_no_file(tmp_path: Path) -> None:
    target = tmp_path / "never.db"
    with pytest.raises(ValueError, match="sqlserver and postgres backends only"):
        await provision_store_schema(StoreSettings(path=str(target)))
    assert not target.exists()


@pytest.mark.parametrize("backend", [StoreBackend.SQLSERVER, StoreBackend.POSTGRES])
async def test_provisioning_dispatches_to_the_backend(
    monkeypatch: pytest.MonkeyPatch, backend: StoreBackend
) -> None:
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    cls = SqlServerStore if backend is StoreBackend.SQLSERVER else PostgresStore
    seen: list[StoreSettings] = []
    result = SchemaProvisionResult(applied=True, schema="dbo")

    async def _provision(settings: StoreSettings, *, posture: Any = None) -> SchemaProvisionResult:
        seen.append(settings)
        return result

    monkeypatch.setattr(cls, "provision_schema", _provision)
    settings = _server(backend)
    assert await provision_store_schema(settings) is result
    assert seen == [settings]


async def test_sqlserver_provisioning_runs_the_batch_with_provisioning_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``provision_schema`` must reach ``_ensure_schema(provisioning=True)`` even though the settings
    resolve to external, run the database options first, report what stayed OFF and where the batch
    landed, and release its pool."""
    from messagefoundry.store.sqlserver import SqlServerStore

    events: list[str] = []

    class _Pool:
        def close(self) -> None:
            events.append("pool.close")

        async def wait_closed(self) -> None:
            return None

    async def _create_pool(**kwargs: Any) -> _Pool:
        events.append(f"create_pool maxsize={kwargs['maxsize']}")
        return _Pool()

    monkeypatch.setitem(sys.modules, "aioodbc", types.SimpleNamespace(create_pool=_create_pool))

    async def _options(
        settings: StoreSettings, *, posture: Any = None, fail_closed: bool = True
    ) -> None:
        # Not an open: an RCSI it cannot enable is reported by the read-back, not raised (#1628).
        events.append(f"options fail_closed={fail_closed}")

    async def _ensure(self: SqlServerStore, *, provisioning: bool = False) -> bool:
        events.append(f"ensure provisioning={provisioning}")
        return True

    async def _fetchone(self: SqlServerStore, sql: str, params: Any = ()) -> dict[str, Any]:
        # The state READ BACK after the run: RCSI on, snapshot isolation still off.
        return {"rcsi": 1, "si": 0, "schema_name": "dbo"}

    monkeypatch.setattr(SqlServerStore, "_ensure_database_options", staticmethod(_options))
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _ensure)
    monkeypatch.setattr(SqlServerStore, "_fetchone", _fetchone)

    settings = _server(StoreBackend.SQLSERVER)
    assert settings.resolved_schema_management() is SchemaManagement.EXTERNAL
    result = await SqlServerStore.provision_schema(settings)
    assert result == SchemaProvisionResult(
        applied=True,
        schema="dbo",
        options_off=("ALLOW_SNAPSHOT_ISOLATION",),
        remedy="alter database [MessageFoundry] SET ALLOW_SNAPSHOT_ISOLATION ON",
    )
    assert events == [
        "options fail_closed=False",
        "create_pool maxsize=1",
        "ensure provisioning=True",
        "pool.close",
    ]


# --- the CLI ----------------------------------------------------------------------------------


def _clear_store_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("MEFOR_STORE_"):
            monkeypatch.delenv(key, raising=False)


def test_cli_refuses_a_sqlite_store_and_creates_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_store_env(monkeypatch)
    target = tmp_path / "never.db"
    toml = tmp_path / "svc.toml"
    toml.write_text(f'[store]\npath = "{target.as_posix()}"\n', encoding="utf-8")
    assert main(["store", "provision-schema", "--service-config", str(toml)]) == 1
    assert "sqlserver and postgres backends only" in capsys.readouterr().err
    assert not target.exists()


def _server_toml(tmp_path: Path, body: str | None = None) -> Path:
    toml = tmp_path / "svc.toml"
    toml.write_text(
        body
        or '[store]\nbackend = "postgres"\nserver = "db.invalid"\ndatabase = "messagefoundry"\n'
        'username = "mefor_runtime"\n',
        encoding="utf-8",
    )
    return toml


def _stub_provision(
    monkeypatch: pytest.MonkeyPatch, result: SchemaProvisionResult, seen: list[StoreSettings]
) -> None:
    async def _provision(settings: StoreSettings, *, posture: Any = None) -> SchemaProvisionResult:
        seen.append(settings)
        return result

    monkeypatch.setattr("messagefoundry.store.base.provision_store_schema", _provision)


def test_cli_provisions_as_the_named_principal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--username`` swaps in the provisioning principal; the runtime one stays in the file."""
    _clear_store_env(monkeypatch)
    seen: list[StoreSettings] = []
    _stub_provision(monkeypatch, SchemaProvisionResult(applied=True, schema="mefor"), seen)
    toml = _server_toml(tmp_path)
    argv = ["store", "provision-schema", "--service-config", str(toml), "--username", "mefor_dba"]
    assert main([*argv, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload == {
        "ok": True,
        "backend": "postgres",
        "database": "messagefoundry",
        "schema": "mefor",
        "applied": True,
        "options_off": [],
        "remedy": None,
        "schema_management": "external",
    }
    assert [s.username for s in seen] == ["mefor_dba"]


def test_cli_reports_an_already_current_schema_and_where_it_is(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_store_env(monkeypatch)
    _stub_provision(monkeypatch, SchemaProvisionResult(applied=False, schema="mefor"), [])
    assert main(["store", "provision-schema", "--service-config", str(_server_toml(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "already current" in out
    assert "schema 'mefor'" in out


def test_cli_exits_3_when_a_database_option_stayed_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The schema is built but RCSI is still off, which the store refuses to open on (#1628). A job
    reading only the exit code must not see a success."""
    _clear_store_env(monkeypatch)
    remedy = "ALTER DATABASE [x] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE"
    result = SchemaProvisionResult(
        applied=True, schema="dbo", options_off=("READ_COMMITTED_SNAPSHOT",), remedy=remedy
    )
    _stub_provision(monkeypatch, result, [])
    argv = ["store", "provision-schema", "--service-config", str(_server_toml(tmp_path))]
    assert main(argv) == 3
    captured = capsys.readouterr()
    assert "error: READ_COMMITTED_SNAPSHOT is OFF" in captured.err
    assert remedy in captured.err
    assert main([*argv, "--json"]) == 3
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is False
    assert payload["options_off"] == ["READ_COMMITTED_SNAPSHOT"]


def test_cli_snapshot_isolation_alone_is_a_warning_not_a_partial_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Nothing in the engine opens a SNAPSHOT transaction, so ALLOW_SNAPSHOT_ISOLATION off alone must
    not fail an exit-code-driven job. It is still reported, with its statement."""
    _clear_store_env(monkeypatch)
    remedy = "ALTER DATABASE [x] SET ALLOW_SNAPSHOT_ISOLATION ON"
    result = SchemaProvisionResult(
        applied=True, schema="dbo", options_off=("ALLOW_SNAPSHOT_ISOLATION",), remedy=remedy
    )
    _stub_provision(monkeypatch, result, [])
    argv = ["store", "provision-schema", "--service-config", str(_server_toml(tmp_path))]
    assert main(argv) == 0
    err = capsys.readouterr().err
    assert "warning: ALLOW_SNAPSHOT_ISOLATION is OFF" in err
    assert remedy in err


def test_cli_refuses_username_under_integrated_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Under integrated auth the ODBC string carries no UID, so a --username would be silently dropped
    and the DDL would run as whoever runs the command."""
    _clear_store_env(monkeypatch)
    seen: list[StoreSettings] = []
    _stub_provision(monkeypatch, SchemaProvisionResult(applied=True), seen)
    toml = _server_toml(
        tmp_path,
        '[store]\nbackend = "sqlserver"\nserver = "db.invalid"\ndatabase = "MessageFoundry"\n'
        'auth = "integrated"\n',
    )
    argv = ["store", "provision-schema", "--service-config", str(toml), "--username", "mefor_dba"]
    assert main(argv) == 1
    assert "--username applies to [store].auth = 'sql' only" in capsys.readouterr().err
    assert seen == []


def test_cli_settings_failure_never_prints_the_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The DBA has the provisioning password in MEFOR_STORE_PASSWORD. A [store] that fails validation
    must be rendered, not stringified, or the section's input values reach the terminal."""
    _clear_store_env(monkeypatch)
    secret = "Px9_" + secrets.token_urlsafe(18)
    monkeypatch.setenv("MEFOR_STORE_PASSWORD", secret)
    toml = _server_toml(tmp_path, '[store]\nbackend = "postgres"\ndatabase = "messagefoundry"\n')
    for extra in ([], ["--json"]):
        code = main(["store", "provision-schema", "--service-config", str(toml), *extra])
        captured = capsys.readouterr()
        assert code == 1
        assert secret not in captured.out + captured.err


def test_cli_reports_a_driver_failure_as_one_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _clear_store_env(monkeypatch)

    async def _provision(settings: StoreSettings, *, posture: Any = None) -> SchemaProvisionResult:
        raise PermissionError("permission denied for schema mefor")

    monkeypatch.setattr("messagefoundry.store.base.provision_store_schema", _provision)
    assert main(["store", "provision-schema", "--service-config", str(_server_toml(tmp_path))]) == 1
    err = capsys.readouterr().err
    assert "provision-schema failed on the postgres database 'messagefoundry'" in err
    assert "Traceback" not in err


def test_the_refusal_names_the_command_and_the_escape() -> None:
    """Loud at start AND actionable: the operator reads what to run and what the alternative costs."""
    text = str(SchemaNotProvisionedError(StoreBackend.SQLSERVER, "MessageFoundry", "a" * 64))
    assert PROVISION_SCHEMA_COMMAND in text
    assert "schema_management = 'auto'" in text
    assert "'MessageFoundry'" in text


# --- owner ruling R16 (ASVS 16.4.2): the audit table is append-only for the runtime login --------
#
# The runtime login needs INSERT and SELECT on audit_log and nothing more, so on a first deployment a
# login that also held UPDATE or DELETE there could rewrite or drop audit rows. R16 first listed
# audit_chain_meta too; the owner amended it on 2026-10-01, when that table was removed and the
# chain's genesis row took over naming the first key (vault BACKLOG #2594). Under
# external schema management the probe names each such right as excess, which refuses the start under
# the shipped `enforce` dial (ADR 0199). The engine's own write paths are INSERT-only, pinned below.

_PG_AUDIT_WRITES = tuple(
    audit_write_grant(privilege, table)
    for table in AUDIT_APPEND_ONLY_TABLES
    for privilege in POSTGRES_AUDIT_WRITE_PRIVILEGES
)
_SS_AUDIT_WRITES = tuple(
    audit_write_grant(privilege, table)
    for table in AUDIT_APPEND_ONLY_TABLES
    for privilege in SQLSERVER_AUDIT_WRITE_PRIVILEGES
)


@pytest.mark.parametrize(("external", "expected"), [(True, _PG_AUDIT_WRITES), (False, ())])
def test_postgres_audit_table_writes_are_excess_in_external_mode_only(
    external: bool, expected: tuple[str, ...]
) -> None:
    """Under auto the role owns the audit tables and may grant itself any right back, so no reading
    of its grants there could show them append-only; the finding is external-only."""
    assert (
        postgres_excess(
            roles=_PLAIN_ROLE,
            owns_database=False,
            create_on_database=False,
            database="messagefoundry",
            external=external,
            schema="mefor",
            audit_writes=_PG_AUDIT_WRITES,
        )
        == expected
    )


@pytest.mark.parametrize(("external", "expected"), [(True, _SS_AUDIT_WRITES), (False, ())])
def test_sqlserver_audit_table_writes_are_excess_in_external_mode_only(
    external: bool, expected: tuple[str, ...]
) -> None:
    """db_datawriter grants UPDATE and DELETE on every table, so without the runbook's DENY a
    row-only login holds both on the audit tables."""
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=("db_datareader", "db_datawriter"),
            control_server=False,
            control_database=False,
            database="MessageFoundry",
            external=external,
            audit_writes=_SS_AUDIT_WRITES,
        )
        == expected
    )


@pytest.mark.parametrize(
    ("server_roles", "roles", "control_server", "control_database"),
    [
        ((), ("db_owner",), False, False),
        (("sysadmin",), (), False, False),
        ((), (), True, False),
        ((), (), False, True),
    ],
    ids=["db_owner", "sysadmin", "control-server", "control-database"],
)
def test_sqlserver_audit_table_writes_are_not_restated_under_a_grant_that_carries_them(
    server_roles: tuple[str, ...],
    roles: tuple[str, ...],
    control_server: bool,
    control_database: bool,
) -> None:
    excess = sqlserver_excess(
        server_roles=server_roles,
        database_roles=roles,
        control_server=control_server,
        control_database=control_database,
        database="MessageFoundry",
        external=True,
        audit_writes=_SS_AUDIT_WRITES,
    )
    assert excess, "the carrying grant itself must still be named"
    assert not set(excess) & set(_SS_AUDIT_WRITES)


def test_sqlserver_a_server_role_with_no_table_right_does_not_hide_an_audit_write() -> None:
    """bulkadmin carries no right on a user table, so it must not stand in for the DENY that is
    missing: the audit rights are named beside it."""
    excess = sqlserver_excess(
        server_roles=("bulkadmin",),
        database_roles=("db_datareader", "db_datawriter"),
        control_server=False,
        control_database=False,
        database="MessageFoundry",
        external=True,
        audit_writes=("UPDATE on table audit_log",),
    )
    assert excess == ("server role bulkadmin", "UPDATE on table audit_log")


@pytest.mark.parametrize(
    ("roles", "alter_schema", "table_alter_named"),
    [
        (("db_datareader", "db_datawriter", "db_ddladmin"), None, False),
        (("db_datareader", "db_datawriter"), "app", True),
    ],
    ids=["db_ddladmin", "schema-alter"],
)
def test_sqlserver_table_alter_is_folded_into_db_ddladmin_only(
    roles: tuple[str, ...], alter_schema: str | None, table_alter_named: bool
) -> None:
    """db_ddladmin carries ALTER on every table. ALTER on the default schema does not: the audit
    tables may resolve to dbo instead, so the table right is still named beside it."""
    excess = sqlserver_excess(
        server_roles=(),
        database_roles=roles,
        control_server=False,
        control_database=False,
        database="MessageFoundry",
        external=True,
        alter_schema=alter_schema,
        audit_writes=_SS_AUDIT_WRITES,
    )
    assert ("ALTER on table audit_log" in excess) is table_alter_named
    assert "UPDATE on table audit_log" in excess
    assert "DELETE on table audit_log" in excess


@pytest.mark.parametrize(
    ("mode", "expected"),
    [(None, ("UPDATE on table audit_log",)), (SchemaManagement.AUTO, ())],
    ids=["external", "auto"],
)
async def test_postgres_probe_names_an_audit_table_update(
    monkeypatch: pytest.MonkeyPatch, mode: SchemaManagement | None, expected: tuple[str, ...]
) -> None:
    store = _postgres_probe(
        monkeypatch, mode=mode, create_on_schema=False, audit_writes=("UPDATE on table audit_log",)
    )
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess == expected


async def test_postgres_probe_that_cannot_see_the_audit_tables_is_unobserved_under_external(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _postgres_probe(monkeypatch, mode=None, create_on_schema=False, audit_writes=None)
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.UNOBSERVABLE
    assert "UPDATE on table audit_log" in report.detail


async def test_postgres_unread_audit_grants_never_soften_a_found_over_grant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With CREATE on the schema already found, the start must still refuse under enforce, so the
    report stays OBSERVED with that finding, and the unread audit grants are named in the detail."""
    store = _postgres_probe(monkeypatch, mode=None, create_on_schema=True, audit_writes=None)
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess == ("CREATE on schema mefor",)
    assert "audit-table grants read NULL" in report.detail


def test_postgres_audit_probe_reads_every_assumable_role_and_column_updates() -> None:
    """``has_table_privilege(current_user, ...)`` counts only INHERITED rights, and a NOINHERIT member
    can still SET ROLE to the holder. A column UPDATE grant rewrites row content as well. The probe
    column must reach both, and must stay NULL for a table it cannot resolve."""
    from messagefoundry.store.postgres import _audit_write_probe

    update = _audit_write_probe("audit_log", "UPDATE")
    assert "pg_has_role(current_user, r.oid, 'MEMBER')" in update
    assert "has_any_column_privilege(r.oid" in update
    assert "IS NULL THEN NULL" in update
    delete = _audit_write_probe("audit_log", "DELETE")
    assert "has_table_privilege(r.oid" in delete


def test_sqlserver_audit_probe_reads_column_updates() -> None:
    """A column-level GRANT outranks a table-level DENY on SQL Server, so UPDATE is read per column."""
    from messagefoundry.store.sqlserver import _audit_write_probe

    update = _audit_write_probe("audit_log", "UPDATE")
    assert "c.name, 'COLUMN'" in update and "sys.columns" in update
    assert "'COLUMN'" not in _audit_write_probe("audit_log", "DELETE")


async def test_postgres_probe_that_cannot_see_the_audit_tables_is_still_clean_under_auto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The control: auto does not count the audit grants, so it does not need them read."""
    store = _postgres_probe(
        monkeypatch, mode=SchemaManagement.AUTO, create_on_schema=False, audit_writes=None
    )
    report = await store.probe_principal_privileges()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.excess == ()


async def test_postgres_runtime_grants_ask_only_insert_and_select_of_the_audit_tables() -> None:
    """The missing-grants check must not demand UPDATE or DELETE on the audit tables, or a role
    granted exactly what R16 prescribes would be refused as under-granted."""
    from messagefoundry.store.postgres import _schema_hash

    conn = _FakePgConn(present=True, schema_hash=_schema_hash())
    store = _postgres_store_over(conn, None)
    assert await store._ensure_schema() is False
    (sql,) = [q for q in conn.reads if "has_table_privilege" in q]
    assert conn.fetch_args[0] == (list(AUDIT_APPEND_ONLY_TABLES),)
    audit_arm = sql.split("c.relname = ANY($1::text[])", 1)[1].split(" OR ", 1)[0]
    assert "'INSERT'" in audit_arm and "'SELECT'" in audit_arm
    assert "'UPDATE'" not in audit_arm and "'DELETE'" not in audit_arm


class _GenesisPgConn:
    """A connection for the genesis append: answers the head read and records every statement.

    ``head`` is what the append's read of the chain head returns under the advisory lock. ``None``
    is an empty log; a row is a chain a peer engine started first."""

    def __init__(self, *, head: dict[str, Any] | None) -> None:
        self._head = head
        self.statements: list[str] = []
        self.inserted: list[tuple[Any, ...]] = []

    async def fetchrow(self, sql: str, *args: Any) -> dict[str, Any] | None:
        self.statements.append(sql)
        return self._head

    async def fetchval(self, sql: str, *args: Any) -> int:
        self.statements.append(sql)
        self.inserted.append(args)
        return 1

    def transaction(self) -> Any:
        return contextlib.nullcontext()


def _keyed_postgres_store(conn: _GenesisPgConn, chain: list[list[dict[str, Any]]]) -> Any:
    """A keyed PostgresStore over ``conn``. ``chain`` is what successive reads of the chain return,
    in order: the open reads the row at seq 1, and reads it again after its genesis attempt. Past
    the end of the list the log reads empty."""
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.store import build_audit_mac_keys

    store = PostgresStore(None, _server(StoreBackend.POSTGRES))
    store._audit_mac_key = b"\x01" * 32  # a keying secret in hand, so a fresh chain is keyed
    store._audit_mac_keys = build_audit_mac_keys(None, store._audit_mac_key)

    @contextlib.asynccontextmanager
    async def _timed_acquire(*, record: bool = True) -> AsyncIterator[Any]:
        yield conn

    async def _no_lock(conn: Any, classid: int, key: str) -> None:
        return None

    async def _fetchall(sql: str, *args: Any) -> list[dict[str, Any]]:
        conn.statements.append(sql)
        return chain.pop(0) if chain and "WHERE action" not in sql else []

    store._timed_acquire = _timed_acquire  # type: ignore[method-assign]
    store._advisory_lock = _no_lock  # type: ignore[method-assign]
    store._fetchall = _fetchall  # type: ignore[method-assign]
    return store


def _no_row_change(statements: list[str]) -> None:
    for sql in statements:
        assert "DO UPDATE" not in sql
        assert not sql.lstrip().upper().startswith(("UPDATE", "DELETE"))


def _genesis_row(key: bytes) -> dict[str, Any]:
    """The genesis row a keyed open writes, as a read of the chain returns it."""
    from messagefoundry.store.crypto import audit_key_id
    from messagefoundry.store.store import (
        AUDIT_KEY_EPOCH_ACTION,
        audit_genesis_detail,
        audit_row_hash,
    )

    detail = audit_genesis_detail(audit_key_id(key))
    row: dict[str, Any] = {
        "id": 1,
        "seq": 1,
        "ts": 1.0,
        "actor": "system",
        "action": AUDIT_KEY_EPOCH_ACTION,
        "channel_id": None,
        "detail": detail,
        "client": None,
    }
    row["row_hash"] = audit_row_hash(
        "",
        seq=1,
        ts=1.0,
        actor="system",
        action=AUDIT_KEY_EPOCH_ACTION,
        channel_id=None,
        detail=detail,
        key=key,
    )
    return row


async def test_postgres_starts_a_fresh_chain_with_insert_alone() -> None:
    """The open's one audit write is the genesis row, and it is an INSERT: the runtime role needs
    no UPDATE or DELETE on ``audit_log`` to start a keyed chain (owner ruling R16)."""
    from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, load_audit_chain

    conn = _GenesisPgConn(head=None)
    key = b"\x01" * 32
    store = _keyed_postgres_store(conn, [[], [_genesis_row(key)]])
    await load_audit_chain(store, read_only=False)
    assert store._audit_chain_keyed is True
    (written,) = conn.inserted
    assert written[0] == 1 and written[3] == AUDIT_KEY_EPOCH_ACTION  # seq 1, the genesis action
    assert any(sql.startswith("INSERT INTO audit_log") for sql in conn.statements)
    _no_row_change(conn.statements)


async def test_postgres_adopts_the_genesis_row_a_peer_wrote_first() -> None:
    """Two engines opening one empty store both try to start its chain. The append requires an
    empty log under the advisory lock, so the loser writes nothing and reads what the winner
    wrote."""
    from messagefoundry.store.store import load_audit_chain

    key = b"\x01" * 32
    peer = _genesis_row(key)
    # Empty at the open's first read; a row is there by the time the append reads the head.
    conn = _GenesisPgConn(head=peer)
    store = _keyed_postgres_store(conn, [[], [peer]])
    await load_audit_chain(store, read_only=False)
    assert store._audit_chain_keyed is True and store._audit_range_from == 1
    assert conn.inserted == [], "the loser must not write a second genesis row"
    _no_row_change(conn.statements)


async def test_postgres_a_read_only_open_starts_no_chain() -> None:
    """The control for the two above: told the open is read-only, the load writes nothing."""
    from messagefoundry.store.store import load_audit_chain

    conn = _GenesisPgConn(head=None)
    store = _keyed_postgres_store(conn, [[]])
    await load_audit_chain(store, read_only=True)
    assert store._audit_chain_keyed is False and conn.inserted == []


class _GenesisSsCursor:
    """A cursor for the SQL Server genesis append. ``rowcount`` is pinned to -1, what a session
    under NOCOUNT reports, so an append that read it would misjudge every case."""

    def __init__(self) -> None:
        self.rowcount = -1
        self._last = ""
        self.statements: list[str] = []

    async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self.statements.append(sql)
        self._last = sql

    async def fetchall(self) -> list[tuple[Any, ...]]:
        return []

    async def fetchone(self) -> tuple[Any, ...] | None:
        if self._last.startswith("INSERT"):
            return (1,)  # OUTPUT INSERTED.id
        return None  # the head read: an empty log


async def test_sqlserver_starts_a_fresh_chain_with_insert_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SQL Server checks an UPDATE's permission when it compiles the statement, touched rows or
    not, so the genesis write must be an INSERT and nothing else. It is the ordinary append,
    under the audit applock, told to require an empty log."""
    from messagefoundry.store.sqlserver import SqlServerStore
    from messagefoundry.store.store import build_audit_mac_keys, load_audit_chain

    key = b"\x01" * 32
    cur = _GenesisSsCursor()
    store = SqlServerStore(None, _server(StoreBackend.SQLSERVER))
    store._audit_mac_key = key
    store._audit_mac_keys = build_audit_mac_keys(None, key)
    chain: list[list[dict[str, Any]]] = [[], [_genesis_row(key)]]

    class _Conn:
        async def rollback(self) -> None:
            return None

    @contextlib.asynccontextmanager
    async def _acquire() -> AsyncIterator[Any]:
        yield _Conn()

    @contextlib.asynccontextmanager
    async def _cursor(_conn: Any) -> AsyncIterator[Any]:
        yield cur

    async def _commit(_conn: Any) -> None:
        return None

    async def _applock(_cur: Any, _resource: str) -> None:
        return None

    async def _fetchall(sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        return chain.pop(0) if chain and "WHERE action" not in sql else []

    monkeypatch.setattr(store, "_acquire", _acquire)
    monkeypatch.setattr(store, "_cursor", _cursor)
    monkeypatch.setattr(store, "_commit", _commit)
    monkeypatch.setattr(store, "_applock", _applock)
    monkeypatch.setattr(store, "_fetchall", _fetchall)
    await load_audit_chain(store, read_only=False)
    assert store._audit_chain_keyed is True
    assert [s for s in cur.statements if s.startswith("INSERT INTO audit_log")]
    for sql in cur.statements:
        assert not sql.lstrip().upper().startswith(("UPDATE", "DELETE"))


#: An audit table's name as a statement may spell it: bare, bracketed, or schema-qualified.
_AUDIT_TABLE = r"(?:\[?\w+\]?\.)?\[?audit_log\]?(?!\w)"
_TOP = r"(?:TOP\s*\([^)]*\)\s*(?:PERCENT\s+)?)?"
#: A statement that changes or removes rows of an append-only audit table.
_AUDIT_ROW_CHANGE = re.compile(
    rf"\b(?:UPDATE\s+{_TOP}{_AUDIT_TABLE}|DELETE\s+{_TOP}(?:FROM\s+)?{_AUDIT_TABLE}"
    rf"|TRUNCATE\s+(?:TABLE\s+)?{_AUDIT_TABLE}|MERGE\s+{_TOP}(?:INTO\s+)?{_AUDIT_TABLE})",
    re.IGNORECASE,
)


def _audit_row_changes(source: str) -> list[str]:
    """Every LITERAL row-changing statement on an audit table in ``source``, plus any INSERT into one
    that turns into an update on conflict (an upsert). It reads at least the
    literal shapes, not a statement built from a variable or a schema-qualified name, so the live legs'
    DENY and REVOKE are the behavioural guard and this is only the cheap early one."""
    found = [m.group(0) for m in _AUDIT_ROW_CHANGE.finditer(source)]
    for m in re.finditer(r"INTO\s+audit_log\b", source, re.IGNORECASE):
        if "DO UPDATE" in source[m.end() : m.end() + 400]:
            found.append(source[m.start() : m.end() + 400])
    return found


def test_the_row_change_scan_can_see_the_statements_it_forbids() -> None:
    """Positive control: the scan must find the shapes it exists to catch, including an upsert,
    or its zero below proves nothing."""
    removed = (
        '"INSERT INTO audit_log (seq, row_hash) VALUES ($1, $2) "\n'
        '"ON CONFLICT (seq) DO UPDATE SET row_hash = EXCLUDED.row_hash, "\n'
        '"UPDATE audit_log SET row_hash=? WHERE seq=1",\n'
        '"DELETE FROM audit_log WHERE id < ?"\n'
        '"DELETE TOP (1000) FROM dbo.audit_log WHERE ts < ?"\n'
        '"DELETE audit_log WHERE seq=1"\n'
        '"UPDATE TOP (1) [audit_log] SET detail = ?"\n'
    )
    assert len(_audit_row_changes(removed)) == 6
    # ...and none of the INSERT and SELECT shapes the engine does run.
    kept = (
        '"INSERT INTO audit_log (seq, ts, actor) OUTPUT INSERTED.id"\n'
        '"SELECT seq, row_hash FROM audit_log ORDER BY seq DESC"\n'
        '"UPDATE audit_log_archive SET x = 1"\n'
    )
    assert _audit_row_changes(kept) == []


@pytest.mark.parametrize("module", ["postgres", "sqlserver"])
def test_no_server_store_statement_changes_an_audit_row(module: str) -> None:
    """The engine's own statements must fit the INSERT and SELECT grant R16 prescribes."""
    source = (_ROOT / "messagefoundry" / "store" / f"{module}.py").read_text(encoding="utf-8")
    assert "INSERT INTO audit_log" in source  # the scan reads the file that writes the row
    assert _audit_row_changes(source) == []


# --- the live legs must actually be RUN somewhere ----------------------------------------------


@pytest.mark.parametrize("gate", ["MEFOR_TEST_SQLSERVER", "MEFOR_TEST_POSTGRES"])
def test_the_live_legs_of_this_file_are_run_by_a_server_db_ci_step(gate: str) -> None:
    """These legs gate PER TEST, so tests/test_serverdb_ci_coverage.py does not see them. A ci.yml step
    exporting ``gate`` must name this file, or the live SQL executes nowhere."""
    ci = (_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    steps = re.split(r"\n\s*- name: ", ci)
    assert any(f'{gate}: "1"' in step and _THIS_FILE in step for step in steps), (
        f"no ci.yml step exporting {gate} runs {_THIS_FILE}, so its live legs execute nowhere"
    )


# --- live server legs (skipped locally; CI's store-privilege steps run them) -------------------


def _update_of(table: str) -> str:
    """An UPDATE of one ordinary column of ``table``. Not the id: SQL Server refuses an identity column
    at compile time, before it checks the permission this statement exists to hit."""
    return f"UPDATE {table} SET actor = actor"


@pytest.fixture
async def sqlserver_split_scratch() -> AsyncIterator[tuple[SqlServerAdmin, StoreSettings, str]]:
    """An EMPTY scratch database and a login name, both unique to one test and both dropped afterwards,
    even when the test fails. Yields the admin connection, the scratch database's external-mode store
    settings, and the login name (the test creates the login itself, at the point the flow needs it).

    These were the fixed names ``mefor_schema_split_test`` and ``mefor_split_runtime`` behind an
    ``IF SUSER_ID(...) IS NULL`` guard, so a run that died before its teardown handed the next one a
    login holding the dead run's password. Skips (never fails) when the principal cannot create a
    database: that is a limit of the fixture's credential, not a finding."""
    base = load_settings(environ=os.environ).store
    db = scratch_name("mefor_split")
    login = scratch_name("mefor_split_rt")
    async with sqlserver_admin(base) as admin:
        try:
            try:
                await bounded(
                    base, "create the scratch database", admin.run(f"CREATE DATABASE [{db}]")
                )
            except TimeoutError:
                raise  # a stall is a finding, reported above; only a refusal is a fixture limit
            except Exception as exc:  # noqa: BLE001 - a fixture limit, not a finding
                pytest.skip(f"cannot create a scratch database with this principal: {exc}")
            external = base.model_copy(
                update={"database": db, "schema_management": SchemaManagement.EXTERNAL}
            )
            yield admin, external, login
        finally:
            await admin.teardown(databases=[db], logins=[login])


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_external_refuses_then_provisions_then_runs_row_only(
    sqlserver_split_scratch: tuple[SqlServerAdmin, StoreSettings, str],
) -> None:
    """End to end on a real SQL Server, in a database the fixture creates and drops:

    1. external open of an EMPTY database refuses, and the database is still empty afterwards;
    2. provision-schema builds it, and a second run is a no-op;
    3. a login holding only db_datareader + db_datawriter is named for UPDATE and DELETE on the audit
       table; after the runbook's DENY it opens it, starts the keyed chain with INSERT alone, appends,
       verifies and rotates its key, probes clean, and an UPDATE or DELETE of the audit table is
       refused (owner ruling R16);
    4. the same login given db_ddladmin is named as over-granted.
    """
    from messagefoundry.store.sqlserver import SqlServerStore

    admin, external, login = sqlserver_split_scratch
    db = external.database
    assert db is not None  # the fixture set it
    password = throwaway_password()
    # Every step is bounded: a stall writes the server's blocking report instead of running into the
    # leg's whole-test timeout with nothing said (tests/_live_scratch.py, `bounded`).
    sa = admin.settings

    with pytest.raises(SchemaNotProvisionedError):
        await bounded(sa, "external open of the empty database", SqlServerStore.open(external))
    objects = f"SELECT COUNT(*) FROM [{db}].sys.objects WHERE is_ms_shipped = 0"
    assert await bounded(sa, "count objects", admin.scalar(objects)) == 0

    assert (await bounded(sa, "provision", provision_store_schema(external))).applied is True
    tables = f"SELECT COUNT(*) FROM [{db}].sys.tables"
    assert await bounded(sa, "count tables", admin.scalar(tables)) > 0
    assert (await bounded(sa, "provision again", provision_store_schema(external))).applied is False

    # Unconditional: the name is this test's own, so an existing login is a defect to see, not reuse.
    await bounded(
        sa,
        "create the login",
        admin.run(f"CREATE LOGIN [{login}] WITH PASSWORD='{password}', CHECK_POLICY=OFF"),
    )
    await bounded(
        sa, "create the user", admin.run_in(db, f"CREATE USER [{login}] FOR LOGIN [{login}]")
    )
    for role in sorted(SQLSERVER_RUNTIME_DATABASE_ROLES):
        await bounded(
            sa, f"grant {role}", admin.run_in(db, f"ALTER ROLE {role} ADD MEMBER [{login}]")
        )
    runtime = external.model_copy(
        update={"auth": SqlAuth.SQL, "username": login, "password": password}
    )
    # Owner ruling R16, the control arm: db_datawriter alone grants UPDATE and DELETE on the audit
    # tables, and the probe must see them before the DENY below, or its clean read after proves nothing.
    store = await bounded(sa, "open before the audit DENY", SqlServerStore.open(runtime))
    try:
        undenied = await bounded(sa, "probe before the DENY", store.probe_principal_privileges())
    finally:
        await store.close()
    assert "UPDATE on table audit_log" in undenied.excess
    assert "DELETE on table audit_log" in undenied.excess
    for table in AUDIT_APPEND_ONLY_TABLES:
        await bounded(
            sa,
            f"deny writes on {table}",
            admin.run_in(db, f"DENY UPDATE, DELETE ON {table} TO [{login}]"),
        )
    # With a key, the open starts the empty chain: the genesis row is an INSERT, run as this login
    # under the DENY. The audit key rides the cipher, and `open_store` is what hands it over; a
    # direct open must too.
    old_key = generate_key()
    cipher = make_cipher(old_key)
    keyed = await bounded(
        sa,
        "open as the row-only login",
        SqlServerStore.open(runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()),
    )
    try:
        clean = await bounded(sa, "probe", keyed.probe_principal_privileges())
        assert not keyed.audit_chain_unkeyed(), "the INSERT-only login must start a keyed chain"
        await keyed.record_audit("r16.probe", actor="live-test", detail=None)
        ok, message = await bounded(sa, "verify under the DENY", keyed.verify_audit_chain())
        assert ok and "verified 2" in (message or ""), message  # the genesis row and the probe row
        for table in AUDIT_APPEND_ONLY_TABLES:
            for statement in (_update_of(table), f"DELETE FROM {table}"):
                with pytest.raises(Exception, match="permission was denied"):
                    await bounded(sa, statement, keyed._execute(statement))
    finally:
        await keyed.close()
    # A key rotation is one appended row too, so it also runs under the DENY.
    cipher = make_cipher(generate_key(), (old_key,))
    rotated = await bounded(
        sa,
        "open under the new key",
        SqlServerStore.open(runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()),
    )
    try:
        ok, message = await bounded(sa, "roll under the DENY", rotated.roll_audit_key_epoch())
        assert ok, f"the INSERT-only login must still roll the audit key: {message}"
        ok, message = await bounded(sa, "verify after the roll", rotated.verify_audit_chain())
        assert ok, message
    finally:
        await rotated.close()
    assert clean.status is StorePrivilegeStatus.OBSERVED
    assert clean.excess == (), f"a row-only runtime login must be silent, got {clean.excess}"
    rows = f"SELECT COUNT(*) FROM [{db}].dbo.audit_log"
    assert await bounded(sa, "count audit rows", admin.scalar(rows)) >= 1

    await bounded(
        sa, "grant db_ddladmin", admin.run_in(db, f"ALTER ROLE db_ddladmin ADD MEMBER [{login}]")
    )
    store = await bounded(
        sa,
        "reopen with db_ddladmin",
        SqlServerStore.open(runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()),
    )
    try:
        over = await bounded(sa, "probe again", store.probe_principal_privileges())
    finally:
        await store.close()
    assert "database role db_ddladmin" in over.excess


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_external_refuses_then_provisions_then_runs_row_only() -> None:
    """The Postgres twin, in a schema this test creates and drops. The provisioning principal owns
    every object it creates; the runtime role holds USAGE plus row grants and nothing else, and on the
    audit table only INSERT and SELECT (owner ruling R16): an UPDATE or DELETE there is refused."""
    from messagefoundry.store.postgres import PostgresStore

    base = load_settings(environ=os.environ).store
    # Unique per call, so a leftover from a crashed attempt can never be the role this run logs in as.
    schema = scratch_name("mefor_split")
    role = scratch_name("mefor_split_rt")
    password = throwaway_password()
    admin = await PostgresStore.open(base)
    try:
        try:
            await admin._execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            await admin._execute(f"DROP ROLE IF EXISTS {role}")
            await admin._execute(f"CREATE SCHEMA {schema}")
        except Exception as exc:  # noqa: BLE001 - a fixture limit, not a finding
            pytest.skip(f"cannot create a scratch schema with this principal: {exc}")

        async def tables() -> int:
            row = await admin._fetchone(
                "SELECT count(*) AS n FROM pg_catalog.pg_class c"
                " JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = $1",
                schema,
            )
            return int(row["n"])

        external = base.model_copy(
            update={"db_schema": schema, "schema_management": SchemaManagement.EXTERNAL}
        )
        with pytest.raises(SchemaNotProvisionedError):
            await PostgresStore.open(external)
        assert await tables() == 0

        assert (await provision_store_schema(external)).applied is True
        assert await tables() > 0
        assert (await provision_store_schema(external)).applied is False

        await admin._execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
        for stmt in (
            f"GRANT CONNECT ON DATABASE {base.database} TO {role}",
            f"GRANT USAGE ON SCHEMA {schema} TO {role}",
            f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}",
            f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}",
        ):
            await admin._execute(stmt)
        runtime = external.model_copy(update={"username": role, "password": password})
        # Owner ruling R16, the control arm: the blanket grant above covers the audit tables too, and
        # the probe must name it there before the REVOKE, or its clean read after proves nothing.
        store = await PostgresStore.open(runtime)
        try:
            unrevoked = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert "UPDATE on table audit_log" in unrevoked.excess
        assert "DELETE on table audit_log" in unrevoked.excess
        audit_tables = ", ".join(f"{schema}.{table}" for table in AUDIT_APPEND_ONLY_TABLES)
        await admin._execute(
            f"REVOKE UPDATE, DELETE, TRUNCATE, TRIGGER ON {audit_tables} FROM {role}"
        )
        # With a key, the open starts the empty chain: the genesis row is an INSERT, run as this
        # role under the REVOKE. The audit key rides the cipher; `open_store` hands it over, so a
        # direct open must too.
        old_key = generate_key()
        cipher = make_cipher(old_key)
        store = await PostgresStore.open(
            runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
        try:
            clean = await store.probe_principal_privileges()
            assert not store.audit_chain_unkeyed(), "the INSERT-only role must start a keyed chain"
            await store.record_audit("r16.probe", actor="live-test", detail=None)
            ok, message = await store.verify_audit_chain()
            assert ok and "verified 2" in (message or ""), message  # genesis row + probe row
            for table in AUDIT_APPEND_ONLY_TABLES:
                statements = (_update_of(table), f"DELETE FROM {table}", f"TRUNCATE {table}")
                for statement in statements:
                    with pytest.raises(Exception, match="permission denied"):
                        await store._execute(statement)
        finally:
            await store.close()
        # A key rotation is one appended row too, so it also runs under the REVOKE.
        cipher = make_cipher(generate_key(), (old_key,))
        store = await PostgresStore.open(
            runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
        try:
            ok, message = await store.roll_audit_key_epoch()
            assert ok, f"the INSERT-only role must still roll the audit key: {message}"
            ok, message = await store.verify_audit_chain()
            assert ok, message
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.excess == (), f"a row-only runtime role must be silent, got {clean.excess}"
        row = await admin._fetchone(f"SELECT count(*) AS n FROM {schema}.audit_log")
        assert row is not None and int(row["n"]) >= 1

        await admin._execute(f"GRANT CREATE ON SCHEMA {schema} TO {role}")
        store = await PostgresStore.open(
            runtime, cipher=cipher, audit_mac_key=cipher.audit_mac_key()
        )
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert f"CREATE on schema {schema}" in over.excess
    finally:
        await postgres_teardown(admin, database=base.database, schemas=[schema], roles=[role])
        await admin.close()
