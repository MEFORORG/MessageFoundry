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
    AuthSettings,
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
from messagefoundry.store.privilege import (
    SQLSERVER_DOCUMENTED_DATABASE_ROLES,
    SQLSERVER_RUNTIME_DATABASE_ROLES,
    PostgresRoleFacts,
    postgres_excess,
    sqlserver_excess,
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
            (),
            (),
            (),
            None,
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
            ("CREATE TABLE on database MessageFoundry", "ALTER on schema dbo"),
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
    monkeypatch: pytest.MonkeyPatch, *, mode: SchemaManagement | None, create_on_schema: bool | None
) -> Any:
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
    assert "NOT READ" in report.detail


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
    assert "GRANT USAGE ON SCHEMA mefor" in str(info.value)
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
    assert coordinator._run_schema_ddl is expected  # type: ignore[union-attr]


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

    async def _options(settings: StoreSettings, *, posture: Any = None) -> None:
        events.append("options")

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
        remedy="ALTER DATABASE [MessageFoundry] SET ALLOW_SNAPSHOT_ISOLATION ON",
    )
    assert events == [
        "options",
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
    """The schema is built but RCSI is still off, which the pooled default refuses to start on. A job
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


def _throwaway_password() -> str:
    """Generated per run, never a literal; ``token_urlsafe`` needs no quoting inside SQL literals."""
    return "Px9_" + secrets.token_urlsafe(24)


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_external_refuses_then_provisions_then_runs_row_only() -> None:
    """End to end on a real SQL Server, in a database this test creates and drops:

    1. external open of an EMPTY database refuses, and the database is still empty afterwards;
    2. provision-schema builds it, and a second run is a no-op;
    3. a login holding only db_datareader + db_datawriter opens it and probes clean;
    4. the same login given db_ddladmin is named as over-granted.
    """
    import aioodbc

    from messagefoundry.store.sqlserver import SqlServerStore, connection_string

    base = load_settings(environ=os.environ).store
    db = "mefor_schema_split_test"
    login = "mefor_split_runtime"
    password = _throwaway_password()
    admin = await aioodbc.connect(dsn=connection_string(base), autocommit=True)
    try:
        cur = await admin.cursor()

        async def run(sql: str) -> None:
            await cur.execute(sql)

        async def scalar(sql: str) -> Any:
            await cur.execute(sql)
            row = await cur.fetchone()
            return None if row is None else row[0]

        try:
            await run(
                f"IF DB_ID('{db}') IS NOT NULL BEGIN ALTER DATABASE [{db}] SET SINGLE_USER WITH "
                f"ROLLBACK IMMEDIATE; DROP DATABASE [{db}]; END"
            )
            await run(f"CREATE DATABASE [{db}]")
        except Exception as exc:  # noqa: BLE001 - a fixture limit, not a finding
            pytest.skip(f"cannot create a scratch database with this principal: {exc}")

        external = base.model_copy(
            update={"database": db, "schema_management": SchemaManagement.EXTERNAL}
        )
        with pytest.raises(SchemaNotProvisionedError):
            await SqlServerStore.open(external)
        assert await scalar(f"SELECT COUNT(*) FROM [{db}].sys.objects WHERE is_ms_shipped = 0") == 0

        assert (await provision_store_schema(external)).applied is True
        assert await scalar(f"SELECT COUNT(*) FROM [{db}].sys.tables") > 0
        assert (await provision_store_schema(external)).applied is False

        await run(
            f"IF SUSER_ID('{login}') IS NULL CREATE LOGIN {login} WITH PASSWORD='{password}',"
            " CHECK_POLICY=OFF"
        )
        await run(f"USE [{db}]; CREATE USER {login} FOR LOGIN {login}")
        for role in sorted(SQLSERVER_RUNTIME_DATABASE_ROLES):
            await run(f"USE [{db}]; ALTER ROLE {role} ADD MEMBER {login}")
        runtime = external.model_copy(
            update={"auth": SqlAuth.SQL, "username": login, "password": password}
        )
        store = await SqlServerStore.open(runtime)
        try:
            clean = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.excess == (), f"a row-only runtime login must be silent, got {clean.excess}"

        await run(f"USE [{db}]; ALTER ROLE db_ddladmin ADD MEMBER {login}")
        store = await SqlServerStore.open(runtime)
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert "database role db_ddladmin" in over.excess
    finally:
        for stmt in (
            # USE master first: the setup's USE left this connection inside the scratch database.
            f"USE master; IF DB_ID('{db}') IS NOT NULL BEGIN ALTER DATABASE [{db}] SET SINGLE_USER "
            f"WITH ROLLBACK IMMEDIATE; DROP DATABASE [{db}]; END",
            f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN {login}",
        ):
            with contextlib.suppress(Exception):  # teardown is best-effort
                await (await admin.cursor()).execute(stmt)
        await admin.close()


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_external_refuses_then_provisions_then_runs_row_only() -> None:
    """The Postgres twin, in a schema this test creates and drops. The provisioning principal owns
    every object it creates; the runtime role holds USAGE plus row grants and nothing else."""
    from messagefoundry.store.postgres import PostgresStore

    base = load_settings(environ=os.environ).store
    schema = "mefor_schema_split_test"
    role = "mefor_split_runtime"
    password = _throwaway_password()
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
        store = await PostgresStore.open(runtime)
        try:
            clean = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.excess == (), f"a row-only runtime role must be silent, got {clean.excess}"

        await admin._execute(f"GRANT CREATE ON SCHEMA {schema} TO {role}")
        store = await PostgresStore.open(runtime)
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert f"CREATE on schema {schema}" in over.excess
    finally:
        for stmt in (
            f"DROP SCHEMA IF EXISTS {schema} CASCADE",
            f"REVOKE ALL ON DATABASE {base.database} FROM {role}",
            f"DROP ROLE IF EXISTS {role}",
        ):
            with contextlib.suppress(Exception):  # teardown is best-effort
                await admin._execute(stmt)
        await admin.close()
