# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #1008 (ASVS 13.2.2) — the startup preflight on the store principal's EFFECTIVE privileges.

The defect, in the conditional this repo requires (MessageFoundry is a not-deployed beta, zero
instances): the engine DOCUMENTED a least-privilege store grant it could never observe, so on a first
deployment an over-granted store principal WOULD go unobserved. ``[store].require_managed_identity``
does not close it — it constrains the credential's KIND, and a ``sysadmin`` gMSA satisfies it clean.

Three properties are pinned here, and the third is the one a careless refactor breaks:

1. **It sees an over-grant.** Both pure comparators name every privilege beyond the documented set.
2. **It does not false-alarm.** A correctly-granted principal produces an EMPTY excess list. A control
   that only ever fires is indistinguishable from one that always fires.
3. **"Could not observe" is never "observed and fine".** A probe that raises, a store handle with no
   probe at all, and SQLite's genuine non-applicability each produce a DISTINCT status with its own
   wording — and under a declared ``require_least_privilege`` the unobservable case REFUSES, because a
   declared refusal that passes a principal it could not read is the fail-open shape the setting was
   turned on to prevent.

**The live legs run against real servers** (``MEFOR_TEST_SQLSERVER`` / ``MEFOR_TEST_POSTGRES``) and
carry directions 1 and 2 end to end: they create a purpose-made least-privilege principal, connect AS
it, and assert an empty excess list — then over-grant it and assert the probe names the grant. A local
``pytest`` silently skips both legs, so a green local run proves the policy and the wiring, never the
SQL. CI's own store legs connect as ``sa`` / ``postgres``, which are over-granted by construction, so
the CI leg is itself a standing positive control that the probe fires on a real superuser.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecuritySettings,
    SqlAuth,
    StoreBackend,
    StorePrivilegePosture,
    StorePrivilegeStatus,
    StoreSettings,
    security_loosenings,
)
from messagefoundry.pipeline import Engine
from messagefoundry.store import open_store, sqlite_settings
from messagefoundry.store.privilege import (
    SQLSERVER_DOCUMENTED_DATABASE_ROLES,
    PostgresRoleFacts,
    StorePrivilegeError,
    StorePrivilegeReport,
    postgres_excess,
    run_store_privilege_preflight,
    sqlserver_excess,
)

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))

# The exact grant docs/DEPLOY-SERVER-DB.md §1.1 prescribes, restated here so a change to either side
# has to be a deliberate two-file edit rather than a silent drift in one.
_DOCUMENTED_SQLSERVER = ("db_datareader", "db_datawriter", "db_ddladmin")


# --- direction 2 first: the correctly-granted principal must be SILENT ------------------------


def test_sqlserver_documented_grant_is_not_flagged() -> None:
    """The three prescribed database roles, no server role, no direct CONTROL: nothing to report."""
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=_DOCUMENTED_SQLSERVER,
            control_server=False,
            control_database=False,
            database="MessageFoundry",
        )
        == ()
    )


def test_the_comparator_and_the_runbook_name_the_same_three_roles() -> None:
    """The documented set is a CONSTANT the comparator reads, not a list retyped in two places."""
    assert set(_DOCUMENTED_SQLSERVER) == set(SQLSERVER_DOCUMENTED_DATABASE_ROLES)


def test_sqlserver_deny_roles_are_reported_but_never_called_excess() -> None:
    """``db_deny*`` REMOVES access. Flagging a restriction as an over-grant would train an operator to
    ignore the list, which is the one failure a posture control cannot afford."""
    assert (
        sqlserver_excess(
            server_roles=(),
            database_roles=(*_DOCUMENTED_SQLSERVER, "db_denydatawriter"),
            control_server=False,
            control_database=False,
            database="MessageFoundry",
        )
        == ()
    )


def test_postgres_documented_grant_is_not_flagged() -> None:
    """A plain LOGIN role with no attributes, no extra role membership, owning no database."""
    facts = (PostgresRoleFacts("mefor", True, False, False, False, False, False),)
    assert (
        postgres_excess(
            roles=facts, owns_database=False, create_on_database=False, database="mefor"
        )
        == ()
    )


# --- direction 1: an over-granted principal must be NAMED -------------------------------------


def test_sqlserver_db_owner_is_named() -> None:
    excess = sqlserver_excess(
        server_roles=(),
        database_roles=("db_owner",),
        control_server=False,
        control_database=True,
        database="MessageFoundry",
    )
    assert excess == ("database role db_owner",)


def test_sqlserver_sysadmin_is_named_and_the_implied_permission_is_not_restated() -> None:
    """``sysadmin`` carries ``CONTROL SERVER`` and ``db_owner`` carries database ``CONTROL``. Listing
    the implied permissions too would restate one grant as several and inflate the count an operator
    reads."""
    excess = sqlserver_excess(
        server_roles=("sysadmin",),
        database_roles=("db_owner", *_DOCUMENTED_SQLSERVER),
        control_server=True,
        control_database=True,
        database="MessageFoundry",
    )
    assert excess == ("server role sysadmin", "database role db_owner")


def test_sqlserver_direct_control_grants_are_named_without_a_role() -> None:
    """An over-grant made by ``GRANT CONTROL`` rather than by role membership is still seen — role
    membership alone would miss it entirely."""
    excess = sqlserver_excess(
        server_roles=(),
        database_roles=_DOCUMENTED_SQLSERVER,
        control_server=True,
        control_database=True,
        database="MessageFoundry",
    )
    assert excess == ("CONTROL SERVER", "CONTROL on database MessageFoundry")


def test_sqlserver_user_defined_role_is_named() -> None:
    """The closed fixed-role set cannot name a site's own role; the catalog enumeration adds it."""
    excess = sqlserver_excess(
        server_roles=(),
        database_roles=(*_DOCUMENTED_SQLSERVER, "app_admins"),
        control_server=False,
        control_database=False,
        database="MessageFoundry",
    )
    assert excess == ("database role app_admins",)


def test_postgres_superuser_is_named() -> None:
    facts = (PostgresRoleFacts("postgres", True, True, True, True, True, True),)
    excess = postgres_excess(
        roles=facts, owns_database=True, create_on_database=True, database="mefor"
    )
    assert excess[0] == "SUPERUSER"
    assert "CREATEROLE" in excess


def test_postgres_superuser_does_not_enumerate_every_implied_role() -> None:
    """A superuser is implicitly a member of every predefined role. Listing them would bury the one
    finding that matters under a dozen restatements of it."""
    facts = (
        PostgresRoleFacts("postgres", True, True, False, False, False, False),
        PostgresRoleFacts("pg_read_all_data", False, False, False, False, False, False),
        PostgresRoleFacts("pg_execute_server_program", False, False, False, False, False, False),
    )
    excess = postgres_excess(
        roles=facts, owns_database=True, create_on_database=True, database="mefor"
    )
    assert excess == ("SUPERUSER",)


def test_postgres_superuser_via_an_assumable_wrapper_role_is_caught() -> None:
    """The principal itself has no attributes; a role it may assume is SUPERUSER. A denylist of role
    NAMES cannot see this — reading attributes per assumable role can."""
    facts = (
        PostgresRoleFacts("mefor", True, False, False, False, False, False),
        PostgresRoleFacts("site_dba", False, True, False, False, False, False),
    )
    excess = postgres_excess(
        roles=facts, owns_database=False, create_on_database=False, database="mefor"
    )
    assert excess == ("SUPERUSER",)


def test_postgres_dangerous_predefined_roles_are_named() -> None:
    facts = (
        PostgresRoleFacts("mefor", True, False, False, False, False, False),
        PostgresRoleFacts("pg_write_all_data", False, False, False, False, False, False),
    )
    excess = postgres_excess(
        roles=facts, owns_database=False, create_on_database=False, database="mefor"
    )
    assert excess == ("role pg_write_all_data",)


def test_postgres_database_ownership_is_named_and_suppresses_the_implied_create() -> None:
    facts = (PostgresRoleFacts("mefor", True, False, False, False, False, False),)
    assert postgres_excess(
        roles=facts, owns_database=True, create_on_database=True, database="mefor"
    ) == ("OWNER of database mefor",)
    assert postgres_excess(
        roles=facts, owns_database=False, create_on_database=True, database="mefor"
    ) == ("CREATE on database mefor",)


# --- direction 3: the three non-observations must read differently ----------------------------


class _FakeStore:
    """A store handle exposing only what the preflight touches: a backend, a probe and an audit sink."""

    def __init__(self, report: StorePrivilegeReport | None, *, raises: Exception | None = None):
        self.backend = StoreBackend.SQLSERVER
        self._report = report
        self._raises = raises
        self.audits: list[tuple[str, str | None]] = []

    async def probe_principal_privileges(self) -> StorePrivilegeReport:
        if self._raises is not None:
            raise self._raises
        assert self._report is not None
        return self._report

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
        self.audits.append((action, detail))


class _ProbelessStore:
    """A store handle that implements NO privilege probe — structurally outside the protocol."""

    def __init__(self) -> None:
        self.backend = StoreBackend.POSTGRES
        self.audits: list[tuple[str, str | None]] = []

    async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
        self.audits.append((action, detail))


def _clean(excess: tuple[str, ...] = ()) -> StorePrivilegeReport:
    return StorePrivilegeReport(
        backend=StoreBackend.SQLSERVER,
        status=StorePrivilegeStatus.OBSERVED,
        principal="CORP\\mefor-svc$",
        database="MessageFoundry",
        database_roles=_DOCUMENTED_SQLSERVER,
        excess=excess,
    )


async def test_a_probe_that_raises_is_unobservable_not_clean() -> None:
    store = _FakeStore(None, raises=RuntimeError("permission denied on sys.database_principals"))
    report = await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=True,
    )
    assert report.status is StorePrivilegeStatus.UNOBSERVABLE
    assert report.excess == ()
    # The wording, not just the enum: this string is what an operator actually reads.
    assert "COULD NOT OBSERVE" in report.summary()
    assert "UNVERIFIED" in report.summary()


async def test_a_store_with_no_probe_is_unobservable_not_skipped() -> None:
    """An unimplemented probe is a thing the engine could not observe. Narrowing it away silently
    would make a whole backend invisible to this control while every output still read clean."""
    store = _ProbelessStore()
    report = await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=True,
    )
    assert report.status is StorePrivilegeStatus.UNOBSERVABLE
    assert "implements no privilege probe" in report.detail


async def test_the_probe_secret_redacts_the_driver_message() -> None:
    """A driver diagnostic can echo connection parameters, and this text lands in a durable audit row."""
    store = _FakeStore(
        None, raises=RuntimeError("login failed; MEFOR_STORE_PASSWORD=hunter2swordfish")
    )
    report = await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=False,
    )
    assert "hunter2swordfish" not in report.detail
    assert "hunter2swordfish" not in json.dumps(report.audit_detail())


async def test_sqlite_is_not_applicable_and_says_what_it_did(tmp_path: Path) -> None:
    """SQLite must not report OBSERVED-clean: that is a clean bill of health for a check that never
    happened. It reports its own status and names the control that DOES govern access here."""
    store = await open_store(sqlite_settings(tmp_path / "p.db"))
    try:
        report = await run_store_privilege_preflight(
            store, require_least_privilege=True, enforcing=True
        )
    finally:
        await store.close()
    assert report.status is StorePrivilegeStatus.NOT_APPLICABLE
    assert "filesystem ACL" in report.detail
    assert "NOT APPLICABLE" in report.summary()


async def test_sqlite_never_refuses_even_under_a_declared_requirement(tmp_path: Path) -> None:
    """There is genuinely no principal to over-grant, so refusing would block every single-node
    install for a condition that cannot exist. Pinned so a later 'fail closed everywhere' edit reds."""
    store = await open_store(sqlite_settings(tmp_path / "p2.db"))
    try:
        await run_store_privilege_preflight(store, require_least_privilege=True, enforcing=True)
    finally:
        await store.close()


# --- the WARN arm ships ON; only the REFUSE arm is gated --------------------------------------


async def test_an_over_grant_warns_loudly_on_the_shipped_defaults(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The shipped default must not be silent: default-off warning would leave the exact blind spot
    this item exists to close."""
    store = _FakeStore(_clean(excess=("server role sysadmin",)))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.privilege"):
        report = await run_store_privilege_preflight(
            store,  # type: ignore[arg-type]
            require_least_privilege=False,
            enforcing=True,
        )
    assert report.excess == ("server role sysadmin",)
    assert any("BEYOND the documented least-privilege grant" in r.message for r in caplog.records)


async def test_a_clean_observation_is_not_a_warning(caplog: pytest.LogCaptureFixture) -> None:
    """The complementary arm — a control that warns on a correct grant becomes noise and stops being
    read, which is indistinguishable from not shipping it."""
    store = _FakeStore(_clean())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.store.privilege"):
        await run_store_privilege_preflight(
            store,  # type: ignore[arg-type]
            require_least_privilege=True,
            enforcing=True,
        )
    assert [r for r in caplog.records if r.levelno >= logging.WARNING] == []


async def test_an_over_grant_does_not_refuse_on_the_shipped_defaults() -> None:
    """Refusal is gated BY DESIGN: a preflight that refused by default could block a legitimate
    deployment mid-setup, which is not this control's job."""
    store = _FakeStore(_clean(excess=("database role db_owner",)))
    await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=True,
    )


async def test_an_over_grant_refuses_under_a_declared_requirement() -> None:
    store = _FakeStore(_clean(excess=("database role db_owner",)))
    with pytest.raises(StorePrivilegeError, match="db_owner"):
        await run_store_privilege_preflight(
            store,  # type: ignore[arg-type]
            require_least_privilege=True,
            enforcing=True,
        )


async def test_the_declared_refusal_downgrades_under_enforcement_warn() -> None:
    """The split reads [security].enforcement, exactly like the require_managed_identity gate it copies."""
    store = _FakeStore(_clean(excess=("database role db_owner",)))
    report = await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=True,
        enforcing=False,
    )
    assert report.excess == ("database role db_owner",)


async def test_an_unobservable_probe_refuses_under_a_declared_requirement() -> None:
    """THE fail-open test. An operator who declared require_least_privilege asked for a control; one
    that passes a principal it could not read is not a control, it is a log line pretending to be one."""
    store = _FakeStore(None, raises=RuntimeError("permission denied"))
    with pytest.raises(StorePrivilegeError, match="COULD NOT OBSERVE"):
        await run_store_privilege_preflight(
            store,  # type: ignore[arg-type]
            require_least_privilege=True,
            enforcing=True,
        )


# --- the durable record -----------------------------------------------------------------------


async def test_an_observation_writes_an_audit_row_carrying_the_status() -> None:
    store = _FakeStore(_clean(excess=("server role sysadmin",)))
    await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=True,
    )
    assert len(store.audits) == 1
    action, detail = store.audits[0]
    assert action == "store_privilege_preflight"
    assert detail is not None
    payload = json.loads(detail)
    assert payload["status"] == "observed"
    assert payload["excess"] == ["server role sysadmin"]
    assert payload["refused"] is False


async def test_an_unobservable_probe_also_writes_the_row() -> None:
    """A missing row would make the loudest condition the least durable one."""
    store = _FakeStore(None, raises=RuntimeError("permission denied"))
    await run_store_privilege_preflight(
        store,  # type: ignore[arg-type]
        require_least_privilege=False,
        enforcing=True,
    )
    assert json.loads(store.audits[0][1] or "{}")["status"] == "unobservable"


async def test_an_audit_failure_never_masks_the_refusal() -> None:
    """Auditing is best-effort; the finding is not."""

    class _AuditFails(_FakeStore):
        async def record_audit(self, action: str, *, actor: str | None, detail: str | None) -> None:
            raise RuntimeError("audit table unavailable")

    store = _AuditFails(_clean(excess=("database role db_owner",)))
    with pytest.raises(StorePrivilegeError):
        await run_store_privilege_preflight(
            store,  # type: ignore[arg-type]
            require_least_privilege=True,
            enforcing=True,
        )


# --- the posture registry ---------------------------------------------------------------------


def _names(store_privilege: StorePrivilegePosture | None) -> dict[str, str]:
    return dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            (),
            (),
            (),
            store_privilege,
        )
    )


def test_registry_names_an_over_granted_principal() -> None:
    named = _names(
        StorePrivilegePosture(
            status=StorePrivilegeStatus.OBSERVED, excess=("server role sysadmin",)
        )
    )
    assert "store_principal_over_granted" in named
    # The names, individually — a count would say "1 grant is excessive" without saying which, which
    # is the shape that lets a grant nobody intended survive a posture review.
    assert "server role sysadmin" in named["store_principal_over_granted"]


def test_registry_names_an_unobservable_probe_separately() -> None:
    """Two entries, not one: an over-grant and an un-run probe demand different operator actions."""
    named = _names(
        StorePrivilegePosture(status=StorePrivilegeStatus.UNOBSERVABLE, detail="permission denied")
    )
    assert "store_principal_privileges_unobserved" in named
    assert "store_principal_over_granted" not in named
    assert "UNVERIFIED" in named["store_principal_privileges_unobserved"]


def test_registry_is_silent_on_a_clean_observation() -> None:
    assert _names(StorePrivilegePosture(status=StorePrivilegeStatus.OBSERVED)) == {}


def test_registry_is_silent_on_sqlite() -> None:
    assert _names(StorePrivilegePosture(status=StorePrivilegeStatus.NOT_APPLICABLE)) == {}


def test_registry_is_silent_when_no_probe_result_reached_it() -> None:
    """`None` is "this call site has no probe result", and the CALLER declares that gap in its own
    output (`security show`'s loosenings_scope, the posture route's `store_privilege` field). Rendering
    it as an entry here would fire a finding on every graphless read."""
    assert _names(None) == {}


def test_the_refusal_switch_is_a_hardening_and_is_not_itself_a_loosening() -> None:
    """``require_least_privilege`` at its non-default value TIGHTENS, so it must not appear — the
    registry reports switches at their INSECURE value, and reporting a hardening would invert it. It
    is exempted in tests/test_security_posture_defaults.py's [store] floor for exactly this reason."""
    assert (
        dict(
            security_loosenings(
                SecuritySettings(),
                StoreSettings(require_least_privilege=True),
                AuthSettings(),
                AlertsSettings(),
                (),
                (),
                (),
                None,
            )
        )
        == {}
    )


# --- the API read-out -------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "priv.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _posture(engine: Engine, **state: object) -> dict[str, Any]:
    app = create_app(engine, allow_no_auth=True)
    for key, value in state.items():
        setattr(app.state, key, value)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    body: dict[str, Any] = resp.json()
    return body


async def test_posture_route_says_not_probed_when_no_preflight_ran(engine: Engine) -> None:
    """An app built without the managed lifespan never ran the probe. It must SAY so rather than omit
    the field or render an empty/clean-looking value — silence here is the fail-open shape."""
    body = await _posture(engine)
    assert body["store_privilege"]["status"] == "not_probed"


async def test_posture_route_reports_an_observed_over_grant(engine: Engine) -> None:
    body = await _posture(
        engine,
        store_privilege=StorePrivilegePosture(
            status=StorePrivilegeStatus.OBSERVED, excess=("server role sysadmin",)
        ),
    )
    assert body["store_privilege"]["status"] == "observed"
    assert body["store_privilege"]["excess"] == ["server role sysadmin"]
    switches = [entry["switch"] for entry in body["loosenings"]]
    assert "store_principal_over_granted" in switches


async def test_posture_route_reports_an_unobservable_probe(engine: Engine) -> None:
    body = await _posture(
        engine,
        store_privilege=StorePrivilegePosture(
            status=StorePrivilegeStatus.UNOBSERVABLE, detail="permission denied"
        ),
    )
    assert body["store_privilege"]["status"] == "unobservable"
    switches = [entry["switch"] for entry in body["loosenings"]]
    assert "store_principal_privileges_unobserved" in switches


async def test_posture_route_distinguishes_clean_from_unobserved(engine: Engine) -> None:
    """The property the whole design turns on, asserted at the surface an operator reads."""
    clean = await _posture(
        engine, store_privilege=StorePrivilegePosture(status=StorePrivilegeStatus.OBSERVED)
    )
    blind = await _posture(
        engine,
        store_privilege=StorePrivilegePosture(
            status=StorePrivilegeStatus.UNOBSERVABLE, detail="permission denied"
        ),
    )
    assert clean["store_privilege"]["status"] != blind["store_privilege"]["status"]
    assert clean["loosenings"] != blind["loosenings"]


def test_serve_lifespan_runs_the_preflight_and_stashes_a_real_observation(tmp_path: Path) -> None:
    """The wiring, not the policy: a managed app must reach the route with the probe's OWN result, or
    the field sits at `not_probed` forever and the whole preflight is invisible in the console.

    ``TestClient`` as a context manager is what drives the lifespan (the same idiom the rest of the
    suite uses), and the lifespan is where the preflight runs."""
    from starlette.testclient import TestClient

    from messagefoundry.api.app import create_managed_app

    app = create_managed_app(store_settings=sqlite_settings(tmp_path / "managed.db"))
    with TestClient(app) as tc:
        resp = tc.get("/security/posture")
    assert resp.status_code == 200
    # SQLite: NOT_APPLICABLE — the real probe result, provably not the `not_probed` default.
    assert resp.json()["store_privilege"]["status"] == "not_applicable"


# --- live server legs (skipped locally; CI's store legs are the standing coverage) -------------


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_probe_observes_the_configured_principal() -> None:
    """The probe runs against a real SQL Server and OBSERVES — never UNOBSERVABLE on a working store."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    try:
        report = await store.probe_principal_privileges()
    finally:
        await store.close()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.principal, "the probe must name the login it observed"
    assert report.database


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_probe_sees_both_directions_on_a_purpose_made_principal() -> None:
    """Create a least-privilege login, connect AS it, assert an EMPTY excess list — then add
    ``db_owner`` and assert the probe names it. Both directions against a real server, or neither.

    Skips (never fails) when the configured principal cannot create logins: the assertion is about the
    probe, and a store credential without ``ALTER ANY LOGIN`` cannot set the fixture up. CI connects as
    ``sa``, so the leg that matters always runs it."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    base = load_settings(environ=os.environ).store
    login = "mefor_privprobe_test"
    password = "Pr0be_Synth_2026!x"  # synthetic, throwaway, dropped below — never a real credential
    admin = await SqlServerStore.open(base)
    try:
        try:
            await admin._execute(
                f"IF SUSER_ID('{login}') IS NULL CREATE LOGIN {login} WITH PASSWORD='{password}',"
                " CHECK_POLICY=OFF"
            )
            await admin._execute(
                f"IF USER_ID('{login}') IS NULL CREATE USER {login} FOR LOGIN {login}"
            )
            for role in _DOCUMENTED_SQLSERVER:
                await admin._execute(f"ALTER ROLE {role} ADD MEMBER {login}")
        except Exception as exc:  # noqa: BLE001 — a fixture-setup limit, not a probe failure
            pytest.skip(f"cannot create a test login with this store principal: {exc}")

        least = base.model_copy(
            update={"auth": SqlAuth.SQL, "username": login, "password": password}
        )
        store = await SqlServerStore.open(least)
        try:
            clean = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.excess == (), f"a correctly-granted login must be silent, got {clean.excess}"
        assert set(_DOCUMENTED_SQLSERVER) <= set(clean.database_roles)

        await admin._execute(f"ALTER ROLE db_owner ADD MEMBER {login}")
        store = await SqlServerStore.open(least)
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert "database role db_owner" in over.excess
    finally:
        for stmt in (
            f"IF USER_ID('{login}') IS NOT NULL DROP USER {login}",
            f"IF SUSER_ID('{login}') IS NOT NULL DROP LOGIN {login}",
        ):
            with contextlib.suppress(Exception):  # teardown is best-effort
                await admin._execute(stmt)
        await admin.close()


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_probe_observes_the_configured_principal() -> None:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    store = await PostgresStore.open(load_settings(environ=os.environ).store)
    try:
        report = await store.probe_principal_privileges()
    finally:
        await store.close()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.principal
    assert report.database


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_probe_sees_both_directions_on_a_purpose_made_role() -> None:
    """The Postgres twin: a plain LOGIN role must be silent, and one granted ``pg_read_all_data`` must
    be named. Skips (never fails) when the configured role cannot CREATE ROLE."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    base = load_settings(environ=os.environ).store
    role = "mefor_privprobe_test"
    password = "Pr0be_Synth_2026!x"  # synthetic, throwaway, dropped below
    admin = await PostgresStore.open(base)
    try:
        schema = base.db_schema or "public"
        try:
            await admin._execute(f"DROP ROLE IF EXISTS {role}")
            await admin._execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
            # docs/DEPLOY-SERVER-DB.md §1.2 posture B (pre-created objects, engine role holds CRUD):
            # CONNECT + USAGE + row CRUD + sequence USAGE, and nothing wider. The role must be able to
            # OPEN the store, or the negative direction would skip for the wrong reason.
            for stmt in (
                f"GRANT CONNECT ON DATABASE {base.database} TO {role}",
                f"GRANT USAGE ON SCHEMA {schema} TO {role}",
                f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema} TO {role}",
                f"GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA {schema} TO {role}",
            ):
                await admin._execute(stmt)
        except Exception as exc:  # noqa: BLE001 — a fixture-setup limit, not a probe failure
            pytest.skip(f"cannot create a test role with this store principal: {exc}")

        least = base.model_copy(update={"username": role, "password": password})
        store = await PostgresStore.open(least)
        try:
            clean = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.excess == (), f"a correctly-granted role must be silent, got {clean.excess}"

        await admin._execute(f"GRANT pg_read_all_data TO {role}")
        store = await PostgresStore.open(least)
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert "role pg_read_all_data" in over.excess
    finally:
        for stmt in (
            f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA {base.db_schema or 'public'} FROM {role}",
            f"REVOKE ALL ON ALL TABLES IN SCHEMA {base.db_schema or 'public'} FROM {role}",
            f"REVOKE ALL ON SCHEMA {base.db_schema or 'public'} FROM {role}",
            f"REVOKE ALL ON DATABASE {base.database} FROM {role}",
            f"DROP ROLE IF EXISTS {role}",
        ):
            with contextlib.suppress(Exception):  # teardown is best-effort
                await admin._execute(stmt)
        await admin.close()
