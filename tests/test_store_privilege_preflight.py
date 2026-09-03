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
SQL.

Those legs connect as ``sa`` / ``postgres``, which are over-granted by construction, so each is also a
standing POSITIVE control that the probe still fires on a real superuser — but that is only true while
a workflow step actually runs this file, and per-test ``skipif`` gating puts it outside the scope
``tests/test_serverdb_ci_coverage.py`` polices. So the wiring is asserted here, by
``test_the_live_legs_of_this_file_are_run_by_a_server_db_ci_step``, which was failed on purpose
against the unedited workflow before it was trusted.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import re
import secrets
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

#: This file's own path as a ci.yml step spells it — read by the wiring guards further down.
_THIS_FILE = "tests/test_store_privilege_preflight.py"

# The exact grant docs/DEPLOY-SERVER-DB.md §1.1 prescribes, restated here so a change to either side
# has to be a deliberate two-file edit rather than a silent drift in one.
_DOCUMENTED_SQLSERVER = ("db_datareader", "db_datawriter", "db_ddladmin")


def _throwaway_password() -> str:
    """A per-run password for the purpose-made live-leg principal, GENERATED rather than written down.

    Not a literal, on purpose. A hardcoded one would be a credential-shaped string in a public repo —
    it would need a `.gitleaks.toml` allowlist entry, and every allowlist entry is a rule the scanner
    stops applying. `token_urlsafe` is `[A-Za-z0-9_-]` only, so it never needs quoting inside the
    fixture's SQL string literals, and the prefix keeps it complex enough for a password policy."""
    return "Px9_" + secrets.token_urlsafe(24)


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
    NAMES cannot see this — reading attributes per assumable role can.

    The wrapper is NAMED, because that role is the object an operator has to change; ``SUPERUSER``
    alone would send them looking at a principal whose own attributes are all clean."""
    facts = (
        PostgresRoleFacts("mefor", True, False, False, False, False, False),
        PostgresRoleFacts("site_dba", False, True, False, False, False, False),
    )
    excess = postgres_excess(
        roles=facts, owns_database=False, create_on_database=False, database="mefor"
    )
    assert excess == ("SUPERUSER via role site_dba",)


def test_postgres_createrole_via_an_assumable_wrapper_role_is_caught() -> None:
    """Every role ATTRIBUTE is reachable through membership, not only ``SUPERUSER`` — so every one of
    them is read across the assumable roles, not just on the principal's own row.

    Measured on PostgreSQL 16.14 rather than assumed: a member of a ``CREATEROLE`` role is refused
    ``CREATE ROLE`` outright (attributes are never inherited) and succeeds immediately after
    ``SET ROLE`` to it. ``pg_has_role(current_user, oid, 'MEMBER')`` — the predicate the probe reads
    with — is exactly "may SET ROLE to it", so a reachable attribute is a held one. Checking these four
    on the principal's own row alone let a wrapper carrying ``CREATEROLE`` / ``CREATEDB`` /
    ``REPLICATION`` / ``BYPASSRLS`` read as a clean least-privilege role."""
    facts = (
        PostgresRoleFacts("mefor", True, False, False, False, False, False),
        PostgresRoleFacts("site_ops", False, False, True, True, False, False),
    )
    excess = postgres_excess(
        roles=facts, owns_database=False, create_on_database=False, database="mefor"
    )
    assert excess == ("CREATEROLE via role site_ops", "CREATEDB via role site_ops")


def test_postgres_membership_in_a_plain_role_is_not_an_attribute_finding() -> None:
    """The complementary arm of the test above: reading attributes across every assumable role must
    not turn mere MEMBERSHIP into an attribute finding. A wrapper that carries no attribute and is not
    a predefined ``pg_*`` role is silent — otherwise every site that groups grants behind a role would
    get a permanent finding it cannot act on."""
    facts = (
        PostgresRoleFacts("mefor", True, False, False, False, False, False),
        PostgresRoleFacts("app_readers", False, False, False, False, False, False),
    )
    assert (
        postgres_excess(
            roles=facts, owns_database=False, create_on_database=False, database="mefor"
        )
        == ()
    )


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


def test_the_preflight_reads_the_PASSED_store_settings_not_the_ambient_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A green that depends on the ambient environment is not a green.

    Every non-live test in this file asserts against a SQLite store it constructs explicitly, which is
    only meaningful if a hostile ``MEFOR_STORE_*`` in the environment cannot reach in and change which
    backend is probed. This runs the whole managed lifespan with the environment set to a SQL Server
    the box cannot reach and ``require_least_privilege`` declared, and still expects the SQLite
    ``not_applicable`` result — an ambient leak would instead try to open ``db.invalid`` and fail, or
    refuse on an unobservable probe.

    **The second half is what stops this being vacuous.** It asserts the same environment WOULD have
    produced a SQL Server store through ``load_settings``, so the hostile values are demonstrably ones
    the code reads. A hostile-ambient test built on a variable nothing consults proves nothing, and
    that is the shape it is guarding against."""
    from messagefoundry.api.app import create_managed_app
    from messagefoundry.config.settings import load_settings

    hostile = {
        "MEFOR_STORE_BACKEND": "sqlserver",
        "MEFOR_STORE_SERVER": "db.invalid",
        "MEFOR_STORE_DATABASE": "Hostile",
        "MEFOR_STORE_USERNAME": "hostile",
        "MEFOR_STORE_PASSWORD": "unused-by-this-test",
        "MEFOR_STORE_REQUIRE_LEAST_PRIVILEGE": "true",
    }
    # The pin is load-bearing: these exact keys resolve to a SQL Server store with the refusal armed.
    would_be = load_settings(environ=hostile).store
    assert would_be.backend is StoreBackend.SQLSERVER
    assert would_be.require_least_privilege is True

    from starlette.testclient import TestClient

    for key, value in hostile.items():
        monkeypatch.setenv(key, value)
    app = create_managed_app(store_settings=sqlite_settings(tmp_path / "pinned.db"))
    with TestClient(app) as tc:
        resp = tc.get("/security/posture")
    assert resp.status_code == 200
    assert resp.json()["store_privilege"]["status"] == "not_applicable"


# --- the live legs must actually be RUN somewhere, or they are decoration ----------------------


def _ci_yml() -> str:
    return (Path(__file__).resolve().parents[1] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )


def _steps_running_this_file(gate: str) -> list[str]:
    """ci.yml step names that EXPORT ``gate`` and whose executable lines run this test file.

    Comment lines are stripped first, for the reason ``tests/test_serverdb_ci_coverage.py`` states:
    a step's prose may name a file it does not run."""
    out: list[str] = []
    for block in re.split(r"\n      - name:", _ci_yml()):
        if f"{gate}: " not in block:
            continue
        executable = "\n".join(
            line for line in block.splitlines() if not line.lstrip().startswith("#")
        )
        if _THIS_FILE in executable:
            out.append(block.splitlines()[0].strip())
    return out


@pytest.mark.parametrize("gate", ["MEFOR_TEST_SQLSERVER", "MEFOR_TEST_POSTGRES"])
def test_the_live_legs_of_this_file_are_run_by_a_server_db_ci_step(gate: str) -> None:
    """The live probe SQL executes NOWHERE unless a ci.yml step under ``gate`` names this file.

    ``tests/test_serverdb_ci_coverage.py`` does not cover this file and says so: it asserts the sharp
    MODULE-gated invariant only, and this file gates its live legs PER TEST so its SQLite cases still
    run. That leaves the exact hole it was built to close, one class over — the file collects on every
    plain leg, its live legs report `skipped`, and `skipped` reads identical to `passed` at a glance.
    Since the probe's SQL is the one thing no local run and no SQLite leg can exercise, a file nobody
    wires means the statements in ``store/sqlserver.py`` and ``store/postgres.py`` are never once
    executed.

    Falsified on purpose before it was trusted: with ci.yml unedited this parametrization failed for
    BOTH gates, naming the file it scanned for. Scope is deliberately this one file — a general
    version needs an allow-list, which is what keeps the sibling guard sharp."""
    steps = _steps_running_this_file(gate)
    assert steps, (
        f"no ci.yml step exporting {gate} runs {_THIS_FILE}, so its live legs execute nowhere — "
        f"scanned {len(_ci_yml().splitlines())} lines of .github/workflows/ci.yml. Add the file to "
        "the sqlserver-store / postgres-store job and extend the `serverdb` change-detection "
        "alternation so editing it pulls the leg that proves it."
    )


def test_editing_this_file_pulls_the_server_db_legs_that_prove_it() -> None:
    """A file a leg runs but the change-detection alternation does not match is covered only by the
    nightly cron — editing it does not pull the leg. Same invariant
    ``test_serverdb_path_gate_admits_every_file_those_legs_run`` enforces, asserted here because that
    test derives its file set from module-gated suites and never sees this one."""
    for line in _ci_yml().splitlines():
        if "grep -qE" in line and "tests/test_(" in line:
            match = re.search(r"tests/test_\(([^)]*)\)", line)
            assert match is not None
            alternation = re.compile(rf"^test_({match.group(1)})")
            assert alternation.match(Path(_THIS_FILE).stem), (
                f"the `serverdb` alternation does not match {_THIS_FILE}; it reads: "
                f"tests/test_({match.group(1)})"
            )
            return
    pytest.fail("could not locate the `serverdb` change-detection alternation in ci.yml")


# --- live server legs (skipped locally; CI's store legs are the standing coverage) -------------


@pytest.mark.skipif(not _SQLSERVER_ON, reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env)")
async def test_live_sqlserver_probe_observes_the_configured_principal() -> None:
    """The probe runs against a real SQL Server and OBSERVES — never UNOBSERVABLE on a working store."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store
    store = await SqlServerStore.open(settings)
    try:
        report = await store.probe_principal_privileges()
    finally:
        await store.close()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.principal, "the probe must name the login it observed"
    assert report.database
    # THE STANDING POSITIVE CONTROL, and the reason this leg is worth its runtime. CI connects as
    # `sa`, which is `sysadmin` by construction, so a probe that has quietly stopped SEEING an
    # over-grant — a mis-bound parameter, a renamed column, a driver returning True/False where the
    # comparison expects 1 — reds here instead of reporting a clean bill of health for a superuser.
    # Gated on the CONFIGURED login name, which comes from the environment and not from the probe, so
    # a site pointing this leg at a correctly least-privileged login is not failed for being correct.
    if (settings.username or "").lower() == "sa":
        assert "server role sysadmin" in report.excess, (
            "this leg is configured as `sa`, a sysadmin login, so the probe MUST name it; a clean "
            f"result here means the probe is not observing what it claims to (server roles: "
            f"{report.server_roles})"
        )


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
    password = _throwaway_password()
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

    settings = load_settings(environ=os.environ).store
    store = await PostgresStore.open(settings)
    try:
        report = await store.probe_principal_privileges()
    finally:
        await store.close()
    assert report.status is StorePrivilegeStatus.OBSERVED
    assert report.principal
    assert report.database
    # The Postgres half of the standing POSITIVE control (see the SQL Server twin). This leg is
    # configured as `postgres`, a SUPERUSER that also owns the database, so the probe must say so;
    # gated on the configured role name, which comes from the environment and not from the probe.
    if (settings.username or "").lower() == "postgres":
        assert "SUPERUSER" in report.excess, (
            "this leg is configured as the `postgres` superuser, so the probe MUST name it; a clean "
            f"result means it is not observing what it claims to (roles read: {report.database_roles})"
        )


@pytest.mark.skipif(not _POSTGRES_ON, reason="set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env)")
async def test_live_postgres_probe_sees_both_directions_on_a_purpose_made_role() -> None:
    """The Postgres twin, and the one leg that carries BOTH directions end to end: a correctly-granted
    role must be SILENT, and the same role granted ``pg_read_all_data`` must be NAMED.

    The fixture builds ``docs/DEPLOY-SERVER-DB.md`` §1.2 **posture A** — the engine role owns its own
    schema — and that choice is a measurement, not a preference. Posture B (``USAGE`` on a pre-created
    schema, no ``CREATE``) cannot open the store on a database whose ``schema_meta`` marker is absent
    or stale: measured on PostgreSQL 16.14, ``CREATE TABLE IF NOT EXISTS`` on an ALREADY-EXISTING table
    is refused with *permission denied for schema* — the schema ACL is checked BEFORE the existence
    skip, so ``IF NOT EXISTS`` does not save it. A posture-B fixture would therefore have failed inside
    ``PostgresStore.open`` and reported as a probe defect. Posture A is self-contained: the role
    bootstraps its own schema, so this leg does not depend on any earlier CI step having seeded one.

    Schema ownership is deliberately NOT something ``postgres_excess`` looks at — it is the documented
    posture, so an empty excess list here is the assertion that matters.

    Skips (never fails) when the configured role cannot CREATE ROLE: that is a limit of the fixture's
    credential, not a fact about the probe."""
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.postgres import PostgresStore

    base = load_settings(environ=os.environ).store
    role = "mefor_privprobe_test"
    schema = "mefor_privprobe_test"
    password = _throwaway_password()
    admin = await PostgresStore.open(base)
    try:
        try:
            await admin._execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
            await admin._execute(f"DROP ROLE IF EXISTS {role}")
            await admin._execute(f"CREATE ROLE {role} LOGIN PASSWORD '{password}'")
            await admin._execute(f"GRANT CONNECT ON DATABASE {base.database} TO {role}")
            # Posture A, and NOTHING wider: no role attribute, no predefined pg_* membership, no
            # database ownership. `CREATE SCHEMA ... AUTHORIZATION` is the runbook's own statement.
            await admin._execute(f"CREATE SCHEMA {schema} AUTHORIZATION {role}")
        except Exception as exc:  # noqa: BLE001 — a fixture-setup limit, not a probe failure
            pytest.skip(f"cannot create a test role with this store principal: {exc}")

        least = base.model_copy(
            update={"username": role, "password": password, "db_schema": schema}
        )
        store = await PostgresStore.open(least)
        try:
            clean = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert clean.status is StorePrivilegeStatus.OBSERVED
        assert clean.principal == role
        assert clean.excess == (), f"a correctly-granted role must be silent, got {clean.excess}"

        await admin._execute(f"GRANT pg_read_all_data TO {role}")
        store = await PostgresStore.open(least)
        try:
            over = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert "role pg_read_all_data" in over.excess

        # The attribute arm, on the SAME role: an attribute carried by a role the principal may merely
        # assume is reachable via SET ROLE, so the probe must name it AND name the wrapper. This is the
        # direction that read clean before the comparator was corrected.
        await admin._execute(f"CREATE ROLE {role}_wrap CREATEROLE NOLOGIN")
        await admin._execute(f"GRANT {role}_wrap TO {role}")
        store = await PostgresStore.open(least)
        try:
            wrapped = await store.probe_principal_privileges()
        finally:
            await store.close()
        assert f"CREATEROLE via role {role}_wrap" in wrapped.excess
    finally:
        for stmt in (
            f"DROP SCHEMA IF EXISTS {schema} CASCADE",
            f"REVOKE ALL ON DATABASE {base.database} FROM {role}",
            f"DROP ROLE IF EXISTS {role}",
            f"DROP ROLE IF EXISTS {role}_wrap",
        ):
            with contextlib.suppress(Exception):  # teardown is best-effort
                await admin._execute(stmt)
        await admin.close()
