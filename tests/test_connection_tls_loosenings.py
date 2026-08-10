# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The two per-connection TLS deviations reaching the surfaces an operator actually reads (#333).

Both were invisible to the loosening registry. ``tls_allow_expired`` appeared in NONE of
``config/settings.py``, ``api/app.py``, ``checks.py`` or ``__main__.py``; the generic-ODBC ``DATABASE``
hop's whole control was a construction log line whose detector was value-blind. Under ADR 0148's "one
posture, loosen only", a deviation the registry cannot see is a second posture by the back door.

``tests/test_security_posture_defaults.py`` owns the registry entries, the shared readers and the
connection-scoped completeness floor. This file owns the two OTHER surfaces: ``messagefoundry check``
and ``GET /security/posture``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.pipeline import Engine

_TOML = """
[store]
backend = "sqlite"

[ai]
environment = "dev"

[security]
handles_real_patient_data = false
"""

#: An outbound holding an expiry bridge open, and a generic-ODBC DATABASE pair — one outbound with no
#: TLS keyword at all, one INBOUND poll pinned to psqlODBC's explicit no-TLS value. Synthetic hosts.
_CONFIG_MODULE = """
from messagefoundry import Database, DatabasePoll, MLLP, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15098), router="r")
inbound(
    "IB_PG_ORDERS",
    DatabasePoll(
        server="orders.example.invalid",
        dialect="generic",
        odbc_driver="PostgreSQL Unicode",
        poll_statement="SELECT id, body FROM queue",
        odbc_params={"SSLmode": "disable"},
    ),
    router="r",
)
outbound(
    "OB_BRIDGE",
    MLLP(host="partner.example.invalid", port=6100, tls=True, tls_allow_expired=True),
)
outbound(
    "OB_PG_RESULTS",
    Database(
        server="results.example.invalid",
        dialect="generic",
        odbc_driver="PostgreSQL Unicode",
        statement="INSERT INTO r (a) VALUES (:a)",
    ),
)


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_BRIDGE", msg)
"""

#: The same graph with every deviation removed — the negative control for each assertion below. An
#: absence claim ships with a live positive control or the check is blind, and the pair IS the control:
#: the same code path, the same fixture shape, one green and one reporting.
_CLEAN_MODULE = """
from messagefoundry import Database, MLLP, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15098), router="r")
outbound("OB_BRIDGE", MLLP(host="partner.example.invalid", port=6100, tls=True))
outbound(
    "OB_PG_RESULTS",
    Database(
        server="results.example.invalid",
        dialect="generic",
        odbc_driver="PostgreSQL Unicode",
        statement="INSERT INTO r (a) VALUES (:a)",
        odbc_params={"SSLmode": "verify-full"},
    ),
)


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_BRIDGE", msg)
"""


def _write_config(tmp_path: Path, *, clean: bool = False) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_CLEAN_MODULE if clean else _CONFIG_MODULE, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    return cfg


def _result(report: object, name: str):  # type: ignore[no-untyped-def]
    return next(r for r in report.results if r.name == name)  # type: ignore[attr-defined]


# --- `messagefoundry check` ---------------------------------------------------------------------


def test_check_surfaces_the_expiry_bridge(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    report = run_checks(_write_config(tmp_path), run_lint=False)
    r = _result(report, "tls-allow-expired")
    assert r.ok and not r.required and not r.skipped
    assert "OB_BRIDGE" in r.detail and "partner.example.invalid:6100" in r.detail
    # Advisory, and honest in both directions: it must not imply verify-off.
    assert "chain, hostname and key usage are still verified" in r.detail


def test_check_surfaces_the_generic_db_hops_in_both_directions(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    report = run_checks(_write_config(tmp_path), run_lint=False)
    r = _result(report, "generic-db-tls")
    assert r.ok and not r.required and not r.skipped
    # The OUTBOUND with no keyword at all, and the INBOUND poll pinned to a no-TLS VALUE. Missing
    # either is the defect: the value case was read as "TLS addressed", and inbound was never walked.
    assert "OB_PG_RESULTS" in r.detail and "no TLS keyword" in r.detail
    assert "inbound:IB_PG_ORDERS" in r.detail and "SSLmode=disable" in r.detail


def test_check_says_none_explicitly_when_there_is_nothing_to_report(tmp_path: Path) -> None:
    """The negative control, and it must SAY "none" rather than go quiet: an absent line is
    indistinguishable from a check that did not run, which is how a green gate stops being evidence."""
    from messagefoundry.checks import run_checks

    report = run_checks(_write_config(tmp_path, clean=True), run_lint=False)
    assert "no connection declares tls_allow_expired" in _result(report, "tls-allow-expired").detail
    assert (
        "no generic-ODBC DATABASE connection leaves TLS unenforced"
        in _result(report, "generic-db-tls").detail
    )


def test_check_skips_rather_than_reporting_clean_on_an_unloadable_config(tmp_path: Path) -> None:
    """Same convention as ``cleartext-accepted``: a check that silently reported an empty set on a
    config it could not read would be worse than one that says it could not look."""
    from messagefoundry.checks import run_checks

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text("this is not python(", encoding="utf-8")
    report = run_checks(cfg, run_lint=False)
    for name in ("tls-allow-expired", "generic-db-tls"):
        r = _result(report, name)
        assert r.skipped and r.ok and "config did not load" in r.detail


# --- GET /security/posture ----------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "posture.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _posture(engine: Engine) -> dict[str, object]:
    import httpx

    from messagefoundry.api import create_app

    app = create_app(engine, allow_no_auth=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200, resp.text
    body: dict[str, object] = resp.json()
    return body


async def test_posture_route_reports_both_connection_deviations(engine: Engine) -> None:
    """The surface an auditor queries. It reads the LIVE graph off the registry runner, so a reload is
    reflected rather than a startup snapshot going stale."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Database,
        Registry,
        build_outbound_connection,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_BRIDGE",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={
                    "host": "partner.example.invalid",
                    "port": 6100,
                    "tls_allow_expired": True,
                },
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PG_RESULTS",
            Database(
                server="results.example.invalid",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement="INSERT INTO r (a) VALUES (:a)",
            ),
        )
    )
    engine.add_registry(reg)
    switches = {e["switch"]: e["risk"] for e in _loosenings(await _posture(engine))}
    assert "OB_BRIDGE" in switches["tls_allow_expired"]
    assert "OB_PG_RESULTS" in switches["generic_odbc_tls_unenforced"]


async def test_posture_route_scope_names_all_three_connection_deviations(engine: Engine) -> None:
    """With no graph the route cannot see ANY per-connection declaration, and the marker must name all
    three. Naming only ``cleartext_accepted`` made the DECLARED scope itself incomplete — the same
    defect one level up from the one this item fixes."""
    scope = str((await _posture(engine))["loosenings_scope"])
    assert "cleartext_accepted" in scope
    assert "tls_allow_expired" in scope
    assert "DATABASE" in scope


def _loosenings(body: dict[str, object]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = body["loosenings"]  # type: ignore[assignment]
    return entries
