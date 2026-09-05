# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The static-credential DATABASE hop inventory (BACKLOG #1182, ASVS 13.2.1).

ASVS 13.2.1 asks that backend component communications use individual service accounts, short-term
tokens or certificates rather than unchanging credentials. The engine's one control on that verb is
``[store].require_managed_identity``, which is a ``StoreSettings`` method and therefore reaches the
store hop and nothing else. On a first deployment a site could run four database hops on static SQL
logins with nothing naming them.

Two discriminators carry this suite, and the plumbing is the least of it.

**The table census.** There are FOUR database-hop factories and #1182 named two. A reader that walked
``outbound`` and ``lookups`` alone would look correct on the common graph while silently omitting a
``DatabasePoll`` inbound and a ``DatabaseRef`` reference source, both of which dial a real database
with a real credential. Each table therefore gets its own assertion.

**The generic-ODBC rule.** ``_build_odbc_dsn`` never reads ``auth`` — it emits the top-level
``username``/``password`` under the operator's own keywords. So ``auth='integrated'`` written on a
``dialect='generic'`` connection produces a static login, and a reader that classified on ``auth``
alone would report the engine's most misleading configuration as compliant. That case is pinned in
both directions.

Its silences carry the same weight as its findings: the delegated kinds stay quiet, and so does the
one generic case the reader deliberately cannot classify.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.wiring import load_config, static_credential_db_hops

_TOML = """
[store]
backend = "sqlite"

[ai]
environment = "dev"

[security]
handles_real_patient_data = false
"""

#: One graph carrying every shape the reader has an opinion about and every shape it must stay quiet
#: on. Synthetic hosts; nothing here builds a connector, so no driver or server is needed --
#: ``load_config`` runs the module body and the reader walks the resulting graph.
_CONFIG_MODULE = """
from messagefoundry import (
    Database,
    DatabaseLookup,
    DatabasePoll,
    DatabaseRef,
    MLLP,
    Reference,
    Send,
    handler,
    inbound,
    outbound,
    router,
)

inbound("IB", MLLP(port=15098), router="r")

# --- FIRES, one per table. The ledger named two of these four. ---------------------------------

# outbound: the shipped default. auth= is not even written, and "sql" is what it resolves to.
outbound(
    "OB_SQL",
    Database(server="db1.example.invalid", database="Feeds", statement="INSERT INTO t VALUES (:b)"),
)
# inbound: a DatabasePoll crosses the same hop with the same credential in the same DSN.
inbound(
    "IB_POLL",
    DatabasePoll(
        server="db2.example.invalid",
        database="Inbox",
        poll_statement="SELECT id, body FROM q WHERE status='NEW'",
        body_column="body",
        username="poller",
        password="static",
    ),
    router="r",
)
# lookups: the ADR 0010 db_lookup read pool, which require_managed_identity has never reached.
DatabaseLookup(
    "clarity",
    server="db3.example.invalid",
    database="Clarity",
    username="ro",
    password="static",
)
# references: a DatabaseRef source, dialled on the reference set's own refresh cadence.
Reference(
    "providers",
    source=DatabaseRef(
        server="db4.example.invalid",
        database="Ref",
        statement="SELECT npi, name FROM providers",
        key_column="npi",
        value_column="name",
        username="ref",
        password="static",
    ),
)
# FIRES, and it carries auth='integrated'. THE DISCRIMINATOR: the generic arm never reads auth, so
# this hop emits UID/PWD. A reader keyed on auth alone would call this compliant.
outbound(
    "OB_GENERIC_MISLEADING",
    Database(
        server="pg.example.invalid",
        dialect="generic",
        auth="integrated",
        statement="INSERT INTO t VALUES (:b)",
        username="pguser",
        password="static",
        odbc_driver="PostgreSQL Unicode",
    ),
)

# --- everything below must stay QUIET ----------------------------------------------------------

# A delegated Windows/gMSA principal on the SQL Server preset.
outbound(
    "OB_INTEGRATED",
    Database(
        server="db5.example.invalid",
        database="Feeds",
        auth="integrated",
        statement="INSERT INTO t VALUES (:b)",
    ),
)
# Entra ID, the other delegated kind, on the lookup pool -- so the quiet half is proven off the
# outbound table too.
DatabaseLookup("entra_pool", server="db6.example.invalid", database="C", auth="entra")
# The written-down residual: a generic hop with no top-level credential. Anything in odbc_params
# belongs to a driver vocabulary the engine cannot enumerate, so classifying it would be guessing.
outbound(
    "OB_GENERIC_NO_CRED",
    Database(
        server="my.example.invalid",
        dialect="generic",
        statement="INSERT INTO t VALUES (:b)",
        odbc_driver="MySQL ODBC 8.0 Unicode Driver",
        odbc_params={"SSLMODE": "REQUIRED"},
    ),
)
# Not a database hop at all -- an MLLP outbound has no credential of this kind to classify.
outbound("OB_MLLP", MLLP(host="peer.example.invalid", port=15097))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_SQL", msg)
"""

#: The same graph with every static credential removed -- the negative control. An absence claim ships
#: with a live positive control or the reader is blind, and the pair IS the control: same code path,
#: same fixture shape, one green and one reporting.
_CLEAN_MODULE = """
from messagefoundry import Database, DatabaseLookup, MLLP, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15096), router="r")
outbound(
    "OB_SQL",
    Database(
        server="db1.example.invalid",
        database="Feeds",
        auth="integrated",
        statement="INSERT INTO t VALUES (:b)",
    ),
)
DatabaseLookup("clarity", server="db3.example.invalid", database="Clarity", auth="entra")


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_SQL", msg)
"""


def _write_config(tmp_path: Path, *, clean: bool = False) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_CLEAN_MODULE if clean else _CONFIG_MODULE, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    return cfg


@pytest.fixture(scope="module")
def reported(tmp_path_factory: pytest.TempPathFactory) -> dict[str, str]:
    """The reader's verdict over the mixed graph, as ``{name: reason}``, from ONE ``load_config``.

    Module-scoped because ``load_config`` re-imports and re-executes the config module on each call,
    and a dozen assertions against one mapping do not need a dozen passes. The clean graph and the
    ``run_checks`` pass keep their own runs -- they are different questions, not different reads."""
    cfg = _write_config(tmp_path_factory.mktemp("static_db"))
    return dict(static_credential_db_hops(load_config(cfg)))


# --- the table census: four factories, and the ledger named two ---------------------------------


def test_an_outbound_database_on_the_shipped_default_is_reported(reported: dict[str, str]) -> None:
    assert "OB_SQL" in reported
    assert "static SQL login" in reported["OB_SQL"]
    # The peer rides along, so the report names WHICH database rather than only that one exists.
    assert "db1.example.invalid" in reported["OB_SQL"]


def test_a_databasepoll_inbound_is_reported_under_its_own_namespace(
    reported: dict[str, str],
) -> None:
    """Reading ``outbound`` alone would report a live polling hop's static credential as absent."""
    assert "inbound:IB_POLL" in reported
    assert "db2.example.invalid" in reported["inbound:IB_POLL"]


def test_the_db_lookup_pool_is_reported(reported: dict[str, str]) -> None:
    """The ADR 0010 read pool. ``[store].require_managed_identity`` cannot reach it -- it is a
    ``StoreSettings`` method and this hop is a graph entry."""
    assert "db_lookup:clarity" in reported
    assert "db3.example.invalid" in reported["db_lookup:clarity"]


def test_a_databaseref_reference_source_is_reported(reported: dict[str, str]) -> None:
    """The fourth factory, named in no row of #1182. A reference set dials its source on a refresh
    cadence with the credential written here."""
    assert "reference:providers" in reported
    assert "db4.example.invalid" in reported["reference:providers"]


def test_all_four_tables_are_covered_in_one_pass(reported: dict[str, str]) -> None:
    """The census itself, so removing any single arm goes red here as well as in its own test."""
    assert {"OB_SQL", "inbound:IB_POLL", "db_lookup:clarity", "reference:providers"} <= set(
        reported
    )


# --- the generic-ODBC discriminator -------------------------------------------------------------


def test_integrated_auth_on_a_generic_hop_is_still_reported(reported: dict[str, str]) -> None:
    """THE discriminator. ``_build_odbc_dsn`` never reads ``auth``; it emits the top-level
    username/password. So this connection presents a static credential no matter what ``auth`` says,
    and a reader keyed on ``auth`` alone would report the engine's most misleading configuration as
    compliant."""
    assert "OB_GENERIC_MISLEADING" in reported
    assert "auth= is not read on this arm" in reported["OB_GENERIC_MISLEADING"]


def test_a_generic_hop_with_no_top_level_credential_stays_quiet(reported: dict[str, str]) -> None:
    """The written-down residual. A credential smuggled into ``odbc_params`` under an arbitrary
    driver keyword is not classifiable, and a reader that guessed would put a wrong name in a
    security report."""
    assert "OB_GENERIC_NO_CRED" not in reported


# --- the silences -------------------------------------------------------------------------------


def test_the_delegated_kinds_stay_quiet(reported: dict[str, str]) -> None:
    assert "OB_INTEGRATED" not in reported
    assert "db_lookup:entra_pool" not in reported


def test_a_non_database_connection_is_not_classified(reported: dict[str, str]) -> None:
    assert "OB_MLLP" not in reported


def test_a_graph_with_no_static_credential_reports_nothing(tmp_path: Path) -> None:
    """The negative control for every assertion above: same code path, same fixture shape, and the
    reader must come back empty rather than merely smaller."""
    cfg = _write_config(tmp_path, clean=True)
    assert static_credential_db_hops(load_config(cfg)) == []


# --- the check surface --------------------------------------------------------------------------


def test_the_check_names_every_hop_and_never_blocks(tmp_path: Path) -> None:
    """``messagefoundry check`` prints the whole set, advisory. A refusing gate is deliberately not
    built -- see the check's docstring and BACKLOG #1182."""
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path)
    result = next(
        r for r in run_checks(cfg, run_lint=False).results if r.name == "static-db-credentials"
    )
    assert result.ok and not result.required and not result.skipped
    detail = str(result.detail)
    for name in ("OB_SQL", "inbound:IB_POLL", "db_lookup:clarity", "reference:providers"):
        assert name in detail
    # The line has to say what the one existing control does NOT cover, or a reader who has set the
    # flag concludes these hops are already gated.
    assert "[store].require_managed_identity does NOT cover these hops" in detail


def test_the_check_states_the_clean_case_out_loud(tmp_path: Path) -> None:
    """A check that went silent on a clean graph is indistinguishable from one that did not run --
    the ``alert-smtp-tls`` convention."""
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path, clean=True)
    result = next(
        r for r in run_checks(cfg, run_lint=False).results if r.name == "static-db-credentials"
    )
    assert result.ok and not result.skipped
    assert "no DATABASE hop authenticates with a static credential" in str(result.detail)


def test_the_check_skips_rather_than_reporting_empty_on_an_unloadable_graph(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "broken.py").write_text("this is not python(", encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML, encoding="utf-8")
    result = next(
        r for r in run_checks(cfg, run_lint=False).results if r.name == "static-db-credentials"
    )
    assert result.skipped and result.ok and not result.required
