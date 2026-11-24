# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An empty host is not loopback (BACKLOG #5512).

``tls_policy.is_loopback_hop_host("")`` used to answer True, so a caller that passed an unset host
as ``""`` took the on-box carve-out on its cleartext, revocation and trust-anchor checks. An empty
host means different things to different callers, so the predicate no longer answers for them.
Each caller here says what empty means where it stands:

* an unconfigured feature: no log forwarder is built, so there is no hop to judge;
* a gate where "remote" is the permissive answer: empty still counts as this host;
* an unknown destination: a Postgres store, and every shared guard and trust anchor. It is judged
  off-box, so the caller's gate applies as it does to any remote hop;
* no destination at all: a generic ODBC ``server`` naming no host and a blank SQL Server store are
  refused whatever the posture or declaration.

One more meaning, a default that really is local, is the HTTP listener's: a blank host binds
loopback. ``test_offloopback_without_effective_peer_control_refused_by_posture`` in
``tests/test_inbound_http_intake_auth.py`` pins it. The predicate's own answer is in
``tests/test_tls_policy.py``, and ``is_never_proxied_host`` in
``tests/test_loopback_hop_never_proxied.py``.

Every case pairs the empty host with a control on a real host, so a site that refused everything,
or allowed everything, would fail too. Nothing here touches the network.
"""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.__main__ import _warn_on_an_unrevoked_store_hop
from messagefoundry.auth.trust_anchors import smtp_hop_anchor_spec
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AiSettings,
    AlertsSettings,
    AuthSettings,
    EgressSettings,
    LoggingSettings,
    SecurityEnforcement,
    StoreBackend,
    StoreSettings,
    TlsSettings,
    _names_this_host,
    forward_hop_disposition,
    pinned_host_port,
)
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    TrustAnchorPolicy,
    active_hop_posture,
    is_loopback_hop_host,
    resolve_trust_anchor,
)
from messagefoundry.pipeline.reference_sync import database_source_dsn
from messagefoundry.restricted_file import _loopback_share_problem
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.transports.database import (
    DatabaseDestination,
    DatabaseLookupExecutor,
    DatabaseSource,
)
from messagefoundry.transports.mllp import InsecureHopGuard
from messagefoundry.transports.tcp import TcpDestination
from tests.test_hop_refusal_db_inbound import _GENERIC_CONNECTORS, _generic_dest, _generic_source
from tests.test_hop_refusal_rawtcp import tcp_cfg
from tests.test_hop_refusal_revocation import _guard, _pg

ENFORCING = HopPosture(enforcing=True)
REMOTE = "192.0.2.10"  # RFC 5737 TEST-NET-1: never routed
LOOPBACK = "127.0.0.1"


@pytest.fixture(autouse=True)
def _no_escape_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither relaxation may mask a refusal these tests expect."""
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)


# --- an unconfigured feature: the log forwarder -----------------------------------------------


@pytest.mark.parametrize("host", [None, ""])
def test_an_unconfigured_forwarder_is_never_refused(host: str | None) -> None:
    """With no host, ``serve`` builds no forwarder, so there is no hop to refuse. Built with
    ``model_copy`` because the validator refuses ``forward_enabled`` with no host."""
    log = LoggingSettings().model_copy(update={"forward_host": host, "forward_enabled": True})
    assert forward_hop_disposition(log, ENFORCING) is HopDisposition.ALLOW


def test_a_configured_plaintext_forwarder_is_still_refused() -> None:
    log = LoggingSettings(forward_host=REMOTE, forward_enabled=True)
    assert forward_hop_disposition(log, ENFORCING) is HopDisposition.REFUSE


# --- a gate where remote is the permissive answer ----------------------------------------------


@pytest.mark.parametrize("host", ["", " ", ".", " . "])
def test_a_host_that_trims_to_nothing_is_not_a_separate_collector(host: str) -> None:
    """The forwarding gate and the share check ask whether a host is this one, and there "remote"
    passes. A value that trims to nothing names no other system, so it keeps counting as this one."""
    assert _names_this_host(host) is True


@pytest.mark.parametrize("host", ["localhost", "LOCALHOST.", "app.localhost"])
def test_names_this_host_still_reads_the_localhost_names(host: str) -> None:
    assert _names_this_host(host) is True


def test_names_this_host_still_reads_a_real_remote_as_remote() -> None:
    assert _names_this_host(REMOTE) is False


def test_a_key_share_whose_server_trims_to_nothing_is_still_refused() -> None:
    """The share check reads ``_names_this_host``, and a share it cannot tell from this host is
    refused. CONTROL: a share on a named remote server is not."""
    assert _loopback_share_problem("\\\\ \\share\\key.pem", "thishost", lambda _: None) is not None
    assert (
        _loopback_share_problem("\\\\files.example\\share\\key.pem", "thishost", lambda _: None)
        is None
    )


# --- an unknown destination: the store ---------------------------------------------------------


def _store_with_server(server: str | None) -> StoreSettings:
    # model_copy: the validator refuses a None server, so the None case cannot be built through it.
    return _pg(LOOPBACK).model_copy(update={"server": server})


@pytest.mark.parametrize("server", ["", None])
def test_a_store_with_no_server_is_not_judged_on_box(server: str | None) -> None:
    with pytest.raises(InsecureHopRefused, match=r"to \(no \[store\]\.server\):"):
        _build_ssl(_store_with_server(server), posture=ENFORCING)


def test_a_store_on_loopback_is_still_on_box() -> None:
    assert _build_ssl(_store_with_server(LOOPBACK), posture=ENFORCING) is not None


@pytest.mark.parametrize(
    ("server", "warned"), [("", True), (None, True), (LOOPBACK, False)], ids=str
)
def test_a_cli_store_open_at_warn_warns_on_a_store_with_no_server(
    server: str | None, warned: bool, caplog: pytest.LogCaptureFixture
) -> None:
    """The CLI's own run of the store guard, at ``warn``, where a refusal becomes a WARNING."""
    settings = SimpleNamespace(
        ai=AiSettings(),
        security=SimpleNamespace(enforcement=SecurityEnforcement.WARN),
        store=_store_with_server(server),
    )
    with caplog.at_level("WARNING"):
        _warn_on_an_unrevoked_store_hop(settings)  # type: ignore[arg-type]
    assert ("(no [store].server)" in caplog.text) is warned


# --- an unknown destination: a generic ODBC server -----------------------------------------------


#: Each passes the required-setting check, and each leaves a host unnamed.
_GENERIC_SERVERS_NAMING_NO_HOST = [
    "  ",
    ":5432",
    "[]",
    "[ ]:5432",
    "[,]",
    ":1433:",
    ",1433",
    " ,db.example",
    "db.example,",
    "db.example,,other.example",
]


@pytest.mark.parametrize("server", _GENERIC_SERVERS_NAMING_NO_HOST)
@pytest.mark.parametrize("posture", [ENFORCING, HopPosture(enforcing=False), None], ids=str)
@pytest.mark.parametrize(("connector", "config"), _GENERIC_CONNECTORS)
def test_a_generic_server_naming_no_host_is_refused_at_every_posture(
    connector: Callable[[Any], object],
    config: Callable[..., Any],
    posture: HopPosture | None,
    server: str,
) -> None:
    """The driver is handed that text, so where it dials is not known here. CONTROL: real loopback
    builds at the same posture."""
    with active_hop_posture(posture), pytest.raises(InsecureHopRefused, match="names no host"):
        connector(config(server=server))
    with active_hop_posture(posture):
        assert connector(config(server=LOOPBACK))


_ATTESTED = {"tls_hop_attested": True, "tls_hop_attested_reason": "a segment the engine cannot see"}
_ACCEPTED = {"cleartext_accepted": True, "cleartext_reason": "a hop accepted as cleartext"}
_TLS_MODE = {"odbc_params": {"sslmode": "verify-full"}}


@pytest.mark.parametrize(
    ("connector", "config", "declared"),
    [
        (DatabaseDestination, _generic_dest, _ATTESTED),
        (DatabaseDestination, _generic_dest, _ACCEPTED),
        (DatabaseDestination, _generic_dest, _TLS_MODE),
        (DatabaseSource, _generic_source, _ATTESTED),
    ],
    ids=["outbound-attested", "outbound-accepted", "outbound-tls-mode", "inbound-attested"],
)
def test_nothing_declared_covers_a_generic_hop_with_no_named_host(
    connector: Callable[[Any], object], config: Callable[..., Any], declared: dict[str, Any]
) -> None:
    """A declaration is about a hop, and this one has no destination to be about. The cleartext
    guard stands down on a TLS mode, so the refusal sits in front of it. CONTROL: the same
    declaration still builds on a named remote host."""
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="names no host"):
        connector(config(server="  ", **declared))
    with active_hop_posture(ENFORCING):
        assert connector(config(server=REMOTE, **declared))


# --- the SQL Server preset: Database, DatabasePoll, DatabaseLookup, DatabaseRef ---------------------

#: "" is left out: the connectors refuse it earlier, as a missing setting. A value holding a comma
#: is left out too: the preset refuses every comma first, with its own remedy.
_PRESET_NO_HOST = ["  ", ":1433", "[]", ":1433:"]
_PRESET_BASE = {"database": "d", "statement": "INSERT INTO t (x) VALUES (:x)"}


def _preset_dest(**overrides: object) -> Destination:
    attested = bool(overrides.pop("tls_hop_attested", False))
    return Destination(
        name="OB_DB_PRE",
        type=ConnectorType.DATABASE,
        settings={**_PRESET_BASE, **overrides},
        tls_hop_attested=attested,
        tls_hop_attested_reason="a segment the engine cannot see" if attested else None,
    )


def _preset_source(**overrides: object) -> Source:
    settings = {"database": "d", "poll_statement": "SELECT 1", **overrides}
    return Source(name="IB_DB_PRE", type=ConnectorType.DATABASE, settings=settings)


def _preset_lookup(**overrides: object) -> object:
    settings = {"database": "d", **overrides}
    return DatabaseLookupExecutor({"c": settings}, egress=EgressSettings(deny_by_default=False))


def _preset_ref(**overrides: object) -> object:
    return database_source_dsn({"database": "d", **overrides})


_PRESET_ENTRY_POINTS = [
    (DatabaseDestination, _preset_dest),
    (DatabaseSource, _preset_source),
    (None, _preset_lookup),
    (None, _preset_ref),
]


@pytest.mark.parametrize("server", _PRESET_NO_HOST)
@pytest.mark.parametrize("posture", [ENFORCING, HopPosture(enforcing=False), None], ids=str)
@pytest.mark.parametrize(("connector", "config"), _PRESET_ENTRY_POINTS)
def test_a_sql_server_preset_server_naming_no_host_is_refused_at_every_posture(
    connector: Callable[[Any], object] | None,
    config: Callable[..., Any],
    posture: HopPosture | None,
    server: str,
) -> None:
    """It would reach the driver as ``SERVER=,1433``. CONTROL: a named host builds at the same
    posture."""

    def build(**overrides: object) -> object:
        made = config(**overrides)
        return made if connector is None else connector(made)

    with active_hop_posture(posture), pytest.raises(InsecureHopRefused, match="names no host"):
        build(server=server)
    with active_hop_posture(posture):
        assert build(server=LOOPBACK)


@pytest.mark.parametrize("declared", [{}, "attested"], ids=["plain", "attested"])
@pytest.mark.parametrize("posture", [ENFORCING, HopPosture(enforcing=False), None], ids=str)
@pytest.mark.parametrize(("connector", "config"), _PRESET_ENTRY_POINTS)
def test_a_sql_server_preset_server_of_none_is_refused_whatever_is_declared(
    connector: Callable[[Any], object] | None,
    config: Callable[..., Any],
    posture: HopPosture | None,
    declared: object,
) -> None:
    """``None`` must not become the host ``None`` and ``SERVER=None,1433``. The DatabaseRef path
    has no required-setting check ahead of the build, so it is the one that sees ``None``; the
    others are pinned too, so none can start sending it. CONTROL: a named host builds."""
    extra: dict[str, Any] = {"tls_hop_attested": True} if declared == "attested" else {}
    if declared == "attested" and config is not _preset_dest:
        extra = {
            "tls_hop_attested": True,
            "tls_hop_attested_reason": "a segment the engine cannot see",
        }

    def build(**overrides: object) -> object:
        made = config(**{**extra, **overrides})
        return made if connector is None else connector(made)

    with active_hop_posture(posture), pytest.raises(ValueError, match="server") as caught:
        build(server=None)
    assert "None,1433" not in str(caught.value)
    with active_hop_posture(posture):
        assert build(server=LOOPBACK)


def test_a_sql_server_preset_dsn_never_carries_the_host_none() -> None:
    """The build itself, below every entry point."""
    from messagefoundry.transports.database import _build_dsn

    with pytest.raises(InsecureHopRefused, match="names no host"):
        _build_dsn({"database": "d", "server": None})


def test_a_database_ref_with_an_empty_server_is_refused() -> None:
    """The DatabaseRef path has no required-setting check ahead of the build."""
    with active_hop_posture(None), pytest.raises(InsecureHopRefused, match="names no host"):
        database_source_dsn({"database": "d", "server": ""})


@pytest.mark.parametrize("server", ["  ", ":1433"])
def test_an_attestation_does_not_cover_a_preset_server_with_no_host(server: str) -> None:
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused, match="names no host"):
        DatabaseDestination(_preset_dest(server=server, tls_hop_attested=True))
    with active_hop_posture(ENFORCING):
        assert DatabaseDestination(_preset_dest(server=REMOTE, tls_hop_attested=True))


@pytest.mark.parametrize("server", ["1433", "1:2", "12:34", "[1433]", "::", "[::]", "::1", "db"])
def test_names_no_host_accepts_a_plain_number_and_the_unspecified_literals(server: str) -> None:
    """Pins what the docs say is accepted, so the stated rule cannot drift from the code."""
    from messagefoundry.hostlist import names_no_host

    assert names_no_host(server) is False


@pytest.mark.parametrize("server", ["[", "]", ":1433:", "[,]", "", ":1433", "[]"])
def test_names_no_host_refuses_what_the_docs_say_it_refuses(server: str) -> None:
    from messagefoundry.hostlist import names_no_host

    assert names_no_host(server) is True


# --- the leaf module: settings may not import the transports package -----------------------------


def test_validating_a_sql_server_store_does_not_import_the_transports_package() -> None:
    """In a subprocess, so another test's imports cannot mask it."""
    tree = Path(__file__).resolve().parents[1]
    code = (
        "import sys\n"
        "import messagefoundry\n"
        "print(messagefoundry.__file__)\n"
        "from messagefoundry.config.settings import StoreBackend, StoreSettings\n"
        "StoreSettings(backend=StoreBackend.SQLSERVER, server='db.example', database='d',"
        " username='u')\n"
        "raise SystemExit(1 if 'messagefoundry.transports' in sys.modules else 0)\n"
    )
    # PYTHONPATH and cwd name this tree, so an editable install pointing elsewhere cannot make
    # the subprocess test another one; the imported module's path is asserted below.
    env = {**os.environ, "PYTHONPATH": str(tree)}
    done = subprocess.run(
        [sys.executable, "-P", "-c", code],
        capture_output=True,
        text=True,
        cwd=tree,
        env=env,
        timeout=120,
    )
    imported = Path(done.stdout.splitlines()[0]).resolve() if done.stdout else None
    assert imported is not None and imported.is_relative_to(tree), (imported, done.stderr)
    assert done.returncode == 0, done.stderr


# --- what a blank [store].server means on each backend ------------------------------------------


@pytest.mark.parametrize("server", ["", " ", "\t", ":1433", "[]", ",1433", "db.example,"])
def test_a_sql_server_store_refuses_a_server_naming_no_host(server: str) -> None:
    """It would reach the driver as ``SERVER=,1433`` or the like, and no hop guard reads the SQL
    Server store's host."""
    with pytest.raises(ValidationError, match=r"\[store\]\.server names no host"):
        _pg(server, backend=StoreBackend.SQLSERVER)


@pytest.mark.parametrize("server", ["db.example", "tcp:db.example", r".\SQLEXPRESS", "::1"])
def test_a_sql_server_store_keeps_a_server_that_names_a_host(server: str) -> None:
    assert _pg(server, backend=StoreBackend.SQLSERVER).server == server


@pytest.mark.parametrize("server", [" ", "\t"])
def test_a_postgres_store_refuses_a_server_of_spaces_and_names_the_setting(server: str) -> None:
    """Spaces are not empty to asyncpg: it would try them as a host name."""
    with pytest.raises(ValidationError, match=r"\[store\]\.server names no host"):
        _pg(server)


def test_a_postgres_store_keeps_an_empty_server() -> None:
    """Empty is legal here (docs/CONFIGURATION.md, the ``server`` row). The hop is still judged
    off-box (``test_a_store_with_no_server_is_not_judged_on_box``)."""
    assert _pg("").server == ""


@pytest.mark.parametrize("server", ["", " "])
def test_a_sqlite_store_has_no_server_to_refuse(server: str) -> None:
    assert StoreSettings(backend=StoreBackend.SQLITE, server=server).server == server


# --- an unknown destination: the shared guards and the trust anchor -----------------------------


def test_the_cleartext_guard_refuses_an_empty_host() -> None:
    def guard(host: str) -> InsecureHopGuard:
        with active_hop_posture(ENFORCING):
            return InsecureHopGuard.capture(
                host=host,
                port=2575,
                cell="test",
                description="test",
                attested=False,
                attested_reason=None,
                connection=None,
            )

    with pytest.raises(InsecureHopRefused):
        guard("").enforce_construction()
    guard(LOOPBACK).enforce_construction()


def test_the_revocation_guard_refuses_an_empty_host() -> None:
    with active_hop_posture(ENFORCING):
        assert _guard("").disposition() is HopDisposition.REFUSE
        assert _guard(LOOPBACK).disposition() is HopDisposition.ALLOW


def test_a_trust_anchor_on_an_empty_host_keeps_the_ca_and_the_crl() -> None:
    """The loopback arm drops the instance CA and the CRL, so a hop nobody can place keeps both."""
    policy = TrustAnchorPolicy(internal_ca_file="internal.pem", mode="pinned", crl_file="org.crl")
    empty = resolve_trust_anchor(connection_ca_file=None, host="", policy=policy)
    assert (empty.cafile, empty.crl_file) == ("internal.pem", "org.crl")
    on_box = resolve_trust_anchor(connection_ca_file=None, host=LOOPBACK, policy=policy)
    assert (on_box.cafile, on_box.crl_file) == (None, None)


# --- callers that read the predicate's answer for an empty host ----------------------------------


def test_a_vault_hop_with_a_blank_host_does_not_stay_on_the_box() -> None:
    # strict_requests imports requests at module level and the harness leg lacks it.
    pytest.importorskip("requests")
    from messagefoundry.transports.strict_requests import _stays_on_the_box

    assert _stays_on_the_box("", None) is False
    assert _stays_on_the_box(LOOPBACK, None) is True


@pytest.mark.parametrize("entry", [":8123", "[]:8123"])
def test_a_sidecar_entry_with_no_host_is_not_pinned(entry: str) -> None:
    assert pinned_host_port(entry) is None
    assert pinned_host_port(f"{LOOPBACK}:8123") == (LOOPBACK, 8123)


def test_an_smtp_relay_with_no_host_reads_no_internal_ca() -> None:
    alerts: dict[str, Any] = {"email_from": "a@example.org", "email_to": ["b@example.org"]}
    tls = TlsSettings(internal_ca_file="internal.pem", trust_anchor_mode="pinned")
    assert smtp_hop_anchor_spec(AlertsSettings(**alerts), AuthSettings(), tls) is None
    relay = AlertsSettings(**alerts, email_smtp_host="smtp.example.org")
    assert smtp_hop_anchor_spec(relay, AuthSettings(), tls) is not None


# --- row item 1: a bracketed literal reads as remote ---------------------------------------------


def test_a_bracketed_loopback_literal_reads_as_remote() -> None:
    """Not a defect (row item 1). The predicate reads a host as written, and ``[::1]`` is not an
    address to :mod:`ipaddress`. Reading it as remote can only refuse, so it adds no hop to those
    judged on-box. The HTTP family never meets the spelling: ``urlsplit`` strips the brackets."""
    assert is_loopback_hop_host("[::1]") is False
    assert is_loopback_hop_host("::1") is True


@pytest.mark.parametrize(("host", "refused"), [("[::1]", True), ("::1", False)])
def test_a_bracketed_loopback_tcp_hop_is_refused_when_enforcing(host: str, refused: bool) -> None:
    config: Destination = tcp_cfg(host)
    with active_hop_posture(ENFORCING):
        if refused:
            with pytest.raises(InsecureHopRefused):
                TcpDestination(config)
        else:
            assert TcpDestination(config)
