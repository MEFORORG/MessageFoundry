# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An empty host is not loopback (BACKLOG #5512).

``tls_policy.is_loopback_hop_host("")`` used to answer True, so a caller that passed an unset host
as ``""`` took the on-box carve-out on its cleartext, revocation and trust-anchor checks. An empty
host means different things to different callers, so the predicate no longer answers for them.
Each caller here says what empty means where it stands:

* a default that really is local: the HTTP listener binds ``127.0.0.1``, so it stays on-box;
* an unconfigured feature: no log forwarder is built, so there is no hop to judge;
* a gate where "remote" is the permissive answer: empty still counts as this host;
* an unknown destination: the store, a generic ODBC ``server``, and every shared guard and trust
  anchor. It is judged off-box, so it fails closed.

Every case pairs the empty host with a control on a real host, so a site that refused everything,
or allowed everything, would fail too. Nothing here touches the network.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.auth.trust_anchors import smtp_hop_anchor_spec
from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    LoggingSettings,
    StoreBackend,
    StoreSettings,
    TlsSettings,
    _names_this_host,
    forward_hop_disposition,
    pinned_host_port,
)
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    RevocationHopGuard,
    TrustAnchorPolicy,
    active_hop_posture,
    is_loopback_hop_host,
    resolve_trust_anchor,
)
from messagefoundry.config.wiring import WiringError
from messagefoundry.pipeline.wiring_runner import check_http_intake_auth
from messagefoundry.restricted_file import _loopback_share_problem
from messagefoundry.store.postgres import _build_ssl
from messagefoundry.transports.bounded_read import is_never_proxied_host
from messagefoundry.transports.database import DatabaseDestination, DatabaseSource
from messagefoundry.transports.mllp import InsecureHopGuard
from messagefoundry.transports.strict_requests import _stays_on_the_box
from messagefoundry.transports.tcp import TcpDestination

ENFORCING = HopPosture(enforcing=True)
REMOTE = "192.0.2.10"  # RFC 5737 TEST-NET-1: never routed
LOOPBACK = "127.0.0.1"


@pytest.fixture(autouse=True)
def _no_escape_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Neither relaxation may mask a refusal these tests expect."""
    monkeypatch.delenv("MEFOR_TLS_REVOCATION_ATTESTED", raising=False)
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)


# --- the predicate ----------------------------------------------------------------------------


def test_an_empty_host_is_not_loopback() -> None:
    assert is_loopback_hop_host("") is False
    # CONTROL: the three shapes that really do name this box still do.
    assert all(is_loopback_hop_host(h) for h in ("localhost", "127.0.0.1", "::1"))


# --- a default that really is local: the inbound HTTP listener --------------------------------


def _http_source(host: str) -> Source:
    return Source(type=ConnectorType.HTTP, settings={"host": host, "port": 8080})


def test_a_blank_http_listener_host_binds_loopback_so_the_gate_passes_it() -> None:
    """``HttpSource`` reads ``s.get("host") or "127.0.0.1"``, so a blank host binds loopback. The
    gate has to read the same default, or it would refuse a listener that is not exposed."""
    check_http_intake_auth(_http_source(""), "IB_HTTP", posture=ENFORCING)


def test_the_http_listener_gate_still_refuses_an_exposed_bind() -> None:
    with pytest.raises(WiringError, match="non-loopback host"):
        check_http_intake_auth(_http_source("0.0.0.0"), "IB_HTTP", posture=ENFORCING)


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


def _pg(server: str | None) -> StoreSettings:
    settings = StoreSettings(
        backend=StoreBackend.POSTGRES, server=LOOPBACK, database="mefor", username="mefor"
    )
    # model_copy: the validator refuses a None server, and a blank one is the case it lets through.
    return settings.model_copy(update={"server": server})


@pytest.mark.parametrize("server", ["", None])
def test_a_store_with_no_server_is_not_judged_on_box(server: str | None) -> None:
    with pytest.raises(InsecureHopRefused, match="revocation"):
        _build_ssl(_pg(server), posture=ENFORCING)


def test_a_store_on_loopback_is_still_on_box() -> None:
    assert _build_ssl(_pg(LOOPBACK), posture=ENFORCING) is not None


# --- an unknown destination: a generic ODBC server -----------------------------------------------


_GENERIC: dict[str, object] = {
    "dialect": "generic",
    "odbc_driver": "PostgreSQL Unicode",
}


def _generic_dest(server: str) -> Destination:
    return Destination(
        name="OB_DB_GEN",
        type=ConnectorType.DATABASE,
        settings={**_GENERIC, "server": server, "statement": "INSERT INTO t (x) VALUES (:x)"},
    )


def _generic_source(server: str) -> Source:
    return Source(
        name="IB_DB_GEN",
        type=ConnectorType.DATABASE,
        settings={**_GENERIC, "server": server, "poll_statement": "SELECT 1"},
    )


_GENERIC_CONNECTORS = [(DatabaseDestination, _generic_dest), (DatabaseSource, _generic_source)]


@pytest.mark.parametrize(("connector", "config"), _GENERIC_CONNECTORS)
def test_a_blank_generic_server_is_not_judged_on_box(
    connector: Callable[[Any], object], config: Callable[[str], Any]
) -> None:
    """A ``server`` of spaces passes the required-setting check and splits to an empty host. The
    driver is handed that text, so where it dials is not known here. CONTROL: real loopback."""
    with active_hop_posture(ENFORCING), pytest.raises(InsecureHopRefused):
        connector(config("  "))
    with active_hop_posture(ENFORCING):
        assert connector(config(LOOPBACK))


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
    def disposition(host: str) -> HopDisposition | None:
        return RevocationHopGuard.capture(
            host=host,
            cell="test",
            description="test",
            attested=False,
            posture=ENFORCING,
            connection=None,
        ).disposition()

    assert disposition("") is HopDisposition.REFUSE
    assert disposition(LOOPBACK) is HopDisposition.ALLOW


def test_a_trust_anchor_on_an_empty_host_keeps_the_ca_and_the_crl() -> None:
    """The loopback arm drops the instance CA and the CRL, so a hop nobody can place keeps both."""
    policy = TrustAnchorPolicy(internal_ca_file="internal.pem", mode="pinned", crl_file="org.crl")
    empty = resolve_trust_anchor(connection_ca_file=None, host="", policy=policy)
    assert (empty.cafile, empty.crl_file) == ("internal.pem", "org.crl")
    on_box = resolve_trust_anchor(connection_ca_file=None, host=LOOPBACK, policy=policy)
    assert (on_box.cafile, on_box.crl_file) == (None, None)


# --- callers that already answer for an empty host themselves ------------------------------------


def test_the_never_proxied_reader_reads_no_host_as_off_box() -> None:
    assert is_never_proxied_host("") is False
    assert is_never_proxied_host(None) is False
    assert is_never_proxied_host(LOOPBACK) is True


def test_a_vault_hop_with_a_blank_host_does_not_stay_on_the_box() -> None:
    assert _stays_on_the_box("", None) is False
    assert _stays_on_the_box(LOOPBACK, None) is True


def test_a_sidecar_entry_with_no_host_is_not_pinned() -> None:
    assert pinned_host_port(":8123") is None
    assert pinned_host_port(f"{LOOPBACK}:8123") == (LOOPBACK, 8123)


def test_an_smtp_relay_with_no_host_reads_no_internal_ca() -> None:
    alerts: dict[str, Any] = {"email_from": "a@example.org", "email_to": ["b@example.org"]}
    tls = TlsSettings(internal_ca_file="internal.pem", trust_anchor_mode="pinned")
    assert smtp_hop_anchor_spec(AlertsSettings(**alerts), AuthSettings(), tls) is None
    relay = AlertsSettings(**alerts, email_smtp_host="smtp.example.org")
    assert smtp_hop_anchor_spec(relay, AuthSettings(), tls) is not None


# --- row item 1: a bracketed literal reads as remote, which fails closed -------------------------


def test_a_bracketed_loopback_literal_reads_as_remote() -> None:
    """Not a defect (row item 1). The predicate reads a host as written, and ``[::1]`` is not an
    address to :mod:`ipaddress`. Reading it as remote can only refuse, so it adds no hop to those
    judged on-box. The HTTP family never meets the spelling: ``urlsplit`` strips the brackets."""
    assert is_loopback_hop_host("[::1]") is False
    assert is_loopback_hop_host("::1") is True


@pytest.mark.parametrize(("host", "refused"), [("[::1]", True), ("::1", False)])
def test_a_bracketed_loopback_tcp_hop_fails_closed(host: str, refused: bool) -> None:
    config = Destination(
        name="OB_TCP",
        type=ConnectorType.TCP,
        settings={"host": host, "port": 9100, "framing": "stx_etx"},
    )
    with active_hop_posture(ENFORCING):
        if refused:
            with pytest.raises(InsecureHopRefused):
                TcpDestination(config)
        else:
            assert TcpDestination(config)
