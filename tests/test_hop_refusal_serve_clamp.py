# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#200 (ADR 0092) apply-findings coverage: the LIVE serve/reload connector-build sites stamp the derived
posture (so the raw/MLLP/HTTP hop guards actually decide against the real posture on ``serve`` — not the
unstamped fail-closed/no-op default), and the strict verify-off cells (MLLP/FTPS ``tls_verify=false``,
credentialed plain-ftp, engine<->store TLS) CLAMP the ``MEFOR_ALLOW_INSECURE_TLS`` escape so it can never
relax a production-PHI hop (decision 2).

These guard the exact regressions the review found: ``engine.start()`` never calls ``build_check``, so the
guards no-op / fail-closed on the primary serve path unless the build sites stamp the posture themselves.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    SqlAuth,
    StoreBackend,
    StoreSettings,
)
from messagefoundry.config.tls_policy import HopPosture, active_hop_posture
from messagefoundry.config.wiring import (
    Registry,
    Rest,
    Tcp,
    build_outbound_connection,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.sqlserver import connection_string

PROD_PHI = HopPosture(is_phi=True, production=True)
STAGING_PHI = HopPosture(is_phi=True, production=False)
SYNTHETIC = HopPosture(is_phi=False, production=False)  # dev / synthetic instance (no PHI)
REMOTE = "10.0.0.5"  # a non-loopback host (never resolves; treated as off-box)


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "hop.db")
    yield s
    await s.close()


# --- Fix A: the LIVE serve path stamps the posture (findings 1 + 6) ----------------------------


async def test_serve_refuses_prod_phi_cleartext_tcp_outbound(store: MessageStore) -> None:
    # Finding 1: a prod-PHI plaintext raw-TCP outbound must be REFUSED at serve. Before the fix the
    # raw guard no-op'd when unstamped, so it shipped PHI in cleartext with no refusal.
    reg = Registry()
    reg.add_outbound(build_outbound_connection("OB_TCP", Tcp(host=REMOTE, port=5000)))
    runner = RegistryRunner(reg, store, poll_interval=0.02, hop_posture=PROD_PHI)
    await runner.start()
    try:
        degraded = runner.degraded_connections()
        assert "OB_TCP" in degraded
        assert "InsecureHopRefused" in degraded["OB_TCP"] or "no verified TLS" in degraded["OB_TCP"]
    finally:
        await runner.stop()


async def test_serve_allows_synthetic_cleartext_http_outbound(store: MessageStore) -> None:
    # Finding 6: a synthetic (non-PHI) instance's cleartext http egress PASSES build_check, so it must
    # also come up at serve. Before the fix the HTTP cell fail-closed to prod-PHI when unstamped and
    # wrongly degraded the lane at serve.
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection("OB_REST", Rest(url="http://partner.example.com/ingest"))
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02, hop_posture=SYNTHETIC)
    await runner.start()
    try:
        assert runner.connection_failed("OB_REST") is None  # lane built + live, not refused
        assert "OB_REST" not in runner.degraded_connections()
    finally:
        await runner.stop()


async def test_serve_prod_phi_still_refuses_cleartext_http(store: MessageStore) -> None:
    # The prod-PHI HTTP refusal is preserved by the stamped posture (not loosened by Fix A).
    reg = Registry()
    reg.add_outbound(
        build_outbound_connection("OB_REST", Rest(url="http://partner.example.com/ingest"))
    )
    runner = RegistryRunner(reg, store, poll_interval=0.02, hop_posture=PROD_PHI)
    await runner.start()
    try:
        assert "OB_REST" in runner.degraded_connections()
    finally:
        await runner.stop()


async def test_reload_rebuild_stamps_posture_no_spurious_refusal(store: MessageStore) -> None:
    # Finding 6 reload path: _reconcile_outbounds rebuilds outside the build_check scope. Without
    # stamping, adding a synthetic-OK cleartext http lane on reload would raise InsecureHopRefused AFTER
    # intake is quiesced ("connector builds here cannot fail"). With stamping the reload swaps cleanly.
    reg0 = Registry()
    reg0.add_outbound(build_outbound_connection("OB_TCP", Tcp(host="127.0.0.1", port=5000)))
    runner = RegistryRunner(reg0, store, poll_interval=0.02, hop_posture=SYNTHETIC)
    await runner.start()
    try:
        reg1 = Registry()
        reg1.add_outbound(build_outbound_connection("OB_TCP", Tcp(host="127.0.0.1", port=5000)))
        reg1.add_outbound(
            build_outbound_connection("OB_REST", Rest(url="http://partner.example.com/ingest"))
        )
        await runner.reload(reg1)  # must not raise InsecureHopRefused
        assert runner.connection_failed("OB_REST") is None
    finally:
        await runner.stop()


# --- Fix B: verify-off / credentialed cells clamp the escape to non production-PHI (findings 4,5) ---


def test_mllp_verify_off_refuses_prod_phi_even_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.transports.mllp import MLLPDestination

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    cfg = Destination(
        name="OB",
        type=ConnectorType.MLLP,
        settings={"host": REMOTE, "port": 5000, "tls": True, "tls_verify": False},
    )
    # Finding 5: the escape must NOT silence a production-PHI verify-off hop.
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="tls_verify=false"):
            MLLPDestination(cfg)
    # Non-production PHI + escape still crosses (escape clamp only bites production-PHI).
    with active_hop_posture(STAGING_PHI):
        MLLPDestination(cfg)


def test_ftps_verify_off_refuses_prod_phi_even_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.transports.remotefile import RemoteFileDestination

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    cfg = Destination(
        name="OB",
        type=ConnectorType.REMOTEFILE,
        settings={
            "host": REMOTE,
            "remote_dir": "/in",
            "protocol": "ftps",
            "tls_verify": False,
        },
    )
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="tls_verify=false"):
            RemoteFileDestination(cfg)
    with active_hop_posture(STAGING_PHI):
        RemoteFileDestination(cfg)  # crosses with the escape on non-prod


def test_credentialed_ftp_refuses_prod_phi_even_with_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry.transports.remotefile import RemoteFileDestination

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    cfg = Destination(
        name="OB",
        type=ConnectorType.REMOTEFILE,
        settings={
            "host": REMOTE,
            "remote_dir": "/in",
            "protocol": "ftp",
            "username": "u",
            "password": "p",
        },
    )
    # Finding 4: the strictly-worse credential-on-the-wire hop now gets the same clamp the sibling
    # anonymous-ftp guard already applied — the escape can't cross it on production-PHI.
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="CLEARTEXT"):
            RemoteFileDestination(cfg)
    with active_hop_posture(STAGING_PHI):
        RemoteFileDestination(cfg)  # crosses with the escape on non-prod


# --- Fix C: engine<->store weakened-TLS clamp (finding 3) --------------------------------------


def _weakened_store() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="db",
        database="mf",
        username="svc",
        password="pw",
        auth=SqlAuth.SQL,
        trust_server_certificate=True,  # the weakened (MITM-able) TLS posture
    )


def test_store_tls_refuses_prod_phi_even_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    s = _weakened_store()
    # Finding 3: the engine<->store hop must refuse a weakened-TLS production-PHI hop even with the
    # global escape set (decision 2 — the escape can never relax a production hop).
    with pytest.raises(ValueError, match="MITM-able"):
        connection_string(s, posture=PROD_PHI)
    # Non-production + escape still permitted (the escape downgrades a non-prod hop).
    assert "TrustServerCertificate=yes" in connection_string(s, posture=STAGING_PHI)
    # Unstamped (backup utility / test) falls back to the unclamped escape — byte-identical to pre-#200.
    assert "TrustServerCertificate=yes" in connection_string(s, posture=None)


def test_store_tls_refuses_weakened_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(INSECURE_TLS_ESCAPE_ENV, raising=False)
    s = _weakened_store()
    # No escape at all: refused for every posture (unchanged strict-cell behaviour).
    for posture in (PROD_PHI, STAGING_PHI, SYNTHETIC, None):
        with pytest.raises(ValueError, match="MITM-able"):
            connection_string(s, posture=posture)


def test_postgres_build_ssl_clamps_prod_phi(monkeypatch: pytest.MonkeyPatch) -> None:
    # The Postgres engine<->store twin is keyed identically to the SQL Server one.
    from messagefoundry.store.postgres import _build_ssl

    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    pg = StoreSettings(
        backend=StoreBackend.POSTGRES,
        server="db.example",
        database="mefor",
        username="mefor",
        trust_server_certificate=True,
    )
    with pytest.raises(ValueError, match="MITM-able"):
        _build_ssl(pg, posture=PROD_PHI)
    # Non-prod + escape: an escape-permitted CERT_NONE context is returned (crosses, not refused).
    import ssl as _ssl

    ctx = _build_ssl(pg, posture=STAGING_PHI)
    assert isinstance(ctx, _ssl.SSLContext) and ctx.verify_mode is _ssl.CERT_NONE
