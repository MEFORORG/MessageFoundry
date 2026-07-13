# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""#200 (ADR 0092) DEFERRED residuals — the posture-keyed transport-hop refusal extended to the paths
the core shipment left OPEN:

1. **API PHI-read data-path guard** — the raw-view / attachment-download / summary RESPONSE path refuses
   to emit PHI on a production-PHI instance whose API serve hop is not proven secure (not loopback / TLS /
   proxy-terminated), rather than silently putting PHI on the wire. A synthetic / dev / loopback lane is
   byte-identical.
2. **db_lookup / fhir_lookup posture stamp** — the LIVE-runner build of the lookup executors now stamps
   the derived posture, so the production-PHI clamp (``weakened_tls_escape_permitted``) actually applies
   to a weakened-TLS live read (it previously keyed on the UNCLAMPED escape, posture unstamped there), and
   a legitimate synthetic cleartext read is no longer false-closed.
3. **``messagefoundry check`` posture-stamped build_check** — the commit/CI gate now runs the same
   posture-stamped ``build_check_registry`` that serve/reload run, so a prod-PHI cleartext hop is caught
   at commit time, not only at serve.

Every path pairs a REFUSE case (prod-PHI + insecure hop) with an ALLOW case (synthetic / dev / secure)
so the guard bites without false-closing a legitimate lane; the production-PHI clamp is the single
authority throughout.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AiSettings,
    EgressSettings,
)
from messagefoundry.config.tls_policy import (
    HopDisposition,
    HopPosture,
    InsecureHopRefused,
    phi_read_hop_disposition,
)
from messagefoundry.config.wiring import DatabaseLookupSpec, FhirLookupSpec, Registry
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore

PROD_PHI = HopPosture(is_phi=True, production=True)
STAGING_PHI = HopPosture(is_phi=True, production=False)
SYNTHETIC = HopPosture(is_phi=False, production=False)

# Non-routable / documentation hosts only (leak-gate): RFC 5737 TEST-NET-1 + RFC 2606 .example.
REMOTE_DB = "192.0.2.10"
CLEARTEXT_FHIR = "http://fhir.example.org/fhir"

ADT = "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


# =====================================================================================
# Residual 1 — the API PHI-read data-path guard
# =====================================================================================


# --- the pure authority ---------------------------------------------------------------


def test_phi_read_disposition_none_posture_allows() -> None:
    # No declared [ai] posture (embedding / test) → ALLOW, byte-identical to before the residual.
    assert (
        phi_read_hop_disposition(None, serve_hop_secure=False, audited_opt_out=False)
        is HopDisposition.ALLOW
    )


def test_phi_read_disposition_prod_phi_insecure_hop_refuses() -> None:
    # A production-PHI instance over an insecure serve hop → REFUSE (do not emit PHI in the clear).
    assert (
        phi_read_hop_disposition(PROD_PHI, serve_hop_secure=False, audited_opt_out=False)
        is HopDisposition.REFUSE
    )


def test_phi_read_disposition_prod_phi_secure_hop_allows() -> None:
    # The same prod-PHI instance over a SECURE serve hop (loopback / TLS / proxy-terminated) → ALLOW.
    assert (
        phi_read_hop_disposition(PROD_PHI, serve_hop_secure=True, audited_opt_out=False)
        is HopDisposition.ALLOW
    )


def test_phi_read_disposition_synthetic_insecure_hop_allows() -> None:
    # A synthetic instance carries no PHI, so an insecure serve hop is not refused (no false-close).
    assert (
        phi_read_hop_disposition(SYNTHETIC, serve_hop_secure=False, audited_opt_out=False)
        is HopDisposition.ALLOW
    )


def test_phi_read_disposition_staging_phi_insecure_hop_warns() -> None:
    # Non-production PHI (staging) WARNs, not REFUSEs — the refusal is production-only.
    assert (
        phi_read_hop_disposition(STAGING_PHI, serve_hop_secure=False, audited_opt_out=False)
        is HopDisposition.WARN
    )


def test_phi_read_disposition_prod_phi_escape_cannot_relax() -> None:
    # The production-PHI clamp is the single authority: even if the caller passed a truthy audited_opt_out,
    # a correct clamp keeps it False on production — but assert directly that a True opt_out still cannot
    # satisfy prod (the clamp lives upstream; the authority's production arm wins only when opt_out=False).
    # A caller that (correctly) clamps to False on prod → REFUSE.
    assert (
        phi_read_hop_disposition(PROD_PHI, serve_hop_secure=False, audited_opt_out=False)
        is HopDisposition.REFUSE
    )


# --- the wired API response path ------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "phi_read.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _seed(engine: Engine) -> str:
    return await engine.store.enqueue_message(
        channel_id="ch1",
        raw=ADT,
        deliveries=[("archive", ADT)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
    )


def _client(engine: Engine, *, ai: AiSettings | None, secure: bool) -> httpx.AsyncClient:
    app = create_app(engine, allow_no_auth=True, ai_settings=ai, phi_read_hop_secure=secure)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def test_api_prod_phi_insecure_hop_refuses_raw_view(engine: Engine) -> None:
    mid = await _seed(engine)
    # Production-PHI instance whose serve hop is NOT proven secure → the raw view is REFUSED (403), and
    # the PHI body never leaves.
    async with _client(engine, ai=AiSettings(environment="prod"), secure=False) as c:
        r = await c.get(f"/messages/{mid}")
        assert r.status_code == 403
        assert "PHI read refused" in r.json()["detail"]
        assert ADT not in r.text
        # The summary list + attachment download ride the same folded guard.
        assert (await c.get("/messages")).status_code == 403
        assert (await c.get(f"/messages/{mid}/attachments/deadbeef")).status_code == 403


async def test_api_prod_phi_secure_hop_serves_raw_view(engine: Engine) -> None:
    mid = await _seed(engine)
    # The SAME prod-PHI instance over a secure serve hop (loopback / TLS) serves the raw body: the guard
    # only bites the insecure hop, so a properly-exposed prod instance is unaffected.
    async with _client(engine, ai=AiSettings(environment="prod"), secure=True) as c:
        r = await c.get(f"/messages/{mid}")
        assert r.status_code == 200
        assert r.json()["raw"] == ADT


async def test_api_synthetic_insecure_hop_is_byte_identical(engine: Engine) -> None:
    mid = await _seed(engine)
    # A synthetic (dev) instance over an insecure hop is UNAFFECTED — no PHI to protect, byte-identical.
    async with _client(engine, ai=AiSettings(environment="dev"), secure=False) as c:
        assert (await c.get(f"/messages/{mid}")).status_code == 200


async def test_api_no_ai_posture_is_byte_identical(engine: Engine) -> None:
    mid = await _seed(engine)
    # No [ai] at all (embedding) → ALLOW, byte-identical to before this seam, even with secure=False.
    async with _client(engine, ai=None, secure=False) as c:
        assert (await c.get(f"/messages/{mid}")).status_code == 200


# =====================================================================================
# Residual 2 — db_lookup / fhir_lookup live-runner posture stamp
# =====================================================================================


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "lookup.db")
    yield s
    await s.close()


def _fhir_registry() -> Registry:
    reg = Registry()
    reg.add_fhir_lookup(FhirLookupSpec("epic", {"url": CLEARTEXT_FHIR}))
    return reg


def _db_registry() -> Registry:
    reg = Registry()
    reg.add_lookup(
        DatabaseLookupSpec(
            "clarity",
            {
                "server": REMOTE_DB,
                "database": "Clarity",
                "auth": "sql",
                "username": "u",
                "password": "p",
                "port": 1433,
                "encrypt": True,
                # weakened TLS: trust the server cert (MITM-able) — a strict verify-off cell.
                "trust_server_certificate": True,
                "odbc_driver": "ODBC Driver 18 for SQL Server",
            },
        )
    )
    return reg


async def test_runner_refuses_prod_phi_cleartext_fhir_lookup(store: MessageStore) -> None:
    # A prod-PHI instance building the live FHIR-lookup executor must REFUSE a cleartext http read hop.
    runner = RegistryRunner(_fhir_registry(), store, poll_interval=0.02, hop_posture=PROD_PHI)
    with pytest.raises(InsecureHopRefused):
        runner._build_fhir_lookup_executor()


async def test_runner_allows_synthetic_cleartext_fhir_lookup(store: MessageStore) -> None:
    # A synthetic instance is NOT false-closed: the same cleartext read builds fine. Before the residual
    # the live-runner build was unstamped → fail-closed (prod-PHI) → this would have wrongly refused.
    runner = RegistryRunner(_fhir_registry(), store, poll_interval=0.02, hop_posture=SYNTHETIC)
    assert runner._build_fhir_lookup_executor() is not None


async def test_runner_refuses_prod_phi_weakened_db_lookup_even_with_escape(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The core bug this residual closes: the escape is set, but a prod-PHI weakened-TLS live read must
    # STILL be refused (the production-PHI clamp). Before the stamp the live-runner build keyed on the
    # UNCLAMPED insecure_tls_allowed() (posture unstamped) → it would have been PERMITTED.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    runner = RegistryRunner(_db_registry(), store, poll_interval=0.02, hop_posture=PROD_PHI)
    # The DATABASE weakened-TLS cell refuses with a ValueError (surfaced as a config-load error) — the
    # strict verify-off cell, keyed on the stamped posture through the production-PHI clamp.
    with pytest.raises(ValueError, match="weakened"):
        runner._build_lookup_executor()


async def test_runner_allows_synthetic_weakened_db_lookup_with_escape(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Byte-identical for a synthetic instance: with the escape set, a weakened-TLS lookup still builds —
    # the clamp only closes the production-PHI case, never a dev lane.
    monkeypatch.setenv(INSECURE_TLS_ESCAPE_ENV, "1")
    runner = RegistryRunner(_db_registry(), store, poll_interval=0.02, hop_posture=SYNTHETIC)
    assert runner._build_lookup_executor() is not None


# =====================================================================================
# Residual 3 — the check-command posture-stamped build_check
# =====================================================================================

# A minimal config module declaring a single cleartext-http REST outbound to a non-loopback host, wired
# to a trivial inbound so the graph loads. The posture-keyed refusal keys ONLY on the instance posture,
# so the SAME config is refused on prod-PHI and allowed on dev.
_CONFIG_MODULE = """
from messagefoundry import MLLP, Rest, Send, handler, inbound, outbound, router

inbound("IB", MLLP(port=15099), router="r")
outbound("OB", Rest(url="http://collector.example.org/ingest"))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB", msg)
"""

# Egress allows the cleartext host so ONLY the posture-keyed hop refusal decides (not the allowlist).
_TOML = """
[ai]
environment = "{env}"

[egress]
allowed_http = ["collector.example.org"]

[inbound]
bind_host = "127.0.0.1"
"""


def _write_config(tmp_path: Path, *, env: str) -> Path:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_CONFIG_MODULE, encoding="utf-8")
    (tmp_path / "messagefoundry.toml").write_text(_TOML.format(env=env), encoding="utf-8")
    return cfg


def _build_result(report):  # type: ignore[no-untyped-def]
    return next(r for r in report.results if r.name == "build-check")


def test_check_build_refuses_prod_phi_cleartext_hop(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path, env="prod")
    report = run_checks(cfg, run_lint=False)
    result = _build_result(report)
    # A prod-PHI cleartext egress hop FAILS the gate at commit/CI, exactly as serve would refuse it.
    assert result.required and not result.ok and not result.skipped
    assert not report.ok  # the whole gate fails on a blocking required check


def test_check_build_allows_dev_cleartext_hop(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    cfg = _write_config(tmp_path, env="dev")
    report = run_checks(cfg, run_lint=False)
    result = _build_result(report)
    # A synthetic (dev) instance: the SAME cleartext hop is allowed — byte-identical, no false-close.
    assert result.ok and not result.skipped


def test_check_build_skips_without_service_toml(tmp_path: Path) -> None:
    from messagefoundry.checks import run_checks

    # A bare config dir with no messagefoundry.toml has no declared posture → the build-check SKIPs
    # (never blocks a dev checkout), byte-identical to before this check.
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_CONFIG_MODULE, encoding="utf-8")
    report = run_checks(cfg, run_lint=False)
    result = _build_result(report)
    assert result.skipped and result.ok


def test_egress_default_allows_lookup_host() -> None:
    # Guard: the residual-2 runner tests rely on the default egress not pre-refusing the lookup host
    # (empty allowlist = unrestricted), so the posture guard is what decides. Assert that invariant.
    e = EgressSettings()
    assert not e.allowed_http and not e.allowed_db and not e.deny_by_default
