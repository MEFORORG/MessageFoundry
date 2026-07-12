# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Posture-keyed transport-hop refusal — the ``db-inbound-cli`` cell group (#200, ADR 0092).

Covers three cells that consume the shared authority in ``config/tls_policy.py``:

* **DB egress/lookup** (``transports/database.py``): the customer-DB weakened-TLS (verify-off) refusal,
  routed through the ONE escape/predicate — a STRICT verify-off cell (refused for staging AND prod PHI),
  with the global escape CLAMPED so it can never relax a production hop, plus the per-connection
  ``tls_hop_attested`` opt-in and the zero-I/O send-time byte-crossing re-assertion.
* **Inbound listeners** (``pipeline/wiring_runner.py``): the four exposed-gate checks
  (MLLP/HTTP/DIMSE/TCP) with ``--allow-insecure-bind`` CLAMPED so a production-PHI listener refuses
  cleartext even with the flag.
* **CLI** (``__main__.py``): the ``[api]`` cleartext-bind ``--allow-insecure-bind`` clamp on a prod-PHI
  instance.

Store Postgres/SQL Server engine<->store TLS is exercised by the CI store legs; this file gates on
SQLite + pure logic only (no optional extras).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.tls_policy import (
    HopPosture,
    InsecureHopRefused,
    active_hop_posture,
)
from messagefoundry.pipeline.wiring_runner import (
    WiringError,
    _inbound_insecure_bind_permitted,
    check_dimse_tls_exposure,
    check_http_tls_exposure,
    check_mllp_tls_exposure,
    check_tcp_tls_exposure,
)
from messagefoundry.transports.database import (
    DatabaseDestination,
    _assert_send_hop,
    _build_dsn,
    _weakened_tls_permitted,
)

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

PROD_PHI = HopPosture(is_phi=True, production=True)
STAGING_PHI = HopPosture(is_phi=True, production=False)
DEV = HopPosture(is_phi=False, production=False)

_WEAK_DB = {"server": "s", "database": "d", "encrypt": False}


def _db_dest(**overrides: object) -> Destination:
    settings: dict[str, object] = {
        "server": "s",
        "database": "d",
        "statement": "INSERT INTO t (x) VALUES (:x)",
        "encrypt": False,
    }
    attested = bool(overrides.pop("tls_hop_attested", False))
    reason = overrides.pop("tls_hop_attested_reason", None)
    settings.update(overrides)
    return Destination(
        name="OB_DB",
        type=ConnectorType.DATABASE,
        settings=settings,
        tls_hop_attested=attested,
        tls_hop_attested_reason=reason,  # type: ignore[arg-type]
    )


# --- DB: the posture-keyed weakened-TLS permission predicate (_weakened_tls_permitted) ----------
def test_db_attestation_always_permits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(PROD_PHI):
        assert _weakened_tls_permitted(attested=True) is True


def test_db_prod_phi_refused_even_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # decision 2: the global escape is CLAMPED — it can never relax a production-PHI hop.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(PROD_PHI):
        assert _weakened_tls_permitted(attested=False) is False


def test_db_staging_phi_strict_without_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # decision 5: a verify-off cell that refuses staging PHI today MUST stay refused (not warn-and-cross).
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(STAGING_PHI):
        assert _weakened_tls_permitted(attested=False) is False


def test_db_staging_phi_escape_downgrades(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(STAGING_PHI):
        assert _weakened_tls_permitted(attested=False) is True  # non-prod escape honored


def test_db_unstamped_falls_back_to_unclamped_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    # Unstamped posture (runtime delivery build / embedding, outside build_check's gate) falls back to
    # the pre-#200 unclamped escape so a legitimately-escaped dev instance is not refused at delivery.
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    assert _weakened_tls_permitted(attested=False) is True
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    assert _weakened_tls_permitted(attested=False) is False


# --- DB: _build_dsn routes its verify-off refusal through the predicate --------------------------
def test_build_dsn_prod_phi_weak_tls_refused_with_escape(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="weakened"):
            _build_dsn(dict(_WEAK_DB))


def test_build_dsn_prod_phi_weak_tls_allowed_by_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(PROD_PHI):
        dsn = _build_dsn(dict(_WEAK_DB), attested=True)
    assert "Encrypt=no" in dsn


def test_build_dsn_staging_phi_trust_cert_refused_without_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with active_hop_posture(STAGING_PHI):
        with pytest.raises(ValueError, match="weakened"):
            _build_dsn({"server": "s", "database": "d", "trust_server_certificate": True})


def test_build_dsn_dev_synthetic_escape_allows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")
    with active_hop_posture(DEV):
        assert "Encrypt=no" in _build_dsn(dict(_WEAK_DB))


# --- DB: DatabaseDestination construction + send-time byte-crossing re-assertion -----------------
def test_database_destination_prod_phi_weak_tls_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ALLOW_INSECURE_TLS", "1")  # inert on prod-PHI (the clamp)
    with active_hop_posture(PROD_PHI):
        with pytest.raises(ValueError, match="weakened"):
            DatabaseDestination(_db_dest())


def test_database_destination_prod_phi_attested_constructs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    cfg = _db_dest(tls_hop_attested=True, tls_hop_attested_reason="mesh sidecar mTLS")
    with active_hop_posture(PROD_PHI):
        dest = DatabaseDestination(cfg)
    assert dest._weakened_tls is True
    assert dest._hop_attested is True


def test_assert_send_hop_refuses_weak_unpermitted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MEFOR_ALLOW_INSECURE_TLS", raising=False)
    with pytest.raises(InsecureHopRefused):
        _assert_send_hop(weakened=True, attested=False)


def test_assert_send_hop_noop_when_not_weakened() -> None:
    _assert_send_hop(weakened=False, attested=False)  # verifying TLS — nothing to assert


def test_assert_send_hop_permitted_when_attested() -> None:
    _assert_send_hop(weakened=True, attested=True)  # attested secure by other means


# --- INBOUND: the --allow-insecure-bind clamp predicate -----------------------------------------
@pytest.mark.parametrize(
    ("allow_flag", "attested", "posture", "expected"),
    [
        (False, True, PROD_PHI, True),  # attestation permits regardless of the flag
        (False, False, DEV, False),  # no flag -> refused (byte-identical to the shipped gate)
        (True, False, PROD_PHI, False),  # CLAMP: prod-PHI refuses cleartext even WITH the flag
        (True, False, STAGING_PHI, True),  # non-prod PHI: the flag is honored (warn)
        (True, False, DEV, True),  # synthetic: the flag is honored (warn)
        (True, False, None, True),  # unstamped (direct/embedding): shipped warn preserved
    ],
)
def test_inbound_insecure_bind_permitted(
    allow_flag: bool, attested: bool, posture: HopPosture | None, expected: bool
) -> None:
    assert (
        _inbound_insecure_bind_permitted(
            allow_insecure_bind=allow_flag, attested=attested, posture=posture
        )
        is expected
    )


# --- INBOUND: the four exposed-gate checks, posture-keyed ----------------------------------------
def _src(conn: ConnectorType, *, host: str = "0.0.0.0", tls: bool = False, attested: bool = False):
    settings: dict[str, object] = {"host": host}
    if tls:
        settings["tls"] = True
    return Source(type=conn, settings=settings, tls_hop_attested=attested)


_INBOUND_CHECKS = {
    ConnectorType.MLLP: check_mllp_tls_exposure,
    ConnectorType.HTTP: check_http_tls_exposure,
    ConnectorType.DIMSE: check_dimse_tls_exposure,
    ConnectorType.TCP: check_tcp_tls_exposure,
    ConnectorType.X12: check_tcp_tls_exposure,
}


@pytest.mark.parametrize("conn", list(_INBOUND_CHECKS))
def test_inbound_no_flag_refuses(conn: ConnectorType) -> None:
    check = _INBOUND_CHECKS[conn]
    with pytest.raises(WiringError):
        check(_src(conn), "IB", allow_insecure_bind=False, posture=DEV)


@pytest.mark.parametrize("conn", list(_INBOUND_CHECKS))
def test_inbound_flag_clamped_on_prod_phi(conn: ConnectorType) -> None:
    check = _INBOUND_CHECKS[conn]
    with pytest.raises(WiringError):
        check(_src(conn), "IB", allow_insecure_bind=True, posture=PROD_PHI)


@pytest.mark.parametrize("conn", list(_INBOUND_CHECKS))
def test_inbound_flag_honored_on_staging(conn: ConnectorType) -> None:
    check = _INBOUND_CHECKS[conn]
    check(_src(conn), "IB", allow_insecure_bind=True, posture=STAGING_PHI)  # warns, no raise


@pytest.mark.parametrize("conn", list(_INBOUND_CHECKS))
def test_inbound_attestation_crosses_prod_phi(conn: ConnectorType) -> None:
    check = _INBOUND_CHECKS[conn]
    check(
        _src(conn, attested=True), "IB", allow_insecure_bind=False, posture=PROD_PHI
    )  # attested, no raise


@pytest.mark.parametrize("conn", list(_INBOUND_CHECKS))
def test_inbound_loopback_passes(conn: ConnectorType) -> None:
    check = _INBOUND_CHECKS[conn]
    check(_src(conn, host="127.0.0.1"), "IB", allow_insecure_bind=False, posture=PROD_PHI)


def test_inbound_mllp_tls_on_passes() -> None:
    # A TLS-on MLLP listener passes unconditionally even on prod-PHI without the flag.
    check_mllp_tls_exposure(
        _src(ConnectorType.MLLP, tls=True), "IB", allow_insecure_bind=False, posture=PROD_PHI
    )


def test_inbound_unstamped_flag_honored() -> None:
    # An unstamped posture (a direct/embedding call outside the enforced serve/reload gate, which always
    # stamps a real posture) preserves the shipped --allow-insecure-bind warn (no raise).
    check_mllp_tls_exposure(_src(ConnectorType.MLLP), "IB", allow_insecure_bind=True, posture=None)


# --- CLI: the [api] cleartext-bind --allow-insecure-bind clamp (full serve, uvicorn mocked) ------
def test_serve_prod_phi_refuses_cleartext_even_with_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip(
        "psutil"
    )  # the serve path pulls api.metrics; psutil is a CI-installed extra
    from messagefoundry.__main__ import main
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())  # pass the keyless-PHI gate
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text(
        '[api]\nhost = "0.0.0.0"\n[egress]\ndeny_by_default = true\n', encoding="utf-8"
    )
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "prod", "--allow-insecure-bind"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "PRODUCTION PHI" in err and "--allow-insecure-bind cannot relax" in err


def test_serve_dev_synthetic_honors_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    pytest.importorskip(
        "psutil"
    )  # the serve path pulls api.metrics; psutil is a CI-installed extra
    from messagefoundry.__main__ import main
    from messagefoundry.store.crypto import generate_key

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    (tmp_path / "messagefoundry.toml").write_text('[api]\nhost = "0.0.0.0"\n', encoding="utf-8")
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev", "--allow-insecure-bind"])
    assert rc == 0
    err = capsys.readouterr().err
    assert "cleartext" in err  # the flag is honored (loud warning), not refused
    assert "PRODUCTION PHI" not in err
