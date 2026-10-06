# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2131: ``messagefoundry check`` reports the OIDC revocation refusal (ADR 0173 AC-4).

``serve`` refuses an off-box OIDC token or JWKS leg that checks no certificate revocation under an
enforcing posture (#1887). ``verify`` reported it as ``fed.idp_revocation`` (#1923); the commit/CI
gate did not. The ``oidc-revocation`` leg now reads the same decision, through
``verify/federation.py:idp_revocation_result``, so the two cannot disagree.

The FAIL arm alone would pass against a leg that always fails, so the arms that pass are the half
that shows it reads the right facts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from messagefoundry.checks import _check_oidc_revocation, run_checks
from messagefoundry.config.settings import SecurityEnforcement, ServiceSettings
from messagefoundry.config.tls_policy import TLS_REVOCATION_ATTESTED_ENV
from messagefoundry.verify.federation import idp_revocation_result
from messagefoundry.verify.model import Status

_OFF_BOX = {
    "oidc_token_endpoint": '"https://idp.example.invalid/token"',
    "oidc_jwks_uri": '"https://idp.example.invalid/jwks"',
}
_LOOPBACK = {
    "oidc_token_endpoint": '"https://127.0.0.1:8443/token"',
    "oidc_jwks_uri": '"https://127.0.0.1:8443/jwks"',
}


def _toml(tmp_path: Path, *, enforcement: str = "enforce", **auth: str) -> Path:
    """A minimal ``messagefoundry.toml`` with OIDC on. Synthetic values only."""
    merged = {
        "ad_enabled": "true",
        "ad_server": '"ldaps://dc.example.invalid"',
        "ad_user_search_base": '"dc=example,dc=invalid"',
        "ad_bind_dn": '"cn=svc,dc=example,dc=invalid"',
        "ad_bind_password": '"placeholder-not-a-real-secret"',
        "oidc_enabled": "true",
        "oidc_issuer": '"https://idp.example.invalid"',
        "oidc_client_id": '"mefor-console"',
        "oidc_client_secret": '"placeholder-not-a-real-secret"',
        "oidc_authorization_endpoint": '"https://idp.example.invalid/authorize"',
        "oidc_allowed_endpoints": '["idp.example.invalid", "127.0.0.1"]',
        "oidc_allowed_username_domains": '["example.invalid"]',
        **_OFF_BOX,
        **auth,
    }
    body = "\n".join(f"{k} = {v}" for k, v in merged.items())
    path = tmp_path / "messagefoundry.toml"
    path.write_text(
        '[store]\nbackend = "sqlite"\n\n'
        '[ai]\nenvironment = "dev"\n\n'
        f'[security]\nenforcement = "{enforcement}"\nblock_unlisted_outbound = true\n'
        'web_console_public_address = "https://mefor.example.invalid"\n\n'
        f"[auth]\n{body}\n",
        encoding="utf-8",
    )
    return path


def test_an_off_box_idp_with_no_crl_fails_the_gate(tmp_path: Path) -> None:
    result = _check_oidc_revocation(tmp_path, service_config=_toml(tmp_path))
    assert result.name == "oidc-revocation"
    assert result.required and not result.ok and not result.skipped, result.detail
    assert "refuses to start" in result.detail
    assert "OIDC token endpoint" in result.detail
    assert "OIDC jwks_uri endpoint" in result.detail


def test_on_box_legs_pass(tmp_path: Path) -> None:
    result = _check_oidc_revocation(tmp_path, service_config=_toml(tmp_path, **_LOOPBACK))
    assert result.required and result.ok and not result.skipped
    assert result.detail.startswith("PASS:"), result.detail


def test_a_warn_posture_passes_the_gate_as_manual(tmp_path: Path) -> None:
    """Under warn the engine starts, so failing the gate would refuse what serve allows. The legs
    still cross unchecked, so the line says a person must confirm it."""
    result = _check_oidc_revocation(tmp_path, service_config=_toml(tmp_path, enforcement="warn"))
    assert result.required and result.ok and not result.skipped
    assert result.detail.startswith("MANUAL:"), result.detail


def _missing(tmp_path: Path, name: str) -> str:
    """A TOML string naming a file that does not exist, as a CI runner sees a host-only path."""
    return f'"{(tmp_path / name).as_posix()}"'


def test_a_missing_anchor_does_not_hide_the_refusal(tmp_path: Path) -> None:
    """``check`` runs where the host's files may not be, such as CI. The anchor cannot change
    either leg's revocation decision, so the refusal is still decided and still fails."""
    toml = _toml(tmp_path, oidc_tls_ca_cert_file=_missing(tmp_path, "ca.pem"))
    result = _check_oidc_revocation(tmp_path, service_config=toml)
    assert result.required and not result.ok and not result.skipped
    assert "refuses to start" in result.detail
    assert "is not on this machine" in result.detail


def test_a_missing_anchor_alone_does_not_fail_the_gate(tmp_path: Path) -> None:
    """The control for the arm above: the same missing file with on-box legs passes, so a file
    absent on this machine is not by itself a failure. The line still names it."""
    toml = _toml(tmp_path, **_LOOPBACK, oidc_tls_ca_cert_file=_missing(tmp_path, "ca.pem"))
    result = _check_oidc_revocation(tmp_path, service_config=toml)
    assert result.required and result.ok and not result.skipped
    assert result.detail.startswith("PASS:"), result.detail
    assert "is not on this machine" in result.detail


def test_a_present_anchor_the_engine_refuses_fails_the_gate(tmp_path: Path) -> None:
    """A file that IS here and that the engine refuses is not the absent-file case: serve refuses
    to build the opener, so the gate must fail even with on-box legs."""
    ca = tmp_path / "ca.pem"
    ca.write_text("not a certificate\n", encoding="utf-8")
    toml = _toml(tmp_path, **_LOOPBACK, oidc_tls_ca_cert_file=f'"{ca.as_posix()}"')
    result = _check_oidc_revocation(tmp_path, service_config=toml)
    assert result.required and not result.ok and not result.skipped
    assert "does not build" in result.detail


def test_a_crl_file_the_engine_refuses_fails_the_gate(tmp_path: Path) -> None:
    """Settings load refuses a CRL path that is not a file. One that is a file but holds no CRL
    loads, and the engine then refuses to build the opener, so the gate fails too."""
    crl = tmp_path / "idp.crl"
    crl.write_text("not a CRL\n", encoding="utf-8")
    toml = _toml(tmp_path, **_LOOPBACK, oidc_tls_crl_file=f'"{crl.as_posix()}"')
    result = _check_oidc_revocation(tmp_path, service_config=toml)
    assert result.required and not result.ok and not result.skipped
    assert "CRL file" in result.detail


def test_federation_off_passes_without_a_guard(tmp_path: Path) -> None:
    result = _check_oidc_revocation(tmp_path, service_config=_toml(tmp_path, oidc_enabled="false"))
    assert result.required and result.ok and not result.skipped
    assert "oidc_enabled=false" in result.detail


def test_no_settings_file_skips(tmp_path: Path) -> None:
    result = _check_oidc_revocation(tmp_path, suppress_search=True)
    assert result.required and result.ok and result.skipped


_VALID_CONFIG = (
    "from messagefoundry import inbound, router, MLLP\n"
    "inbound('IB_2131', MLLP(port=2611), router='r')\n"
    "@router('r')\n"
    "def r(m): return []\n"
)


@pytest.mark.parametrize(("legs", "refused"), [(_OFF_BOX, True), (_LOOPBACK, False)])
def test_the_gate_fails_on_this_leg_alone(
    tmp_path: Path, legs: dict[str, str], refused: bool
) -> None:
    """The wiring arm. The config is valid, so with the legs on this host no leg blocks, and with
    them off-box this leg is the one that does."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(_VALID_CONFIG, encoding="utf-8")
    report = run_checks(cfg, run_lint=False, service_config=_toml(tmp_path, **legs))
    blocking = [r.name for r in report.results if r.blocking]
    assert blocking == (["oidc-revocation"] if refused else []), report.to_json()
    assert report.ok is not refused


def _settings(enforcement: SecurityEnforcement, legs: dict[str, Any]) -> ServiceSettings:
    auth: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_allowed_endpoints": ["idp.example", "127.0.0.1"],
        **legs,
    }
    return ServiceSettings.model_validate(
        {
            "auth": auth,
            "api": {"public_origin": "https://ops.example"},
            "security": {"enforcement": enforcement.value},
        }
    )


@pytest.mark.parametrize("enforcement", [SecurityEnforcement.ENFORCE, SecurityEnforcement.WARN])
@pytest.mark.parametrize(
    "legs",
    [
        {
            "oidc_token_endpoint": "https://idp.example/token",
            "oidc_jwks_uri": "https://idp.example/jwks",
        },
        {
            "oidc_token_endpoint": "https://127.0.0.1:8443/token",
            "oidc_jwks_uri": "https://127.0.0.1:8443/jwks",
        },
    ],
    ids=["off-box", "loopback"],
)
def test_the_attestation_env_never_moves_the_status(
    monkeypatch: pytest.MonkeyPatch, enforcement: SecurityEnforcement, legs: dict[str, Any]
) -> None:
    """The ledger's item 3. ``verify`` and ``check`` read ``MEFOR_TLS_REVOCATION_ATTESTED`` from
    their own environment, not the service's. That is safe to document rather than report MANUAL
    because the variable cannot move the status: under enforce it cannot cross a refusal (#299),
    and under warn it turns a WARN into an ALLOW that is MANUAL as well."""
    settings = _settings(enforcement, legs)
    monkeypatch.delenv(TLS_REVOCATION_ATTESTED_ENV, raising=False)
    without = idp_revocation_result(settings)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with_env = idp_revocation_result(settings)
    assert without.status is with_env.status, (without.detail, with_env.detail)
    # The arms are not all one status, or the comparison above could not tell anything apart.
    expected = {
        ("off-box", SecurityEnforcement.ENFORCE): Status.FAIL,
        ("off-box", SecurityEnforcement.WARN): Status.MANUAL,
        ("loopback", SecurityEnforcement.ENFORCE): Status.PASS,
        ("loopback", SecurityEnforcement.WARN): Status.PASS,
    }
    shape = "loopback" if "127.0.0.1" in legs["oidc_token_endpoint"] else "off-box"
    assert without.status is expected[(shape, enforcement)]
