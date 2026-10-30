# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2610, the Kerberos realm limb: a ticket signs in only from ``[auth].kerberos_realm``.

``kerberos_principal`` used to keep the text before the first ``@`` and drop the realm unread, so
``alice@REALM-A`` and ``alice@REALM-B`` both answered ``alice``. On a deployment whose KDC trusts
another realm, ``admin@PARTNER`` would then have signed in as the local ``admin``.

Pinned here, each with the probe that fails on the unfixed code:

* the principal's realm must equal the configured one up to ASCII case, and a principal with no
  realm, the ``DOMAIN\\user`` form, or a name that is not a bare account name is refused;
* settings refuse ``kerberos_enabled`` without a realm, and a malformed realm, at load, and never
  take the realm from ``ad_domain``;
* settings built without validation are refused at first use, before the acceptor is built;
* the service audits a refused principal as ``no_principal`` with its ``refusal`` reason, and
  never asks the directory.

No SPNEGO exchange runs: ``spnego.server`` is replaced by a stub that reports a finished context.
Which name form a real Windows SSPI acceptor reports is UNVERIFIED; no lab has run it.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest
import spnego
from pydantic import ValidationError

from messagefoundry.auth import ldap as ldap_mod
from messagefoundry.auth.ldap import (
    KERBEROS_PRINCIPAL_REFUSALS,
    KerberosPrincipalRefused,
    LdapError,
    kerberos_acceptor_preflight,
    kerberos_principal,
)
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings, check_kerberos_realm
from messagefoundry.pipeline import Engine

_REALM = "REALM-A"

_AD: dict[str, Any] = {
    "ad_enabled": True,
    "ad_server": "ldaps://dc.test.invalid",
    "ad_user_search_base": "DC=test,DC=invalid",
    "ad_bind_dn": "CN=svc,DC=test,DC=invalid",
    "ad_bind_password": "synthetic",
}


def _stub_acceptor(monkeypatch: pytest.MonkeyPatch, principal: str) -> list[dict[str, Any]]:
    """Make the acceptor a finished context naming ``principal``; return the build calls."""
    calls: list[dict[str, Any]] = []

    class _Server:
        client_principal = principal
        complete = True

        def step(self, _token: bytes) -> None:
            return None

    def fake_server(**kwargs: Any) -> _Server:
        calls.append(kwargs)
        return _Server()

    monkeypatch.setattr(spnego, "server", fake_server)
    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: True)
    return calls


# --- the principal ------------------------------------------------------------------------------


_SIGNS_IN = [
    # Controls: the configured realm signs in, whatever the ASCII case of either side.
    pytest.param(_REALM, "alice@REALM-A", id="same-realm"),
    pytest.param(_REALM, "alice@realm-a", id="same-realm-lower-case"),
    pytest.param("realm-a", "alice@REALM-A", id="lower-case-configured-realm"),
]

_REFUSED = [
    # The review's probe: the unfixed code answered alice for both realms.
    pytest.param(_REALM, "alice@REALM-B", "realm_mismatch", id="other-realm"),
    pytest.param(_REALM, "admin@PARTNER", "realm_mismatch", id="trusted-partner-admin"),
    pytest.param(_REALM, "alice@REALM-A.EVIL", "realm_mismatch", id="realm-with-a-suffix"),
    pytest.param(_REALM, "alice@", "realm_mismatch", id="empty-realm"),
    # The Kelvin sign lowers to an ASCII k, so without the ASCII test this one would match.
    pytest.param(
        "REALM-K", "alice@REALM-\N{KELVIN SIGN}", "realm_mismatch", id="non-ascii-realm-folds"
    ),
    pytest.param(_REALM, "alice", "no_realm", id="no-realm"),
    pytest.param(_REALM, "CORP\\alice", "domain_backslash_form", id="domain-backslash-form"),
    pytest.param(_REALM, "@REALM-A", "not_a_bare_account_name", id="empty-account"),
    pytest.param(
        _REALM, "alice\\@upn.example@REALM-A", "not_a_bare_account_name", id="escaped-enterprise"
    ),
    pytest.param(_REALM, "ann@bob@REALM-A", "not_a_bare_account_name", id="account-holding-an-at"),
    pytest.param(_REALM, "HTTP/web.example@REALM-A", "not_a_bare_account_name", id="service"),
]


@pytest.mark.parametrize(("realm", "principal"), _SIGNS_IN)
def test_the_configured_realm_signs_in(
    monkeypatch: pytest.MonkeyPatch, realm: str, principal: str
) -> None:
    _stub_acceptor(monkeypatch, principal)
    assert kerberos_principal(b"token", AuthSettings(kerberos_realm=realm)) == "alice"


@pytest.mark.parametrize(("realm", "principal", "reason"), _REFUSED)
def test_every_other_principal_is_refused_by_reason_alone(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    realm: str,
    principal: str,
    reason: str,
) -> None:
    """Fails on the unfixed code, which returned the text before the first ``@`` for each. Neither
    the refusal nor the log names any part of the principal: its account, its realm, or both."""
    _stub_acceptor(monkeypatch, principal)
    with (
        caplog.at_level(logging.WARNING, logger=ldap_mod.logger.name),
        pytest.raises(KerberosPrincipalRefused) as caught,
    ):
        kerberos_principal(b"token", AuthSettings(kerberos_realm=realm))
    assert caught.value.reason == reason
    messages = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert messages == [f"Kerberos sign-in refused the ticket's client principal: {reason}"]
    parts = [p for p in re.split(r"[@\\/]", principal) if p]
    for text in [*messages, str(caught.value)]:
        assert not [p for p in parts if p in text], text


def test_the_refusal_set_is_exercised_and_documented_whole() -> None:
    """SECURITY.md names the closed set an audit row's ``refusal`` field takes. A reason added in
    ldap.py alone, or dropped from the doc, fails here."""
    assert {p.values[2] for p in _REFUSED} == KERBEROS_PRINCIPAL_REFUSALS
    doc = (Path(__file__).resolve().parents[1] / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    listed = re.search(r"naming the case from a closed set \(([^)]*)\)", doc)
    assert listed is not None, "the Realm paragraph's closed-set list moved"
    assert set(re.findall(r"`([a-z_]+)`", listed.group(1))) == KERBEROS_PRINCIPAL_REFUSALS


# --- settings -----------------------------------------------------------------------------------


@pytest.mark.parametrize("realm", [None, ""])
def test_settings_refuse_kerberos_without_a_realm(realm: str | None) -> None:
    with pytest.raises(ValidationError, match="kerberos_enabled requires kerberos_realm"):
        AuthSettings(**_AD, kerberos_enabled=True, kerberos_realm=realm)


def test_the_realm_is_never_taken_from_ad_domain() -> None:
    # ad_domain is a UPN suffix and often differs from the realm, so it fills nothing in.
    with pytest.raises(ValidationError, match="kerberos_enabled requires kerberos_realm"):
        AuthSettings(**_AD, kerberos_enabled=True, ad_domain="corp.example")


def test_settings_accept_a_realm() -> None:
    s = AuthSettings(**_AD, kerberos_enabled=True, kerberos_realm="EXAMPLE.COM")
    assert s.kerberos_realm == "EXAMPLE.COM"


@pytest.mark.parametrize(
    "realm",
    [
        # Not EXAMPLE.COM: the error text's own example would then read as an echo.
        pytest.param("alice@CORP.TEST", id="principal"),
        pytest.param("CORP.TEST@X", id="at"),
        pytest.param("HTTP/CORP.TEST", id="slash"),
        pytest.param("CORP\\TEST", id="backslash"),
        pytest.param(" CORP.TEST", id="leading-space"),
        pytest.param("CORP TEST", id="inner-space"),
        pytest.param("CORP.TEST\x00", id="nul"),
        pytest.param("CORP.TES\N{KELVIN SIGN}", id="non-ascii"),
    ],
)
def test_settings_refuse_a_malformed_realm_without_echoing_it(realm: str) -> None:
    with pytest.raises(ValueError, match="kerberos_realm") as caught:
        check_kerberos_realm(realm)
    assert realm not in str(caught.value)
    with pytest.raises(ValidationError, match="kerberos_realm") as refused:
        AuthSettings(**_AD, kerberos_enabled=True, kerberos_realm=realm)
    # The text a loader or CLI prints, not only the inner ValueError.
    assert realm not in str(refused.value) and realm not in repr(refused.value)


@pytest.mark.parametrize("realm", [None, "", "alice@EXAMPLE.COM"])
def test_settings_built_without_validation_are_refused_before_the_acceptor(
    monkeypatch: pytest.MonkeyPatch, realm: str | None
) -> None:
    calls = _stub_acceptor(monkeypatch, "alice@EXAMPLE.COM")
    bad = AuthSettings.model_construct(kerberos_realm=realm)
    with pytest.raises(LdapError, match="kerberos_realm"):
        kerberos_principal(b"token", bad)
    with pytest.raises(LdapError, match="kerberos_realm"):
        kerberos_acceptor_preflight(bad)
    assert calls == []


# --- the service --------------------------------------------------------------------------------


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "kerberos_realm.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


class _UnaskedDirectory:
    """A directory that fails the test if asked: a refused principal must never reach it."""

    def resolve_principal(self, username: str, **_: object) -> Any:
        raise AssertionError(f"the directory was asked about {username!r}")


async def test_the_service_audits_another_realm_as_no_principal(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr("messagefoundry.auth.service._sleep_until", no_sleep)
    _stub_acceptor(monkeypatch, "admin@PARTNER")
    settings = AuthSettings(
        **_AD,
        kerberos_enabled=True,
        kerberos_realm=_REALM,
        login_rate_limit_enabled=False,
        require_mfa=False,
    )
    service = AuthService(engine.store, settings, ldap=_UnaskedDirectory())  # type: ignore[arg-type]
    await service.initialize()
    outcome = await service.authenticate_kerberos(b"token", client="192.0.2.7")
    assert not outcome.ok
    rows = [dict(r) for r in await engine.store.list_audit(action="auth.login_failed")]
    assert [json.loads(r["detail"]) for r in rows] == [
        {
            "provider": "ad",
            "mech": "kerberos",
            "reason": "no_principal",
            "refusal": "realm_mismatch",
        }
    ]
    assert rows[0]["actor"] == "<kerberos>"
    assert "PARTNER" not in json.dumps(rows)
