# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #275: ``[auth].kerberos_spn`` reaches pyspnego split into ``service`` and ``hostname``.

pyspnego builds the acceptor SPN itself as ``"<service>/<hostname>"`` with ``hostname`` defaulting
to ``"unspecified"``. The engine used to pass the whole documented value (``HTTP/host.example.com``)
as ``service=``, so the acceptor principal came out ``HTTP/host.example.com/unspecified``.

Three layers are pinned here:

* the pure splitter, with the real library as the control: the split arguments build the intended
  SPN and the whole-value form builds the broken one;
* both acceptor call sites (the per-login step and the boot preflight) hand ``spnego.server`` the
  two halves separately -- these fail on the pre-fix code;
* a malformed value is refused at settings load, and again at first use if a caller bypasses the
  validator.

No lab is needed for any of this. Whether a live KDC and SSPI accept the corrected principal is a
separate, lab-only confirmation.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import spnego
from pydantic import ValidationError

from messagefoundry.auth import ldap as ldap_mod
from messagefoundry.auth.ldap import (
    LdapError,
    kerberos_acceptor_preflight,
    kerberos_principal,
)
from messagefoundry.config.settings import AuthSettings, split_kerberos_spn

_SPN = "HTTP/host.example.com"
_SPIKE = Path(__file__).resolve().parents[1] / "scripts" / "kerberos_epa_spike.py"

_MALFORMED = [
    pytest.param("HTTP", id="no-slash"),
    pytest.param("/host.example.com", id="empty-service"),
    pytest.param("HTTP/", id="empty-host"),
    pytest.param("HTTP/host.example.com/extra", id="two-slashes"),
    pytest.param("HTTP/host.example.com@EXAMPLE.COM", id="realm-suffix"),
    pytest.param("HTTP/host example.com", id="whitespace"),
    pytest.param(" HTTP/host.example.com", id="leading-space"),
    pytest.param("HTTP/host\x00.example.com", id="nul"),
    pytest.param("HTTP/host.example.com\x7f", id="del"),
]


# --- the splitter, with the real library as the control ---------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        pytest.param(_SPN, ("HTTP", "host.example.com"), id="documented"),
        pytest.param("HTTP/host.example.com:8443", ("HTTP", "host.example.com:8443"), id="port"),
        pytest.param("http/host.example.com", ("http", "host.example.com"), id="lower-case"),
    ],
)
def test_split_returns_service_then_hostname(value: str, expected: tuple[str, str]) -> None:
    # The port and case arms pin valid AD forms, so a later tightening cannot refuse them quietly.
    assert split_kerberos_spn(value) == expected


def test_real_pyspnego_builds_the_intended_spn_only_from_the_split_form() -> None:
    # The pure-Python negotiate proxy runs on every platform and needs no credential, so this is the
    # library's own SPN construction, not a mock of it.
    opts = spnego.NegotiateOptions.use_negotiate
    service, hostname = split_kerberos_spn(_SPN)
    fixed = spnego.server(hostname=hostname, service=service, options=opts)
    assert fixed.spn == _SPN
    # Control: the pre-fix call shape. If this stops producing the broken SPN, pyspnego changed.
    broken = spnego.server(service=_SPN, options=opts)
    assert broken.spn == "HTTP/host.example.com/unspecified"


@pytest.mark.parametrize("value", _MALFORMED)
def test_split_refuses_a_malformed_value(value: str) -> None:
    with pytest.raises(ValueError, match="kerberos_spn"):
        split_kerberos_spn(value)


# --- settings load -----------------------------------------------------------------------------


def test_settings_accept_the_documented_form() -> None:
    assert AuthSettings(kerberos_spn=_SPN).kerberos_spn == _SPN


@pytest.mark.parametrize("value", [None, ""])
def test_settings_accept_unset(value: str | None) -> None:
    assert AuthSettings(kerberos_spn=value).kerberos_spn == value


@pytest.mark.parametrize("value", _MALFORMED)
def test_settings_refuse_a_malformed_value_at_load(value: str) -> None:
    with pytest.raises(ValidationError, match="kerberos_spn"):
        AuthSettings(kerberos_spn=value)


# --- both call sites ---------------------------------------------------------------------------


class _FakeServer:
    client_principal = "alice@EXAMPLE.COM"

    def step(self, token: bytes) -> None:
        return None


@pytest.fixture
def server_calls(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []

    def fake_server(*args: Any, **kwargs: Any) -> _FakeServer:
        assert not args, "spnego.server must be called by keyword; hostname is its FIRST positional"
        calls.append(kwargs)
        return _FakeServer()

    monkeypatch.setattr(spnego, "server", fake_server)
    monkeypatch.setattr(ldap_mod, "_kerberos_capable", lambda: True)
    return calls


def test_login_step_passes_hostname_and_service_separately(
    server_calls: list[dict[str, Any]],
) -> None:
    assert kerberos_principal(b"token", AuthSettings(kerberos_spn=_SPN)) == "alice"
    assert server_calls == [{"hostname": "host.example.com", "service": "HTTP"}]


def test_preflight_passes_hostname_and_service_separately(
    server_calls: list[dict[str, Any]],
) -> None:
    kerberos_acceptor_preflight(AuthSettings(kerberos_spn=_SPN))
    assert server_calls == [{"hostname": "host.example.com", "service": "HTTP"}]


@pytest.mark.parametrize("value", [None, ""])
def test_unset_spn_keeps_the_library_default(
    server_calls: list[dict[str, Any]], value: str | None
) -> None:
    kerberos_acceptor_preflight(AuthSettings(kerberos_spn=value))
    assert server_calls == [{}]


def test_a_value_that_bypassed_the_validator_is_refused_at_first_use(
    server_calls: list[dict[str, Any]],
) -> None:
    # model_construct skips validation, standing in for any path that builds settings unchecked.
    bad = AuthSettings.model_construct(kerberos_spn="HTTP")
    with pytest.raises(LdapError, match="kerberos_spn"):
        kerberos_acceptor_preflight(bad)
    with pytest.raises(LdapError, match="kerberos_spn"):
        kerberos_principal(b"token", bad)
    assert server_calls == []


# --- the lab spike refuses what the engine refuses ----------------------------------------------


def test_the_lab_spike_run_by_path_refuses_a_malformed_spn() -> None:
    # Run by path in a subprocess, the way the lab runbook runs it, so the script's own import of the
    # engine splitter is exercised too. A refused SPN is a setup failure: exit 2, no exchange.
    env = {k: v for k, v in os.environ.items() if not k.startswith("MEFOR_SPIKE_")}
    env.update(
        MEFOR_SPIKE_SPN="HTTP/host.example.com@EXAMPLE.COM",
        MEFOR_SPIKE_USER="synthetic",
        MEFOR_SPIKE_PASS="synthetic",
        MEFOR_SPIKE_DOMAIN="EXAMPLE.COM",
    )
    result = subprocess.run(
        [sys.executable, str(_SPIKE)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=env,
        timeout=120,
        check=False,
    )
    assert result.returncode == 2, result.stderr
    assert "MEFOR_SPIKE_SPN is refused" in result.stdout
    assert "realm suffix" in result.stdout
