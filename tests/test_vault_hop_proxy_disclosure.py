# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An environment proxy on a Vault hop is disclosed where it is used (vault BACKLOG #4028).

Owner ruling 2026-10-11: an ambient proxy must not attach silently, or must be disclosed. ``serve``
and ``supervise`` disclose one at start (``tests/test_ambient_proxy_disclosure.py``), but that read
is once, at start, and only in those two commands. ``check-privileges`` probes the configured
Vault, ``verify`` reads a ``*_ref`` OIDC credential from it, and a proxy can be set after start. So
the Vault clients' adapter names the proxy ``requests`` picked for a send, once per hop and proxy
per process. These tests drive the shipped clients and both commands through a loopback listener
standing in for the proxy, which hangs up on every connection, so nothing reaches a real Vault.
"""

from __future__ import annotations

import logging
import os
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

# The cleartext-hop tests' stand-in proxy: a loopback socket that hangs up on every connection.
from tests._vault_hop_sockets import _closed_port, _Listener

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_VAULT = "https://vault.synthetic.test:8200"
_SECRET = "s3cretpw"  # nosec B105 - a made-up proxy password, checked never to be echoed
_KV = "Vault KV secret provider"
_PICKED = "was picked for a request to Vault: "
_REASON = "synthetic test: the Vault certificate is short-lived"


@pytest.fixture(autouse=True)
def _clean_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only what a test sets may move the hop, and each test starts with nothing disclosed."""
    for name in list(os.environ):
        if name.lower().endswith("_proxy") or name.startswith(("MEFOR_", "VAULT_")):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.delenv("REQUEST_METHOD", raising=False)
    # With no *_proxy variable left, urllib falls back to the host's own system proxy.
    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    from messagefoundry.transports import strict_requests

    monkeypatch.setattr(strict_requests, "_CROSSINGS_LOGGED", set())
    # hvac reads these once, at import, so unsetting the env vars would not undo them.
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    for name in ("VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
        monkeypatch.setattr(hvac.v1, name, None, raising=False)


@pytest.fixture
def listener() -> Iterator[_Listener]:
    lst = _Listener()
    try:
        yield lst
    finally:
        lst.close()


def _disclosures(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [r for r in caplog.records if _PICKED in r.getMessage()]


# --- the disclosure itself ------------------------------------------------------------------------


def _disclose(connector: str, proxy: str | None) -> None:
    from messagefoundry.transports.strict_requests import _disclose_ambient_proxy

    _disclose_ambient_proxy(connector, proxy)


def test_one_proxy_is_named_once_per_hop_and_never_with_its_credential(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        for _ in range(3):
            _disclose(_KV, f"http://alice:{_SECRET}@proxy.example:3128")
    records = _disclosures(caplog)
    assert len(records) == 1, caplog.text
    text = records[0].getMessage()
    assert records[0].levelno == logging.WARNING
    assert text.startswith(
        f"{_KV}: a web proxy from the environment or the system proxy settings {_PICKED}"
        "http://proxy.example:3128. "
    )
    assert "No engine setting names it" in text
    assert "no_proxy" in text and "the system bypass list" in text
    assert "vault BACKLOG #4028" in text
    assert "alice" not in text and _SECRET not in text and "@" not in text


def test_a_new_proxy_or_another_hop_is_named_again(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        _disclose(_KV, "http://proxy.example:3128")
        _disclose(_KV, "http://other.example:8080")
        _disclose("Vault transit key provider", "http://proxy.example:3128")
        # Going back to a proxy already named for this hop does not name it again.
        _disclose(_KV, "http://proxy.example:3128")
    assert len(_disclosures(caplog)) == 3, caplog.text


@pytest.mark.parametrize("proxy", [None, ""])
def test_no_proxy_logs_nothing(proxy: str | None, caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING):
        _disclose(_KV, proxy)
    assert caplog.records == []


def test_a_proxy_value_that_does_not_parse_is_named_unreadable_never_echoed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        _disclose(_KV, f"http://alice:{_SECRET}@proxy.example:3128 ")
    text = _disclosures(caplog)[0].getMessage()
    assert f"{_PICKED}an unreadable value." in text
    assert _SECRET not in text and "proxy.example" not in text


def test_two_different_unreadable_proxies_are_each_named(caplog: pytest.LogCaptureFixture) -> None:
    """The dedupe key is the raw value's digest, not its label. Mutation: key on the label; red."""
    with caplog.at_level(logging.WARNING):
        _disclose(_KV, "http://proxy.example:3128 ")
        _disclose(_KV, "http://other.example:8080 ")
    assert len(_disclosures(caplog)) == 2, caplog.text


def test_a_proxy_the_two_parsers_read_differently_is_named_unreadable(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """urlsplit reads the host after the backslash and ``@``; urllib3, which dials, reads the one
    before it. Naming either would be wrong or could print the user part, so neither is named.
    Mutation: name proxy_label's answer alone; red, the WARNING names corp-proxy.example."""
    with caplog.at_level(logging.WARNING):
        _disclose(_KV, "https://proxy.dialled.example:443\\@corp-proxy.example:443")
    text = _disclosures(caplog)[0].getMessage()
    assert f"{_PICKED}an unreadable value." in text
    assert "corp-proxy.example" not in text and "proxy.dialled.example" not in text


# --- the shipped Vault clients --------------------------------------------------------------------


def _kv_client() -> Any:
    from messagefoundry.config import secretprovider_vault

    return secretprovider_vault._build_client(_VAULT, _TOKEN, revocation_attested=True)


def _store_client() -> Any:
    from messagefoundry.store import keyprovider_vault

    return keyprovider_vault._build_client(_VAULT, _TOKEN, revocation_attested=True)


_CLIENTS = pytest.mark.parametrize(
    ("build", "connector"),
    [(_kv_client, _KV), (_store_client, "Vault transit key provider")],
    ids=["kv-secret", "store"],
)


def _send(client: Any) -> None:
    import requests

    # The listener hangs up on the CONNECT, so the send fails after the pool is chosen.
    with pytest.raises(requests.exceptions.RequestException):
        client.adapter.get("v1/auth/token/lookup-self")


@_CLIENTS
@pytest.mark.parametrize("variable", ["HTTPS_PROXY", "ALL_PROXY"])
def test_each_vault_client_names_the_environment_proxy_it_sends_by(
    build: Any,
    connector: str,
    variable: str,
    monkeypatch: pytest.MonkeyPatch,
    listener: _Listener,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mutation: drop the call in ``get_connection_with_tls_context``; red, nothing logs."""
    monkeypatch.setenv(variable, listener.url)
    client = build()
    # The claim "no engine setting names it" rests on this: the engine passes hvac no proxies.
    assert client.adapter._kwargs.get("proxies") is None
    assert not client.adapter.session.proxies
    with caplog.at_level(logging.WARNING):
        _send(client)
        _send(client)
    assert listener.connections >= 1
    records = _disclosures(caplog)
    assert len(records) == 1, caplog.text
    assert records[0].getMessage().startswith(f"{connector}: ")
    assert f"{_PICKED}{listener.url}." in records[0].getMessage()


@_CLIENTS
def test_a_proxy_set_after_the_client_is_built_is_named_on_the_send_that_picks_it_up(
    build: Any,
    connector: str,
    monkeypatch: pytest.MonkeyPatch,
    listener: _Listener,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The start warning and the construction check read the proxy once. This one reads the proxy
    the send itself picked. Mutation: disclose at construction instead; red, nothing logs."""
    client = build()
    monkeypatch.setenv("HTTPS_PROXY", listener.url)
    with caplog.at_level(logging.WARNING):
        _send(client)
    assert listener.connections >= 1
    assert len(_disclosures(caplog)) == 1, caplog.text


def test_control_a_direct_send_or_a_bypassed_host_names_no_proxy(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener, caplog: pytest.LogCaptureFixture
) -> None:
    import requests

    from messagefoundry.config import secretprovider_vault

    direct = secretprovider_vault._build_client(
        f"https://127.0.0.1:{_closed_port()}", _TOKEN, revocation_attested=True
    )
    monkeypatch.setenv("HTTPS_PROXY", listener.url)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    with caplog.at_level(logging.WARNING), pytest.raises(requests.exceptions.RequestException):
        direct.adapter.get("v1/auth/token/lookup-self")
    assert listener.connections == 0
    assert _disclosures(caplog) == []


def test_control_a_send_with_no_proxy_set_names_none(caplog: pytest.LogCaptureFixture) -> None:
    import requests

    from messagefoundry.config import secretprovider_vault

    client = secretprovider_vault._build_client(
        f"https://127.0.0.1:{_closed_port()}", _TOKEN, revocation_attested=True
    )
    with caplog.at_level(logging.WARNING), pytest.raises(requests.exceptions.RequestException):
        client.adapter.get("v1/auth/token/lookup-self")
    assert _disclosures(caplog) == []


def test_a_send_refused_for_revocation_is_not_disclosed_as_picked(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener, caplog: pytest.LogCaptureFixture
) -> None:
    """A proxy set after start takes a loopback Vault off the box, and the send-time revocation
    guard then refuses it (vault BACKLOG #2983). Mutation: disclose before that guard; red."""
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.config.tls_policy import InsecureHopRefused

    client = secretprovider_vault._build_client(
        f"https://127.0.0.1:{_closed_port()}", _TOKEN, revocation_attested=False
    )
    monkeypatch.setenv("HTTPS_PROXY", listener.url)
    with caplog.at_level(logging.WARNING), pytest.raises(InsecureHopRefused):
        client.adapter.get("v1/auth/token/lookup-self")
    assert listener.connections == 0
    assert _disclosures(caplog) == []


def test_a_refused_send_is_not_disclosed_as_picked(
    monkeypatch: pytest.MonkeyPatch, listener: _Listener, caplog: pytest.LogCaptureFixture
) -> None:
    """A loopback ``http://`` Vault behind a proxy is refused when the adapter picks its pool
    (BACKLOG #2317), so the disclosure, which runs after that method's refusals, does not log. A
    refusal later in the send, such as at connect time, can still follow a disclosure."""
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.config.tls_policy import InsecureHopRefused

    client = secretprovider_vault._build_client(
        "http://127.0.0.1:9", _TOKEN, revocation_attested=False
    )
    monkeypatch.setenv("HTTP_PROXY", listener.url)
    with caplog.at_level(logging.WARNING), pytest.raises(InsecureHopRefused):
        client.adapter.get("v1/auth/token/lookup-self")
    assert listener.connections == 0
    assert _disclosures(caplog) == []


# --- the commands that reach Vault outside serve and supervise ------------------------------------


def test_check_privileges_names_the_proxy_its_vault_probe_sends_by(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    listener: _Listener,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.__main__ import main
    from messagefoundry.config.settings import StoreBackend, StorePrivilegeStatus, StoreSettings
    from messagefoundry.store.privilege import StorePrivilegeReport

    async def _probe(settings: StoreSettings, *, posture: Any = None) -> StorePrivilegeReport:
        return StorePrivilegeReport(
            backend=StoreBackend.SQLITE, status=StorePrivilegeStatus.NOT_APPLICABLE
        )

    monkeypatch.setattr("messagefoundry.store.base.probe_store_privileges", _probe)
    toml = tmp_path / "svc.toml"
    toml.write_text(
        '[store]\nkey_provider = "vault"\nvault_revocation_attested = true\n'
        f'vault_revocation_attested_reason = "{_REASON}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _VAULT)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("HTTPS_PROXY", listener.url)
    with caplog.at_level(logging.WARNING):
        code = main(["check-privileges", "--service-config", str(toml)])
    assert code == 4, caplog.text  # the probe could not observe Vault: the proxy hung up
    assert listener.connections >= 1
    records = _disclosures(caplog)
    assert len(records) == 1, caplog.text
    assert f"{_PICKED}{listener.url}." in records[0].getMessage()
    assert _TOKEN not in caplog.text


def test_verify_names_the_proxy_its_oidc_credential_read_sends_by(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    listener: _Listener,
    caplog: pytest.LogCaptureFixture,
) -> None:
    from messagefoundry.__main__ import main

    toml = tmp_path / "svc.toml"
    toml.write_text(
        '[security]\nweb_console_public_address = "https://ops.example"\n'
        '[secrets]\nprovider = "vault"\nvault_revocation_attested = true\n'
        f'vault_revocation_attested_reason = "{_REASON}"\n'
        "[auth]\nad_enabled = true\n"
        'ad_server = "ldaps://ad.synthetic.test"\n'
        'ad_user_search_base = "DC=synthetic,DC=test"\n'
        'ad_bind_dn = "CN=svc,DC=synthetic,DC=test"\n'
        'ad_bind_password = "synthetic-bind"\n'
        'ad_domain = "synthetic.test"\n'
        "oidc_enabled = true\n"
        'oidc_issuer = "https://idp.example"\n'
        'oidc_client_id = "mefor-console"\n'
        'oidc_client_secret_ref = "mefor/oidc#secret"\n'
        'oidc_authorization_endpoint = "https://idp.example/authorize"\n'
        'oidc_token_endpoint = "https://idp.example/token"\n'
        'oidc_jwks_uri = "https://idp.example/jwks"\n'
        'oidc_allowed_endpoints = ["idp.example"]\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _VAULT)
    monkeypatch.setenv("HTTPS_PROXY", listener.url)
    with caplog.at_level(logging.WARNING):
        main(["verify", "--section", "federation", "--service-config", str(toml)])
    assert listener.connections >= 1, caplog.text
    records = _disclosures(caplog)
    assert len(records) == 1, caplog.text
    assert records[0].getMessage().startswith(f"{_KV}: ")
    assert f"{_PICKED}{listener.url}." in records[0].getMessage()
    assert _TOKEN not in caplog.text
