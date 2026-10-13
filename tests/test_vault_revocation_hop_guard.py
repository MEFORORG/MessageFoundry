# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The revocation guard on the three Vault hops (vault BACKLOG #2983, owner ruling 2026-10-13).

Each hop verifies the Vault server's certificate and checks no revocation. The guard refuses the
hop when the client is built, unless the Vault is on the box or the hop's own settings pair attests
that revocation is covered outside the engine. The guard is keyed on the instance posture, which
each caller hands down. A caller that holds none passes ``None``, and an unknown posture counts as
enforcing.

These tests drive the three shipped entry points with a real ``hvac`` client. Nothing reaches a
network: the one function urllib3 dials through records the address and fails.
``tests/test_vault_revocation_attestation.py`` holds the settings pair and the caller census.

Synthetic data only: every host, token, key name and reason here is made up.
"""

from __future__ import annotations

import ssl
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.secretprovider import SecretProviderError
from messagefoundry.config.settings import SecretsSettings, StoreSettings
from messagefoundry.config.tls_policy import (
    TLS_REVOCATION_ATTESTED_ENV,
    HopPosture,
    InsecureHopRefused,
    tls_revocation_attested,
)
from messagefoundry.store.keyprovider import KeyProviderError
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed

pytestmark = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)

_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential
_REASON = "the Vault server certificate lives 24 hours (synthetic)"
_HOST = "vault.synthetic.test"
_OFF_BOX = f"https://{_HOST}:8200"
_ON_BOX = "https://127.0.0.1:8200"
_PROXY_HOST = "proxy.synthetic.test"
_PROXY = f"http://{_PROXY_HOST}:3128"

#: Every variable that can move the hop or its decision, cleared so only what a test sets applies.
_HOP_ENV = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    "ALL_PROXY",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
    "VAULT_ADDR",
    "VAULT_CACERT",
    "VAULT_CAPATH",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
    "MEFOR_SECRETS_VAULT_ADDR",
    "MEFOR_SECRETS_VAULT_CA_FILE",
    "MEFOR_STORE_VAULT_ADDR",
    "MEFOR_STORE_VAULT_CA_FILE",
    TLS_REVOCATION_ATTESTED_ENV,
)


@pytest.fixture(autouse=True)
def _hop_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _HOP_ENV:
        monkeypatch.delenv(name, raising=False)
    # With no *_proxy variable left, urllib falls back to the host's own system proxy (Windows
    # Internet Settings, or macOS's), which would move the hop under these tests.
    import urllib.request

    monkeypatch.setattr(urllib.request, "getproxies_registry", dict, raising=False)
    monkeypatch.setattr(urllib.request, "getproxies_macosx_sysconf", dict, raising=False)
    monkeypatch.setattr(urllib.request, "proxy_bypass_registry", lambda host: False, raising=False)
    # hvac reads these once, at import, so unsetting the env vars would not undo them.
    import hvac.v1  # type: ignore[import-untyped]  # the [vault] extra ships no stubs

    for name in ("VAULT_CACERT", "VAULT_CAPATH", "VAULT_CLIENT_CERT", "VAULT_CLIENT_KEY"):
        monkeypatch.setattr(hvac.v1, name, None, raising=False)
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", _TOKEN)
    monkeypatch.setenv("MEFOR_STORE_VAULT_TRANSIT_KEY", "synthetic-kek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_WRAPPED_DEK", "vault:v1:c3ludGhldGlj")
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "synthetic-data-key")
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)


@pytest.fixture
def dials(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Every address urllib3 would dial. The dial itself fails, so no test reaches a network, and
    a hop that got past the guard fails closed on that with its provider's own error."""
    import urllib3.util.connection

    seen: list[object] = []

    def record(address: object, *args: Any, **kwargs: Any) -> Any:
        seen.append(address)
        raise OSError("synthetic: this test dials nothing")

    # urllib3.connection calls it through this module, so one patch covers every pool.
    monkeypatch.setattr(urllib3.util.connection, "create_connection", record)
    return seen


# --- the three shipped entry points -----------------------------------------------------------


def _pair(attested: bool) -> dict[str, Any]:
    if not attested:
        return {}
    return {"vault_revocation_attested": True, "vault_revocation_attested_reason": _REASON}


def _kv(
    monkeypatch: pytest.MonkeyPatch,
    addr: str | None,
    attested: bool = False,
    posture: HopPosture | None = None,
) -> Any:
    """The connector secret provider, from the dispatch every credential point calls."""
    from messagefoundry.config.secretprovider import resolve_secret_provider

    if addr is not None:
        monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", addr)
    provider = resolve_secret_provider(
        SecretsSettings(provider="vault", **_pair(attested)), posture=posture
    )
    assert provider is not None
    return provider.resolve("mefor/ad")


def _kek(
    monkeypatch: pytest.MonkeyPatch,
    addr: str | None,
    attested: bool = False,
    posture: HopPosture | None = None,
) -> Any:
    """The store key provider, from the cipher build ``open_store`` runs."""
    from messagefoundry.store.base import build_store_cipher

    if addr is not None:
        monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", addr)
    return build_store_cipher(
        StoreSettings(key_provider="vault", **_pair(attested)), posture=posture
    )


def _transit(
    monkeypatch: pytest.MonkeyPatch,
    addr: str | None,
    attested: bool = False,
    posture: HopPosture | None = None,
) -> Any:
    """The Transit cipher, from the cipher build ``open_store`` runs."""
    from messagefoundry.store.base import build_store_cipher

    if addr is not None:
        monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", addr)
    return build_store_cipher(
        StoreSettings(cipher_provider="vault_transit", **_pair(attested)), posture=posture
    )


EntryPoint = Callable[..., Any]
#: Each entry point's own fail-closed type, its connector label and the section its pair is in.
_HOPS: dict[EntryPoint, tuple[type[Exception], str, str]] = {
    _kv: (SecretProviderError, "Vault KV secret provider", "secrets"),
    _kek: (KeyProviderError, "Vault transit key provider", "store"),
    _transit: (KeyProviderError, "Vault transit key provider", "store"),
}
_ENTRY_POINTS = pytest.mark.parametrize(
    "entry", [_kv, _kek, _transit], ids=["kv-secret", "store-key", "transit"]
)
_FAIL_CLOSED = (SecretProviderError, KeyProviderError)


def _assert_refused(caught: pytest.ExceptionInfo[Exception], entry: EntryPoint) -> None:
    """The provider raised its own fail-closed type, caused by the marked refusal, with the
    refusal's fixed text kept whole. The text names this hop's settings pair and no other lever,
    and no part of the address or the proxy."""
    from messagefoundry.transports import strict_requests

    own, connector, section = _HOPS[entry]
    lever = {
        "store": strict_requests._STORE_REVOCATION_LEVER,
        "secrets": strict_requests._SECRETS_REVOCATION_LEVER,
    }[section]
    assert type(caught.value) is own
    assert type(caught.value.__cause__) is strict_requests.VaultHopRefused
    text = str(caught.value)
    assert text == f"{connector}: {strict_requests._UNREVOKED_VAULT_HOP} {lever}"
    assert f"[{section}].vault_revocation_attested = true" in text
    assert f"[{section}].vault_revocation_attested_reason" in text
    other = "secrets" if section == "store" else "store"
    for absent in (
        f"[{other}].",
        _HOST,
        _PROXY_HOST,
        "127.0.0.1",
        "8200",
        "3128",
        TLS_REVOCATION_ATTESTED_ENV,
        "crl_file",
    ):
        assert absent not in text, absent


def _assert_crossed(caught: pytest.ExceptionInfo[Exception], entry: EntryPoint) -> None:
    """The hop got past the guard: it failed on the dial this test refuses, not on a refusal."""
    assert type(caught.value) is _HOPS[entry][0]
    assert not isinstance(caught.value.__cause__, InsecureHopRefused)
    assert "vault_revocation_attested" not in str(caught.value)


@_ENTRY_POINTS
def test_an_off_box_vault_with_no_attestation_is_refused_before_anything_is_sent(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """RED before the change: each entry point built its client and dialled the Vault.
    Mutation: drop the ``_refuse_an_unrevoked_vault_hop`` call from ``mount_strict_reply_adapter``."""
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX)
    _assert_refused(caught, entry)
    assert dials == []


@_ENTRY_POINTS
def test_the_attestation_with_its_reason_crosses(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """The control for the refusal above, on the same address: the pair is the way across.
    Mutation: pass ``False`` for ``revocation_attested`` at the entry point's client build."""
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX, True)
    _assert_crossed(caught, entry)
    assert dials == [(_HOST, 8200)]


@_ENTRY_POINTS
def test_a_loopback_vault_with_no_proxy_needs_no_attestation(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """On the box: a revoked certificate on this machine is not the threat the guard is for.
    Mutation: pass ``is_loopback_hop=False`` to the authority."""
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _ON_BOX)
    _assert_crossed(caught, entry)
    assert dials == [("127.0.0.1", 8200)]


@_ENTRY_POINTS
@pytest.mark.parametrize("variable", ["HTTPS_PROXY", "ALL_PROXY"])
def test_a_loopback_vault_behind_a_proxy_is_refused(
    entry: EntryPoint, variable: str, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """A loopback address sent through a proxy is not on the box: the TLS session ends wherever
    the proxy sends it. Mutation: drop ``not proxy`` from ``on_box``."""
    monkeypatch.setenv(variable, _PROXY)
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _ON_BOX)
    _assert_refused(caught, entry)
    assert dials == []
    # The control: the same proxied hop crosses with the attestation, and it dials the proxy.
    with pytest.raises(_FAIL_CLOSED) as crossed:
        entry(monkeypatch, _ON_BOX, True)
    _assert_crossed(crossed, entry)
    assert dials == [(_PROXY_HOST, 3128)]


@_ENTRY_POINTS
@pytest.mark.parametrize("value", ["1", "true"])
def test_the_blanket_variable_does_not_cross_an_enforcing_hop(
    entry: EntryPoint, value: str, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """The control that the clamp holds (BACKLOG #299): the process-wide variable is a claim about
    every hop at once, so it sits below the enforcing refusal. Mutation: pass
    ``tls_revocation_attested()`` in the per-hop ``attested`` slot."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, value)
    # The premise: this environment does arm the blanket attestation.
    assert tls_revocation_attested() is True
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX)
    _assert_refused(caught, entry)
    assert dials == []


_ENFORCING = HopPosture(enforcing=True)
_NOT_ENFORCING = HopPosture(enforcing=False)


@_ENTRY_POINTS
@pytest.mark.parametrize("posture", [None, _ENFORCING], ids=["unknown", "enforcing"])
def test_an_unknown_posture_refuses_like_an_enforcing_one(
    entry: EntryPoint,
    posture: HopPosture | None,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
) -> None:
    """A caller that holds no posture passes ``None``, and ``None`` must never be a way across.
    The blanket variable is set here too, so this is also the clamp under both postures.
    Mutation: ``enforcing=False if posture is None else posture.enforcing`` in the guard."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX, False, posture)
    _assert_refused(caught, entry)
    assert dials == []


@_ENTRY_POINTS
def test_the_blanket_variable_crosses_only_under_a_posture_that_is_not_enforcing(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """The process-wide variable turns the warning into a silent crossing on an instance whose
    ``[security].enforcement`` is not ``enforce``, as it does on every other revocation guard.
    It reaches the guard only if every link hands the posture down, so this also proves the
    chain from the dispatch to the guard on each hop.
    Mutation: drop ``posture=posture`` from any link, such as ``build_store_cipher`` to
    ``_build_store_cipher``, or ``_build_client`` to the mount."""
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX, False, _NOT_ENFORCING)
    _assert_crossed(caught, entry)
    assert dials == [(_HOST, 8200)]


@pytest.mark.parametrize("provider", ["key_provider", "cipher_provider"])
def test_open_store_hands_its_posture_to_the_cipher_build(
    provider: str, monkeypatch: pytest.MonkeyPatch, dials: list[object], tmp_path: Any
) -> None:
    """``open_store`` is where ``serve`` and the commands that hold a posture enter the chain.
    Mutation: ``build_store_cipher(settings)`` in ``open_store``."""
    import asyncio

    from messagefoundry.store.base import open_store

    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _OFF_BOX)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    selected = (
        {"key_provider": "vault"}
        if provider == "key_provider"
        else {"cipher_provider": "vault_transit"}
    )
    settings = StoreSettings(path=str(tmp_path / "s.db"), **selected)

    async def opened(posture: HopPosture | None) -> None:
        await open_store(settings, create=True, posture=posture)

    with pytest.raises(KeyProviderError) as refused:
        asyncio.run(opened(None))
    assert "vault_revocation_attested" in str(refused.value)
    assert dials == []
    with pytest.raises(KeyProviderError) as crossed:
        asyncio.run(opened(_NOT_ENFORCING))
    assert "vault_revocation_attested" not in str(crossed.value)
    assert dials == [(_HOST, 8200)]


@_ENTRY_POINTS
def test_hvacs_own_vault_addr_fallback_is_the_hop_that_is_judged(
    entry: EntryPoint, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """With the ``MEFOR_*`` address unset, hvac dials ``VAULT_ADDR``. The guard reads the address
    the client holds, so an unset variable is neither waved through nor refused as unreadable."""
    monkeypatch.setenv("VAULT_ADDR", _OFF_BOX)
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, None)
    _assert_refused(caught, entry)
    assert dials == []
    monkeypatch.setenv("VAULT_ADDR", _ON_BOX)
    with pytest.raises(_FAIL_CLOSED) as crossed:
        entry(monkeypatch, None)
    _assert_crossed(crossed, entry)
    assert dials == [("127.0.0.1", 8200)]


def test_a_proxy_that_appears_after_construction_is_refused_before_sending(
    monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """The construction check reads the proxy once. A proxy that appears later takes a loopback
    Vault off the box, and the adapter checks again before each send. Mutation: drop the call in
    ``StrictReplyAdapter.get_connection_with_tls_context``."""
    from messagefoundry.config import secretprovider_vault
    from messagefoundry.transports.strict_requests import VaultHopRefused

    client = secretprovider_vault._build_client(_ON_BOX, _TOKEN, revocation_attested=False)
    monkeypatch.setenv("HTTPS_PROXY", _PROXY)
    with pytest.raises(VaultHopRefused, match=r"\[secrets\]\.vault_revocation_attested = true"):
        client.adapter.get("v1/secret/data/mefor/ad")
    assert dials == []


# --- the decision itself ----------------------------------------------------------------------


def _unchecked() -> ssl.SSLContext:
    return ssl.create_default_context()


def _refuse(url: str, proxy: str | None = None, **overrides: Any) -> None:
    from messagefoundry.transports.strict_requests import _refuse_an_unrevoked_vault_hop

    arguments: dict[str, Any] = {
        "connector": "Vault test hop",
        "ssl_context_factory": _unchecked,
        "revocation_attested": False,
        "attestation_section": "store",
    }
    _refuse_an_unrevoked_vault_hop(url, proxy, **{**arguments, **overrides})


@pytest.mark.parametrize("truthy", ["true", "false", 1, object()])
def test_only_the_value_true_counts_as_an_attestation(truthy: object) -> None:
    """``bool("false")`` is ``True``. A value that reached the guard past the typed setting must
    not cross on being truthy. Mutation: ``attested = bool(revocation_attested)``."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    with pytest.raises(VaultHopRefused):
        _refuse(_OFF_BOX, revocation_attested=truthy)
    _refuse(_OFF_BOX, revocation_attested=True)  # the control


def test_an_address_that_is_not_https_has_no_certificate_to_judge() -> None:
    """The cleartext refusal owns an ``http://`` address, and has already run. An address the
    parser cannot read is not ``https://`` either, and that refusal has refused it."""
    _refuse("http://127.0.0.1:8200")
    _refuse(f"http://{_HOST}:8200")
    _refuse("")


def test_a_context_that_checks_revocation_crosses_and_is_read_only_when_needed() -> None:
    """The decision reads the CRL flag off a context the factory builds, never off a setting. No
    CRL lever is built, so no shipped factory sets it; this pins that the read is live.
    Mutation: pass ``crl_checked=False``."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    built: list[ssl.SSLContext] = []

    def checking() -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        built.append(ctx)
        return ctx

    _refuse(_OFF_BOX, ssl_context_factory=checking)
    assert len(built) == 1
    # The control: the same call on a context without the flag refuses.
    with pytest.raises(VaultHopRefused):
        _refuse(_OFF_BOX)
    # On the box, or attested, the answer is already ALLOW, so no context is built for it.
    _refuse(_ON_BOX, ssl_context_factory=checking)
    _refuse(_OFF_BOX, ssl_context_factory=checking, revocation_attested=True)
    assert len(built) == 1


@pytest.mark.parametrize("url", ["https://localhost:8200", "https://[::1]:8200", _ON_BOX])
def test_loopback_is_decided_without_dns(url: str) -> None:
    from messagefoundry.transports.strict_requests import VaultHopRefused

    _refuse(url)
    # A name that only resolves to loopback is not proven on the box.
    with pytest.raises(VaultHopRefused):
        _refuse("https://localhost.synthetic.test:8200")
