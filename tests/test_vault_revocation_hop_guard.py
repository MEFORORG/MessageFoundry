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

import logging
import ssl
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.secretprovider import SecretProviderError
from messagefoundry.config.settings import SecretsSettings, ServiceSettings, StoreSettings
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
    # A crossing is logged once per process for each hop, so each test starts with none logged.
    from messagefoundry.transports import strict_requests

    monkeypatch.setattr(strict_requests, "_CROSSINGS_LOGGED", set())


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
    selected: dict[str, Any] = (
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
@pytest.mark.parametrize("vault_addr", [_OFF_BOX, _ON_BOX], ids=["off-box", "on-box"])
def test_an_unset_address_refuses_and_vault_addr_is_never_judged_or_dialled(
    entry: EntryPoint, vault_addr: str, monkeypatch: pytest.MonkeyPatch, dials: list[object]
) -> None:
    """BACKLOG #2851: with the ``MEFOR_*`` address unset, hvac used to dial ``VAULT_ADDR``, and
    this guard judged that address. There is no fallback now, so the provider refuses on the unset
    variable before any client is built, whatever ``VAULT_ADDR`` holds: an off-box one is not the
    hop the guard judges, and an on-box one is not dialled."""
    own, _, section = _HOPS[entry]
    monkeypatch.setenv("VAULT_ADDR", vault_addr)
    with pytest.raises(_FAIL_CLOSED, match=f"MEFOR_{section.upper()}_VAULT_ADDR is not set") as c:
        entry(monkeypatch, None)
    assert type(c.value) is own
    assert dials == []


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


def _refuse(
    url: str,
    proxy: str | None = None,
    *,
    ssl_context_factory: Callable[[], ssl.SSLContext] = _unchecked,
    **overrides: Any,
) -> None:
    """One call of the guard. The CRL flag is read off a context ``ssl_context_factory``
    builds, each time the guard asks; the adapter's kept read has its own test."""
    from messagefoundry.config.tls_policy import context_checks_revocation
    from messagefoundry.transports.strict_requests import _refuse_an_unrevoked_vault_hop

    arguments: dict[str, Any] = {
        "connector": "Vault test hop",
        "checks_revocation": lambda: context_checks_revocation(ssl_context_factory()),
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


# --- the three answers, and what each one logs ------------------------------------------------

_LOGGER = "messagefoundry.transports.strict_requests"
_CROSSED = "verified TLS hop crossed without certificate revocation checking"


def _crossing_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if record.name == _LOGGER and _CROSSED in record.getMessage()
    ]


def _assert_names_no_address(line: str) -> None:
    for absent in (_HOST, _PROXY_HOST, "8200", "3128", _TOKEN, "https://"):
        assert absent not in line, absent


@_ENTRY_POINTS
@pytest.mark.parametrize("posture", [None, _ENFORCING], ids=["unknown", "enforcing"])
def test_an_attested_crossing_is_logged_once_for_the_hop_with_its_reason(
    entry: EntryPoint,
    posture: HopPosture | None,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Enforcing with the attestation: the hop crosses, and the crossing is on the record. Three
    client builds in one process log one line, because the secret provider builds a client on
    every read and the key provider on every DR backup pass.
    Mutations: drop the ``log_attested_crossing`` call (no line); drop ``_first_crossing`` from
    its condition (three lines); pass no ``revocation_reason`` at the client build (no reason)."""
    from messagefoundry.secretscrub import scrub_credentials

    caplog.set_level(logging.WARNING, logger=_LOGGER)
    section = _HOPS[entry][2]
    for _ in range(3):
        with pytest.raises(_FAIL_CLOSED) as caught:
            entry(monkeypatch, _OFF_BOX, True, posture)
        _assert_crossed(caught, entry)
    assert dials == [(_HOST, 8200)] * 3
    (line,) = _crossing_lines(caplog)
    assert "on operator attestation" in line
    assert _HOPS[entry][1] in line
    assert f"[{section}].vault_revocation_attested; reason: {_REASON})" in line
    assert "no CRL lever is built" in line
    assert "Logged once per process for this hop" in line
    _assert_names_no_address(line)
    # The credential scrub on the log handlers leaves the line as it was written.
    assert scrub_credentials(line) == line


@_ENTRY_POINTS
def test_a_posture_that_is_not_enforcing_warns_once_and_crosses(
    entry: EntryPoint,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """``[security].enforcement = warn`` with no attestation: the hop crosses and says so, once
    per process. The line names the hop's own pair as the way to cross under ``enforce``.
    Mutations: delete the WARN arm, so WARN falls through to the refusal (the hop is refused);
    drop the ``logger.warning`` call (no line); drop ``_first_crossing`` (three lines)."""
    from messagefoundry.secretscrub import scrub_credentials

    caplog.set_level(logging.WARNING, logger=_LOGGER)
    section = _HOPS[entry][2]
    for _ in range(3):
        with pytest.raises(_FAIL_CLOSED) as caught:
            entry(monkeypatch, _OFF_BOX, False, _NOT_ENFORCING)
        _assert_crossed(caught, entry)
    assert dials == [(_HOST, 8200)] * 3
    (line,) = _crossing_lines(caplog)
    assert "because [security].enforcement is not enforce" in line
    assert _HOPS[entry][1] in line
    assert f"refused unless [{section}].vault_revocation_attested is true with its reason" in line
    assert "on operator attestation" not in line
    assert TLS_REVOCATION_ATTESTED_ENV not in line
    _assert_names_no_address(line)
    assert scrub_credentials(line) == line


@_ENTRY_POINTS
def test_the_crossings_that_log_nothing(
    entry: EntryPoint,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Three crossings write no line: a Vault on the box, an attested hop on an instance that
    is not enforcing, where the attestation crossed no refusal, and the blanket variable on such
    an instance. The controls are the two tests above, on the same address."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    with pytest.raises(_FAIL_CLOSED):
        entry(monkeypatch, _ON_BOX, False, _ENFORCING)
    with pytest.raises(_FAIL_CLOSED):
        entry(monkeypatch, _OFF_BOX, True, _NOT_ENFORCING)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(_FAIL_CLOSED):
        entry(monkeypatch, _OFF_BOX, False, _NOT_ENFORCING)
    assert len(dials) == 3
    assert _crossing_lines(caplog) == []


def test_a_refusal_logs_no_crossing(
    monkeypatch: pytest.MonkeyPatch, dials: list[object], caplog: pytest.LogCaptureFixture
) -> None:
    """A refused hop crossed nothing, and it does not use up the hop's one line."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    with pytest.raises(_FAIL_CLOSED):
        _kv(monkeypatch, _OFF_BOX, False, _ENFORCING)
    assert _crossing_lines(caplog) == []
    with pytest.raises(_FAIL_CLOSED):
        _kv(monkeypatch, _OFF_BOX, True, _ENFORCING)
    assert len(_crossing_lines(caplog)) == 1


def test_one_hop_crossed_both_ways_logs_each_once(
    monkeypatch: pytest.MonkeyPatch, dials: list[object], caplog: pytest.LogCaptureFixture
) -> None:
    """The key is the hop and the kind of crossing. The two store hops share one label, one
    address and one pair, so they share a line; the secret provider has its own."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    for entry in (_kek, _transit, _kv):
        with pytest.raises(_FAIL_CLOSED):
            entry(monkeypatch, _OFF_BOX, True, _ENFORCING)
        with pytest.raises(_FAIL_CLOSED):
            entry(monkeypatch, _OFF_BOX, False, _NOT_ENFORCING)
    lines = _crossing_lines(caplog)
    assert len(lines) == 4
    assert sum("Vault transit key provider" in line for line in lines) == 2
    assert sum("Vault KV secret provider" in line for line in lines) == 2
    assert sum("on operator attestation" in line for line in lines) == 2


@pytest.mark.parametrize(
    ("attested", "posture", "reads"),
    [
        # Warned: the answer could turn on the flag, so it is read, at the mount, once.
        (False, _NOT_ENFORCING, 1),
        # Attested: the answer is ALLOW without it, so no context is built to read it. The
        # client build then builds one context, the one the suite assertion checks.
        (True, _ENFORCING, 0),
        (True, _NOT_ENFORCING, 0),
    ],
    ids=["warned", "attested", "attested-not-enforcing"],
)
def test_the_crl_flag_is_read_once_for_a_client_however_many_times_it_sends(
    attested: bool,
    posture: HopPosture,
    reads: int,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
) -> None:
    """The guard runs at the mount and before every send, and the Transit cipher sends once per
    stored cell. Reading the flag builds a TLS context, so it is read off one context and kept.
    Mutation: ``return context_checks_revocation(self._ssl_context_factory())`` with no kept
    answer."""
    import requests

    from messagefoundry.config import secretprovider_vault
    from messagefoundry.config.tls_policy import context_checks_revocation
    from messagefoundry.transports import strict_requests

    seen: list[object] = []

    def counting(ctx: ssl.SSLContext | None) -> bool:
        seen.append(ctx)
        return context_checks_revocation(ctx)

    monkeypatch.setattr(strict_requests, "context_checks_revocation", counting)
    client = secretprovider_vault._build_client(
        _OFF_BOX,
        _TOKEN,
        revocation_attested=attested,
        posture=posture,
        revocation_reason=_REASON if attested else None,
    )
    assert len(seen) == reads
    for _ in range(4):
        with pytest.raises(requests.exceptions.ConnectionError):
            client.adapter.get("v1/secret/data/mefor/ad")
    assert len(dials) == 4
    assert len(seen) == reads


def test_one_hop_under_every_posture() -> None:
    """The decision table, on the guard itself: a posture that is not enforcing crosses with no
    attestation, and an enforcing or unknown one needs it."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    _refuse(_OFF_BOX, posture=_NOT_ENFORCING)
    for posture in (None, _ENFORCING):
        with pytest.raises(VaultHopRefused):
            _refuse(_OFF_BOX, posture=posture)
        _refuse(_OFF_BOX, posture=posture, revocation_attested=True)


def test_an_answer_the_guard_does_not_know_refuses(monkeypatch: pytest.MonkeyPatch) -> None:
    """ALLOW and WARN are named, and everything else refuses. So a fourth answer added to the
    shared authority later fails closed here.
    Mutation: ``if disposition is not HopDisposition.REFUSE: return`` in place of the WARN arm."""
    from messagefoundry.transports import strict_requests

    monkeypatch.setattr(strict_requests, "revocation_hop_disposition", lambda **_: object())
    with pytest.raises(strict_requests.VaultHopRefused):
        _refuse(_OFF_BOX, posture=_NOT_ENFORCING)


# --- the two check-privileges clients ---------------------------------------------------------
#
# `check-privileges` reads each Vault token's own grants through the client the provider builds.
# So the probe is held to the hop's revocation rule, with the hop's own attestation and the
# command's posture. Three consumers, two clients: the key provider and the Transit cipher share
# the store client.


def _consumer(kind: str) -> Any:
    from messagefoundry.privilege_check import VaultConsumer

    hop = "vault.secrets" if kind == "kv" else "vault.store"
    return VaultConsumer(hop, kind, kind, kind, ("mefor/ad",) if kind == "kv" else ())  # type: ignore[arg-type]


def _probe(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    *,
    attested: tuple[str, ...] = (),
    posture: HopPosture | None = None,
) -> tuple[str, ...]:
    """The problems one probe reports. ``attested`` names the sections whose pair is set."""
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.privilege_probes import probe_vault

    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _OFF_BOX)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _OFF_BOX)
    settings = ServiceSettings.model_validate({section: _pair(True) for section in attested})
    return probe_vault(_consumer(kind), settings, posture=posture).problems


_PROBES = pytest.mark.parametrize(
    ("kind", "section", "connector"),
    [
        ("kv", "secrets", "Vault KV secret provider"),
        ("kek", "store", "Vault transit key provider"),
        ("transit", "store", "Vault transit key provider"),
    ],
)


def _assert_probe_refused(problems: tuple[str, ...], section: str, connector: str) -> None:
    from messagefoundry.transports import strict_requests

    lever = {
        "store": strict_requests._STORE_REVOCATION_LEVER,
        "secrets": strict_requests._SECRETS_REVOCATION_LEVER,
    }[section]
    assert problems == (
        f"no Vault client: {connector}: {strict_requests._UNREVOKED_VAULT_HOP} {lever}",
    )
    assert _HOST not in problems[0]


@_PROBES
@pytest.mark.parametrize("posture", [None, _ENFORCING], ids=["unknown", "enforcing"])
def test_a_probe_of_an_off_box_vault_is_refused_without_its_hops_attestation(
    kind: str,
    section: str,
    connector: str,
    posture: HopPosture | None,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
) -> None:
    """The probe never raises: the refusal comes back as a problem, with the fixed text whole,
    and it names the pair this path reads. The OTHER section's pair is set here, and so is the
    blanket variable, and neither is a way across.
    Mutation: give either client the other section's ``vault_revocation_attested``."""
    other = "store" if section == "secrets" else "secrets"
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    problems = _probe(monkeypatch, kind, attested=(other,), posture=posture)
    _assert_probe_refused(problems, section, connector)
    assert dials == []


@_PROBES
@pytest.mark.parametrize("posture", [None, _ENFORCING], ids=["unknown", "enforcing"])
def test_a_probe_crosses_on_its_hops_attestation_and_logs_it_once(
    kind: str,
    section: str,
    connector: str,
    posture: HopPosture | None,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """RED before this change: both clients passed ``False``, so the probe refused an off-box
    Vault even with the pair set, and the refusal told the operator to set a flag this path
    ignored. Mutation: ``revocation_attested=False`` at either client's build."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    for _ in range(2):
        problems = _probe(monkeypatch, kind, attested=(section,), posture=posture)
        assert len(problems) == 1 and problems[0].startswith("token lookup-self failed")
        assert "vault_revocation_attested" not in problems[0]
    assert dials == [(_HOST, 8200)] * 2
    (line,) = _crossing_lines(caplog)
    assert connector in line
    assert f"[{section}].vault_revocation_attested; reason: {_REASON})" in line


@_PROBES
def test_a_probe_under_a_posture_that_is_not_enforcing_warns_and_crosses(
    kind: str,
    section: str,
    connector: str,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Mutation: drop ``posture=posture`` where ``probe_vault`` binds either client."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    for _ in range(2):
        problems = _probe(monkeypatch, kind, posture=_NOT_ENFORCING)
        assert len(problems) == 1 and problems[0].startswith("token lookup-self failed")
    assert dials == [(_HOST, 8200)] * 2
    (line,) = _crossing_lines(caplog)
    assert connector in line
    assert "because [security].enforcement is not enforce" in line
    assert f"unless [{section}].vault_revocation_attested is true" in line


@_PROBES
def test_the_blanket_variable_crosses_a_probe_only_where_the_posture_is_not_enforcing(
    kind: str,
    section: str,
    connector: str,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    _assert_probe_refused(_probe(monkeypatch, kind, posture=_ENFORCING), section, connector)
    assert dials == []
    problems = _probe(monkeypatch, kind, posture=_NOT_ENFORCING)
    assert len(problems) == 1 and problems[0].startswith("token lookup-self failed")
    assert dials == [(_HOST, 8200)]
    assert _crossing_lines(caplog) == []


# --- repairs from the first round of code review ----------------------------------------------


def test_a_posture_with_no_dial_is_enforcing() -> None:
    """``HopPosture`` is a plain dataclass, so nothing stops a caller building one whose dial is
    ``None``. Only the value ``False`` relaxes the guard.
    Mutation: ``enforcing = posture is None or posture.enforcing``."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    for dial in (None, 0, ""):
        with pytest.raises(VaultHopRefused):
            _refuse(_OFF_BOX, posture=HopPosture(enforcing=dial))  # type: ignore[arg-type]
    _refuse(_OFF_BOX, posture=HopPosture(enforcing=False))  # the control


def test_an_attested_crossing_never_reads_the_crl_flag(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An attested hop is allowed without the flag, and its line is written without it. So a
    context factory is never called on that path: it cannot fail there, and an attested client
    build makes no context beyond the one the suite assertion checks.
    Mutation: add ``and not checks_revocation()`` to the attested arm's condition."""
    from messagefoundry.transports.strict_requests import _refuse_an_unrevoked_vault_hop

    caplog.set_level(logging.WARNING, logger=_LOGGER)

    def never() -> bool:
        raise AssertionError("the attested path read the CRL flag")

    for _ in range(2):
        _refuse_an_unrevoked_vault_hop(
            _OFF_BOX,
            None,
            connector="Vault test hop",
            checks_revocation=never,
            revocation_attested=True,
            revocation_reason=_REASON,
            attestation_section="store",
        )
    assert len(_crossing_lines(caplog)) == 1


def test_the_restore_verify_hands_its_callers_posture_to_the_key_resolve(
    monkeypatch: pytest.MonkeyPatch, dials: list[object], tmp_path: Any
) -> None:
    """DR activation inside ``serve`` verifies its cold seed through ``run_restore_verify``, and
    the engine holds the posture. The ``restore-verify`` command holds none.
    Mutation: ``resolve_decrypt_keys(store_settings)`` in ``run_restore_verify``."""
    import asyncio

    from messagefoundry.pipeline.dr_backup import run_restore_verify

    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _OFF_BOX)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    settings = StoreSettings(key_provider="vault")
    archive = str(tmp_path / "absent.mfbak")

    with pytest.raises(KeyProviderError) as refused:
        asyncio.run(run_restore_verify(archive, store_settings=settings))
    assert "vault_revocation_attested" in str(refused.value)
    assert dials == []
    with pytest.raises(KeyProviderError) as crossed:
        asyncio.run(run_restore_verify(archive, store_settings=settings, posture=_NOT_ENFORCING))
    assert "vault_revocation_attested" not in str(crossed.value)
    assert dials == [(_HOST, 8200)]


@pytest.mark.parametrize(("enforcement", "crosses"), [("warn", True), ("enforce", False)])
def test_the_serve_path_upload_cipher_is_built_under_the_instance_posture(
    enforcement: str,
    crosses: bool,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    tmp_path: Any,
) -> None:
    """``serve`` builds the uploaded-logs cipher in ``create_app``, before its lifespan opens the
    store. That build is the first Vault dial of a start, so it takes the posture the lifespan
    derives. RED before the repair: it passed none, so a ``warn`` instance was refused here.
    Mutation: ``build_store_cipher(store_settings)`` in ``create_app``."""
    from messagefoundry.api.app import create_app
    from messagefoundry.config.settings import AiSettings, SecuritySettings

    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _OFF_BOX)
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(KeyProviderError) as caught:
        create_app(
            store_settings=StoreSettings(key_provider="vault", uploads_dir=str(tmp_path)),
            ai_settings=AiSettings(),
            security_settings=SecuritySettings(enforcement=enforcement),  # type: ignore[arg-type]
            allow_no_auth=True,
        )
    assert ("vault_revocation_attested" not in str(caught.value)) is crosses
    assert dials == ([(_HOST, 8200)] if crosses else [])


#: The OIDC client credential held in the Vault, by the row that reads it.
_CREDENTIALS: dict[str, dict[str, str]] = {
    "fed.client_secret": {"oidc_client_secret_ref": "mefor/oidc"},
    "fed.client_key": {
        "oidc_token_endpoint_auth_method": "private_key_jwt",
        "oidc_client_private_key_ref": "mefor/oidc-key",
        "oidc_client_assertion_algorithm": "ES256",
    },
}


def _verify_settings(
    enforcement: str, attested: bool, store_path: str, row: str = "fed.client_secret"
) -> ServiceSettings:
    """An instance whose OIDC client credential and store key are both held in an off-box Vault.
    ``row`` picks the credential: the client secret, or the ``private_key_jwt`` signing key."""
    settings = ServiceSettings.model_validate(
        {
            "security": {"enforcement": enforcement},
            "secrets": {"provider": "vault", **_pair(attested)},
            "store": {"path": store_path, "key_provider": "vault", **_pair(attested)},
            "auth": {
                # Federated logins resolve roles through AD, so the settings demand it.
                "ad_enabled": True,
                "ad_server": "ldaps://ad.synthetic.test",
                "ad_user_search_base": "DC=synthetic",
                "ad_bind_dn": "CN=svc,DC=synthetic",
                "ad_bind_password": "synthetic",  # nosec B105 - a made-up test value
                "ad_domain": "synthetic.test",
                "oidc_enabled": True,
                "oidc_issuer": "https://idp.synthetic.test",
                "oidc_client_id": "mefor-console",
                "oidc_authorization_endpoint": "https://idp.synthetic.test/authorize",
                "oidc_token_endpoint": "https://idp.synthetic.test/token",
                "oidc_jwks_uri": "https://idp.synthetic.test/jwks",
                "oidc_allowed_endpoints": ["idp.synthetic.test"],
                **_CREDENTIALS[row],
            },
            "api": {"public_origin": "https://ops.synthetic.test"},
        }
    )
    assert bool(settings.auth.oidc_private_key_jwt) is (row == "fed.client_key")
    return settings


@pytest.mark.parametrize("enforcement", ["warn", "enforce"])
def test_verify_judges_its_secrets_vault_hop_as_strictly_as_its_store_opens(
    enforcement: str, monkeypatch: pytest.MonkeyPatch, dials: list[object], tmp_path: Any
) -> None:
    """``verify`` holds no posture for its store opens (vault BACKLOG #2354), so it holds none for
    its secrets read either: one command dials neither unattested off-box Vault. A ``warn``
    instance is not a way across here, as it is in ``serve``; only the hop's own pair is.
    The store row FAILs on both postures. The credential row FAILs under ``enforce`` and is MANUAL
    under ``warn``, where ``serve`` would cross (vault BACKLOG #3619). Mutation: pass
    ``posture=hop_posture_from_ai(...)`` to ``resolve_secret_provider`` in
    ``_client_credential_row``; the ``warn`` case then dials."""
    from messagefoundry.verify.federation import _client_credential_row
    from messagefoundry.verify.model import Status
    from messagefoundry.verify.smoke import check_store_connectivity

    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _OFF_BOX)
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", _OFF_BOX)
    store = tmp_path / "store.db"
    store.write_bytes(b"")  # the store row's file gate looks for the file before it opens it

    refused = _verify_settings(enforcement, False, str(store))
    secret = _client_credential_row(refused)
    opened = check_store_connectivity(refused.store)
    expected = Status.MANUAL if enforcement == "warn" else Status.FAIL
    assert secret.status is expected, secret.detail
    assert "[secrets].vault_revocation_attested = true" in (secret.evidence or secret.detail)
    assert opened.status is Status.FAIL, opened.detail
    assert "[store].vault_revocation_attested = true" in opened.detail
    assert dials == []

    # The control, on the same address: the hop's own pair, with its reason, is the way across.
    # The read then fails on the dial this test refuses, so it reached the Vault.
    secret = _client_credential_row(_verify_settings(enforcement, True, str(store)))
    assert secret.status is Status.FAIL
    assert "vault_revocation_attested" not in secret.detail
    assert dials == [(_HOST, 8200)]


@pytest.mark.parametrize("row", sorted(_CREDENTIALS))
@pytest.mark.parametrize("blanket", [False, True], ids=["no-env", "blanket-env"])
@pytest.mark.parametrize("enforcement", ["warn", "enforce"])
def test_verify_reports_a_hop_serve_would_cross_as_manual_and_still_dials_nothing(
    enforcement: str,
    blanket: bool,
    row: str,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    tmp_path: Any,
) -> None:
    """Vault BACKLOG #3619. On ``warn`` the credential row is MANUAL, says ``serve`` would cross
    the hop, names the hop's own pair, and keeps the guard's refusal as evidence. Under
    ``enforce`` it stays FAIL with the refusal. ``MEFOR_TLS_REVOCATION_ATTESTED``, set in
    ``verify``'s own process, moves neither: ``verify``'s read is strict, so the variable crosses
    nothing there. ``verify`` dials the unattested Vault in no case.
    RED before the repair on ``warn``: the row was FAIL with the raw refusal and no word on
    ``serve``. Mutation: return ``None`` from ``_serve_crossing``, or drop its posture read."""
    from messagefoundry.transports import strict_requests
    from messagefoundry.verify.federation import _client_credential_row
    from messagefoundry.verify.model import Status

    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _OFF_BOX)
    if blanket:
        monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    result = _client_credential_row(
        _verify_settings(enforcement, False, str(tmp_path / "s.db"), row)
    )
    refusal = (
        f"Vault KV secret provider: {strict_requests._UNREVOKED_VAULT_HOP} "
        f"{strict_requests._SECRETS_REVOCATION_LEVER}"
    )
    assert result.id == row
    assert dials == []
    if enforcement == "enforce":
        assert result.status is Status.FAIL
        assert result.detail == refusal
        return
    assert result.status is Status.MANUAL, result.detail
    assert result.evidence == refusal
    assert "`serve` would dial it" in result.detail
    assert "log a WARNING" in result.detail
    assert TLS_REVOCATION_ATTESTED_ENV in result.detail
    assert "cannot say whether the reference resolves" in result.detail
    assert "[secrets].vault_revocation_attested pair" in result.detail


def test_a_classification_that_raises_keeps_the_reads_own_fail(
    monkeypatch: pytest.MonkeyPatch, dials: list[object], tmp_path: Any
) -> None:
    """The classification must not raise out of the check, nor hide the read's failure behind its
    own. Mutation: let the classifier's exception propagate, or report it in place of the refusal.
    """
    from messagefoundry.transports import strict_requests
    from messagefoundry.verify.federation import _client_credential_row
    from messagefoundry.verify.model import Status

    def broken(exc: BaseException | None, section: str) -> bool:
        raise RuntimeError("synthetic classifier fault")

    monkeypatch.setattr(strict_requests, "is_unrevoked_vault_hop_refusal", broken)
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _OFF_BOX)
    result = _client_credential_row(_verify_settings("warn", False, str(tmp_path / "s.db")))
    assert result.status is Status.FAIL
    assert "[secrets].vault_revocation_attested = true" in result.detail
    assert "synthetic classifier fault" in (result.evidence or "")
    assert dials == []


def test_any_other_refusal_of_the_hop_stays_a_fail_on_warn(
    monkeypatch: pytest.MonkeyPatch, dials: list[object], tmp_path: Any
) -> None:
    """Only the revocation refusal is one ``serve`` would cross on ``warn``. A cleartext off-box
    Vault is refused at every posture, so its row stays FAIL. The control is the same instance on
    ``https``, which is MANUAL. Mutation: treat every ``VaultHopRefused`` as the revocation one."""
    from messagefoundry.verify.federation import _client_credential_row
    from messagefoundry.verify.model import Status

    settings = _verify_settings("warn", False, str(tmp_path / "s.db"))
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", f"http://{_HOST}:8200")
    cleartext = _client_credential_row(settings)
    assert cleartext.status is Status.FAIL, cleartext.detail
    assert "vault_revocation_attested" not in cleartext.detail
    monkeypatch.setenv("MEFOR_SECRETS_VAULT_ADDR", _OFF_BOX)
    assert _client_credential_row(settings).status is Status.MANUAL
    assert dials == []


def test_the_revocation_refusal_is_told_apart_by_type_and_whole_text() -> None:
    """The classifier takes the exact type and the whole fixed text after the label, for one
    section. Each section's real refusal, raised by the guard, is it, and only for its own
    section. A substring, a subclass or another refusal is not it. Mutation: compare with ``in``
    rather than ``==``, use ``isinstance``, or let the two raise texts drift from the table."""
    from messagefoundry.transports import strict_requests
    from messagefoundry.transports.strict_requests import (
        VaultAttestationSection,
        VaultHopRefused,
        is_unrevoked_vault_hop_refusal,
    )

    pairs: tuple[tuple[VaultAttestationSection, VaultAttestationSection], ...] = (
        ("secrets", "store"),
        ("store", "secrets"),
    )
    for section, wrong in pairs:
        with pytest.raises(VaultHopRefused) as raised:
            _refuse(_OFF_BOX, attestation_section=section)
        assert is_unrevoked_vault_hop_refusal(raised.value, section), section
        assert not is_unrevoked_vault_hop_refusal(raised.value, wrong), section

    reason = strict_requests._UNREVOKED_VAULT_HOP_REASONS
    exact = VaultHopRefused(f"Vault KV secret provider: {reason['secrets']}")

    class _Elsewhere(VaultHopRefused):
        pass

    for other in (
        _Elsewhere(str(exact)),
        InsecureHopRefused(str(exact)),
        VaultHopRefused(f"{exact} and more"),
        VaultHopRefused(f"label: prefix {reason['secrets']}"),
        VaultHopRefused(reason["secrets"]),
        VaultHopRefused(f"label: {strict_requests._CLEARTEXT_VAULT_HOP}"),
    ):
        assert not is_unrevoked_vault_hop_refusal(other, "secrets"), str(other)


# --- the TLS leg to an https:// proxy (vault BACKLOG #3561) ----------------------------------
#
# Proxy credentials and the Vault host name cross that leg on its TLS alone. Its guard decides
# on the hop's own posture and attestation, off the leg's own context, before its socket opens.

_HTTPS_PROXY = f"https://{_PROXY_HOST}:3128"
#: The proxy leg guard's arguments, unless a test overrides one: unattested, unknown posture.
_PROXY_LEG_GUARD: dict[str, Any] = {
    "connector": "Vault test hop",
    "revocation_attested": False,
    "attestation_section": "store",
}


def _proxy_leg(
    proxy_host: str | None = _PROXY_HOST,
    *,
    context: ssl.SSLContext | None = None,
    **overrides: Any,
) -> None:
    """One call of the proxy leg's guard, on an unchecked context unless one is given."""
    from messagefoundry.transports.strict_requests import _refuse_an_unrevoked_proxy_leg

    _refuse_an_unrevoked_proxy_leg(
        context if context is not None else _unchecked(),
        proxy_host,
        **{**_PROXY_LEG_GUARD, **overrides},
    )


@pytest.mark.parametrize("section", ["store", "secrets"])
@pytest.mark.parametrize("posture", [None, _ENFORCING], ids=["unknown", "enforcing"])
def test_an_unattested_proxy_leg_is_refused_with_fixed_text(
    section: Any, posture: HopPosture | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED before the change: nothing judged this leg. The text names the hop's own pair, says
    the reason must cover the proxy's certificate, and names no host, port or other lever. The
    blanket variable is set too, so this is also the clamp. Mutation: drop the guard."""
    from messagefoundry.transports import strict_requests

    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    with pytest.raises(strict_requests.VaultHopRefused) as caught:
        _proxy_leg(posture=posture, attestation_section=section)
    lever = {
        "store": strict_requests._STORE_PROXY_LEG_LEVER,
        "secrets": strict_requests._SECRETS_PROXY_LEG_LEVER,
    }[section]
    text = str(caught.value)
    assert text == f"Vault test hop: {strict_requests._UNREVOKED_PROXY_LEG} {lever}"
    assert f"[{section}].vault_revocation_attested = true" in text
    assert "proxy's certificate" in text
    other = "secrets" if section == "store" else "store"
    for absent in (f"[{other}].", _PROXY_HOST, "3128", TLS_REVOCATION_ATTESTED_ENV, "crl_file"):
        assert absent not in text, absent
    # A proxy-leg refusal is not the Vault leg's, so `verify` does not read it as one.
    assert not strict_requests.is_unrevoked_vault_hop_refusal(caught.value, section)


def test_the_proxy_leg_under_every_posture(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """The decision table, on the proxy leg's guard: the hop's attestation crosses it under any
    posture, a posture that is not enforcing warns, and the blanket variable crosses only there,
    silently. Mutations: pass ``enforcing=True`` to the authority (the warn row refuses); pass
    ``blanket_attested=False`` (the blanket row warns)."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    caplog.set_level(logging.WARNING, logger=_LOGGER)
    _proxy_leg(posture=_NOT_ENFORCING, connector="warned hop")
    assert any("warned hop" in line for line in _proxy_leg_lines(caplog))
    for posture in (None, _ENFORCING, _NOT_ENFORCING):
        _proxy_leg(posture=posture, revocation_attested=True)
    caplog.clear()
    monkeypatch.setenv(TLS_REVOCATION_ATTESTED_ENV, "1")
    _proxy_leg(posture=_NOT_ENFORCING, connector="blanket hop")
    assert _proxy_leg_lines(caplog) == []
    with pytest.raises(VaultHopRefused):
        _proxy_leg(posture=_ENFORCING)


@pytest.mark.parametrize("section", ["store", "secrets"])
def test_the_vault_legs_refusal_names_the_proxys_certificate(section: Any) -> None:
    """The Vault leg's guard refuses a proxied hop first, so its lever is the one an operator
    reads, and it must say the attestation covers the proxy's certificate too. Mutation: drop
    the proxy clause from ``_STORE_REVOCATION_LEVER``."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    with pytest.raises(VaultHopRefused) as caught:
        _refuse(_OFF_BOX, _HTTPS_PROXY, attestation_section=section)
    assert "https:// proxy's certificate" in str(caught.value)
    assert _PROXY_HOST not in str(caught.value)


@pytest.mark.parametrize("truthy", ["true", 1, object()])
def test_only_the_value_true_attests_the_proxy_leg(truthy: object) -> None:
    """Mutation: ``attested = bool(revocation_attested)`` in the proxy leg's guard."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    with pytest.raises(VaultHopRefused):
        _proxy_leg(revocation_attested=truthy)
    _proxy_leg(revocation_attested=True)  # the control


@pytest.mark.parametrize("host", ["127.0.0.1", "[::1]", "::1", "localhost"])
def test_a_proxy_on_a_loopback_address_needs_no_attestation(host: str) -> None:
    """The leg ends on this machine, decided without DNS. Mutation: ``on_box = False``."""
    from messagefoundry.transports.strict_requests import VaultHopRefused

    _proxy_leg(host)
    # A name that only resolves to loopback is not proven on the box, and no host is not either.
    for off_box in ("localhost.synthetic.test", "", None):
        with pytest.raises(VaultHopRefused):
            _proxy_leg(off_box)


def test_a_proxy_leg_whose_own_context_checks_a_crl_crosses() -> None:
    """The flag is read off the leg's own context, never off a setting, so a later CRL lever
    that reaches the context needs no edit here. Mutation: pass ``crl_checked=False``."""
    checking = ssl.create_default_context()
    checking.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    _proxy_leg(context=checking)


def test_a_proxy_leg_answer_the_guard_does_not_know_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: ``if disposition is not HopDisposition.REFUSE: return`` in the proxy guard."""
    from messagefoundry.transports import strict_requests

    monkeypatch.setattr(strict_requests, "revocation_hop_disposition", lambda **_: object())
    with pytest.raises(strict_requests.VaultHopRefused):
        _proxy_leg(posture=_NOT_ENFORCING)


def _proxied_connection(**overrides: Any) -> Any:
    """A narrowed connection to the Vault through an https proxy, as the adapter's pool opens it,
    with the real proxy leg guard bound as the adapter binds it."""
    import functools

    from urllib3.connection import ProxyConfig
    from urllib3.util import parse_url

    from messagefoundry.transports import strict_requests

    classes = strict_requests._narrowed_pool_classes(
        ssl.create_default_context,
        connector=_PROXY_LEG_GUARD["connector"],
        judge_proxy_leg=functools.partial(
            strict_requests._refuse_an_unrevoked_proxy_leg, **{**_PROXY_LEG_GUARD, **overrides}
        ),
    )
    # As urllib3's proxy pool builds it: the connection dials the proxy and tunnels to Vault.
    conn = classes["https"].ConnectionCls(
        _PROXY_HOST,
        3128,
        proxy=parse_url(_HTTPS_PROXY),
        proxy_config=ProxyConfig(
            ssl_context=None,
            use_forwarding_for_https=False,
            assert_hostname=None,
            assert_fingerprint=None,
        ),
    )
    conn.set_tunnel(_HOST, 8200, scheme="https")
    return conn


def test_the_proxy_leg_is_refused_before_its_socket_opens(dials: list[object]) -> None:
    """The guard runs in the connection's ``connect``, before the socket, so before ``CONNECT``
    and any proxy credentials cross. Mutation: drop the guard's call from
    ``_narrow_the_proxy_leg``."""
    from urllib3.exceptions import NewConnectionError

    from messagefoundry.transports.strict_requests import VaultHopRefused

    with pytest.raises(VaultHopRefused, match=r"\[store\]\.vault_revocation_attested = true"):
        _proxied_connection().connect()
    assert dials == []
    # The control: the same connection, attested, goes on to dial the proxy.
    with pytest.raises(NewConnectionError, match="this test dials nothing"):
        _proxied_connection(revocation_attested=True).connect()
    assert dials == [(_PROXY_HOST, 3128)]


def _proxy_leg_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [line for line in _crossing_lines(caplog) if "https:// proxy" in line]


def test_each_proxy_leg_crossing_is_logged_once_for_the_hop(
    dials: list[object], caplog: pytest.LogCaptureFixture
) -> None:
    """Warned and attested crossings of the leg each log one line per process for the hop,
    however many connections cross, and neither names an address. A leg that checks a CRL logs
    no warning. Mutations: drop either ``_first_crossing`` (three lines of a kind); drop
    ``kind`` from the kinds (the proxy leg shares the Vault leg's line)."""
    from urllib3.exceptions import NewConnectionError

    from messagefoundry.secretscrub import scrub_credentials

    caplog.set_level(logging.WARNING, logger=_LOGGER)
    crossings: tuple[dict[str, Any], ...] = (
        {"posture": _NOT_ENFORCING},
        {"posture": _ENFORCING, "revocation_attested": True, "revocation_reason": _REASON},
    )
    for _ in range(3):
        for overrides in crossings:
            with pytest.raises(NewConnectionError, match="this test dials nothing"):
                _proxied_connection(**overrides).connect()
    assert len(dials) == 6
    warned, attested = sorted(_proxy_leg_lines(caplog), key=lambda line: "attestation" in line)
    assert "because [security].enforcement is not enforce" in warned
    assert "refused unless [store].vault_revocation_attested is true" in warned
    assert "on operator attestation" in attested
    assert f"[store].vault_revocation_attested; reason: {_REASON})" in attested
    for line in (warned, attested):
        assert "Vault test hop" in line
        assert "Logged once per process for this hop" in line
        # Not `_assert_names_no_address`: these lines name the leg as "https:// proxy".
        for absent in (_HOST, _PROXY_HOST, "8200", "3128", _TOKEN):
            assert absent not in line, absent
        assert scrub_credentials(line) == line
    # An unattested leg whose own context checks a CRL crosses on that, with no warning.
    caplog.clear()
    checking = ssl.create_default_context()
    checking.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    _proxy_leg(context=checking, posture=_NOT_ENFORCING, connector="other")
    assert _proxy_leg_lines(caplog) == []


@_ENTRY_POINTS
def test_each_entry_point_hands_its_posture_to_the_proxy_leg(
    entry: EntryPoint,
    monkeypatch: pytest.MonkeyPatch,
    dials: list[object],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Through an https proxy on a warn instance, both legs cross with a line each, and the hop
    dials the proxy. The posture reaches the proxy leg only if the adapter binds it into the
    guard it hands its pool classes. Mutation: bind ``posture=None`` there (the leg is
    refused)."""
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    monkeypatch.setenv("HTTPS_PROXY", _HTTPS_PROXY)
    with pytest.raises(_FAIL_CLOSED) as caught:
        entry(monkeypatch, _OFF_BOX, False, _NOT_ENFORCING)
    _assert_crossed(caught, entry)
    assert dials == [(_PROXY_HOST, 3128)]
    (proxy_line,) = _proxy_leg_lines(caplog)
    assert _HOPS[entry][1] in proxy_line
    assert len(_crossing_lines(caplog)) == 2
