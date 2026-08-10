# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every `[vault]` client refuses redirects (BACKLOG #1042, ASVS 15.3.2 / 1.3.6).

Every other shipped HTTP egress routes through a no-redirect opener (`transports/rest.py`'s
`_NO_REDIRECT_OPENER`, and `auth/oidc_http.py`'s local twin for the IdP hop). The three `[vault]`
clients were the exception: they built an `hvac.Client` with no redirect policy, and hvac's default
is `allow_redirects=True` -- so on a first deployment an on-path 3xx (absent TLS integrity) or a
spoofed Vault could relocate a request carrying `X-Vault-Token` off-path.

**Why the fake, and what it does and does not prove.** `hvac` is the optional `[vault]` extra and CI
never installs it, so these tests stand a recording module in for it and assert what OUR code asks
for. That the request honours the ask was verified against the real library rather than assumed:
hvac 2.4.0's `Client.__init__` takes `allow_redirects` (defaulting to `True`), stores it on the
adapter, and the adapter passes `allow_redirects=self.allow_redirects` to `requests.Session.request`
-- measured 2026-08-10, and recorded here because a test cannot reach it in an environment without
the extra.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest


class _RecordingHvac:
    """A stand-in `hvac` module that records the kwargs each `Client(...)` was constructed with."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def Client(self, **kwargs: Any) -> Any:  # noqa: N802 — mirrors hvac's own class name
        self.calls.append(kwargs)
        return _FakeVaultClient()


class _FakeTransit:
    def read_key(self, *, name: str) -> dict[str, Any]:
        return {"data": {"name": name}}


class _FakeSecrets:
    def __init__(self) -> None:
        self.transit = _FakeTransit()


class _FakeVaultClient:
    def __init__(self) -> None:
        self.secrets = _FakeSecrets()


def _install_fake_hvac(monkeypatch: pytest.MonkeyPatch) -> _RecordingHvac:
    """Put a recording `hvac` in `sys.modules` so the lazy `import hvac` inside each provider
    resolves to it. Returns the recorder."""
    recorder = _RecordingHvac()
    module = types.ModuleType("hvac")
    module.Client = recorder.Client  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hvac", module)
    return recorder


# --- the two client factories ----------------------------------------------------------------


def test_store_key_provider_client_refuses_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """`store/keyprovider_vault.py` `_build_client` -- the KEK-unwrap client, and the one
    `store/crypto_transit.py` reuses.

    Mutation: drop `allow_redirects=False` from the `hvac.Client(...)` call. Red: the assertion
    reports the constructed kwargs, which then carry no redirect policy at all."""
    from messagefoundry.store import keyprovider_vault

    recorder = _install_fake_hvac(monkeypatch)
    keyprovider_vault._build_client("https://vault.example:8200", "s3cr3t-token")

    assert len(recorder.calls) == 1, "the provider must construct exactly one client"
    assert recorder.calls[0].get("allow_redirects") is False, (
        f"the store KEK client must refuse redirects; it was built with {recorder.calls[0].keys()}"
    )


def test_secret_provider_client_refuses_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """`config/secretprovider_vault.py` `_build_client` -- the KV v2 connector-credential client.

    Mutation: drop `allow_redirects=False`. Red: the assertion reports the constructed kwargs."""
    from messagefoundry.config import secretprovider_vault

    recorder = _install_fake_hvac(monkeypatch)
    secretprovider_vault._build_client("https://vault.example:8200", "s3cr3t-token")

    assert len(recorder.calls) == 1, "the provider must construct exactly one client"
    assert recorder.calls[0].get("allow_redirects") is False, (
        f"the KV secret client must refuse redirects; it was built with {recorder.calls[0].keys()}"
    )


def test_transit_cipher_client_refuses_redirects(monkeypatch: pytest.MonkeyPatch) -> None:
    """The third client, driven END TO END rather than by inspection: `build_transit_cipher` is the
    real entry point, and it is what proves the Transit cipher inherits the policy instead of
    quietly growing its own client construction.

    Mutation: give `crypto_transit` its own `hvac.Client(...)` call without the policy. Red: this
    test, where an identity assertion against `keyprovider_vault._build_client` would not
    necessarily be."""
    from messagefoundry.config.settings import StoreSettings
    from messagefoundry.store import crypto_transit

    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", "mefor-store-dek")
    monkeypatch.setenv("MEFOR_STORE_VAULT_ADDR", "https://vault.example:8200")
    monkeypatch.setenv("MEFOR_STORE_VAULT_TOKEN", "s3cr3t-token")
    monkeypatch.delenv("MEFOR_STORE_TRANSIT_AUDIT_KEY", raising=False)
    recorder = _install_fake_hvac(monkeypatch)

    crypto_transit.build_transit_cipher(StoreSettings())

    assert len(recorder.calls) == 1, "the Transit cipher must construct exactly one client"
    assert recorder.calls[0].get("allow_redirects") is False, (
        f"the Transit cipher client must refuse redirects; it was built with "
        f"{recorder.calls[0].keys()}"
    )


# --- the guard is not vacuous ------------------------------------------------------------------


def test_the_recorder_would_see_a_missing_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    """Live positive control for the three assertions above: the recorder reports a client built
    WITHOUT the policy as `None`, so a green above is a statement about the shipped call and not an
    artifact of the fake swallowing kwargs it does not recognise."""
    recorder = _install_fake_hvac(monkeypatch)
    import hvac  # noqa: PLC0415 — resolves to the fake installed just above

    hvac.Client(url="https://vault.example:8200", token="t")  # type: ignore[attr-defined]

    assert recorder.calls[0].get("allow_redirects") is None
    assert recorder.calls[0]["url"] == "https://vault.example:8200", (
        "the recorder must capture the kwargs verbatim, or the assertions above measure nothing"
    )
