# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5609: the Transit cipher renews the store token it read once at build.

The fake Vault below holds one token with a TTL on a clock the test moves. Every Transit call after
the token's expiry is refused, as Vault refuses a lapsed token, and ``renew-self`` extends it by its
TTL again. Before the fix the cipher never renewed, so a call made past the first TTL failed.
"""

from __future__ import annotations

import functools
import logging
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import crypto_transit
from messagefoundry.store.crypto import CipherError
from messagefoundry.store.crypto_transit import build_transit_cipher
from tests.test_crypto_transit import _FakeTransit, _use_fake


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class _Forbidden(Exception):
    """Stands in for hvac's ``Forbidden``: Vault's answer to a lapsed token."""


class _Token:
    """One Vault token with a TTL on ``clock``. ``ttl`` 0 is a token with no TTL."""

    def __init__(self, clock: _Clock, *, ttl: int, renewable: bool) -> None:
        self.clock = clock
        self.ttl = ttl
        self.renewable = renewable
        self.expires_at = clock.now + ttl if ttl else None
        self.renewals = 0
        self.lookups = 0

    def live(self) -> None:
        if self.expires_at is not None and self.clock.now >= self.expires_at:
            raise _Forbidden("permission denied")

    def lookup_self(self) -> dict[str, Any]:
        self.live()
        self.lookups += 1
        left = 0 if self.expires_at is None else int(self.expires_at - self.clock.now)
        return {"data": {"ttl": left, "renewable": self.renewable}}

    def renew_self(self) -> dict[str, Any]:
        self.live()
        if not self.renewable:
            raise _Forbidden("lease is not renewable")
        self.renewals += 1
        self.expires_at = self.clock.now + self.ttl
        return {"auth": {"lease_duration": self.ttl, "renewable": True}}


class _ExpiringTransit(_FakeTransit):
    """The fake Transit, refusing every call once the token has lapsed."""

    def __init__(self, token: _Token) -> None:
        super().__init__()
        self.token = token

    def encrypt_data(self, **kwargs: Any) -> dict[str, Any]:
        self.token.live()
        return super().encrypt_data(**kwargs)

    def decrypt_data(self, **kwargs: Any) -> dict[str, Any]:
        self.token.live()
        return super().decrypt_data(**kwargs)


class _Auth:
    def __init__(self, token: _Token) -> None:
        self.token = token


class _Secrets:
    def __init__(self, transit: _FakeTransit) -> None:
        self.transit = transit


class _Client:
    def __init__(self, transit: _ExpiringTransit) -> None:
        self.secrets = _Secrets(transit)
        self.auth = _Auth(transit.token)


def _cipher(
    monkeypatch: pytest.MonkeyPatch, *, ttl: int, renewable: bool
) -> tuple[Any, _Token, _Clock]:
    clock = _Clock()
    token = _Token(clock, ttl=ttl, renewable=renewable)
    transit = _ExpiringTransit(token)
    _use_fake(monkeypatch, transit)
    # The rate limit is process-global; a fresh one per test, so no earlier warning hides this one.
    monkeypatch.setattr(crypto_transit, "_logged_at", {})
    monkeypatch.setattr(crypto_transit, "_build_client", lambda addr, token, **_: _Client(transit))
    monkeypatch.setattr(
        crypto_transit, "_TokenRenewal", functools.partial(crypto_transit._TokenRenewal, clock)
    )
    return build_transit_cipher(StoreSettings()), token, clock


def test_a_renewable_token_is_renewed_so_calls_past_its_first_ttl_succeed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=True)
    sealed = cipher.encrypt("value")
    for _ in range(5):  # 300 s in all, three TTLs, a call every 60 s
        clock.now += 60
        assert cipher.decrypt(sealed) == "value"
    assert token.renewals >= 3


def test_a_token_with_no_ttl_is_not_renewed(monkeypatch: pytest.MonkeyPatch) -> None:
    cipher, token, clock = _cipher(monkeypatch, ttl=0, renewable=False)
    clock.now += 10_000
    assert cipher.decrypt(cipher.encrypt("value")) == "value"
    assert token.lookups == 1 and token.renewals == 0


def test_a_token_that_is_not_renewable_is_reported_once_and_not_renewed(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=crypto_transit.log.name)
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=False)
    assert "not renewable and expires in 100 s" in caplog.text
    sealed = cipher.encrypt("value")
    clock.now += 150
    with pytest.raises(CipherError):
        cipher.decrypt(sealed)
    assert token.renewals == 0


def test_a_failed_renewal_never_fails_the_call_and_is_tried_again(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=True)
    sealed = cipher.encrypt("value")
    calls = {"n": 0}
    real = token.renew_self

    def flaky() -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("vault unreachable")
        return real()

    monkeypatch.setattr(token, "renew_self", flaky)
    clock.now += 60  # due: the renewal fails, the call itself still succeeds
    assert cipher.decrypt(sealed) == "value"
    assert token.renewals == 0
    clock.now += 10  # 40 s were left, so the retry waits 20 s: not yet
    assert cipher.decrypt(sealed) == "value"
    assert calls["n"] == 1
    clock.now += 10  # 80 s after build, before the token lapses at 100 s: the retry renews it
    assert cipher.decrypt(sealed) == "value"
    assert calls["n"] == 2 and token.renewals == 1
    clock.now += 70  # past the first TTL
    assert cipher.decrypt(sealed) == "value"


def test_once_the_token_has_lapsed_renewal_stops_and_says_to_replace_it(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=crypto_transit.log.name)
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=True)
    sealed = cipher.encrypt("value")
    calls = {"n": 0}

    def refused() -> dict[str, Any]:
        calls["n"] += 1
        raise _Forbidden("permission denied")

    monkeypatch.setattr(token, "renew_self", refused)
    clock.now += 150  # no call in the renewal window: the token lapsed at 100 s
    for _ in range(3):
        clock.now += 5
        with pytest.raises(CipherError):
            cipher.decrypt(sealed)
    assert calls["n"] == 1, "a lapsed token was renewed again on every call"
    assert "after the token expired; replace the token" in caplog.text


def test_a_renewal_with_no_lease_stops_renewing_and_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=crypto_transit.log.name)
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=True)
    monkeypatch.setattr(token, "renew_self", lambda: {"auth": {}})
    clock.now += 60
    cipher.encrypt("value")
    assert "renewal answered with no lease" in caplog.text


def test_a_shorter_lease_than_before_is_reported_as_the_max_ttl_nearing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.WARNING, logger=crypto_transit.log.name)
    cipher, token, clock = _cipher(monkeypatch, ttl=100, renewable=True)
    leases = iter([100, 40])

    def capped() -> dict[str, Any]:
        lease = next(leases)
        token.expires_at = clock.now + lease
        return {"auth": {"lease_duration": lease, "renewable": True}}

    monkeypatch.setattr(token, "renew_self", capped)
    clock.now += 60
    cipher.encrypt("value")  # first renewal: 100 s
    assert "max TTL" not in caplog.text
    clock.now += 60
    cipher.encrypt("value")  # second: 40 s, capped
    assert "granted 40 s, less than the 100 s before" in caplog.text


def test_a_failed_lookup_at_open_is_tried_again_so_renewal_still_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _Clock()
    token = _Token(clock, ttl=100, renewable=True)
    real = token.lookup_self
    calls = {"n": 0}

    def flaky() -> dict[str, Any]:
        calls["n"] += 1
        if calls["n"] == 1:
            raise ConnectionError("vault unreachable")
        return real()

    monkeypatch.setattr(token, "lookup_self", flaky)
    transit = _ExpiringTransit(token)
    _use_fake(monkeypatch, transit)
    monkeypatch.setattr(crypto_transit, "_logged_at", {})
    monkeypatch.setattr(crypto_transit, "_build_client", lambda addr, token, **_: _Client(transit))
    monkeypatch.setattr(
        crypto_transit, "_TokenRenewal", functools.partial(crypto_transit._TokenRenewal, clock)
    )
    cipher = build_transit_cipher(StoreSettings())
    sealed = cipher.encrypt("value")
    clock.now += 61  # the lookup is tried again: TTL 39 s left, renewal due in about 20 s
    assert cipher.decrypt(sealed) == "value"
    assert calls["n"] == 2
    clock.now += 25  # renewed before the token's expiry at 100 s
    assert cipher.decrypt(sealed) == "value"
    assert token.renewals == 1
    clock.now += 60  # past the first TTL
    assert cipher.decrypt(sealed) == "value"


def test_the_renewal_paths_are_in_the_capabilities_the_probe_asks_for(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _use_fake(monkeypatch)
    required = crypto_transit.transit_cipher_required_capabilities()
    assert required["auth/token/lookup-self"] == frozenset({"read"})
    assert required["auth/token/renew-self"] == frozenset({"update"})
