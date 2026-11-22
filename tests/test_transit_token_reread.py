# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Transit cipher re-reads its Vault token after a 403 (BACKLOG #5609).

The token was read once when the store opened, so a replaced token went unused until a restart and
an expired one failed every Transit call. After a 403 the cipher now re-reads the token through the
same accessor, rebuilds its clients and asks once more. It adds no renewal call and no Vault
capability, and it fails as before when the token did not change.

Synthetic data only: the tokens, key names and plaintext are made up.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("hvac")
from hvac.exceptions import Forbidden  # type: ignore[import-untyped]  # noqa: E402

from messagefoundry.config.settings import StoreSettings  # noqa: E402
from messagefoundry.privilege_check import HopPrivilege, HopState  # noqa: E402
from messagefoundry.store import crypto_transit  # noqa: E402
from messagefoundry.store.crypto import CipherError, TransitSealRefused  # noqa: E402
from messagefoundry.store.crypto_transit import (  # noqa: E402
    TransitCipher,
    build_transit_cipher,
)
from messagefoundry.store.keyprovider import KeyProviderError  # noqa: E402
from messagefoundry.store.keyprovider_vault import store_vault_token  # noqa: E402
from tests._vault_hop_env import STORE, supply_vault_hop  # noqa: E402
from tests.test_crypto_transit import _KEY_NAME, _FakeClient, _FakeTransit  # noqa: E402
from tests.test_engine_secrets import _directory_in_process  # noqa: E402
from tests.test_transit_batch import _BatchTransit  # noqa: E402

real_refuse_over_granted = crypto_transit._refuse_over_granted
_OLD = "hvs.synthetic-old-token"  # nosec B105 - a made-up test value
_NEW = "hvs.synthetic-new-token"  # nosec B105 - a made-up test value
_TOKEN_VAR = "MEFOR_STORE_VAULT_TOKEN"
_AAD = b"cell"


class _Gate:
    """What the fake Vault accepts, and every token a request carried."""

    def __init__(self, *valid: str) -> None:
        self.valid = set(valid)
        self.asked: list[str] = []
        self.lock = threading.Lock()

    def check(self, token: str) -> None:
        with self.lock:
            self.asked.append(token)
            allowed = token in self.valid
        if not allowed:
            raise Forbidden("permission denied")


class _GatedTransit:
    """A fake Transit that answers 403 for a token the gate does not accept."""

    def __init__(self, real: _FakeTransit, gate: _Gate, token: str) -> None:
        self._real, self._gate, self._token = real, gate, token

    def __getattr__(self, name: str) -> Callable[..., Any]:
        method = getattr(self._real, name)

        def call(**kwargs: Any) -> Any:
            self._gate.check(self._token)
            return method(**kwargs)

        return call


@pytest.fixture
def vault(monkeypatch: pytest.MonkeyPatch) -> tuple[_Gate, list[str]]:
    """The fake Vault's gate, accepting the old token until a test changes it, and the token each
    built client got. The re-read's rate limit is off unless a test sets it."""
    supply_vault_hop(monkeypatch, STORE)
    monkeypatch.setenv(_TOKEN_VAR, _OLD)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_INTERVAL_S", 0.0)
    real = _BatchTransit()
    gate = _Gate(_OLD)
    built: list[str] = []

    def build(addr: str, token: str, **_: Any) -> _FakeClient:
        built.append(token)
        client = _FakeClient(real)
        client.secrets.transit = _GatedTransit(real, gate, token)  # type: ignore[assignment]
        return client

    monkeypatch.setattr(crypto_transit, "_build_client", build)
    # The fake has no lookup-self; the judgement has its own tests below.
    monkeypatch.setattr(crypto_transit, "_refuse_over_granted", lambda *_: None)
    return gate, built


def _finish_reread(cipher: TransitCipher) -> None:
    source = cipher._token_source
    assert source is not None
    reader = source._reader
    if reader is not None:
        reader.join(timeout=30)


class _RefusesBatches:
    """A Transit that answers 403 to a batch and serves single requests."""

    def __init__(self, inner: Any, before_single: Callable[[], None] = lambda: None) -> None:
        self._inner = inner
        self._before_single = before_single

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def _single(self, name: str, kwargs: dict[str, Any]) -> Any:
        if "batch_input" in kwargs:
            raise Forbidden("permission denied")
        self._before_single()
        return getattr(self._inner, name)(**kwargs)

    def encrypt_data(self, **kwargs: Any) -> Any:
        return self._single("encrypt_data", kwargs)

    def decrypt_data(self, **kwargs: Any) -> Any:
        return self._single("decrypt_data", kwargs)


def _expire_and_replace(monkeypatch: pytest.MonkeyPatch, gate: _Gate) -> None:
    gate.valid = {_NEW}
    monkeypatch.setenv(_TOKEN_VAR, _NEW)


def test_a_403_then_a_replaced_token_succeeds(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, built = vault
    cipher = build_transit_cipher(StoreSettings())
    stored = cipher.encrypt("synthetic", aad=_AAD)
    _expire_and_replace(monkeypatch, gate)
    gate.asked.clear()
    assert cipher.decrypt(stored, aad=_AAD) == "synthetic"
    assert gate.asked == [_OLD, *[_NEW] * 4, _NEW]  # refused, four checks, the retry
    assert built[-1] == _NEW


@pytest.mark.parametrize(
    "call",
    [
        lambda c: c.encrypt("synthetic", aad=_AAD),
        lambda c: c.encrypt_many([("one", _AAD), ("two", _AAD)]),
        lambda c: c.audit_hmac(b"row"),
        lambda c: c.seal_probe(),
    ],
    ids=["encrypt", "encrypt_many", "audit_hmac", "seal_probe"],
)
def test_every_write_path_recovers(
    vault: tuple[_Gate, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    call: Callable[[TransitCipher], object],
) -> None:
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    _expire_and_replace(monkeypatch, gate)
    gate.asked.clear()
    call(cipher)
    assert gate.asked[0] == _OLD and gate.asked[-1] == _NEW
    # Refused, four checks of the new token, the retry; a batch is not split into singles.
    assert len(gate.asked) == 6


def test_decrypt_many_recovers_without_turning_batching_off(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    items = [(cipher.encrypt(text, aad=_AAD), _AAD) for text in ("one", "two")]
    _expire_and_replace(monkeypatch, gate)
    assert cipher.decrypt_many(items) == ["one", "two"]
    assert cipher._batch_alone is False


def test_an_unchanged_token_fails_with_one_request(vault: tuple[_Gate, list[str]]) -> None:
    gate, built = vault
    cipher = build_transit_cipher(StoreSettings())
    stored = cipher.encrypt("synthetic", aad=_AAD)
    gate.valid = set()
    gate.asked.clear()
    before = len(built)
    with pytest.raises(CipherError) as caught:
        cipher.decrypt(stored, aad=_AAD)
    assert isinstance(caught.value.__cause__, Forbidden)
    assert gate.asked == [_OLD]
    assert len(built) == before


def test_a_replaced_token_vault_also_refuses_fails_closed(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    gate.valid = set()
    monkeypatch.setenv(_TOKEN_VAR, _NEW)
    gate.asked.clear()
    with pytest.raises(CipherError):
        cipher.encrypt("synthetic", aad=_AAD)
    assert gate.asked == [_OLD, _NEW]  # the new token's check failed, so no retry
    assert cipher._token_source is not None and cipher._token_source.epoch == 0


def test_a_token_that_cannot_be_read_fails_closed_and_adds_no_fallback(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, built = vault
    cipher = build_transit_cipher(StoreSettings())
    gate.valid = {"hvs.synthetic-ambient-token"}
    monkeypatch.delenv(_TOKEN_VAR)
    monkeypatch.setenv("VAULT_TOKEN", "hvs.synthetic-ambient-token")
    gate.asked.clear()
    before = len(built)
    with pytest.raises(CipherError) as caught:
        cipher.encrypt("synthetic", aad=_AAD)
    assert isinstance(caught.value.__cause__, Forbidden)
    assert gate.asked == [_OLD] and len(built) == before


def test_a_rebuild_failure_raises_the_403_as_before(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    stored = cipher.encrypt("synthetic", aad=_AAD)
    _expire_and_replace(monkeypatch, gate)

    def refuse(addr: str, token: str, **_: Any) -> Any:
        raise ValueError("synthetic build refusal")

    monkeypatch.setattr(crypto_transit, "_build_client", refuse)
    with pytest.raises(CipherError) as caught:
        cipher.decrypt(stored, aad=_AAD)
    assert isinstance(caught.value.__cause__, Forbidden)


def test_the_reread_is_rate_limited(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_INTERVAL_S", 3600.0)
    reads: list[int] = []

    def counted() -> str:
        reads.append(1)
        return store_vault_token()

    monkeypatch.setattr(crypto_transit, "store_vault_token", counted)
    cipher = build_transit_cipher(StoreSettings())
    gate.valid = set()
    for _ in range(5):
        with pytest.raises(CipherError):
            cipher.encrypt("synthetic", aad=_AAD)
    assert len(reads) == 1


def test_a_replaced_file_in_the_secrets_directory_is_used(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    gate, _ = vault
    directory = _directory_in_process(tmp_path, monkeypatch)
    token_file = directory / _TOKEN_VAR
    token_file.write_text(_OLD, encoding="utf-8")
    monkeypatch.delenv(_TOKEN_VAR)
    cipher = build_transit_cipher(StoreSettings())
    stored = cipher.encrypt("synthetic", aad=_AAD)
    gate.valid = {_NEW}
    token_file.write_text(_NEW, encoding="utf-8")
    assert cipher.decrypt(stored, aad=_AAD) == "synthetic"
    # The file gone, with nothing else configured: the 403 stands.
    gate.valid = set()
    token_file.unlink()
    with pytest.raises(CipherError) as caught:
        cipher.decrypt(stored, aad=_AAD)
    assert isinstance(caught.value.__cause__, Forbidden)


def test_every_thread_moves_to_the_new_token(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_INTERVAL_S", 3600.0)
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_WAIT_S", 30.0)
    cipher = build_transit_cipher(StoreSettings())
    gate.asked.clear()
    workers = 8
    failures: list[BaseException] = []

    def rotate() -> None:
        _expire_and_replace(monkeypatch, gate)

    rotated = threading.Barrier(workers, action=rotate)

    def work() -> None:
        try:
            cipher.encrypt("first", aad=_AAD)  # every thread now holds a client on the old token
            rotated.wait(timeout=30)
            cipher.encrypt("second", aad=_AAD)
            cipher.encrypt("third", aad=_AAD)
        except BaseException as exc:  # noqa: BLE001 -- asserted on the test's thread
            failures.append(exc)

    threads = [threading.Thread(target=work) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)
    assert not any(thread.is_alive() for thread in threads)
    assert not failures
    # After its one refused request, no thread sent the dead token again.
    assert gate.asked[-1] == _NEW
    # Each thread's first call, and at most one 403: a thread that starts after the swap has none.
    assert workers < gate.asked.count(_OLD) <= workers * 2
    assert gate.asked.count(_NEW) == workers * 2 + 4  # four checks, once


@pytest.mark.parametrize("op", ["encrypt", "decrypt"])
def test_a_batch_refused_on_the_event_loop_leaves_batching_on(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch, op: str
) -> None:
    """Mutation: drop the epoch check at either latch. Red: the single requests succeed on the new
    token, and the cipher stops batching for good. The read is made to land before them."""
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    items = [(cipher.encrypt(text, aad=_AAD), _AAD) for text in ("one", "two")]
    client = cipher._client
    client.secrets.transit = _RefusesBatches(
        client.secrets.transit, before_single=lambda: _finish_reread(cipher)
    )
    _expire_and_replace(monkeypatch, gate)

    async def on_loop() -> None:
        if op == "encrypt":
            cipher.encrypt_many([("one", _AAD), ("two", _AAD)])
        else:
            assert cipher.decrypt_many(items) == ["one", "two"]

    asyncio.run(on_loop())
    assert cipher._batch_alone is False


def test_a_replacement_vault_refuses_keeps_the_working_token(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    cipher = build_transit_cipher(StoreSettings())
    source = cipher._token_source
    assert source is not None
    monkeypatch.setenv(_TOKEN_VAR, _NEW)  # gate accepts only the old token
    source._reread()
    assert source.epoch == 0 and source.value == _OLD
    gate.asked.clear()
    cipher.encrypt("synthetic", aad=_AAD)
    assert gate.asked == [_OLD]


@pytest.mark.parametrize(("moved", "breaks"), [(True, False), (False, True)])
def test_a_token_change_during_a_row_check_is_not_a_break(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch, moved: bool, breaks: bool
) -> None:
    cipher = build_transit_cipher(StoreSettings())
    source = cipher._token_source
    assert source is not None
    epoch = source.epoch
    source.epoch += int(moved)

    def fails(*_: Any) -> Any:
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(cipher, "_fixed_input_verifies", lambda: True)
    monkeypatch.setattr(cipher, "_transit_verify_call", fails)
    args = (b"row", "vault:v1:bWFj", 1, Forbidden("permission denied"), epoch)
    if breaks:
        assert cipher._recheck_refused_row(*args) is False
    else:
        with pytest.raises(CipherError):
            cipher._recheck_refused_row(*args)


@pytest.mark.parametrize("op", ["encrypt", "decrypt"])
def test_a_batch_403_with_an_unchanged_token_still_turns_batching_off(
    vault: tuple[_Gate, list[str]], op: str
) -> None:
    """A proxy or policy that refuses batches and serves single requests keeps today's latch."""
    cipher = build_transit_cipher(StoreSettings())
    items = [(cipher.encrypt(text, aad=_AAD), _AAD) for text in ("one", "two")]
    client = cipher._client
    client.secrets.transit = _RefusesBatches(client.secrets.transit)
    if op == "encrypt":
        cipher.encrypt_many([("one", _AAD), ("two", _AAD)])
    else:
        assert cipher.decrypt_many(items) == ["one", "two"]
    assert cipher._batch_alone is True


def test_a_hung_reread_charges_its_wait_once(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_INTERVAL_S", 3600.0)
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_WAIT_S", 3.0)
    release = threading.Event()

    def hung() -> str:
        assert release.wait(timeout=30)
        return store_vault_token()

    monkeypatch.setattr(crypto_transit, "store_vault_token", hung)
    cipher = build_transit_cipher(StoreSettings())
    gate.valid = set()
    try:
        with pytest.raises(CipherError):
            cipher.encrypt("synthetic", aad=_AAD)
        started = time.monotonic()
        with pytest.raises(CipherError):
            cipher.encrypt("synthetic", aad=_AAD)
        assert time.monotonic() - started < 1.5
    finally:
        release.set()
        _finish_reread(cipher)


def test_on_the_event_loop_the_reread_runs_off_it_and_the_next_call_recovers(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    release = threading.Event()
    read_on: list[int] = []

    def slow() -> str:
        read_on.append(threading.get_ident())
        assert release.wait(timeout=30)
        return store_vault_token()

    monkeypatch.setattr(crypto_transit, "store_vault_token", slow)
    cipher = build_transit_cipher(StoreSettings())
    _expire_and_replace(monkeypatch, gate)

    async def on_loop() -> int:
        with pytest.raises(CipherError):  # returned without waiting for the held read
            cipher.encrypt("synthetic", aad=_AAD)
        return threading.get_ident()

    loop_thread = asyncio.run(on_loop())
    assert read_on and loop_thread not in read_on
    release.set()
    _finish_reread(cipher)
    assert cipher.encrypt("synthetic", aad=_AAD).startswith("mfenc:v3:")


def test_the_token_is_never_logged(
    vault: tuple[_Gate, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    gate, _ = vault
    caplog.set_level(logging.DEBUG)
    cipher = build_transit_cipher(StoreSettings())
    _expire_and_replace(monkeypatch, gate)
    cipher.encrypt("synthetic", aad=_AAD)
    gate.valid = set()
    monkeypatch.delenv(_TOKEN_VAR)
    with pytest.raises(CipherError):
        cipher.encrypt("synthetic", aad=_AAD)
    text = caplog.text
    assert _OLD not in text and _NEW not in text
    assert "synthetic-" not in text


def test_a_cipher_without_a_token_source_is_unchanged() -> None:
    transit = _FakeTransit()

    client = _FakeClient(transit)
    gate = _Gate()
    client.secrets.transit = _GatedTransit(transit, gate, _OLD)  # type: ignore[assignment]
    cipher = TransitCipher(client, _KEY_NAME)
    with pytest.raises(CipherError):
        cipher.encrypt("synthetic", aad=_AAD)
    assert gate.asked == [_OLD]


@pytest.mark.parametrize(
    ("refusing", "unexcused", "adopted"),
    [(("root",), (), False), ((), ("TypeError",), False), ((), (), True)],
)
def test_a_replacement_is_held_to_the_start_privilege_judgement(
    vault: tuple[_Gate, list[str]],
    monkeypatch: pytest.MonkeyPatch,
    refusing: tuple[str, ...],
    unexcused: tuple[str, ...],
    adopted: bool,
) -> None:
    gate, _ = vault
    monkeypatch.setattr(crypto_transit, "_refuse_over_granted", real_refuse_over_granted)
    hop = HopPrivilege(
        "vault.store", HopState.OVER_GRANTED, "i", "m", "d", refusing=refusing, unexcused=unexcused
    )
    monkeypatch.setattr("messagefoundry.privilege_probes.read_vault_token", lambda *_: object())
    monkeypatch.setattr("messagefoundry.privilege_check.vault_hop", lambda *_, **__: hop)
    cipher = build_transit_cipher(StoreSettings())
    source = cipher._token_source
    assert source is not None
    gate.valid = {_OLD, _NEW}
    monkeypatch.setenv(_TOKEN_VAR, _NEW)
    source._reread()
    assert (source.value == _NEW) is adopted


def test_a_seal_403_from_a_dead_token_is_an_outage_and_a_key_403_is_a_refusal(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    gate, _ = vault
    monkeypatch.setattr(crypto_transit, "_TOKEN_REREAD_INTERVAL_S", 3600.0)
    cipher = build_transit_cipher(StoreSettings())
    client = cipher._client
    inner = client.secrets.transit

    class _RefusesVerify:
        def __getattr__(self, name: str) -> Any:
            return getattr(inner, name)

        def verify_signed_data(self, **_: Any) -> Any:
            raise Forbidden("permission denied")

    client.secrets.transit = _RefusesVerify()
    with pytest.raises(TransitSealRefused):  # the token still serves: the key refused it
        cipher.verify_seal_hmac(_KEY_NAME, b"d" * 32, "vault:v1:bWFj")
    gate.valid = set()
    with pytest.raises(CipherError):  # the token is dead: an outage, not a refused seal
        cipher.verify_seal_hmac(_KEY_NAME, b"d" * 32, "vault:v1:bWFj")


def test_a_missing_token_at_build_still_refuses(
    vault: tuple[_Gate, list[str]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_TOKEN_VAR)
    with pytest.raises(KeyProviderError):
        build_transit_cipher(StoreSettings())
