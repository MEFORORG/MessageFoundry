# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The Transit cipher's hvac clients: one per thread, closed with the store, with a set timeout.

BACKLOG #5963: one hvac client, and the one requests Session inside it, was shared by the event
loop and the worker threads the store hands cipher work to, and its pooled sockets were never
closed when the store closed. BACKLOG #5983, in part: the client carried hvac's 30-second default
timeout rather than a bound the engine sets.

Synthetic data only: the token, key names and plaintext are made up.
"""

from __future__ import annotations

import gc
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store import crypto_transit
from messagefoundry.store.crypto import CipherError, CipherUnavailableError, gave_no_verdict
from messagefoundry.store.crypto_transit import (
    TRANSIT_REQUEST_TIMEOUT_S,
    TransitCipher,
    build_transit_cipher,
)
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests._extras_probe import OPTIONAL_EXTRAS, extra_is_installed
from tests._vault_hop_env import STORE, supply_vault_hop
from tests.test_crypto_transit import _KEY_NAME, _FakeClient, _FakeTransit
from tests.test_transit_batch import _frames_reach

_vault_extra = pytest.mark.skipif(
    not extra_is_installed(OPTIONAL_EXTRAS["vault"]),
    reason="the [vault] extra (hvac + requests + urllib3) is not installed in this interpreter",
)
_TOKEN = "s.synthetic-token"  # nosec B105 - a made-up test value, not a credential


class _Adapter:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _TrackedClient(_FakeClient):
    """A fake hvac client that records the threads that use it and how often it was closed."""

    def __init__(self, transit: _FakeTransit) -> None:
        super().__init__(transit)
        self.adapter = _Adapter()
        self.threads: set[int] = set()
        real = self.secrets.transit
        client = self

        class _Recording:
            def __getattr__(self, name: str) -> Any:
                client.threads.add(threading.get_ident())
                return getattr(real, name)

        self.secrets.transit = _Recording()  # type: ignore[assignment]


def _factory(transit: _FakeTransit) -> tuple[list[_TrackedClient], Callable[[], _TrackedClient]]:
    built: list[_TrackedClient] = []

    def build() -> _TrackedClient:
        client = _TrackedClient(transit)
        built.append(client)
        return client

    return built, build


def _cipher() -> tuple[TransitCipher, list[_TrackedClient]]:
    built, build = _factory(_FakeTransit())
    return TransitCipher(build(), _KEY_NAME, client_factory=build), built


@pytest.fixture
def _no_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real-client tests must not depend on the runner's proxy settings: the hop guard
    refuses a loopback Vault reached through a proxy."""
    for name in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(name, raising=False)


def _in_thread(fn: Callable[[], object]) -> None:
    failures: list[BaseException] = []

    def run() -> None:
        try:
            fn()
        except BaseException as exc:  # noqa: BLE001 -- re-raised on the test's thread
            failures.append(exc)

    worker = threading.Thread(target=run)
    worker.start()
    worker.join(timeout=30)
    assert not worker.is_alive()
    if failures:
        raise failures[0]


def test_build_transit_cipher_gives_a_worker_thread_its_own_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation: drop ``client_factory=build_client`` from build_transit_cipher. Red: the worker
    thread uses the startup client, so one client is built rather than two."""
    supply_vault_hop(monkeypatch, STORE)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    built, build = _factory(_FakeTransit())
    monkeypatch.setattr(crypto_transit, "_build_client", lambda addr, token, **_: build())
    cipher = build_transit_cipher(StoreSettings())
    stored = cipher.encrypt("synthetic", aad=b"cell")
    _in_thread(lambda: cipher.decrypt(stored, aad=b"cell"))
    assert len(built) == 2
    assert built[0].threads == {threading.get_ident()}
    assert len(built[1].threads) == 1 and threading.get_ident() not in built[1].threads


def test_build_transit_cipher_builds_every_client_with_the_engine_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    supply_vault_hop(monkeypatch, STORE)
    monkeypatch.setenv("MEFOR_STORE_TRANSIT_KEY", _KEY_NAME)
    transit = _FakeTransit()
    timeouts: list[object] = []

    def spy(addr: str, token: str, **kwargs: Any) -> _FakeClient:
        timeouts.append(kwargs.get("timeout"))
        return _FakeClient(transit)

    monkeypatch.setattr(crypto_transit, "_build_client", spy)
    cipher = build_transit_cipher(StoreSettings())
    _in_thread(lambda: cipher.encrypt("synthetic"))
    assert timeouts == [TRANSIT_REQUEST_TIMEOUT_S, TRANSIT_REQUEST_TIMEOUT_S]


def test_many_threads_never_share_a_client() -> None:
    """A threaded stress run: every client is only ever used by the one thread that built it."""
    cipher, built = _cipher()
    stored = cipher.encrypt("synthetic", aad=b"cell")
    start = threading.Barrier(8)
    failures: list[BaseException] = []

    def churn() -> None:
        try:
            start.wait(timeout=10)
            for _ in range(25):
                opened = cipher.decrypt(cipher.encrypt("synthetic", aad=b"cell"), aad=b"cell")
                assert opened == "synthetic"
            assert cipher.decrypt(stored, aad=b"cell") == "synthetic"
        except BaseException as exc:  # noqa: BLE001 -- re-raised on the test's thread
            failures.append(exc)

    workers = [threading.Thread(target=churn) for _ in range(8)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=60)
    assert not any(worker.is_alive() for worker in workers)
    if failures:
        raise failures[0]
    assert len(built) == 9  # the startup client, then one per worker
    assert all(len(client.threads) == 1 for client in built)
    assert len({next(iter(client.threads)) for client in built}) == 9


def test_close_releases_every_client_and_a_later_call_builds_a_fresh_one() -> None:
    cipher, built = _cipher()
    cipher.encrypt("synthetic")
    _in_thread(lambda: cipher.encrypt("synthetic"))
    cipher.close_connections()
    assert [client.adapter.closed for client in built] == [1, 1]
    cipher.encrypt("synthetic")  # still usable: more than one store can share the cipher
    assert len(built) == 3
    cipher.close_connections()
    assert [client.adapter.closed for client in built] == [1, 1, 1]


def test_a_thread_that_exits_closes_its_own_client() -> None:
    """A worker thread's client is closed when the thread ends, not kept until the store closes,
    so threads that come and go do not each leave a Vault socket open."""
    cipher, built = _cipher()
    _in_thread(lambda: cipher.encrypt("synthetic"))
    # The thread's locals are torn down as it ends, which can land just after join() returns.
    deadline = time.monotonic() + 10
    while built[1].adapter.closed == 0 and time.monotonic() < deadline:
        gc.collect()
        time.sleep(0.01)
    assert [client.adapter.closed for client in built] == [0, 1]
    cipher.close_connections()
    assert [client.adapter.closed for client in built] == [1, 1]  # closed once each


def test_a_cipher_without_a_factory_keeps_its_one_client_across_close() -> None:
    client = _TrackedClient(_FakeTransit())
    cipher = TransitCipher(client, _KEY_NAME)
    _in_thread(lambda: cipher.encrypt("synthetic"))
    cipher.close_connections()
    cipher.encrypt("synthetic")
    cipher.close_connections()
    assert client.adapter.closed == 2
    assert len(client.threads) == 2


def test_a_client_close_that_raises_is_logged_and_the_rest_still_close(
    caplog: pytest.LogCaptureFixture,
) -> None:
    cipher, built = _cipher()
    ready, done = threading.Event(), threading.Event()

    def hold() -> None:
        cipher.encrypt("synthetic")
        ready.set()
        done.wait(timeout=10)  # alive, so its client is still held when the cipher closes

    worker = threading.Thread(target=hold)
    worker.start()
    try:
        assert ready.wait(timeout=10)

        def boom() -> None:
            raise OSError("synthetic")

        built[0].adapter.close = boom  # type: ignore[method-assign]
        cipher.close_connections()
        assert built[1].adapter.closed == 1
    finally:
        done.set()
        worker.join(timeout=10)
    gc.collect()
    assert built[1].adapter.closed == 1  # the thread's exit does not close it a second time
    assert "closing a Transit client's connections raised OSError" in caplog.text


def _encrypt_in_a_thread(factory: Callable[[], Any]) -> list[BaseException]:
    """Encrypt once in a worker thread of a cipher whose thread clients come from ``factory``."""
    cipher = TransitCipher(_FakeClient(_FakeTransit()), _KEY_NAME, client_factory=factory)
    failures: list[BaseException] = []

    def encrypt() -> None:
        try:
            cipher.encrypt("synthetic")
        except CipherError as exc:
            failures.append(exc)

    _in_thread(encrypt)
    return failures


@_vault_extra
def test_a_thread_client_build_refusal_is_a_refusal_not_an_outage() -> None:
    """Mutation: relabel every build failure as a requests ConnectionError. Red: a build failure
    the failure classifier reads as a refusal, here a synthetic ValueError, reads as an outage
    that gave no verdict on an encrypt."""

    def refuse() -> Any:
        raise ValueError("synthetic TLS-suite refusal")

    failures = _encrypt_in_a_thread(refuse)
    assert len(failures) == 1
    assert not isinstance(failures[0], CipherUnavailableError)
    assert isinstance(failures[0], CipherError) and not gave_no_verdict(failures[0])
    assert isinstance(failures[0].__cause__, ValueError)
    assert str(failures[0].__cause__) == "synthetic TLS-suite refusal"


@_vault_extra
def test_a_decrypt_build_refusal_gives_no_verdict() -> None:
    """Mutation: give a decrypt build failure the encrypt side's refusal. Red: a cell walk reads
    every cell as damaged although Transit was never asked, rather than stopping as could-not-run.
    The text the refusal had and its cause are kept."""

    def refuse() -> Any:
        raise ValueError("synthetic TLS-suite refusal")

    cipher = TransitCipher(_FakeClient(_FakeTransit()), _KEY_NAME, client_factory=refuse)
    failures: list[CipherError] = []

    def decrypt() -> None:
        try:
            cipher.decrypt("mfenc:v3:vault:v1:c3ludGhldGlj")
        except CipherError as exc:
            failures.append(exc)

    _in_thread(decrypt)
    assert len(failures) == 1 and isinstance(failures[0], CipherUnavailableError)
    assert gave_no_verdict(failures[0])
    assert str(failures[0]) == f"Transit decrypt failed (key={_KEY_NAME!r}): ValueError"
    assert isinstance(failures[0].__cause__, ValueError)
    assert str(failures[0].__cause__) == "synthetic TLS-suite refusal"


@_vault_extra
def test_a_batch_decrypt_build_failure_keeps_no_traceback_to_other_plaintext() -> None:
    """Mutation: return the batch build failure's errors without detaching them. Red: a returned
    error's cause keeps a traceback whose frames reach decrypt_many's locals, which hold the
    plaintext of a value already opened (BACKLOG #6706)."""

    def refuse() -> Any:
        raise ValueError("synthetic TLS-suite refusal")

    cipher = TransitCipher(
        _FakeClient(_FakeTransit()), _KEY_NAME, client_factory=refuse, allow_unmarked=True
    )
    opened: list[list[str | CipherError]] = []
    items: list[tuple[str, bytes | None]] = [("synthetic opened plaintext", None)]
    items += [(f"mfenc:v3:vault:v1:c3ludGhldGlj{n}", None) for n in range(2)]
    _in_thread(lambda: opened.append(cipher.decrypt_many(items)))
    results = opened[0]
    assert results[0] == "synthetic opened plaintext"
    for error in results[1:]:
        assert isinstance(error, CipherUnavailableError)
        assert isinstance(error.__cause__, ValueError)
        assert not _frames_reach(error, "synthetic opened plaintext")


@_vault_extra
def test_a_build_refusal_on_a_batch_leaves_batching_on() -> None:
    """Mutation: read the thread's client inside the batch request's handler. Red: a build refusal
    reads as Transit refusing the batch, and the cipher sends every later value alone although
    Transit was never asked."""

    def refuse() -> Any:
        raise ValueError("synthetic TLS-suite refusal")

    cipher = TransitCipher(_FakeClient(_FakeTransit()), _KEY_NAME, client_factory=refuse)
    stored = [f"mfenc:v3:vault:v1:c3ludGhldGlj{n}" for n in range(2)]
    opened: list[list[str | CipherError]] = []
    raised: list[BaseException] = []

    def batches() -> None:
        opened.append(cipher.decrypt_many([(value, None) for value in stored]))
        try:
            cipher.encrypt_many([("synthetic one", None), ("synthetic two", None)])
        except CipherError as exc:
            raised.append(exc)

    _in_thread(batches)
    assert not cipher._batch_alone
    assert len(opened[0]) == 2
    for result in opened[0]:
        assert isinstance(result, CipherUnavailableError)  # a decrypt build failure: no verdict
        assert isinstance(result.__cause__, ValueError)
    assert len(raised) == 1 and not isinstance(raised[0], CipherUnavailableError)
    assert isinstance(raised[0].__cause__, ValueError)


async def test_closing_the_sqlite_store_releases_the_transit_clients(tmp_path: Path) -> None:
    """Mutation: drop the close_connections call from MessageStore.close. Red: no client is
    closed."""
    cipher, built = _cipher()
    store = await MessageStore.open(tmp_path / "store.db", cipher=cipher)
    await store.close()
    assert built and all(client.adapter.closed == 1 for client in built)


@pytest.mark.parametrize("store_class", [MessageStore, PostgresStore, SqlServerStore])
async def test_every_store_close_releases_the_clients_even_when_a_close_step_raises(
    store_class: type[Any],
) -> None:
    """All three backends: the release runs in a finally, so a close step that raises still
    closes the Vault sockets, and the step's error still propagates. No database is opened."""
    cipher, built = _cipher()
    store = object.__new__(store_class)
    store._cipher = cipher

    async def broken() -> None:
        raise OSError("synthetic close failure")

    store._close_handles = broken
    with pytest.raises(OSError, match="synthetic close failure"):
        await store.close()
    assert [client.adapter.closed for client in built] == [1]


# --- a real hvac client --------------------------------------------------------------------------


@_vault_extra
@pytest.mark.usefixtures("_no_proxy")
def test_a_real_client_takes_the_timeout_and_the_stock_build_keeps_hvacs() -> None:
    from messagefoundry.store import keyprovider_vault

    addr = "https://vault.example.test:8200"
    stock = keyprovider_vault._build_client(addr, _TOKEN, revocation_attested=True)
    bounded = keyprovider_vault._build_client(
        addr, _TOKEN, revocation_attested=True, timeout=TRANSIT_REQUEST_TIMEOUT_S
    )
    assert stock.adapter._kwargs["timeout"] == 30
    assert bounded.adapter._kwargs["timeout"] == TRANSIT_REQUEST_TIMEOUT_S


@_vault_extra
@pytest.mark.usefixtures("_no_proxy")
def test_real_thread_clients_hold_separate_sessions() -> None:
    from messagefoundry.store import keyprovider_vault

    def build() -> Any:
        return keyprovider_vault._build_client(
            "https://vault.example.test:8200", _TOKEN, revocation_attested=True
        )

    cipher = TransitCipher(build(), _KEY_NAME, client_factory=build)
    sessions: list[object] = [cipher._client.adapter.session]
    _in_thread(lambda: sessions.append(cipher._client.adapter.session))
    assert sessions[0] is not sessions[1]
    cipher.close_connections()


@_vault_extra
@pytest.mark.usefixtures("_no_proxy")
def test_a_vault_that_never_answers_ends_in_the_timeout_as_an_outage() -> None:
    """A Transit request to a Vault that accepts and never replies ends at the read timeout as a
    no-verdict CipherUnavailableError, rather than holding the caller until hvac's 30 seconds."""
    import socket

    from messagefoundry.store import keyprovider_vault

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    try:
        client = keyprovider_vault._build_client(
            f"http://127.0.0.1:{listener.getsockname()[1]}",
            _TOKEN,
            revocation_attested=False,
            timeout=(2.0, 0.5),
        )
        cipher = TransitCipher(client, _KEY_NAME)
        began = time.monotonic()
        with pytest.raises(CipherUnavailableError):
            cipher.encrypt("synthetic")
        assert time.monotonic() - began < 10
    finally:
        listener.close()
