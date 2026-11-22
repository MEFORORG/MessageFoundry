# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3714 steps 9 and 11, as decision d20261122T111258871-87279a scoped them.

Step 9: the in-process pin baseline's WARNING tells the operator how to accept a renewal they
made, a restart, since the baseline moves only then.

Step 11, re-scoped: after a settings check at ``enforce`` refuses the SQL Server store pin, the
store refuses new connects, its pool's (through the pool executor) and its claim holders' and
sync handoff pools', until a check passes the pin again. A check at ``warn`` does not.

``aioodbc`` and ``pyodbc`` are the optional ``sqlserver`` extra, so recording modules stand in for
them through ``sys.modules``, as ``tests/test_sqlserver_login_timeout.py`` does. The one test that
needs the real ``aioodbc`` skips without it: it pins that aioodbc 0.5.0's pool connect reaches the
executor as ``pyodbc.connect``, which is what the executor gate keys on.
"""

from __future__ import annotations

import sys
import types
from functools import partial
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import pki
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.auth.trust_anchors import (
    TrustAnchorError,
    run_anchor_preflight,
    store_pin_anchor_spec,
)
from messagefoundry.config.settings import StoreSettings
from messagefoundry.config.tls_policy import StoreTlsRefused
from messagefoundry.store.sqlserver import (
    SqlServerStore,
    _build_pool_executor,
    check_pinned_certificate,
    refuse_connect_after_pin_refusal,
)
from messagefoundry.store.store import MessageStore

_KEY_BLOCK = b"-----BEGIN PRIVATE" + b" KEY-----\nAAAA\n-----END PRIVATE" + b" KEY-----\n"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _fresh_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ta, "_LOADED", {})
    monkeypatch.setattr(ta, "_WARNED_AT_OPEN", {})
    monkeypatch.setattr(ta, "_STORE_CONTENT_RECORDED", {})
    monkeypatch.setattr(ta, "_STORE_PIN_FIRST_CHECKED", {})
    # raising=False: the negative control runs this file against a head without the gate.
    monkeypatch.setattr(ta, "_STORE_PIN_REFUSED", {}, raising=False)
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))


def _pin(tmp_path: Path) -> Path:
    pin = tmp_path / "db-server.pem"
    pin.write_bytes(pki.make_self_signed("db.example", [], 30)[0])
    return pin


def _settings(pin: Path) -> StoreSettings:
    return StoreSettings.model_validate(
        {
            "backend": "sqlserver",
            "server": "db.example",
            "database": "mefor",
            "username": "mefor",
            "ssl_root_cert": str(pin),
        }
    )


def _specs(settings: StoreSettings) -> list[ta.AnchorSpec]:
    spec = store_pin_anchor_spec(settings)
    assert spec is not None
    return [spec]


async def _refuse_at(store: MessageStore, pin: Path, *, enforcing: bool) -> StoreSettings:
    """Put a private key in the pin, which a settings check refuses at either setting, and run
    the check once at ``enforcing``. Returns the store settings naming that pin."""
    settings = _settings(pin)
    pin.write_bytes(pin.read_bytes() + _KEY_BLOCK)
    with pytest.raises(TrustAnchorError):
        await run_anchor_preflight(_specs(settings), store, enforcing=enforcing)
    return settings


# --- step 9: the warning says how to accept a renewal -------------------------------------------


def test_the_off_hop_pin_warning_says_a_restart_accepts_a_renewal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Red on batch/w5-a 68c1a2d2128, whose warning says what to do only when the change is not a
    renewal, so an operator who renewed the certificate is not told that only a restart accepts
    it, and is warned at each check until then."""
    spec = _specs(_settings(_pin(tmp_path)))[0]
    ta.note_store_pin_checked(spec, "a" * 64)
    caplog.set_level("WARNING", logger=ta.__name__)
    ta._warn_off_hop_pin_change(spec, "b" * 64)
    (message,) = [r.getMessage() for r in caplog.records]
    assert "If it is a renewal you made, restart each engine process" in message
    assert "the baseline moves only at a restart" in message


# --- step 11: refused new connects after an enforce refusal -------------------------------------


async def test_an_enforce_refusal_refuses_new_store_connects(
    store: MessageStore, tmp_path: Path
) -> None:
    """Red on batch/w5-a 68c1a2d2128, where a refused reload leaves the store connecting."""
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    with pytest.raises(StoreTlsRefused, match="a new store connection was refused"):
        refuse_connect_after_pin_refusal(settings)


async def test_a_warn_refusal_leaves_new_store_connects_alone(
    store: MessageStore, tmp_path: Path
) -> None:
    """The control: the same refusal at ``warn`` stops no connect."""
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=False)
    refuse_connect_after_pin_refusal(settings)


async def test_a_passing_settings_check_lets_the_store_connect_again(
    store: MessageStore, tmp_path: Path
) -> None:
    pin = _pin(tmp_path)
    good = pin.read_bytes()
    settings = await _refuse_at(store, pin, enforcing=True)
    pin.write_bytes(good)
    await run_anchor_preflight(_specs(settings), store, enforcing=True)
    refuse_connect_after_pin_refusal(settings)


async def test_a_store_open_check_at_enforce_lets_the_store_connect_again(
    store: MessageStore, tmp_path: Path
) -> None:
    """The store open's own checks of the pin, at ``enforce`` (no posture counts as enforcing),
    release the refusal, so a reopen with a corrected file is not refused by a stale one."""
    pin = _pin(tmp_path)
    good = pin.read_bytes()
    settings = await _refuse_at(store, pin, enforcing=True)
    pin.write_bytes(good)
    check_pinned_certificate(settings)
    refuse_connect_after_pin_refusal(settings)


def _fake_pyodbc(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    dialled: list[str] = []

    class _Conn:
        timeout = 0

        def close(self) -> None:
            return None

    def connect(dsn: str, **_kwargs: Any) -> _Conn:
        dialled.append(dsn)
        return _Conn()

    module = types.ModuleType("pyodbc")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "pyodbc", module)
    return dialled


async def test_the_pool_executor_refuses_a_pyodbc_connect_after_an_enforce_refusal(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pool dials through its executor, so the executor refuses the connect before it runs.
    Red on batch/w5-a 68c1a2d2128, where the executor runs it. The controls: another call on the
    same executor still runs, and so does the connect once nothing is refused."""
    dialled = _fake_pyodbc(monkeypatch)
    pyodbc: Any = sys.modules["pyodbc"]
    pin = _pin(tmp_path)
    executor = _build_pool_executor(_settings(pin), 1)
    try:
        assert executor.submit(partial(pyodbc.connect, "dsn-before")).result() is not None
        await _refuse_at(store, pin, enforcing=True)
        with pytest.raises(StoreTlsRefused):
            executor.submit(partial(pyodbc.connect, "dsn-after"))
        with pytest.raises(StoreTlsRefused):
            executor.submit(pyodbc.connect, "dsn-bare")
        assert executor.submit(lambda: 42).result() == 42
        assert dialled == ["dsn-before"]
    finally:
        executor.shutdown(wait=True)


async def test_a_claim_holder_connect_is_refused_after_an_enforce_refusal(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red on batch/w5-a 68c1a2d2128, where the dedicated claim connection dials."""
    dialled: list[dict[str, Any]] = []

    async def connect(**kwargs: Any) -> object:
        dialled.append(kwargs)
        return object()

    module = types.ModuleType("aioodbc")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    claim_store = object.__new__(SqlServerStore)  # the offline-test idiom: no pool, no I/O
    claim_store._settings = settings
    with pytest.raises(StoreTlsRefused):
        await claim_store._connect_claim_conn()
    assert dialled == []


async def test_a_sync_handoff_connect_is_refused_after_an_enforce_refusal(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red on batch/w5-a 68c1a2d2128, where the sync handoff pool dials."""
    dialled = _fake_pyodbc(monkeypatch)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    sync_store = object.__new__(SqlServerStore)
    sync_store._settings = settings
    sync_store._sync_pools = {}
    with pytest.raises(StoreTlsRefused):
        sync_store.open_sync_handoff_pool("routed", 1)
    assert dialled == []


async def test_aioodbc_dials_through_the_pool_executor_as_pyodbc_connect(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The executor gate keys on aioodbc 0.5.0 submitting ``pyodbc.connect`` to the executor it
    was given, which the pool hands every connection. Skipped without the ``sqlserver`` extra;
    it runs where that extra is installed."""
    aioodbc = pytest.importorskip("aioodbc")
    pytest.importorskip("pyodbc")
    dialled: list[str] = []

    def connect(dsn: str, **_kwargs: Any) -> object:
        dialled.append(dsn)
        raise AssertionError("dialled")

    monkeypatch.setattr(sys.modules["pyodbc"], "connect", connect)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    executor = _build_pool_executor(settings, 1)
    try:
        with pytest.raises(StoreTlsRefused):
            await aioodbc.connect(dsn="DRIVER=x", executor=executor)
        assert dialled == []
    finally:
        executor.shutdown(wait=True)
