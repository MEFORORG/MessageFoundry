# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3714 steps 9 and 11, as decision d20261122T111258871-87279a scoped them.

Step 9: the in-process pin baseline's WARNING tells the operator how to accept a renewal they
made, a restart, since the baseline moves only then.

Step 11, re-scoped: after a settings check at ``enforce`` refuses the SQL Server store pin, the
store refuses new connects. Item 11 of the trust anchors module docstring states the hold.

``aioodbc`` and ``pyodbc`` are the optional ``sqlserver`` extra, so recording modules stand in for
them through ``sys.modules``, as ``tests/test_sqlserver_login_timeout.py`` does. The one test that
needs the real ``aioodbc`` skips without it: it pins that aioodbc 0.5.0's pool connect reaches the
executor as ``pyodbc.connect``, which is what the executor gate keys on.
"""

from __future__ import annotations

import sys
import types
from concurrent.futures import ThreadPoolExecutor
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
from messagefoundry.store.sqlserver import (
    SqlServerStore,
    StorePinConnectRefused,
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
    monkeypatch.setattr(ta, "_STORE_PIN_REFUSED", {})
    monkeypatch.setattr(ta, "_STORE_PIN_RELEASE_REFUSED", set())
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
    """Red under: the warning text of batch/w5-a 68c1a2d2128, which says what to do only when the
    change is not a renewal, so an operator who renewed the certificate is not told that a restart
    makes the renewed pin the baseline, and is warned at each check until then."""
    spec = _specs(_settings(_pin(tmp_path)))[0]
    ta.note_store_pin_checked(spec, "a" * 64)
    caplog.set_level("WARNING", logger=ta.__name__)
    ta._warn_off_hop_pin_change(spec, "b" * 64)
    (message,) = [r.getMessage() for r in caplog.records]
    assert "If it is a renewal you made, restart each engine process" in message
    assert "takes the renewed pin as its baseline" in message
    assert "the baseline moves only at a restart" in message


# --- step 11: refused new connects after an enforce refusal -------------------------------------


async def test_an_enforce_refusal_refuses_new_store_connects(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Red under: the refusal not held in :func:`_preflight_one`, where a refused reload leaves the
    store connecting. Holding it logs an ERROR, since the reload's refusal does not say so."""
    caplog.set_level("ERROR", logger=ta.__name__)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    (held,) = [r.getMessage() for r in caplog.records if "now refuses new" in r.getMessage()]
    assert "The refusal: " in held and "PRIVATE KEY" in held  # it names what was refused
    with pytest.raises(StorePinConnectRefused, match="a new store connection was refused"):
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
    with pytest.raises(StorePinConnectRefused):  # the control: refused until the check passes
        refuse_connect_after_pin_refusal(settings)
    pin.write_bytes(good)
    await run_anchor_preflight(_specs(settings), store, enforcing=True)
    refuse_connect_after_pin_refusal(settings)


async def test_a_settings_check_that_only_warns_of_the_pin_keeps_the_refusal(
    store: MessageStore, tmp_path: Path
) -> None:
    """A pin the settings check only warns of, here a file of two certificates, which the store
    open refuses, does not let the store connect again. Red under: the release run on any pass."""
    pin = _pin(tmp_path)
    good = pin.read_bytes()
    settings = await _refuse_at(store, pin, enforcing=True)
    other = tmp_path / "other"
    other.mkdir()
    pin.write_bytes(good + _pin(other).read_bytes())
    await run_anchor_preflight(_specs(settings), store, enforcing=True)  # warns, does not refuse
    with pytest.raises(StorePinConnectRefused):
        refuse_connect_after_pin_refusal(settings)


async def test_a_swapped_pin_does_not_lift_its_own_refusal(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A swapped pin in a broadly writable file is refused at enforce for its ACL. Fixing the ACL
    alone must not lift the hold, since the bytes still differ from the baseline; the release is
    refused with one ERROR. A store open of the same file does not lift it either. Red under: the
    release without the baseline compare (head a6b67798b4a), where the fixed ACL lifts the hold."""
    pin = _pin(tmp_path)
    settings = _settings(pin)
    await run_anchor_preflight(_specs(settings), store, enforcing=True)  # sets the baseline
    other = tmp_path / "other"
    other.mkdir()
    pin.write_bytes(_pin(other).read_bytes())  # the swap
    owner_only = {"ok": False}
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: owner_only["ok"])
    with pytest.raises(TrustAnchorError):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    owner_only["ok"] = True  # the ACL fix the refusal asks for
    caplog.set_level("ERROR", logger=ta.__name__)
    for _ in range(2):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    check_pinned_certificate(settings)
    with pytest.raises(StorePinConnectRefused):
        refuse_connect_after_pin_refusal(settings)
    refused = [r for r in caplog.records if "connections stay refused" in r.getMessage()]
    assert len(refused) == 1, refused
    assert "The pin changed" in refused[0].getMessage()


@pytest.mark.parametrize(
    "fault",
    [
        FileNotFoundError(2, "No such file or directory"),  # mid-renewal, between unlink and write
        PermissionError(13, "The process cannot access the file"),  # a scanner's lock
    ],
    ids=["renewal-by-rename", "scanner-lock"],
)
async def test_a_pin_that_cannot_be_read_sets_no_hold(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: OSError
) -> None:
    """A read fault at ``enforce`` still refuses the reload, but it is no verdict on the file,
    so it sets no hold and new store connects go on. Red under: the hold set for every refusal
    (head c985a608fee)."""
    settings = _settings(_pin(tmp_path))

    def unreadable(_spec: Any) -> Any:
        raise fault

    monkeypatch.setattr(ta, "evaluate_anchor", unreadable)
    with pytest.raises(TrustAnchorError, match="could not read the trust anchor"):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    refuse_connect_after_pin_refusal(settings)


async def test_a_pipe_or_device_at_the_pin_path_sets_the_hold(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pipe or device swapped in for the pin is refused as not a regular file, an ``OSError``
    that is a verdict, not a read the next check may not repeat, so it holds new connects shut.
    Red under: every ``OSError`` exempted from the hold (head 3ee826a4d6a)."""
    settings = _settings(_pin(tmp_path))

    def not_regular(_spec: Any) -> Any:
        raise OSError(22, "not a regular file")

    monkeypatch.setattr(ta, "evaluate_anchor", not_regular)
    with pytest.raises(TrustAnchorError):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    with pytest.raises(StorePinConnectRefused):
        refuse_connect_after_pin_refusal(settings)


async def test_an_acl_that_could_not_be_read_sets_the_hold(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An ACL read that came back indeterminate holds new connects shut, since the owner of a
    swapped file can make its ACL unreadable on purpose. Red under: an indeterminate ACL exempted
    from the hold (head 48166601156)."""
    settings = _settings(_pin(tmp_path))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: None)
    with pytest.raises(TrustAnchorError):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    with pytest.raises(StorePinConnectRefused):
        refuse_connect_after_pin_refusal(settings)


def test_the_connect_refusal_is_a_refused_store_call() -> None:
    """Callers that degrade on a refused store call catch :func:`store_call_errors`; the refusal
    must be in it. Red under: the class derived from ``Exception`` (head 48166601156)."""
    from messagefoundry.store.base import store_call_errors

    assert issubclass(StorePinConnectRefused, store_call_errors())


async def test_in_serve_order_a_corrected_acl_lifts_the_hold(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The order ``serve`` runs: the store open sets the baseline, a reload refuses the unchanged
    pin for its ACL, and a reload after the ACL fix lifts the hold, since the bytes still match.
    Red under: a release compared with anything but the baseline the open set."""
    pin = _pin(tmp_path)
    settings = _settings(pin)
    check_pinned_certificate(settings)  # the store open: sets the baseline
    owner_only = {"ok": False}
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: owner_only["ok"])
    with pytest.raises(TrustAnchorError):
        await run_anchor_preflight(_specs(settings), store, enforcing=True)
    with pytest.raises(StorePinConnectRefused):
        refuse_connect_after_pin_refusal(settings)
    owner_only["ok"] = True
    await run_anchor_preflight(_specs(settings), store, enforcing=True)
    refuse_connect_after_pin_refusal(settings)


async def test_the_store_open_database_options_connects_are_refused_under_a_hold(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The open's database-options connect dials outside the pool, so it takes the gate itself,
    and the refusal reaches the caller as itself, not as a failed options read. Red under: no
    gate in ``_ensure_database_options``, where it dials."""
    dialled: list[dict[str, Any]] = []

    async def connect(**kwargs: Any) -> object:
        dialled.append(kwargs)
        raise AssertionError("dialled")

    module = types.ModuleType("aioodbc")
    module.connect = connect  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    with pytest.raises(StorePinConnectRefused):
        await SqlServerStore._ensure_database_options(settings)
    assert dialled == []


def test_a_store_with_no_pin_gets_a_plain_pool_executor() -> None:
    """No pin, so nothing can refuse a connect, and the pool's calls skip the gate's check."""
    settings = StoreSettings.model_validate(
        {"backend": "sqlserver", "server": "db.example", "database": "mefor", "username": "mefor"}
    )
    executor = _build_pool_executor(settings, 1)
    try:
        assert type(executor) is ThreadPoolExecutor
    finally:
        executor.shutdown(wait=True)


async def test_a_store_open_check_at_enforce_lets_the_store_connect_again(
    store: MessageStore, tmp_path: Path
) -> None:
    """The store open's own checks of the pin, at ``enforce`` (no posture counts as enforcing),
    release the refusal, so a reopen with a corrected file is not refused by a stale one."""
    pin = _pin(tmp_path)
    good = pin.read_bytes()
    settings = await _refuse_at(store, pin, enforcing=True)
    with pytest.raises(StorePinConnectRefused):  # the control: refused until the check passes
        refuse_connect_after_pin_refusal(settings)
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
    Red under: a plain ``ThreadPoolExecutor``, which runs it. The controls: another call on the
    same executor still runs, and so does the connect once nothing is refused."""
    dialled = _fake_pyodbc(monkeypatch)
    pyodbc: Any = sys.modules["pyodbc"]
    pin = _pin(tmp_path)
    executor = _build_pool_executor(_settings(pin), 1)
    try:
        assert executor.submit(partial(pyodbc.connect, "dsn-before")).result() is not None
        await _refuse_at(store, pin, enforcing=True)
        with pytest.raises(StorePinConnectRefused):
            executor.submit(partial(pyodbc.connect, "dsn-after"))
        with pytest.raises(StorePinConnectRefused):
            executor.submit(pyodbc.connect, "dsn-bare")
        assert executor.submit(lambda: 42).result() == 42
        assert dialled == ["dsn-before"]
    finally:
        executor.shutdown(wait=True)


async def test_a_claim_holder_connect_is_refused_after_an_enforce_refusal(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red under: no gate in ``_connect_claim_conn``, where the dedicated connection dials."""
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
    with pytest.raises(StorePinConnectRefused):
        await claim_store._connect_claim_conn()
    assert dialled == []


async def test_a_sync_handoff_connect_is_refused_after_an_enforce_refusal(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red under: no gate in the sync handoff factory, where the pool dials."""
    dialled = _fake_pyodbc(monkeypatch)
    settings = await _refuse_at(store, _pin(tmp_path), enforcing=True)
    sync_store = object.__new__(SqlServerStore)
    sync_store._settings = settings
    sync_store._sync_pools = {}
    with pytest.raises(StorePinConnectRefused):
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
        with pytest.raises(StorePinConnectRefused):
            await aioodbc.connect(dsn="DRIVER=x", executor=executor)
        assert dialled == []
    finally:
        executor.shutdown(wait=True)
