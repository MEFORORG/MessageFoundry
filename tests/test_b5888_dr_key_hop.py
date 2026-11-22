# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5888: the DR backup, verify and restore resolve the store key off the event loop.

Each resolved and decoded the key on the loop, so a slow key provider would have stalled the engine
and, on a DR activation, kept the takeover timeout around ``run_restore_verify`` from firing. Every
key and provider here is synthetic, and no Vault server is started."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import BackupSettings, DrSettings, StoreSettings
from messagefoundry.pipeline import dr as drmod
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.secrets_dpapi import DpapiError
from messagefoundry.store import MessageStore
from messagefoundry.store.base import StoreCipherConfigError
from messagefoundry.store.keyprovider import KeyProviderError
from tests._refusal_log_capture import until

#: How long the fake provider can hold a thread. On the unfixed code it holds the loop this long.
_HOLD_SECONDS = 3.0
_GOOD_KEY = "A" * 43 + "="


def _verify(tmp_path: Path) -> Awaitable[object]:
    return dr_backup.run_restore_verify(
        str(tmp_path / "never-read.mfbak"),
        store_settings=StoreSettings(path=str(tmp_path / "x.db")),
    )


def _restore(tmp_path: Path) -> Awaitable[object]:
    return dr_backup.run_restore(
        str(tmp_path / "never-read.mfbak"),
        dest_store_path=tmp_path / "never-written.db",
        store_settings=StoreSettings(path=str(tmp_path / "x.db")),
    )


def _backup(tmp_path: Path) -> Awaitable[object]:
    runner = BackupRunner(
        None,  # type: ignore[arg-type]  # the key is resolved before the store is touched
        BackupSettings(enabled=True, destination=str(tmp_path / "dest")),
        store_settings=StoreSettings(path=str(tmp_path / "x.db")),
        config_dir=None,
        instance="dev",
    )
    return runner._do_backup(0.0)


_ENTRY_POINTS = pytest.mark.parametrize(
    "call", [_verify, _restore, _backup], ids=["restore-verify", "restore", "backup"]
)
_Call = Callable[[Path], Awaitable[object]]


class _Provider:
    """Stands in for both key seams: holds its caller until released, then answers or raises."""

    def __init__(self, *, raises: BaseException | None = None, hold: bool = False) -> None:
        self.raises = raises
        self.hold = hold
        self.entered = threading.Event()
        self.release = threading.Event()
        self.left = threading.Event()

    def _answer(self) -> str:
        self.entered.set()
        try:
            if self.hold:
                self.release.wait(_HOLD_SECONDS)
            if self.raises is not None:
                raise self.raises
            return _GOOD_KEY
        finally:
            self.left.set()

    def active(self, _settings: object, *, posture: object = None) -> str:
        return self._answer()

    def keyring(self, _settings: object, *, posture: object = None) -> list[str]:
        return [self._answer()]


def _install(monkeypatch: pytest.MonkeyPatch, provider: _Provider) -> None:
    monkeypatch.setattr(dr_backup, "resolve_active_key", provider.active)
    monkeypatch.setattr(dr_backup, "resolve_decrypt_keys", provider.keyring)


@pytest.fixture
def held(monkeypatch: pytest.MonkeyPatch) -> Iterator[_Provider]:
    provider = _Provider(raises=KeyProviderError("synthetic refusal"), hold=True)
    _install(monkeypatch, provider)
    try:
        yield provider
    finally:
        provider.release.set()
        assert not provider.entered.is_set() or provider.left.wait(_HOLD_SECONDS * 2)


@_ENTRY_POINTS
async def test_the_loop_stays_live_while_the_key_provider_blocks(
    call: _Call, tmp_path: Path, held: _Provider
) -> None:
    """Red before the fix: the provider ran on the loop, so it had left before the loop ran again."""
    task = asyncio.ensure_future(call(tmp_path))
    await until(held.entered.is_set, "the provider call", timeout=_HOLD_SECONDS)
    assert not held.left.is_set(), "the loop did not run while the provider was blocked"
    held.release.set()
    with pytest.raises(KeyProviderError, match="synthetic refusal"):
        await task


async def test_the_takeover_timeout_fires_on_a_blocked_key_provider(
    tmp_path: Path, held: _Provider
) -> None:
    """Red before the fix: the timeout could not fire, and the provider's own error aborted as
    ``seed`` once it returned. The abort must be the ``key`` one, while the provider still holds."""

    async def noop() -> None:
        return None

    store = await MessageStore.open(tmp_path / "msg.db")
    try:
        coord = drmod.DrCoordinator(
            store,
            DrSettings(enabled=True, takeover_timeout_seconds=0.2),
            store_settings=StoreSettings(path=str(tmp_path / "x.db")),
            activate_profile=noop,
            deactivate_profile=noop,
        )
        with pytest.raises(drmod.DrActivationError) as raised:
            await coord._verify_seed(str(tmp_path / "seed.mfbak"), "synthetic-actor", 1.0)
        assert raised.value.kind == "key"
        assert "KeyProvider unreachable" in str(raised.value)
        assert held.entered.is_set() and not held.left.is_set()
    finally:
        held.release.set()
        await store.close()


@_ENTRY_POINTS
@pytest.mark.parametrize(
    "error",
    [
        DpapiError("synthetic dpapi refusal"),
        KeyProviderError("synthetic provider refusal"),
        StoreCipherConfigError("synthetic cipher refusal"),
    ],
    ids=["dpapi", "key-provider", "cipher-config"],
)
async def test_each_key_error_reaches_the_caller_unchanged(
    call: _Call,
    error: Exception,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A control, green before and after: the same object, with no cause and no context."""
    _install(monkeypatch, _Provider(raises=error))
    with pytest.raises(type(error)) as caught:
        await call(tmp_path)
    assert caught.value is error
    assert error.__cause__ is None and error.__context__ is None


@_ENTRY_POINTS
async def test_a_key_that_does_not_decode_refuses_off_the_loop(
    call: _Call, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The decode shares the hop, and its typed refusal still arrives with no chain."""
    seen: list[int] = []
    real = dr_backup._decode_store_key

    def decode(key: str) -> bytes:
        seen.append(threading.get_ident())
        return real("!!!not-base64")

    _install(monkeypatch, _Provider())
    monkeypatch.setattr(dr_backup, "_decode_store_key", decode)
    with pytest.raises(StoreCipherConfigError) as caught:
        await call(tmp_path)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert seen and threading.get_ident() not in seen


@pytest.mark.parametrize("call", [_verify, _restore], ids=["restore-verify", "restore"])
async def test_the_blocking_step_runs_only_after_the_key_hop_and_gets_its_keys(
    call: _Call, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def blocking(**kwargs: Any) -> object:
        return kwargs["keys"]

    _install(monkeypatch, _Provider())
    monkeypatch.setattr(dr_backup, "_verify_archive_blocking", blocking)
    monkeypatch.setattr(dr_backup, "_restore_blocking", blocking)
    assert await call(tmp_path) == [bytes(32)]
