# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5888: the DR restore-verify resolves a read-only store key off the event loop.

It resolved and decoded the key on the loop, so a slow key provider would have stalled the engine
and, on a DR activation, kept the takeover timeout around ``run_restore_verify`` from firing. A
provider whose resolve can write custody state stays on the loop, so an abort cannot land mid-write.
``run_restore`` and the backup still resolve on the loop, as on main.
Every key and provider here is synthetic, and no Vault server is started."""

from __future__ import annotations

import asyncio
import sys
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import restricted_file
from messagefoundry.config.settings import BackupSettings, DrSettings, StoreSettings
from messagefoundry.pipeline import dr as drmod
from messagefoundry.pipeline import dr_backup
from messagefoundry.pipeline.dr_backup import BackupRunner
from messagefoundry.secrets_dpapi import DpapiError
from messagefoundry.store import MessageStore, custody_host
from messagefoundry.store.base import StoreCipherConfigError
from messagefoundry.store.keyprovider import KNOWN_PROVIDERS, KeyProviderError
from tests._refusal_log_capture import until
from tests.test_store_custody_host import _handoff, _proved_blob

#: A safety bound on the fake provider's hold, well past any scheduling delay on a loaded runner, so
#: it cannot expire on correct code. Each test releases it. On the unfixed code it holds the loop.
_HOLD_SECONDS = 30.0
_GOOD_KEY = "A" * 43 + "="


def _store(tmp_path: Path, provider: str = "auto") -> StoreSettings:
    # model_copy: an unknown name must reach the code under test, past the settings validator.
    return StoreSettings(path=str(tmp_path / "x.db")).model_copy(update={"key_provider": provider})


def _verify(tmp_path: Path, provider: str = "auto") -> Awaitable[object]:
    return dr_backup.run_restore_verify(
        str(tmp_path / "never-read.mfbak"), store_settings=_store(tmp_path, provider)
    )


def _restore(tmp_path: Path, provider: str = "auto") -> Awaitable[object]:
    return dr_backup.run_restore(
        str(tmp_path / "never-read.mfbak"),
        dest_store_path=tmp_path / "never-written.db",
        store_settings=_store(tmp_path, provider),
    )


def _backup(tmp_path: Path, provider: str = "auto") -> Awaitable[object]:
    runner = BackupRunner(
        None,  # type: ignore[arg-type]  # the key is resolved before the store is touched
        BackupSettings(enabled=True, destination=str(tmp_path / "dest")),
        store_settings=_store(tmp_path, provider),
        config_dir=None,
        instance="dev",
    )
    return runner._do_backup(0.0)


_ENTRY_POINTS = pytest.mark.parametrize(
    "call", [_verify, _restore, _backup], ids=["restore-verify", "restore", "backup"]
)
_HOP_ENTRY_POINTS = pytest.mark.parametrize("call", [_verify], ids=["restore-verify"])
_Call = Callable[..., Awaitable[object]]


class _Provider:
    """Stands in for both key seams: holds its caller until released, then answers or raises."""

    def __init__(self, *, raises: BaseException | None = None, hold: bool = False) -> None:
        self.raises = raises
        self.hold = hold
        self.entered = threading.Event()
        self.release = threading.Event()
        self.left = threading.Event()
        self.threads: list[int] = []

    def _answer(self) -> str:
        self.threads.append(threading.get_ident())
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
        assert not provider.entered.is_set() or provider.left.wait(_HOLD_SECONDS)


@_HOP_ENTRY_POINTS
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
    tmp_path: Path, held: _Provider, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the fix: the timeout could not fire, and the provider's own error aborted as
    ``seed`` once it returned. The abort must be the ``key`` one, while the provider still holds."""

    def keyring(_settings: object, _posture: object) -> list[bytes]:
        # Replaces the whole hop: a worker that starts after this test has undone its patches then
        # reaches only this fake, never the real resolver.
        return [dr_backup._decode_store_key(k) for k in held.keyring(_settings)]

    async def noop() -> None:
        return None

    monkeypatch.setattr(dr_backup, "_resolve_decrypt_keyring", keyring)
    store = await MessageStore.open(tmp_path / "msg.db")
    try:
        coord = drmod.DrCoordinator(
            store,
            DrSettings(enabled=True, takeover_timeout_seconds=0.2),
            store_settings=_store(tmp_path),
            activate_profile=noop,
            deactivate_profile=noop,
        )
        with pytest.raises(drmod.DrActivationError) as raised:
            await coord._verify_seed(str(tmp_path / "seed.mfbak"), "synthetic-actor", 1.0)
        assert raised.value.kind == "key"
        assert "KeyProvider unreachable" in str(raised.value)
        # Not `entered`: on a loaded runner the timeout can fire before the worker thread starts.
        assert not held.left.is_set()
    finally:
        held.release.set()
        await store.close()


@_ENTRY_POINTS
@pytest.mark.parametrize(
    "make_error",
    [
        lambda: DpapiError("synthetic dpapi refusal"),
        lambda: KeyProviderError("synthetic provider refusal"),
        lambda: StoreCipherConfigError("synthetic cipher refusal"),
    ],
    ids=["dpapi", "key-provider", "cipher-config"],
)
@pytest.mark.parametrize("provider", ["auto", "host"], ids=["off-loop", "inline"])
async def test_each_key_error_reaches_the_caller_unchanged(
    call: _Call,
    make_error: Callable[[], Exception],
    provider: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A control, green before and after: the same object, with no cause and no context."""
    error = make_error()
    _install(monkeypatch, _Provider(raises=error))
    with pytest.raises(type(error)) as caught:
        await call(tmp_path, provider)
    assert caught.value is error
    assert error.__cause__ is None and error.__context__ is None


@_HOP_ENTRY_POINTS
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


# --- which providers take the hop -------------------------------------------------------------


@_HOP_ENTRY_POINTS
@pytest.mark.parametrize("name", ["auto", "env", "dpapi", "vault"])
async def test_a_read_only_provider_resolves_off_the_loop(
    call: _Call, name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    provider = _Provider(raises=KeyProviderError("synthetic refusal"))
    _install(monkeypatch, provider)
    with pytest.raises(KeyProviderError):
        await call(tmp_path, name)
    assert provider.threads and threading.get_ident() not in provider.threads


@pytest.mark.parametrize("call", [_restore, _backup], ids=["restore", "backup"])
@pytest.mark.parametrize("name", ["auto", "env", "dpapi", "vault", "host", "synthetic-unknown"])
async def test_restore_and_backup_resolve_on_the_loop_as_main_does(
    call: _Call, name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The row's remainder. A backup hop needs a bounded wait wired to its failure row."""
    provider = _Provider(raises=KeyProviderError("synthetic refusal"))
    _install(monkeypatch, provider)
    with pytest.raises(KeyProviderError):
        await call(tmp_path, name)
    assert provider.threads == [threading.get_ident()]


@_HOP_ENTRY_POINTS
@pytest.mark.parametrize("name", ["host", "synthetic-unknown"])
async def test_a_writing_or_unknown_provider_resolves_on_the_loop(
    call: _Call, name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red before the rule: every provider took the thread hop."""
    provider = _Provider(raises=KeyProviderError("synthetic refusal"))
    _install(monkeypatch, provider)
    with pytest.raises(KeyProviderError):
        await call(tmp_path, name)
    assert provider.threads == [threading.get_ident()]


def test_every_known_provider_but_host_is_classified_read_only() -> None:
    """A provider added later turns this red, though it resolves on the loop meanwhile. List it as
    read-only only after checking that its resolve writes no custody or key file."""
    assert {*dr_backup._READ_ONLY_KEY_PROVIDERS, "host"} == set(KNOWN_PROVIDERS)


@pytest.mark.skipif(sys.platform != "win32", reason="the handoff is Windows-only")
async def test_an_abort_is_not_followed_by_a_custody_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real host provider and a real synthetic handoff. Red before the rule: the abort returned
    with the handoff in place, and the abandoned thread then wrote the host file and deleted it.

    The timer expires during the on-loop resolve and fires at the first yield after it, the verify
    hop, which the stand-in holds open. So the conversion is complete when the abort arrives."""
    for name in (
        "MEFOR_STORE_ENCRYPTION_KEY",
        "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
        "MEFOR_SECRETS_DIRECTORY",
    ):
        monkeypatch.delenv(name, raising=False)
    sid = custody_host._engine_sid()
    if sid is not None and sid.upper().startswith("S-1-5-21-"):
        domain = sid.rpartition("-")[0]
        monkeypatch.setattr(restricted_file, "local_account_domain_sid", lambda: domain)
    handoff, host = tmp_path / "handoff.key", tmp_path / "master.key"
    _handoff(handoff, _proved_blob())
    finished = threading.Event()
    threads: list[int] = []
    real = custody_host._convert_handoff

    def slow_convert(host_path: Path, handoff_path: Path) -> Any:
        threads.append(threading.get_ident())
        time.sleep(0.4)  # longer than the caller's timeout below
        try:
            return real(host_path, handoff_path)
        finally:
            finished.set()

    def files() -> tuple[bool, bool]:
        return handoff.exists(), host.exists()

    def slow_verify(**_kwargs: object) -> object:
        time.sleep(0.5)
        return None

    monkeypatch.setattr(custody_host, "_convert_handoff", slow_convert)
    monkeypatch.setattr(dr_backup, "_verify_archive_blocking", slow_verify)
    settings = StoreSettings(path=str(tmp_path / "store.db")).model_copy(
        update={"key_provider": "host"}
    )
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(
            dr_backup.run_restore_verify(str(tmp_path / "none.mfbak"), store_settings=settings),
            timeout=0.1,
        )
    at_abort = files()
    assert at_abort == (False, True), "the conversion had not completed when the abort arrived"
    assert finished.is_set()
    assert threads == [threading.get_ident()]
