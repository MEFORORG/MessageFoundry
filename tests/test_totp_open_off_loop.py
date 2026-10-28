# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3929: the auth service opens a TOTP cell OFF the event loop, on every path that reaches
it.

Under the ``vault_transit`` cipher a decrypt is a blocking HTTP call (``crypto_transit.py``,
``decrypt_data``). The combined sign-in opens the cell before it knows the password is right, so a
username alone reaches it; on the loop, each attempt would hold every request the engine serves for
one Transit round trip (CLAUDE.md section 6). These tests put a cipher that blocks for a measured
time in place of the store's opener, and measure the loop itself, with a second task standing in for
another request.
"""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Awaitable, Callable
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth import totp
from messagefoundry.auth.identity import Identity
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import ADMIN_USERNAME, login_admin
from tests._totp_clock import pin_totp_clock

#: How long the stub cipher holds each open: long against a loop tick, so a stall is unmistakable.
_BLOCK = 0.6
#: The longest loop stall the off-loop arm tolerates: well under one blocked open, and well over a
#: scheduler hiccup on a loaded runner.
_TOLERATED_STALL = _BLOCK / 2

_Opener = Callable[[str, str | None], str | None]


class _Steps:
    """Pins the TOTP clock and hands out the code of a fresh step on every call, so no code is
    refused as a replay of the step the enrolment consumed."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, secret: str) -> None:
        self._monkeypatch = monkeypatch
        self._secret = secret
        self._now = 3_000_000.0

    def next_code(self) -> str:
        self._now += totp.DEFAULT_PERIOD
        pin_totp_clock(self._monkeypatch, self._now)
        return totp.totp(self._secret, now=self._now)


async def _totp_admin(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, *, before_confirm: Callable[[], None]
) -> tuple[AuthService, Identity, str, _Steps, list[str]]:
    """An Administrator with TOTP active, and a padding seam that does not wait. ``before_confirm``
    runs between the enrolment's begin and its confirm, so a spy can see the confirm's open.
    Returns the service, the identity, the password, the code stepper and the recovery codes."""

    async def no_pad(_deadline: float) -> None:
        return None

    monkeypatch.setattr(service_module, "_sleep_until", no_pad)
    # A blocked open overruns the failure budget, and that warning latches once per process; a
    # private latch keeps this file from silencing it for a later test that asserts it.
    monkeypatch.setattr(service_module, "_BUDGET_OVERRUN_WARNED", set())
    service = AuthService(
        store, AuthSettings(mfa_verify_min_elapsed_seconds=0, login_rate_limit_enabled=False)
    )
    identity, token, password = await login_admin(service)
    enroll = await service.begin_mfa_enrollment(identity)
    steps = _Steps(monkeypatch, enroll.secret)
    before_confirm()
    confirmed = await service.confirm_mfa_enrollment(identity, steps.next_code(), token=token)
    assert confirmed.ok and confirmed.recovery_codes
    return service, identity, password, steps, list(confirmed.recovery_codes)


def _blocking_cipher(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[_Opener, list[threading.Thread]]:
    """Stand a cipher that blocks for :data:`_BLOCK` in place of the store's TOTP opener, as a
    Transit ``decrypt_data`` round trip would. Returns the stub and the threads it ran on."""
    real_open = store.open_totp_secret
    threads: list[threading.Thread] = []

    def blocking_open(user_id: str, cell: str | None) -> str | None:
        threads.append(threading.current_thread())
        time.sleep(_BLOCK)
        return real_open(user_id, cell)

    monkeypatch.setattr(store, "open_totp_secret", blocking_open)
    return blocking_open, threads


async def _longest_stall[T](work: Awaitable[T]) -> tuple[T, float]:
    """``work``'s result, and the longest the event loop went without running another task while
    ``work`` ran. A heartbeat task, standing in for any other request the engine serves, notes the
    time between each of its turns."""
    stalls = [0.0]
    stop = asyncio.Event()

    async def heartbeat() -> None:
        last = time.perf_counter()
        while not stop.is_set():
            await asyncio.sleep(0.005)
            now = time.perf_counter()
            stalls.append(now - last)
            last = now

    beat = asyncio.create_task(heartbeat())
    await asyncio.sleep(0)  # the heartbeat takes its first turn before the work starts
    try:
        result = await work
    finally:
        stop.set()
        await beat
    return result, max(stalls)


@pytest.mark.parametrize("on_loop", [False, True], ids=["off-loop", "control-on-loop"])
async def test_a_combined_sign_in_does_not_stall_the_loop_on_a_blocking_decrypt(
    monkeypatch: pytest.MonkeyPatch, on_loop: bool
) -> None:
    """A combined sign-in with a WRONG password, as anyone who knows the username can send, waits on
    a decrypt that blocks for :data:`_BLOCK`; the loop keeps serving the heartbeat meanwhile.

    The control runs the same blocking cipher ON the loop, by making the service's hand-off run the
    stub inline, and shows the instrument sees the stall, so the off-loop arm can fail."""
    store = await MessageStore.open(":memory:")
    try:
        service, _identity, _password, steps, _codes = await _totp_admin(
            store, monkeypatch, before_confirm=lambda: None
        )
        loop_thread = threading.current_thread()
        blocking_open, threads = _blocking_cipher(store, monkeypatch)
        if on_loop:
            real_to_thread = asyncio.to_thread

            async def inline_for_the_cipher(fn: Callable[..., Any], /, *a: Any, **kw: Any) -> Any:
                if fn is blocking_open:
                    return fn(*a, **kw)
                return await real_to_thread(fn, *a, **kw)

            monkeypatch.setattr(asyncio, "to_thread", inline_for_the_cipher)
        out, stall = await _longest_stall(
            service.login(ADMIN_USERNAME, "not-the-passphrase", totp_code=steps.next_code())
        )
        assert not out.ok
        assert threads, "the combined sign-in opened no cell, so the stub measured nothing"
        if on_loop:
            assert stall >= _BLOCK * 0.9, f"the control saw no stall ({stall:.3f}s)"
            assert loop_thread in threads
            return
        assert stall < _TOLERATED_STALL, f"the loop stalled {stall:.3f}s on a blocking decrypt"
        assert loop_thread not in threads, "a TOTP cell was opened on the event loop"
    finally:
        await store.close()


async def test_the_service_paths_that_open_the_totp_cell_open_it_off_the_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """At least these service paths open the TOTP cell in a worker thread: the enrolment's confirm,
    the combined sign-in, the two-step verify (its code check and its before-and-after enrolment
    reads), a replayed code's failed spend (its after-read), a way-past gate (``_totp_state``), and
    the status read where a re-enrolment is possible. The lockable-account census is not among them:
    it reads through the store's ``get_totp_secret``, whose decrypt is the store's own."""
    store = await MessageStore.open(":memory:")
    try:
        real_open = store.open_totp_secret
        seen: dict[str, list[threading.Thread]] = {}
        path = ["setup"]

        def spy(user_id: str, cell: str | None) -> str | None:
            seen.setdefault(path[0], []).append(threading.current_thread())
            return real_open(user_id, cell)

        def install() -> None:
            path[0] = "confirm"
            monkeypatch.setattr(store, "open_totp_secret", spy)

        service, identity, password, steps, _codes = await _totp_admin(
            store, monkeypatch, before_confirm=install
        )
        path[0] = "combined"
        assert (await service.login(ADMIN_USERNAME, password, totp_code=steps.next_code())).ok
        path[0] = "two-step"
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.ok and pending.mfa_required and pending.token is not None
        code = steps.next_code()
        assert (await service.verify_mfa(pending.token, code)).ok
        path[0] = "replayed"
        again = await service.login(ADMIN_USERNAME, password)
        assert again.ok and again.token is not None
        assert not (await service.verify_mfa(again.token, code)).ok  # its step is spent
        path[0] = "gate"
        await service.must_enrol_before_rotating(identity)
        path[0] = "status"
        monkeypatch.setattr(totp, "reenrolment_possible", lambda: True)
        await service.mfa_status(identity)
        assert set(seen) == {"confirm", "combined", "two-step", "replayed", "gate", "status"}, (
            sorted(seen)
        )
        # A verify opens the cell for the enrolment it checks, for the code, and again for the
        # enrolment the row holds after the check; the replay's after-read is its third.
        assert len(seen["two-step"]) >= 3 and len(seen["replayed"]) >= 3, seen
        loop_thread = threading.current_thread()
        on_loop = sorted(p for p, threads in seen.items() if loop_thread in threads)
        assert on_loop == [], f"a TOTP cell was opened on the event loop by: {on_loop}"
    finally:
        await store.close()


async def test_a_cell_that_did_not_open_before_the_check_spends_no_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The two-step verify reads the enrolment before the check and compares it after. Where that
    first open fails and a later one would succeed, as a Transit service that drops one request
    can do, the verify is refused ``factor_unverified`` BEFORE the check, so a recovery code sent
    with it is not spent: it still verifies once the cell opens. RED when the code is checked and
    spent against an enrolment the request can no longer compare, and then refused anyway."""
    from messagefoundry.store.crypto import CipherError

    store = await MessageStore.open(":memory:")
    try:
        service, _identity, password, _steps, codes = await _totp_admin(
            store, monkeypatch, before_confirm=lambda: None
        )
        real_open = store.open_totp_secret
        fails = [1]

        def drops_one(user_id: str, cell: str | None) -> str | None:
            if fails[0]:
                fails[0] -= 1
                raise CipherError("synthetic: the cipher service dropped this request")
            return real_open(user_id, cell)

        monkeypatch.setattr(store, "open_totp_secret", drops_one)
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.ok and pending.token is not None
        assert not (await service.verify_mfa(pending.token, codes[0])).ok
        rows = await store.list_audit(action="auth.mfa_failed")
        assert any((r["detail"] or "").find("factor_unverified") >= 0 for r in rows), rows
        # The control: the same recovery code was not spent, so it verifies now.
        assert (await service.verify_mfa(pending.token, codes[0])).ok
    finally:
        await store.close()


async def test_a_cell_that_opens_before_the_check_but_not_for_it_spends_no_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The other order: the enrolment read before the check opens, the check's own open does not.
    The check raises at its TOTP decrypt, before any recovery code is read, so the verify is refused
    ``factor_unverified``, never raised, and the recovery code still verifies afterwards."""
    from messagefoundry.store.crypto import CipherError

    store = await MessageStore.open(":memory:")
    try:
        service, _identity, password, _steps, codes = await _totp_admin(
            store, monkeypatch, before_confirm=lambda: None
        )
        real_open = store.open_totp_secret
        opens = [0]

        def second_fails(user_id: str, cell: str | None) -> str | None:
            opens[0] += 1
            if opens[0] == 2:
                raise CipherError("synthetic: the cipher service dropped this request")
            return real_open(user_id, cell)

        monkeypatch.setattr(store, "open_totp_secret", second_fails)
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.ok and pending.token is not None
        assert not (await service.verify_mfa(pending.token, codes[0])).ok
        assert opens[0] == 2, "the verify did not reach the check's own open"
        rows = await store.list_audit(action="auth.mfa_failed")
        assert any((r["detail"] or "").find("factor_unverified") >= 0 for r in rows), rows
        assert (await service.verify_mfa(pending.token, codes[0])).ok
    finally:
        await store.close()


async def test_a_disable_during_the_after_check_comparison_stops_the_factor_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The after-check comparison opens the cell in a worker thread, so a self-service disable,
    which takes no account queue, can land during it. The holder is read again after it, so the
    disable is seen: the verify is refused ``factor_removed`` and the session's factor is not
    marked. RED when the factor is written after the comparison with no read of the holder."""
    store = await MessageStore.open(":memory:")
    try:
        service, identity, password, steps, _codes = await _totp_admin(
            store, monkeypatch, before_confirm=lambda: None
        )
        real_moved = service._totp_enrolment_moved
        landed: list[bool] = []

        async def disable_lands_meanwhile(*args: Any, **kwargs: Any) -> Any:
            moved = await real_moved(*args, **kwargs)
            if not landed:
                landed.append(True)
                await store.disable_totp(identity.user_id)
            return moved

        monkeypatch.setattr(service, "_totp_enrolment_moved", disable_lands_meanwhile)
        pending = await service.login(ADMIN_USERNAME, password)
        assert pending.ok and pending.token is not None
        assert not (await service.verify_mfa(pending.token, steps.next_code())).ok
        assert landed, "the comparison never ran, so nothing landed during it"
        assert not await service.mfa_satisfied(pending.token)
        rows = await store.list_audit(action="auth.mfa_failed")
        assert any((r["detail"] or "").find("factor_removed") >= 0 for r in rows), rows
    finally:
        await store.close()
