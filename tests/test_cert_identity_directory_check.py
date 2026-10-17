# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An mTLS certificate identity for a directory account asks the directory on every request.

BACKLOG #2316. ``identity_for_cert_user_id`` read only the engine row's ``disabled`` flag and stored
roles. The reconciler probes only accounts holding a live session, and a certificate caller holds
none, so nothing refreshed either one: a directory-side disable or group removal never reached the
certificate path. Now an AD row is probed on each request and fails closed, and its roles narrow to
what its current groups still map to. A local account is the control that is never probed. All
directory data here is synthetic.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest

from messagefoundry.auth import reconcile
from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import DirectoryAnswer, DirectoryProbe, LdapReferralError
from messagefoundry.auth.permissions import Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore, UserRecord
from tests._admin_account import login_admin
from tests.test_mfa_directory_recheck import _OPERATORS, _PRINCIPAL, _VIEWERS, _Directory, _settings

_SERVICE_LOGGER = "messagefoundry.auth.service"
_OUTAGE_LINE = "mTLS certificate identities for directory accounts"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _directory_account(
    store: MessageStore, *groups: str, role_map: list[tuple[str, str]] | None = None
) -> tuple[AuthService, _Directory, str]:
    """A directory account whose roles a sign-in wrote from ``groups`` under the synthetic map.

    The sign-in is only how the row is born. The certificate path holds no session."""
    await AuthService(store, _settings()).initialize()  # the map's role ids need the seeded roles
    await store.set_ad_group_role_map(role_map or [(_OPERATORS, "operator"), (_VIEWERS, "viewer")])
    principal = replace(_PRINCIPAL, groups=frozenset(groups))
    directory = _Directory(principal)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    await service.initialize()
    login = await service._complete_ad_login(principal, None, mfa_verified=False)
    assert login.identity is not None
    directory.probes.clear()
    return service, directory, login.identity.user_id


async def test_an_enabled_unchanged_directory_account_resolves_with_its_full_roles(
    store: MessageStore,
) -> None:
    """The control: the check must not refuse the account it exists to let through, and asks the
    directory by the immutable id."""
    service, directory, user_id = await _directory_account(store, _OPERATORS, _VIEWERS)

    identity = await service.identity_for_cert_user_id(user_id)

    assert identity is not None
    assert identity.auth_provider is AuthProvider.AD
    assert identity.roles == {Role.OPERATOR, Role.VIEWER}
    assert directory.probes == [("jdoe", _PRINCIPAL.directory_object_id)]


async def test_every_request_asks_again(store: MessageStore) -> None:
    """No cache: a cached answer would bring back the staleness this item removes."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)

    assert await service.identity_for_cert_user_id(user_id) is not None
    directory.answer = DirectoryAnswer.DISABLED
    assert await service.identity_for_cert_user_id(user_id) is None
    assert len(directory.probes) == 2


@pytest.mark.parametrize(
    "answer",
    [DirectoryAnswer.DISABLED, DirectoryAnswer.NOT_FOUND, DirectoryAnswer.UNDETERMINED],
    ids=["disabled", "absent", "undetermined"],
)
async def test_a_directory_account_the_directory_does_not_confirm_is_refused(
    store: MessageStore, answer: DirectoryAnswer
) -> None:
    """RED when: the certificate path reads only the engine row, which still says enabled."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    directory.answer = answer

    assert await service.identity_for_cert_user_id(user_id) is None
    assert directory.probes == [("jdoe", _PRINCIPAL.directory_object_id)]
    user = await store.get_user(user_id)
    assert user is not None and user.disabled is False  # refused, and wrote nothing


async def test_an_unreachable_directory_refuses(store: MessageStore) -> None:
    """Fail closed: unlike the reconciler, which revokes and so fails open, this path grants."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    directory.unreachable = True

    assert await service.identity_for_cert_user_id(user_id) is None


async def test_a_referring_directory_refuses(store: MessageStore) -> None:
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    directory.raises = LdapReferralError("synthetic: AD answered the user search with a referral")

    assert await service.identity_for_cert_user_id(user_id) is None


async def test_a_lookup_that_raises_something_else_refuses(store: MessageStore) -> None:
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    directory.raises = KeyError("userAccountControl")

    assert await service.identity_for_cert_user_id(user_id) is None


async def test_a_row_with_no_directory_id_is_refused_unasked(store: MessageStore) -> None:
    """Its only other key is its name, which a directory may reissue to someone else."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    await store._db.execute("UPDATE users SET directory_object_id = NULL WHERE id = ?", (user_id,))
    await store._db.commit()

    assert await service.identity_for_cert_user_id(user_id) is None
    assert directory.probes == []


async def test_a_directory_account_with_no_directory_configured_is_refused(
    store: MessageStore,
) -> None:
    """Nothing can confirm it, so nothing is granted."""
    _service, _directory, user_id = await _directory_account(store, _VIEWERS)
    unwired = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))

    assert await unwired.identity_for_cert_user_id(user_id) is None


async def test_an_account_removed_from_one_of_two_groups_keeps_only_the_other_role(
    store: MessageStore,
) -> None:
    """Roles NARROW to what the current groups still map to; they do not refuse outright, and the
    stored roles are left for a sign-in to re-sync.

    RED when: the identity still carries the operator role the directory withdrew."""
    service, directory, user_id = await _directory_account(store, _OPERATORS, _VIEWERS)
    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))

    identity = await service.identity_for_cert_user_id(user_id)

    assert identity is not None
    assert identity.roles == {Role.VIEWER}
    assert set(await store.get_user_role_ids(user_id)) == {"operator", "viewer"}  # wrote nothing


async def test_a_role_the_directory_grants_but_the_row_does_not_hold_is_not_granted(
    store: MessageStore,
) -> None:
    """Never more than the row holds: this path writes nothing and must not grant."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    directory.principal = replace(_PRINCIPAL, groups=frozenset({_OPERATORS, _VIEWERS}))

    identity = await service.identity_for_cert_user_id(user_id)

    assert identity is not None and identity.roles == {Role.VIEWER}


async def test_an_account_removed_from_every_mapped_group_is_refused(
    store: MessageStore,
) -> None:
    service, directory, user_id = await _directory_account(store, _OPERATORS, _VIEWERS)
    directory.principal = replace(_PRINCIPAL, groups=frozenset())

    assert await service.identity_for_cert_user_id(user_id) is None


async def test_a_local_account_is_never_probed(store: MessageStore) -> None:
    """The control: a local row behaves exactly as before, and the directory sees no call."""
    directory = _Directory(_PRINCIPAL)
    service = AuthService(store, _settings(), ldap=directory)  # type: ignore[arg-type]
    identity, _token, _ = await login_admin(service)

    resolved = await service.identity_for_cert_user_id(identity.user_id)

    assert resolved is not None and resolved.user_id == identity.user_id
    assert directory.probes == []


async def test_a_full_probe_cap_refuses_after_the_bounded_wait(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every slot is held, as a burst during a slow directory would hold them, and the wait bound
    passes: the request is refused rather than queued, and asks the directory nothing."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    monkeypatch.setattr(service_module, "_CERT_PROBE_SLOT_WAIT_SECONDS", 0.05)
    for _ in range(service_module._CERT_PROBE_MAX_CONCURRENCY):
        await service._cert_probe_slots.acquire()

    assert await service.identity_for_cert_user_id(user_id) is None
    assert directory.probes == []

    service._cert_probe_slots.release()  # one slot frees: the next request is asked about again
    assert await service.identity_for_cert_user_id(user_id) is not None
    assert len(directory.probes) == 1


async def test_more_requests_than_the_cap_all_reach_the_directory_in_turn(
    store: MessageStore,
) -> None:
    """RED when: a finished probe does not give its slot back, so the cap fills and stays full."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    calls = service_module._CERT_PROBE_MAX_CONCURRENCY * 2 + 1

    for _ in range(calls):
        assert await service.identity_for_cert_user_id(user_id) is not None

    assert len(directory.probes) == calls


async def test_a_cancelled_request_holds_its_slot_until_the_probe_thread_ends(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The probe's worker thread cannot be cancelled. Releasing the slot when the caller gives up
    would let the threads outnumber the cap; the slot comes back when the thread is done."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    entered, gate = threading.Event(), threading.Event()
    real_probe = directory.probe_principal

    def _gated(username: str, *, object_id: str | None = None) -> DirectoryProbe:
        entered.set()
        gate.wait(10)
        return real_probe(username, object_id=object_id)

    monkeypatch.setattr(directory, "probe_principal", _gated)
    request = asyncio.create_task(service.identity_for_cert_user_id(user_id))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        assert len(service._cert_probe_tasks) == 1  # the probe still runs
        # RED when: the slot goes back with the cancelled caller. The orphaned probe holds one,
        # so only CAP-1 can be taken without waiting, and the CAP-th would block.
        for _ in range(service_module._CERT_PROBE_MAX_CONCURRENCY - 1):
            assert not service._cert_probe_slots.locked()
            await service._cert_probe_slots.acquire()
        assert service._cert_probe_slots.locked()
        for _ in range(service_module._CERT_PROBE_MAX_CONCURRENCY - 1):
            service._cert_probe_slots.release()
    finally:
        gate.set()
    async with asyncio.timeout(10):
        while service._cert_probe_tasks:
            await asyncio.sleep(0.01)

    # Every slot is free again: all of them can be taken without waiting.
    for _ in range(service_module._CERT_PROBE_MAX_CONCURRENCY):
        assert not service._cert_probe_slots.locked()
        await service._cert_probe_slots.acquire()
    assert service._cert_probe_slots.locked()
    for _ in range(service_module._CERT_PROBE_MAX_CONCURRENCY):
        service._cert_probe_slots.release()
    with pytest.raises(ValueError):  # bounded: a release with no acquire cannot widen the cap
        service._cert_probe_slots.release()


async def test_a_probe_that_raises_after_its_caller_left_reports_nothing_to_the_loop(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raise from an orphaned probe would reach the loop's exception handler through the shield,
    one ERROR per cancelled request. The probe returns a refusal reason instead, and fails closed."""
    service, _directory, user_id = await _directory_account(store, _VIEWERS)
    entered, gate = asyncio.Event(), asyncio.Event()

    async def _raises(user: UserRecord) -> reconcile.Probe | str:
        entered.set()
        await gate.wait()
        raise RuntimeError("synthetic fault after the caller left")

    monkeypatch.setattr(service, "_directory_presence", _raises)
    loop = asyncio.get_running_loop()
    reported: list[dict[str, object]] = []
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, context: reported.append(context))
    try:
        request = asyncio.create_task(service.identity_for_cert_user_id(user_id))
        await entered.wait()
        request.cancel()
        with pytest.raises(asyncio.CancelledError):
            await request
        gate.set()
        async with asyncio.timeout(10):
            while service._cert_probe_tasks:
                await asyncio.sleep(0.01)
        await asyncio.sleep(0)  # let any done callback the shield scheduled run
    finally:
        loop.set_exception_handler(previous)

    assert reported == []
    # The same fault with the caller still waiting is a refusal, not a raise. The gate stays set.
    assert await service.identity_for_cert_user_id(user_id) is None


async def test_an_engine_fault_in_the_probe_has_its_own_reason_not_unavailable(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """BACKLOG #3115. A raise past the directory layer's own catches is an engine fault. Reported
    as ``unavailable`` it would send an operator after a directory outage that is not there.

    RED when: the certificate probe maps the fault to ``unavailable`` again."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    user = await store.get_user(user_id)
    assert user is not None
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)
    # The control: an unreachable directory is still "unavailable".
    directory.unreachable = True
    assert await service._cert_directory_presence(user) == "unavailable"
    directory.unreachable = False

    async def _raises(user: UserRecord) -> reconcile.Probe | str:
        raise RuntimeError("synthetic engine fault")

    monkeypatch.setattr(service, "_directory_presence", _raises)
    assert await service._cert_directory_presence(user) == service_module.CERT_PROBE_FAULT
    for _ in range(3):
        assert await service.identity_for_cert_user_id(user_id) is None

    # One WARNING while the fault persists, and never as a directory outage.
    assert _outage_records(caplog, logging.WARNING) == []
    warnings = [
        r.getMessage()
        for r in caplog.records
        if r.name == _SERVICE_LOGGER
        and r.levelno == logging.WARNING
        and "mTLS certificate identity" in r.getMessage()
    ]
    assert len(warnings) == 1 and "was refused: probe_fault" in warnings[0]
    assert "jdoe" not in warnings[0]


def _fault_warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == _SERVICE_LOGGER
        and r.levelno == logging.WARNING
        and "was refused: probe_fault" in r.getMessage()
    ]


async def _faulting_service(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[AuthService, _Directory, UserRecord, dict[str, bool]]:
    """A directory account whose certificate probe raises while ``state["faulting"]`` is set.
    Any other row probes as the account would, so another account answers beside it."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    user = await store.get_user(user_id)
    assert user is not None
    real = service._directory_presence
    state = {"faulting": True}

    async def _sometimes_raises(probed: UserRecord) -> reconcile.Probe | str:
        if state["faulting"] and probed.id == user_id:
            raise LookupError("synthetic engine fault")
        return await real(user)

    monkeypatch.setattr(service, "_directory_presence", _sometimes_raises)
    return service, directory, user, state


async def _ask(service: AuthService, row: UserRecord) -> object:
    answer = await service._cert_directory_presence(row)
    service._note_cert_directory_answer(answer)
    return answer


@pytest.mark.parametrize(
    "between",
    [
        DirectoryAnswer.FOUND,
        DirectoryAnswer.DISABLED,
        DirectoryAnswer.NOT_FOUND,
        DirectoryAnswer.UNDETERMINED,
    ],
    ids=lambda answer: answer.name.lower(),
)
async def test_a_probe_fault_is_tracked_per_account_and_ends_on_any_directory_answer(
    store: MessageStore,
    caplog: pytest.LogCaptureFixture,
    monkeypatch: pytest.MonkeyPatch,
    between: DirectoryAnswer,
) -> None:
    """BACKLOG #3115, the Lander's asks on PR 2317. A fault logs one WARNING naming the exception
    type and repeats at DEBUG. Another account's healthy answer does not end it, or one account
    whose entry always raises beside a healthy one would read as a flapping fault; any directory
    answer about the same account does. Inside the interval a new fault logs at DEBUG, and it
    warns once the interval since the account's last WARNING has passed.

    RED when: the WARNING omits the type, or another account's answer ends the fault, or an
    answer other than present does not, or a fault past the interval does not warn."""
    service, directory, user, state = await _faulting_service(store, monkeypatch)
    other = replace(user, id="synthetic-other-user-id")
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)

    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    warnings = _fault_warnings(caplog)
    assert len(warnings) == 1 and "LookupError" in warnings[0]
    assert "jdoe" not in warnings[0] and "synthetic engine fault" not in warnings[0]

    # A repeat while the fault persists is DEBUG, and so is it after ANOTHER account's answer.
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert isinstance(await _ask(service, other), reconcile.Probe)
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 2

    # This account gets a directory answer once, then faults again: a new fault, not a repeat.
    state["faulting"] = False
    directory.answer = between
    assert await _ask(service, user) != service_module.CERT_PROBE_FAULT
    state["faulting"] = True
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 2

    # The interval passes: the next fault warns.
    _age_last_warning(service, user)
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 2


def _age_last_warning(service: AuthService, user: UserRecord) -> None:
    """Move the account's last fault WARNING one interval into the past."""
    service._cert_probe_fault_warned_at[user.id] -= service_module._CERT_OUTAGE_LOG_INTERVAL_SECONDS


async def test_a_fault_returning_after_the_account_went_unprobed_warns(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Lander's 2026-10-16 addition. An account that is simply not probed for a while keeps
    its fault entry, so with no directory answer between, its next fault is a repeat. Once an
    interval has passed since its last WARNING, that repeat warns.

    RED when: a repeat never warns, so the returning fault is silent above DEBUG however long the
    gap. Measured RED on a3f41758d7."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT

    _age_last_warning(service, user)  # no probe of the account for an interval
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT

    warnings = _fault_warnings(caplog)
    assert len(warnings) == 2 and "LookupError" in warnings[1]


async def test_a_fault_repeating_inside_the_interval_stays_debug(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control for the test above: the same two faults with no interval between log one
    WARNING and one DEBUG repeat. If this ever logs a second WARNING, the test above no longer
    shows that the elapsed interval is what makes the repeat warn."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT

    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 1


async def test_a_flapping_probe_fault_warns_at_most_once_an_interval_and_is_never_silent(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An account whose probe alternates between raising and answering must not log a WARNING per
    request. A fault inside the interval logs its WARNING on its first repeat after it.

    RED when: the per-account WARNING has no interval, or a fault inside it is never logged."""
    service, _directory, user, state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)
    for _ in range(3):
        state["faulting"] = True
        assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
        state["faulting"] = False
        assert isinstance(await _ask(service, user), reconcile.Probe)
    assert len(_fault_warnings(caplog)) == 1

    # The interval passes while the account faults again.
    state["faulting"] = True
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    _age_last_warning(service, user)
    assert await _ask(service, user) == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 2


async def _set_disabled(service: AuthService, user: UserRecord, *, disabled: bool) -> None:
    """The administrator's edit, changing only the disabled flag."""
    await service.update_user(
        user.id,
        display_name=user.display_name,
        email=user.email,
        disabled=disabled,
        actor="synthetic-admin",
    )


def _repeat_debugs(caplog: pytest.LogCaptureFixture) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == _SERVICE_LOGGER
        and r.levelno == logging.DEBUG
        and "raised LookupError again" in r.getMessage()
    ]


async def test_a_re_enabled_account_whose_probe_still_faults_warns_again(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The Lander's review of PR 2317 at a3f41758d7. A fault, a local disable, a re-enable, and
    the probe still raises: that fault is a fresh healthy-to-fault transition, so it warns and
    names the type, even inside the WARNING interval (left at its real value here).

    RED when: the fault state outlives the account's exit from the probe set, so the re-entry
    fault takes the repeat branch and logs only at DEBUG."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)

    assert await service.identity_for_cert_user_id(user.id) is None
    assert len(_fault_warnings(caplog)) == 1
    # Leaving the probe set drops BOTH of the account's entries.
    await _set_disabled(service, user, disabled=True)
    assert user.id not in service._cert_probe_faulting
    assert user.id not in service._cert_probe_fault_warned_at
    await _set_disabled(service, user, disabled=False)

    assert await service.identity_for_cert_user_id(user.id) is None
    warnings = _fault_warnings(caplog)
    assert len(warnings) == 2 and "LookupError" in warnings[1]
    assert not _repeat_debugs(caplog)


async def test_without_the_reset_the_re_entry_fault_is_only_debug(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Negative control for the test above: with the reset made a no-op, the same sequence logs
    the re-entry fault only at DEBUG. If this ever logs a second WARNING, the test above no longer
    shows that the reset is what makes it warn."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    monkeypatch.setattr(service, "_forget_cert_probe_fault", lambda _user_id: None)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)

    assert await service.identity_for_cert_user_id(user.id) is None
    await _set_disabled(service, user, disabled=True)
    await _set_disabled(service, user, disabled=False)
    assert await service.identity_for_cert_user_id(user.id) is None

    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 1


async def test_a_disable_the_certificate_path_sees_drops_the_fault_state(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disable written by another writer (another engine process on the shared store) reaches
    this process first through the certificate path, which then drops both entries, the
    warned-at time included, rather than leaving them until eviction.

    RED when: only update_user drops the state, or the warned-at entry is never deleted."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    assert await service.identity_for_cert_user_id(user.id) is None
    assert user.id in service._cert_probe_faulting
    assert user.id in service._cert_probe_fault_warned_at

    await store._db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user.id,))
    await store._db.commit()
    assert await service.identity_for_cert_user_id(user.id) is None

    assert user.id not in service._cert_probe_faulting
    assert user.id not in service._cert_probe_fault_warned_at


async def test_a_profile_save_on_an_enabled_faulting_account_keeps_its_fault_state(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every administrator save posts the disabled flag. A save that leaves an enabled account
    enabled is not a re-entry, so the next fault stays a repeat at DEBUG.

    RED when: any save with ``disabled=False`` resets the state, so an edit re-arms the WARNING."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    assert await service.identity_for_cert_user_id(user.id) is None

    await service.update_user(
        user.id,
        display_name="Synthetic Renamed",
        email=user.email,
        disabled=False,
        actor="synthetic-admin",
    )
    assert await service.identity_for_cert_user_id(user.id) is None

    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 1


async def test_an_answer_to_a_probe_issued_before_the_fault_does_not_end_it(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Probes overlap. A slow answer to a probe that started before the fault says nothing about
    whether the fault cleared, so the next fault is a repeat.

    RED when: the fault ends in completion order rather than issue order."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    user = await store.get_user(user_id)
    assert user is not None
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    real = service._directory_presence
    release = asyncio.Event()
    calls = 0

    async def _first_slow_then_raises(probed: UserRecord) -> reconcile.Probe | str:
        nonlocal calls
        calls += 1
        if calls == 1:
            await release.wait()
            return await real(probed)
        raise LookupError("synthetic engine fault")

    monkeypatch.setattr(service, "_directory_presence", _first_slow_then_raises)
    slow = asyncio.create_task(service._cert_directory_presence(user))
    async with asyncio.timeout(10):
        while calls == 0:
            await asyncio.sleep(0)
    assert await service._cert_directory_presence(user) == service_module.CERT_PROBE_FAULT
    release.set()
    assert isinstance(await slow, reconcile.Probe)
    assert await service._cert_directory_presence(user) == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 1
    assert len(_repeat_debugs(caplog)) == 1


async def test_a_fault_from_a_probe_running_when_the_account_left_is_recorded_nowhere(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Probes that started before a disable say nothing about the account as it is. Their faults
    log at DEBUG and recreate no state, so requests for the disabled account between them cannot
    turn each one into a fresh WARNING.

    RED when: a fault from a probe already running at the disable recreates the state, or warns."""
    service, _directory, user_id = await _directory_account(store, _VIEWERS)
    user = await store.get_user(user_id)
    assert user is not None
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    gates: list[asyncio.Event] = []

    async def _slow_raises(probed: UserRecord) -> reconcile.Probe | str:
        gate = asyncio.Event()
        gates.append(gate)
        await gate.wait()
        raise LookupError("synthetic engine fault")

    monkeypatch.setattr(service, "_directory_presence", _slow_raises)
    first = asyncio.create_task(service._cert_directory_presence(user))
    async with asyncio.timeout(10):
        while not gates:
            await asyncio.sleep(0)
    gates[0].set()
    assert await first == service_module.CERT_PROBE_FAULT
    assert len(_fault_warnings(caplog)) == 1

    running = [asyncio.create_task(service._cert_directory_presence(user)) for _ in range(3)]
    async with asyncio.timeout(10):
        while len(gates) < 4:
            await asyncio.sleep(0)
    await _set_disabled(service, user, disabled=True)
    for task, gate in zip(running, gates[1:], strict=True):
        gate.set()
        assert await task == service_module.CERT_PROBE_FAULT
        assert await service.identity_for_cert_user_id(user.id) is None  # out of the set

    assert len(_fault_warnings(caplog)) == 1
    assert user.id not in service._cert_probe_faulting
    assert user.id not in service._cert_probe_fault_warned_at
    assert not service._cert_probe_inflight and not service._cert_probe_left_at
    left = [r for r in caplog.records if "after the account left" in r.getMessage()]
    assert len(left) == 3 and all(r.levelno == logging.DEBUG for r in left)


async def test_a_fault_from_a_request_waiting_for_a_slot_at_the_disable_is_recorded_nowhere(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A request that read the account before the disable, and is still waiting for a probe slot,
    predates the exit too, however late its probe starts.

    RED when: a probe is numbered when its task starts rather than before the slot wait."""
    service, _directory, user_id = await _directory_account(store, _VIEWERS)
    user = await store.get_user(user_id)
    assert user is not None
    service._cert_probe_slots = asyncio.BoundedSemaphore(1)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    gate = asyncio.Event()
    calls = 0

    async def _gated_raises(probed: UserRecord) -> reconcile.Probe | str:
        nonlocal calls
        calls += 1
        await gate.wait()
        raise LookupError("synthetic engine fault")

    monkeypatch.setattr(service, "_directory_presence", _gated_raises)
    holding = asyncio.create_task(service._cert_directory_presence(user))
    async with asyncio.timeout(10):
        while calls == 0:
            await asyncio.sleep(0)
    waiting = asyncio.create_task(service._cert_directory_presence(user))
    await asyncio.sleep(0)
    assert calls == 1  # the second request is waiting for the slot

    await _set_disabled(service, user, disabled=True)
    gate.set()
    assert await holding == service_module.CERT_PROBE_FAULT
    assert await waiting == service_module.CERT_PROBE_FAULT

    assert calls == 2
    assert not _fault_warnings(caplog)
    assert user.id not in service._cert_probe_faulting
    assert user.id not in service._cert_probe_fault_warned_at
    assert not service._cert_probe_inflight and not service._cert_probe_left_at


async def test_a_re_enable_after_a_disable_this_process_never_saw_resets_the_state(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A disable written by another writer, with no certificate request while it held, leaves the
    state in place. The administrator's re-enable here is then the only reset, and the next fault
    warns at once, inside the interval.

    RED when: update_user drops the state on a disable but not on a re-enable."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    assert await service.identity_for_cert_user_id(user.id) is None
    await store._db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user.id,))
    await store._db.commit()
    assert user.id in service._cert_probe_fault_warned_at

    await _set_disabled(service, user, disabled=False)
    assert await service.identity_for_cert_user_id(user.id) is None

    assert len(_fault_warnings(caplog)) == 2
    assert not _repeat_debugs(caplog)


@pytest.mark.parametrize("exit_by", ["admin-delete", "row-gone", "local-provider"])
async def test_an_account_that_stops_being_a_probed_directory_account_drops_its_state(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, exit_by: str
) -> None:
    """The other exits from the probe set: the administrator deletes the account, its row is gone
    by another route, or it is no longer a directory account. The delete drops both entries at
    once; otherwise the certificate path's next read of the row does.

    RED when: only a disable drops the state."""
    service, _directory, user, _state = await _faulting_service(store, monkeypatch)
    assert await service.identity_for_cert_user_id(user.id) is None
    assert user.id in service._cert_probe_fault_warned_at

    if exit_by == "admin-delete":
        await service.delete_user(user.id, actor="synthetic-admin")
    elif exit_by == "row-gone":
        await store.delete_user(user.id)
        assert await service.identity_for_cert_user_id(user.id) is None
    else:
        await store._db.execute("UPDATE users SET auth_provider = 'local' WHERE id = ?", (user.id,))
        await store._db.commit()
        await service.identity_for_cert_user_id(user.id)

    assert user.id not in service._cert_probe_faulting
    assert user.id not in service._cert_probe_fault_warned_at


async def test_a_directory_key_moved_during_a_healthy_probe_drops_the_state(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The re-read after a healthy probe finds the row moved away from the account it asked
    about, so the old account's fault state no longer describes this row.

    RED when: the post-probe refusal keeps the state."""
    service, _directory, user, state = await _faulting_service(store, monkeypatch)
    assert await service.identity_for_cert_user_id(user.id) is None
    real_probe = service._probe_principal

    async def _probe(probed: UserRecord) -> reconcile.Probe:
        probe = await real_probe(probed)
        await store._db.execute(
            "UPDATE users SET directory_object_id = 'synthetic-other-object-id' WHERE id = ?",
            (user.id,),
        )
        await store._db.commit()
        return probe

    monkeypatch.setattr(service, "_probe_principal", _probe)
    state["faulting"] = False
    assert await service.identity_for_cert_user_id(user.id) is None

    assert user.id not in service._cert_probe_fault_warned_at


@pytest.mark.parametrize(
    "moved",
    [
        "directory_object_id = 'synthetic-other-object-id'",
        "auth_provider = 'local'",
    ],
    ids=["object-id", "provider"],
)
async def test_a_row_whose_directory_key_moved_during_the_probe_is_refused(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, moved: str
) -> None:
    """The answer vouches only for the account the probe asked about.

    RED when: the re-read after the probe checks only that the row exists and is enabled."""
    service, _directory, user_id = await _directory_account(store, _VIEWERS)
    real_probe = service._probe_principal

    async def _probe(user: UserRecord) -> reconcile.Probe:
        probe = await real_probe(user)
        await store._db.execute(f"UPDATE users SET {moved} WHERE id = ?", (user_id,))
        await store._db.commit()
        return probe

    monkeypatch.setattr(service, "_probe_principal", _probe)

    assert await service.identity_for_cert_user_id(user_id) is None


async def test_a_local_disable_during_the_probe_is_honoured(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The probe is a round trip of up to seconds, so the row is read again after it."""
    service, _directory, user_id = await _directory_account(store, _VIEWERS)
    real_probe = service._probe_principal

    async def _probe(user: UserRecord) -> reconcile.Probe:
        probe = await real_probe(user)
        await store._db.execute("UPDATE users SET disabled = 1 WHERE id = ?", (user_id,))
        await store._db.commit()
        return probe

    monkeypatch.setattr(service, "_probe_principal", _probe)

    assert await service.identity_for_cert_user_id(user_id) is None


_ADMINS = "CN=MF-Admins,OU=Groups,DC=test,DC=invalid"
_CUSTOM = "CN=MF-Validators,OU=Groups,DC=test,DC=invalid"
_CHANNEL_A = "CN=MF-Channel-A,OU=Groups,DC=test,DC=invalid"
_CHANNEL_B = "CN=MF-Channel-B,OU=Groups,DC=test,DC=invalid"


async def test_an_administrator_removed_from_the_admin_group_loses_every_channel_grant(
    store: MessageStore,
) -> None:
    """Administrator reaches every channel by role. Narrowed away, the identity falls back to the
    stored scope, which for this account grants none."""
    service, directory, user_id = await _directory_account(
        store, _ADMINS, _VIEWERS, role_map=[(_ADMINS, "administrator"), (_VIEWERS, "viewer")]
    )

    full = await service.identity_for_cert_user_id(user_id)
    assert full is not None and Role.ADMINISTRATOR in full.roles
    assert full.allowed_channels is None

    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))
    narrowed = await service.identity_for_cert_user_id(user_id)

    assert narrowed is not None and narrowed.roles == {Role.VIEWER}
    assert narrowed.allowed_channels == frozenset()


async def test_a_custom_role_narrows_away_with_its_group(store: MessageStore) -> None:
    """A custom role's permission overlay goes the same way as a built-in role."""
    seed = AuthService(store, _settings())
    await seed.initialize()
    custom = await seed.create_custom_role(
        display_name="cert-validators",
        description=None,
        permissions=["config:validate"],
        actor="test",
    )
    service, directory, user_id = await _directory_account(
        store, _CUSTOM, _VIEWERS, role_map=[(_CUSTOM, custom.id), (_VIEWERS, "viewer")]
    )
    assert set(await store.get_user_role_ids(user_id)) == {custom.id, "viewer"}
    validate = Permission("config:validate")

    with_custom = await service.identity_for_cert_user_id(user_id)
    assert with_custom is not None and validate in with_custom.permissions

    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))
    narrowed = await service.identity_for_cert_user_id(user_id)

    assert narrowed is not None and validate not in narrowed.permissions


async def test_a_channel_group_removal_narrows_the_scope_and_writes_nothing(
    store: MessageStore,
) -> None:
    """The scope narrows on the same groups as the roles, by the rule login and the reconciler
    share. A cert-only account never signs in, so nothing else would ever apply it."""
    await AuthService(store, _settings()).initialize()
    await store.set_ad_group_scope_map([(_CHANNEL_A, "IB_A"), (_CHANNEL_B, "IB_B")])
    service, directory, user_id = await _directory_account(store, _VIEWERS, _CHANNEL_A, _CHANNEL_B)
    stored = (await store.get_user(user_id)).channel_scope  # type: ignore[union-attr]

    full = await service.identity_for_cert_user_id(user_id)
    assert full is not None and full.allowed_channels == frozenset({"IB_A", "IB_B"})

    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS, _CHANNEL_A}))
    one = await service.identity_for_cert_user_id(user_id)
    assert one is not None and one.allowed_channels == frozenset({"IB_A"})

    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS}))
    none = await service.identity_for_cert_user_id(user_id)
    assert none is not None and none.allowed_channels == frozenset()

    assert (await store.get_user(user_id)).channel_scope == stored  # type: ignore[union-attr]


async def test_a_scope_the_groups_would_widen_is_not_widened(store: MessageStore) -> None:
    """Never more than the row holds: a widening waits for a sign-in to write it."""
    await AuthService(store, _settings()).initialize()
    await store.set_ad_group_scope_map([(_CHANNEL_A, "IB_A"), (_CHANNEL_B, "IB_B")])
    service, directory, user_id = await _directory_account(store, _VIEWERS, _CHANNEL_A)
    directory.principal = replace(_PRINCIPAL, groups=frozenset({_VIEWERS, _CHANNEL_A, _CHANNEL_B}))

    identity = await service.identity_for_cert_user_id(user_id)

    assert identity is not None and identity.allowed_channels == frozenset({"IB_A"})


def _outage_records(caplog: pytest.LogCaptureFixture, level: int) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == _SERVICE_LOGGER and r.levelno == level and _OUTAGE_LINE in r.getMessage()
    ]


async def test_one_outage_logs_one_warning_and_its_end_one_info(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """RED when: every refused request during one outage logs its own line, or the line names the
    account."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    directory.unreachable = True

    for _ in range(5):
        assert await service.identity_for_cert_user_id(user_id) is None

    warnings = _outage_records(caplog, logging.WARNING)
    assert len(warnings) == 1
    assert "jdoe" not in warnings[0].getMessage()
    assert _outage_records(caplog, logging.INFO) == []

    directory.unreachable = False
    for _ in range(3):
        assert await service.identity_for_cert_user_id(user_id) is not None
    assert len(_outage_records(caplog, logging.INFO)) == 1

    # An outage that returns within the interval logs nothing more at WARNING, so a flapping one
    # cannot log a pair per request.
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None
    directory.unreachable = False
    assert await service.identity_for_cert_user_id(user_id) is not None
    assert len(_outage_records(caplog, logging.WARNING)) == 1
    assert len(_outage_records(caplog, logging.INFO)) == 1


async def test_a_new_outage_past_the_interval_logs_again(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    monkeypatch.setattr(service_module, "_CERT_OUTAGE_LOG_INTERVAL_SECONDS", 0.0)
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)
    for _ in range(2):
        directory.unreachable = True
        assert await service.identity_for_cert_user_id(user_id) is None
        directory.unreachable = False
        assert await service.identity_for_cert_user_id(user_id) is not None

    assert len(_outage_records(caplog, logging.WARNING)) == 2
    assert len(_outage_records(caplog, logging.INFO)) == 2


async def test_an_outage_that_starts_inside_the_interval_warns_once_the_interval_ends(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A blip, its recovery, then a long outage within the minute. The long one must still log a
    WARNING, or the last line an operator reads says the directory is back.

    RED when: a latched outage that logged nothing never looks at the interval again."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None
    directory.unreachable = False
    assert await service.identity_for_cert_user_id(user_id) is not None
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None  # inside the interval
    assert len(_outage_records(caplog, logging.WARNING)) == 1

    monkeypatch.setattr(service_module, "_CERT_OUTAGE_LOG_INTERVAL_SECONDS", 0.0)
    for _ in range(3):
        assert await service.identity_for_cert_user_id(user_id) is None

    assert len(_outage_records(caplog, logging.WARNING)) == 2  # one more, not one per request
    directory.unreachable = False
    assert await service.identity_for_cert_user_id(user_id) is not None
    assert len(_outage_records(caplog, logging.INFO)) == 2


async def test_a_logged_outage_that_changes_its_reason_says_so_and_the_recovery_names_the_last(
    store: MessageStore, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    monkeypatch.setattr(service_module, "_CERT_PROBE_SLOT_WAIT_SECONDS", 0.05)
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None
    cap = service_module._CERT_PROBE_MAX_CONCURRENCY
    for _ in range(cap):
        await service._cert_probe_slots.acquire()
    assert await service.identity_for_cert_user_id(user_id) is None  # saturated
    for _ in range(cap):
        service._cert_probe_slots.release()
    assert await service.identity_for_cert_user_id(user_id) is None  # unavailable again

    changes = [r.getMessage() for r in _outage_records(caplog, logging.INFO)]
    assert len(changes) == 1  # the flip back is inside the interval, so DEBUG
    assert "now returns probe_capacity_saturated" in changes[0]

    directory.unreachable = False
    assert await service.identity_for_cert_user_id(user_id) is not None
    recovered = _outage_records(caplog, logging.INFO)[-1].getMessage()
    assert "reaches the directory again (it last returned unavailable)" in recovered
    assert len(_outage_records(caplog, logging.WARNING)) == 1


async def test_a_fault_reading_the_entry_does_not_warn_per_request_by_name(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The probe's own per-fault WARNING names the account. It suits a per-pass reconciler, not a
    per-request path, so here it goes to DEBUG. The fault is not an outage (BACKLOG #3100): the
    certificate path's per-account fault line reports it once, naming no account.

    RED when: a fault the probe caught is logged as a directory outage again."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    directory.raises = KeyError("userAccountControl")
    caplog.clear()  # the sign-in that made the row logs its own lines

    for _ in range(4):
        assert await service.identity_for_cert_user_id(user_id) is None

    warnings = [
        r for r in caplog.records if r.name == _SERVICE_LOGGER and r.levelno >= logging.WARNING
    ]
    assert len(warnings) == 1 and "was refused: probe_fault" in warnings[0].getMessage()
    assert "raised KeyError" in warnings[0].getMessage()  # the type survives the reason string
    assert _OUTAGE_LINE not in warnings[0].getMessage()
    assert "jdoe" not in warnings[0].getMessage()
    assert service._cert_directory_outage is None and user_id in service._cert_probe_faulting


async def test_the_reconciler_and_step_up_still_warn_on_a_fault(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The control: the DEBUG level is the certificate task's alone and leaks nowhere else."""
    service, directory, _user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    directory.raises = KeyError("userAccountControl")
    user = await store.get_user(_user_id)
    assert user is not None

    await service.identity_for_cert_user_id(_user_id)
    assert await service._directory_step_up_refusal(user) == "probe_fault"
    await service.reconcile_directory_sessions()  # the sign-in left a live session to probe

    # The probe's own line only; the certificate path's per-account fault line names the type too.
    raised = [
        r
        for r in caplog.records
        if r.getMessage().startswith("directory probe of jdoe raised KeyError")
    ]
    assert [r.levelno for r in raised] == [logging.DEBUG, logging.WARNING, logging.WARNING]


async def test_a_configuration_refusal_logs_once_per_process(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """No directory wired: an operator would otherwise see a bare 401, like an unmapped cert."""
    _service, _directory, user_id = await _directory_account(store, _VIEWERS)
    unwired = AuthService(store, AuthSettings(mfa_verify_min_elapsed_seconds=0))
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)

    for _ in range(3):
        assert await unwired.identity_for_cert_user_id(user_id) is None

    refused = [
        r
        for r in caplog.records
        if r.levelno == logging.WARNING and "not_configured" in r.getMessage()
    ]
    assert len(refused) == 1 and "jdoe" not in refused[0].getMessage()


async def test_an_answer_about_the_account_ends_an_outage(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """A refusal the directory itself gave still proves the directory answers again."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.INFO, logger=_SERVICE_LOGGER)
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None

    directory.unreachable = False
    directory.answer = DirectoryAnswer.DISABLED
    assert await service.identity_for_cert_user_id(user_id) is None

    assert len(_outage_records(caplog, logging.INFO)) == 1
