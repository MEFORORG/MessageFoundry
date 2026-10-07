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
    one ERROR per cancelled request. The probe returns an outage instead, and fails closed."""
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
    gate.clear()
    gate.set()  # the same fault with the caller still waiting is a refusal, not a raise
    assert await service.identity_for_cert_user_id(user_id) is None


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
    per-request path, so here it goes to DEBUG and the outage line reports the fault once."""
    service, directory, user_id = await _directory_account(store, _VIEWERS)
    caplog.set_level(logging.DEBUG, logger=_SERVICE_LOGGER)
    directory.raises = KeyError("userAccountControl")
    caplog.clear()  # the sign-in that made the row logs its own lines

    for _ in range(4):
        assert await service.identity_for_cert_user_id(user_id) is None

    warnings = [
        r for r in caplog.records if r.name == _SERVICE_LOGGER and r.levelno >= logging.WARNING
    ]
    assert len(warnings) == 1 and _OUTAGE_LINE in warnings[0].getMessage()
    assert "jdoe" not in warnings[0].getMessage()


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
    assert await service._directory_step_up_refusal(user) == "unavailable"
    await service.reconcile_directory_sessions()  # the sign-in left a live session to probe

    raised = [r for r in caplog.records if "raised KeyError" in r.getMessage()]
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
