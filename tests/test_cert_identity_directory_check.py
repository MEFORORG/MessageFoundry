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

import logging
from collections.abc import AsyncIterator
from dataclasses import replace

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import DirectoryAnswer, LdapReferralError
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
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
    store: MessageStore, *groups: str
) -> tuple[AuthService, _Directory, str]:
    """A directory account whose roles a sign-in wrote from ``groups`` under the synthetic map.

    The sign-in is only how the row is born. The certificate path holds no session."""
    await AuthService(store, _settings()).initialize()  # the map's role ids need the seeded roles
    await store.set_ad_group_role_map([(_OPERATORS, "operator"), (_VIEWERS, "viewer")])
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

    # A second outage is a new one, and logs again.
    directory.unreachable = True
    assert await service.identity_for_cert_user_id(user_id) is None
    assert len(_outage_records(caplog, logging.WARNING)) == 2


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
