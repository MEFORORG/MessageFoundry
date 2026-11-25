# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``finish_webauthn_assertion``'s docstring on invalid input (vault BACKLOG #3775 item 5).

It said the method "never raises" for invalid input and was "always audited", while its last
paragraph says an exception in the passkey re-read can raise, and a call with no token, an unknown
session or a disabled account returns before any audit write. The docstring now says both. These
tests run the early returns it names, with a passkey-free account, and check that no audit row is
written; a successful sign-in in the same store is the control that the audit log is read.
"""

from __future__ import annotations

import inspect
from collections.abc import AsyncIterator

import pytest

from messagefoundry.auth.service import AuthService
from messagefoundry.auth.tokens import hash_token
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests.test_monitoring_scope_doc_drift import PW, _operator

_RP = "console.test.invalid"
_ORIGIN = f"https://{_RP}"


@pytest.fixture
async def store() -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(":memory:")
    yield s
    await s.close()


async def _audit_count(store: MessageStore) -> int:
    return len(await store.list_audit(limit=1000))


async def _finish(service: AuthService, token: str | None) -> bool:
    result = await service.finish_webauthn_assertion(token, "{}", rp_id=_RP, origin=_ORIGIN)
    return result.ok


async def test_no_token_and_an_unknown_session_return_unaudited(store: MessageStore) -> None:
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()
    before = await _audit_count(store)
    assert not await _finish(service, None)
    assert not await _finish(service, "")
    assert not await _finish(service, "not-a-session-token")
    assert await _audit_count(store) == before


async def test_a_disabled_account_returns_unaudited(store: MessageStore) -> None:
    service = AuthService(store, AuthSettings(require_mfa=False))
    await service.initialize()
    user_id = await _operator(service, "pk-user")
    signed_in = await service.login("pk-user", PW)
    assert signed_in.token, "control: the sign-in itself writes audit rows"
    await store.set_user_disabled(user_id, disabled=True)
    assert await store.get_session(hash_token(signed_in.token)) is not None
    before = await _audit_count(store)
    assert before > 0
    assert not await _finish(service, signed_in.token)
    assert await _audit_count(store) == before


def test_the_docstring_no_longer_promises_no_raise_or_an_audit_row() -> None:
    doc = " ".join((inspect.getdoc(AuthService.finish_webauthn_assertion) or "").split())
    assert "(never raises)" not in doc
    assert "always audited" not in doc
    assert "returns one with no ``auth.*`` row" in doc
