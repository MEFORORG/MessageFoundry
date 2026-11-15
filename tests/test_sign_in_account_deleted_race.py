# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A local sign-in whose account is deleted between its checks and its session insert (BACKLOG
#2733).

The store refuses the insert for a missing account (``create_session`` returns ``False``), and the
local leg answers as it does for an unknown account: ``invalid credentials``, padded like every
other refusal, with an ``unknown_or_disabled`` failure row. Before the fix the insert's foreign-key
error left the service as an unhandled exception, which the API answers with a 500.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from messagefoundry.auth import service as service_module
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.store.store import MessageStore
from tests._admin_account import create_admin


async def _service() -> tuple[AuthService, MessageStore]:
    store = await MessageStore.open(":memory:")
    return AuthService(store, AuthSettings()), store


def _delete_before_insert(monkeypatch: pytest.MonkeyPatch, store: MessageStore) -> list[bool]:
    """Delete the account inside ``create_session``, before its read: the race's losing order."""
    real = store.create_session
    issued: list[bool] = []

    async def racing(**kwargs: Any) -> bool:
        await store.delete_user(kwargs["user_id"])
        result = await real(**kwargs)
        issued.append(result)
        return result

    monkeypatch.setattr(store, "create_session", racing)
    return issued


#: Widened as test_mfa.py's AC6 arm widens it, so a loaded host cannot push the work or the
#: deferred row past a slot boundary and add a second deadline.
_BUDGET = 5.0


def _pad_slots(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    """Record the slot of each failure-pad deadline, and skip the pad's waits."""
    slots: list[int] = []
    real_deadline = service_module._failure_deadline

    def spy(started: float, now: float, budget: float | None = None) -> float:
        deadline = real_deadline(started, now, budget)
        slots.append(round((deadline - started) / _BUDGET))
        return deadline

    async def no_sleep(_deadline: float) -> None:
        return None

    monkeypatch.setattr(service_module, "_FAILURE_BUDGET_SECONDS", _BUDGET)
    monkeypatch.setattr(service_module, "_failure_deadline", spy)
    monkeypatch.setattr(service_module, "_sleep_until", no_sleep)
    monkeypatch.setattr(service_module, "_sleep_until_write_point", no_sleep)
    return slots


async def test_a_sign_in_whose_account_is_deleted_mid_login_is_refused_and_padded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store = await _service()
    try:
        admin = await create_admin(service)
        issued = _delete_before_insert(monkeypatch, store)
        slots = _pad_slots(monkeypatch)

        outcome = await service.login(admin.username, admin.password)

        assert issued == [False], "the store did not refuse the insert for a missing account"
        assert not outcome.ok and outcome.error == "invalid credentials"
        assert outcome.token is None
        assert slots == [1], "the refusal did not answer in the failure pad's first slot"
        rows = await store.list_audit(action="auth.login_failed")
        assert [json.loads(r["detail"])["reason"] for r in rows] == ["unknown_or_disabled"]
        assert await store.list_audit(action="auth.login_success") == []
    finally:
        await store.close()


async def test_control_an_undisturbed_sign_in_still_mints_a_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, store = await _service()
    try:
        admin = await create_admin(service)
        slots = _pad_slots(monkeypatch)

        outcome = await service.login(admin.username, admin.password)

        assert outcome.ok and outcome.token is not None
        assert slots == []
        assert await store.list_audit(action="auth.login_failed") == []
    finally:
        await store.close()
