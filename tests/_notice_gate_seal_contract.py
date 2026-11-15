# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Cross-backend contract: the startup security-notice gate weighs only sealed records (BACKLOG
#5629).

``_assert_security_notice_is_deliverable`` decides from an Administrator's ``notify_email``, its
``disabled`` flag and its ``user_roles`` rows. On a keyed store each of those is covered by the
user seal, so a value written outside the store must not settle the gate. Each case below starts
from a store the gate refuses, makes the one change that would let it pass with a raw statement,
and requires the refusal to stand; then makes the same change through the store, as the control,
and requires the gate to pass. A gate that refused everything, or read unchecked rows, fails here.

Extra-free, as ``tests/_user_seal_contract.py`` is, so the Postgres and SQL Server suites import it
inside their test functions. ``raw`` is that file's adapter: SQL with ``?`` placeholders, run
outside the store's helpers and committed.
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.api.app import _assert_security_notice_is_deliverable
from messagefoundry.auth.permissions import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecurityEnforcement,
    SecuritySettings,
)
from tests._session_seal_contract import RawSql

_ADDRESS = "ops@example.test"


async def _gate(store: Any, service: AuthService) -> None:
    await _assert_security_notice_is_deliverable(
        store,
        auth=service,
        auth_settings=AuthSettings(notify_security_events=True),
        alerts_settings=AlertsSettings(security_notifications_required=True),
        security_settings=SecuritySettings(enforcement=SecurityEnforcement.ENFORCE),
    )


async def _refuses(store: Any, service: AuthService, why: str) -> str:
    with pytest.raises(RuntimeError) as exc:
        await _gate(store, service)
    assert "refusing to start" in str(exc.value), why
    return str(exc.value)


async def _account(store: Any, user_id: str, roles: list[str]) -> None:
    await store.create_user(
        user_id=user_id,
        username=user_id,
        auth_provider="local",
        password_generated=False,
        audits=(),
    )
    await store.set_user_roles(user_id, roles, assigned_by="contract", audits=())


async def assert_notice_gate_reads_sealed_rows(store: Any, raw: RawSql) -> None:
    """Drive the gate over sealed and tampered records on ``store``'s backend. ``store`` must be
    keyed and hold no account on entry."""
    assert store.row_sealer() is not None, "the contract needs a store opened with a store key"
    alerts: list[str] = []
    service = AuthService(store, AuthSettings(), integrity_alert=alerts.append)
    await service.initialize()
    admin = Role.ADMINISTRATOR.value

    # --- an address written outside the store makes no Administrator reachable -----------------
    await _account(store, "gate-addr", [admin])
    await _refuses(store, service, "no address yet")  # the starting state
    await raw("UPDATE users SET notify_email=? WHERE id=?", (_ADDRESS, "gate-addr"))
    refused = await _refuses(store, service, "a raw notify_email must not satisfy the gate")
    assert any("gate-addr" in a for a in alerts)  # the failing record was reported
    # The record still exists, so the refusal says one was left out rather than only "none exists".
    assert "1 account record(s) failed their integrity check" in refused
    await store.delete_user("gate-addr")
    # Control: the same address through the store satisfies it.
    await _account(store, "gate-addr-ok", [admin])
    await store.set_user_notify_email("gate-addr-ok", email=_ADDRESS)
    await _gate(store, service)
    await store.delete_user("gate-addr-ok")

    # --- an Administrator role row inserted outside the store grants nothing ------------------
    await _account(store, "gate-role", [Role.VIEWER.value])
    await store.set_user_notify_email("gate-role", email=_ADDRESS)
    await _refuses(store, service, "a viewer is no Administrator")
    await raw(
        "INSERT INTO user_roles (user_id, role_id, assigned_at, assigned_by) VALUES (?,?,?,?)",
        ("gate-role", admin, 1.0, None),
    )
    await _refuses(store, service, "a raw user_roles row must not satisfy the gate")
    assert any("gate-role" in a for a in alerts)  # evidence the raw write took effect
    await store.delete_user("gate-role")
    # Control: the same grant through the store satisfies it.
    await _account(store, "gate-role-ok", [Role.VIEWER.value])
    await store.set_user_notify_email("gate-role-ok", email=_ADDRESS)
    await store.set_user_roles(
        "gate-role-ok", [Role.VIEWER.value, admin], assigned_by="contract", audits=()
    )
    await _gate(store, service)
    await store.delete_user("gate-role-ok")

    # --- a disabled flag cleared outside the store re-enables nobody --------------------------
    await _account(store, "gate-off", [admin])
    await store.set_user_notify_email("gate-off", email=_ADDRESS)
    await store.set_user_disabled("gate-off", disabled=True)
    await _refuses(store, service, "a disabled Administrator receives nothing")
    await raw("UPDATE users SET disabled=? WHERE id=?", (False, "gate-off"))
    await _refuses(store, service, "a raw disabled flag must not satisfy the gate")
    assert any("gate-off" in a for a in alerts)  # evidence the raw write took effect
    await store.delete_user("gate-off")
    # Control: the same change through the store satisfies it.
    await _account(store, "gate-off-ok", [admin])
    await store.set_user_notify_email("gate-off-ok", email=_ADDRESS)
    await store.set_user_disabled("gate-off-ok", disabled=True)
    await store.set_user_disabled("gate-off-ok", disabled=False)
    await _gate(store, service)
    await store.delete_user("gate-off-ok")
