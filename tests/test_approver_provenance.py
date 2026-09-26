# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #315: dual control cannot prove two humans, so the cheap ways around it are made loud.

Every approver is an Administrator, and every Administrator can create an account or reset another
one's password and second factor. So one Administrator can supply the "second" approver. Nothing here
refuses that; it cannot be told apart from a real second person in software. What these tests pin:

* limb (b): a release whose approver account was created, had its password changed, or enrolled TOTP
  after the request writes an ``approval.approver_provenance`` audit row and raises an alert, and is
  STILL released. An approver older than the request produces neither.
* limb (c): creating or promoting an Administrator raises ``administrator_granted``; the
  ``user.created`` row carries the creating administrator's address; the new account's notification
  address gets an ``ACCOUNT_CREATED`` notice.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.approvals import ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.notifications import ACCOUNT_CREATED
from messagefoundry.auth.passwords import hash_password
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AuthSettings
from messagefoundry.connection_names import is_connection_name
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.security_notify import _SUBJECTS, _build_body
from tests.test_alert_sinks import _drain, _RecordingTransport
from tests.test_approval_requester_recheck import _client_with_sink, _hold_replay
from tests.test_approval_requester_recheck import _Sink as _RecheckSink
from tests.test_approvals import ON, PW, _add, _service, _token
from tests.test_auth_service import _FakeNotifier

_FLAG = "approval.approver_provenance"


class _Sink(_RecheckSink):
    """The recheck suite's recording sink, plus the two #315 events."""

    def approval_approver_provenance(
        self, name: str, *, operation: str, changed: tuple[str, ...]
    ) -> None:
        self.events.append(
            ("approval_approver_provenance", name, {"operation": operation, "changed": changed})
        )

    def administrator_granted(self, name: str, *, via: str, granted_by: str) -> None:
        self.events.append(("administrator_granted", name, {"via": via, "granted_by": granted_by}))


class _RaisingSink(LoggingAlertSink):
    def approval_approver_provenance(
        self, name: str, *, operation: str, changed: tuple[str, ...]
    ) -> None:
        raise RuntimeError("sink broke its never-raise contract")


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "provenance.db", poll_interval=0.02)
    yield eng
    await eng.stop()


# --- limb (b), at the gate ----------------------------------------------------------------------


async def _noop(_params: Mapping[str, Any]) -> dict[str, Any]:
    return {"ran": True}


def _gate(engine: Engine, service: AuthService, sink: LoggingAlertSink) -> ApprovalGate:
    gate = ApprovalGate(
        engine.store, ON, resolve_identity=service.identity_for_user_id, alert_sink=sink
    )
    gate.register("dead_letter_replay", "replay", _noop, permission=Permission.MESSAGES_REPLAY)
    return gate


async def _request(gate: ApprovalGate, maker_id: str) -> str:
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker_id
    )
    assert approval_id is not None
    return approval_id


async def _release(gate: ApprovalGate, approval_id: str, checker_id: str) -> None:
    out = await gate.approve(
        approval_id, approver="checker", approver_user_id=checker_id, client="10.0.0.7"
    )
    # Never refused: the release goes ahead in every case.
    assert out["approved_by"] == "checker" and out["result"] == {"ran": True}


async def _flags(engine: Engine) -> list[dict[str, Any]]:
    return [dict(r) for r in await engine.store.list_audit(action=_FLAG)]


async def test_an_approver_created_after_the_request_is_flagged_and_released(
    engine: Engine,
) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    sink = _Sink()
    gate = _gate(engine, service, sink)
    approval_id = await _request(gate, maker)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)  # minted after the request

    await _release(gate, approval_id, checker)

    rows = await _flags(engine)
    assert len(rows) == 1
    assert rows[0]["actor"] == "checker"
    assert rows[0]["client"] == "10.0.0.7"  # ADR 0150: the approver's address
    detail = json.loads(str(rows[0]["detail"]))
    assert detail["approval_id"] == approval_id
    assert detail["requester"] == "maker"
    assert "account_created" in detail["changed"]
    assert sink.events[0][0] == "approval_approver_provenance"
    assert sink.events[0][1] == f"approval:{approval_id}"
    assert len(await engine.store.list_audit(action="approval.approved")) == 1


async def test_a_password_changed_after_the_request_is_flagged(engine: Engine) -> None:
    """The takeover variant: reset an EXISTING approver's password. No user.created row is written,
    so creation time alone would miss it."""
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    gate = _gate(engine, service, sink)
    approval_id = await _request(gate, maker)
    await engine.store.set_password(
        checker,
        password_hash=hash_password("another-strong-passphrase"),
        must_change_password=False,
    )

    await _release(gate, approval_id, checker)

    detail = json.loads(str((await _flags(engine))[0]["detail"]))
    assert detail["changed"] == ["password_changed"]
    assert sink.events == [
        (
            "approval_approver_provenance",
            f"approval:{approval_id}",
            {"operation": "dead_letter_replay", "changed": ("password_changed",)},
        )
    ]


async def test_totp_enrolled_after_the_request_is_flagged(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    gate = _gate(engine, service, sink)
    approval_id = await _request(gate, maker)
    await engine.store.set_totp_secret(checker, secret="JBSWY3DPEHPK3PXP")
    await engine.store.enable_totp(checker, recovery_code_hashes=[])

    await _release(gate, approval_id, checker)

    detail = json.loads(str((await _flags(engine))[0]["detail"]))
    assert detail["changed"] == ["totp_enrolled"]


async def test_an_approver_older_than_the_request_is_not_flagged(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)
    sink = _Sink()
    gate = _gate(engine, service, sink)
    approval_id = await _request(gate, maker)

    await _release(gate, approval_id, checker)

    assert await _flags(engine) == []
    assert sink.events == []
    assert len(await engine.store.list_audit(action="approval.approved")) == 1


async def test_a_broken_sink_does_not_stop_the_release(engine: Engine) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    gate = _gate(engine, service, _RaisingSink())
    approval_id = await _request(gate, maker)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)

    await _release(gate, approval_id, checker)

    assert len(await _flags(engine)) == 1  # the durable row still lands


async def test_an_unreadable_approver_does_not_stop_the_release(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)
    gate = _gate(engine, service, _Sink())
    approval_id = await _request(gate, maker)
    real_get_user = engine.store.get_user

    async def _get_user(user_id: str) -> Any:
        if user_id == checker:
            raise OSError("store read failed")
        return await real_get_user(user_id)

    monkeypatch.setattr(engine.store, "get_user", _get_user)

    await _release(gate, approval_id, checker)

    assert await _flags(engine) == []


async def test_the_flag_is_written_over_http_with_the_approvers_address(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "maker", Role.OPERATOR)
    sink = _Sink()
    c, _ = _client_with_sink(engine, service, sink)
    async with c:
        approval_id = await _hold_replay(c, await _token(c, "maker"))
        await _add(service, "checker", Role.ADMINISTRATOR)
        r = await c.post(f"/approvals/{approval_id}/approve", headers=await _token(c, "checker"))
        assert r.status_code == 200, r.text
    rows = await _flags(engine)
    assert len(rows) == 1 and rows[0]["client"] == "127.0.0.1"


# --- limb (c): the Administrator grant --------------------------------------------------------


def _app_client(engine: Engine, service: AuthService, sink: _Sink) -> httpx.AsyncClient:
    app = create_app(engine, auth=service)
    app.state.notifier = sink
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t")


async def _create(c: httpx.AsyncClient, headers: dict[str, str], name: str, role: Role) -> str:
    r = await c.post(
        "/users",
        headers=headers,
        json={"username": name, "password": PW, "roles": [role.value], "email": f"{name}@x.org"},
    )
    assert r.status_code == 201, r.text
    return str(r.json()["id"])


async def test_creating_an_administrator_raises_the_grant_alert(engine: Engine) -> None:
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    sink = _Sink()
    async with _app_client(engine, service, sink) as c:
        headers = await _token(c, "admin1")
        await _create(c, headers, "viewer1", Role.VIEWER)
        assert sink.events == []  # a non-Administrator account pages nothing
        await _create(c, headers, "admin2", Role.ADMINISTRATOR)
    assert sink.events == [
        (
            "administrator_granted",
            "user:admin2",
            {"via": "account_created", "granted_by": "admin1"},
        )
    ]
    # Limb (c): the enabling step is attributed to a host, like the approval rows are.
    created = await engine.store.list_audit(action="user.created")
    assert {str(r["client"]) for r in created if r["actor"] == "admin1"} == {"127.0.0.1"}


async def test_promoting_to_administrator_raises_the_grant_alert(engine: Engine) -> None:
    """Promotion mints an approver exactly as creation does, so it must page too."""
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    target = await _add(service, "op", Role.OPERATOR)
    sink = _Sink()
    async with _app_client(engine, service, sink) as c:
        headers = await _token(c, "admin1")
        body = {"roles": [Role.OPERATOR.value, Role.ADMINISTRATOR.value]}
        r = await c.put(f"/users/{target}/roles", headers=headers, json=body)
        assert r.status_code == 200, r.text
        # Re-saving an existing Administrator's roles grants nothing new.
        r = await c.put(f"/users/{target}/roles", headers=headers, json=body)
        assert r.status_code == 200, r.text
    assert sink.events == [
        ("administrator_granted", "user:op", {"via": "roles_changed", "granted_by": "admin1"})
    ]


async def test_account_created_notice_goes_to_the_new_accounts_address(engine: Engine) -> None:
    notifier = _FakeNotifier()
    service = AuthService(engine.store, AuthSettings(require_mfa=False), security_notifier=notifier)
    await service.initialize()
    await service.create_local_user(
        username="newbie",
        password=PW,
        display_name=None,
        email="newbie@example.org",
        roles=[Role.ADMINISTRATOR.value],
        actor="admin1",
        client="10.1.1.1",
    )
    sent = [e for e in notifier.events if e.event_type == ACCOUNT_CREATED]
    assert len(sent) == 1
    assert sent[0].email == "newbie@example.org"
    assert sent[0].client_ip == "10.1.1.1"
    body = _build_body(sent[0])
    # Wired into BOTH renderers: each falls back silently to generic text when an arm is missing.
    assert ACCOUNT_CREATED in _SUBJECTS
    assert "A security event occurred on your account." not in body
    assert "Roles: administrator" in body
    assert "If this was you" not in body  # an administrator did this, not the holder


# --- the alert keys and the rule registry -----------------------------------------------------


def test_both_new_events_are_rule_targetable() -> None:
    assert {"approval_approver_provenance", "administrator_granted"} <= _ALERT_EVENT_TYPES


def test_the_alert_keys_can_never_name_a_connection() -> None:
    """BACKLOG #1898: a catch-all rule's control_action is dispatched at the event's key. A key that
    could be a connection name could restart a real connection."""
    assert not is_connection_name("approval:0123abcd")
    assert not is_connection_name("user:admin2")


async def test_the_notifier_sink_emits_both_events() -> None:
    transport = _RecordingTransport("t")
    sink = NotifierAlertSink([transport])
    sink.approval_approver_provenance(
        "approval:a1", operation="dead_letter_replay", changed=("account_created",)
    )
    sink.administrator_granted("user:admin2", via="account_created", granted_by="admin1")
    await _drain(sink)
    by_type = {e["type"]: e for e in transport.events}
    assert by_type["approval_approver_provenance"]["connection"] == "approval:a1"
    assert by_type["approval_approver_provenance"]["changed"] == ["account_created"]
    assert by_type["administrator_granted"]["connection"] == "user:admin2"
    assert by_type["administrator_granted"]["granted_by"] == "admin1"


async def test_mapping_a_directory_group_to_administrator_raises_the_grant_alert(
    engine: Engine,
) -> None:
    """Every member of a group mapped to Administrator becomes an approver at sign-in, and the map is
    an engine table this route writes, so a NEWLY mapped group pages like a promotion."""
    service = await _service(engine)
    await _add(service, "admin1", Role.ADMINISTRATOR)
    sink = _Sink()
    async with _app_client(engine, service, sink) as c:
        headers = await _token(c, "admin1")
        body = {
            "entries": [
                {"ad_group": "CN=Ops", "role": Role.OPERATOR.value},
                {"ad_group": "CN=Admins", "role": Role.ADMINISTRATOR.value},
                # The store folds case, so this is the same group: it must not page twice.
                {"ad_group": "cn=admins ", "role": Role.ADMINISTRATOR.value},
            ]
        }
        r = await c.put("/ad-group-map", headers=headers, json=body)
        assert r.status_code == 200, r.text
        # Saving the same map again grants nothing new.
        r = await c.put("/ad-group-map", headers=headers, json=body)
        assert r.status_code == 200, r.text
    assert sink.events == [
        (
            "administrator_granted",
            "ad-group:cn=admins",
            {"via": "ad_group_map", "granted_by": "admin1"},
        )
    ]
    assert not is_connection_name("ad-group:cn=admins")


async def test_a_failed_executor_is_still_flagged(engine: Engine) -> None:
    """The flag is written in a `finally` around the executor, so a release that failed still says
    who released it."""

    async def _boom(_params: Mapping[str, Any]) -> dict[str, Any]:
        raise RuntimeError("executor failed")

    service = await _service(engine)
    maker = await _add(service, "maker", Role.OPERATOR)
    gate = ApprovalGate(
        engine.store, ON, resolve_identity=service.identity_for_user_id, alert_sink=_Sink()
    )
    gate.register("dead_letter_replay", "replay", _boom, permission=Permission.MESSAGES_REPLAY)
    approval_id = await _request(gate, maker)
    checker = await _add(service, "checker", Role.ADMINISTRATOR)

    with pytest.raises(RuntimeError):
        await gate.approve(approval_id, approver="checker", approver_user_id=checker)

    assert len(await _flags(engine)) == 1
    assert len(await engine.store.list_audit(action="approval.failed")) == 1
