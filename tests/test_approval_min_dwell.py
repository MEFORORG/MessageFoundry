# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The minimum-dwell floor on a pending approval (ASVS 2.4.2, BACKLOG #287).

``[approvals].expiry_hours`` is a ceiling. ``[approvals].min_dwell_seconds`` is the floor: a request
younger than it cannot be approved yet. ``ApprovalGate.approve`` enforces it, so every release path
does. The gate-level tests drive the gate's injected clock; the store and auth service keep the real
one.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.auth import Permission, Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import ApprovalsSettings, load_settings
from messagefoundry.pipeline import Engine
from tests.test_approvals import _add, _service, _token

OPS = ["dead_letter_replay", "connection_purge"]
FLOOR = 30.0
T0 = 1_900_000_000.0


class _Clock:
    def __init__(self, now: float) -> None:
        self.now = now

    def __call__(self) -> float:
        return self.now


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "dwell.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def _gate_with_request(
    engine: Engine, service: AuthService, floor: float, clock: _Clock
) -> tuple[ApprovalGate, str, list[Mapping[str, Any]]]:
    """A gate with the replay op registered and one request held by ``maker`` at the clock's now."""
    maker = await _add(service, "maker", Role.OPERATOR)
    gate = ApprovalGate(
        engine.store,
        ApprovalsSettings(enabled=True, operations=OPS, min_dwell_seconds=floor),
        resolve_identity=service.identity_for_user_id,
        clock=clock,
    )
    ran: list[Mapping[str, Any]] = []

    async def _record(p: Mapping[str, Any]) -> dict[str, Any]:
        ran.append(p)
        return {"ran": True}

    gate.register("dead_letter_replay", "replay", _record, permission=Permission.MESSAGES_REPLAY)
    approval_id = await gate.guard(
        "dead_letter_replay", {}, requester="maker", requester_user_id=maker
    )
    assert approval_id is not None
    return gate, approval_id, ran


async def test_an_approve_before_the_floor_is_refused_audited_and_left_pending(
    engine: Engine,
) -> None:
    service = await _service(engine)
    clock = _Clock(T0)
    gate, approval_id, ran = await _gate_with_request(engine, service, FLOOR, clock)
    clock.now = T0 + FLOOR - 0.5
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    assert "minimum is 30.0 seconds" in caught.value.detail
    assert "again in 1 second(s)" in caught.value.detail
    assert ran == []  # the operation did not run
    row = await engine.store.get_pending_approval(approval_id)
    assert row is not None and str(row["status"]) == "pending"
    audit = await engine.store.list_audit(action="approval.too_early")
    assert len(audit) == 1
    detail = json.loads(str(audit[0]["detail"]))
    assert audit[0]["actor"] == "checker"
    assert detail["approval_id"] == approval_id
    assert detail["operation"] == "dead_letter_replay"
    assert detail["min_dwell_seconds"] == FLOOR
    assert detail["age_seconds"] == pytest.approx(FLOOR - 0.5)
    assert await engine.store.list_audit(action="approval.approved") == []


async def test_an_approve_at_the_floor_succeeds(engine: Engine) -> None:
    """Exactly at the floor is allowed: the refusal is age < floor, not age <= floor."""
    service = await _service(engine)
    clock = _Clock(T0)
    gate, approval_id, ran = await _gate_with_request(engine, service, FLOOR, clock)
    clock.now = T0 + FLOOR
    out = await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert out["result"] == {"ran": True}
    assert len(ran) == 1
    assert await engine.store.list_audit(action="approval.too_early") == []


async def test_a_refused_request_can_be_approved_once_the_floor_passes(engine: Engine) -> None:
    """Nothing retries a refused approve, and nothing needs to: the row is still pending."""
    service = await _service(engine)
    clock = _Clock(T0)
    gate, approval_id, ran = await _gate_with_request(engine, service, FLOOR, clock)
    clock.now = T0 + 1.0
    with pytest.raises(ApprovalError):
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert ran == []
    clock.now = T0 + FLOOR + 1.0
    await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert len(ran) == 1
    assert len(await engine.store.list_audit(action="approval.too_early")) == 1


async def test_a_clock_behind_the_request_is_too_early_and_states_the_real_wait(
    engine: Engine,
) -> None:
    """A negative age (two engine processes whose clocks disagree) fails closed, and the 409 names
    the whole remaining wait rather than just the floor."""
    service = await _service(engine)
    clock = _Clock(T0)
    gate, approval_id, ran = await _gate_with_request(engine, service, FLOOR, clock)
    clock.now = T0 - 5.0
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert caught.value.status == 409
    assert "again in 35 second(s)" in caught.value.detail
    assert ran == []


async def test_a_zero_floor_releases_at_once(engine: Engine) -> None:
    service = await _service(engine)
    gate, approval_id, ran = await _gate_with_request(engine, service, 0.0, _Clock(T0))
    await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert len(ran) == 1


async def test_self_approval_inside_the_floor_is_still_the_403(engine: Engine) -> None:
    """The self-approval refusal runs first, so a requester is told the real reason."""
    service = await _service(engine)
    gate, approval_id, _ran = await _gate_with_request(engine, service, FLOOR, _Clock(T0))
    maker = await service.store.get_user_by_username("maker")
    assert maker is not None
    with pytest.raises(ApprovalError) as caught:
        await gate.approve(approval_id, approver="maker", approver_user_id=maker.id)
    assert caught.value.status == 403
    assert await engine.store.list_audit(action="approval.too_early") == []


async def test_the_json_route_reaches_the_floor(engine: Engine) -> None:
    """End to end over the API: an immediate release is a 409, not a 200.

    The floor is raised to a minute here ONLY so the test cannot race it. It uses the real clock, and
    two logins (argon2id) on a loaded runner could take longer than the shipped 2 s. What this test
    proves is that the route reaches the gate's floor, which does not depend on the value."""
    service = await _service(engine)
    await _add(service, "maker", Role.OPERATOR)
    await _add(service, "checker", Role.ADMINISTRATOR)
    app = create_app(
        engine,
        auth=service,
        approvals=ApprovalsSettings(enabled=True, operations=OPS, min_dwell_seconds=60.0),
    )
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        maker_auth = await _token(c, "maker")
        checker_auth = await _token(c, "checker")
        held = await c.post("/dead-letters/replay", headers=maker_auth, json={})
        assert held.status_code == 202, held.text
        approval_id = held.json()["approval_id"]
        r = await c.post(f"/approvals/{approval_id}/approve", headers=checker_auth)
        assert r.status_code == 409, r.text
        assert "too new to approve" in r.json()["detail"]
    assert len(await engine.store.list_audit(action="approval.too_early")) == 1
    assert await engine.store.list_audit(action="approval.approved") == []


async def test_a_zero_floor_is_no_floor_even_with_a_clock_behind(engine: Engine) -> None:
    """``0`` means NO floor. A negative age must not trip it: unguarded, a clock 1 ms behind
    requested_at gives age < 0.0 and refuses an approve the operator switched the floor off for."""
    service = await _service(engine)
    clock = _Clock(T0)
    gate, approval_id, ran = await _gate_with_request(engine, service, 0.0, clock)
    clock.now = T0 - 0.001
    await gate.approve(approval_id, approver="checker", approver_user_id="checker-id")
    assert len(ran) == 1
    assert await engine.store.list_audit(action="approval.too_early") == []


# --- the setting ---------------------------------------------------------------------------------

#: Card, Moran and Newell (1980), keystroke-level model: M 1.35 s + P 1.10 s + K 0.08 s (fastest).
#: The derivation is stated in docs/SECURITY.md. This is only the check that the default stays under
#: that sum; it is not a second statement of it.
_KLM_LEAST_RELEASE_SECONDS = 1.35 + 1.10 + 0.08


def test_the_default_is_at_or_below_the_published_human_minimum() -> None:
    """The default must not refuse a genuine reviewer. If someone raises it past the published
    minimum, this reds and asks for the source that justifies the new figure."""
    default = ApprovalsSettings().min_dwell_seconds
    assert default == 2.0
    assert 0 < default <= _KLM_LEAST_RELEASE_SECONDS


@pytest.mark.parametrize("bad", [-1.0, float("nan"), float("inf")])
def test_a_negative_or_non_finite_floor_is_refused(bad: float) -> None:
    with pytest.raises(ValidationError):
        ApprovalsSettings(min_dwell_seconds=bad)


@pytest.mark.parametrize("bad", [float("nan"), float("inf")])
def test_a_non_finite_expiry_is_refused(bad: float) -> None:
    """A non-finite expiry means something different on each backend, and a nan one would also skip
    the dwell cross-check (nan > 0 is False)."""
    with pytest.raises(ValidationError):
        ApprovalsSettings(enabled=True, expiry_hours=bad, min_dwell_seconds=1e9)


def test_an_expiry_that_overflows_to_inf_in_seconds_is_refused() -> None:
    with pytest.raises(ValidationError, match="too large"):
        ApprovalsSettings(expiry_hours=1e305)


def test_a_floor_at_or_past_the_expiry_is_refused() -> None:
    with pytest.raises(ValidationError, match="shorter than approvals.expiry_hours"):
        ApprovalsSettings(enabled=True, expiry_hours=1.0, min_dwell_seconds=3600.0)
    ApprovalsSettings(enabled=True, expiry_hours=1.0, min_dwell_seconds=3599.0)


def test_a_disabled_gate_does_not_refuse_startup_over_its_default_floor() -> None:
    """A tiny expiry with dual control OFF must still load; the default floor is not in play."""
    ApprovalsSettings(enabled=False, expiry_hours=0.0005)


def test_a_never_expiring_request_takes_any_finite_floor() -> None:
    ApprovalsSettings(enabled=True, expiry_hours=0.0, min_dwell_seconds=86_400.0)


def test_the_loader_reads_the_floor_from_toml_and_env(tmp_path: Path) -> None:
    cfg = tmp_path / "mf.toml"
    cfg.write_text("[approvals]\nmin_dwell_seconds = 5.0\n", encoding="utf-8")
    assert load_settings(config_path=cfg, environ={}).approvals.min_dwell_seconds == 5.0
    env = {"MEFOR_APPROVALS_MIN_DWELL_SECONDS": "7.5"}
    assert load_settings(config_path=cfg, environ=env).approvals.min_dwell_seconds == 7.5


def test_the_loader_refuses_a_floor_past_the_expiry(tmp_path: Path) -> None:
    """Startup refuses it, through the real loader and not only at model construction."""
    cfg = tmp_path / "mf.toml"
    cfg.write_text(
        "[approvals]\nenabled = true\nexpiry_hours = 1.0\nmin_dwell_seconds = 3600.0\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError, match="shorter than approvals.expiry_hours"):
        load_settings(config_path=cfg, environ={})
