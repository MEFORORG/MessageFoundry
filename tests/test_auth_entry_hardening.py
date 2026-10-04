# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Phase-3a auth entry-surface hardening: fail-closed (SYS-1), rate limiting (AUTH-RATE),
input/body caps (API-INPUT)."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from messagefoundry.api import create_app
from messagefoundry.auth.ratelimit import SlidingWindowRateLimiter
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "entry.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


async def _service(engine: Engine, settings: AuthSettings | None = None) -> AuthService:
    service = AuthService(engine.store, settings or AuthSettings())
    await service.initialize()
    return service


def _client(engine: Engine, service: AuthService) -> httpx.AsyncClient:
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    return httpx.AsyncClient(transport=transport, base_url="http://t")


async def _login(c: httpx.AsyncClient, username: str, password: str) -> httpx.Response:
    return await c.post(
        "/auth/login", json={"username": username, "password": password, "provider": "local"}
    )


# --- SYS-1: fail-closed when no auth is attached -----------------------------


async def test_no_auth_fails_closed(engine: Engine) -> None:
    # create_app without an auth service AND without the opt-in must deny protected routes.
    transport = httpx.ASGITransport(app=create_app(engine))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/health")).status_code == 200  # liveness stays open
        assert (await c.get("/channels")).status_code == 503  # fail-closed, not full access


async def test_no_auth_opt_in_allows_access(engine: Engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        assert (await c.get("/channels")).status_code == 200  # explicit embedding/dev opt-in


# --- AUTH-RATE: sliding-window limiter ---------------------------------------


def test_rate_limiter_per_key() -> None:
    rl = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=60)
    assert rl.allow("a")
    assert rl.allow("a")
    assert not rl.allow("a")  # third attempt from the same key is blocked
    assert rl.allow("b")  # a different key is unaffected


def test_rate_limiter_global() -> None:
    rl = SlidingWindowRateLimiter(per_key=0, glob=2, window_seconds=60)
    assert rl.allow("a")
    assert rl.allow("b")
    assert not rl.allow("c")  # global cap hit regardless of key


# --- ADR 0154 D6: the read-only peek -----------------------------------------


def test_would_allow_never_consumes_budget() -> None:
    # The whole point (AC-13). Intake auth consults the budget before comparing a credential and
    # charges it only when the comparison fails; if the consult itself charged, intake_auth_rate_limit
    # would stop bounding brute force and become a per-peer throughput cap.
    rl = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=60)
    for _ in range(50):
        assert rl.would_allow("a")
    # ... and the full per-key budget is still there afterwards.
    assert rl.allow("a")
    assert rl.allow("a")
    assert not rl.allow("a")


def test_would_allow_agrees_with_allow() -> None:
    # They share one predicate; a caller that consults one and charges the other must never see them
    # disagree at the boundary.
    rl = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=60)
    assert rl.would_allow("a") and rl.allow("a")
    assert rl.would_allow("a") and rl.allow("a")
    assert not rl.would_allow("a")
    assert not rl.allow("a")
    assert rl.would_allow("b")  # a different key is unaffected


def test_would_allow_reports_the_global_bucket_regardless_of_key() -> None:
    # Pins the hazard AC-19 exists to handle: the global bucket refuses irrespective of key, so a
    # global arm consulted for EVERY peer would let one attacker deny an authenticated partner. The
    # limiter is behaving correctly here — the mitigation belongs in the caller, which must consult
    # the global arm only for peers with no successful authentication in the window.
    rl = SlidingWindowRateLimiter(per_key=0, glob=2, window_seconds=60)
    assert rl.allow("attacker")
    assert rl.allow("attacker")
    assert not rl.would_allow("innocent-partner")


def test_would_allow_prunes_the_expired_window() -> None:
    # would_allow is "no append", NOT "side-effect free": it must prune, or it compares against
    # stale counts and stays closed forever after one burst.
    rl = SlidingWindowRateLimiter(per_key=1, glob=0, window_seconds=0.05)
    assert rl.allow("a")
    assert not rl.would_allow("a")
    time.sleep(0.08)
    assert rl.would_allow("a")  # the expired hit aged out of the window


async def test_admin_write_limiter_per_actor(engine: Engine) -> None:
    # BACKLOG #193 (ASVS 2.4.2): allow_admin_write is a per-actor sliding window; a different actor is
    # independent, and enabled=False is a transparent pass-through.
    svc = await _service(
        engine,
        AuthSettings(
            admin_write_min_interval_seconds=0,
            admin_write_rate_limit_per_actor=2,
            admin_write_rate_limit_window_seconds=60.0,
        ),
    )
    assert svc.allow_admin_write("a")
    assert svc.allow_admin_write("a")
    assert not svc.allow_admin_write("a")  # third write from the same actor is throttled
    assert svc.allow_admin_write("b")  # a different actor is unaffected (no cross-actor cap)

    off = await _service(engine, AuthSettings(admin_write_rate_limit_enabled=False))
    for _ in range(50):
        assert off.allow_admin_write("a")  # disabled limiter → always allowed


async def test_login_rate_limited_per_ip(engine: Engine) -> None:
    service = await _service(
        engine, AuthSettings(login_rate_limit_per_ip=2, login_rate_limit_global=1000)
    )
    async with _client(engine, service) as c:
        assert (await _login(c, "nobody", "x")).status_code == 401  # 1 — invalid creds
        assert (await _login(c, "nobody", "x")).status_code == 401  # 2
        assert (await _login(c, "nobody", "x")).status_code == 429  # 3 — rate limited


def test_admin_write_pacing_ships_default_on_at_the_human_timing_floor() -> None:
    # ASVS 2.4.2 register drift-guard: anti-automation pacing is DEFAULT-ON (not opt-in). BACKLOG #287
    # moved the window from 1.0 s to a PROVISIONAL human-timing floor of 12 writes per 15 s, derived
    # from the keystroke-level model in the comment on the setting. Pinning the three shipped defaults
    # makes a change to them a deliberate act that must also move the register row and the docs.
    settings = AuthSettings()
    assert settings.admin_write_rate_limit_enabled is True
    assert settings.admin_write_rate_limit_per_actor == 12
    assert settings.admin_write_rate_limit_window_seconds == 15.0


@pytest.mark.parametrize("window", [0.0, -1.0, float("nan"), float("inf")])
def test_admin_write_window_refuses_a_value_that_would_switch_the_floor_off_or_jam_it(
    window: float,
) -> None:
    # BACKLOG #287 made the window an operator tuning knob. A zero or negative window prunes every
    # hit at once (the floor is silently off); a nan one never prunes (every write after the twelfth
    # is refused until restart). Both are refused at load instead.
    with pytest.raises(ValidationError):
        AuthSettings(admin_write_rate_limit_window_seconds=window)


# --- BACKLOG #2301 (ASVS 2.4.2): the minimum gap between two admin writes ----------------------


def test_admin_write_gap_ships_default_on_at_its_provisional_floor() -> None:
    # Pinned like the count above: the default is a provisional human-timing floor (the comment on
    # the setting derives it), so changing it must be a deliberate act that moves the docs too.
    assert AuthSettings().admin_write_min_interval_seconds == 0.15


def test_admin_write_gap_as_long_as_the_window_is_refused_at_load() -> None:
    # The limiter prunes the last write before it measures the gap, so a gap as long as the window
    # would silently fall back to the count. Refused while the limiter is on; ignored while it is off.
    with pytest.raises(ValidationError, match="shorter than"):
        AuthSettings(admin_write_min_interval_seconds=15.0)
    assert AuthSettings(admin_write_min_interval_seconds=14.9).admin_write_min_interval_seconds
    AuthSettings(admin_write_rate_limit_enabled=False, admin_write_min_interval_seconds=15.0)


async def test_admin_write_gap_refuses_a_write_just_inside_it_and_admits_one_just_past_it(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The count alone admits twelve writes back to back. The gap refuses the second write while it
    # is younger than the floor after the first, and admits it just past. The limiter's own clock is
    # faked, so no test sleeps.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    gap = AuthSettings().admin_write_min_interval_seconds
    svc = AuthService(engine.store, AuthSettings())
    assert svc.allow_admin_write("a")
    clock[0] += gap - 0.001
    assert not svc.allow_admin_write("a"), "a write just inside the gap was admitted"
    assert svc.allow_admin_write("b"), "the gap is per actor, not global"
    # A refused write is not recorded, so the gap still runs from the first write.
    clock[0] += 0.002
    assert svc.allow_admin_write("a"), "a write just past the gap was refused"


async def test_admin_write_gap_zero_admits_back_to_back_writes(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control for the refusal above: with the gap off, one instant admits the count's budget.
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: 1000.0)
    )
    svc = AuthService(engine.store, AuthSettings(admin_write_min_interval_seconds=0))
    assert all(svc.allow_admin_write("a") for _ in range(12))
    assert not svc.allow_admin_write("a")  # the count still binds at the thirteenth


# --- API-INPUT: length + body-size caps --------------------------------------


async def test_login_password_length_capped(engine: Engine) -> None:
    service = await _service(engine)
    async with _client(engine, service) as c:
        r = await _login(c, "u", "p" * 2000)  # over the password max_length
        assert r.status_code == 422  # rejected by request validation before any hashing


async def test_oversized_request_body_rejected(engine: Engine) -> None:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.post("/config/reload", json={"config_dir": "x" * 1_200_000})
        assert r.status_code == 413  # body exceeds the 1 MiB cap
