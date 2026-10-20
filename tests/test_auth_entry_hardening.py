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


@pytest.mark.parametrize(("window", "expected"), [(37.5, 38), (60.0, 60), (0.2, 1)])
async def test_login_retry_after_is_the_whole_window_whatever_the_bucket_holds(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, window: float, expected: int
) -> None:
    # BACKLOG #3293, owner ruling 2026-10-20: the sign-in 429 sends the whole window, rounded up and
    # never below 1, so it carries no bucket's timing. It reads the same before any attempt, with
    # the bucket full, and just before it drains.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    svc = await _service(
        engine,
        AuthSettings(
            login_rate_limit_per_ip=1,
            login_rate_limit_global=1000,
            login_rate_limit_window_seconds=window,
        ),
    )
    assert svc.login_retry_after() == expected
    assert svc.allow_login_attempt(None)
    assert not svc.allow_login_attempt(None)
    assert svc.login_retry_after() == expected
    clock[0] += window * 0.99
    assert svc.login_retry_after() == expected


async def test_retry_after_floor_is_1_with_the_limiter_off(engine: Engine) -> None:
    # No refusal happens with the limiter off; the accessor answers its floor rather than raising.
    off = await _service(engine, AuthSettings(phi_read_rate_limit_enabled=False))
    assert off.phi_read_retry_after("a") == 1


def test_admin_write_count_refuses_a_negative_value_at_load() -> None:
    # BACKLOG #3293. A negative count loaded, and the limiter then read it as a budget of one write
    # per window: a floor far tighter than any value an operator meant, and one no loosening check
    # names. 0 still loads, as the named off value; the control shows the bound is not above 0.
    with pytest.raises(ValidationError, match="admin_write_rate_limit_per_actor"):
        AuthSettings(admin_write_rate_limit_per_actor=-1)
    assert AuthSettings(admin_write_rate_limit_per_actor=0).admin_write_rate_limit_per_actor == 0


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


def test_limiter_retry_after_is_the_wait_of_the_gate_that_fired(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #2144: the wait a refusal's Retry-After carries. The count gate waits for the key's
    # oldest hit to leave the window; the gap gate waits out the gap; both at once wait the longer.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = SlidingWindowRateLimiter(
        per_key=2, glob=0, window_seconds=37.5, min_interval_seconds=4.0
    )
    assert limiter.retry_after("a") == 0.0  # a key with no hits would be admitted now
    assert limiter.allow("a")
    clock[0] = 1001.0
    assert limiter.retry_after("a") == 3.0  # the gap alone: 4.0 less the second gone
    assert limiter.retry_after("b") == 0.0  # per key
    clock[0] = 1035.0
    assert limiter.allow("a")
    assert limiter.retry_after("a") == 4.0  # both fire; the gap (4.0) outlasts the count (2.5)
    clock[0] = 1036.0
    assert limiter.retry_after("a") == 3.0  # still the gap
    clock[0] = 1039.0
    assert limiter.retry_after("a") == 0.0
    # Asking records nothing: the write the wait promised is admitted.
    assert limiter.allow("a")
    # The count alone, with no gap to mask it.
    counted = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=37.5)
    clock[0] = 2000.0
    assert counted.allow("a")
    clock[0] = 2010.0
    assert counted.allow("a")
    assert counted.retry_after("a") == 27.5
    clock[0] = 2037.5
    assert counted.retry_after("a") == 0.0
    assert counted.allow("a")
    # A negative budget still loads for the sign-in and PHI-read counts (only the admin-write
    # count is refused at load, BACKLOG #3293) and refuses every hit after a key's first. The
    # wait must be a number, not an IndexError that would turn the 429 into a 500: here, until
    # the one hit ages out.
    negative = SlidingWindowRateLimiter(per_key=-1, glob=0, window_seconds=37.5)
    clock[0] = 3000.0
    assert negative.allow("a")
    clock[0] = 3010.0
    assert not negative.allow("a")
    assert negative.retry_after("a") == 27.5
    # At the window's edge the wait and the gate must round the same way. A hit time whose sum
    # with the window is not exact used to read 0.0, "admitted now", while the gate still refused.
    edge = SlidingWindowRateLimiter(per_key=1, glob=0, window_seconds=60.0)
    for hit in (1011.8644575581972, 4000.1, 5000.7, 6000.3):
        clock[0] = hit
        assert edge.allow("k")
        clock[0] = hit + 60.0
        assert (edge.retry_after("k") == 0.0) is edge.would_allow("k"), hit
        clock[0] = hit + 61.0
        assert edge.retry_after("k") == 0.0  # and the bucket is clear for the next hit time


def test_limiter_retry_after_hides_other_keys_when_the_global_budget_is_full(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The true wait on a full global budget is set by when OTHER keys hit. A refused caller gets
    # the whole window instead, so the header cannot be used to read another caller's timing.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = SlidingWindowRateLimiter(per_key=5, glob=2, window_seconds=60.0)
    assert limiter.allow("a")
    clock[0] = 1030.0
    assert limiter.allow("b")
    clock[0] = 1031.0
    assert not limiter.allow("c")
    assert limiter.retry_after("c") == 60.0  # not the 29 s until a's hit ages out


def test_limiter_drops_aged_buckets_of_keys_that_never_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #2714: a bucket used to go only inside a later call for the same key, so a table
    # keyed on a peer address grew with every address ever seen. Now any call drops aged buckets,
    # whoever calls.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = SlidingWindowRateLimiter(per_key=1, glob=0, window_seconds=60.0)
    for n in range(1000):
        assert limiter.allow(f"peer-{n}")
    assert len(limiter._hits) == 1000
    # Inside the window nothing has aged out, and a refused key keeps the bucket retry_after reads.
    clock[0] = 1030.0
    assert not limiter.allow("peer-0")
    assert limiter.retry_after("peer-0") == 30.0
    assert len(limiter._hits) == 1000
    # Four windows later the thousand that never returned drain, two per call, so no one call
    # pays for the whole table.
    clock[0] = 1240.0
    assert limiter.allow("new")
    assert len(limiter._hits) == 999  # two dropped, one added
    for _ in range(499):
        assert not limiter.would_allow("new")  # per_key=1: refused, and records nothing
    assert set(limiter._hits) == {"new"}
    # A bucket whose newest hit is still live survives; would_allow records nothing.
    clock[0] = 1290.0
    assert limiter.allow("late")
    clock[0] = 1300.5
    assert not limiter.would_allow("late")
    assert set(limiter._hits) == {"late"}
    assert list(limiter._hits["late"]) == [1290.0]


def test_limiter_orders_buckets_by_newest_hit_so_eviction_stops_at_the_first_live_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The table is ordered by each key's newest hit, so a call drops aged buckets from the front
    # and never scans the rest. A key that returns moves to the back, past an older key.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = SlidingWindowRateLimiter(per_key=2, glob=0, window_seconds=60.0)
    assert limiter.allow("a")
    clock[0] = 1010.0
    assert limiter.allow("b")
    clock[0] = 1020.0
    assert limiter.allow("a")  # "a" now has the newer hit
    assert list(limiter._hits) == ["b", "a"]
    clock[0] = 1071.0
    assert limiter.allow("c")  # drops "b" (1010), keeps "a" (1020) though its first hit is older
    assert list(limiter._hits) == ["a", "c"]
    assert list(limiter._hits["a"]) == [1000.0, 1020.0]  # its own hits prune on its own call
    clock[0] = 1081.0
    assert limiter.would_allow("z")  # evicts "a" (1020), and records nothing for "z"
    assert list(limiter._hits) == ["c"]


def test_limiter_table_stays_bounded_under_a_stream_of_new_keys(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A peer-keyed table under a steady stream of addresses never seen again: one new key a second,
    # for ten windows. The table never grows past the 60 keys live at one time, the new one included.
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    limiter = SlidingWindowRateLimiter(per_key=5, glob=0, window_seconds=60.0)
    for n in range(600):
        clock[0] = 1000.0 + n
        assert limiter.allow(f"peer-{n}")
        assert len(limiter._hits) == min(n + 1, 60)
    # A limiter with no per-key gate (the intake global window) keeps no buckets at all.
    global_only = SlidingWindowRateLimiter(per_key=0, glob=1000, window_seconds=60.0)
    for n in range(100):
        assert global_only.allow(f"peer-{n}")
    assert not global_only._hits
    # A gap with no count still keeps buckets, or the gap would never fire.
    gap_only = SlidingWindowRateLimiter(
        per_key=0, glob=0, window_seconds=60.0, min_interval_seconds=1.0
    )
    assert gap_only.allow("a")
    assert not gap_only.allow("a")
    clock[0] += 1.0
    assert gap_only.allow("a")


def test_limiter_with_no_global_gate_keeps_no_global_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # BACKLOG #2714 follow-up. With the global gate off, nothing reads the global window, so an
    # admitted call must not add to it; it used to hold every call of the last window.
    # RED when: a call admitted with ``glob=0`` lands in ``_global_hits``.
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: 1000.0)
    )
    per_key_only = SlidingWindowRateLimiter(per_key=5, glob=0, window_seconds=60.0)
    for n in range(500):
        assert per_key_only.allow(f"peer-{n}")
    assert not per_key_only._global_hits
    # The control: with the gate on, the window still counts and still refuses.
    global_on = SlidingWindowRateLimiter(per_key=0, glob=3, window_seconds=60.0)
    for n in range(3):
        assert global_on.allow(f"peer-{n}")
    assert len(global_on._global_hits) == 3
    assert not global_on.allow("peer-x")
    assert global_on.retry_after("peer-x") == 60.0


async def test_admin_write_retry_after_is_whole_seconds_rounded_up_and_at_least_one(
    engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(
        "messagefoundry.auth.ratelimit.time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    # The shipped defaults: a refusal by the 0.15 s gap rounds up to 1, never 0.
    svc = AuthService(engine.store, AuthSettings())
    assert svc.allow_admin_write("a")
    assert not svc.allow_admin_write("a")
    assert svc.admin_write_retry_after("a") == 1
    # The count: 12 writes at one instant fill the default 15 s window, so the wait is all of it.
    counted = AuthService(engine.store, AuthSettings(admin_write_min_interval_seconds=0))
    assert all(counted.allow_admin_write("a") for _ in range(12))
    assert counted.admin_write_retry_after("a") == 15
    clock[0] += 0.25
    assert counted.admin_write_retry_after("a") == 15  # 14.75 rounds UP
    assert counted.admin_write_retry_after("b") == 1  # an actor who is not throttled: the minimum
    # A disabled limiter refuses nothing; the accessor still answers with a valid header value.
    off = AuthService(engine.store, AuthSettings(admin_write_rate_limit_enabled=False))
    assert off.admin_write_retry_after("a") == 1


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
