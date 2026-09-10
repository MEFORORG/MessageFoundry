# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 6.3.8 — every FAILED challenge answers at a deadline fixed before dispatch (BACKLOG #1140).

The verb asks that valid users not be deducible from failed authentication challenges, *including by
different response times*. Messages and status codes were already uniform on both challenge seams;
latency was not. Measured 2026-09-05 at the parent commit, in-process against a real SQLite store,
warmed and interleaved, 25 samples per branch: the local failure branches ran 45.7-49.6 ms while a
``provider=ad`` refusal returned in 0.61 ms — a 75x spread across one seam.

**What these tests assert, and what they deliberately do not.** They assert INVARIANCE: every failure
branch answers at the SAME deadline, and that deadline does not depend on which branch ran. They do
not compare either seam against a shared constant. An equality assertion against the symbol the
production code reads goes tautological exactly where the property under test is "does not depend on
caller input" — it would still pass if the deadline were computed from the username.

**No directory, no clock-watching, on every CI leg.** The pad's one sleep site is the module-level
:func:`~messagefoundry.auth.service._sleep_until`, so a test replaces it and reads back the deadline
the seam computed instead of paying a wall-clock wait. The directory is the duck-typed fake the
``/ui/sso`` suite already uses. Owner ruling 2026-08-20: there is no multi-VM lab, so a control whose
verification needed a live domain controller would not be verifiable here at all.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest

import messagefoundry.auth.service as svc
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "login_deadline.db", poll_interval=0.02)
    yield eng
    await eng.stop()


class _DeadlineRecorder:
    """Stands in for ``service._sleep_until``: records the deadline, never waits.

    Recording the deadline rather than the elapsed is what keeps these tests off the wall clock. The
    deadline is the value the control actually computes; a measured elapsed would only be that value
    plus scheduler jitter, which on Windows is ~15 ms and would force a tolerance wide enough to hide
    the differences the tests exist to catch.
    """

    def __init__(self) -> None:
        self.deadlines: list[float] = []

    async def __call__(self, deadline: float) -> None:
        self.deadlines.append(deadline)


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _DeadlineRecorder:
    rec = _DeadlineRecorder()
    monkeypatch.setattr(svc, "_sleep_until", rec)
    # The overrun warning latches per process; clear it so a test that drives an overrun sees the
    # warning regardless of which tests ran before it.
    monkeypatch.setattr(svc, "_BUDGET_OVERRUN_WARNED", set())
    return rec


# --- the deadline primitive --------------------------------------------------


@pytest.mark.parametrize(
    "elapsed",
    [-5.0, -0.001, 0.0, 1e-9, 0.1, 0.4999, 0.5, 0.5001, 0.9, 1.0, 3.7, 60.0, 3600.0],
)
def test_the_deadline_is_always_strictly_ahead_of_now(elapsed: float) -> None:
    # THE FAIL-OPEN GUARD. A pad that returns a deadline at or behind `now` does not pad at all, and
    # it does so exactly under the load that made the work slow — the moment the timing differential
    # is widest. Exact slot boundaries and a backwards clock are included because both are where an
    # off-by-one lands.
    started = 1000.0
    now = started + elapsed
    assert svc._failure_deadline(started, now) > now


@pytest.mark.parametrize(
    ("elapsed_slots", "expected_slots"),
    [(0.0, 1), (0.5, 1), (0.999, 1), (1.0, 2), (1.5, 2), (2.0, 3), (4.2, 5), (19.9, 20)],
)
def test_an_overrun_quantizes_to_a_whole_slot(elapsed_slots: float, expected_slots: int) -> None:
    # Work that outran its budget lands on the NEXT whole multiple, so what it discloses is a slot
    # index rather than the elapsed itself. The 19.9-slot case is the directory-outage shape: two
    # 10 s ldap3 timeouts against a 0.5 s budget.
    budget = 0.5
    started = 1000.0
    deadline = svc._failure_deadline(started, started + elapsed_slots * budget, budget)
    assert deadline == pytest.approx(started + expected_slots * budget)


def test_the_shipped_budget_leaves_room_above_a_real_argon2_verify() -> None:
    """The budget is a control only while it exceeds the slowest failure branch.

    Below that, every branch overruns and the quantization — which is the FALLBACK — silently becomes
    the mechanism. argon2 dominates the local branches, so it is the floor the constant has to clear,
    and it is measured rather than asserted from t/m/p because the cost is as much a property of the
    machine as of the parameters.

    **The comparison takes the MINIMUM of several verifies, and the margin is 1x on purpose.** A
    wall-clock measurement on a shared CI runner only ever reads HIGH under load, so a mean and a
    generous multiplier is precisely the shape that goes red for a reason that has nothing to do with
    the code. The minimum is robust to that — load cannot make a verify finish early — and 1x is the
    real necessary condition. The separate floor below is what catches the change this is here for: a
    budget dropped to milliseconds, which disables the control without deleting a line of it.
    """
    from messagefoundry.auth.passwords import hash_password, verify_password

    h = hash_password(PW)
    costs = []
    for _ in range(3):
        start = time.monotonic()
        verify_password(h, "definitely-not-it")
        costs.append(time.monotonic() - start)
    assert min(costs) < svc._FAILURE_BUDGET_SECONDS
    assert svc._FAILURE_BUDGET_SECONDS >= 0.1


# --- seam 1: the credential sign-in seam -------------------------------------


async def _service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    for name in ("jane", "locky"):
        user_id = await service.create_local_user(
            username=name,
            password=PW,
            display_name=None,
            email=None,
            roles=[Role.OPERATOR.value],
            actor="test",
        )
        user = await service.store.get_user(user_id)
        assert user is not None and user.password_hash is not None
        await service.store.set_password(
            user_id, password_hash=user.password_hash, must_change_password=False
        )
    for _ in range(12):  # drive `locky` past the lockout threshold
        await service.login("locky", "definitely-not-it")
    return service


async def test_every_login_failure_branch_answers_at_one_deadline(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    """THE INVARIANCE ASSERTION for the sign-in seam.

    Five failure branches whose real costs differ by 75x at the parent commit. Each is driven from a
    call start captured here, and the assertion is that ``deadline - start`` is the same for all of
    them — not that it equals any particular number, and not that it equals a constant the production
    code also reads.
    """
    service = await _service(engine)
    branches = {
        "unknown_username": lambda: service.login("nosuchuser", "definitely-not-it"),
        "wrong_password": lambda: service.login("jane", "definitely-not-it"),
        "locked_account": lambda: service.login("locky", "definitely-not-it"),
        # The bootstrap spelling takes an extra store lookup plus the supersession check (#1268), and
        # measured 3.6 ms slower than every other local branch before the pad.
        "bootstrap_username": lambda: service.login("admin", "definitely-not-it"),
        # BACKLOG #1137 retired directory password sign-in on 2026-08-22, AFTER this item's research
        # was written. It refuses before any store lookup, so it was by far the loudest branch here.
        "ad_pathway_retired": lambda: service.login("jane", PW, provider=AuthProvider.AD),
    }
    offsets: dict[str, float] = {}
    for name, call in branches.items():
        recorder.deadlines.clear()
        start = time.monotonic()
        outcome = await call()
        assert not outcome.ok, f"{name} was expected to fail"
        assert len(recorder.deadlines) == 1, f"{name} did not pad exactly once"
        offsets[name] = recorder.deadlines[0] - start

    spread = max(offsets.values()) - min(offsets.values())
    # The tolerance covers only the microseconds between this test's `time.monotonic()` and the
    # seam's own — NOT the branch's work, which is on the other side of the deadline. At the parent
    # commit these branches spread 49 ms; 1 ms would fail there by 49x.
    assert spread < 0.001, f"deadline depends on the branch taken: {offsets}"


async def test_a_successful_login_is_never_padded(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    # A valid credential has already disclosed that the account exists, so padding it would cost
    # every real sign-in half a second and conceal nothing. This is also the control for the test
    # above: it proves the recorder is wired to something that can be ABSENT, so five recorded
    # deadlines there are a fact about the code rather than about the fixture.
    service = await _service(engine)
    recorder.deadlines.clear()  # the fixture's own lockout drive padded 12 times
    outcome = await service.login("jane", PW)
    assert outcome.ok
    assert recorder.deadlines == []


async def test_the_pad_does_not_alter_the_outcome(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    # The equaliser returns the outcome unchanged. Asserted because a pad that swallowed or rebuilt
    # the outcome would still satisfy every timing assertion above while breaking sign-in.
    service = await _service(engine)
    assert (await service.login("jane", PW)).ok
    bad = await service.login("jane", "definitely-not-it")
    assert not bad.ok and bad.error == "invalid credentials"
    ad = await service.login("jane", PW, provider=AuthProvider.AD)
    assert not ad.ok and "retired" in (ad.error or "")


async def test_an_overrun_warns_once_per_seam(
    engine: Engine, recorder: _DeadlineRecorder, caplog: pytest.LogCaptureFixture
) -> None:
    # An overrun cannot fail open, but it does mean the budget is wrong for this hardware, and only a
    # log says so. Warning per overrun would be an unbounded log amplifier on an unauthenticated
    # surface, so the latch is deliberate — and asserted, because "warns" and "warns once" are
    # different controls and only one of them is safe here.
    service = await _service(engine)
    monkey_budget = 1e-9  # every real branch overruns this
    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"),
        pytest.MonkeyPatch.context() as mp,
    ):
        mp.setattr(svc, "_FAILURE_BUDGET_SECONDS", monkey_budget)
        for _ in range(3):
            await service.login("nosuchuser", "definitely-not-it")
    warnings = [r for r in caplog.records if "anti-enumeration budget" in r.message]
    assert len(warnings) == 1, f"expected exactly one warning, got {len(warnings)}"
    assert "login" in warnings[0].getMessage()


# --- seam 2: the Windows-SSO challenge seam (GET /ui/sso) --------------------


def _sso_service(engine: Engine, *, conflicting_local: bool = False) -> AuthService:
    """The duck-typed directory the ``/ui/sso`` suite already uses. No AD exists in any test infra."""
    principal = AdPrincipal(
        username="jdoe",
        display_name="J Doe",
        email="j@x",
        dn="CN=jdoe,DC=x",
        groups=frozenset({"cn=mf-admins,dc=x"}),
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "pw") else None

        def resolve_principal(self, username: str) -> AdPrincipal | None:
            # A resolvable principal costs a directory search; an unresolvable one does not. That
            # difference is the branch the pad has to hide on this seam.
            time.sleep(0.002)
            return principal if username == "jdoe" else None

    settings = AuthSettings(
        ad_enabled=True,
        kerberos_enabled=True,
        ad_server="ldaps://x",
        ad_user_search_base="DC=x",
        ad_bind_dn="CN=svc,DC=x",
        ad_bind_password="x",
    )
    return AuthService(engine.store, settings, ldap=_FakeLdap())  # type: ignore[arg-type]


async def test_every_kerberos_reject_answers_at_one_deadline(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE INVARIANCE ASSERTION for the second seam — the one a pad on ``login`` alone would miss.

    ``GET /ui/sso`` calls ``authenticate_kerberos`` directly and never reaches the sign-in seam, so
    this seam needs its own deadline. The branches differ in real cost: an unparseable token returns
    before any directory work, an unresolvable principal costs a search, and a like-named local
    account costs that search plus a store lookup.
    """
    service = _sso_service(engine)
    await service.initialize()
    # A local account colliding with the directory name: the conflict branch, reachable only after a
    # SUCCESSFUL resolve, and therefore the slowest reject on this seam.
    await service.create_local_user(
        username="jdoe",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )
    branches = {
        "no_principal": None,
        "not_in_directory": "stranger",
        "local_account_conflict": "jdoe",
    }
    offsets: dict[str, float] = {}
    for name, principal_name in branches.items():
        monkeypatch.setattr(
            "messagefoundry.auth.service.kerberos_principal",
            lambda _t, _s, _p=principal_name: _p,
        )
        recorder.deadlines.clear()
        start = time.monotonic()
        outcome = await service.authenticate_kerberos(b"spnego-token")
        assert not outcome.ok, f"{name} was expected to fail"
        assert len(recorder.deadlines) == 1, f"{name} did not pad exactly once"
        offsets[name] = recorder.deadlines[0] - start
    spread = max(offsets.values()) - min(offsets.values())
    assert spread < 0.001, f"deadline depends on the reject branch: {offsets}"


async def test_a_disabled_sso_seam_pads_like_every_other_reject(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    # "Windows SSO is not configured" returns before any directory or store work at all — the
    # cheapest branch on this seam, and the one a pad sited after the guard would leave uncovered.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    start = time.monotonic()
    outcome = await service.authenticate_kerberos(b"spnego-token")
    assert not outcome.ok
    assert len(recorder.deadlines) == 1
    assert recorder.deadlines[0] - start > 0


async def test_the_ui_sso_route_inherits_the_deadline(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pad is sited on the SERVICE method, not in the route — this proves that covers ``/ui/sso``.

    Siting it in ``messagefoundry_webconsole/routes/sso.py`` would have equalized one caller and left
    the JSON Kerberos leg to be fixed separately. Driving the real route here is what turns "the
    service pads" into "this seam is padded".
    """
    service = _sso_service(engine)
    await service.initialize()
    monkeypatch.setattr("messagefoundry.auth.service.kerberos_principal", lambda _t, _s: "stranger")
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get(
            "/ui/sso",
            headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu"},
        )
    # The route's own collapsed response is unchanged; what is new is that it is now also timed the
    # same as every other reject that reaches the service.
    assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
    assert len(recorder.deadlines) == 1, "the /ui/sso reject was not padded"


async def test_route_local_rejects_are_deliberately_not_padded(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    """The two rejects ``/ui/sso`` answers itself are NOT padded, and that is the intended boundary.

    A malformed base64 header and a non-navigation fetch are properties of the caller's own request,
    identical for every principal and knowable to the caller before it sends them. They disclose
    nothing about a username, so padding them would add latency for no property. Pinned so that a
    later reading of "the pad must be sited at every entry point" does not quietly become "pad
    everything", and so the boundary is a decision on the record rather than an oversight.
    """
    service = _sso_service(engine)
    await service.initialize()
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))  # type: ignore[arg-type]
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate !!!not-base64!!!"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
        r = await c.get(
            "/ui/sso",
            headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu", "Sec-Fetch-Mode": "cors"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
    assert recorder.deadlines == []


# --- the equaliser itself ----------------------------------------------------


async def test_the_equaliser_pads_on_ok_false_and_only_on_ok_false(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    # Driven directly so the property is pinned at the helper, independent of either seam's branch
    # set: a seam that grows a new failure outcome inherits this rather than needing its own test.
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    await service.initialize()
    started = time.monotonic()
    failed = LoginOutcome(ok=False, error="nope")
    assert await service._equalize_failure(failed, started, seam="t") is failed
    assert len(recorder.deadlines) == 1
    ok = LoginOutcome(ok=True, token="t")
    assert await service._equalize_failure(ok, started, seam="t") is ok
    assert len(recorder.deadlines) == 1
