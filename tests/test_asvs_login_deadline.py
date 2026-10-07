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

**Reading the deadline is not the same as being off the wall clock, and this docstring used to say it
was.** The retired sentence lived on :class:`_DeadlineRecorder` and claimed the deadline "is the value
the control actually computes; a measured elapsed would only be that value plus scheduler jitter".
That holds inside one slot and not across slots. :func:`~messagefoundry.auth.service._failure_deadline`
QUANTIZES — it reads the measured elapsed and rounds up to the next whole multiple of the budget — so
a process stall longer than the budget moves the deadline a whole slot without any branch doing extra
work. The invariance assertions below therefore rest partly on wall-clock measurements. What keeps
them reading the code rather than the runner is :func:`_deadline_samples` and
:func:`_assert_one_deadline`, not the recorder.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry.auth.service as svc
from messagefoundry.api import create_app
from messagefoundry.auth import Role
from messagefoundry.auth.identity import AuthProvider
from messagefoundry.auth.ldap import AdPrincipal
from messagefoundry.auth.service import AuthService, LoginOutcome
from messagefoundry.config.settings import AuthSettings, EgressSettings
from messagefoundry.pipeline import Engine
from tests._admin_account import create_local_user_chosen

PW = "a-strong-test-passphrase"  # >=15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(
        tmp_path / "login_deadline.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    yield eng
    await eng.stop()


class _DeadlineRecorder:
    """Stands in for ``service._sleep_until``: records the deadline, never waits.

    Recording the deadline rather than the elapsed is what buys the tight tolerance. The deadline is
    the value the control actually computes, so it carries none of the scheduler jitter a measured
    elapsed would add on the way back out — on Windows ~15 ms, which would force a tolerance wide
    enough to hide the differences these tests exist to catch.

    It does NOT take these tests off the wall clock, and an earlier version of this docstring said it
    did. The deadline is quantized from a measured elapsed, so a stall still reaches it; see the
    module docstring and :func:`_assert_one_deadline`.
    """

    def __init__(self) -> None:
        self.deadlines: list[float] = []
        #: When each pad was reached: after the branch's work and its deferred audit writes, so no
        #: earlier than any clock read the deadline was computed from.
        self.reached: list[float] = []

    async def __call__(self, deadline: float) -> None:
        self.reached.append(time.monotonic())
        self.deadlines.append(deadline)

    def clear(self) -> None:
        self.deadlines.clear()
        self.reached.clear()


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _DeadlineRecorder:
    rec = _DeadlineRecorder()
    monkeypatch.setattr(svc, "_sleep_until", rec)
    # The overrun warning latches per process; clear it so a test that drives an overrun sees the
    # warning regardless of which tests ran before it.
    monkeypatch.setattr(svc, "_BUDGET_OVERRUN_WARNED", set())
    return rec


#: Interleaved rounds for the two invariance assertions: at least the minimum, then more while some
#: branch has not yet answered on the base slot, up to the maximum. Over that many rounds the
#: wrong-password branch would walk its account into lockout, so the sign-in seam clears that
#: account's counter before each of its samples; the per-sample outcome check is the guard that
#: still holds if that reset ever stops working.
_MIN_ROUNDS = 3
_MAX_ROUNDS = 6

#: Covers only the microseconds between two `time.monotonic()` reads that stand for one instant,
#: never a branch's work, which is on the other side of the deadline.
_TOLERANCE = 0.001

#: A seam's failure branches: name -> (a callable that drives it, the error it must keep returning).
#: The call is re-invoked per sample, so it is a factory rather than a coroutine, which can only be
#: awaited once.
type _Branches = Mapping[str, tuple[Callable[[], Awaitable[LoginOutcome]], str]]


@dataclass(frozen=True)
class _Sample:
    """One failed challenge."""

    #: The deadline, measured from the test's own call start: what a caller observes.
    offset: float
    #: The deadline, measured from the ``started`` the seam handed its equaliser.
    seam_offset: float
    #: When the pad was reached, after the branch's work and writes, from that same ``started``.
    reached: float
    #: The wait in the account's credential queue the seam reported (0 on a seam with no queue).
    queued: float


async def _deadline_samples(
    recorder: _DeadlineRecorder,
    service: AuthService,
    branches: _Branches,
    *,
    before_each: Callable[[str], Awaitable[None]] | None = None,
    max_rounds: int = _MAX_ROUNDS,
) -> dict[str, list[_Sample]]:
    """Drive every branch in interleaved rounds and return each one's samples.

    **Interleaved, because a stall is a stretch of time and not a branch.** Merge-queue intermittent,
    2026-10-07 (run 37562580245, windows-2025, xdist worker gw2): ``wrong_password`` read 1.0000032
    against 0.5000019-0.5000033 for the other three. A refusal's row is written at the later of
    the write point, a quarter second in, and the end of the branch's work, so the gaps between one
    branch's consecutive rows read its work. ``wrong_password``'s rows were 0.65 s and 0.64 s apart,
    and the other two local branches' were 0.29-0.50 s apart, against about 0.05 s of work unloaded.
    The whole worker was starved, every argon2 branch ran close to the budget, and the one that also
    counts a failure in the store before the pad crossed it. Sampled branch after branch, one
    starved stretch of about two seconds covered all three of that branch's samples, so their
    minimum could not recover. Round-robin, the same stretch is spread over every branch's samples,
    and the further rounds below can outlast it.

    **Adaptive, because the minimum is still the reading that survives load.** Load only makes a
    branch read HIGH, so a branch that answers on the base slot even once has shown that its own
    cost fits. Sampling stops once every branch has, after at least :data:`_MIN_ROUNDS`, and goes
    on to ``max_rounds`` otherwise. Measured 2026-09-16, the earlier eviction this keeps fixed:
    ``ad_pathway_retired``, the CHEAPEST branch on the seam at 0.30 ms min / 0.47 ms median against
    34-55 ms for every local branch, read one slot late. A 0.3 ms branch cannot reliably need a
    second 500 ms slot, so the direction of that anomaly identifies the environment.

    **The seam's own ``started`` and ``queued`` are read off its equaliser call**, so the first part
    of :func:`_assert_one_deadline` judges each sample against the instants the seam computed from,
    and a pause between the test's clock read and the seam's cannot pass for a defect.

    **Every sample re-checks that the branch is still the branch**, so repetition cannot quietly
    collapse two branches into one and leave the invariance assertion trivially satisfied.
    ``before_each`` gets the branch's name and runs before that sample's clock starts, so it costs
    no branch any time.
    """
    calls: list[tuple[float, float]] = []
    equalize = service._equalize_failure

    async def watched(outcome: LoginOutcome, started: float, **kwargs: Any) -> LoginOutcome:
        calls.append((started, kwargs.get("queued", 0.0)))
        return await equalize(outcome, started, **kwargs)

    samples: dict[str, list[_Sample]] = {name: [] for name in branches}
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(service, "_equalize_failure", watched)
        for completed in range(1, max_rounds + 1):
            for name, (call, expected_error) in branches.items():
                if before_each is not None:
                    await before_each(name)
                recorder.clear()
                calls.clear()
                start = time.monotonic()
                outcome = await call()
                assert not outcome.ok, f"{name} was expected to fail"
                assert outcome.error == expected_error, (
                    f"{name} stopped being that branch under repetition: {outcome.error!r}"
                )
                assert len(recorder.deadlines) == 1, f"{name} did not pad exactly once"
                assert len(calls) == 1, f"{name} did not reach the equaliser exactly once"
                deadline, (started, queued) = recorder.deadlines[0], calls[0]
                samples[name].append(
                    _Sample(
                        offset=deadline - start,
                        seam_offset=deadline - started,
                        reached=recorder.reached[0] - started,
                        queued=queued,
                    )
                )
            if completed >= _MIN_ROUNDS and not _late_branches(samples):
                break
    return samples


def _late_branches(samples: Mapping[str, list[_Sample]]) -> dict[str, list[float]]:
    """The branches that never answered on the base slot, with every deadline each one read."""
    base = min(sample.offset for branch in samples.values() for sample in branch)
    return {
        name: [round(sample.offset, 7) for sample in branch]
        for name, branch in samples.items()
        if min(sample.offset for sample in branch) > base + _TOLERANCE
    }


def _assert_one_deadline(samples: Mapping[str, list[_Sample]]) -> None:
    """THE INVARIANCE ASSERTION, in two parts: one that load cannot reach, and one it can only delay.

    **A late answer from a sample that finished in time is a defect, on any single sample.** The
    seam fixes its deadline from ``started``, the queue wait, and clock reads taken no later than
    the pad. A sample that did not wait in the queue and reached its pad before the base slot's
    boundary had nothing to round up, so if it still answered on a later slot, the deadline depended
    on something other than the clock, which is the branch. Both are measured from the seam's own
    ``started``, so load cannot produce this: it only moves the pad later or adds a queue wait, and
    either excuses the sample. A late sample that waited, or reached its pad at or after the
    boundary, is the designed fail-safe (:func:`~messagefoundry.auth.service._failure_deadline`
    rounds an overrun up to a whole slot, and a queued attempt gets a floor). No number of clean
    samples can hide one that fails this.

    **Every branch must still answer on the base slot at least once, as the caller sees it.** That
    is the minimum the previous form of this test read, measured from the test's own call start, so
    it also reds a seam that starts one branch's clock later than another's. It is what reds a
    branch whose own cost CONSISTENTLY overruns the budget: it never reaches the base slot, in any
    round. What it costs, stated rather than glossed: a cost that overruns only on a fraction ``p``
    of calls is caught with probability ``p ** rounds``, up to ``p ** 6``, so this is weaker against
    an intermittently slow branch than a single sample would be. A single sample is not the safer
    alternative, because it reds for the environment on a starved runner, and a guard that reds for
    the wrong reason gets relaxed by whoever is unblocking the queue. An intermittent branch would
    have to swing across a whole 500 ms slot to be visible to either form, which against branches
    costing 0.3-55 ms is a hundredfold regression. This part cannot pass on a runner starved for the
    whole test: then every argon2 branch overruns in every round, the seam really does answer them
    a slot after the cheap branch, and this reds, as
    ``test_the_shipped_budget_leaves_room_above_a_real_argon2_verify`` would.

    **A uniform stall is deliberately tolerated.** Nothing asserts that the base is slot 1. If every
    branch is pushed to a later slot together they are still indistinguishable, which is the
    property; asserting the slot index would put the load sensitivity straight back.
    """
    base = min(sample.seam_offset for branch in samples.values() for sample in branch)
    for name, branch in samples.items():
        for sample in branch:
            late = sample.seam_offset > base + _TOLERANCE
            clean = sample.queued < _TOLERANCE and sample.reached < base - _TOLERANCE
            assert not (late and clean), (
                f"deadline depends on the branch taken: {name} answered at "
                f"{sample.seam_offset:.7f} past its start, after the base {base:.7f}, although it "
                f"waited {sample.queued:.7f} and reached its pad at {sample.reached:.7f}"
            )
    never = _late_branches(samples)
    assert not never, (
        f"deadline depends on the branch taken: never on the base slot in "
        f"{max(len(branch) for branch in samples.values())} interleaved rounds: {never}"
    )


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
        user_id = await create_local_user_chosen(
            service,
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
            user_id,
            password_hash=user.password_hash,
            must_change_password=False,
            password_generated=False,
        )
    for _ in range(12):  # drive `locky` past the lockout threshold
        await service.login("locky", "definitely-not-it")
    return service


async def test_every_login_failure_branch_answers_at_one_deadline(
    engine: Engine, recorder: _DeadlineRecorder
) -> None:
    """THE INVARIANCE ASSERTION for the sign-in seam.

    Four failure branches whose real costs differed by up to 75x before the pad. A fifth, the
    first-run account's spelling, went with that account (ADR 0183). Each is driven from a
    call start captured in :func:`_deadline_samples`, and the assertion is that
    ``deadline - start`` is the same for all of them — not that it equals any particular number, and
    not that it equals a constant the production code also reads.
    """
    service = await _service(engine)
    jane = await service.store.get_user_by_username("jane")
    assert jane is not None
    retired = "Directory password sign-in has been retired; use Windows SSO or OIDC"
    branches: _Branches = {
        "unknown_username": (
            lambda: service.login("nosuchuser", "definitely-not-it"),
            "invalid credentials",
        ),
        "wrong_password": (
            lambda: service.login("jane", "definitely-not-it"),
            "invalid credentials",
        ),
        "locked_account": (lambda: service.login("locky", "definitely-not-it"), "account locked"),
        # BACKLOG #1137 retired directory password sign-in on 2026-08-22, AFTER this item's research
        # was written. It refuses before any store lookup, so it was by far the loudest branch here —
        # and, measured 2026-09-16, by far the CHEAPEST, which is why a stall reaches it first.
        "ad_pathway_retired": (
            lambda: service.login("jane", PW, provider=AuthProvider.AD),
            retired,
        ),
    }

    async def unlock_jane(branch: str) -> None:
        # Repetition must not turn `wrong_password` into `locked_account`; see _MIN_ROUNDS.
        if branch == "wrong_password":
            await service.store.clear_lockout(jane.id)

    # At the parent commit of BACKLOG #1140 these branches spread 49 ms; _TOLERANCE is 1 ms.
    _assert_one_deadline(
        await _deadline_samples(recorder, service, branches, before_each=unlock_jane)
    )


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
        directory_object_id="75920276-799f-51a3-9e67-4e4b9c43fd0c",
    )

    class _FakeLdap:
        def authenticate(self, username: str, password: str, **_: object) -> AdPrincipal | None:
            return principal if (username == "jdoe" and password == "pw") else None

        def resolve_principal(self, username: str, **_: object) -> AdPrincipal | None:
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
    await create_local_user_chosen(
        service,
        username="jdoe",
        password=PW,
        display_name=None,
        email=None,
        roles=[Role.OPERATOR.value],
        actor="test",
    )

    def _reject(principal_name: str | None) -> Callable[[], Awaitable[LoginOutcome]]:
        # The principal patch is re-applied per sample rather than once per branch, so each sample is
        # self-contained and no sample can run against the name a previous branch installed.
        async def _call() -> LoginOutcome:
            monkeypatch.setattr(
                "messagefoundry.auth.service.kerberos_principal",
                lambda _t, _s, _p=principal_name: _p,
            )
            return await service.authenticate_kerberos(b"spnego-token")

        return _call

    branches: _Branches = {
        "no_principal": (_reject(None), "SSO authentication failed"),
        "not_in_directory": (_reject("stranger"), "user not found in directory"),
        "local_account_conflict": (_reject("jdoe"), "account conflict"),
    }
    _assert_one_deadline(await _deadline_samples(recorder, service, branches))


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
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
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
    transport = httpx.ASGITransport(app=create_app(engine, auth=service, serve_ui=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        r = await c.get("/ui/sso", headers={"Authorization": "Negotiate !!!not-base64!!!"})
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
        r = await c.get(
            "/ui/sso",
            headers={"Authorization": "Negotiate c3BuZWdvLXRva2Vu", "Sec-Fetch-Mode": "cors"},
        )
        assert r.status_code == 303 and r.headers["location"] == "/ui/login?e=sso_failed"
    assert recorder.deadlines == []


# --- the invariance instrument itself ----------------------------------------
#
# Driven through the real equaliser with synthetic work, so they run in about a second and each part
# of `_assert_one_deadline` is shown able to fail, and able to pass, on a shape it has to judge.

#: A budget well above the steady branches' few microseconds of work, and short enough to keep these
#: tests fast. A "stall" is half as long again, so it lands on the second slot.
_INSTRUMENT_BUDGET = 0.3


def _timed_branches(
    service: AuthService, work: Mapping[str, Callable[[], float]]
) -> dict[str, tuple[Callable[[], Awaitable[LoginOutcome]], str]]:
    """One branch per name, each spending ``work[name]()`` seconds before the equaliser runs."""
    failed = LoginOutcome(ok=False, error="nope")

    def branch(seconds: Callable[[], float]) -> Callable[[], Awaitable[LoginOutcome]]:
        async def call() -> LoginOutcome:
            started = time.monotonic()
            await asyncio.sleep(seconds())
            return await service._equalize_failure(failed, started, seam="t")

        return call

    return {name: (branch(cost), "nope") for name, cost in work.items()}


async def test_a_stall_over_one_branchs_first_samples_does_not_red(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The 2026-10-07 shape, made certain: one branch overruns on its first three calls only.

    Read as the previous form of this test read it, three samples of one branch in a row and then
    their minimum, this reds exactly as merge-queue run 37562580245 did, one branch a whole slot
    late. Interleaved and adaptive, the fourth round (or a later one on a loaded runner) brings
    that branch back to the base slot.
    """
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", _INSTRUMENT_BUDGET)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    stalls = iter([1.5 * _INSTRUMENT_BUDGET] * 3)
    samples = await _deadline_samples(
        recorder,
        service,
        _timed_branches(service, {"steady": lambda: 0.0, "stalled": lambda: next(stalls, 0.0)}),
    )
    # At least the second slot: a loaded runner can only push a stalled sample later still.
    slots = [round(sample.offset / _INSTRUMENT_BUDGET) for sample in samples["stalled"]]
    assert min(slots[:3]) >= 2 and slots[-1] == 1, slots
    _assert_one_deadline(samples)


async def test_a_late_answer_from_a_branch_that_finished_in_time_reds_on_one_sample(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the load-proof part: a deadline that depends on the branch, with no overrun.

    The ``shifted`` branch does no work and its recorded deadline is moved one slot later, which is
    what a seam computing a branch-dependent deadline would record. It must red, and on the first
    part of the assertion: its pad was reached long before the base deadline.
    """
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", _INSTRUMENT_BUDGET)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    branches = _timed_branches(service, {"steady": lambda: 0.0, "shifted": lambda: 0.0})
    shifted_call, error = branches["shifted"]

    async def shifted() -> LoginOutcome:
        outcome = await shifted_call()
        recorder.deadlines[-1] += _INSTRUMENT_BUDGET
        return outcome

    branches["shifted"] = (shifted, error)
    samples = await _deadline_samples(recorder, service, branches, max_rounds=_MIN_ROUNDS)
    with pytest.raises(AssertionError, match="although it waited"):
        _assert_one_deadline(samples)


async def test_a_branch_that_overruns_every_round_still_reds(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the second part: a branch whose own cost always needs a second slot.

    Every one of its samples is the fail-safe working as designed, so the first part excuses each
    of them. The branch never reaches the base slot, so the second part must red.
    """
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", _INSTRUMENT_BUDGET)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    samples = await _deadline_samples(
        recorder,
        service,
        _timed_branches(service, {"steady": lambda: 0.0, "slow": lambda: 1.5 * _INSTRUMENT_BUDGET}),
        max_rounds=_MIN_ROUNDS,
    )
    with pytest.raises(AssertionError, match="never on the base slot"):
        _assert_one_deadline(samples)


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


# --- the deferred audit writes (BACKLOG #2467) --------------------------------


def _rows(count: int, each: float) -> list[Callable[[], Awaitable[None]]]:
    """``count`` stand-in audit writes, each taking ``each`` seconds."""

    async def row() -> None:
        await asyncio.sleep(each)

    return [row] * count


async def test_the_deadline_does_not_move_with_the_number_of_audit_rows(
    engine: Engine, recorder: _DeadlineRecorder, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RED when: the equaliser reads the clock for the deadline after the refusal's audit writes.

    The ``queued`` value puts the write point 10 ms before a slot boundary, the shape a caller who
    queues a second attempt on a name can pick. Read after the writes, zero rows answered on that
    boundary and one or two rows on the next. Fixed before them, with room left, all three answer
    on one deadline."""
    budget = 0.4
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", budget)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    failed = LoginOutcome(ok=False, error="nope")
    offsets: dict[int, float] = {}
    for count in (0, 1, 2):
        started = time.monotonic()
        await service._equalize_failure(
            failed,
            started,
            seam="t",
            queued=budget / 2 - 0.01,
            writes=_rows(count, 0.03),
            write_room=True,
        )
        offsets[count] = recorder.deadlines[-1] - started
    spread = max(offsets.values()) - min(offsets.values())
    assert spread < 0.001, f"the deadline depends on how many rows were written: {offsets}"


async def test_writes_that_outrun_their_room_answer_on_a_whole_later_slot(
    engine: Engine,
    recorder: _DeadlineRecorder,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Writes longer than their room cannot put the raw elapsed on the wire: the answer waits to the
    next slot boundary after they finish, the same fail-safe as work over the budget. The overrun
    is logged once, apart from the work overrun's warning, so an operator learns the room is short.
    """
    budget = 0.2
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", budget)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))
    started = time.monotonic()
    # The write point is half a budget in and the rows take a whole one, so they end past slot 1.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.auth.service"):
        await service._equalize_failure(
            LoginOutcome(ok=False, error="nope"),
            started,
            seam="t",
            writes=_rows(1, budget),
            write_room=True,
        )
    finished = time.monotonic()
    warnings = [r.getMessage() for r in caplog.records if "audit writes took" in r.getMessage()]
    assert len(warnings) == 1 and "failed t challenge" in warnings[0], warnings
    slots = (recorder.deadlines[-1] - started) / budget
    assert abs(slots - round(slots)) < 1e-6 and round(slots) >= 2, slots
    assert recorder.deadlines[-1] > finished - 0.001


async def test_a_cancel_before_the_write_point_reaches_the_caller_when_a_write_fails(
    engine: Engine, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A caller who drops the request before the write point still gets its cancel back, and the
    failed write is logged rather than raised in its place, which would turn a disconnect into a
    500."""
    monkeypatch.setattr(svc, "_FAILURE_BUDGET_SECONDS", 2.0)
    service = AuthService(engine.store, AuthSettings(require_mfa=False))

    async def failing() -> None:
        raise RuntimeError("store down")

    task = asyncio.ensure_future(
        service._equalize_failure(
            LoginOutcome(ok=False, error="nope"),
            time.monotonic(),
            seam="t",
            writes=[failing],
            write_room=True,
        )
    )
    await asyncio.sleep(0.05)  # before the write point, a whole second in
    with caplog.at_level(logging.ERROR, logger="messagefoundry.auth.service"):
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert "audit write failed after a cancel" in caplog.text
