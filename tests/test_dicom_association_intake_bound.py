# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ASVS 2.4.1 / 15.2.2 -- the DICOM SCP association bound (BACKLOG #1114).

**Why this file exists separately from the poll ceilings.** BACKLOG #1114 needed two different
controls, and they were first built together in
``tests/test_poll_and_association_intake_bounds.py``. The poll-ceiling half of that module was
written against ``max_files_per_poll``, a knob the packet D merge retires in favour of
``poll_max_files`` -- a rename that also moves where the budget is charged, from the candidate
listing to the files a scan actually disposes of. The ceiling is now measured against the shipped
knob in ``tests/test_poll_source_tick_ceilings.py``, which also covers the Database poll source that
the earlier module never reached. The association bound is unchanged by any of that, so it is
carried here rather than deleted with the module it happened to share.

*The DICOM SCP* has a peer to make wait, so its bound **ships OFF** for the same ruled reason the
message-rate pacer does (2026-08-11): a guessed rate throttles a real modality. Its unit is an
**association**, not a message, because ``pynetdicom`` owns the read loop -- by ``EVT_C_STORE`` the
object is already read and decoded, and pacing after decode is the thing this item's record rejects
by name.

**The load-bearing test here is not that the bound bites.** It is
:func:`test_a_paced_scp_still_establishes_every_association`. A bound that dropped or refused would
pass a "the rate is bounded" assertion while breaking the count-and-log invariant, which forbids
accept-and-drop.

The doc-drift guards run BEFORE the ``[dicom]`` extra is required, so a run without the extra still
measures the security prose rather than skipping the whole module.
"""

from __future__ import annotations

import asyncio
import inspect
import re
import threading
import time
from pathlib import Path

import pytest

from messagefoundry.config import wiring
from messagefoundry.config.connections_file import _TRANSPORTS
from messagefoundry.config.models import ConnectorType, Source

# --- doc drift: the security prose must agree with the signatures, in BOTH directions --------------


def _ingest_row() -> str:
    doc = (Path(__file__).resolve().parent.parent / "docs" / "SECURITY.md").read_text(
        encoding="utf-8"
    )
    return next(line for line in doc.splitlines() if line.startswith("| **Ingest plane**"))


def test_the_ingest_row_agrees_with_the_dicom_signature() -> None:
    """Reachability is READ FROM THE SIGNATURE and the row must agree with whatever it says.

    The same shape the existing MLLP / raw-TCP / X12 / HTTP guard uses, and for the same reason:
    pinning either state as the correct one would settle a product question by build. Remove this
    control and the test demands the row say so; keep it and it demands the row stop calling the
    DICOM SCP uncovered.

    **The poll-ceiling half of this guard is deliberately absent, and its absence is a finding
    rather than a simplification.** It read the row against ``max_files_per_poll``; the shipped knob
    is now ``poll_max_files`` at a different default, and the Database poll source the row calls
    uncovered now carries ``poll_max_rows``. The row is therefore stale in more than a name, and
    restoring this half belongs with the change that rewrites it -- not with the merge that made it
    stale.
    """
    row = _ingest_row()
    dicom_reaches = "max_associations_per_second" in inspect.signature(wiring.DICOM).parameters

    if dicom_reaches:
        assert "max_associations_per_second" in row, (
            "DICOM() now takes an association-rate bound, so the ingest row must name it"
        )
        assert "Not covered even when set:** the DICOM C-STORE SCP" not in row, (
            "DICOM() now takes an association-rate bound; the row may no longer call the SCP "
            "uncovered"
        )
    else:
        assert "the DICOM C-STORE SCP" in row, (
            "DICOM() takes no rate bound, so the row must say the SCP has none"
        )


def test_the_ingest_row_does_not_generalise_the_toml_surface_past_x12() -> None:
    """The row claimed the code-first AND TOML surfaces both express the pacing keys "across all
    four named factories". For ``X12`` the second half was false, and it was false for a reason the
    row's own sibling paragraph already gave: ``_TRANSPORTS`` carries no ``x12`` key, so NO X12
    setting is expressible in ``connections.toml``.

    Derived from the loader map, not from the retired wording, so this flips by itself the day the
    transport is added: add ``x12`` to ``_TRANSPORTS`` and the row is required to stop carving it out.
    """
    row = _ingest_row()
    code_first = [
        f
        for f in ("MLLP", "Tcp", "X12", "Http")
        if "max_messages_per_second" in inspect.signature(getattr(wiring, f)).parameters
    ]
    toml_reachable = [f for f in code_first if f.lower() in _TRANSPORTS]
    assert code_first, "no listen factory takes the pacing keys any more; re-derive this guard"

    if len(toml_reachable) < len(code_first):
        missing = sorted(set(code_first) - set(toml_reachable))
        assert "the code-first and the TOML surface both express them" not in row, (
            f"{missing} take the pacing keys code-first but have no connections.toml row, so the "
            "ingest row may not claim both surfaces express them across all four factories"
        )
        for factory in missing:
            assert factory in row, (
                f"{factory} is unreachable from connections.toml; the ingest row must name it rather "
                "than let a reader generalise from the factories that are reachable"
            )
    else:
        assert "three of the four" not in row, (
            "every pacing factory now has a connections.toml row, so the row must stop carving one "
            "out of the TOML claim"
        )


def test_the_ingest_row_still_states_the_shipped_default_for_the_association_bound() -> None:
    """The DICOM bound is off, so a default install still has no rate bound on ANY listen intake --
    the fact that decides the ASVS cell. A row that stated only the poll side would mislead."""
    row = _ingest_row()
    assert "NO message-RATE bound" in row, (
        "the row must keep stating that a default install has no ingest message-rate bound; the "
        "DICOM association bound ships OFF and does not change that"
    )


# --- REACHABILITY: a connector that reads a key no author can write is not a shipped control -------


def test_the_dicom_factory_reaches_the_association_bound() -> None:
    spec = wiring.DICOM(
        ae_title="AE", port=104, max_associations_per_second=9.5, association_burst=30.0
    )
    assert spec.settings["max_associations_per_second"] == 9.5
    assert spec.settings["association_burst"] == 30.0


def test_dicom_has_no_toml_surface_at_all_which_is_a_separate_gap() -> None:
    """Recorded so the missing ``dicom`` row reads as a measurement rather than an oversight.

    ``DICOM`` is absent from ``_TRANSPORTS`` entirely -- the same shape as the ``x12`` gap, and the
    connector's own fail-closed error message already says so in its own words. The association bound
    is not a special case of that; closing it means adding the transport, a different decision.
    """
    assert "dicom" not in _TRANSPORTS
    assert "file" in _TRANSPORTS, "positive control -- the map is populated"


def test_the_dicom_factory_still_rejects_an_unknown_key() -> None:
    """Positive control on the reachability tests above. If the factory swallowed arbitrary keywords,
    each of those assertions would pass without the parameter existing at all."""
    with pytest.raises(TypeError):
        wiring.DICOM(ae_title="AE", mefor_no_such_intake_key_1114=1.0)


def test_the_dicom_factory_default_is_still_off() -> None:
    """Exposing the keys must not turn the bound on. A defaulted number here would ship a guessed
    rate to every SCP deployment -- the failure the 2026-08-11 ruling judged worse than no bound."""
    spec = wiring.DICOM(ae_title="AE")
    assert spec.settings["max_associations_per_second"] is None
    assert spec.settings["association_burst"] is None


# --- the DICOM SCP association bound ---------------------------------------------------------------

pydicom = pytest.importorskip(
    "pydicom", reason="the DICOM association bound needs the [dicom] extra"
)
pynetdicom = pytest.importorskip(
    "pynetdicom", reason="the DICOM association bound needs the [dicom] extra"
)

from messagefoundry.transports.dicom import (  # noqa: E402
    DEFAULT_MAX_ASSOCIATIONS_PER_SECOND,
    DicomScpSource,
)

_SCP_AE = "MEFOR_PACE"


def _scp(**settings: object) -> DicomScpSource:
    base: dict[str, object] = {"ae_title": _SCP_AE, "host": "127.0.0.1", "port": 0}
    base.update(settings)
    return DicomScpSource(Source(name="IB_DICOM", type=ConnectorType.DIMSE, settings=base))


def test_the_association_bound_ships_off() -> None:
    """Unlike the poll ceiling and LIKE the message pacer -- this one makes a real peer wait."""
    assert DEFAULT_MAX_ASSOCIATIONS_PER_SECOND is None
    src = _scp()
    assert src.max_associations_per_second is None
    assert src._pacer is None, "no rate configured must mean no pacer object at all"


def test_association_burst_defaults_to_one_seconds_worth() -> None:
    """Setting only the rate must not leave the burst at zero, which would pace the first peer."""
    assert _scp(max_associations_per_second=25).association_burst == 25.0
    assert _scp(max_associations_per_second=25, association_burst=100).association_burst == 100.0


def test_the_pacing_handlers_are_registered_only_when_a_rate_is_set() -> None:
    """An unpaced SCP -- the shipped default -- must run the handler set it always did.

    Read from ``_start_server`` rather than asserted in prose: the handlers are appended under a
    guard, and this is what fails if that guard is removed and every default install starts paying
    for two callbacks on its association path.
    """
    source = inspect.getsource(DicomScpSource._start_server)
    assert "if self._pacer is not None:" in source
    guard = source.index("if self._pacer is not None:")
    for event in ("EVT_CONN_OPEN", "EVT_ACCEPTED"):
        assert source.index(event) > guard, f"{event} is registered outside the pacer guard"


def test_the_wait_is_before_the_association_request_is_read() -> None:
    """The property that makes this honest, pinned against the events it is wired to.

    ``EVT_CONN_OPEN`` fires before the A-ASSOCIATE-RQ is read, so an over-budget peer's request is
    never taken in. ``EVT_C_STORE`` is after decode, which this item's record rejects by name -- a wait
    there would delay a message the count-and-log invariant has already obliged us to account for.
    """
    source = inspect.getsource(DicomScpSource._start_server)
    assert re.search(r"EVT_CONN_OPEN,\s*self\._pace_association", source)
    assert re.search(r"EVT_ACCEPTED,\s*self\._charge_association", source)
    assert not re.search(r"EVT_C_STORE,\s*self\._pace_association", source)


def test_only_an_accepted_association_charges_the_budget() -> None:
    """A connection that opens and never associates charges nothing.

    Charging earlier would let a peer that submits no object spend a real modality's budget, which
    turns the limiter into the denial of service it exists to prevent (the HTTP listener's rule).
    """
    src = _scp(max_associations_per_second=10, association_burst=10)
    assert src._pacer is not None
    for _ in range(50):
        src._pace_association(object())  # opening alone must never deepen the debt
    assert src._pacer.deficit(now=time.monotonic()) == 0.0
    for _ in range(15):
        src._charge_association(object())
    assert src._pacer.deficit(now=time.monotonic()) > 0.0


async def test_stop_releases_an_outstanding_pacing_wait() -> None:
    """Shutdown must not wait out a rate debt. A 0.1/s rate owes tens of seconds; ``stop()`` clears it.

    **This test goes through ``stop()`` itself, and that is a correction it earned.** The first draft
    set ``_stopping`` by hand and asserted the WAIT responded to it. A mutation that deleted
    ``self._stopping.set()`` from ``stop()`` then survived: the wait was still interruptible and
    nothing was left to interrupt it, so the assertion held while shutdown had silently become
    unbounded. Testing the seam a caller actually uses is the difference.
    """
    src = _scp(max_associations_per_second=0.1, association_burst=1)
    assert src._pacer is not None

    async def handler(raw: bytes) -> str | None:  # pragma: no cover - nothing is stored here
        return None

    await src.start(handler)
    try:
        src._charge_association(object())
        src._charge_association(object())
        assert src._pacer.deficit(now=time.monotonic()) > 5.0, "fixture drifted: no real debt owed"
        waiter = threading.Thread(target=src._pace_association, args=(object(),))
        waiter.start()
        time.sleep(0.2)  # let it get into the wait
        assert waiter.is_alive(), "fixture drifted: the pacing wait returned before stop() ran"
        start = time.monotonic()
        await src.stop()
        waiter.join(timeout=5.0)
        assert not waiter.is_alive(), "stop() did not release the pacing wait"
        assert time.monotonic() - start < 5.0, "shutdown waited out the rate debt"
    finally:
        src._stopping.set()
        await src.stop()


def test_the_pacer_lock_is_not_held_across_the_wait() -> None:
    """A thread sleeping off its own debt must not block the bucket for every other association.

    Held across the wait, the lock would serialise the acceptor and turn a rate knob into the denial
    of service it guards against -- the failure the ``EVT_CONN_OPEN`` threading measurement rules out.
    """
    src = _scp(max_associations_per_second=0.5, association_burst=1)
    assert src._pacer is not None
    src._charge_association(object())
    src._charge_association(object())
    waiter = threading.Thread(target=src._pace_association, args=(object(),))
    waiter.start()
    try:
        time.sleep(0.2)  # let it get into the wait
        assert src._pacer_lock.acquire(timeout=1.0), "the pacing wait holds the bucket lock"
        src._pacer_lock.release()
    finally:
        src._stopping.set()
        waiter.join(timeout=5.0)
    assert not waiter.is_alive()


_ECHOES = 6
#: The paced arm's bucket capacity. ``_MessagePacer`` clamps capacity to ``max(burst, 1.0)``, so 1.0
#: is the smallest burst that means what it says.
_PACED_BURST = 1.0
#: How many arrivals must WAIT, and so how many entries the pacer's decision record must hold.
#: Derived from the schedule in the test docstring, never written as a literal -- an earlier draft
#: guessed ``N - burst`` and was wrong by exactly this one.
_PACED_STEPS = _ECHOES - 1 - _PACED_BURST
#: How far the pacing floor is held above the MEASURED control. It sets the test's wall time (about
#: ``_SEPARATION`` times the control arm) and it sets how much slower per association the paced arm
#: would have to run, for a reason other than pacing, before either timing arm stopped discriminating.
_SEPARATION = 4.0
#: Below this the floor no longer separates from the control and the wall-clock arm could be
#: satisfied by machine speed alone, so the test says that rather than passing.
_MIN_SEPARATION = 2.0
#: The wall-clock arm is asserted at this fraction of the floor. Kept TIGHT on purpose, and 0.75 was
#: measured to be far too loose: the paced arm's own work hands it ``floor / 4`` for free, so at 0.75
#: pacing need only supply 60 percent of what it honestly supplies and a wait capped at half a step
#: would still pass. The floor is exact bucket arithmetic rather than a measurement -- ``paced_elapsed
#: == floor + 2w``, so the honest arm measured 1.03 to 1.21 times the floor over five runs, its low
#: end of 1.03 being the arithmetic one rather than a lucky sample. Read that spread as the host and
#: not the pacer: the control arms behind it ranged 0.165 s to 0.436 s inside ONE process, which is
#: contention visible within the measurement itself. A later reading on the same host found 117
#: processes and 5,308 CPU-seconds, but load was not sampled at the moment those five ran, so the two
#: are consistent rather than one measurement -- and an ``Event.wait``
#: returns LATE on Windows, never early (0 of 240, ``tests/_pace_probe.py``). So the slack buys
#: nothing against a false red and costs discrimination on the one mutation class the decision arm
#: below cannot see: a wait asked for and then shortened.
_PACED_MARGIN = 0.95
#: Shortest step the schedule may be squeezed to, in seconds. Windows' timer granularity is about
#: 15.6 ms, so a shorter step stops being the thing measured. Clamping here only RAISES separation.
_STEP_FLOOR_S = 0.1
#: Longest step, in seconds. A wait that outlasts the SCU's ACSE timeout becomes an abort on the
#: sender's side -- a refusal this control is careful never to make, and one this test would then
#: misreport as the pacer refusing. It also caps the paced arm at ``_PACED_STEPS * _STEP_CEILING_S``,
#: which keeps a derived rate off the ``--timeout=60`` watchdog on a badly loaded runner. Clamping
#: here LOWERS separation, which is why ``_MIN_SEPARATION`` is checked rather than assumed.
_STEP_CEILING_S = 5.0


class _WaitRecorder(threading.Event):
    """A ``DicomScpSource._stopping`` that records every pacing wait the SCP is asked to take.

    ``_stopping.wait`` has exactly ONE caller -- the wait in ``_pace_association`` -- so what lands
    here is the pacer's decision and nothing else. The wait still happens: this records what the seam
    DECIDED without changing what the peer experiences, which is the distinction
    ``tests/_pace_probe.py`` draws for the egress pacer (BACKLOG #82). Recording rather than
    substituting is why both timing arms below can be read from one run.
    """

    def __init__(self) -> None:
        super().__init__()
        #: Driven from N concurrent pynetdicom association threads, so the list needs its own lock.
        self._lock = threading.Lock()
        self._asked: list[float] = []

    def wait(self, timeout: float | None = None) -> bool:
        if timeout is not None:
            with self._lock:
                self._asked.append(timeout)
        return super().wait(timeout)

    @property
    def asked(self) -> list[float]:
        with self._lock:
            return list(self._asked)


async def _echo_run(**settings: object) -> tuple[list[bool], float, list[float]]:
    """Open ``_ECHOES`` C-ECHO associations against one SCP; return what established, the elapsed
    seconds, and every wait the pacer asked for. Serial on purpose: the bound is on the ACCEPTANCE
    rate, so the arrivals must queue."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    src = _scp(**settings)
    # Installed before start(), which only clear()s it. An unpaced source registers no pacing handler
    # at all, so its record stays empty -- that emptiness is this recorder's own negative control.
    recorder = _WaitRecorder()
    src._stopping = recorder

    async def handler(raw: bytes) -> str | None:  # pragma: no cover - C-ECHO stores nothing
        return None

    await src.start(handler)
    port = src.sockport
    try:

        def run() -> list[bool]:
            scu = AE(ae_title="MODALITY1")
            scu.add_requested_context(Verification)
            out: list[bool] = []
            for _ in range(_ECHOES):
                assoc = scu.associate("127.0.0.1", port, ae_title=_SCP_AE)
                out.append(bool(assoc.is_established))
                if assoc.is_established:
                    assoc.release()
            return out

        start = time.monotonic()
        established = await asyncio.to_thread(run)
        return established, time.monotonic() - start, recorder.asked
    finally:
        await src.stop()


async def test_a_paced_scp_still_establishes_every_association(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """THE LOAD-BEARING DICOM TEST: pacing waits, it never refuses.

    **The timing arm runs BOTH arms, and that is a correction this test earned.** The first draft
    asserted the paced run took at least 0.15 s; its own unpaced control then measured 0.25 s for six
    loopback associations, so the threshold was satisfied by the baseline and proved nothing. A
    weaker assertion that never fails is the defect this paragraph exists to prevent, and every
    rewrite since has had to answer it.

    **The expected delay is NOT ``(N - burst) / rate``, and the second draft asserted that it was.**
    The bucket REFILLS throughout the run, so the wall time the associations take is itself paying
    down the debt; and the LAST association's token is charged after it is accepted, with nobody left
    to wait on it.

    **The third draft asserted a fixed absolute difference, ``paced - unpaced >= 0.5``, and this is
    the rewrite of that (BACKLOG #1536).** Simulating :class:`_MessagePacer` against this connector's
    call order -- ``EVT_CONN_OPEN`` waits off ``deficit()``, then ``EVT_ACCEPTED`` charges one --
    gives the schedule exactly, for per-association work ``w``::

        paced_elapsed == max(N * w, (N - 1 - capacity) / rate + 2 * w)

    **The two terms compete; they do not add**, and that is the whole defect in a difference
    assertion: as a loaded runner pushes ``N * w`` up toward the pacing floor, the difference
    collapses while both arms behave perfectly. The two arms are also timed one after the other on a
    shared runner, so they need not see the same machine at all.

    **On ``main`` the difference did not merely fall short -- on one leg it came out NEGATIVE, which
    is what rules out widening the threshold.** Run 34563466896, ``test (windows-2022, py3.14)``:
    paced 1.379 s against unpaced 1.760 s. The paced arm finished FASTER than its own control. A
    wider window admits that case too, so the test would then pass while measuring nothing; only an
    assertion that never compares the two arms' durations to each other survives it. BACKLOG #1536
    carries both legs' figures.

    **So this asserts what the pacer DECIDED before it asserts how long the box took to obey** --
    the rule ``tests/_pace_probe.py`` established for the egress pacer after the same class of flake
    ejected a pull request from the merge queue (BACKLOG #82). ``_stopping.wait`` has one caller, so
    :class:`_WaitRecorder` turns the pacing wait into a list no runner can influence, and the
    unpaced control's own record must come back EMPTY -- that pair is what catches a recorder which
    has stopped recording as well as one that over-records.

    **The wall-clock arm is kept, because the decision arm cannot see a wait that is asked for and
    not taken.** It is made runner-proof the same way the rate is: choose ``rate`` so the floor lands
    ``_SEPARATION`` times the measured control and the algebra cancels, since ``floor ==
    _SEPARATION * unpaced_elapsed`` by construction and ``paced_elapsed >= floor`` exactly, for any
    ``w``. A spuriously slow control buys a proportionally lower rate and a proportionally larger
    floor, so control noise moves both sides together. Simulated across a hundredfold swing in the
    paced arm's speed relative to the control, the ratio never fell below 4.03.

    **What must hold exactly is that all six associate in both arms** -- a bound on this plane may
    delay a modality, never turn one away.

    **The residual, stated because a threshold that hides one is worse than no threshold.** Both
    timing arms scale the schedule off the CONTROL arm's work, never the paced arm's, so a paced arm
    running several times slower per association than the control would stop discriminating: the
    bucket would refill between arrivals, fewer waits would be asked for, and the wall clock would
    clear the floor on work. That is a silent loss of power, never a false red, which is the right
    way round for a required context. The mutation arms are what keep it honest.

    **Mutation arms, measured 2026-09-11, quiet and under 24-way CPU load.** With
    ``_pace_association`` returning before it consults the bucket, and again with its
    ``EVT_CONN_OPEN`` handler never registered, the decision record comes back empty. With the wait
    HALVED rather than removed the record is still four entries and only the wall clock sees it, at
    0.86 of the floor -- which is why ``_PACED_MARGIN`` is 0.95 and not the 0.75 an earlier draft
    used, since 0.75 passes that mutation. Recorded because a test nobody watched fail is not
    evidence, and because the three do not land on the same assertion.
    """
    unpaced, unpaced_elapsed, unpaced_waits = await _echo_run()
    assert unpaced == [True] * _ECHOES, "the control arm could not associate; the fixture is broken"

    # Derived in floor-space, because both clamps are reasoned in step DURATIONS and the connector's
    # knob is a rate: stating the floor directly leaves exactly one inversion, on the line below it.
    floor = min(
        max(_SEPARATION * unpaced_elapsed, _PACED_STEPS * _STEP_FLOOR_S),
        _PACED_STEPS * _STEP_CEILING_S,
    )
    rate = _PACED_STEPS / floor
    # Checked BEFORE the paced arm is paid for, since it condemns that arm's measurement and the
    # clamp that causes it has already fired by here.
    assert floor >= unpaced_elapsed * _MIN_SEPARATION, (
        f"a control of {unpaced_elapsed:.3f}s for {_ECHOES} loopback associations clamps the "
        f"schedule at {_STEP_CEILING_S}s per step, so the floor ({floor:.3f}s) no longer separates "
        f"from it and the wall-clock arm below could be satisfied by machine speed alone. This "
        f"runner is too slow for that arm to discriminate"
    )

    paced, paced_elapsed, paced_waits = await _echo_run(
        max_associations_per_second=rate, association_burst=_PACED_BURST
    )

    # REPORTED, NOT GATED, the way tests/test_benchmark_parser.py records its scaling ratio. A green
    # that used 3 percent of its headroom and a green that used 95 percent are the same word and mean
    # opposite things: the second is a flake waiting for a contended runner and nothing in a pass/fail
    # line distinguishes them. The decision arm below is exact and needs no number; the wall-clock arm
    # does, so put its realised fraction where a CI log keeps it. Printed BEFORE the assertions so a
    # red and a green emit the same line and can be compared directly.
    with capsys.disabled():
        print(
            f"\n[BACKLOG #1536 margin] control {unpaced_elapsed:.3f}s -> {rate:.3f}/s, floor "
            f"{floor:.3f}s | paced {paced_elapsed:.3f}s = {paced_elapsed / floor:.3f}x floor "
            f"against a {_PACED_MARGIN} bound | waits {len(paced_waits)}/{int(_PACED_STEPS)}"
        )

    assert paced == [True] * _ECHOES, "pacing REFUSED an association; it may only ever wait"
    assert unpaced_waits == [], (
        f"the unpaced control asked for {len(unpaced_waits)} pacing wait(s), but it has no pacer at "
        "all -- the recorder is attributing something else's wait to the bound"
    )
    assert len(paced_waits) == int(_PACED_STEPS), (
        f"the pacer decided on {len(paced_waits)} wait(s) where the schedule says "
        f"{int(_PACED_STEPS)} at {rate:.3f}/s with a burst of {_PACED_BURST}: {paced_waits}"
    )
    assert paced_elapsed >= floor * _PACED_MARGIN, (
        f"the pacer asked for {sum(paced_waits):.3f}s of waiting but the paced arm took only "
        f"{paced_elapsed:.3f}s against a floor of {floor:.3f}s, so the waits were not taken"
    )
