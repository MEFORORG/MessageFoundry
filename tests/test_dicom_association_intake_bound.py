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
#: How many associations must actually WAIT. The bucket starts full, so the first ``capacity`` go
#: free on the initial tokens and one more goes free at a deficit of exactly zero; every later
#: arrival waits ``1 / rate``. Derived from the schedule in the test docstring, not guessed -- an
#: earlier draft guessed ``N - burst`` and was wrong by exactly this one.
_PACED_STEPS = _ECHOES - 1 - _PACED_BURST
#: How far the pacing floor is held above the MEASURED control. It sets the test's wall time (about
#: ``_SEPARATION`` times the control arm) and it sets how much slower per association the paced arm
#: would have to run, for a reason other than pacing, before the measurement stopped discriminating.
_SEPARATION = 4.0
#: Asserted at this fraction of the derived floor. The floor is an exact lower bound on the paced
#: arm in the bucket arithmetic, so this absorbs only an ``Event.wait`` that returns marginally
#: early -- it is not slack for runner speed, which the derived rate already handles.
_PACED_MARGIN = 0.8
#: Above this rate a step is under 0.1 s, close enough to the Windows timer granularity (about
#: 15.6 ms) that the schedule stops being the thing measured. Clamping here only RAISES separation.
_RATE_CEILING = 10.0
#: Below this rate a step runs over 5 s, and a wait that outlasts the SCU's ACSE timeout becomes an
#: abort on the sender's side -- a refusal this control is otherwise careful never to make, and one
#: this test would then misreport as the pacer refusing. Clamping here LOWERS separation, which is
#: why the assertion below reads the floor back from the clamped rate and checks it still separates.
#: It also caps the paced arm at ``_PACED_STEPS / _RATE_FLOOR`` seconds, which is what keeps a
#: derived rate from walking this test into the ``--timeout=60`` watchdog on a badly loaded runner.
_RATE_FLOOR = 0.2


async def _echo_run(**settings: object) -> tuple[list[bool], float]:
    """Open ``_ECHOES`` C-ECHO associations against one SCP; return what established and the elapsed
    seconds. Serial on purpose: the bound is on the ACCEPTANCE rate, so the arrivals must queue."""
    from pynetdicom import AE
    from pynetdicom.sop_class import Verification  # type: ignore[attr-defined]

    src = _scp(**settings)

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
        return established, time.monotonic() - start
    finally:
        await src.stop()


async def test_a_paced_scp_still_establishes_every_association() -> None:
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
    assertion. As a loaded runner pushes ``N * w`` up toward the pacing floor, the DIFFERENCE
    collapses while both arms behave perfectly. Measured on CI 2026-09-11 at rate 3 and burst 1:
    paced 1.373 s against unpaced 1.056 s, a difference of 0.317 against the required 0.5. The floor
    there is 1.333 s, so the paced arm matched its own schedule to three decimal places -- the
    control was the arm that had drifted, and the red named the wrong one.

    **The two arms also do not see the same machine.** They are timed one after the other on a shared
    runner. On that CI run the paced arm's own work came out near 0.02 s per association against the
    control's 0.176 s. The gap is not only noise: measured locally 2026-09-11, the control's
    associations queue back-to-back at 0.030 s each while the paced arm's arrive into an idle SCP at
    0.017 s, so a difference assertion is biased against itself even on a quiet box.

    **So the RATE is derived from the measured control, and the assertion is on the floor that rate
    implies.** Choose ``rate`` so the floor lands ``_SEPARATION`` times the control and the algebra
    cancels: ``floor == _SEPARATION * unpaced_elapsed`` by construction, and ``paced_elapsed >=
    floor`` exactly, for any ``w``. A spuriously slow control buys a proportionally lower rate and a
    proportionally larger floor, so control noise moves both sides together. Simulated across a
    hundredfold swing in the paced arm's speed relative to the control, the ratio never fell below
    4.03.

    **What must hold exactly is that all six associate in both arms** -- a bound on this plane may
    delay a modality, never turn one away.

    **The residual, stated because a threshold that hides one is worse than no threshold.** The paced
    arm could clear the floor on WORK rather than on pacing if it ran about ``_SEPARATION *
    _PACED_MARGIN`` times slower per association than the control did. That is a silent loss of
    discrimination, never a false red, which is the right way round for a required context; the
    mutation arm is what keeps it honest.

    **Mutation arm, measured 2026-09-11.** With ``_pace_association`` returning before it consults
    the bucket, the paced arm collapses onto the control and this assertion fails by more than
    threefold. Recorded because a test nobody watched fail is not evidence.
    """
    unpaced, unpaced_elapsed = await _echo_run()

    # Derived, not chosen: the floor has to scale with the machine, or the threshold is a guess about
    # the runner rather than a statement about the pacer.
    rate = min(max(_PACED_STEPS / (_SEPARATION * unpaced_elapsed), _RATE_FLOOR), _RATE_CEILING)
    floor = _PACED_STEPS / rate

    paced, paced_elapsed = await _echo_run(
        max_associations_per_second=rate, association_burst=_PACED_BURST
    )

    assert unpaced == [True] * _ECHOES, "the control arm could not associate; the fixture is broken"
    assert paced == [True] * _ECHOES, "pacing REFUSED an association; it may only ever wait"
    assert floor >= unpaced_elapsed * 2.0, (
        f"the pacing floor ({floor:.3f}s at {rate:.3f}/s) does not separate from the control "
        f"({unpaced_elapsed:.3f}s), so the assertion below could be satisfied by machine speed "
        f"alone. Either _RATE_FLOOR clamped the derived rate, which means this runner needs over "
        f"{_PACED_STEPS / _RATE_FLOOR / _SEPARATION:.1f}s for six loopback associations, or "
        "_SEPARATION was edited below 2.0"
    )
    assert paced_elapsed >= floor * _PACED_MARGIN, (
        f"pacing applied no measurable delay: paced {paced_elapsed:.3f}s against a floor of "
        f"{floor:.3f}s derived from {rate:.3f}/s, itself derived from an unpaced control of "
        f"{unpaced_elapsed:.3f}s"
    )
