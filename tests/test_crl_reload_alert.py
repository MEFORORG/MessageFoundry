# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2904: a refused CRL reload raises its own alert, ``crl_reload_refused``.

What this file proves, and the instrument for each:

* **The alert carries the file, the remedy class and the count, and no CRL contents.** A real
  reload pass over a real refused file, read through a recording sink. The control for "no CRL
  contents" is the refusal's reason from the same pass, which does quote the issuer.
* **One alert per file version, then a reminder while it stands.** The same pass run again and again
  raises nothing more until the reminder is due. A second refused version raises one more (vault
  BACKLOG #3543 added the reminder).
* **It is raised on the event loop.** A real ``NotifierAlertSink`` writes its alert-state row only
  with a running loop. The control makes the same call from a worker thread, and no row lands.
* **Its inverse, ``crl_reload_applied``, resolves it only on evidence.** Applying the file, putting
  the old bytes back, and losing every holder each resolve it once. A file that cannot be read and
  a pass that fails resolve nothing: the control is the refusal still on record. A stop resolves
  what is open.

All material is synthetic and minted by ``tests/test_crl_reload.py``. No PHI.
"""

from __future__ import annotations

import asyncio
import gc
import logging
import os
import ssl
import threading
import time
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.config import loaded_crls
from messagefoundry.config.loaded_crls import (
    ReloadRefusal,
    crl_path_key,
    record_crl_load,
    reload_refusals,
)
from messagefoundry.config.settings import _ALERT_EVENT_TYPES, AlertRule, EgressSettings
from messagefoundry.connection_names import is_connection_name
from messagefoundry.pipeline import crl_reload
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink, crl_reload_refused_detail
from messagefoundry.pipeline.crl_reload import (
    ALERT_PATH_MAX_LENGTH,
    FIX,
    RESTART,
    WAIT,
    CrlReloadRunner,
    ReloadOutcome,
    reload_alert_subject,
    reload_replaced_crls,
)
from messagefoundry.pipeline.intake_bound import (
    INTAKE_SUBJECT_MAX_LENGTH,
    process_alert_subject,
    shorten_with_checksum,
)
from messagefoundry.pki import read_soonest_crl_facts
from tests import test_crl_reload as _base
from tests._refusal_log_capture import until
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_crl_reload import _DAY, _fresher, _Pki, _refusals_logged

# The reload suite's fixtures, bound here by name so pytest finds them in this module too: an
# empty registry and pass state per test, and one CA with a leaf and a CRL file.
_fresh_registry = _base._fresh_registry
pki = _base.pki

#: The issuer every CRL of the ``pki`` fixture carries, as a refusal's reason quotes it. With the
#: ``CN=``, because the fixture's file name holds the bare common name too.
_ISSUER = "CN=mefor-299-reload-ca"


class _Sink(LoggingAlertSink):
    """Records the reload alert and its inverse. Every other event logs, so an engine can run on
    it. While ``down`` is set both calls raise, as a broken sink would."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []
        self.threads: list[str] = []
        self.down = False

    def _record(self, kind: str, name: str, payload: dict[str, Any]) -> None:
        if self.down:
            raise RuntimeError("sink down")
        self.events.append((kind, name, payload))

    def crl_reload_refused(self, name: str, **payload: Any) -> None:
        self.threads.append(threading.current_thread().name)
        self._record("refused", name, payload)

    def crl_reload_applied(self, name: str, **payload: Any) -> None:
        self._record("applied", name, payload)

    def kinds(self) -> list[str]:
        return [kind for kind, _name, _payload in self.events]

    def refused(self) -> list[dict[str, Any]]:
        return [payload for kind, _name, payload in self.events if kind == "refused"]


def _runner(sink: object, **kw: Any) -> CrlReloadRunner:
    return CrlReloadRunner(alert_sink=cast(AlertSink, sink), **kw)


def _pass(runner: CrlReloadRunner, **kw: Any) -> list[ReloadOutcome]:
    """One real pass, and the runner's report of it from what that pass saw, as ``_run`` does
    after its await."""
    view = crl_reload._PassView()
    token = crl_reload._PASS_VIEW.set(view)
    try:
        outcomes = reload_replaced_crls(**kw)
    finally:
        crl_reload._PASS_VIEW.reset(token)
    runner._report(outcomes, view)
    return outcomes


def _sighted_pass(runner: CrlReloadRunner) -> list[ReloadOutcome]:
    """One real pass through the runner's own wrapper, its report and the first-sight clear from
    what that pass saw, as ``_run`` does after its await."""
    view = crl_reload._PassView()
    outcomes = runner._judged_pass(view)
    assert isinstance(outcomes, list)
    runner._report(outcomes, view)
    runner._clear_on_first_sight(view)
    return outcomes


def _recorded() -> crl_reload._PassView:
    """The refusal record as it stands now, as a pass that judged nothing would leave it, for a
    test that writes the record itself and reports outcomes of its own."""
    view = crl_reload._PassView()
    view.take_refusals()
    return view


def _stamp_denied(_path: str) -> tuple[int, int, int]:
    """A stand-in for ``crl_reload._stamp`` on a file the engine may not read."""
    raise PermissionError(13, "Permission denied")


def _expired(pki: _Pki) -> bytes:
    return pki.crl_pem(issued=10 * _DAY, lasts=-_DAY, revoke=True)


def _not_newer(pki: _Pki) -> bytes:
    """Issued no later than the held copy, so OpenSSL would go on choosing the held one."""
    return pki.crl_pem(issued=3 * _DAY, lasts=60 * _DAY, revoke=True)


def _unproven_hop(pki: _Pki) -> ssl.SSLContext:
    """A context that holds the file's CRL but recorded no blocks, so the reload must refuse it
    rather than guess. The caller keeps it alive: the registry holds contexts weakly."""
    hop = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pem = pki.crl.read_bytes()
    record_crl_load(hop, str(pki.crl), pem, read_soonest_crl_facts(pem, now=time.time()))
    return hop


# --- the alert: the file, the remedy class, the count, and no CRL contents ----------------------


async def test_a_refused_reload_raises_the_alert_with_the_file_the_class_and_the_count(
    pki: _Pki,
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_not_newer(pki))

    (outcome,) = _pass(runner)

    assert outcome.refusal is not None and outcome.refusal.remedy == RESTART
    ((kind, name, payload),) = sink.events
    assert kind == "refused"
    assert name == reload_alert_subject(pki.crl) and name.startswith("crl_reload:")
    assert Path(payload["path"]) == pki.crl.resolve()
    assert payload == {
        "path": outcome.path,
        "remedy_class": "restart",
        "stale_contexts": 1,
        "remedy": RESTART,
        "start_refuses": False,
    }
    # No CRL contents. Control: the reason from the same pass does quote the CRL's issuer.
    assert _ISSUER in outcome.refusal.reason
    assert _ISSUER not in repr(sink.events)
    assert outcome.refusal.reason not in repr(sink.events)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF  # keeps the context alive to here


async def test_one_alert_per_file_version_for_a_verdict_the_reload_treats_as_final(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        first = _pass(runner)
        for _ in range(3):
            again = _pass(runner)
            assert again[0].refusal == first[0].refusal  # the pass still returns it every time
        assert len(sink.events) == 1, "raised once though every pass returns the refusal"
        assert sink.refused()[0]["remedy_class"] == "fix_file"

        pki.crl.write_bytes(pki.crl_pem(issued=_DAY, lasts=60 * _DAY, delta=True))
        for _ in range(3):
            _pass(runner)

    assert len(sink.events) == 2, "a second refused version raises one more"
    # Matching the log: one ERROR line per version, by the same rule.
    assert _refusals_logged(caplog) == 2
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_one_alert_for_a_refusal_the_reload_judges_again_every_pass(pki: _Pki) -> None:
    """A wait is not final: every pass judges the same bytes again and returns a fresh outcome.
    Its reason stays the same across those passes, which is what keeps this to one alert."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True))

    outcomes = [_pass(runner)[0] for _ in range(4)]

    assert all(o.refusal is not None and not o.refusal.sticky for o in outcomes)
    assert [p["remedy_class"] for p in sink.refused()] == ["wait"]
    assert sink.refused()[0]["remedy"] == WAIT
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_count_is_the_contexts_still_on_the_old_copy(pki: _Pki) -> None:
    # Two hops hold the starting copy. One recorded no blocks, so the reload refuses it and
    # brings the other current: one context reloaded, one still on the old copy.
    current = pki.outbound_hop()
    unproven = _unproven_hop(pki)
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_fresher(pki, revoke=False))

    (outcome,) = _pass(runner)

    assert (outcome.reloaded, outcome.stale) == (1, 1)
    assert sink.refused()[0]["stale_contexts"] == 1
    assert current.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF
    assert unproven.verify_mode == ssl.CERT_REQUIRED  # keeps both contexts alive to here


async def test_a_refusal_replayed_without_a_new_judgment_still_carries_the_count(
    pki: _Pki,
) -> None:
    """A verdict the reload treats as final is not judged again: later passes replay it. A runner
    that starts after the first pass meets only the replay, and its alert needs the count too."""
    hops = [pki.outbound_hop(), pki.outbound_hop()]
    pki.crl.write_bytes(_expired(pki))
    (first,) = reload_replaced_crls()
    assert first.refusal is not None and first.refusal.sticky and first.stale == 2
    sink = _Sink()

    (replayed,) = _pass(_runner(sink))

    assert replayed.refusal == first.refusal and replayed.stale == 2
    assert sink.refused()[0]["stale_contexts"] == 2
    assert all(hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF for hop in hops)


async def test_a_restart_that_a_start_would_refuse_too_says_so(pki: _Pki) -> None:
    """A context at its reload cap needs a restart. While the file is not in effect a start
    refuses it too, so the alert must not send the operator into that start."""
    capped = pki.outbound_hop()
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    assert reload_replaced_crls(max_reloads=1)[0].reloaded == 1
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=90 * _DAY, revoke=True))  # not in effect

    (outcome,) = _pass(runner, max_reloads=1)

    assert outcome.refusal is not None and outcome.refusal.remedy == RESTART
    assert "a start until then refuses this file too" in outcome.refusal.reason  # the control
    assert outcome.start_refuses
    (payload,) = sink.refused()
    assert payload["remedy_class"] == "restart" and payload["start_refuses"] is True
    detail = crl_reload_refused_detail(
        remedy_class="restart", stale_contexts=1, remedy=RESTART, start_refuses=True
    )
    # The warning comes before the remedy that names a restart: the reason column is cut short.
    assert detail.index("do not restart before then") < detail.index(RESTART)
    assert capped.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_every_remedy_has_its_own_class_token() -> None:
    tokens = [crl_reload._REMEDY_CLASS[remedy] for remedy in crl_reload._PRECEDENCE]
    assert len(set(tokens)) == len(crl_reload._PRECEDENCE) == len(crl_reload._REMEDY_CLASS)
    assert crl_reload._OTHER_REMEDY_CLASS not in tokens
    for token in tokens:
        assert token == token.lower() and " " not in token
    assert ReloadOutcome("p", 1, None).remedy_class is None
    assert ReloadOutcome("p", 0, ReloadRefusal((1, 2), "why", FIX), 1).remedy_class == "fix_file"


async def test_a_remedy_the_class_map_does_not_hold_sends_a_token_and_no_sentence(
    pki: _Pki,
) -> None:
    """No pass produces such a remedy today. If one ever did, its text must not ride the alert
    unvouched for: the class is ``other`` and the sentence is left out."""
    sink = _Sink()
    runner = _runner(sink)
    refusal = ReloadRefusal((1, 2), "a reason", "an unlisted remedy naming CN=someone")
    loaded_crls.record_reload_refusal(pki.crl, refusal)

    runner._report([ReloadOutcome(str(pki.crl), 0, refusal, 3)], _recorded())

    (payload,) = sink.refused()
    assert (payload["remedy_class"], payload["remedy"]) == ("other", "")
    assert "CN=someone" not in repr(sink.events)


# --- the runner: on the event loop, and robust to what the pass returns -------------------------


class _CountedPasses:
    """The real pass, counted, so a test can wait for whole passes and their reports."""

    def __init__(self) -> None:
        self.done = 0

    def __call__(self) -> list[ReloadOutcome]:
        try:
            return reload_replaced_crls()
        finally:
            self.done += 1

    async def more(self, passes: int = 2) -> None:
        """Wait until ``passes`` further passes have run AND been reported. A pass is counted
        when it returns, before its report, so one more pass must finish to cover the last."""
        target = self.done + passes + 1
        await until(lambda: self.done >= target, f"reload pass {target}")


async def test_the_runner_raises_on_the_event_loop_and_the_alert_store_gets_its_row(
    pki: _Pki,
) -> None:
    hop = pki.outbound_hop()
    transport, store = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, store))
    passes = _CountedPasses()
    runner = CrlReloadRunner(interval_seconds=0.01, reload=passes, alert_sink=sink)
    pki.crl.write_bytes(_not_newer(pki))

    runner.start()
    try:
        await passes.more(3)
    finally:
        await runner.stop()
    await _drain_state(sink)
    await _drain_transports(sink)

    subject = reload_alert_subject(pki.crl)
    assert len(store.upserts) == 1, "one row, though several passes returned the refusal"
    row = store.upserts[0]
    assert (row["event_type"], row["connection"]) == ("crl_reload_refused", subject)
    (event,) = transport.events
    assert row["reason"] == event["detail"]
    assert event["detail"] == crl_reload_refused_detail(
        remedy_class="restart", stale_contexts=1, remedy=RESTART
    )
    assert (event["type"], event["connection"]) == ("crl_reload_refused", subject)
    assert (event["remedy_class"], event["stale_contexts"]) == ("restart", 1)
    assert Path(event["path"]) == pki.crl.resolve()
    # The file, the class, the count and fixed words (plus the ts/severity the framework adds).
    assert set(event) == {
        "type",
        "connection",
        "path",
        "remedy_class",
        "stale_contexts",
        "detail",
        "ts",
        "severity",
    }
    assert _ISSUER not in repr(event) and _ISSUER not in repr(store.upserts)

    # The control: the same call from a worker thread, where the pass runs, writes no row. So
    # the row above proves the runner raised on the loop.
    await asyncio.to_thread(
        sink.crl_reload_refused,
        "crl_reload:control",
        path="control.pem",
        remedy_class="restart",
        stale_contexts=1,
        remedy=RESTART,
    )
    await _drain_state(sink)
    assert [r["connection"] for r in store.upserts] == [subject]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_runner_raises_from_the_loop_thread_not_the_pass_thread(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    pass_threads: list[str] = []

    def reload() -> list[ReloadOutcome]:
        pass_threads.append(threading.current_thread().name)
        return reload_replaced_crls()

    runner = CrlReloadRunner(interval_seconds=0.01, reload=reload, alert_sink=sink)
    pki.crl.write_bytes(_expired(pki))
    runner.start()
    try:
        await until(lambda: bool(sink.events), "the refused-reload alert")
    finally:
        await runner.stop()

    assert sink.threads == [threading.current_thread().name]
    assert pass_threads and threading.current_thread().name not in pass_threads
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize("returned", [None, "text", 7, [None, "x", object()], {"a": 1}])
async def test_a_pass_that_returns_no_outcomes_raises_nothing(returned: object) -> None:
    """The injected ``reload`` is typed to return anything, and two older tests return None."""
    sink = _Sink()
    _runner(sink)._report(returned, _recorded())
    assert sink.events == []


async def test_a_sink_that_raises_does_not_stop_the_runner_and_is_retried(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    sink.down = True
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        for _ in range(3):
            _pass(runner)
        failures = [r for r in caplog.records if "could not be raised" in r.getMessage()]
        assert len(failures) == 1, "one WARNING for the failing streak, not one a pass"
        assert sink.events == []
        sink.down = False
        _pass(runner)
        _pass(runner)

    assert len(sink.events) == 1, "the refused report was retried, then raised once"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_each_failing_sink_call_has_its_own_streak(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """One file's success must not restart another file's streak, and one standing failure must
    not hide a new one."""

    class _Selective(_Sink):
        def __init__(self) -> None:
            super().__init__()
            self.failing: set[tuple[str, str]] = set()

        def _record(self, kind: str, name: str, payload: dict[str, Any]) -> None:
            if (kind, name) in self.failing:
                raise RuntimeError("sink down for this call")
            super()._record(kind, name, payload)

    a, b = str(tmp_path / "a.pem"), str(tmp_path / "b.pem")
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    outcomes = [ReloadOutcome(path, 0, refusal, 1) for path in (a, b)]
    for path in (a, b):
        loaded_crls.record_reload_refusal(path, refusal)
    sink = _Selective()
    sink.failing = {("refused", reload_alert_subject(a)), ("applied", reload_alert_subject(b))}
    runner = _runner(sink)

    def warned(what: str) -> int:
        return sum(f"could not be {what}" in r.getMessage() for r in caplog.records)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        for _ in range(3):
            # A's raise fails every time; B's raise lands once.
            runner._report(outcomes, _recorded())
        assert (warned("raised"), warned("resolved")) == (1, 0)
        assert sink.kinds() == ["refused"]

        loaded_crls.clear_reload_refusal(b)  # B is cleared, and its clear now fails too
        for _ in range(3):
            runner._report(outcomes[:1], _recorded())
        assert (warned("raised"), warned("resolved")) == (1, 1)


async def test_a_pass_in_flight_at_stop_raises_nothing(pki: _Pki) -> None:
    """A refusal raised after the stop was asked for would page, and the stop would resolve it a
    moment later, for a condition the restart itself ends."""
    hop = pki.outbound_hop()
    sink = _Sink()
    returned: list[list[ReloadOutcome]] = []
    runner = _runner(sink, interval_seconds=0.01)

    def reload() -> list[ReloadOutcome]:
        runner._stop.set()  # the stop arrives while the pass runs
        returned.append(reload_replaced_crls())
        return returned[-1]

    runner._reload = reload
    pki.crl.write_bytes(_expired(pki))
    runner.start()
    await until(lambda: bool(returned), "the pass in flight")
    await runner.stop()

    assert returned[0][0].refusal is not None, "the control: the pass did refuse the file"
    assert sink.events == []
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_an_outcome_the_report_cannot_read_stops_nothing_else(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The pass is guarded, and so is each outcome of its report. One of an odd shape, from an
    injected ``reload``, must not end the loop, nor hold back the outcomes after it or the clears."""
    good, cleared = str(tmp_path / "good.pem"), str(tmp_path / "cleared.pem")
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    for path in (good, cleared):
        loaded_crls.record_reload_refusal(path, refusal)
    passes: list[int] = []
    sink = _Sink()

    def reload() -> list[ReloadOutcome]:
        passes.append(1)
        if len(passes) == 2:
            loaded_crls.clear_reload_refusal(cleared)
        return [
            ReloadOutcome(cast(Any, 123), 0, refusal, 1),  # not a path
            ReloadOutcome(good, 0, refusal, 1),
            *([ReloadOutcome(cleared, 0, refusal, 1)] if len(passes) < 2 else []),
        ]

    runner = _runner(sink, interval_seconds=0.01, reload=reload, skip_when_idle=False)
    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        runner.start()
        try:
            await until(lambda: len(passes) >= 4, "a fourth pass after three unreadable outcomes")
            assert [(kind, name) for kind, name, _ in sink.events] == [
                ("refused", reload_alert_subject(good)),
                ("refused", reload_alert_subject(cleared)),
                ("applied", reload_alert_subject(cleared)),
            ]
        finally:
            await runner.stop()
    assert any("could not report a refused file" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("idle", [False, True], ids=["after-a-pass", "idle-branch"])
async def test_a_report_that_raises_does_not_end_the_loop(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    idle: bool,
) -> None:
    """Vault BACKLOG #3543 item 6: the guard around the whole report came back. Each outcome and
    each sink call is guarded inside, but a step can still raise outside them, and that must not
    end the loop that applies revocations to running hops. Both places the loop reports from.
    After a pass, the clears read the record that pass copied, and that read fails. The idle
    branch reads no record, so there the reminder step's clock fails, with the sink down so the
    alert stays open and every interval reaches that step."""
    path = str(tmp_path / "a.pem")
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    loaded_crls.record_reload_refusal(path, refusal)
    sink = _Sink()
    passes: list[int] = []

    def reload() -> list[ReloadOutcome]:
        passes.append(1)
        return [ReloadOutcome(path, 0, refusal, 1)]

    runner = _runner(sink, interval_seconds=0.01, reload=reload, skip_when_idle=idle)
    # One open alert, so clears read the record.
    runner._report([ReloadOutcome(path, 0, refusal, 1)], _recorded())
    sink.down = idle
    reads: list[int] = []

    def broken(*_args: object) -> Any:
        reads.append(1)
        raise RuntimeError("could not be read")

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        runner.start()
        try:
            # Its own context, so leaving it undoes this patch alone and not the fixture's.
            with monkeypatch.context() as patched:
                patched.setattr(crl_reload, "_monotonic" if idle else "reload_refusals", broken)
                await until(lambda: len(reads) >= 3, "three reports that raised")
                assert runner._task is not None and not runner._task.done(), "the loop lives on"
        finally:
            await runner.stop()
    logged = [r for r in caplog.records if "step failed" in r.getMessage()]
    assert len(logged) == 1, "once per failing streak, not once a pass"
    assert bool(passes) is not idle, "the control: which branch reported"


async def test_a_streak_ends_once_its_call_is_no_longer_owed(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A raise that kept failing for a refusal since cleared is moot. Its streak must end, or
    the next failure for that file would be logged nowhere."""
    path = str(tmp_path / "a.pem")
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    outcomes = [ReloadOutcome(path, 0, refusal, 1)]
    sink = _Sink()
    sink.down = True
    runner = _runner(sink)

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        for expected in (1, 2):
            loaded_crls.record_reload_refusal(path, refusal)
            runner._report(outcomes, _recorded())
            runner._report(outcomes, _recorded())
            failures = [r for r in caplog.records if "could not be raised" in r.getMessage()]
            assert len(failures) == expected, "one WARNING per streak"
            assert crl_path_key(path) in failures[-1].getMessage(), "and it names the file"
            loaded_crls.clear_reload_refusal(path)
            # The refusal is gone, so the failed raise is no longer owed.
            runner._report([], _recorded())
    assert sink.events == []


async def test_a_clear_that_fails_at_stop_is_said_at_stop(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    """No later pass will try again, so the stop names what an operator must resolve by hand."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    sink.down = True

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        await runner.stop()
        await runner.stop()

    said = [r for r in caplog.records if "could not be resolved at stop" in r.getMessage()]
    assert len(said) == 2, "said at every stop that leaves one open, whatever streak is open"
    assert crl_path_key(pki.crl) in said[0].getMessage()
    assert sink.kinds() == ["refused"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_stop_warnings_list_of_files_survives_the_log_redaction(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Vault BACKLOG #3543 item 8, dropped on this reading. The finding: the stop's WARNING joins
    path keys with ", ", a shape the redaction pass might rewrite, unconfirmed whether the log
    filter applies it. Measured: the filter does apply it, and the join is not a shape it
    rewrites, because every key after a comma starts with a separator or, on Windows, a drive
    letter the key has folded to lower case. A path's own text can still be rewritten, as in any
    log line that names a path; this pins only the join."""
    from messagefoundry.logging_setup import RedactionFilter

    root = Path(os.path.abspath(os.sep))
    paths = [str(root / "pki" / "Acme"), str(root / "pki" / "Partner-CRL.pem")]
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    sink = _Sink()
    runner = _runner(sink)
    for path in paths:
        loaded_crls.record_reload_refusal(path, refusal)
    runner._report([ReloadOutcome(path, 0, refusal, 1) for path in paths], _recorded())
    sink.down = True

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        await runner.stop()
    (record,) = [r for r in caplog.records if "could not be resolved at stop" in r.getMessage()]
    joined = ", ".join(sorted(crl_path_key(path) for path in paths))
    assert joined in record.getMessage()
    assert RedactionFilter().filter(record)
    assert joined in record.getMessage(), "the filter left the list as it was"
    # The control: the same filter does rewrite a name run, so it ran on this record.
    control = logging.LogRecord("x", logging.WARNING, __file__, 1, "%s", ("Doe, Jane",), None)
    RedactionFilter().filter(control)
    assert "Jane" not in control.getMessage()


async def test_a_refusal_after_a_clear_is_not_held_back_by_the_cooldown() -> None:
    """A refusal the notifier throttled would wait for the runner's next reminder. So the clear
    must end the cooldown, and the refusal after it pages at once."""
    transport = _RecordingTransport("webhook")
    sink = NotifierAlertSink([transport])  # the default cooldown, far longer than this test

    def refuse(name: str) -> None:
        sink.crl_reload_refused(
            name, path="a.pem", remedy_class="fix_file", stale_contexts=1, remedy=FIX
        )

    refuse("crl_reload:fixed-between")
    sink.crl_reload_applied("crl_reload:fixed-between", path="a.pem")
    refuse("crl_reload:fixed-between")
    # The control: with no clear between them, the second raise is throttled.
    refuse("crl_reload:still-open")
    refuse("crl_reload:still-open")
    await _drain_transports(sink)

    paged = [e["connection"] for e in transport.events]
    assert paged.count("crl_reload:fixed-between") == 2
    assert paged.count("crl_reload:still-open") == 1


async def test_the_same_bytes_refused_again_after_a_fix_alert_again(pki: _Pki) -> None:
    """Matching the log: a refusal that was cleared and then recurs is a new refusal."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    bad = _expired(pki)
    pki.crl.write_bytes(bad)
    _pass(runner)
    assert crl_path_key(pki.crl) in reload_refusals()

    pki.crl.write_bytes(_fresher(pki, revoke=False))
    (fixed,) = _pass(runner)
    assert fixed.refusal is None and crl_path_key(pki.crl) not in reload_refusals()
    pki.crl.write_bytes(bad)
    _pass(runner)

    assert [p["remedy_class"] for p in sink.refused()] == ["fix_file", "fix_file"]
    assert sink.kinds() == ["refused", "applied", "refused"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- the reminder while a refusal stands (vault BACKLOG #3543 item 1) ----------------------------


class _Clock:
    """The runner's reminder clock, moved by hand."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    moved = _Clock()
    monkeypatch.setattr(crl_reload, "_monotonic", moved)
    return moved


async def test_a_reminder_fires_while_the_refusal_stands_and_stops_once_it_clears(
    pki: _Pki, clock: _Clock
) -> None:
    """The owner ruling of 2026-10-13: a periodic reminder while the refusal stands, as
    ``intake_paused`` has. It repeats the version raised, with its payload, and no more often
    than ``reminder_seconds``."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(_expired(pki))

    _pass(runner)
    clock.now += 299
    _pass(runner)
    assert len(sink.refused()) == 1, "not before it is due"
    clock.now += 1
    _pass(runner)
    _pass(runner)
    first, reminder = sink.refused()
    assert reminder == first, "one reminder, with the payload of the version raised"
    assert sink.events[0][1] == sink.events[1][1] == reload_alert_subject(pki.crl)
    clock.now += 300
    _pass(runner)
    assert len(sink.refused()) == 3

    pki.crl.write_bytes(_fresher(pki, revoke=False))
    _pass(runner)
    clock.now += 900
    _pass(runner)
    assert sink.kinds() == ["refused", "refused", "refused", "applied"], "none once it clears"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_reminder_follows_the_record_when_the_pass_cannot_read_the_file(
    pki: _Pki, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pass returns no outcome for a file it cannot read, while the refusal still stands. The
    reminder reads the record, so it still fires."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)

    monkeypatch.setattr(crl_reload, "_stamp", _stamp_denied)
    clock.now += 300
    assert _pass(runner) == [], "the control: no outcome at all"
    assert len(sink.refused()) == 2
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_refusal_judged_every_pass_is_not_reminded_about_unjudged(
    pki: _Pki, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A wait names a time, which may pass while the file cannot be read. So unlike a final
    verdict, it is reminded about only once a pass has judged it again."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True))
    (waiting,) = _pass(runner)
    assert waiting.refusal is not None and not waiting.refusal.sticky  # the premise

    with monkeypatch.context() as patched:
        patched.setattr(crl_reload, "_stamp", _stamp_denied)
        clock.now += 900
        _pass(runner)
        _pass(runner)
        assert len(sink.refused()) == 1, "no reminder from a verdict nobody judged again"
    _pass(runner)
    assert [p["remedy_class"] for p in sink.refused()] == ["wait", "wait"], "judged, reminded"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_refusal_judged_every_pass_is_reminded_about_only_from_the_pass_just_run(
    pki: _Pki, clock: _Clock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3543, review finding 1. A judgment from an earlier pass is not enough: the
    file may have become unreadable since, and the wait it named may have passed. Here a pass
    judges the refusal again before the reminder is due, the file then becomes unreadable, and
    the reminder falls due at a pass that judged nothing."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True))
    (waiting,) = _pass(runner)
    assert waiting.refusal is not None and not waiting.refusal.sticky  # the premise
    clock.now += 60
    assert _pass(runner), "a pass that judged the same version again, before the reminder"

    with monkeypatch.context() as patched:
        patched.setattr(crl_reload, "_stamp", _stamp_denied)
        clock.now += 240
        assert _pass(runner) == [], "the reminder falls due at a pass that judged nothing"
        assert len(sink.refused()) == 1, "no reminder from an earlier pass's judgment"
    _pass(runner)
    assert [p["remedy_class"] for p in sink.refused()] == ["wait", "wait"], "judged, reminded"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_reminder_the_sink_refuses_waits_for_the_next_reminder(
    pki: _Pki, clock: _Clock, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    sink.down = True

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        clock.now += 300
        for _ in range(3):
            _pass(runner)
        sink.down = False
        _pass(runner)
        assert len(sink.refused()) == 1, "spaced from the attempt, not retried every pass"
        clock.now += 300
        _pass(runner)
    assert len(sink.refused()) == 2
    failures = [r.getMessage() for r in caplog.records if "as a reminder" in r.getMessage()]
    assert len(failures) == 1 and "the next reminder tries again" in failures[0]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_notifier_pages_the_reminder_once_its_cooldown_has_passed(
    pki: _Pki, clock: _Clock
) -> None:
    """What the reminder is for: a page sent again while the refusal stands. The notifier's own
    cooldown still spaces it, so it is set to zero here."""
    hop = pki.outbound_hop()
    transport = _RecordingTransport("webhook")
    sink = NotifierAlertSink([transport], realert_seconds=0)
    runner = _runner(sink, reminder_seconds=300)
    pki.crl.write_bytes(_expired(pki))

    _pass(runner)
    _pass(runner)
    clock.now += 300
    _pass(runner)
    await _drain_transports(sink)

    paged = [(e["type"], e["connection"], e["remedy_class"]) for e in transport.events]
    assert paged == [("crl_reload_refused", reload_alert_subject(pki.crl), "fix_file")] * 2
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


# --- the inverse: resolved when the file is applied or the refusal is cleared -------------------


@pytest.mark.parametrize("node", [None, "shard:a"])
async def test_applying_the_file_resolves_the_alert_once(pki: _Pki, node: str | None) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink, node=node)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    _pass(runner)
    assert sink.kinds() == ["refused"]

    pki.crl.write_bytes(_fresher(pki, revoke=False))
    (applied,) = _pass(runner)
    for _ in range(3):
        _pass(runner)

    assert (applied.reloaded, applied.refusal) == (1, None)
    assert sink.kinds() == ["refused", "applied"], "resolved once, and not again"
    (_, raised_as, _), (_, cleared_as, cleared) = sink.events
    # The clear names the instance the raise opened, and this process's alone.
    assert raised_as == cleared_as == reload_alert_subject(pki.crl, node)
    assert cleared_as != reload_alert_subject(pki.crl, "shard:b")
    assert Path(cleared["path"]) == pki.crl.resolve()
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_putting_the_old_bytes_back_resolves_the_alert(pki: _Pki) -> None:
    """The refusal is cleared without any reload: every hop holds the file's bytes again."""
    hop = pki.outbound_hop()
    original = pki.crl.read_bytes()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)

    pki.crl.write_bytes(original)

    assert _pass(runner) == [], "the pass has nothing to do, so it returns no outcome"
    assert sink.kinds() == ["refused", "applied"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_alert_stays_while_any_context_is_on_the_old_copy(pki: _Pki) -> None:
    current = pki.outbound_hop()
    unproven = _unproven_hop(pki)
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_fresher(pki, revoke=False))

    for _ in range(3):
        _pass(runner)
    assert sink.kinds() == ["refused"], "one hop took the file, and the other still has not"

    del unproven
    gc.collect()
    _pass(runner)

    assert sink.kinds() == ["refused", "applied"]
    assert current.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_alert_resolves_once_no_hop_holds_the_file(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    assert sink.kinds() == ["refused"]

    del hop
    gc.collect()
    _pass(runner)

    assert sink.kinds() == ["refused", "applied"]


@pytest.mark.parametrize("busy", [False, True], ids=["the-lock-free", "the-lock-busy"])
async def test_the_idle_runner_resolves_an_alert_for_a_file_no_hop_holds(
    pki: _Pki, busy: bool
) -> None:
    """With no CRL load recorded the runner starts no pass, so the idle branch must resolve. It
    does so also while a pass an earlier runner's stop abandoned holds the lock, and this runner
    has run no pass of its own: nothing stands either way. Only the free lock prunes the record."""
    sink = _Sink()
    passes: list[int] = []
    # A stand-in pass that touches no record, so only the idle branch can clear the refusal.
    runner = CrlReloadRunner(
        interval_seconds=0.01, reload=lambda: passes.append(1), alert_sink=sink
    )
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    loaded_crls.record_reload_refusal(pki.crl, refusal)
    runner._report([ReloadOutcome(str(pki.crl), 0, refusal, 1)], _recorded())
    assert sink.kinds() == ["refused"] and not loaded_crls.has_held_copies()
    abandoned = _AbandonedPass()
    if busy:
        abandoned.start()
    try:
        runner.start()
        try:
            # Before the stop, which resolves too.
            await until(lambda: "applied" in sink.kinds(), "the idle branch's clear")
            assert sink.kinds() == ["refused", "applied"]
            assert passes == [], "no pass ran: the idle branch resolved it"
            assert crl_reload._PASS_LOCK.locked() is busy, "the premise"
            assert (reload_refusals() == {}) is not busy, "pruned only once the lock was free"
        finally:
            await runner.stop()
    finally:
        abandoned.release()
    assert sink.kinds() == ["refused", "applied"]


class _AbandonedPass:
    """Holds the pass lock from a thread of its own, as a pass an earlier runner's stop abandoned
    does, until released. A loop that waited on the lock would then stall for the timeout and fail
    the test, not deadlock on a lock its own thread holds."""

    def __init__(self) -> None:
        self.held = threading.Event()
        self._release = threading.Event()
        self._thread = threading.Thread(target=self._hold, name="abandoned-pass")

    def _hold(self) -> None:
        with crl_reload._PASS_LOCK:
            self.held.set()
            # Long enough that it never lets go before a test releases it, even on a slow runner.
            self._release.wait(60)

    def start(self) -> None:
        self._thread.start()
        assert self.held.wait(5), "the premise: the abandoned pass holds the lock"

    def release(self) -> None:
        self._release.set()
        if self._thread.ident is not None:
            self._thread.join(10)


def _idle_after_one_pass(
    passes: list[int], abandoned: _AbandonedPass | None, clock: _Clock
) -> Callable[[], bool]:
    """A stand-in for ``has_held_copies``: a hop holds a CRL until the runner's first pass, and
    none after it. At the first idle interval, before the branch runs, the reminder clock moves
    past the reminder of a refusal raised at that pass, and ``abandoned``, if given, takes the
    lock."""
    started = False

    def held_copies() -> bool:
        nonlocal started
        if not passes:
            return True
        if not started:
            started = True
            if abandoned is not None:
                abandoned.start()
            clock.now += 300
        return False

    return held_copies


def _count_calls(patched: pytest.MonkeyPatch, name: str) -> list[int]:
    """Count the calls of ``crl_reload``'s ``name``, one entry each. For ``_forget_all``, that is
    one per idle interval."""
    calls: list[int] = []
    real = getattr(crl_reload, name)

    def counted(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        return real(*args, **kwargs)

    patched.setattr(crl_reload, name, counted)
    return calls


class _ClearRefusedOnce(_Sink):
    """A sink whose first ``crl_reload_applied`` raises, so that clear is owed and retried."""

    def __init__(self) -> None:
        super().__init__()
        self.clears_refused = 0

    def _record(self, kind: str, name: str, payload: dict[str, Any]) -> None:
        if kind == "applied" and not self.clears_refused:
            self.clears_refused += 1
            raise RuntimeError("sink down for the first clear")
        super()._record(kind, name, payload)


@pytest.mark.parametrize("busy", [True, False], ids=["the-lock-busy", "the-lock-free"])
async def test_while_no_hop_holds_a_crl_nothing_stands_whoever_holds_the_lock(
    pki: _Pki,
    clock: _Clock,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    busy: bool,
) -> None:
    """Vault BACKLOG #3543. While no hop holds any CRL no refusal stands, so the idle branch
    sends no reminder and resolves every alert still open. While a pass an earlier runner's stop
    abandoned holds the lock, the branch decides the same: the free lock is the control that both
    paths agree. The sink refuses the first clear, so that clear is owed, and a later idle
    interval retries it."""
    sink = _ClearRefusedOnce()
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    passes: list[int] = []
    abandoned = _AbandonedPass() if busy else None

    def reload() -> list[ReloadOutcome]:
        passes.append(1)
        loaded_crls.record_reload_refusal(pki.crl, refusal)
        return [ReloadOutcome(str(pki.crl), 0, refusal, 1)]

    reads = _count_calls(monkeypatch, "reload_refusals")
    monkeypatch.setattr(
        crl_reload, "has_held_copies", _idle_after_one_pass(passes, abandoned, clock)
    )
    runner = _runner(sink, interval_seconds=0.01, reload=reload, reminder_seconds=300)
    ticks = _count_calls(monkeypatch, "_forget_all")
    caplog.set_level(logging.INFO, logger="messagefoundry.pipeline.crl_reload")
    runner.start()
    try:
        await until(lambda: len(ticks) >= 3, "three idle intervals")
        assert len(sink.refused()) == 1, "no reminder: nothing stands"
        assert sink.clears_refused == 1 and sink.kinds() == ["refused", "applied"], (
            "the clear the sink refused is retried, and lands"
        )
        assert not runner._alerted
        assert reads == [1], (
            "crl_reload's reload_refusals ran for the pass alone, not the idle branch"
        )
        if abandoned is not None:
            assert crl_reload._PASS_LOCK.locked(), "the premise: decided while the lock was held"
    finally:
        if abandoned is not None:
            abandoned.release()
        await runner.stop()
    assert passes == [1] and sink.kinds() == ["refused", "applied"]
    resolved = [r.getMessage() for r in caplog.records if "is resolved" in r.getMessage()]
    assert resolved and all(m.endswith(": no hop holds any CRL") for m in resolved), resolved


async def test_the_idle_runner_runs_no_first_sight_clear(
    pki: _Pki, clock: _Clock, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A first-sight clear needs the judgment of a pass the loop has just run, and the idle
    branch runs none. Here the pass judged a file and raised, so it ran none either, and the file
    is still unseen. The idle branch resolves the alert it has open, the control that it ran, and
    sends nothing for the judged file. The lock is busy and then free, the two ways the idle
    branch was ever reached, though neither changes what it decides."""
    sink = _Sink()
    refusal = ReloadRefusal((1, 2), "why", RESTART)
    judged = str(tmp_path / "judged.pem")
    passes: list[int] = []
    abandoned = _AbandonedPass()

    def reload() -> None:
        passes.append(1)
        view = crl_reload._PASS_VIEW.get()
        assert view is not None
        view.judged[crl_path_key(judged)] = judged
        # A pass that raised runs no first-sight clear, so the judged file is still unseen.
        raise RuntimeError("the pass failed after judging a file")

    monkeypatch.setattr(
        crl_reload, "has_held_copies", _idle_after_one_pass(passes, abandoned, clock)
    )
    runner = _runner(sink, interval_seconds=0.01, reload=reload, reminder_seconds=300)
    loaded_crls.record_reload_refusal(pki.crl, refusal)
    runner._report([ReloadOutcome(str(pki.crl), 0, refusal, 1)], _recorded())
    ticks = _count_calls(monkeypatch, "_forget_all")
    subject = reload_alert_subject(pki.crl)
    expected = [("refused", subject), ("applied", subject)]
    runner.start()
    try:
        await until(lambda: len(ticks) >= 3, "three idle intervals")
        assert crl_reload._PASS_LOCK.locked(), "the premise: decided while the lock was held"
        assert [(kind, name) for kind, name, _ in sink.events] == expected, (
            "no clear for the file the pass judged"
        )
        abandoned.release()
        freed_at = len(ticks)
        await until(lambda: len(ticks) >= freed_at + 3, "three idle intervals with the lock free")
    finally:
        abandoned.release()
        await runner.stop()
    assert [(kind, name) for kind, name, _ in sink.events] == expected, (
        "the judged file was never cleared"
    )
    assert passes == [1]


@pytest.mark.parametrize("final", [True, False], ids=["a-final-verdict", "a-retried-verdict"])
async def test_a_file_the_pass_cannot_read_resolves_nothing(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, final: bool
) -> None:
    """A pass returns no outcome for a file it cannot stat or read. The refusal still stands, so
    the missing outcome must not read as a clear."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    future = pki.crl_pem(issued=-_DAY, lasts=60 * _DAY, revoke=True)
    pki.crl.write_bytes(_expired(pki) if final else future)
    (refused,) = _pass(runner)
    assert refused.refusal is not None and refused.refusal.sticky is final

    with monkeypatch.context() as patched:
        patched.setattr(crl_reload, "_stamp", _stamp_denied)
        for _ in range(3):
            assert _pass(runner) == [], "no outcome at all for the unreadable file"
        # The control: the refusal is still on record, which is what the runner reads.
        assert crl_path_key(pki.crl) in reload_refusals()
        assert sink.kinds() == ["refused"]

    pki.crl.write_bytes(_fresher(pki, revoke=False))
    _pass(runner)
    assert sink.kinds() == ["refused", "applied"], "and a real clear still resolves it"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_pass_that_fails_resolves_nothing(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)

    def boom(*_args: object) -> None:
        raise RuntimeError("the triage failed")

    with monkeypatch.context() as patched:
        patched.setattr(crl_reload, "_triage", boom)
        assert _pass(runner) == [], "a failure on the file is logged and returns no outcome"
        runner._report(None, _recorded())  # what _run reports when the whole pass raised
        assert crl_path_key(pki.crl) in reload_refusals()
        assert sink.kinds() == ["refused"]

    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_stop_resolves_what_is_still_open_and_pages_nobody(pki: _Pki) -> None:
    """A restart rebuilds every context from the file, so nothing later would clear the alert."""
    hop = pki.outbound_hop()
    transport, store = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, store))
    passes = _CountedPasses()
    runner = CrlReloadRunner(interval_seconds=0.01, reload=passes, alert_sink=sink)
    pki.crl.write_bytes(_not_newer(pki))
    runner.start()
    try:
        await passes.more(2)
        await _drain_state(sink)
        assert len(store.upserts) == 1 and store.resolves == [], "open while the runner runs"
    finally:
        await runner.stop()
    await runner.stop()  # idempotent: nothing is left to resolve
    await _drain_state(sink)
    await _drain_transports(sink)

    subject = reload_alert_subject(pki.crl)
    assert store.resolves == [{"event_type": "crl_reload_refused", "connection": subject}]
    assert [e["type"] for e in transport.events] == ["crl_reload_refused"], "a clear needs no page"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_an_alert_a_dead_process_left_open_is_resolved_once_by_the_next_run(
    pki: _Pki,
) -> None:
    """Vault BACKLOG #3543 item 3. Open alerts lived only in runner memory, so a process killed
    with one open left it open, false, with nothing to clear it. The next run of that process
    holds the file afresh and refuses nothing, so its loop resolves the subject, once, and pages
    nobody."""
    hop = pki.outbound_hop()  # built from the file as it is: nothing to refuse
    transport, store = _RecordingTransport("webhook"), _RecordingStore()
    sink = NotifierAlertSink([transport], store=cast(Any, store))
    passes = _CountedPasses()
    runner = CrlReloadRunner(interval_seconds=0.01, reload=passes, alert_sink=sink, node="node:a")
    runner.start()
    try:
        await passes.more(3)
    finally:
        await runner.stop()
    await _drain_state(sink)
    await _drain_transports(sink)

    subject = reload_alert_subject(pki.crl, "node:a")
    assert store.resolves == [{"event_type": "crl_reload_refused", "connection": subject}]
    assert store.upserts == [] and transport.events == []
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_first_sight_clear_leaves_this_runners_own_refusal_open(pki: _Pki) -> None:
    """The control for the test above: a file this run refuses is not cleared at first sight.
    Its own alert stays open until its refusal ends, or the stop."""
    hop = pki.outbound_hop()
    sink = _Sink()
    passes = _CountedPasses()
    runner = CrlReloadRunner(interval_seconds=0.01, reload=passes, alert_sink=sink)
    pki.crl.write_bytes(_expired(pki))
    runner.start()
    try:
        await passes.more(3)
        assert sink.kinds() == ["refused"]
    finally:
        await runner.stop()
    assert sink.kinds() == ["refused", "applied"], "the stop's clear, and no other"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_first_sight_clear_the_sink_refuses_is_retried(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    sink.down = True
    runner = _runner(sink)
    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.crl_reload"):
        for _ in range(3):
            _sighted_pass(runner)  # each pass's report retries the clear
        sink.down = False
        _sighted_pass(runner)
        _sighted_pass(runner)
    assert sink.kinds() == ["applied"], "retried, then sent once, and the file judged once"
    failures = [r for r in caplog.records if "could not send the clear" in r.getMessage()]
    assert len(failures) == 1, "one line for the streak"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_first_sight_clear_that_fails_says_there_may_be_no_alert(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3543, review finding 6. The clear for an earlier run goes for every held
    file, so most resolve nothing. A failed one logged as a refused-reload alert that could not
    be resolved, a WARNING per file, would send an operator after refusals that never existed.
    So it is said as what it is, at INFO. The stop's WARNING still names what is left owed."""
    hop = pki.outbound_hop()
    sink = _Sink()
    sink.down = True
    passes = _CountedPasses()
    runner = _runner(sink, interval_seconds=0.01, reload=passes)
    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.crl_reload"):
        runner.start()
        try:
            await passes.more(3)
        finally:
            await runner.stop()

    key = crl_path_key(pki.crl)
    (said,) = [r for r in caplog.records if "could not send the clear" in r.getMessage()]
    assert said.levelno == logging.INFO and key in said.getMessage()
    assert "there may be no such alert" in said.getMessage()
    assert not [r for r in caplog.records if "could not be resolved;" in r.getMessage()]
    # The control: the sink did refuse every clear, and the stop says so.
    assert sink.events == []
    assert any("could not be resolved at stop" in r.getMessage() for r in caplog.records)
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_first_sight_clear_waits_for_a_pass_that_judged_the_file(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only on evidence, as every other clear: a pass that failed on the file, or could not
    read it, says nothing about whether a refusal would stand, so it clears nothing."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)

    def boom(*_args: object) -> None:
        raise RuntimeError("the triage failed")

    for name, broken in (("_triage", boom), ("_stamp", _stamp_denied)):
        with monkeypatch.context() as patched:
            patched.setattr(crl_reload, name, broken)
            assert _sighted_pass(runner) == []
            assert sink.events == [], f"no clear while {name} fails"
    _sighted_pass(runner)
    assert sink.kinds() == ["applied"], "the control: a pass that judged it clears"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_the_first_sight_clear_skips_a_file_held_only_after_the_pass_judged(
    pki: _Pki, tmp_path: Path
) -> None:
    """Vault BACKLOG #3543, review finding 2. A hop can begin to hold a CRL file while a pass
    runs, such as a config reload building one. No pass has judged that file, so the clear must
    wait for one that does. It used to read every held file, and so cleared one that no pass had
    judged, which could resolve an open refusal alert with no evidence."""
    hop = pki.outbound_hop()
    other = tmp_path / "other-crl.pem"
    other.write_bytes(pki.crl.read_bytes())
    late: list[ssl.SSLContext] = []
    before_second: list[list[str]] = []
    sink = _Sink()

    def reload() -> list[ReloadOutcome]:
        if late and not before_second:
            # The loop awaits this pass, so the events are what the first pass's report sent.
            before_second.append([name for _kind, name, _payload in sink.events])
        outcomes = reload_replaced_crls()
        if not late:
            late.append(replace(pki, crl=other).outbound_hop())  # held once the pass judged
        return outcomes

    runner = _runner(sink, interval_seconds=0.01, reload=reload)
    runner.start()
    try:
        await until(lambda: len(sink.events) >= 2, "a clear for each file")
    finally:
        await runner.stop()

    assert before_second == [[reload_alert_subject(pki.crl)]], "only the file the pass judged"
    # The control: the next pass judged the other file, and cleared it then.
    assert sorted(name for _kind, name, _payload in sink.events) == sorted(
        [reload_alert_subject(pki.crl), reload_alert_subject(other)]
    )
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF and late


async def test_the_first_sight_clear_reads_what_its_own_pass_judged(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3543, review finding 4. The pass state is touched only under the pass lock,
    and a pass an earlier runner's stop abandoned may still be changing it. So the clear reads
    what its own pass judged, handed back from the worker thread, and never that state. Here the
    pass cannot read the file, and the state then changes under the loop as such a pass would
    change it: the clear must still see a pass that judged nothing."""
    hop = pki.outbound_hop()
    key = crl_path_key(pki.crl)
    monkeypatch.setattr(crl_reload, "_stamp", _stamp_denied)
    unread: list[bool] = []
    sink = _Sink()

    def reload() -> list[ReloadOutcome]:
        outcomes = reload_replaced_crls()
        unread.append(key in crl_reload._UNREADABLE)
        crl_reload._UNREADABLE.discard(key)  # another pass's write, after this one returned
        return outcomes

    runner = _runner(sink, interval_seconds=0.01, reload=reload)
    runner.start()
    try:
        await until(lambda: len(unread) >= 3, "three passes that could not read the file")
    finally:
        await runner.stop()

    assert all(unread), "the premise: each pass found the file unreadable"
    assert sink.events == []
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


class _PassAborted(BaseException):
    """Ends a whole pass: the pass guards each file against an ``Exception`` only."""


@pytest.mark.parametrize("fails", [False, True], ids=["a-pass-that-returns", "a-pass-that-raises"])
def test_the_real_pass_copies_the_record_before_it_releases_the_lock(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, fails: bool
) -> None:
    """The copy is taken in the same hold of the pass lock as the pass's own writes, so no other
    pass can write between them, and also when the pass raises: what it recorded stands."""
    hop = pki.outbound_hop()
    pki.crl.write_bytes(_expired(pki))
    copied_locked: list[bool] = []
    real_read = loaded_crls.reload_refusals

    def read() -> dict[str, ReloadRefusal]:
        copied_locked.append(crl_reload._PASS_LOCK.locked())
        return real_read()

    monkeypatch.setattr(crl_reload, "reload_refusals", read)
    if fails:
        real_finish = crl_reload._finish

        def finish_then_fail(*args: Any) -> ReloadOutcome:
            real_finish(*args)  # records the refusal
            raise _PassAborted("the pass fails after recording")

        # Not an Exception, so the per-file guard lets it end the whole pass.
        monkeypatch.setattr(crl_reload, "_finish", finish_then_fail)
    view = crl_reload._PassView()
    token = crl_reload._PASS_VIEW.set(view)
    try:
        if fails:
            with pytest.raises(_PassAborted):
                reload_replaced_crls()
        else:
            reload_replaced_crls()
    finally:
        crl_reload._PASS_VIEW.reset(token)

    assert copied_locked == [True], "one copy, taken while the pass still held the lock"
    assert crl_path_key(pki.crl) in view.refusals(), "the refusal the pass recorded"
    assert (crl_path_key(pki.crl) in view.judged) is not fails, (
        "judged only by a pass that returned"
    )
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


class _RaiseDown(_Sink):
    """A sink whose ``crl_reload_refused`` raises and whose inverse lands, so a refusal stays
    unalerted and only the first-sight clear could resolve its subject."""

    def _record(self, kind: str, name: str, payload: dict[str, Any]) -> None:
        if kind == "refused":
            raise RuntimeError("sink down for the raise")
        super()._record(kind, name, payload)


class _CountedCollect:
    """The ``gc`` module as :mod:`crl_reload` sees it, with ``collect`` counted and not run."""

    def __init__(self) -> None:
        self.calls: list[int] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(gc, name)

    def collect(self, generation: int = 2) -> int:
        if generation not in (0, 1, 2):
            raise ValueError("invalid generation")
        self.calls.append(generation)
        return 0


@pytest.mark.parametrize("raise_lands", [True, False], ids=["follow-the-record", "first-sight"])
async def test_the_loop_decides_from_the_refusal_record_its_own_pass_left(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, raise_lands: bool
) -> None:
    """Vault BACKLOG #3543, review of 585270cd3. Every write to the refusal record is made under
    the pass lock, and a pass an earlier runner's stop abandoned may still be making one. So the
    loop decides from the record as its own pass left it, read under that lock in the worker
    thread, and never from the live record. Here each pass refuses the file, and the refusal is
    then cleared under the loop, after the pass returned, as such a pass would clear it.

    With the raise landing, following the record must not resolve the alert just raised. With
    the raise failing, the refusal has no alert of this runner's, and the first-sight clear must
    not resolve its subject."""
    hop = pki.outbound_hop()
    sink = _Sink() if raise_lands else _RaiseDown()
    refused: list[bool] = []

    def reload() -> list[ReloadOutcome]:
        outcomes = reload_replaced_crls()
        refused.append(crl_path_key(pki.crl) in reload_refusals())
        loaded_crls.clear_reload_refusal(pki.crl)  # another pass's write, after this one returned
        return outcomes

    runner = _runner(sink, interval_seconds=0.01, reload=reload)
    pki.crl.write_bytes(_expired(pki))
    # While a cleared record makes the pass's collect gate fire, every pass here would run a full
    # gc.collect(), whose cost grows with the heap the suite has built up: in a worker that has
    # run many files, four passes may not fit the wait. The hop is held strongly, so the collect
    # decides nothing this test asserts; the pass calls a counter instead. Not gc.freeze(): that
    # is process-wide, and pre-freeze garbage would outlive this test into a later one.
    collects = _CountedCollect()
    monkeypatch.setattr(crl_reload, "gc", collects)
    runner.start()
    try:
        await until(lambda: len(refused) >= 4, "four passes that refused the file")
        # Before the stop, which resolves whatever is still open.
        kinds = sink.kinds()
    finally:
        await runner.stop()

    assert all(refused), "the premise: each pass refused the file and recorded the refusal"
    # The first pass reads new bytes, so it collects whatever the gate does on a cleared record.
    assert collects.calls, "the control: the pass's collect reached the stand-in"
    assert sink.threads, "the control: the runner tried to raise the refusal"
    assert kinds == (["refused"] if raise_lands else [])
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_an_unreadable_pass_does_not_end_a_failing_streak(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3543, review finding 3. A failure on one file is logged with its traceback
    once per streak. A pass that cannot read the file judges nothing, so it must not end the
    streak, or the same failure is logged again at the next pass."""
    hop = pki.outbound_hop()
    real_triage = crl_reload._triage
    failing = [True]

    def triage(key: str, pairs: Any) -> object:
        if failing[0]:
            raise RuntimeError("the triage failed")
        return real_triage(key, pairs)

    monkeypatch.setattr(crl_reload, "_triage", triage)

    def logged() -> int:
        return sum("could not check" in r.getMessage() for r in caplog.records)

    with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.crl_reload"):
        reload_replaced_crls()
        failing[0] = False
        with monkeypatch.context() as patched:
            patched.setattr(crl_reload, "_stamp", _stamp_denied)
            reload_replaced_crls()
        failing[0] = True
        reload_replaced_crls()
        assert logged() == 1, "one traceback for the streak, across a pass that read nothing"
        # The control: a pass that judges the file does end it.
        failing[0] = False
        reload_replaced_crls()
        failing[0] = True
        reload_replaced_crls()
        assert logged() == 2
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_file_the_reload_cannot_read_is_not_judged_at_first_sight(
    pki: _Pki, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #3543: the guard for the reload's own ``_Unread.UNREAD`` return, which the
    fixes for review findings 2 and 3 added. The code before them passes this too, through its
    ``_UNREADABLE`` check, so it pins the new return, not those findings. With its stamp unchanged
    since the triage last read it, the triage hands the reload no bytes, and the reload reads
    them. A file that still stats but cannot be read there judged nothing, so it must not clear
    an earlier run's alert. Here no refusal stands, because the reload before it failed, so only
    that rule holds the clear back."""
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_fresher(pki, revoke=False))

    def boom(*_args: object) -> None:
        raise RuntimeError("the reload failed")

    with monkeypatch.context() as patched:
        patched.setattr(crl_reload, "_reload_path", boom)
        assert _sighted_pass(runner) == []  # the triage read the bytes; the reload failed
    assert reload_refusals() == {}, "the premise: no refusal stands"

    def denied(_self: Path) -> bytes:
        raise PermissionError(13, "Permission denied")

    with monkeypatch.context() as patched:
        patched.setattr(Path, "read_bytes", denied)
        assert _sighted_pass(runner) == []
        assert crl_path_key(pki.crl) in crl_reload._UNREADABLE, "the reload's own read failed"
    assert sink.events == [] and runner._seen_held == set()

    (applied,) = _sighted_pass(runner)  # the control: a pass that reads it judges it
    assert applied.reloaded == 1 and sink.kinds() == ["applied"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_refused_file_whose_raise_failed_is_judged_again_at_first_sight(
    pki: _Pki,
) -> None:
    """A file refused at first sight whose own raise failed has no alert of this run to clear
    the subject. If the refusal ends before a raise lands, the first-sight clear must still
    reach it, so the file is not counted as judged yet."""
    hop = pki.outbound_hop()
    original = pki.crl.read_bytes()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    sink.down = True
    _sighted_pass(runner)
    assert sink.events == [] and crl_path_key(pki.crl) not in runner._seen_held

    sink.down = False
    pki.crl.write_bytes(original)  # the refusal ends before any raise landed
    _sighted_pass(runner)
    assert sink.kinds() == ["applied"], "the subject a dead process may have left is cleared"
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_runner_started_again_raises_a_refusal_that_still_stands(pki: _Pki) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    await runner.stop()
    assert sink.kinds() == ["refused", "applied"]

    _pass(runner)

    assert sink.kinds() == ["refused", "applied", "refused"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


async def test_a_clear_the_sink_refuses_is_retried(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    hop = pki.outbound_hop()
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_expired(pki))
    _pass(runner)
    pki.crl.write_bytes(_fresher(pki, revoke=False))
    sink.down = True  # after the raise landed, so only the clear is refused

    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.crl_reload"):
        for _ in range(3):
            _pass(runner)
        failures = [r for r in caplog.records if "could not be resolved" in r.getMessage()]
        assert len(failures) == 1 and sink.kinds() == ["refused"]
        sink.down = False
        _pass(runner)
        _pass(runner)

    assert sink.kinds() == ["refused", "applied"]
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


def test_the_inverse_resolves_the_alert_and_no_rule_can_name_it() -> None:
    assert _AUTO_RESOLVE["crl_reload_applied"] == "crl_reload_refused"
    assert "crl_reload_applied" not in _ALERT_EVENT_TYPES
    with pytest.raises(ValidationError, match="event_type"):
        AlertRule(event_type="crl_reload_applied")


def test_the_logging_sink_logs_the_inverse_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().crl_reload_applied("crl_reload:a", path="a.pem")
    (record,) = caplog.records
    assert record.levelno == logging.DEBUG and "crl_reload_applied" in record.getMessage()


# --- the alert key -------------------------------------------------------------------------------


def test_the_subject_names_the_file_and_the_process() -> None:
    # A short absolute path, so the subject carries it whole wherever the suite runs.
    path = Path(os.path.abspath(os.sep)) / "pki" / "Partner-CRL.pem"
    key = crl_path_key(path)
    assert len(key) <= ALERT_PATH_MAX_LENGTH
    assert reload_alert_subject(path) == f"crl_reload:{key}"
    assert reload_alert_subject(path, "shard:a") == f"crl_reload:{key}@shard:a"
    # The path key, so a raise and its clear agree however the path was spelled.
    assert reload_alert_subject(key) == reload_alert_subject(path)
    assert reload_alert_subject(str(path)) == reload_alert_subject(path)


def test_a_long_path_and_a_long_node_label_stay_inside_the_column(tmp_path: Path) -> None:
    deep = tmp_path.joinpath(*["a-long-directory-name"] * 12)
    first, second = deep / "one" / "partner-crl.pem", deep / "two" / "partner-crl.pem"
    assert len(crl_path_key(first)) > ALERT_PATH_MAX_LENGTH
    for node in (None, "shard:a", "node:" + "x" * 400):
        subjects = {reload_alert_subject(p, node) for p in (first, second)}
        assert len(subjects) == 2, "two long paths with one tail stay distinct"
        for subject in subjects:
            assert len(subject) <= INTAKE_SUBJECT_MAX_LENGTH < 256
            assert subject.startswith("crl_reload:~")
            assert "partner-crl.pem" in subject, "the tail, which holds the file name, is kept"
    # Deterministic, so a clear names the instance its raise opened.
    assert reload_alert_subject(first, "shard:a") == reload_alert_subject(first, "shard:a")


def test_a_path_and_a_node_label_are_shortened_by_one_rule(tmp_path: Path) -> None:
    """Vault BACKLOG #3543 item 7: one shortening routine, where there were two hand-rolled
    copies. A CRL path keeps its tail and a node label its head, with one checksum of the whole
    text between, so the two cannot drift apart."""
    key = crl_path_key(tmp_path.joinpath(*["a-long-directory-name"] * 12, "partner-crl.pem"))
    short = shorten_with_checksum(key, ALERT_PATH_MAX_LENGTH, keep_tail=True)
    assert reload_alert_subject(key) == f"crl_reload:{short}"
    assert len(short) == ALERT_PATH_MAX_LENGTH and short.endswith("partner-crl.pem")
    assert shorten_with_checksum(key, ALERT_PATH_MAX_LENGTH) == f"{key[:111]}~{short[1:9]}"
    assert shorten_with_checksum("short", ALERT_PATH_MAX_LENGTH, keep_tail=True) == "short"
    # A limit with no room for a tail keeps none, rather than the whole text.
    assert len(shorten_with_checksum(key, 10, keep_tail=True)) == 10

    node = "node:" + "x" * 400
    subject = process_alert_subject("crl_reload:a", node)
    assert subject == f"crl_reload:a@{shorten_with_checksum(node, INTAKE_SUBJECT_MAX_LENGTH - 13)}"
    assert len(subject) == INTAKE_SUBJECT_MAX_LENGTH
    # A lone surrogate gets a checksum on both paths. The node label's copy used to raise.
    assert process_alert_subject("intake:x", "node:\ud800" + "y" * 400).startswith("intake:x@")


def test_the_subject_is_outside_the_connection_name_grammar(tmp_path: Path) -> None:
    """control_action's default target is the subject; it must never read as a connection."""
    for path in (tmp_path / "crl.pem", Path("crl.pem"), tmp_path.joinpath(*["d"] * 90, "c.pem")):
        for node in (None, "shard:a", "node:h1:42:ab12cd34"):
            assert not is_connection_name(reload_alert_subject(path, node))


# --- the sinks and the rule layer ----------------------------------------------------------------


def test_the_logging_sink_warns_with_fixed_words(caplog: pytest.LogCaptureFixture) -> None:
    sink = LoggingAlertSink()
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.alerts"):
        sink.crl_reload_refused(
            "crl_reload:/etc/pki/partner-crl.pem",
            path="/etc/pki/partner-crl.pem",
            remedy_class="wait",
            stale_contexts=2,
            remedy=WAIT,
        )
    (record,) = caplog.records
    assert record.levelno == logging.WARNING
    message = record.getMessage()
    assert "ALERT crl_reload_refused" in message and "/etc/pki/partner-crl.pem" in message
    assert "CRL reload refused (wait): 2 running TLS context(s) keep the copy they hold." in message
    assert WAIT in message and "engine log gives the reason" in message


def test_the_detail_leads_with_the_class_and_the_count() -> None:
    detail = crl_reload_refused_detail(remedy_class="fix_file", stale_contexts=3, remedy=FIX)
    assert detail.startswith(
        "CRL reload refused (fix_file): 3 running TLS context(s) keep the copy they hold."
    )
    assert "do not restart" not in detail
    assert crl_reload_refused_detail(remedy_class="other", stale_contexts=1, remedy="") == (
        "CRL reload refused (other): 1 running TLS context(s) keep the copy they hold. "
        "The crl_reload ERROR line in the engine log gives the reason."
    )


async def test_the_notifier_adds_the_start_warning_only_when_it_applies() -> None:
    transport = _RecordingTransport("webhook")
    sink = NotifierAlertSink([transport])
    sink.crl_reload_refused(
        "crl_reload:a", path="a", remedy_class="restart", stale_contexts=1, remedy=RESTART
    )
    sink.crl_reload_refused(
        "crl_reload:b",
        path="b",
        remedy_class="restart",
        stale_contexts=1,
        remedy=RESTART,
        start_refuses=True,
    )
    await _drain_transports(sink)
    plain, warned = transport.events
    assert "start_refuses" not in plain
    assert warned["start_refuses"] is True and "do not restart before then" in warned["detail"]


def test_the_alert_is_rule_targetable_and_takes_no_control_action() -> None:
    assert "crl_reload_refused" in _ALERT_EVENT_TYPES
    AlertRule(event_type="crl_reload_refused")
    with pytest.raises(ValidationError, match="connection-scoped event_type"):
        AlertRule(event_type="crl_reload_refused", control_action="restart_inbound")


def test_every_shipped_sink_implements_the_alert_and_its_inverse() -> None:
    for cls in (LoggingAlertSink, NotifierAlertSink):
        for method in ("crl_reload_refused", "crl_reload_applied"):
            assert callable(getattr(cls, method, None)), f"{cls.__name__}.{method}"


# --- the engine wiring ---------------------------------------------------------------------------


async def test_the_engine_hands_its_sink_and_its_identity_to_the_runner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.pipeline.engine import Engine

    monkeypatch.setattr(Engine, "instance_identity", property(lambda _self: "shard:a"))
    sink = _Sink()
    engine = await Engine.create(
        tmp_path / "engine.db",
        alert_sink=cast(AlertSink, sink),
        egress_settings=EgressSettings(deny_by_default=False),
    )
    await engine.start()
    try:
        runner = engine._crl_reload_runner
        assert runner is not None
        assert runner._alert_sink is sink and runner._node == "shard:a"
    finally:
        await engine.stop()


def test_the_runner_defaults_to_the_logging_sink() -> None:
    """Not gated on ``[cert_monitor]`` or on a notifier: with neither, the alert is a log line."""
    assert isinstance(CrlReloadRunner()._alert_sink, LoggingAlertSink)
