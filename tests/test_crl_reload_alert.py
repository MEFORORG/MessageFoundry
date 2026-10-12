# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #2904: a refused CRL reload raises its own alert, ``crl_reload_refused``.

What this file proves, and the instrument for each:

* **The alert carries the file, the remedy class and the count, and no CRL contents.** A real
  reload pass over a real refused file, read through a recording sink. The control for "no CRL
  contents" is the refusal's reason from the same pass, which does quote the issuer.
* **One alert per file version.** The same pass run again and again raises nothing more. A second
  refused version raises one more.
* **It is raised on the event loop.** A real ``NotifierAlertSink`` writes its alert-state row only
  with a running loop. The control makes the same call from a worker thread, and no row lands.

All material is synthetic and minted by ``tests/test_crl_reload.py``. No PHI.
"""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import threading
import time
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
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
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
from messagefoundry.pipeline.intake_bound import INTAKE_SUBJECT_MAX_LENGTH
from messagefoundry.pki import read_soonest_crl_facts
from tests import test_crl_reload as _base
from tests.test_alert_sinks import _drain as _drain_transports
from tests.test_alert_sinks import _RecordingTransport
from tests.test_alert_state import _drain as _drain_state
from tests.test_alert_state import _RecordingStore
from tests.test_crl_reload import _DAY, _fresher, _Pki

# The reload suite's fixtures, bound here by name so pytest finds them in this module too: an
# empty registry and pass state per test, and one CA with a leaf and a CRL file.
_fresh_registry = _base._fresh_registry
pki = _base.pki

#: The issuer every CRL of the ``pki`` fixture carries, as a refusal's reason quotes it. With the
#: ``CN=``, because the fixture's file name holds the bare common name too.
_ISSUER = "CN=mefor-299-reload-ca"


class _Sink(LoggingAlertSink):
    """Records the reload alert. Every other event logs, so an engine can run on it."""

    def __init__(self) -> None:
        self.events: list[tuple[str, str, dict[str, Any]]] = []
        self.threads: list[str] = []

    def crl_reload_refused(
        self,
        name: str,
        *,
        path: str,
        remedy_class: str,
        stale_contexts: int,
        remedy: str,
        start_refuses: bool = False,
    ) -> None:
        self.threads.append(threading.current_thread().name)
        payload = {
            "path": path,
            "remedy_class": remedy_class,
            "stale_contexts": stale_contexts,
            "remedy": remedy,
            "start_refuses": start_refuses,
        }
        self.events.append(("refused", name, payload))

    def kinds(self) -> list[str]:
        return [kind for kind, _name, _payload in self.events]

    def refused(self) -> list[dict[str, Any]]:
        return [payload for kind, _name, payload in self.events if kind == "refused"]


def _runner(sink: object, **kw: Any) -> CrlReloadRunner:
    return CrlReloadRunner(alert_sink=cast(AlertSink, sink), **kw)


def _pass(runner: CrlReloadRunner, **kw: Any) -> list[ReloadOutcome]:
    """One real pass, and the runner's report of it, as ``_run`` does after its await."""
    outcomes = reload_replaced_crls(**kw)
    runner._report(outcomes)
    return outcomes


def _expired(pki: _Pki) -> bytes:
    return pki.crl_pem(issued=10 * _DAY, lasts=-_DAY, revoke=True)


def _not_newer(pki: _Pki) -> bytes:
    """Issued no later than the held copy, so OpenSSL would go on choosing the held one."""
    return pki.crl_pem(issued=3 * _DAY, lasts=60 * _DAY, revoke=True)


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
    assert sum("refused to apply" in r.getMessage() for r in caplog.records) == 2
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
    unproven = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    pem = pki.crl.read_bytes()
    record_crl_load(unproven, str(pki.crl), pem, read_soonest_crl_facts(pem, now=time.time()))
    sink = _Sink()
    runner = _runner(sink)
    pki.crl.write_bytes(_fresher(pki, revoke=False))

    (outcome,) = _pass(runner)

    assert (outcome.reloaded, outcome.stale) == (1, 1)
    assert sink.refused()[0]["stale_contexts"] == 1
    assert current.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


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

    runner._report([ReloadOutcome(str(pki.crl), 0, refusal, 3)])

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
        for _ in range(2000):
            if self.done >= target:
                return
            await asyncio.sleep(0.005)
        raise AssertionError(f"the runner made {self.done} passes, short of {target}")


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
        for _ in range(2000):
            if sink.events:
                break
            await asyncio.sleep(0.005)
    finally:
        await runner.stop()

    assert sink.threads == [threading.current_thread().name]
    assert pass_threads and threading.current_thread().name not in pass_threads
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


@pytest.mark.parametrize("returned", [None, "text", 7, [None, "x", object()], {"a": 1}])
async def test_a_pass_that_returns_no_outcomes_raises_nothing(returned: object) -> None:
    """The injected ``reload`` is typed to return anything, and two older tests return None."""
    sink = _Sink()
    _runner(sink)._report(returned)
    assert sink.events == []


async def test_a_sink_that_raises_does_not_stop_the_runner_and_is_retried(
    pki: _Pki, caplog: pytest.LogCaptureFixture
) -> None:
    class _Broken(_Sink):
        down = True

        def crl_reload_refused(self, name: str, **kw: Any) -> None:
            if self.down:
                raise RuntimeError("sink down")
            super().crl_reload_refused(name, **kw)

    hop = pki.outbound_hop()
    sink = _Broken()
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
    assert hop.verify_flags & ssl.VERIFY_CRL_CHECK_LEAF


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


def test_every_shipped_sink_implements_the_alert() -> None:
    for cls in (LoggingAlertSink, NotifierAlertSink):
        assert callable(getattr(cls, "crl_reload_refused", None)), cls.__name__


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
