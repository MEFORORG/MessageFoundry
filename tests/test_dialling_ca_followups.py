# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Dialling CA check follow-ups (vault BACKLOG #3224), from the round 4 and 5 review of engine PR 2108.

Item 1: a DR activation that a trust anchor refuses answers and records a fixed line. The refusal's
own text names the CA's path, the folders above it and its SHA-256, so it goes to the server log
only.

Item 5: a ``tls_ca_pin`` setting the lane check refuses is reported as a setting to fix, not a file.
A kept CA failure whose settings stop resolving says so in the log.

Item 6: the two tests the review found missing, on the inbound arm of the connection test's CA
check and on the ``deployed`` and ``auto_start`` compares of a kept CA failure.

Each test names the single mutation it goes red under.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.auth.trust_anchors as ta
from messagefoundry.api.app import _ANCHOR_REFUSED_DETAIL, _run_connection_test
from messagefoundry.auth.trust_anchors import TrustAnchorError
from messagefoundry.config.models import Priority
from messagefoundry.config.settings import DrSettings, EgressSettings
from messagefoundry.config.wiring import (
    Ftp,
    Registry,
    WiringError,
    build_inbound_connection,
    env,
)
from messagefoundry.pipeline import Engine, wiring_runner
from messagefoundry.pipeline.dr import DrActivationError, _caused_by_trust_anchor
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from tests.test_dr_outlive_deadline import _admin_client, _coordinator, _rows, _seed
from tests.test_dr_passive_followups import _PASSIVE_UNCHECKED, _runner
from tests.test_outbound_ca_anchors import _ca, _CountingSink, _sha
from tests.test_trust_anchors import _block, _path_ok

_IB = "IB_FTPS"
_PIN_MISMATCH = "does not match its configured SHA-256 pin"
#: What a step-4 abort says in place of the refusal's own text.
_ABORT_LINE = "a trust anchor was refused; the server log says which one and why"
#: A pin no file here has, so the lane check refuses the CA.
_WRONG_PIN = "00" * 32


@pytest.fixture
def judged(monkeypatch: pytest.MonkeyPatch) -> None:
    """The ACL and path read as owner-only, so a test varies only the pin."""
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr(ta, "anchor_path_verdict", _path_ok)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "followups.db")
    yield s
    await s.close()


def _poller_graph(
    ca: Path, pin: Any, *, deployed: bool = True, auto_start: bool = True
) -> Registry:
    """One critical inbound ``Ftp`` poller over FTPS, on a dead loopback port and routed nowhere.
    It is the one inbound that dials out, so the runner checks its CA lane by lane."""
    reg = Registry()
    spec = Ftp(
        host="127.0.0.1",
        port=9,
        tls=True,
        remote_dir="/out",
        tls_ca_file=str(ca),
        tls_ca_pin=pin,
    )
    reg.add_inbound(
        build_inbound_connection(
            _IB,
            spec,
            router="r",
            priority=Priority.CRITICAL,
            deployed=deployed,
            auto_start=auto_start,
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


# --- item 1: a refused DR activation names no CA path -------------------------------------


@pytest.fixture
async def dr_engine(tmp_path: Path) -> AsyncIterator[Engine]:
    """A passive DR standby with the two CA checks ``serve`` hands an engine. Its store is
    encrypted and carries a cold-seed archive of itself, so an activation clears its gates."""
    store, archive, ss = await _seed(tmp_path)
    engine = Engine(
        store,
        poll_interval=0.02,
        config_dir=None,
        store_settings=ss,
        dr_settings=DrSettings(enabled=True, activate=False, seed_archive=archive),
        egress_settings=EgressSettings(deny_by_default=False),
        registry_preflight=ta.make_registry_anchor_preflight(store, enforcing=True),
        lane_anchor_check=ta.make_lane_anchor_check(store, enforcing=True),
    )
    # The seed holds a row for a destination this graph does not declare.
    await store.dead_letter_missing_destinations(set())
    yield engine
    await engine.stop()


#: The folder the short CA path names. A word no abort line holds, so finding it is a leak.
_CA_DIR = "anchors3224"


def _short_ca(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A CA named by a short relative path, with the working directory moved under it.

    The length matters. ``safe_exc`` keeps 200 characters and drops a token that crosses that
    mark, so the long path of a pytest temp folder never reached the old abort line, and a test
    using one passes against the unfixed code. A path of an ordinary length did reach it."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / _CA_DIR).mkdir()
    return _ca(tmp_path / _CA_DIR).relative_to(tmp_path)


def _leaks(ca: Path, text: str) -> list[str]:
    """The parts of the CA's path found in ``text``: its file name and its folder. Neither
    needle holds a path separator, since a quoted Windows path doubles each one."""
    return [part for part in (ca.name, ca.parent.name) if part in text]


async def test_a_dr_activation_a_poller_ca_refuses_answers_and_records_no_path(
    dr_engine: Engine,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The reload's lane check refuses the poller's CA, which refuses the activation, and the
    route answers 503. Red under: step 4 of ``DrCoordinator._activate_locked`` taking
    ``safe_exc(exc)`` for every error, as it did before."""
    ca = _short_ca(tmp_path, monkeypatch)
    dr_engine.add_registry(_poller_graph(ca, _WRONG_PIN))
    await dr_engine.start()
    client, _app = await _admin_client(dr_engine, deadline=30.0)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.dr"):
        async with client:
            answer = await client.post("/dr/activate", json={})

    assert answer.status_code == 503
    detail = str(answer.json()["detail"])
    (row,) = await _rows(dr_engine.store, "dr_activation_aborted")
    assert row["kind"] == "profile"
    for text in (detail, str(row["reason"])):
        assert _leaks(ca, text) == [], text
        assert _ABORT_LINE in text
        assert "could not bind the priority feeds" in text  # the reload refused, not the preflight
    # The control for the two zeros above: the same needles find the path in the server log,
    # which keeps the refusal's own text.
    logged = [r.getMessage() for r in caplog.records if r.name == "messagefoundry.pipeline.dr"]
    refusals = [line for line in logged if _PIN_MISMATCH in line]
    assert refusals and all(_leaks(ca, line) == [ca.name, _CA_DIR] for line in refusals), refusals
    assert dr_engine.dr_active is False


async def _refused_in_its_preflight(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refuse: Any
) -> tuple[DrActivationError, str]:
    """Activate a box whose registry preflight is ``refuse``. Returns what the abort leaves: the
    error the route answers with, and the audit row's reason."""
    ca = _ca(tmp_path)
    dr_engine.add_registry(_poller_graph(ca, _sha(ca)))
    await dr_engine.start()
    monkeypatch.setattr(dr_engine, "preflight_registry", refuse)
    with pytest.raises(DrActivationError) as caught:
        await _coordinator(dr_engine).activate(actor="alice")
    assert caught.value.kind == "profile"
    (row,) = await _rows(dr_engine.store, "dr_activation_aborted")
    return caught.value, str(row["reason"])


async def test_a_dr_activation_its_preflight_refuses_names_no_path(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The other arm of step 4: the trust-anchor preflight refuses before any reload. The
    refusal is raised the way ``make_registry_anchor_preflight`` raises a listener's or a
    ``FhirLookup``'s. Red under the same mutation as the test above.

    The abort is raised outside the handler that caught the refusal, as the connection-start
    route raises its 409, so the refusal is not left on the abort for a later reader of the
    chain. Red under: the abort raised inside the handler."""
    named = Path(_CA_DIR) / "partner-ca.pem"

    async def refuse(_registry: object) -> None:
        error = ta.refused_connection_anchor(
            TrustAnchorError(f"the trust anchor '{named.as_posix()}' {_PIN_MISMATCH}")
        )
        raise error from error.__cause__

    abort, reason = await _refused_in_its_preflight(dr_engine, tmp_path, monkeypatch, refuse)
    for text in (str(abort), reason):
        assert _leaks(named, text) == [], text
        assert _ABORT_LINE in text
        assert "stopped at its trust-anchor preflight" in text
    assert abort.__context__ is None and abort.__cause__ is None


async def test_a_dr_activation_refused_by_anything_else_keeps_its_own_text(
    dr_engine: Engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two above, and the limit of the repair: only a refusal a trust anchor
    caused loses its text. An error raised while one was being handled is not such a refusal, so
    it keeps its own. Red under: the chain walk following ``__context__``."""

    async def refuse(_registry: object) -> None:
        try:
            raise TrustAnchorError("a refusal that was handled")
        except TrustAnchorError:
            raise WiringError(f"a config value under {_CA_DIR} is not readable")  # noqa: B904

    abort, reason = await _refused_in_its_preflight(dr_engine, tmp_path, monkeypatch, refuse)
    for text in (str(abort), reason):
        assert f"a config value under {_CA_DIR} is not readable" in text
        assert _ABORT_LINE not in text
    assert isinstance(abort.__context__, WiringError)  # such an abort keeps what caused it


def test_the_chain_walk_follows_explicit_causes_only_and_ends_on_a_cycle() -> None:
    """``_caused_by_trust_anchor`` on each shape step 4 can be handed."""
    refusal = TrustAnchorError("refused")
    assert _caused_by_trust_anchor(refusal)
    wrapped = ta.refused_connection_anchor(refusal)
    assert wrapped.__cause__ is refusal and _caused_by_trust_anchor(wrapped)
    # A blank pin is a ValueError, which the reload check wraps in a TrustAnchorError first.
    assert _caused_by_trust_anchor(ta.refused_connection_anchor(ValueError("a blank pin")))
    assert not _caused_by_trust_anchor(WiringError("a listener could not bind"))
    looped, other = RuntimeError("a"), RuntimeError("b")
    looped.__cause__, other.__cause__ = other, looped
    assert not _caused_by_trust_anchor(looped)


# --- item 5: the advice a refused setting gets, and a kept failure that stops resolving --------

_FIX_THE_FILE = "Fix the file"


def _blank_pin_runner(store: MessageStore, tmp_path: Path, **kw: Any) -> RegistryRunner:
    """A poller whose ``tls_ca_pin`` is an ``env()`` value set to nothing. A blank literal
    refuses when the graph loads; this one reaches the lane check, which raises ``ValueError``."""
    reg = _poller_graph(_ca(tmp_path), env("ftps_ca_pin"))
    return _runner(store, reg, env_values={"ftps_ca_pin": ""}, **kw)


async def test_a_refused_pin_setting_is_not_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """A blank pin is a setting to change, and a start reads the same setting again. Red under:
    the ``ValueError`` arm of ``_check_lane_anchor`` removed."""
    runner = _blank_pin_runner(store, tmp_path)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert reason == (
            f"TrustAnchorError: inbound connection '{_IB}': its tls_ca_pin or tls_ca_file "
            "setting was refused. Fix the setting, then reload and start the connection; the "
            "server log says why"
        )
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


async def test_a_refused_file_is_still_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The control for the test above: a pin the file does not match is a refused file."""
    runner = _runner(store, _poller_graph(_ca(tmp_path), _WRONG_PIN))
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_file was refused. Fix the file, then start the connection" in reason
    finally:
        await runner.stop()


async def test_a_passive_standby_does_not_tell_a_refused_setting_to_fix_the_file(
    store: MessageStore, tmp_path: Path, judged: None
) -> None:
    """The passive start's own line. Red under: the ``ValueError`` arm of
    ``_preflight_passive_lanes`` removed."""
    runner = _blank_pin_runner(store, tmp_path, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert "its tls_ca_pin or tls_ca_file setting was refused on this passive DR" in reason
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


async def test_a_passive_check_that_could_not_run_is_not_told_to_fix_the_file(
    store: MessageStore, tmp_path: Path
) -> None:
    """Nothing read the file, so nothing says it is at fault. Red under: the could-not-be-checked
    arm of ``_preflight_passive_lanes`` given the refused file's advice again."""

    async def cannot_run(_direction: str, _name: str, _settings: object) -> None:
        raise RuntimeError("the audit store did not answer")

    reg = _poller_graph(_ca(tmp_path), _WRONG_PIN)
    runner = _runner(store, reg, lane_anchor_check=cannot_run, dr_standby=Priority.CRITICAL)
    await runner.start()
    try:
        reason = runner.inbound_failed(_IB) or ""
        assert _PASSIVE_UNCHECKED in reason
        assert "reload once the cause is fixed" in reason
        assert _FIX_THE_FILE not in reason
    finally:
        await runner.stop()


async def test_a_kept_failure_whose_settings_stop_resolving_says_so_in_the_log(
    store: MessageStore,
    tmp_path: Path,
    judged: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The lane is rebuilt, and that used to happen with no line saying why the reload read a CA
    it had been leaving alone. Red under: the ``log.info`` call removed."""
    reg = _poller_graph(_ca(tmp_path), _WRONG_PIN)
    runner = _runner(store, reg)
    await runner.start()
    try:
        poller = reg.inbound[_IB]
        assert runner._keeps_anchor_failure("inbound", _IB, reg, poller)  # the control: kept

        def unresolved(_conn: object) -> None:
            raise WiringError("env('ftps_ca_pin') is not set in this environment")

        monkeypatch.setattr(runner, "_anchor_lane_settings", unresolved)
        with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.wiring_runner"):
            assert not runner._keeps_anchor_failure("inbound", _IB, reg, poller)
        lines = [r.getMessage() for r in caplog.records if "no longer resolve" in r.getMessage()]
        assert len(lines) == 1 and _IB in lines[0] and "ftps_ca_pin" in lines[0], lines
    finally:
        await runner.stop()


# --- item 6: the two tests the review found missing -----------------------------------------


async def test_a_connection_test_of_a_failed_poller_does_not_let_the_next_reload_skip_its_ca(
    store: MessageStore, tmp_path: Path, judged: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The inbound arm of ``check_test_anchor``. The poller fails its start for a reason that is
    not its CA, so it is recorded failed and not marked. Its CA is then swapped. A connection
    test checks it and must not mark it, or the next reload would keep the failure and skip the
    check. The outbound arm has this test in ``tests/test_outbound_ca_anchors.py``. Red under:
    ``fails_lane=False`` dropped from the inbound call in ``check_test_anchor``."""
    from messagefoundry.transports import build_source as real

    calls = 0

    def flaky(cfg: Any, **kw: Any) -> Any:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("partner endpoint not ready")
        return real(cfg, **kw)

    monkeypatch.setattr(wiring_runner, "build_source", flaky)
    ca = _ca(tmp_path)
    runner = _runner(store, _poller_graph(ca, _sha(ca)))
    await runner.start()
    try:
        assert "partner endpoint not ready" in (runner.inbound_failed(_IB) or "")
        ca.write_bytes(_block(b"substitute"))
        result = await _run_connection_test(runner, _IB, "inbound")
        assert result.success is False and result.detail == _ANCHOR_REFUSED_DETAIL
        for _ in range(2):
            with pytest.raises(WiringError, match=_PIN_MISMATCH):
                await runner.reload()
    finally:
        await runner.stop()


@pytest.mark.parametrize("flag", ["deployed", "auto_start"])
async def test_flipping_a_flag_back_ends_a_kept_ca_failure(
    store: MessageStore, tmp_path: Path, judged: None, flag: str
) -> None:
    """``_keeps_anchor_failure`` compares ``deployed`` and ``auto_start`` as well as the spec. A
    poller its CA failed is taken down by one flag and put back with no other change. The reload
    that puts it back builds it, so it reads the CA and refuses on the one still refused. Red
    under: that flag's compare removed from ``_keeps_anchor_failure``, one flag per case.

    It needs an inbound. A reload that takes an outbound down drops its failed record, which ends
    the kept failure before either compare is asked."""
    ca = _ca(tmp_path)
    up = _poller_graph(ca, _WRONG_PIN)
    sink = _CountingSink()
    runner = _runner(store, up, alert_sink=sink)
    await runner.start()
    try:
        assert sink.stopped == [_IB]
        await runner.reload(up)  # the control: with nothing changed the failure is kept
        await runner.reload(_poller_graph(ca, _WRONG_PIN, **{flag: False}))
        assert runner.inbound_failed(_IB) is not None  # still recorded, so only the flag differs
        with pytest.raises(WiringError, match=_PIN_MISMATCH):
            await runner.reload(_poller_graph(ca, _WRONG_PIN))
    finally:
        await runner.stop()
