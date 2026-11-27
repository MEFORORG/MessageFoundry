# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The failover report's S26-62 item (BACKLOG #5572, item 1).

``per_lane_ordering`` no longer passes on fewer than two lanes, a run with no accepted load is a
named violation, a NaN or infinite ``[load.failover]`` knob or ``drain_timeout_s`` is refused before
anything starts, and the console escapes the backend name. The dead-row check stays main's absolute
``final.dead == 0``: the rig makes no read of the engine's PHI-gated dead-letter list route.
"""

from __future__ import annotations

import asyncio
import inspect
from dataclasses import replace
from types import SimpleNamespace
from typing import Any

import pytest

import harness.load.failover as failover
from harness.load.failover import (
    FailoverError,
    FailoverPorts,
    NodeStats,
    _build_report,
    _KillOutcome,
)
from harness.load.failover_track import FailoverTracker
from harness.load.metrics import Counters
from harness.load.profile import load_profile_text

_PROFILE = """
[load]
name = "fo-b20006"
pool_size = 1
[[load.target]]
name = "adt"
port = 2600
types = ["ADT"]
[load.mix]
"ADT^A01" = 1.0
[load.failover]
{failover}
[[load.phase]]
name = "sustained"
kind = "sustained"
loop = "open"
rate_start = 20.0
duration_s = 2.0
"""

_FAILOVER = {
    "kill_at_fraction": "0.5",
    "heartbeat_seconds": "2.0",
    "leader_fence_timeout_seconds": "4.0",
    "leader_lease_ttl_seconds": "6.0",
    "recovery_ttl_multiple": "2.0",
    "max_dup_rate": "0.1",
}

_PORTS = FailoverPorts(
    api_a=1, api_b=2, inbound_adt=3, inbound_results=4, inbound_other=5, sink=6, sink_count=1
)


def _profile(**knobs: str) -> Any:
    """The profile, with ``knobs`` written into its ``[load.failover]`` table as TOML values."""
    table = "\n".join(f"{k} = {v}" for k, v in {**_FAILOVER, **knobs}.items())
    return load_profile_text(_PROFILE.format(failover=table), where="<test>")


def _outcome() -> _KillOutcome:
    return _KillOutcome(
        killed=SimpleNamespace(node_id="fo-a"),  # type: ignore[arg-type]
        survivor=SimpleNamespace(node_id="fo-b"),  # type: ignore[arg-type]
        promotion_seconds=2.0,
        recovery_seconds=7.0,
        max_concurrent_leaders=1,
        leader_samples=10,
    )


def _tracker(lanes: tuple[str, ...] = ("d0", "d1"), n: int = 98) -> FailoverTracker:
    t = FailoverTracker()
    for seq in range(n):
        t.on_ack(seq)
        for lane in lanes:
            t.on_delivery(lane, seq)
    return t


def _report(
    *,
    tracker: FailoverTracker | None = None,
    dead: int = 0,
    acked: int = 98,
    db_backend: str | None = "postgres",
) -> failover.FailoverReport:
    profile = _profile()
    return _build_report(
        profile,
        db_backend,
        Counters(sent=100, acked=acked, sink_received=196, timeouts=100 - acked),
        tracker or _tracker(),
        _outcome(),
        NodeStats(done=5196, dead=dead, pending=0, inflight=0, in_pipeline=0),
        done_at_start=5000,
        fo=profile.failover,
        notes=[],
    )


def _refuse_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make any start of the run fail the test, so a refusal is shown to come before it."""

    def started(*_a: object, **_k: object) -> object:
        raise AssertionError("the run started")

    monkeypatch.setattr(failover, "build_corpus", started)
    monkeypatch.setattr(failover, "EngineNode", started)


# --- per_lane_ordering is non-vacuous ----------------------------------------------


def test_a_clean_two_lane_run_passes() -> None:
    rep = _report()
    assert rep.result_ok is True
    assert all(s.ok for s in rep.slos)
    assert not any("lane(s)" in n for n in rep.notes)


def test_per_lane_ordering_fails_on_one_lane() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    assert rep.lanes_observed == 1
    assert rep.result_ok is False
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


def test_per_lane_ordering_fails_on_no_lane() -> None:
    rep = _report(tracker=_tracker(lanes=()))
    assert rep.lanes_observed == 0
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)


def test_per_lane_ordering_names_why_one_lane_fails() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    assert any("observed 1 lane(s)" in n for n in rep.notes)


def test_one_lane_fails_a_named_lane_count_check() -> None:
    rep = _report(tracker=_tracker(lanes=("d0",)))
    lanes = next(s for s in rep.slos if s.name == "lanes_observed")
    assert (lanes.threshold, lanes.observed, lanes.ok) == (2, 1, False)
    assert "lanes_observed: observed=1 threshold=2" in rep.render_console()
    assert next(s for s in _report().slos if s.name == "lanes_observed").ok


def test_per_lane_ordering_fails_on_an_inversion_over_two_lanes() -> None:
    # With two lanes the lane count passes, so only the inversion can fail the check.
    t = _tracker(lanes=("d1",))
    for seq in (*range(96), 97, 96):  # 96 arrives after 97 on lane d0
        t.on_delivery("d0", seq)
    assert t.lanes_observed == 2 and t.lane_inversions == 1
    rep = _report(tracker=t)
    assert any(s.name == "per_lane_ordering" and not s.ok for s in rep.slos)
    assert next(s for s in rep.slos if s.name == "lanes_observed").ok


# --- zero accepted load ------------------------------------------------------------


def test_no_accepted_load_is_a_named_violation() -> None:
    rep = _report(acked=0, tracker=_tracker(n=0))
    assert rep.result_ok is False
    assert any(s.name == "messages_acked" and not s.ok for s in rep.slos)
    # Nothing was delivered, so the lanes note does not blame the lane key.
    assert not any("lane(s)" in n for n in rep.notes)


def test_zero_acks_alone_is_counted_as_a_violation() -> None:
    # Deliveries on two in-order lanes with no ACK, so messages_acked is the only check that fails:
    # before it existed the console printed FAIL with "(0 violated)".
    t = FailoverTracker()
    for seq in range(98):
        t.on_delivery("d0", seq)
        t.on_delivery("d1", seq)
    rep = _report(acked=0, tracker=t)
    assert [s.name for s in rep.slos if not s.ok] == ["messages_acked"]
    assert "(1 violated)" in rep.render_console()


# --- the dead-row check is main's, absolute ------------------------------------------


def test_any_dead_row_still_fails_the_run() -> None:
    rep = _report(dead=1)
    assert rep.result_ok is False
    assert any(s.name == "no_acknowledged_loss" and not s.ok for s in rep.slos)


# Built from parts, so this file does not itself spell the route it scans for.
_ROUTE = "/dead" + "-letters"
_FIELD = "dead" + "_letters"


def _names_dead_letter_route(source: str) -> bool:
    return _ROUTE in source or _FIELD in source


def test_the_failover_module_names_no_dead_letter_route() -> None:
    # The engine's PHI-gated dead-letter list route's reads can go unaudited when a node is
    # stopped ungracefully, so this module does not page it (CLAUDE.md section 9). A spelling scan
    # of this module only: it does not see a path built from parts, or a read made in another
    # module.
    planted = f'await self._signed_in_json(client, "{_ROUTE}?limit=500")'
    assert _names_dead_letter_route(planted)
    assert not _names_dead_letter_route(inspect.getsource(failover))


# --- non-finite knobs are refused before any start ------------------------------------


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("max_dup_rate", "nan"),
        ("recovery_ttl_multiple", "nan"),
        ("max_promotion_seconds", "inf"),
        ("leader_lease_ttl_seconds", "inf"),
    ],
)
def test_a_non_finite_failover_knob_is_refused_before_any_start(
    key: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Through the profile loader, which lets each of these through, so the guard is what stops it.
    profile = _profile(**{key: value})
    _refuse_start(monkeypatch)
    with pytest.raises(FailoverError, match=f"{key} must be a finite number"):
        asyncio.run(failover.run_failover_load(profile, ports=_PORTS, base_env={}))


def test_a_lease_whose_recovery_bound_overflows_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Every knob is finite and passes the loader; the bound 2 x 1e308 is not.
    profile = _profile(leader_lease_ttl_seconds="1e308")
    _refuse_start(monkeypatch)
    with pytest.raises(FailoverError, match="too large"):
        asyncio.run(failover.run_failover_load(profile, ports=_PORTS, base_env={}))


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("inf", "must be a finite number"),
        ("nan", "must be a finite number"),
        # Each finite, and the lease passes its own bound; 4 x 4e307 + 1e308 does not.
        ("1e308", "too large"),
    ],
)
def test_a_non_finite_drain_timeout_is_refused_before_any_start(
    value: str, match: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    text = _PROFILE.replace("pool_size = 1", f"pool_size = 1\ndrain_timeout_s = {value}")
    knobs = {**_FAILOVER, "leader_lease_ttl_seconds": "4e307"}
    table = "\n".join(f"{k} = {v}" for k, v in knobs.items())
    profile = load_profile_text(text.format(failover=table), where="<test>")
    _refuse_start(monkeypatch)
    with pytest.raises(FailoverError, match=f"drain_timeout_s (is )?{match}"):
        asyncio.run(failover.run_failover_load(profile, ports=_PORTS, base_env={}))


def test_the_monitor_deadline_is_unchanged() -> None:
    # Extracted into a helper; the formula stays 4 lease TTLs + the drain timeout + 30 s.
    assert failover._monitor_deadline(_profile().failover, 10.0) == 4.0 * 6.0 + 10.0 + 30.0


# --- terminal escaping ------------------------------------------------------------------


def test_the_console_escapes_the_backend_name() -> None:
    text = _report(db_backend="pg\x1b[2J\n").render_console()
    assert "\x1b" not in text
    assert "pg\\x1b[2J" in text


def test_the_console_escapes_the_profile_name_to_ascii() -> None:
    # A printable non-ASCII letter, written as chr() so the source stays ASCII.
    rep = replace(_report(), profile="fo\x1b[2J" + chr(0xE9))
    assert not rep.profile.isascii()
    header = rep.render_console().splitlines()[0]
    assert header.isascii() and "\x1b" not in header
    assert header.startswith("Failover-load report -- profile 'fo\\x1b[2J")
    assert _report().render_console().splitlines()[0] == (
        "Failover-load report -- profile 'fo-b20006' (backend postgres)"
    )
