# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the plan-usage collector and reader (``scripts/coord/usage-*.ps1``).

Claude Code hands the account's live quota state (``rate_limits``) to a **statusLine command's stdin and
nowhere else** — not to any hook. So quota state has to be collected there and published somewhere
shared. ``usage-collect.ps1`` is that statusLine; ``usage.ps1`` reads what it publishes and answers the
only operationally useful question: *will this window run out before it resets?*

The properties worth pinning are all about **not being confidently wrong**, because a usage tool that
lies converts "I should check" into "I already know":

* **An empty reading must never overwrite a good one.** Every session runs the statusLine and they all
  publish to one shared file, so a session that has not yet had its first API response would otherwise
  blank the account's only reading for all of them.
* **An absent window is carried, not blanked** — and a carried-forward number must keep its own older
  timestamp and must never enter the burn-rate history.
* **Stale, undateable and future-dated readings are UNKNOWN**, never extrapolated.
* **Rate is never computed across a window reset**, where the percentage legitimately falls to zero.

Driven as real subprocesses against fixtures, because these are PowerShell scripts and a Python
re-implementation of their rules would only assert that the re-implementation agrees with itself.

THE DIRECT ``pwsh`` LAUNCHES HERE GO THROUGH ``run_single`` (BACKLOG #1304). A launch out
of this file starved past its 60-second ceiling on the ``windows-2025`` harness leg while
``test_session_mail.py`` held 16 concurrent ``pwsh`` on a 4-vCPU runner; the evidence, and the rule
for what may take the lock, live in ``tests/_spawn_lock.py``. Read that module before adding a launch
here.

AT LEAST ONE ``pwsh`` LAUNCH IN THIS FILE IS STILL UNLOCKED, and it is named rather than counted
because an enumeration here would be the liability CLAUDE.md section 11 warns about (SDS-3.6). The
``bash`` sites are excluded by ``_LOCKED_INTERPRETERS``, which matches on the binary being launched
-- and at least two of them, ``test_bash_runs_the_wired_command_end_to_end_and_it_publishes`` and
the #1459 helper ``_run_under_bash``, run the wired statusLine command, whose whole job is to invoke
``pwsh``. So those are real ``pwsh`` launches on a 60-second ceiling sitting outside the lock. They
are left alone: wrapping them means calling ``single_spawn`` directly around a ``bash`` invocation,
which is a behaviour change with no #1304 evidence behind it, and the module's rule is not to wrap
on a hunch.

``tests/test_spawn_lock.py`` gates the direct sites against one being added unwrapped. That
gate exists because this paragraph is a convention, and ``run_single``'s own docstring says a
convention in a docstring does not hold a line.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from _bash_resolver import probe_env, require_bash

from tests._no_prompt import run_holding_stdin_open
from tests._spawn_lock import run_single

ROOT = Path(__file__).resolve().parents[1]
COLLECT = ROOT / "scripts" / "coord" / "usage-collect.ps1"
READ = ROOT / "scripts" / "coord" / "usage.ps1"
INSTALL = ROOT / "scripts" / "coord" / "install-usage-statusline.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the usage scripts need pwsh on Windows",
)

OK, WARN, CRITICAL, UNKNOWN = 0, 10, 11, 20


def collect(state: Path, payload: dict[str, Any] | str) -> str:
    """Drive the collector exactly as Claude Code drives a statusLine: JSON on stdin, line on stdout.

    THE PIN IS POPPED, and that is not incidental. The collector stamps each freshly observed window
    with the config root that saw it, so a helper that inherited this process's own
    ``CLAUDE_CONFIG_DIR`` would stamp every fixture with the real account root — and any test that then
    read the fixture back through ``usage.ps1 -StateDir <tmp>`` would trip the cross-root refusal and
    fail for a reason that has nothing to do with what it is testing. An unpinned publisher stamps
    ``unset``, which is what a neutral fixture should be. Tests that care about a specific root pass
    one explicitly.
    """
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(COLLECT), "-StateDir", str(state)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(None),
    )
    # A statusLine that exits non-zero degrades the session it decorates; it must never do that.
    assert proc.returncode == 0, f"collector exited {proc.returncode}: {proc.stderr}"
    return proc.stdout.strip()


def read(state: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(READ),
            "-StateDir",
            str(state),
            "-Json",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    out = proc.stdout.strip()
    return proc.returncode, (json.loads(out) if out else {})


def window(pct: float, resets_in_s: int) -> dict[str, Any]:
    return {"used_percentage": pct, "resets_at": int(time.time()) + resets_in_s}


def latest(state: Path) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads((state / "latest.json").read_text(encoding="utf-8"))
    return parsed


def captured_at(state: Path) -> datetime:
    """The window's stamp as an instant. PowerShell drops a trailing zero when it re-serialises a
    kept stamp, so two spellings of one instant differ as strings."""
    return datetime.fromisoformat(latest(state)["seven_day"]["captured_at"])


def history(state: Path) -> list[dict[str, Any]]:
    p = state / "history.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


# ------------------------------------------------------------------------------ collector


def test_publishes_the_weekly_window_and_ignores_a_five_hour_key(tmp_path: Path) -> None:
    """Anthropic removed the five-hour limit, so a payload still carrying the key is not an error
    and its number goes nowhere: not the document, not the history, not the status line."""
    line = collect(
        tmp_path,
        {
            "session_id": "A",
            "rate_limits": {"five_hour": window(80.4, 5940), "seven_day": window(36.2, 280000)},
        },
    )
    d = latest(tmp_path)
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.2)
    assert "five_hour" not in d, d
    assert "7d 36%" in line and "80" not in line and "5h" not in line, line
    (row,) = history(tmp_path)
    assert set(row) == {"at", "seven_day", "seven_reset"}, row


def test_a_payload_carrying_only_five_hour_publishes_no_window(tmp_path: Path) -> None:
    line = collect(tmp_path, {"session_id": "A", "rate_limits": {"five_hour": window(80.0, 5940)}})
    assert line == "mefor-usage: no rate_limits yet", line
    assert not (tmp_path / "latest.json").exists(), "a window nobody reads was published"
    assert history(tmp_path) == []


def test_a_document_and_history_written_with_five_hour_still_read_and_rewrite(
    tmp_path: Path,
) -> None:
    """The real shape of a root published before the change. The reader takes the weekly numbers
    from it, rate included, and the next publish drops the old key."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=71.0, seven_epoch=epoch)
    doc = latest(tmp_path)
    doc["five_hour"] = {"used_percentage": 99.0, "resets_at_epoch": 1, "captured_at": "garbage"}
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    rows = [(60.0, 60.0, 90.0), (30.0, None, 95.0), (1.0, 70.0, 99.0)]
    (tmp_path / "history.jsonl").write_text(
        "".join(
            json.dumps(
                {
                    "at": _minutes_ago(m),
                    "five_hour": five,
                    "seven_day": seven,
                    "five_reset": 1790475000,
                    "seven_reset": epoch,
                }
            )
            + "\n"
            for m, seven, five in rows
        ),
        encoding="utf-8",
    )

    code, d = read(tmp_path)
    assert code == CRITICAL, d
    assert "five_hour" not in d, d
    assert d["seven_day"]["rate_pct_per_hr"] == pytest.approx(10.17, abs=0.5), d

    collect(tmp_path, {"session_id": "B"})
    assert "five_hour" not in latest(tmp_path)
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(71.0)


def test_a_session_with_no_rate_limits_does_not_clobber_a_good_reading(tmp_path: Path) -> None:
    """THE ONE THAT MATTERS. Found by testing, not by reading.

    Every session runs this statusLine and they all publish to ONE shared file, so each session is a
    publisher — there is no privileged collector. ``rate_limits`` is absent until a session's first API
    response lands, so a naive write blanks the account's only good reading for all thirty sessions at
    once, and the reader downstream cannot tell the difference between "0% used" and "nobody has looked".
    """
    collect(
        tmp_path,
        {"session_id": "A", "rate_limits": {"seven_day": window(36.2, 280000)}},
    )
    collect(tmp_path, {"session_id": "B"})  # a session that has not made an API call yet

    d = latest(tmp_path)
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.2), (
        "a session with no data destroyed the reading"
    )


def test_an_absent_window_is_carried_forward_with_its_own_older_timestamp(tmp_path: Path) -> None:
    """A carried-forward value stamped with the current time would be a stale number wearing a fresh
    timestamp — which is precisely the shape of claim that this repo keeps having to retract.
    """
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": window(36.0, 280000)}})
    time.sleep(1.1)
    collect(tmp_path, {"session_id": "C", "rate_limits": {}})

    d = latest(tmp_path)
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.0), (
        "the absent window must be carried, not nulled"
    )
    assert d["seven_day"]["captured_at"] < d["captured_at"], (
        "the carried window must keep its ORIGINAL timestamp, or it reads as freshly observed"
    )


def test_history_never_records_a_carried_forward_value(tmp_path: Path) -> None:
    """Burn rate is computed from this file. A carried-forward percentage against a new timestamp says
    consumption stopped — the one lie that matters in a tool built to warn about consumption."""
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": window(36.0, 280000)}})
    collect(tmp_path, {"session_id": "C", "rate_limits": {}})

    assert len(history(tmp_path)) == 1, "a carried-forward window must not reach the history"


def test_a_flat_reading_does_not_append_history(tmp_path: Path) -> None:
    """The statusline fires many times a minute; a row per fire is a big file describing a flat line."""
    payload = {"session_id": "A", "rate_limits": {"seven_day": window(50.0, 5940)}}
    collect(tmp_path, payload)
    collect(tmp_path, payload)
    collect(tmp_path, payload)
    assert len(history(tmp_path)) == 1


def test_an_idle_session_writes_no_row_on_a_timer(tmp_path: Path) -> None:
    """An idle session keeps reporting its cached percentage. A row for it would read as a measured
    rate of zero while other sessions burn the pool, and a rate of zero lifts the level backstop. So
    however old the last row is, a flat reading adds nothing and the rate stays unmeasured."""
    seven = window(92.0, 280000)
    write_history(tmp_path, [(60.0, 92.0)], seven["resets_at"])
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": seven}})
    assert len(history(tmp_path)) == 1
    _, d = read(tmp_path)
    assert d["seven_day"]["rate_pct_per_hr"] is None, d


def test_a_lower_reading_in_one_reset_period_replaces_nothing(tmp_path: Path) -> None:
    """An idle session keeps reporting its cached percentage, on a timer. Inside one reset period
    the level only rises, so the highest reading binds, and the lower one must not move the number,
    its age, or the history. Live 99 then idle 60 used to grade clear at the ceiling."""
    live = window(91.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": live}})
    first = captured_at(tmp_path)

    time.sleep(1.1)
    idle = {**live, "used_percentage": 60.0}
    line = collect(tmp_path, {"session_id": "idle", "rate_limits": {"seven_day": idle}})
    kept = latest(tmp_path)["seven_day"]
    assert kept["used_percentage"] == pytest.approx(91.0), "the idle reading replaced the live one"
    assert captured_at(tmp_path) == first, "a refused reading must not refresh the age"
    assert "7d 91%" in line, line
    assert len(history(tmp_path)) == 1, "a refused reading reached the rate's history"

    # CONTROL. A guard that froze the window would pass everything above.
    higher = {**live, "used_percentage": 93.0}
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": higher}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(93.0)
    assert len(history(tmp_path)) == 2


def test_a_new_reset_period_replaces_the_old_value_in_either_direction(tmp_path: Path) -> None:
    epoch = int(time.time()) + 3600
    for resets_at, pct in ((epoch, 91.0), (epoch + 7 * 86400, 2.0), (epoch + 14 * 86400, 50.0)):
        seven = {"used_percentage": pct, "resets_at": resets_at}
        collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": seven}})
        assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(pct)
    assert [r["seven_day"] for r in history(tmp_path)] == [91.0, 2.0, 50.0]


def test_a_reading_from_an_earlier_reset_period_replaces_nothing(tmp_path: Path) -> None:
    """After a reset, an idle session still holds last week's number and last week's reset time.
    Letting it in would swap a current reading for a gone one, every few seconds."""
    epoch = int(time.time()) + 3600
    current = {"used_percentage": 2.0, "resets_at": epoch}
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": current}})
    gone = {"used_percentage": 95.0, "resets_at": epoch - 7 * 86400}
    collect(tmp_path, {"session_id": "idle", "rate_limits": {"seven_day": gone}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(2.0)
    assert len(history(tmp_path)) == 1


def test_a_later_reading_with_an_earlier_reset_ahead_of_now_is_a_new_window(tmp_path: Path) -> None:
    """A re-login or a moved reset. Only a reset already passed marks a window as gone."""
    now = int(time.time())
    first = {"used_percentage": 95.0, "resets_at": now + 500000}
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": first}})
    moved = {"used_percentage": 3.0, "resets_at": now + 100000}
    collect(tmp_path, {"session_id": "B", "rate_limits": {"seven_day": moved}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(3.0)


def test_a_higher_reading_with_no_reset_is_refused_and_the_floor_stays_armed(
    tmp_path: Path,
) -> None:
    """It cannot prove which window it belongs to. Taken bare, it would wipe the reset. Given the
    published reset, a cached 95 would set a floor no live reading could lower until that reset."""
    seven = window(3.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": seven}})
    bare = {"used_percentage": 95.0}
    collect(tmp_path, {"session_id": "odd", "rate_limits": {"seven_day": bare}})
    kept = latest(tmp_path)["seven_day"]
    assert kept["used_percentage"] == pytest.approx(3.0), kept
    assert kept["resets_at_epoch"] == seven["resets_at"], kept
    assert len(history(tmp_path)) == 1

    # CONTROL: the next reading that carries the reset still moves the number.
    live = {**seven, "used_percentage": 4.0}
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": live}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(4.0)


def test_with_no_published_reset_there_is_no_floor(tmp_path: Path) -> None:
    """The stated limit, pinned so a change to it is a decision: with no reset to compare, the rule
    has nothing to hold on to. A lower reading replaces, and an equal one refreshes the age."""
    for pct in (70.0, 40.0):
        seven = {"used_percentage": pct}
        collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": seven}})
        assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(pct)
    first = captured_at(tmp_path)
    time.sleep(1.1)
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": {"used_percentage": 40.0}}})
    assert captured_at(tmp_path) > first


def test_a_gone_reading_on_an_empty_directory_is_published_and_read_as_unknown(
    tmp_path: Path,
) -> None:
    """The floor refuses a gone reading only against a later published reset. With nothing published
    it lands in both files, and the reader is what keeps its number from being used."""
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": window(95.0, -300)}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(95.0)
    assert len(history(tmp_path)) == 1
    code, d = read(tmp_path)
    assert code == UNKNOWN, d
    assert d["seven_day"]["used_percentage"] is None, d


def test_a_lower_reading_with_no_reset_cannot_disarm_the_floor(tmp_path: Path) -> None:
    """Taken, it would wipe the published reset, and every lower reading after it would pass too."""
    seven = window(99.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": seven}})
    collect(
        tmp_path, {"session_id": "odd", "rate_limits": {"seven_day": {"used_percentage": 50.0}}}
    )
    kept = latest(tmp_path)["seven_day"]
    assert kept["used_percentage"] == pytest.approx(99.0), kept
    assert kept["resets_at_epoch"] == seven["resets_at"], kept


@pytest.mark.parametrize("stamp", ["own-root", "unset", None], ids=["own", "unset", "absent"])
def test_a_differently_stamped_session_on_this_root_still_meets_the_floor(
    tmp_path: Path, stamp: str | None
) -> None:
    """A pinned session and an unpinned one can share a root, and the reader calls both its own."""
    seven = window(99.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": seven}})
    doc = latest(tmp_path)
    if stamp is None:
        del doc["seven_day"]["config_root_env"]
    else:
        own = str(tmp_path.parent)
        doc["seven_day"]["config_root_env"] = own if stamp == "own-root" else stamp
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")

    idle = {**seven, "used_percentage": 60.0}
    collect(tmp_path, {"session_id": "idle", "rate_limits": {"seven_day": idle}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(99.0)


def test_an_unchanged_reading_does_not_refresh_the_age(tmp_path: Path) -> None:
    """An idle session's cached value looks the same as a live flat one, and restamping it let one
    idle terminal keep a frozen number fresh while the pool burned, so the rung read OK on it. The
    age now counts from the last change. The control is a move, which does refresh it."""
    seven = window(89.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": seven}})
    first = captured_at(tmp_path)
    time.sleep(1.1)
    collect(tmp_path, {"session_id": "idle", "rate_limits": {"seven_day": seven}})
    assert captured_at(tmp_path) == first

    higher = {**seven, "used_percentage": 90.0}
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": higher}})
    assert captured_at(tmp_path) > first


def test_an_unchanged_reading_cannot_revive_a_stale_one(tmp_path: Path) -> None:
    """End to end through the reader: an old reading stays UNKNOWN after an idle session fires."""
    seven = window(89.0, 280000)
    collect(tmp_path, {"session_id": "live", "rate_limits": {"seven_day": seven}})
    doc = latest(tmp_path)
    doc["seven_day"]["captured_at"] = _minutes_ago(300)
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    assert read(tmp_path)[0] == UNKNOWN, "control: the old reading is stale before the idle fire"

    collect(tmp_path, {"session_id": "idle", "rate_limits": {"seven_day": seven}})
    code, d = read(tmp_path)
    assert code == UNKNOWN, d


def test_the_first_reading_of_a_new_reset_period_gets_a_row_at_the_same_percent(
    tmp_path: Path,
) -> None:
    """A row for the new period is what the rate counts from, whatever the number happens to be."""
    epoch = int(time.time()) + 3600
    for resets_at in (epoch, epoch + 7 * 86400):
        seven = {"used_percentage": 0.0, "resets_at": resets_at}
        collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": seven}})
    assert [r["seven_reset"] for r in history(tmp_path)] == [epoch, epoch + 7 * 86400]


def test_the_status_line_shows_no_number_for_a_gone_window(tmp_path: Path) -> None:
    line = collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": window(99.0, -300)}})
    assert line == "7d reset passed, no current reading", line


def test_a_window_carried_from_another_root_is_no_floor_for_this_one(tmp_path: Path) -> None:
    """The highest reading binds inside one account's pool only. A foreign number kept as a floor
    would block this root's own readings until the reset, and the reader would refuse it throughout."""
    seven = window(88.0, 280000)
    collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": seven}})
    doc = latest(tmp_path)
    doc["seven_day"]["config_root_env"] = str(tmp_path / "another-account")
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")

    mine = {**seven, "used_percentage": 12.0}
    collect(tmp_path, {"session_id": "B", "rate_limits": {"seven_day": mine}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(12.0)


def test_the_status_line_truncates_hours_rather_than_rounding_them(tmp_path: Path) -> None:
    """90 minutes rounded to the even hour read as 2h30m."""
    line = collect(tmp_path, {"session_id": "A", "rate_limits": {"seven_day": window(9.0, 5430)}})
    assert re.search(r"resets 1h30m", line), line


@pytest.mark.parametrize("bad", ["", "not json at all", "{truncated", "null"])
def test_the_collector_never_fails_on_a_bad_payload(tmp_path: Path, bad: str) -> None:
    """It decorates a live session. A throw or a non-zero exit here is worse than a missing reading."""
    line = collect(tmp_path, bad)
    assert line, "it must still emit a status line"
    assert not list(tmp_path.glob("*.tmp")), "a failed write must not orphan a temp file"


def test_no_data_publishes_nothing_rather_than_a_document_of_nulls(tmp_path: Path) -> None:
    collect(tmp_path, {"session_id": "B"})
    assert not (tmp_path / "latest.json").exists(), (
        "with nothing observed and nothing remembered, publishing nulls would make 'unknown' look like 'zero'"
    )


# ------------------------------------------------------------------------------ reader


def _minutes_ago(mins: float) -> str:
    return (datetime.now(UTC) - timedelta(minutes=mins)).isoformat().replace("+00:00", "Z")


def publish(
    state: Path,
    *,
    seven: float | None,
    age_min: float = 0.0,
    seven_epoch: int | None = None,
) -> None:
    """Write a latest.json directly, so reader behaviour can be tested independently of the collector."""
    state.mkdir(parents=True, exist_ok=True)
    stamp = _minutes_ago(age_min)
    doc: dict[str, Any] = {
        "captured_at": stamp,
        "published_by": {"session_id": "T"},
        "source": "test",
    }
    doc["seven_day"] = (
        None
        if seven is None
        else {
            "used_percentage": seven,
            "resets_at_epoch": seven_epoch or int(time.time()) + 280000,
            "resets_at": "x",
            "captured_at": stamp,
        }
    )
    (state / "latest.json").write_text(json.dumps(doc), encoding="utf-8")


def _stamp(state: Path, root: Path) -> None:
    """Stamp a published document and its window with ``root``, as a pinned collector would."""
    doc = latest(state)
    doc["published_by"]["config_root_env"] = str(root)
    doc["seven_day"]["config_root_env"] = str(root)
    (state / "latest.json").write_text(json.dumps(doc), encoding="utf-8")


def _floor(state: Path, **published: Any) -> float | None:
    """The level_floor of a reading of this root's, read with -StateDir so wiring does not apply."""
    publish(state, **published)
    _stamp(state, state.parent)
    floor: float | None = read(state)[1]["seven_day"]["level_floor"]
    return floor


def write_history(state: Path, points: list[tuple[float, float]], seven_epoch: int) -> None:
    """points = [(minutes_ago, seven_day_pct)] within one window epoch."""
    state.mkdir(parents=True, exist_ok=True)
    rows = [
        {"at": _minutes_ago(mins), "seven_day": pct, "seven_reset": seven_epoch}
        for mins, pct in points
    ]
    (state / "history.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )


def test_no_data_at_all_is_unknown_and_says_how_to_fix_it(tmp_path: Path) -> None:
    code, _ = read(tmp_path / "nothing")
    assert code == UNKNOWN


def test_a_stale_reading_is_reported_but_never_projected_from(tmp_path: Path) -> None:
    """A dead publisher is the expected steady state here: the statusLine does not run headless, so the
    coordinator itself can never publish. Extrapolating from an hour-old number would be a confident
    answer about a window that may already have reset."""
    publish(tmp_path, seven=71.0, age_min=75)
    code, d = read(tmp_path)
    assert code == UNKNOWN
    assert d["seven_day"]["used_percentage"] == pytest.approx(71.0), "the number is still shown"
    assert d["seven_day"]["reading_age_min"] >= 70, "with its age"
    assert d["seven_day"]["projected_at_reset"] is None, "but nothing is projected from it"


def test_a_future_dated_reading_is_refused_rather_than_treated_as_fresh(tmp_path: Path) -> None:
    """A negative age passes an ``age -gt max`` staleness test unconditionally, so the guard against a
    dead publisher would be disarmed while still looking present. Measured during development: a
    reading written 90 seconds earlier reported as 299 minutes in the future — exactly this machine's
    UTC offset, from stringifying a value ``ConvertFrom-Json`` had already typed as a UTC datetime."""
    publish(tmp_path, seven=71.0, age_min=-120)
    code, d = read(tmp_path)
    assert code == UNKNOWN
    assert "FUTURE" in d["seven_day"]["reason"].upper()


@pytest.mark.parametrize(
    ("pct", "minutes_ahead", "code"),
    [
        pytest.param(99.0, 1.0, CRITICAL, id="ceiling-one-minute-ahead"),
        pytest.param(99.0, 0.5, CRITICAL, id="ceiling-thirty-seconds-ahead"),
        pytest.param(99.0, 120.0, CRITICAL, id="ceiling-two-hours-ahead"),
        pytest.param(92.0, 1.0, UNKNOWN, id="at-the-gates-level"),
        pytest.param(50.0, 1.0, UNKNOWN, id="below-the-rung"),
    ],
)
def test_a_reading_dated_after_now_is_unknown_and_keeps_its_floor(
    tmp_path: Path, pct: float, minutes_ahead: float, code: int
) -> None:
    """It is not fresh, so its own state is UNKNOWN and nothing clears on it. But a small backward clock
    step dates a real reading ahead, and a stop must not lapse on one, so its number stands as a floor. No
    stamp here: a fresh reading's level hit stands on any provenance, so this does too."""
    publish(tmp_path, seven=pct, age_min=-minutes_ahead)
    got, doc = read(tmp_path)
    assert got == code, doc
    window_doc = doc["seven_day"]
    assert window_doc["state"] == "UNKNOWN" and "FUTURE" in window_doc["reason"], doc
    assert window_doc["level_floor"] == pct, doc
    assert window_doc["rate_pct_per_hr"] is None, doc


def test_a_reading_dated_after_now_with_no_reset_keeps_its_floor(tmp_path: Path) -> None:
    """A fresh reading at the rung hits with no reset, because a missing reset must not loosen the rung."""
    publish(tmp_path, seven=99.0, age_min=-1)
    doc = latest(tmp_path)
    del doc["seven_day"]["resets_at_epoch"]
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    assert read(tmp_path)[1]["seven_day"]["level_floor"] == 99.0


def test_a_burn_dated_after_now_stays_critical_and_never_reads_ok(tmp_path: Path) -> None:
    """The reviewer's case: 30, 40, then 50 one minute ahead, with a reset near enough for the rate to
    decide. Dropping the row read OK at 10 percent an hour."""
    epoch = int(time.time()) + 14400
    publish(tmp_path, seven=50.0, age_min=-1, seven_epoch=epoch)
    write_history(tmp_path, [(60, 30.0), (30, 40.0), (-1, 50.0)], epoch)
    code, doc = read(tmp_path)
    assert code == CRITICAL and doc["seven_day"]["state"] == "CRITICAL", doc
    assert doc["seven_day"]["rate_pct_per_hr"] == pytest.approx(20.0, abs=0.5), doc
    assert doc["seven_day"]["level_floor"] == 50.0 and "FUTURE" in doc["seven_day"]["reason"], doc


def test_a_stale_reading_with_its_reset_ahead_is_a_floor_and_nothing_else_is(
    tmp_path: Path,
) -> None:
    """The gate may HALT on level_floor, so only a reading that was once true and whose window is
    still running may carry it. No reset proves no window, for a reading that is only stale. A reading
    dated after now keeps one: test_a_reading_dated_after_now_is_unknown_and_keeps_its_floor."""
    assert _floor(tmp_path, seven=95.0, age_min=75) == pytest.approx(95.0)
    assert _floor(tmp_path, seven=95.0) is None, "a fresh reading is no floor"

    publish(tmp_path, seven=95.0, age_min=75)
    _stamp(tmp_path, tmp_path.parent)
    doc = latest(tmp_path)
    del doc["seven_day"]["resets_at_epoch"]
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    assert read(tmp_path)[1]["seven_day"]["level_floor"] is None, "no reset proves no window"


@pytest.mark.parametrize(
    ("doc_root", "window_root"),
    [
        pytest.param(None, None, id="no-stamp"),
        pytest.param("unset", "unset", id="unset"),
        pytest.param("own", "unset", id="window-unset"),
        pytest.param("unset", "own", id="document-unset"),
    ],
)
def test_a_stale_reading_with_unverified_provenance_is_no_floor(
    tmp_path: Path, doc_root: str | None, window_root: str | None
) -> None:
    """Halting until the reset on a number this reader cannot tie to this account is too long a
    deferral. Such a reading answers REVIEW, as it did before the floor."""
    publish(tmp_path, seven=95.0, age_min=75)
    own = str(tmp_path.parent)
    doc = latest(tmp_path)
    if doc_root:
        doc["published_by"]["config_root_env"] = own if doc_root == "own" else doc_root
    if window_root:
        doc["seven_day"]["config_root_env"] = own if window_root == "own" else window_root
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    assert read(tmp_path)[1]["seven_day"]["level_floor"] is None


@pytest.mark.parametrize(
    ("pct", "expected"),
    [
        pytest.param(97.9, None, id="just-below-the-ceiling"),
        pytest.param(98.0, 98.0, id="the-ceiling"),
        pytest.param(100.0, 100.0, id="spent"),
    ],
)
def test_at_the_ceiling_unverified_provenance_still_leaves_a_floor(
    tmp_path: Path, pct: float, expected: float | None
) -> None:
    """A fresh reading at the ceiling stops work on any provenance, and an idle session's equal reading
    does not refresh its age, so without this the stop would decay on an unchanged number."""
    publish(tmp_path, seven=pct, age_min=21)
    assert read(tmp_path)[1]["seven_day"]["level_floor"] == expected


def test_the_ceiling_floor_keeps_the_other_bounds(tmp_path: Path) -> None:
    """Provenance is the only test the ceiling drops. A fresh, gone or over-long reading still sets
    nothing, and a window stamped with another root is still refused."""
    publish(tmp_path, seven=100.0)
    assert read(tmp_path)[1]["seven_day"]["level_floor"] is None, "fresh"
    publish(tmp_path, seven=100.0, age_min=75, seven_epoch=int(time.time()) + 10050 * 60)
    assert read(tmp_path)[1]["seven_day"]["level_floor"] is None, "does not fit a week"
    publish(tmp_path, seven=100.0, age_min=75, seven_epoch=int(time.time()) - 60)
    assert read(tmp_path)[1]["seven_day"].get("level_floor") is None, "reset passed"
    publish(tmp_path, seven=100.0, age_min=-1, seven_epoch=int(time.time()) - 60)
    assert read(tmp_path)[1]["seven_day"].get("level_floor") is None, "dated ahead, reset passed"

    publish(tmp_path, seven=100.0, age_min=75)
    doc = latest(tmp_path)
    doc["seven_day"]["config_root_env"] = str(tmp_path.parent / "another-root")
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    assert read(tmp_path)[1]["seven_day"].get("level_floor") is None, "another root's window"


def _age_window(state: Path, minutes: float) -> None:
    doc = latest(state)
    doc["seven_day"]["captured_at"] = _minutes_ago(minutes)
    (state / "latest.json").write_text(json.dumps(doc), encoding="utf-8")


def _session_fire(
    state: Path, seven: dict[str, Any], session: str = "S", api_ms: float | str | None = None
) -> None:
    payload: dict[str, Any] = {"session_id": session, "rate_limits": {"seven_day": seven}}
    if api_ms is not None:
        payload["cost"] = {"total_api_duration_ms": api_ms}
    collect(state, payload)


def _mark(state: Path, session: str = "S") -> Path:
    return state / "live-marks" / f"mark-{session}.json"


def _age_min(state: Path) -> float:
    return (datetime.now(UTC) - captured_at(state)).total_seconds() / 60


def _marks(state: Path) -> list[Path]:
    """Every file under the state directory that holds a mark, wherever the collector puts it."""
    return [p for p in state.rglob("*") if p.is_file() and "mark" in p.name]


def test_a_session_that_called_the_api_confirms_an_equal_reading(tmp_path: Path) -> None:
    """A healthy live flat account stays fresh. An idle session's repeat, the same counter, does not."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    _age_window(tmp_path, 25)

    _session_fire(tmp_path, seven, api_ms=1000)
    code, doc = read(tmp_path)
    assert code == UNKNOWN and doc["seven_day"]["reading_age_min"] >= 24, "control: an idle repeat"

    _session_fire(tmp_path, seven, api_ms=2000)
    code, doc = read(tmp_path)
    assert code == 0 and doc["seven_day"]["reading_age_min"] < 5, doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(40.0)
    assert len(history(tmp_path)) == 1, "a confirmation is not a new observation of a moved number"


def _confirm_refused_case(state: Path, case: str) -> None:
    """Drive one fire that must leave the age counting; the window starts 25 minutes old at 40."""
    seven = window(40.0, 280000)
    _session_fire(state, seven, api_ms=1000)
    _age_window(state, 25)
    if case == "first-fire-of-a-session":
        _session_fire(state, seven, session="T", api_ms=5000)
    elif case == "another-sessions-counter":
        _session_fire(state, seven, session="T", api_ms=1000)
        _session_fire(state, seven, session="U", api_ms=2000)
    elif case == "no-counter":
        _session_fire(state, seven)
    elif case == "counter-fell":
        _session_fire(state, seven, api_ms=500)
    elif case == "counter-fell-and-came-back":
        _session_fire(state, seven, api_ms=500)
        _session_fire(state, seven, api_ms=1000)
    elif case == "two-processes-on-one-id":
        for api_ms in (7000, 5000, 7000, 5000, 7000):
            _session_fire(state, seven, api_ms=api_ms)
        _age_window(state, 25)
        for api_ms in (5000, 7000):
            _session_fire(state, seven, api_ms=api_ms)
    elif case == "lower-number":
        _session_fire(state, {**seven, "used_percentage": 30.0}, api_ms=2000)
    elif case == "unreadable-mark":
        _mark(state).write_text("{ not json", encoding="utf-8")
        _session_fire(state, seven, api_ms=2000)
    elif case == "missing-mark":
        _mark(state).unlink()
        _session_fire(state, seven, api_ms=2000)
    elif case == "mark-with-no-counter":
        _mark(state).write_text('{"at": 1}', encoding="utf-8")
        _session_fire(state, seven, api_ms=2000)
    elif case == "mark-with-a-blank-counter":
        _mark(state).write_text('{"api_ms": ""}', encoding="utf-8")
        _session_fire(state, seven, api_ms=2000)
    elif case == "payload-with-a-blank-counter":
        _session_fire(state, seven, session="T", api_ms="")
        _session_fire(state, seven, session="T", api_ms=2000)
    else:
        raise AssertionError(case)


@pytest.mark.parametrize(
    "case",
    [
        "first-fire-of-a-session",
        "another-sessions-counter",
        "no-counter",
        "counter-fell",
        "counter-fell-and-came-back",
        "two-processes-on-one-id",
        "lower-number",
        "unreadable-mark",
        "missing-mark",
        "mark-with-no-counter",
        "mark-with-a-blank-counter",
        "payload-with-a-blank-counter",
    ],
)
def test_nothing_else_confirms_an_equal_reading(tmp_path: Path, case: str) -> None:
    _confirm_refused_case(tmp_path, case)
    code, doc = read(tmp_path)
    assert code == UNKNOWN and doc["seven_day"]["reading_age_min"] >= 24, doc


def test_a_mark_that_cannot_be_written_leaves_the_age_counting(tmp_path: Path) -> None:
    """If the write fails, the mark keeps the old counter, so every idle repeat would read as a rise and
    a frozen number would stay fresh for good. A read-only mark makes the real rename fail. The control
    is the same fire with the write working again."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    _age_window(tmp_path, 25)
    marks = _marks(tmp_path)
    assert marks, "the first fire left no mark to hold read-only"
    for mark in marks:
        mark.chmod(stat.S_IREAD)
    try:
        _session_fire(tmp_path, seven, api_ms=2000)
        assert _age_min(tmp_path) > 24, "a rise whose mark was lost confirmed the reading"
        _session_fire(tmp_path, seven, api_ms=2000)
        assert _age_min(tmp_path) > 24, "an idle repeat confirmed the reading"
    finally:
        for mark in marks:
            mark.chmod(stat.S_IREAD | stat.S_IWRITE)
    _session_fire(tmp_path, seven, api_ms=3000)
    assert _age_min(tmp_path) < 5, "control: with the write working, a rise confirms"


def test_a_blocked_mark_directory_costs_the_refresh_and_not_the_publish(tmp_path: Path) -> None:
    """The directory cannot be made, so the mark write throws. That must not reach the outer catch and
    cost the session its reading."""
    (tmp_path / "live-marks").write_text("in the way", encoding="utf-8")
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    _age_window(tmp_path, 25)
    line = collect(
        tmp_path,
        {
            "session_id": "S",
            "cost": {"total_api_duration_ms": 2000},
            "rate_limits": {"seven_day": seven},
        },
    )
    assert line.startswith("7d 40%"), line
    assert _age_min(tmp_path) > 24, "a rise with no mark confirmed the reading"
    _session_fire(tmp_path, {**seven, "used_percentage": 41.0}, api_ms=3000)
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(41.0)


def test_one_sessions_late_write_cannot_restore_another_sessions_mark(tmp_path: Path) -> None:
    """The race on one shared file, made deterministic: T's write lands after S has recorded a rise. If
    both sessions shared a file, that write would put S's older counter back, and S's idle repeat would
    then read as a rise."""
    seven = window(40.0, 280000)
    other = "44444444-aaaa-4bbb-8ccc-000000000004"
    _session_fire(tmp_path, seven, api_ms=1000)
    before = {p: p.read_bytes() for p in _marks(tmp_path)}
    _session_fire(tmp_path, seven, session=other, api_ms=7000)
    late = {p: p.read_bytes() for p in _marks(tmp_path) if before.get(p) != p.read_bytes()}
    assert late, "control: the other session's fire wrote nothing"

    _session_fire(tmp_path, seven, api_ms=2000)
    for path, content in late.items():
        path.write_bytes(content)
    _age_window(tmp_path, 25)
    _session_fire(tmp_path, seven, api_ms=2000)
    assert _age_min(tmp_path) > 24, "an idle repeat read as a rise"


def test_two_sessions_keep_their_own_marks(tmp_path: Path) -> None:
    """Each session has one file and writes no other. Neither fire disturbs the other's counter."""
    seven = window(40.0, 280000)
    other = "44444444-aaaa-4bbb-8ccc-000000000004"
    _session_fire(tmp_path, seven, api_ms=1000)
    _session_fire(tmp_path, seven, session=other, api_ms=7000)
    held = _mark(tmp_path, other).read_bytes()

    _session_fire(tmp_path, seven, api_ms=2000)
    assert _mark(tmp_path, other).read_bytes() == held
    assert json.loads(_mark(tmp_path).read_text(encoding="utf-8"))["api_ms"] == 2000

    _session_fire(tmp_path, seven, session=other, api_ms=8000)
    assert json.loads(_mark(tmp_path).read_text(encoding="utf-8"))["api_ms"] == 2000
    assert json.loads(_mark(tmp_path, other).read_text(encoding="utf-8"))["api_ms"] == 8000


@pytest.mark.parametrize(
    "session",
    [
        pytest.param("a/../../escaped", id="interior-forward"),
        pytest.param("a\\..\\..\\escaped", id="interior-back"),
        pytest.param("a:stream", id="alternate-stream"),
        pytest.param("..", id="parent"),
        pytest.param("name.with.dots", id="dots"),
        pytest.param("x" * 129, id="too-long"),
    ],
)
def test_a_session_id_that_is_not_a_plain_name_writes_no_mark(tmp_path: Path, session: str) -> None:
    """The id comes from a JSON payload and names a file. An id that is not a plain name is refused
    rather than cleaned up, because two ids cleaned to one name would share a mark. The file name is
    prefixed, so an id must hold an interior segment to climb out; each case here does write a file with
    the test removed."""
    state = tmp_path / "root" / "mefor-usage"
    state.mkdir(parents=True)
    seven = window(40.0, 280000)
    _session_fire(state, seven, session=session, api_ms=1000)
    _age_window(state, 25)
    _session_fire(state, seven, session=session, api_ms=2000)
    assert _age_min(state) > 24, "a refused id cannot prove a rise"
    written = {p.relative_to(tmp_path).as_posix() for p in tmp_path.rglob("*") if p.is_file()}
    assert written == {"root/mefor-usage/latest.json", "root/mefor-usage/history.jsonl"}, written


@pytest.mark.parametrize(
    "damaged",
    [
        pytest.param("{ not json", id="not-json"),
        pytest.param('{"at": 1}', id="no-counter"),
        pytest.param('{"api_ms": ""}', id="blank-counter"),
        pytest.param('{"api_ms": NaN}', id="not-finite"),
    ],
)
def test_a_mark_that_cannot_be_read_is_not_replaced(tmp_path: Path, damaged: str) -> None:
    """It may hide a higher counter, so a lower one must not replace it: the process holding the higher
    counter would then read its own idle repeat as a rise."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=8000)
    _mark(tmp_path).write_text(damaged, encoding="utf-8")
    _age_window(tmp_path, 25)

    _session_fire(tmp_path, seven, api_ms=5000)
    assert _mark(tmp_path).read_text(encoding="utf-8") == damaged, "the mark was replaced"
    _session_fire(tmp_path, seven, api_ms=8000)
    assert _mark(tmp_path).read_text(encoding="utf-8") == damaged, "the mark was replaced"
    assert _age_min(tmp_path) > 24, "an idle repeat read as a rise"


def test_a_mark_the_read_fails_on_is_not_replaced(tmp_path: Path) -> None:
    """The failed-read route: a good mark at 8000, its read denied, while replacing it still works
    (measured). Nothing here says the counter is lower, so the 5000 must not land."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=8000)
    _age_window(tmp_path, 25)
    mark = str(_mark(tmp_path))
    user = os.environ["USERNAME"]
    subprocess.run(["icacls", mark, "/deny", f"{user}:(RD)"], capture_output=True, check=True)
    try:
        _session_fire(tmp_path, seven, api_ms=5000)
    finally:
        subprocess.run(["icacls", mark, "/reset"], capture_output=True, check=True)
    assert json.loads(_mark(tmp_path).read_text(encoding="utf-8"))["api_ms"] == 8000
    _session_fire(tmp_path, seven, api_ms=8000)
    assert _age_min(tmp_path) > 24, "an idle repeat read as a rise"


def test_a_prune_clears_an_unreadable_mark_and_the_session_recovers(tmp_path: Path) -> None:
    """A file holding no number does not mend itself. At least a read that works again or a hand delete
    also ends an unreadable mark; this is the route the collector takes itself."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    _mark(tmp_path).write_text("{ not json", encoding="utf-8")
    eight_days_ago = time.time() - 8 * 86400
    os.utime(_mark(tmp_path), (eight_days_ago, eight_days_ago))

    _session_fire(tmp_path, seven, session="new", api_ms=1000)
    assert not _mark(tmp_path).exists()
    _session_fire(tmp_path, seven, api_ms=2000)
    _age_window(tmp_path, 25)
    _session_fire(tmp_path, seven, api_ms=3000)
    assert _age_min(tmp_path) < 5, "control: a new mark confirms a rise again"


def test_a_new_session_clears_marks_nobody_touched_for_a_week(tmp_path: Path) -> None:
    """One file per session has no other bound. An old mark's loss costs that session one refresh."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    old, recent = _mark(tmp_path, "old"), _mark(tmp_path, "recent")
    other = tmp_path / "live-marks" / "note.txt"
    for path in (old, recent, other):
        path.write_text('{"api_ms": 5}', encoding="utf-8")
    eight_days_ago = time.time() - 8 * 86400
    os.utime(old, (eight_days_ago, eight_days_ago))
    os.utime(other, (eight_days_ago, eight_days_ago))

    _session_fire(tmp_path, seven, api_ms=2000)
    assert old.exists(), "control: a session's later fires prune nothing"

    _session_fire(tmp_path, seven, session="new", api_ms=1000)
    assert not old.exists()
    assert recent.exists() and other.exists() and _mark(tmp_path).exists()


@pytest.mark.parametrize(
    "missing",
    [pytest.param(None, id="absent"), pytest.param("", id="blank")],
)
def test_a_published_window_with_no_number_is_not_a_reading_of_zero(
    tmp_path: Path, missing: str | None
) -> None:
    """A published window with no percentage must not compare as 0. A live 0 for the same reset would
    otherwise be kept, its age refreshed, over a window with no number in it."""
    seven = window(0.0, 280000)
    _session_fire(tmp_path, seven, api_ms=1000)
    doc = latest(tmp_path)
    if missing is None:
        del doc["seven_day"]["used_percentage"]
    else:
        doc["seven_day"]["used_percentage"] = missing
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    _age_window(tmp_path, 25)

    _session_fire(tmp_path, seven, api_ms=2000)
    assert latest(tmp_path)["seven_day"]["used_percentage"] == 0, latest(tmp_path)


@pytest.mark.parametrize(
    "missing",
    [
        pytest.param(None, id="absent"),
        pytest.param("", id="blank"),
        pytest.param(True, id="bool"),
        pytest.param("abc", id="text"),
        pytest.param("NaN", id="nan-string"),
        pytest.param("Infinity", id="infinity-string"),
        pytest.param("-5", id="negative-string"),
        pytest.param(-5, id="negative"),
        pytest.param(-0.1, id="just-below-zero"),
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="infinity"),
        pytest.param(float("-inf"), id="negative-infinity"),
        pytest.param({}, id="object"),
        pytest.param([], id="empty-array"),
        pytest.param([95], id="one-element-array"),
        pytest.param([1, 2], id="array"),
        pytest.param("2026-11-02T10:00:00Z", id="date-string"),
    ],
)
def test_the_reader_does_not_turn_a_window_with_no_number_into_a_zero(
    tmp_path: Path, missing: Any
) -> None:
    """Fresh, stamped and with its reset ahead, so nothing but the number is wrong. Each of these read
    OK or a 0, and NaN cleared the gate. The survey prints no number either."""
    publish(tmp_path, seven=40.0)
    doc = latest(tmp_path)
    if missing is None:
        del doc["seven_day"]["used_percentage"]
    else:
        doc["seven_day"]["used_percentage"] = missing
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    code, got = read(tmp_path)
    assert code == UNKNOWN and got["state"] == "UNKNOWN", got
    assert got["seven_day"]["used_percentage"] is None, got
    assert "carries no percentage" in got["seven_day"]["reason"], got


def test_the_survey_prints_no_number_for_a_window_with_none(fake_home: Path) -> None:
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    publish(state, seven=40.0)
    doc = latest(state)
    del doc["seven_day"]["used_percentage"]
    (state / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    _, got, _ = reader("-Json", "-AllRoots", pin=pin, home=fake_home)
    row = next(r for r in got["roots"] if r["root"].endswith(".claude-account-1"))
    assert row["seven"] is None, row


@pytest.mark.parametrize(
    "value",
    [
        pytest.param("", id="blank"),
        pytest.param("abc", id="text"),
        pytest.param("99%", id="percent-sign"),
        pytest.param("-5", id="negative-string"),
        pytest.param(-5, id="negative"),
    ],
)
def test_a_percentage_that_is_not_one_is_no_reading(tmp_path: Path, value: Any) -> None:
    """An absent window is carried, and one with no percentage in it is absent. The control is that
    nothing replaced the reading, and the empty directory below publishes nothing at all."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven)
    _session_fire(tmp_path, {**window(0.0, 290000), "used_percentage": value})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(40.0)
    assert len(history(tmp_path)) == 1, history(tmp_path)

    empty = tmp_path / "empty"
    empty.mkdir()
    _session_fire(empty, {**window(0.0, 290000), "used_percentage": value})
    assert not (empty / "latest.json").exists()


@pytest.mark.parametrize(
    ("text", "number"),
    [pytest.param("99", 99.0, id="whole"), pytest.param("99.5", 99.5, id="decimal")],
)
def test_a_numeric_string_in_a_payload_is_a_reading(
    tmp_path: Path, text: str, number: float
) -> None:
    """Dropping it would leave a lower reading published and fresh. It is published as a number."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven)
    _session_fire(tmp_path, {**seven, "used_percentage": text})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(number)
    assert history(tmp_path)[-1]["seven_day"] == pytest.approx(number), history(tmp_path)


def test_a_numeric_string_in_the_document_keeps_its_verdict(tmp_path: Path) -> None:
    publish(tmp_path, seven=40.0)
    doc = latest(tmp_path)
    doc["seven_day"]["used_percentage"] = "99"
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    code, got = read(tmp_path)
    assert code == CRITICAL and got["seven_day"]["used_percentage"] == pytest.approx(99.0), got


def test_a_published_numeric_string_still_binds_the_reset(tmp_path: Path) -> None:
    """The highest reading binds, so a lower one for the same reset does not replace it."""
    seven = window(40.0, 280000)
    _session_fire(tmp_path, seven)
    doc = latest(tmp_path)
    doc["seven_day"]["used_percentage"] = "99"
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    _session_fire(tmp_path, seven)
    assert latest(tmp_path)["seven_day"]["used_percentage"] == "99"


def test_a_reading_over_100_stays_a_number_and_keeps_the_stop(tmp_path: Path) -> None:
    """The client clamps this window at 100 today, and the clamp is the client's. Refusing 104 would turn
    a spent pool into UNKNOWN, so it reads as the stop it is."""
    collect(tmp_path, {"session_id": "S", "rate_limits": {"seven_day": window(104.0, 280000)}})
    assert latest(tmp_path)["seven_day"]["used_percentage"] == pytest.approx(104.0)
    code, doc = read(tmp_path)
    assert code == CRITICAL and doc["seven_day"]["used_percentage"] == pytest.approx(104.0), doc


@pytest.mark.parametrize(
    ("ahead_pct", "highest"),
    [
        pytest.param(20.0, 40.0, id="a-low-row-cannot-turn-the-rate-negative"),
        pytest.param(50.0, 50.0, id="a-high-row-stays-in-the-rate"),
    ],
)
@pytest.mark.parametrize("minutes_ahead", [5.0, 1.0], ids=["five-minutes", "one-minute"])
def test_a_history_row_dated_after_now_stays_in_the_rate(
    tmp_path: Path, minutes_ahead: float, ahead_pct: float, highest: float
) -> None:
    """Beside a fresh reading, which is what a live confirmation leaves after a backward clock step. The
    span keeps the row's own date, and the highest percentage is the level reached."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=50.0, seven_epoch=epoch)
    write_history(tmp_path, [(60.0, 30.0), (30.0, 40.0), (-minutes_ahead, ahead_pct)], epoch)
    _, doc = read(tmp_path)
    rate = (highest - 30.0) / ((60.0 + minutes_ahead) / 60.0)
    assert doc["seven_day"]["rate_pct_per_hr"] == pytest.approx(rate, abs=0.5), doc


def test_rows_all_dated_after_now_still_give_a_rate(tmp_path: Path) -> None:
    """Clamping both to 0 left no span and no rate, so a burn read OK where main stops."""
    epoch = int(time.time()) + 14400
    publish(tmp_path, seven=70.0, seven_epoch=epoch)
    write_history(tmp_path, [(-1.0, 40.0), (-16.0, 70.0)], epoch)
    code, doc = read(tmp_path)
    assert code == CRITICAL and doc["seven_day"]["rate_pct_per_hr"] == pytest.approx(120, abs=1), (
        doc
    )


def test_a_burn_dated_after_now_with_no_reset_stays_critical(tmp_path: Path) -> None:
    """No reset to run out before, so the band alone would clear the rate, and the floor of 70 sits below
    the rung. A missing reset must not loosen the rung."""
    publish(tmp_path, seven=70.0, age_min=-1)
    doc = latest(tmp_path)
    del doc["seven_day"]["resets_at_epoch"]
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")
    now = int(time.time())
    write_history(tmp_path, [(15.0, 40.0), (-1.0, 70.0)], now)
    code, got = read(tmp_path)
    assert code == CRITICAL and got["seven_day"]["state"] == "CRITICAL", got
    assert got["seven_day"]["minutes_to_empty"] is not None, got
    assert "FUTURE" in got["seven_day"]["reason"] and got["seven_day"]["dated_ahead"] is True, got


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(float("nan"), id="nan"),
        pytest.param(float("inf"), id="infinity"),
        pytest.param("", id="blank"),
        pytest.param(True, id="bool"),
        pytest.param(-5, id="negative"),
        pytest.param({}, id="object"),
    ],
)
def test_a_history_row_with_no_number_is_skipped(tmp_path: Path, bad: Any) -> None:
    """At either end of the span. A NaN row used to read OK and clear a burn, and a blank one faked a
    burn from 0. The control is the same history without the bad rows: the answer must match it."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=40.0, seven_epoch=epoch)

    def rows(points: list[tuple[float, Any]]) -> None:
        (tmp_path / "history.jsonl").write_text(
            "".join(
                json.dumps({"at": _minutes_ago(m), "seven_day": v, "seven_reset": epoch}) + "\n"
                for m, v in points
            ),
            encoding="utf-8",
        )

    good: list[tuple[float, Any]] = [(60, 30.0), (30, 40.0)]
    rows(good)
    want_code, want = read(tmp_path)
    assert want["seven_day"]["rate_pct_per_hr"] == pytest.approx(20.0, abs=0.5), want
    rows([(80, bad), *good, (1, bad)])
    got_code, got = read(tmp_path)
    assert got_code == want_code, got
    assert got["seven_day"]["rate_pct_per_hr"] == pytest.approx(
        want["seven_day"]["rate_pct_per_hr"], abs=0.5
    ), got


def test_every_copy_of_a_number_rule_agrees() -> None:
    """Copies of one rule in three files that must each survive without the others, so drift goes red
    here."""
    hook = ROOT / "scripts" / "hooks" / "usage-headroom-inject.ps1"
    for name, paths in (("Get-Finite", (COLLECT, READ, hook)), ("Get-Percentage", (COLLECT, READ))):
        body = re.compile(rf"^function {name}\(\$Value\) \{{$.*?^\}}$", re.M | re.S)
        copies = set()
        for path in paths:
            found = body.search(path.read_text(encoding="utf-8"))
            assert found, f"no {name} in {path}"
            copies.add(found.group())
        assert len(copies) == 1, copies


def test_a_session_of_another_root_cannot_confirm_this_roots_reading(tmp_path: Path) -> None:
    root = tmp_path / "this-root"
    state = root / "mefor-usage"
    state.mkdir(parents=True)
    seven = window(40.0, 280000)
    _session_fire(state, seven, api_ms=1000)
    _age_window(state, 25)
    payload = {
        "session_id": "S",
        "cost": {"total_api_duration_ms": 2000},
        "rate_limits": {"seven_day": seven},
    }
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(COLLECT), "-StateDir", str(state)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(tmp_path / "other-root"),
    )
    assert proc.returncode == 0, proc.stderr
    assert datetime.now(UTC) - captured_at(state) > timedelta(minutes=24)


def test_a_gone_window_cannot_be_confirmed(tmp_path: Path) -> None:
    seven = window(40.0, -300)
    _session_fire(tmp_path, seven, api_ms=1000)
    _age_window(tmp_path, 25)
    _session_fire(tmp_path, seven, api_ms=2000)
    assert datetime.now(UTC) - captured_at(tmp_path) > timedelta(minutes=24)


@pytest.mark.parametrize(
    ("pct", "stamped", "code", "state", "floor"),
    [
        pytest.param(100.0, False, CRITICAL, "CRITICAL", 100.0, id="spent-unstamped"),
        pytest.param(98.0, True, CRITICAL, "CRITICAL", 98.0, id="ceiling-stamped"),
        pytest.param(97.9, True, UNKNOWN, "UNKNOWN", 97.9, id="just-below-the-ceiling"),
        pytest.param(90.0, True, UNKNOWN, "UNKNOWN", 90.0, id="at-the-gates-level"),
        pytest.param(85.0, True, UNKNOWN, "UNKNOWN", 85.0, id="fresh-warn-band"),
        pytest.param(84.9, True, UNKNOWN, "UNKNOWN", 84.9, id="below-the-band"),
        pytest.param(90.0, False, UNKNOWN, "UNKNOWN", None, id="high-with-no-floor"),
    ],
)
def test_only_a_floor_at_the_ceiling_sets_the_verdict(
    tmp_path: Path, pct: float, stamped: bool, code: int, state: str, floor: float | None
) -> None:
    """The header promises exit 11 at the ceiling. Below it the number is only a lower bound, so the
    verdict stays UNKNOWN (exit 20), while level_floor still carries it to the gate; test_afk_gate holds
    the gate to it. The window's own state is UNKNOWN throughout, which is what the gate reads below the
    rung."""
    publish(tmp_path, seven=pct, age_min=25)
    if stamped:
        _stamp(tmp_path, tmp_path.parent)
    got, doc = read(tmp_path)
    assert (got, doc["state"]) == (code, state), doc
    assert doc["seven_day"]["state"] == "UNKNOWN", doc
    assert doc["seven_day"]["level_floor"] == floor, doc
    assert ("COMMIT NOW" in doc["advice"]) == (state == "CRITICAL"), doc


def test_a_root_wired_elsewhere_gets_no_floor_and_a_wired_one_does(fake_home: Path) -> None:
    pin = fake_home / ".claude-account-1"
    publish(pin / "mefor-usage", seven=95.0, age_min=75)
    _stamp(pin / "mefor-usage", pin)
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["seven_day"]["level_floor"] is None, "an unwired root's reading is no floor"

    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["seven_day"]["level_floor"] == pytest.approx(95.0), "control: wired, it is one"


@pytest.mark.parametrize(
    ("state_name", "settings"),
    [
        pytest.param("SETTINGS_UNREADABLE", "{ not json", id="settings-unreadable"),
        pytest.param("WIRED_POWERSHELL_SOURCE", None, id="powershell-source"),
    ],
)
def test_a_diagnosis_off_the_untrusted_list_keeps_a_floor_it_cannot_correct(
    fake_home: Path, state_name: str, settings: str | None
) -> None:
    """ADR 0211 states this as a limit: neither state proves the root is wired here, and the floor
    stands anyway. If either joins $dxUntrusted, this fails and that sentence has to go."""
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    publish(state, seven=95.0, age_min=75)
    _stamp(state, pin)
    command = _powershell_source_command(COLLECT, state)
    text = settings or json.dumps({"statusLine": {"type": "command", "command": command}})
    (pin / "settings.json").write_text(text, encoding="utf-8")
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == state_name, doc
    assert doc["seven_day"]["level_floor"] == pytest.approx(95.0), doc


@pytest.mark.parametrize(
    ("resets_in_min", "expected"),
    [
        pytest.param(9000, 95.0, id="fits-a-week"),
        pytest.param(10050, None, id="age-plus-reset-past-a-week"),
        pytest.param(43200, None, id="reset-a-month-ahead"),
    ],
)
def test_no_floor_outlasts_the_seven_day_window(
    tmp_path: Path, resets_in_min: int, expected: float | None
) -> None:
    """A reading 75 minutes old cannot belong to a 7-day window that ends more than 6 days and 22
    hours away. Without this bound a wrong floor could hold for as long as its reset says."""
    epoch = int(time.time()) + resets_in_min * 60
    assert _floor(tmp_path, seven=95.0, age_min=75, seven_epoch=epoch) == expected


def test_a_never_published_window_is_unknown_not_zero(tmp_path: Path) -> None:
    publish(tmp_path, seven=None)
    code, d = read(tmp_path)
    assert code == UNKNOWN
    assert d["seven_day"]["state"] == "UNKNOWN"
    assert d["seven_day"]["used_percentage"] is None, "absent must not render as 0% used"


def test_burning_faster_than_the_window_resets_is_critical(tmp_path: Path) -> None:
    """The operational question is not 'is the number big' but 'does it run out before it resets'."""
    epoch = int(time.time()) + 3600
    publish(tmp_path, seven=71.0, seven_epoch=epoch)
    write_history(tmp_path, [(60, 40.0), (40, 52.0), (20, 64.0), (1, 71.0)], epoch)

    code, d = read(tmp_path)
    assert code == CRITICAL
    assert d["seven_day"]["rate_pct_per_hr"] > 20
    assert 0 < d["seven_day"]["minutes_to_empty"] < 60, "must run out before the window resets"
    gap = d["seven_day"]["minutes_to_reset"] - d["seven_day"]["minutes_to_empty"]
    assert f"{gap:.0f} min before this window resets" in d["seven_day"]["reason"], d


def test_a_high_but_stable_reading_is_not_critical(tmp_path: Path) -> None:
    """85% with nothing being consumed is not an emergency, and calling it one is how a warning gets
    ignored when it is real."""
    epoch = int(time.time()) + 3600
    publish(tmp_path, seven=86.0, seven_epoch=epoch)
    write_history(tmp_path, [(60, 86.0), (30, 86.0), (1, 86.0)], epoch)

    code, d = read(tmp_path)
    assert code == WARN
    assert d["seven_day"]["minutes_to_empty"] is None, "a flat rate cannot project exhaustion"


def test_a_burn_that_stopped_still_reads_as_a_burn_until_its_rows_age_out(tmp_path: Path) -> None:
    """The span ends at the newest row, so the flat time since then does not dilute the rate. It can
    stop work on a pool that has room, and a false stop is the safe direction. Ending the span at now
    let a real burn read as clear: a fresh 80 with rows at 85 and 70 minutes ago and 60 minutes to the
    reset. The rows here are that case."""
    epoch = int(time.time()) + 3600
    publish(tmp_path, seven=80.0, seven_epoch=epoch)
    write_history(tmp_path, [(85, 55.0), (70, 80.0)], epoch)

    code, d = read(tmp_path)
    assert code == CRITICAL, d
    assert d["seven_day"]["rate_pct_per_hr"] == pytest.approx(100.0, abs=0.5), d
    assert d["seven_day"]["minutes_to_empty"] == pytest.approx(12.0, abs=1), d


@pytest.mark.parametrize(
    ("older", "newer", "rate"),
    [
        pytest.param((4.0, 85.0), (0.1, 86.0), 15.4, id="over-four-minutes"),
        pytest.param((0.5, 85.0), (0.02, 86.0), 120.0, id="seconds-apart"),
    ],
)
def test_one_tick_is_a_rate_however_close_the_rows(
    tmp_path: Path, older: tuple[float, float], newer: tuple[float, float], rate: float
) -> None:
    """The weekly prints whole numbers, so a tick can be quantisation, and this can stop work on a pool
    that has room. A false stop is the safe direction, and a minimum span read a real burn as clear."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=86.0, seven_epoch=epoch)
    write_history(tmp_path, [older, newer], epoch)
    code, d = read(tmp_path)
    assert code == CRITICAL, d
    assert d["seven_day"]["rate_pct_per_hr"] == pytest.approx(rate, rel=0.15), d


def test_a_fast_burn_is_a_rate(tmp_path: Path) -> None:
    """40 to 84 in 25 minutes is the burn a stop exists for, and the level alone would grade it clear."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=84.0, seven_epoch=epoch)
    write_history(tmp_path, [(25, 40.0), (15, 60.0), (5, 80.0), (0.5, 84.0)], epoch)
    code, d = read(tmp_path)
    assert code == CRITICAL, d
    assert d["seven_day"]["rate_pct_per_hr"] == pytest.approx(107.8, abs=2), d


def test_a_tick_over_half_an_hour_is_a_small_rate(tmp_path: Path) -> None:
    """The same two percentages, further apart, are a smaller rate."""
    epoch = int(time.time()) + 280000
    publish(tmp_path, seven=86.0, seven_epoch=epoch)
    write_history(tmp_path, [(31.0, 85.0), (0.1, 86.0)], epoch)
    _, d = read(tmp_path)
    assert d["seven_day"]["rate_pct_per_hr"] == pytest.approx(1.94, abs=0.05), d


def test_a_reading_whose_reset_has_passed_is_no_current_reading(tmp_path: Path) -> None:
    """It describes a window that is gone: UNKNOWN, with no number to act on and no reset to print."""
    publish(tmp_path, seven=95.0, seven_epoch=int(time.time()) - 300)
    code, d = read(tmp_path)
    assert code == UNKNOWN, d
    assert d["seven_day"]["state"] == "UNKNOWN", d
    assert d["seven_day"]["used_percentage"] is None, d
    assert "reset has passed" in d["seven_day"]["reason"], d
    _, _, human = reader("-StateDir", str(tmp_path), pin=None)
    assert "95.0%" not in human and "resets in" not in human, human


def test_a_wired_root_with_a_gone_window_gets_no_never_ran_diagnosis(fake_home: Path) -> None:
    """The reading is seconds old, so "no session has started" and "the statusLine never runs" are
    both false. The control is the same root with a stale reading, which does get them."""
    pin = fake_home / ".claude-account-1"
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0
    state = pin / "mefor-usage"
    publish(state, seven=95.0, seven_epoch=int(time.time()) - 300)
    _, _, gone = reader(pin=pin, home=fake_home)
    assert "reset has passed" in gone and "cannot tell them apart" not in gone, gone

    publish(state, seven=95.0, age_min=48)
    _, _, stale = reader(pin=pin, home=fake_home)
    assert "cannot tell them apart" in stale, stale


def test_a_high_reading_with_no_rate_does_not_claim_a_projection(tmp_path: Path) -> None:
    publish(tmp_path, seven=91.0)
    code, d = read(tmp_path)
    assert code == WARN
    assert d["seven_day"]["rate_pct_per_hr"] is None, d
    assert "nothing is projected" in d["seven_day"]["reason"], d


def test_rate_is_not_computed_across_a_window_reset(tmp_path: Path) -> None:
    """THE EPOCH-BOUNDARY TRAP. When a window resets the percentage legitimately collapses (90 -> 5).
    A rate spanning that boundary is large and NEGATIVE, which reads as 'consumption has stopped' at the
    exact moment a fresh window has started being spent. Rows carry their reset epoch so the old window's
    samples are excluded rather than averaged in.
    """
    old_epoch = int(time.time()) - 600  # a window that already reset
    new_epoch = int(time.time()) + 3600
    publish(tmp_path, seven=5.0, seven_epoch=new_epoch)
    state = tmp_path
    rows = [
        {"at": _minutes_ago(m), "seven_day": p, "seven_reset": e}
        for m, p, e in [
            (50, 88.0, old_epoch),
            (40, 93.0, old_epoch),
            (35, 2.0, new_epoch),
            (1, 5.0, new_epoch),
        ]
    ]
    (state / "history.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )

    _, d = read(state)
    rate = d["seven_day"]["rate_pct_per_hr"]
    assert rate is not None and rate > 0, f"rate must come from the CURRENT window only, got {rate}"


def test_the_unmeasured_bucket_is_named_every_run(tmp_path: Path) -> None:
    """The model-scoped weekly bucket (the "Weekly / Fable" bar) is not in the statusLine payload."""
    publish(tmp_path, seven=10.0)
    _, d = read(tmp_path)
    assert "fable" in d["not_measured"].lower()


def test_opus_is_not_claimed_as_a_blind_spot(tmp_path: Path) -> None:
    """A FALSE blind spot is its own defect, and this one shipped in the first draft.

    Opus and Sonnet have **no separate weekly bucket** — they draw on "All models", which is the
    ``seven_day`` window this tool reads. So Opus work is fully covered. The first version warned that
    "heavy Opus use can exhaust a bucket nothing here can see", which is false, and worse than a plain
    omission: a session told its headroom is unknowable stops trusting a reading that was accurate.

    It came from reading ``seven_day_opus``/``seven_day_sonnet`` in an undocumented endpoint's *schema*
    and assuming a field implies an active limit. A schema is not a measurement.
    """
    publish(tmp_path, seven=10.0)
    _, d = read(tmp_path)
    text = d["not_measured"].lower()
    # TWO INDEPENDENT ASSERTIONS, NOT ONE DISJUNCTION. As a single `or` this could not fail for the
    # defect it names: re-inserting the exact false sentence ("heavy Opus use can exhaust a bucket
    # nothing here can see") while leaving the "NOT gaps" text in place kept the whole expression true,
    # and the suite stayed green while every session was told its Opus headroom was unknowable.
    assert "not gaps" in text and "fully covered" in text, (
        f"Opus must be named as covered, not merely omitted: {d['not_measured']}"
    )
    assert "can exhaust" not in text and "nothing here can see" not in text, (
        f"the false blind spot is back: {d['not_measured']}"
    )


# ------------------------------------------------------------------------------ installer


def test_the_installer_refuses_to_replace_someone_elses_statusline(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"statusLine": {"type": "command", "command": "my-own-thing"}}), encoding="utf-8"
    )
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL),
            "-SettingsPath",
            str(settings),
            "-CollectorPath",
            str(COLLECT),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 1
    assert "REFUSING" in proc.stdout
    assert (
        json.loads(settings.read_text(encoding="utf-8"))["statusLine"]["command"] == "my-own-thing"
    )


# --- the shell the statusLine is actually run under ------------------------------------------------

# THE FORM THAT SHIPPED BEFORE THE SHELL-AGNOSTIC ONE, kept here as a literal so the bash check below
# carries its own positive control. An instrument that cannot reject this string proves nothing by
# accepting the current command, and a check that has never failed is not evidence. The paths are
# stand-ins; what bash chokes on is the PowerShell syntax around them, not their contents.
LEGACY_POWERSHELL_COMMAND = (
    "# mefor-usage\n"
    r"$s = 'C:\Code\usage-collect.ps1'; "
    r"$d = 'C:\Roots\.claude-account-4\mefor-usage'; "
    "if (Test-Path -LiteralPath $s) { & pwsh -NoProfile -File $s -StateDir $d } "
    "else { Write-Output 'mefor-usage: collector missing' }"
)


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> str:
    """NOT ``shutil.which("bash")`` (BACKLOG #1216): on a box with WSL that can be the WSL launcher,
    which cannot open a Windows path. ``require_bash`` probes, and fails loudly rather than skipping."""
    return require_bash(tmp_path_factory.mktemp("resolve-bash"))


def bash_parse(bash: str, tmp_path: Path, command: str, name: str) -> tuple[int, str]:
    """Does bash ACCEPT this string as a script? ``bash -n`` parses it and runs nothing.

    Written to a file rather than passed through ``-c`` so the bytes bash reads are the bytes out of
    settings.json, newline and all.
    """
    f = tmp_path / name
    f.write_bytes(command.encode("utf-8"))
    # as_posix, NOT str: bash reads a Windows path's backslashes as escapes, so the check would
    # report a missing file (measured: `C:Users...legacy.sh`) instead of a verdict on the script.
    proc = subprocess.run(
        [bash, "-n", f.as_posix()],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    return proc.returncode, proc.stderr


def test_the_wired_command_parses_under_bash_and_the_form_it_replaced_does_not(
    bash: str, tmp_path: Path
) -> None:
    """THE PROPERTY NOTHING IN THIS FILE ASSERTED, which is exactly why the defect survived.

    A statusLine entry has no ``shell`` key -- its keys are ``command``, ``refreshInterval`` and
    ``type`` -- so unlike the hook entries beside it in the same settings.json it cannot declare
    PowerShell. Claude Code runs it under bash wherever Git Bash is installed. The command wired until
    now was PowerShell SOURCE, so bash died at ``{`` and pwsh was never launched: a root wired that way
    would publish nothing, and every reader downstream would report UNKNOWN without naming the shell.

    THE POSITIVE CONTROL IS HALF OF THIS TEST. ``bash -n`` returning 0 on the current command means
    nothing unless the same call returns non-zero on the form it replaced. Both readings live in one
    test so they cannot drift apart.
    """
    legacy_rc, legacy_err = bash_parse(bash, tmp_path, LEGACY_POWERSHELL_COMMAND, "legacy.sh")
    assert legacy_rc != 0, (
        "bash ACCEPTED the PowerShell-source command, so this check cannot see the class of defect "
        f"it exists for and its verdict on the current command is worthless: {legacy_err!r}"
    )
    assert "syntax error" in legacy_err, f"rejected for some other reason: {legacy_err!r}"

    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    assert install("-SettingsPath", str(settings), pin=None).returncode == 0
    rc, err = bash_parse(bash, tmp_path, wired(settings), "wired.sh")
    assert rc == 0, f"bash cannot parse the wired statusLine, so it never reaches pwsh: {err!r}"


def test_bash_runs_the_wired_command_end_to_end_and_it_publishes(bash: str, tmp_path: Path) -> None:
    """PARSING IS NOT RUNNING. ``bash -n`` would happily accept a command whose quoting split a path
    containing a space, or whose backslashes were eaten -- and the collector would then publish
    nowhere, or into some other directory, with the status bar looking fine. So drive the production
    string through bash for real and assert the reading lands where the command says it will.
    """
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    assert install("-SettingsPath", str(settings), pin=None).returncode == 0

    script = tmp_path / "run-wired.sh"
    script.write_bytes(wired(settings).encode("utf-8"))
    payload = json.dumps({"session_id": "bash", "rate_limits": {"seven_day": window(44.0, 3600)}})
    proc = subprocess.run(
        [bash, script.as_posix()],
        input=payload,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=probe_env(Path(bash), _env(None)),
    )
    assert proc.returncode == 0, f"bash could not run the wired command: {proc.stderr!r}"
    assert "44" in proc.stdout, f"no reading came out of the wired command: {proc.stdout!r}"
    assert (tmp_path / "mefor-usage" / "latest.json").exists(), (
        "bash ran the wired command and nothing was published"
    )


def test_both_command_shapes_read_back_their_publish_path_and_collector(
    fake_home: Path, tmp_path: Path
) -> None:
    """CHANGING THE EMITTER WITHOUT THE READERS WOULD BE A WORSE DEFECT THAN THE ONE IT FIXES.

    ``Get-WiredStateDir`` and ``Get-WiredCollectorPath`` matched ``$d = '...'`` and ``$s = '...'``,
    neither of which the shell-agnostic command contains. Ship part one alone and every correctly
    wired root reports "legacy command, no -StateDir": the mis-wire diagnosis goes blind while still
    rendering a confident line, and nothing anywhere says so.

    LEGACY ROOTS ARE NOT HYPOTHETICAL. A root wired before this change keeps the old command until
    somebody re-runs the installer against it, so both shapes have to read back for as long as one of
    them is on a disk somewhere.
    """
    pin = fake_home / ".claude-account-1"
    elsewhere = tmp_path / "some-other-root" / "mefor-usage"
    shapes = {
        "legacy": f"# mefor-usage\n$s = 'c.ps1'; $d = '{elsewhere}'; x",
        "current": (
            f'# mefor-usage\npwsh -NoProfile -NonInteractive -File "c.ps1" -StateDir "{elsewhere}"'
        ),
    }
    for label, command in shapes.items():
        (pin / "settings.json").write_text(
            json.dumps({"statusLine": {"type": "command", "command": command}}), encoding="utf-8"
        )
        proc = install("-Status", pin=pin, home=fake_home, collector=None)
        assert str(elsewhere) in proc.stdout, f"the {label} shape's publish path did not read back"
        assert "ELSEWHERE" in proc.stdout, f"the {label} shape lost the mis-wire diagnosis"
        assert "legacy command, no -StateDir" not in proc.stdout, (
            f"the {label} shape was misread as carrying no -StateDir"
        )
        assert "collector     : c.ps1" in proc.stdout, (
            f"the {label} shape's collector did not read back"
        )


def test_a_path_the_two_shells_would_quote_differently_is_refused_before_anything_is_written(
    tmp_path: Path,
) -> None:
    """The cost of one string serving two shells, paid at install time in front of a person.

    Both bash and pwsh expand ``$`` and a backtick inside double quotes, and both read a trailing
    backslash as escaping the closing quote. No spelling of those survives the pair, so the alternative
    to refusing is a command that fails in a status bar forever with nothing reporting it. A REFUSAL
    MUST WRITE NOTHING: the check runs over every target before the first write, because a run that
    aborted halfway through ``-AllRoots`` would leave the box in exactly the mixed state the
    both-shapes test above has to tell apart.
    """
    root = tmp_path / "has$dollar"
    root.mkdir()
    settings = root / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    proc = install("-SettingsPath", str(settings), pin=None)
    assert proc.returncode == 2, proc.stdout
    assert "cannot be quoted for both bash and pwsh" in proc.stdout
    assert json.loads(settings.read_text(encoding="utf-8")) == {}, (
        "a root the installer refused was written anyway"
    )


def test_the_installed_command_actually_runs_the_collector(tmp_path: Path) -> None:
    """A wired command that resolves to nothing is this repo's most-repeated defect — the announce hook
    sat merged-and-never-installed for hours, and its own missing-script notice could not fire because it
    lived inside the shim that was never wired. So assert the wired string EXECUTES and publishes.

    IT NOW RUNS THE COMMAND VERBATIM, which is what this docstring always claimed. The earlier version
    rewrote it — ``cmd.replace("-File $s", "-File $s -StateDir '<tmp>'")`` — because the wired command
    carried no publish path, so the test had to inject one to keep the collector off the real
    user-level file. Since the installer now bakes a per-root path in, that injection produces
    ``-StateDir`` twice and pwsh refuses to bind it (measured: exit 1, "specified more than once").
    Deleting the rewrite is what lets the test exercise the actual production string, and the fixture
    is safe by construction: ``-SettingsPath`` puts the root at ``tmp_path``, so the wired path is
    ``tmp_path/mefor-usage``.
    """
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(INSTALL),
            "-SettingsPath",
            str(settings),
            "-CollectorPath",
            str(COLLECT),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    cmd = json.loads(settings.read_text(encoding="utf-8"))["statusLine"]["command"]
    assert "mefor-usage" in cmd

    state = tmp_path / "mefor-usage"
    # The publish path is baked into the command, so assert it points where this root reads — a
    # recomputed expectation would agree with a wrong wiring.
    assert f'-StateDir "{state}"' in cmd, (
        f"the wired command names no per-root publish path: {cmd!r}"
    )

    payload = json.dumps({"session_id": "wired", "rate_limits": {"seven_day": window(55.0, 3600)}})
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", cmd],
        input=payload,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "55" in proc.stdout, f"the wired command produced no reading: {proc.stdout!r}"
    assert (state / "latest.json").exists(), "the wired command ran but published nothing"


# ------------------------------------------------------------- config roots and the publish partition
#
# WHY THIS SECTION EXISTS. The installer used to write ``~/.claude/settings.json`` unconditionally and
# report "INSTALLED (user level -- every session on this machine)". On a box whose launchers pin
# ``CLAUDE_CONFIG_DIR`` to ``~/.claude-account-<N>``, Claude Code reads the PINNED root, so the
# statusLine never fired, nothing ever published, and ``usage.ps1`` correctly said the collector was
# not installed. An install success followed by a reader saying it was never installed.
#
# The second half is the publish path. A config root holds one credential set and therefore one
# Anthropic account; measured on the box this was written for, five account roots carry five different
# account emails and five separate pools. Publishing them all to one user-level file is
# last-writer-wins across unrelated quotas, and it disarms the staleness guard -- some other account
# keeps the file warm, so a reading always looks fresh. So the publish path is per config root, and
# these tests pin that the writer and the reader derive it from the same rule.

CONFIG_ROOTS = ROOT / "scripts" / "coord" / "config-roots.ps1"


def _env(pin: Path | str | None) -> dict[str, str]:
    """A child environment with the pin set EXPLICITLY, or explicitly absent.

    ``os.environ.copy()`` alone is not enough and the gap is silent: this suite runs inside a Claude
    Code session, which on this box is itself pinned, so a child inherits ``CLAUDE_CONFIG_DIR`` and the
    "no pin" arm would quietly test the "pinned" one and pass. It is popped, never merely overwritten.
    """
    env = os.environ.copy()
    env.pop("CLAUDE_CONFIG_DIR", None)
    if pin is not None:
        env["CLAUDE_CONFIG_DIR"] = str(pin)
    return env


def install(
    *args: str,
    pin: Path | str | None = None,
    home: Path | None = None,
    collector: Path | None = COLLECT,
) -> subprocess.CompletedProcess[str]:
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALL)]
    if home is not None:
        cmd += ["-HomeDir", str(home)]
    if collector is not None:
        cmd += ["-CollectorPath", str(collector)]
    cmd += list(args)
    return run_single(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False, env=_env(pin)
    )


def reader(
    *args: str,
    pin: Path | str | None = None,
    home: Path | None = None,
    script: Path | None = None,
) -> tuple[int, dict[str, Any], str]:
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script or READ)]
    if home is not None:
        cmd += ["-HomeDir", str(home)]
    cmd += list(args)
    proc = run_single(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False, env=_env(pin)
    )
    out = proc.stdout.strip()
    parsed: dict[str, Any] = {}
    if "-Json" in args and out:
        parsed = json.loads(out)
    return proc.returncode, parsed, proc.stdout


def wired(settings: Path) -> str:
    cmd: str = json.loads(settings.read_text(encoding="utf-8"))["statusLine"]["command"]
    return cmd


@pytest.fixture
def fake_home(tmp_path: Path) -> Path:
    """A home directory shaped like the real box, INCLUDING the three kinds of look-alike.

    ``.claude-account-2.lock`` is a real directory on this machine carrying a settings.json and no
    ``.claude.json`` — a loose ``.claude-account-*`` glob adopts it, and ``install-gate.ps1`` wired it
    on every run for weeks (BACKLOG #1024). ``.claude-desktop-<N>`` carry a ``.claude.json`` and
    nothing launches from them, which is why "has a .claude.json" is also the wrong predicate.
    """
    h = tmp_path / "home"
    for name in (
        ".claude",
        ".claude-account-1",
        ".claude-account-2",
        ".claude-account-2.lock",
        ".claude-desktop-1",
        ".claude-tools",
    ):
        (h / name).mkdir(parents=True)
    (h / ".claude-account-2.lock" / "settings.json").write_text("{}", encoding="utf-8")
    return h


# --- requirement 1: honour the pin -------------------------------------------------------------


def test_a_pinned_config_dir_is_where_the_statusline_lands(fake_home: Path) -> None:
    """THE LIVE SYMPTOM, REPRODUCED. Reverting the installer to a ``-SettingsPath`` default of
    ``<home>\\.claude\\settings.json`` makes this fail on the second assertion."""
    pin = fake_home / ".claude-account-1"
    proc = install(pin=pin, home=fake_home)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (pin / "settings.json").exists(), "the pinned root was not written"
    assert not (fake_home / ".claude" / "settings.json").exists(), (
        "the default root was written even though CLAUDE_CONFIG_DIR named another"
    )


def test_a_pinned_root_does_not_steal_an_explicit_settings_path(
    fake_home: Path, tmp_path: Path
) -> None:
    """Rule 1 outranks rule 4, and the script-scope explicitness capture actually works.

    THE TWO PRE-EXISTING INSTALLER TESTS CANNOT CATCH THIS. They check only their own fixture root, so
    they pass whether or not the pin is honoured. If ``$PSBoundParameters`` were tested inside the
    resolver function instead of at script scope it would read False for every caller (measured: a
    function's own ``$PSBoundParameters`` is EMPTY), rules 1 and 2 would be unreachable, and this
    install would land in the caller's live pinned root instead of the fixture.
    """
    fixture = tmp_path / "fixture"
    fixture.mkdir()
    settings = fixture / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    pin = fake_home / ".claude-account-2"

    proc = install("-SettingsPath", str(settings), pin=pin, home=fake_home)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "statusLine" in json.loads(settings.read_text(encoding="utf-8"))
    assert not (pin / "settings.json").exists(), "the pin overrode an explicit -SettingsPath"


def test_no_pin_still_installs_into_the_default_config_dir(fake_home: Path) -> None:
    """The negative arm: with no pin the shipped behaviour is restored exactly, so rule 5 is a
    regression fence rather than a new claim."""
    proc = install(pin=None, home=fake_home)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert (fake_home / ".claude" / "settings.json").exists()


def test_the_no_pin_arm_really_runs_without_a_pin_and_inside_the_fixture_home() -> None:
    """A TEST ABOUT THE TESTS, and the one standing between this suite and the real account roots.

    Two ways the fixtures could be lying. First, ``CLAUDE_CONFIG_DIR`` is set in this very process on
    the box these scripts were written for, so a child that merely inherits it would make every "no
    pin" test exercise the pinned path. Second, ``-HomeDir`` has to be a real seam: measured, with
    ``USERPROFILE`` overridden to ``C:/fake/home`` a child pwsh still reports
    ``[Environment]::GetFolderPath('UserProfile') = C:\\Users\\Scott``, so a script that resolved home
    itself could not be redirected — and ``-AllRoots`` would enumerate and WIRE the owner's live
    account roots.
    """
    probe = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "if ($env:CLAUDE_CONFIG_DIR) { 'PINNED:' + $env:CLAUDE_CONFIG_DIR } else { 'NOPIN' }",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
        env=_env(None),
    )
    assert probe.stdout.strip() == "NOPIN", (
        "the child inherited a pin, so every 'no pin' test in this file is testing the pinned path"
    )
    # And the installer must accept -HomeDir at all, or the redirection above is decorative.
    assert "-HomeDir" in INSTALL.read_text(encoding="utf-8")


def test_a_pin_naming_a_directory_that_does_not_exist_is_refused_not_created(
    fake_home: Path,
) -> None:
    """A typo'd CLAUDE_CONFIG_DIR must not manufacture a config root nothing can launch from. This
    repo has already paid once for an installer writing into such a directory (BACKLOG #1024), and
    ``New-Item -Force`` creates every missing parent, so the wrong reflex here is one character."""
    ghost = fake_home / ".claude-account-99"
    proc = install(pin=ghost, home=fake_home)
    assert proc.returncode == 2, proc.stdout
    assert "CANNOT START" in proc.stdout
    assert not ghost.exists(), "a nonexistent pin was created rather than refused"


# --- requirement 2: multi-root ------------------------------------------------------------------


def test_all_roots_wires_the_account_roots_and_skips_the_look_alikes_and_the_default(
    fake_home: Path,
) -> None:
    """Requirement 2, the anchored predicate, and the deliberate exclusion of ``~/.claude``.

    NOT COVERED HERE, and stated rather than implied: the ``-Force`` on the directory glob. Its
    absence is invisible on Windows (a dot-prefixed directory carries no hidden attribute) and
    collapses the set to nothing on Linux. This module is skipif'd to ``os.name == "nt"``, so it can
    never observe that failure; only a CI ubuntu leg could, and this file has none.
    """
    proc = install("-AllRoots", pin=None, home=fake_home)
    assert proc.returncode == 0, proc.stdout + proc.stderr

    assert (fake_home / ".claude-account-1" / "settings.json").exists()
    assert (fake_home / ".claude-account-2" / "settings.json").exists()
    # The three that must be left alone, each for a different reason.
    assert not (fake_home / ".claude" / "settings.json").exists(), (
        "-AllRoots wired the default root"
    )
    assert not (fake_home / ".claude-desktop-1" / "settings.json").exists(), (
        "a .claude-desktop dir was wired -- the 'has a .claude.json' filter would do this"
    )
    lock = json.loads((fake_home / ".claude-account-2.lock" / "settings.json").read_text("utf-8"))
    assert lock == {}, "the .lock look-alike was wired -- the anchors are not holding"


def test_all_roots_on_a_home_with_no_account_roots_touches_nothing_and_says_so(
    tmp_path: Path,
) -> None:
    """The removed empty-set fallback. Seeding ``~/.claude`` when the glob finds nothing would make
    this guard dead code AND manufacture a target that by definition does not exist."""
    empty = tmp_path / "empty-home"
    empty.mkdir()
    proc = install("-AllRoots", pin=None, home=empty)
    assert proc.returncode == 2, proc.stdout
    assert "no account config root found" in proc.stdout
    assert not (empty / ".claude").exists()


def test_each_root_is_wired_to_its_own_publish_path_and_they_do_not_bleed(
    fake_home: Path,
) -> None:
    """THE PARTITION ITSELF. Two roots, two publish paths, and neither names the other's.

    Reverting ``Get-UsageStateDir`` to a single user-level literal makes both wired commands name one
    path, and the second assertion fails.
    """
    assert install("-AllRoots", pin=None, home=fake_home).returncode == 0
    a = wired(fake_home / ".claude-account-1" / "settings.json")
    b = wired(fake_home / ".claude-account-2" / "settings.json")
    pa = str(fake_home / ".claude-account-1" / "mefor-usage")
    pb = str(fake_home / ".claude-account-2" / "mefor-usage")
    assert f'-StateDir "{pa}"' in a
    assert f'-StateDir "{pb}"' in b
    assert pb not in a and pa not in b, "one root's wired command names another root's publish path"


def test_a_root_with_a_foreign_statusline_is_refused_without_abandoning_the_others(
    fake_home: Path,
) -> None:
    """The refusal survives multi-root: PER ROOT, and it does not abort the run.

    A foreign statusLine in one root must not cost the other roots their wiring — an installer that
    stops at the first refusal would leave a partially wired box and a tally that says so only if you
    read it closely, which is why the exit code for that state is 3 and not 0 or 1.
    """
    (fake_home / ".claude-account-1" / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": "my-own-thing"}}), encoding="utf-8"
    )
    proc = install("-AllRoots", pin=None, home=fake_home)
    assert proc.returncode == 3, f"partial outcome must be exit 3: {proc.stdout}"
    assert "REFUSING" in proc.stdout
    assert (fake_home / ".claude-account-2" / "settings.json").exists(), (
        "one refusal abandoned the remaining roots"
    )
    kept = json.loads((fake_home / ".claude-account-1" / "settings.json").read_text("utf-8"))
    assert kept["statusLine"]["command"] == "my-own-thing"


def test_a_foreign_statusline_that_merely_mentions_the_marker_is_still_refused(
    tmp_path: Path,
) -> None:
    """The ownership test had to stop being a substring match when the publish path went INTO the
    command. The wired command now contains ``\\mefor-usage`` inside its ``-StateDir`` argument, so
    ``command -like "*mefor-usage*"`` would judge any foreign statusLine that merely mentions the
    publish path to be ours — and silently replace it, in up to five roots at once."""
    settings = tmp_path / "settings.json"
    theirs = "echo ~/.claude/mefor-usage/latest.json"
    settings.write_text(
        json.dumps({"statusLine": {"type": "command", "command": theirs}}), encoding="utf-8"
    )
    proc = install("-SettingsPath", str(settings), pin=None)
    assert proc.returncode == 1
    assert "REFUSING" in proc.stdout
    assert json.loads(settings.read_text(encoding="utf-8"))["statusLine"]["command"] == theirs


def test_a_statusline_with_an_empty_command_is_treated_as_absent_not_foreign(
    tmp_path: Path,
) -> None:
    """A state that would otherwise have no exit. Classified FOREIGN, this root could never be wired:
    the refusal would print with nothing after the colon (which reads as truncated output, not as a
    finding) and offer a remedy — "merge the two commands by hand" — naming a command that does not
    exist."""
    settings = tmp_path / "settings.json"
    settings.write_text(json.dumps({"statusLine": {"type": "command", "command": ""}}), "utf-8")
    proc = install("-SettingsPath", str(settings), pin=None)
    assert proc.returncode == 0, proc.stdout
    assert "REFUSING" not in proc.stdout
    assert "mefor-usage" in wired(settings)


# --- requirement 3: the message must not claim more than it did ---------------------------------


def test_the_success_message_names_the_file_it_wrote(fake_home: Path) -> None:
    """Requirement 3, positive half. A truthful message would have surfaced this defect on the first
    run instead of costing a debugging round."""
    pin = fake_home / ".claude-account-1"
    proc = install(pin=pin, home=fake_home)
    assert str(pin / "settings.json") in proc.stdout, (
        f"the success output does not name the file it wrote: {proc.stdout}"
    )


def test_a_single_root_install_does_not_claim_every_session_on_this_machine(
    fake_home: Path,
) -> None:
    """Requirement 3, negative half, and the exact sentence that was false.

    A completeness claim is a liability (CLAUDE.md section 11 / SDS-3.6). The phrase is deleted rather
    than conditioned, because naming the files is shorter AND true.
    """
    out = install(pin=fake_home / ".claude-account-1", home=fake_home).stdout
    assert "every session on this machine" not in out
    # And no line that PRINTS can carry it either — the .DESCRIPTION quotes the old claim on purpose,
    # as the explanation of the defect, so a plain "not in the file" check would forbid the history.
    printing = [
        ln
        for ln in INSTALL.read_text(encoding="utf-8").splitlines()
        if ("Write-Host" in ln or "Write-Output" in ln) and "every session on this machine" in ln
    ]
    assert not printing, f"the claim is still printed: {printing}"


def test_no_line_claims_a_publish_that_has_not_happened(fake_home: Path) -> None:
    """The present-tense overclaim. Writing a settings key is not publishing, and nothing on this box
    had ever published when the defect was found — so a line reading "publishes to" would assert
    something no check in the script supports."""
    out = install(pin=fake_home / ".claude-account-1", home=fake_home).stdout
    assert "wired to publish to" in out
    assert "nothing has published there yet" in out
    assert "publishes to " not in out


def test_all_roots_names_each_root_it_wrote_and_the_tally_agrees(fake_home: Path) -> None:
    """Requirement 3 under multi-root, where a bare count is most tempting and least useful.

    The lines and the tally are the same counter, so they cannot disagree — the "summary says N while
    the lines say M" defect is structurally excluded rather than asserted away.
    """
    out = install("-AllRoots", pin=None, home=fake_home).stdout
    named = [ln for ln in out.splitlines() if ln.strip().startswith("WROTE")]
    assert len(named) == 2, out
    assert str(fake_home / ".claude-account-1" / "settings.json") in out
    assert str(fake_home / ".claude-account-2" / "settings.json") in out
    assert "wrote: 2" in out
    assert "Roots examined: 2" in out


def test_whatif_enumerates_every_target_and_exits_zero(fake_home: Path) -> None:
    """A dry run must be safe to run and must not report failure. Under ``-WhatIf`` ShouldProcess
    returns false for every root, so a purely tally-driven exit rule would return 1 — a dry run
    reporting total failure, which is the summary-contradicts-the-lines defect inverted."""
    proc = install("-AllRoots", "-WhatIf", pin=None, home=fake_home)
    assert proc.returncode == 0, proc.stdout
    assert proc.stdout.count("WOULD WRITE") == 2
    assert "would write: 2" in proc.stdout
    assert not (fake_home / ".claude-account-1" / "settings.json").exists()


def test_a_settings_file_too_deep_to_serialise_is_failed_not_silently_truncated(
    tmp_path: Path,
) -> None:
    """The guard a parse-back check cannot provide, and the draft of this design assumed it could.

    Measured with a 24-level document: ``ConvertTo-Json -Depth 20`` emits a truncation warning AND THE
    TRUNCATED TEXT STILL PARSES BACK CLEANLY, with the deep node replaced by its type name as a
    string. So one ``-AllRoots`` run would quietly truncate up to five live account roots and count
    every one as written.
    """
    settings = tmp_path / "settings.json"
    deep: dict[str, Any] = {"leaf": 1}
    for _ in range(24):
        deep = {"a": deep}
    original = json.dumps(deep)
    settings.write_text(original, encoding="utf-8")

    proc = install("-SettingsPath", str(settings), pin=None)
    assert proc.returncode == 1, proc.stdout
    assert "TRUNCATED" in proc.stdout
    assert settings.read_text(encoding="utf-8") == original, "the file was rewritten anyway"


# --- -Status and -Uninstall ---------------------------------------------------------------------


def test_status_under_a_pin_does_not_report_the_default_root_as_configured(
    fake_home: Path,
) -> None:
    """The disagreement, from the other side. ``-Status`` used to read the default root's settings
    while every session read a pinned root — so it reported CONFIGURED about a file no session on the
    box loads. This is the test whose failure message a person would recognise as their own problem."""
    (fake_home / ".claude" / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": "# mefor-usage\n$s = 'x'"}}),
        encoding="utf-8",
    )
    pin = fake_home / ".claude-account-1"
    proc = install("-Status", pin=pin, home=fake_home, collector=None)
    assert str(pin / "settings.json") in proc.stdout
    assert proc.returncode == 1, "an unwired pinned root must not report success"


def test_status_reads_the_publish_path_out_of_the_wired_command_not_a_recomputed_one(
    fake_home: Path, tmp_path: Path
) -> None:
    """The SDS-3.8 defect: the shipped ``-Status`` reported "script exists" against a path THAT
    INVOCATION had just resolved from git, so a root wired from a checkout since deleted still
    reported True. Across roots wired at different times from different checkouts, one recomputed line
    describes none of them."""
    pin = fake_home / ".claude-account-1"
    elsewhere = tmp_path / "some-other-root" / "mefor-usage"
    (pin / "settings.json").write_text(
        json.dumps(
            {
                "statusLine": {
                    "type": "command",
                    "command": f"# mefor-usage\n$s = 'c.ps1'; $d = '{elsewhere}'; x",
                }
            }
        ),
        encoding="utf-8",
    )
    proc = install("-Status", pin=pin, home=fake_home, collector=None)
    assert str(elsewhere) in proc.stdout, "-Status recomputed the path instead of reading it back"
    assert "ELSEWHERE" in proc.stdout
    assert proc.returncode == 1


def test_status_reports_a_legacy_command_as_its_own_state(fake_home: Path) -> None:
    """A command written before publish paths were per-root — including every one the out-of-repo
    propagate stopgap copied — names no ``-StateDir`` at all. Folding that into WIRED is how it goes
    silent; where it publishes then depends on the collector's run-time fallback."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text(
        json.dumps(
            {"statusLine": {"type": "command", "command": "# mefor-usage\n$s = 'c.ps1'; x"}}
        ),
        encoding="utf-8",
    )
    proc = install("-Status", pin=pin, home=fake_home, collector=None)
    assert "legacy command, no -StateDir" in proc.stdout


def test_uninstall_names_the_roots_it_actually_removed_from(fake_home: Path) -> None:
    """The mirror-image lie, and worse than the install one because the operator believes they turned
    something off. A single-root ``-Uninstall`` under a pin used to strip one root, print REMOVED, exit
    0 — and leave every other root wired and still publishing."""
    assert install("-AllRoots", pin=None, home=fake_home).returncode == 0
    proc = install("-AllRoots", "-Uninstall", pin=None, home=fake_home, collector=None)
    assert proc.returncode == 0, proc.stdout
    assert str(fake_home / ".claude-account-1" / "settings.json") in proc.stdout
    assert str(fake_home / ".claude-account-2" / "settings.json") in proc.stdout
    assert "removed: 2" in proc.stdout
    for n in (".claude-account-1", ".claude-account-2"):
        assert "statusLine" not in json.loads(
            (fake_home / n / "settings.json").read_text(encoding="utf-8")
        )


# --- the reader half ----------------------------------------------------------------------------


def test_the_reader_defaults_to_its_own_config_roots_state_dir(fake_home: Path) -> None:
    """Publisher and reader now derive the path from ONE function. They used to agree only because two
    separate string literals happened to match, which is agreement by luck, not by construction."""
    pin = fake_home / ".claude-account-1"
    # WIRE IT FIRST. A root holding a fresh document but carrying no statusLine is a state that cannot
    # occur -- something published there, so something was wired -- and since the wiring diagnosis now
    # reaches the verdict, that contradiction would make this test assert OK over a root the script
    # itself calls unwired.
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0
    state = pin / "mefor-usage"
    state.mkdir(exist_ok=True)
    now = datetime.now(UTC).isoformat()
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": now,
                "seven_day": {
                    "used_percentage": 12.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": now,
                },
            }
        ),
        encoding="utf-8",
    )
    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    # The window is fresh, so the verdict is a real OK rather than the UNKNOWN that an unpublished
    # document would give — which would let this pass while reading the wrong directory.
    assert code == OK, doc
    assert doc["config_root"].lower() == str(pin).lower()
    assert doc["state_dir"].lower() == str(state).lower()
    assert doc["seven_day"]["used_percentage"] == pytest.approx(12.0)


# ---------------------------------------------------------------- requirement 4: the five diagnoses
#
# Requirement 4. Five states with five different fixes must not share one message. The old message
# said "not installed or has not run yet" and printed the bare installer command with NO root -- so
# following the reader's own advice re-ran the exact invocation that produced the false INSTALLED
# claim.
#
# ONE TEST PER STATE, AND THE SPLIT IS THE #1304 FIX RATHER THAN TIDYING. These five arms were one
# test driving EIGHT sequential pwsh launches, and on the windows-2025 harness leg that test measured
# 90.88s GREEN (run 35472705438) against the step's 120s per-test `--timeout` -- a 1.3x margin on a
# tier where a launch's cost is set by whatever else holds the runner's 4 vCPU. The evidence for what
# starved, and why a first-launch cold start is refuted, is in `tests/_spawn_lock.py`; it is not
# restated here.
#
# Charging eight launches to one 120s budget is what made this test the worst case in the file:
# `run_single` waits a storm out BEFORE launching, and the wait is charged to the same per-test clock.
# Split, the widest arm holds three launches instead of eight. THAT BUYS MARGIN, IT DOES NOT BUY
# SAFETY, and the difference is worth stating because the arithmetic does not close: `_SINGLE_WAIT_S`
# is 90s, so any arm can in principle be pushed past 120s by a long enough storm, and three other
# tests in this file hold four or five launches and were not re-timed for this change. What the split
# removes is the test that could not fit under ANY wait; the residual is bounded by the same
# fail-open the lock has everywhere else, and it is recorded beside `_SINGLE_WAIT_S` rather than
# argued away here.
#
# The arms are independent by construction: each writes the whole settings.json state it reads, onto
# its own `fake_home`. That also retires arm (d)'s sequencing hazard -- it used to have to reset the
# fixture before arm (e) because a rewrite of an unparseable file would silently disable every
# setting in it, and there is no shared fixture left to corrupt.
#
# THE (a)-(e) LETTERS IN THE DOCSTRINGS BELOW ARE THE MERGED TEST'S, KEPT ON PURPOSE. They index this
# paragraph and the blame trail, not a list that still exists in the code, so a reader landing on one
# arm from `git log -S` can place it in the original sequence. They are the only thing that survives
# the split as a handle on the old test.
#
# NOTHING GATES THE FIVE STATES BEING DISTINCT FROM EACH OTHER, and that is deliberate after one
# attempt at it was withdrawn. A tuple of the five names plus `len(set(...)) == len(...)` is true by
# construction and stays true however the arms are edited, so it reported nothing while reading like a
# control -- the false-premise shape CLAUDE.md section 11 forbids (SDS-3.7). Distinctness is held, as
# it always was, by five exact-match assertions a reviewer can see. A real gate would have to drive
# the arms off one table, and these arms are too different in shape for that to be an improvement.

#: Requirement 4's five states, named once so one rename cannot leave two spellings behind. NOT every
#: state the reader can emit -- ``WIRED_ELSEWHERE`` and ``NO_SUCH_ROOT`` are requirement 4's
#: neighbours and are pinned by their own tests further down, still as literals.
NOT_WIRED_NO_SETTINGS = "NOT_WIRED_NO_SETTINGS"
NOT_WIRED_NO_STATUSLINE = "NOT_WIRED_NO_STATUSLINE"
FOREIGN_STATUSLINE = "FOREIGN_STATUSLINE"
SETTINGS_UNREADABLE = "SETTINGS_UNREADABLE"
WIRED_HERE = "WIRED_HERE"


def test_a_root_with_no_settings_file_is_diagnosed_as_not_wired(fake_home: Path) -> None:
    """(a) No settings.json at all. The verdict is UNKNOWN and the root is named."""
    pin = fake_home / ".claude-account-1"
    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert code == UNKNOWN
    assert doc["statusline_state"] == NOT_WIRED_NO_SETTINGS
    assert doc["config_root"].lower() == str(pin).lower()


def test_a_settings_file_with_no_statusline_is_diagnosed_separately(fake_home: Path) -> None:
    """(b) The file exists and carries no statusLine, which is a different fix from having no file."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text("{}", encoding="utf-8")
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == NOT_WIRED_NO_STATUSLINE


def test_somebody_elses_statusline_is_not_reported_as_ours(fake_home: Path) -> None:
    """(c) A foreign statusLine. Installing over it is a decision, not a repair, so it gets its own
    state rather than being folded into "not wired"."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": "theirs"}}), encoding="utf-8"
    )
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == FOREIGN_STATUSLINE


def test_an_unreadable_settings_file_is_named_and_the_installer_refuses_it(fake_home: Path) -> None:
    """(d) Unreadable. The installer REFUSES this root (exit 1) rather than rewriting a file it could
    not parse -- a rewrite would silently disable every setting in it, not just this one."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text("{ not json", encoding="utf-8")
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == SETTINGS_UNREADABLE
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 1


def test_a_correctly_wired_root_is_told_to_start_a_new_session(fake_home: Path) -> None:
    """(e) Ours, and pointing where this reader looks -- so the fix really is "start a new session"."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text("{}", encoding="utf-8")
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == WIRED_HERE
    _, _, human = reader(pin=pin, home=fake_home)
    assert "Start a NEW session" in human
    # Every remedy must name the root, or it repeats the original defect.
    assert str(pin) in human


def test_the_no_data_error_says_so_when_a_root_publishes_somewhere_else(
    fake_home: Path, tmp_path: Path
) -> None:
    """THE ARM THE WHOLE DIAGNOSIS EXISTS FOR. Without it the reader tells the operator to restart and
    wait, forever, with nothing anywhere saying the two halves disagree — the original defect
    relocated rather than fixed."""
    pin = fake_home / ".claude-account-1"
    other = tmp_path / "other-root" / "mefor-usage"
    (pin / "settings.json").write_text(
        json.dumps(
            {"statusLine": {"type": "command", "command": f"# mefor-usage\n$s='c'; $d = '{other}'"}}
        ),
        encoding="utf-8",
    )
    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert code == UNKNOWN
    assert doc["statusline_state"] == "WIRED_ELSEWHERE"
    assert doc["wired_state_dir"].lower() == str(other).lower()
    # THE VERDICT, NOT ONLY THE PROSE. The diagnosis used to reach the printed warning and stop there,
    # so a root the script itself called mis-wired still exited 0 and reported state=OK beside
    # statusline_state=WIRED_ELSEWHERE in one document -- two instruments disagreeing inside one run.
    assert doc["state"] == "UNKNOWN", doc
    hcode, _, human = reader(pin=pin, home=fake_home)
    assert hcode == UNKNOWN, f"mis-wired root exited {hcode}"
    assert "WAITING WILL NOT FIX THIS" in human
    assert "--  OK" not in human, f"the heading claimed OK over a leftover: {human}"


def test_a_document_stamped_with_another_config_root_is_refused(tmp_path: Path) -> None:
    """THE TRIPWIRE. A layout mistake becomes loud instead of plausible.

    It gates on ``config_root_env`` — the ambient pin, recorded live — and NOT on ``config_root``,
    which is derived from the write path and therefore agrees with it by construction. A stamp derived
    from where we wrote can detect nothing.
    """
    state = tmp_path / "acct-a" / "mefor-usage"
    state.mkdir(parents=True)
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": datetime.now(UTC).isoformat(),
                "published_by": {"config_root_env": str(tmp_path / "acct-b")},
                "seven_day": {
                    "used_percentage": 99.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": datetime.now(UTC).isoformat(),
                },
            }
        ),
        encoding="utf-8",
    )
    code, doc, _ = reader("-StateDir", str(state), "-Json", pin=None)
    assert code == UNKNOWN
    assert doc["provenance"] == "FOREIGN"
    assert "another account's headroom" in doc["reason"]


def test_a_document_with_no_stamp_is_read_and_says_the_guard_could_not_run(
    tmp_path: Path,
) -> None:
    """Absence is UNVERIFIABLE provenance, not WRONG provenance — two different facts, and only one is
    an error. Refusing on absence would also break every hand-written fixture in this file and every
    document written before the stamp existed, for no gain."""
    collect(tmp_path, {"session_id": "x", "rate_limits": {"seven_day": window(40.0, 3600)}})
    doc = latest(tmp_path)
    del doc["published_by"]["config_root_env"]
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")

    code, parsed, _ = reader("-StateDir", str(tmp_path), "-Json", pin=None)
    assert parsed["provenance"] == "UNVERIFIED"
    assert parsed["seven_day"]["used_percentage"] == pytest.approx(40.0), (
        "an unstamped reading must still be read"
    )
    _, _, human = reader("-StateDir", str(tmp_path), pin=None)
    assert "provenance: UNVERIFIED" in human


def test_an_explicit_state_dir_is_not_refused_for_being_another_root(tmp_path: Path) -> None:
    """The refusal must fire on ERROR, not on INTENT.

    It compares the stamp against the READ-FROM root — the root the document sits under — and not
    against the reader's own. Comparing against the reader's root would break the documented
    cross-root peek (``usage.ps1 -StateDir <other root>\\mefor-usage``, the only way to look at
    another account) and would make every row of the ``-AllRoots`` survey but one render as a refusal.
    """
    other = tmp_path / "acct-b"
    state = other / "mefor-usage"
    state.mkdir(parents=True)
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": datetime.now(UTC).isoformat(),
                "published_by": {"config_root_env": str(other)},
                "seven_day": {
                    "used_percentage": 33.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": datetime.now(UTC).isoformat(),
                },
            }
        ),
        encoding="utf-8",
    )
    # Read it from a session pinned somewhere else entirely.
    _, doc, _ = reader("-StateDir", str(state), "-Json", pin=tmp_path / "acct-a")
    assert doc["provenance"] == "OK", doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(33.0)


def test_the_survey_lists_every_root_and_computes_nothing_across_them(fake_home: Path) -> None:
    """A SURVEY, NEVER A MERGE. These are different accounts with different pools; summing, averaging
    or taking a worst-of across them would rebuild the exact lie the partitioning removes."""
    for name, pct in ((".claude-account-1", 10.0), (".claude-account-2", 90.0)):
        st = fake_home / name / "mefor-usage"
        st.mkdir()
        (st / "latest.json").write_text(
            json.dumps(
                {
                    "captured_at": datetime.now(UTC).isoformat(),
                    "published_by": {"config_root_env": str(fake_home / name)},
                    "seven_day": {
                        "used_percentage": pct,
                        "resets_at_epoch": int(time.time()) + 3600,
                        "captured_at": datetime.now(UTC).isoformat(),
                    },
                }
            ),
            encoding="utf-8",
        )
    pin = fake_home / ".claude-account-1"
    code, doc, _ = reader("-AllRoots", "-Json", pin=pin, home=fake_home)
    rows = {r["root"].lower(): r for r in doc["roots"]}
    assert str(fake_home / ".claude-account-1").lower() in rows
    assert str(fake_home / ".claude-account-2").lower() in rows
    assert str(fake_home / ".claude").lower() in rows, (
        "the survey must list every root, not only ours"
    )
    assert rows[str(fake_home / ".claude-account-2").lower()]["seven"] == pytest.approx(90.0)
    # The exit code is THIS session's verdict, not a roll-up across accounts.
    assert doc["seven_day"]["used_percentage"] == pytest.approx(10.0)
    assert doc["exit_code"] == code


# --- the collector half, and the shared rule ----------------------------------------------------


def test_the_collector_publishes_under_its_pinned_root_when_given_no_state_dir(
    fake_home: Path,
) -> None:
    """The other end of the shared derivation. A LEGACY wired command passes no ``-StateDir``, so this
    is the path such a root actually takes at run time."""
    pin = fake_home / ".claude-account-2"
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(COLLECT),
            "-HomeDir",
            str(fake_home),
        ],
        input=json.dumps({"session_id": "p", "rate_limits": {"seven_day": window(21.0, 3600)}}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(pin),
    )
    assert proc.returncode == 0, proc.stderr
    assert (pin / "mefor-usage" / "latest.json").exists()
    assert not (fake_home / ".claude" / "mefor-usage").exists()


def test_the_collector_never_manufactures_a_config_root(fake_home: Path) -> None:
    """The installer refuses to create a root; the collector must not disagree about the same input.

    ``New-Item -ItemType Directory -Force`` creates every missing ANCESTOR (measured), so without an
    explicit guard a typo'd or stale ``CLAUDE_CONFIG_DIR`` would have a live session build a directory
    nothing can launch from — on every statusLine fire.
    """
    ghost = fake_home / ".claude-account-99"
    payload = json.dumps({"session_id": "g", "rate_limits": {"seven_day": window(5.0, 3600)}})
    for args, pin in (
        ([], ghost),  # resolved from the pin
        (["-StateDir", str(ghost / "mefor-usage")], None),  # named explicitly
    ):
        proc = run_single(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(COLLECT),
                "-HomeDir",
                str(fake_home),
                *args,
            ],
            input=payload,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=_env(pin),
        )
        assert proc.returncode == 0, proc.stderr
        assert "no config root to publish to" in proc.stdout
        assert not ghost.exists(), f"the collector created {ghost} (args={args})"


def test_the_collector_still_publishes_when_the_shared_library_is_missing(
    fake_home: Path, tmp_path: Path
) -> None:
    """NEVER THROWS, NEVER BLOCKS outranks one-definition for a statusLine, so the collector keeps a
    literal fallback copy of the two-line state-dir rule. This pins that the fallback both EXISTS and
    AGREES with the shared function — drift goes red rather than silent."""
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    shutil.copy(COLLECT, isolated / "usage-collect.ps1")
    pin = fake_home / ".claude-account-1"
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(isolated / "usage-collect.ps1"),
            "-HomeDir",
            str(fake_home),
        ],
        input=json.dumps({"session_id": "iso", "rate_limits": {"seven_day": window(7.0, 3600)}}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(pin),
    )
    assert proc.returncode == 0, proc.stderr
    assert (pin / "mefor-usage" / "latest.json").exists(), (
        "the fallback state-dir rule disagrees with Get-UsageStateDir"
    )


def test_the_reader_refuses_to_diagnose_when_the_shared_library_is_missing(
    tmp_path: Path,
) -> None:
    """THE LOUD FLOOR, and the reader needs it more than the collector does.

    ``usage.ps1`` runs under ``SilentlyContinue``, which converts a dot-source failure into a WRONG
    ANSWER rather than an error: the missing functions are swallowed, ``$StateDir`` stays null,
    ``Join-Path $null "latest.json"`` yields the empty string, and the script would print "Nothing has
    published to ." and then diagnose ``\\settings.json``. Testing the resolved PATH is not enough —
    an explicit ``-StateDir`` resolves it without the library while every downstream check still comes
    from there.
    """
    isolated = tmp_path / "isolated"
    isolated.mkdir()
    shutil.copy(READ, isolated / "usage.ps1")
    code, _, out = reader("-StateDir", str(tmp_path), pin=None, script=isolated / "usage.ps1")
    assert code == UNKNOWN
    assert "config-roots.ps1 did not load" in out


def test_config_roots_ps1_keeps_the_contract_three_scripts_depend_on(tmp_path: Path) -> None:
    """FOUR CONSTRAINTS ON A FILE THAT IS DOT-SOURCED INTO A STATUSLINE, made executable.

    Dot-sourcing runs in the CALLER's scope, so anything at top level here happens to them. A comment
    cannot enforce that, and the collector is bound by NEVER THROWS, NEVER BLOCKS.
    """
    text = CONFIG_ROOTS.read_text(encoding="utf-8")
    # BOTH comment forms, and the block form is the one that matters: this file's own header explains
    # the four constraints, so a line-only stripper would find every forbidden token inside the prose
    # that forbids it and fail on the documentation rather than on the code.
    code_lines: list[str] = []
    in_block = False
    for ln in text.splitlines():
        s = ln.strip()
        if in_block:
            if "#>" in s:
                in_block = False
            continue
        if s.startswith("<#"):
            in_block = "#>" not in s
            continue
        if s and not s.startswith("#"):
            code_lines.append(ln)
    body = "\n".join(code_lines)
    assert "$ErrorActionPreference" not in body, (
        "assigning a preference variable would override the caller's and let a statusLine throw"
    )
    # A top-level param() would consume the caller's own arguments. Any param( here must be indented
    # inside a function.
    assert not any(ln.startswith("param(") for ln in code_lines), "top-level param() block"
    assert "$env:USERPROFILE" not in body, (
        "resolving home inside the library defeats the -HomeDir seam every test depends on"
    )
    # Loading it must produce no output and no side effects.
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{CONFIG_ROOTS}'; Write-Output 'LOADED'",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "LOADED", f"loading it emitted output: {proc.stdout!r}"


def test_the_root_list_survives_being_wrapped_in_an_array_at_one_element(
    tmp_path: Path,
) -> None:
    """A one-element result must arrive as ONE STRING, not as a nested array.

    This is not hypothetical: an earlier draft returned ``,@(...)`` — correct for the HashSet in
    ``install-gate.ps1``, wrong for an array — and ``@(Get-LaunchableConfigRoots ...)`` then produced a
    single element that WAS the array. Its string form is every path joined by a space, so
    ``-AllRoots`` resolved one bogus target named ``<root-1> C:\\...\\<root-2>\\settings.json`` and
    reported "Roots examined: 1". Silent, and it survived a smoke test because ``Split-Path`` happens
    to accept arrays.
    """
    home = tmp_path / "h"
    (home / ".claude-account-3").mkdir(parents=True)
    script = (
        f". '{CONFIG_ROOTS}'; "
        f"$r = @(Get-LaunchableConfigRoots -HomeDir '{home}'); "
        "Write-Output $r.Count; Write-Output $r[0].GetType().Name"
    )
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    assert proc.stdout.split() == ["1", "String"], proc.stdout


def test_install_then_the_wired_command_then_the_reader_all_agree(fake_home: Path) -> None:
    """THE ANCHOR TEST: the one path that exercises the whole partition end to end.

    Every other test in this section checks one hop. This one installs into a pinned root, runs the
    string the installer actually wired exactly as Claude Code would, and then reads it back the way a
    session in that root would — with nothing recomputed by the test. A hand-written stamp would let
    this pass whether or not the collector produces one.
    """
    pin = fake_home / ".claude-account-1"
    assert install(pin=pin, home=fake_home).returncode == 0

    cmd = wired(pin / "settings.json")
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", cmd],
        input=json.dumps({"session_id": "e2e", "rate_limits": {"seven_day": window(64.0, 280000)}}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(pin),
    )
    assert proc.returncode == 0, proc.stderr
    assert "64" in proc.stdout

    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert code == OK, doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(64.0)
    assert doc["provenance"] == "OK", (
        "the collector did not stamp the pin, so the cross-root guard cannot fire"
    )
    assert doc["config_root"].lower() == str(pin).lower()
    # And the second root sees nothing, which is the whole point of partitioning.
    code2, doc2, _ = reader("-Json", pin=fake_home / ".claude-account-2", home=fake_home)
    assert code2 == UNKNOWN
    assert doc2["reason"] == "no data"


# --- the predicate now exists in four places, so pin them against each other -------------------

COORD_INSTALL = ROOT / "scripts" / "coord" / "install-coordination.ps1"
GATE_INSTALL = ROOT / "scripts" / "worktree" / "install-gate.ps1"

#: Names that actually occur, or plausibly could, under a home directory on a box running several
#: Claude logins. Each entry is (name, is_a_launchable_account_root).
_ROOT_NAMES = [
    (".claude-account-1", True),
    (".claude-account-42", True),
    (".claude-account-2.lock", False),  # a real directory on this box; carries a settings.json
    (".claude-account-", False),
    (".claude-account-2b", False),
    (".claude-desktop-1", False),  # carries a .claude.json; nothing launches from it
    (".claude-hooks", False),
    (".claude-tools", False),
    (".claudex", False),
]


def test_the_shared_predicate_matches_the_one_install_gate_and_its_python_twin_use() -> None:
    """FOUR COPIES OF ONE RULE, AND THIS IS WHAT KEEPS THEM HONEST.

    ``config-roots.ps1`` was added so ``install-usage-statusline.ps1`` would not write a fourth. It
    could not simply absorb the other three: ``install-gate.ps1`` pairs its copy with a deliberately
    WIDER independent audit population that must not be selected by the same predicate it checks, and
    ``tests/test_gate_installed_parity.py`` holds that copy in parity with a Python reader. Folding
    them in is its own migration with its own test surface.

    So instead of one definition, the rule is one BEHAVIOUR, asserted here across every copy. A future
    edit to any of them turns this red instead of going silent — which is the outcome SDS-3.5 is
    actually after.
    """
    script = "; ".join(
        [
            f". '{CONFIG_ROOTS}'",
            "$g = [regex]'\\A\\.claude-account-\\d+\\z'",  # install-gate.ps1:114, quoted
            "foreach ($n in @(" + ",".join(f"'{n}'" for n, _ in _ROOT_NAMES) + ")) { "
            "$mine = $script:ClaudeAccountRootName.IsMatch($n); "
            "$gate = $g.IsMatch($n); "
            "$coord = $n -match '^\\.claude$|^\\.claude-account-\\d+$'; "
            'Write-Output "$n $mine $gate $coord" }',
        ]
    )
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    seen: dict[str, tuple[bool, bool, bool]] = {}
    for line in proc.stdout.strip().splitlines():
        dir_name, a, b, c = line.split()
        seen[dir_name] = (a == "True", b == "True", c == "True")

    for name, expected in _ROOT_NAMES:
        mine, gate, coord = seen[name]
        assert mine == expected, (
            f"config-roots.ps1 classifies {name} as {mine}, expected {expected}"
        )
        assert gate == expected, f"install-gate.ps1's copy disagrees on {name}"
        assert coord == expected, f"install-coordination.ps1's copy disagrees on {name}"

    # The literal is quoted above rather than parsed out of install-gate.ps1, so assert it is still
    # the literal that file carries — otherwise this test pins a string nobody uses.
    assert "[regex]'\\A\\.claude-account-\\d+\\z'" in GATE_INSTALL.read_text(encoding="utf-8")
    assert "'^\\.claude$|^\\.claude-account-\\d+$'" in COORD_INSTALL.read_text(encoding="utf-8")


def test_the_one_place_the_copies_disagree_is_named_rather_than_discovered() -> None:
    """CASE. ``install-coordination.ps1`` uses ``-match``, which is case-INSENSITIVE by default;
    ``[regex]::IsMatch`` is case-SENSITIVE. A ``.Claude-Account-2`` is creatable on Windows and would
    be accepted by one copy and rejected by the other.

    No such directory exists on the box this was measured on, so nothing differs today. It is asserted
    here anyway, because a difference that is written down is a decision and a difference that is only
    latent is a trap — and the ``-Status`` audit in ``install-usage-statusline.ps1`` reports any
    ``~/.claude*`` directory carrying a settings.json that the predicate rejected, which is what makes
    this under-reach loud rather than silent.
    """
    script = (
        f". '{CONFIG_ROOTS}'; "
        "$n = '.Claude-Account-2'; "
        "Write-Output $script:ClaudeAccountRootName.IsMatch($n); "
        "Write-Output ($n -match '^\\.claude$|^\\.claude-account-\\d+$')"
    )
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    strict, loose = proc.stdout.split()
    assert strict == "False", "the shared predicate stopped being case-sensitive"
    assert loose == "True", "install-coordination.ps1's -match stopped being case-insensitive"


# --- three defects the adversarial review found in the first pass -------------------------------


def test_uninstall_whatif_does_not_claim_it_removed_anything(fake_home: Path) -> None:
    """A DRY RUN THAT REPORTS SUCCESS IS THE SAME LIE, POINTING THE OTHER WAY.

    ``$removed++`` sat OUTSIDE the ShouldProcess guard, so ``-Uninstall -AllRoots -WhatIf`` printed
    "removed: 5" and exited 0 having removed nothing. An operator dry-running before committing reads
    that as "the collector is off" while all five roots keep publishing — and a coordinator branching
    on the documented exit codes gets 0, which the header defines as every root reaching the desired
    state. It is worse than the install claim this change deletes, because a person believes they
    turned something OFF.
    """
    assert install("-AllRoots", pin=None, home=fake_home).returncode == 0
    proc = install("-AllRoots", "-Uninstall", "-WhatIf", pin=None, home=fake_home, collector=None)
    assert proc.returncode == 0, proc.stdout
    assert "removed: 0" in proc.stdout, f"a dry run claimed removals: {proc.stdout}"
    assert "would remove: 2" in proc.stdout
    # And nothing was actually removed.
    for n in (".claude-account-1", ".claude-account-2"):
        assert "statusLine" in json.loads(
            (fake_home / n / "settings.json").read_text(encoding="utf-8")
        )


def test_a_window_carried_from_another_root_is_refused_even_when_the_document_is_ours(
    fake_home: Path,
) -> None:
    """THE ONE-HOP LAUNDERING PATH, and the reason provenance travels with the WINDOW.

    A document-level stamp records who WROTE the file, not where the numbers in it came from, and the
    carry-forward is exactly the hop that separates those. Root A publishes into root B's directory (a
    legacy or hand-copied command). B's next session fires before its first API response, carries A's
    percentages forward, and rebuilds ``published_by`` with B — so a document-level check compares B
    against B, passes, and reports A's headroom as B's. The window kept its older ``captured_at`` and
    would eventually have been called stale; it would never have been called FOREIGN.

    Driven through the real collector, twice, because a hand-written fixture would assert that the
    fixture agrees with itself rather than that the carry-forward stamps what it should.
    """
    a = fake_home / ".claude-account-1"
    b = fake_home / ".claude-account-2"
    state = b / "mefor-usage"  # A publishes into B's directory

    def run(pin: Path, payload: dict[str, Any]) -> None:
        proc = run_single(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(COLLECT),
                "-StateDir",
                str(state),
                "-HomeDir",
                str(fake_home),
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=_env(pin),
        )
        assert proc.returncode == 0, proc.stderr

    run(a, {"session_id": "A", "rate_limits": {"seven_day": window(91.0, 3600)}})
    run(b, {"session_id": "B"})  # B has no rate_limits yet, so A's window is carried forward

    doc = latest(state)
    assert doc["published_by"]["config_root_env"].lower() == str(b).lower(), (
        "the document should now be stamped by B -- that is what makes this laundering"
    )
    assert doc["seven_day"]["config_root_env"].lower() == str(a).lower(), (
        "the carried window must keep A's stamp, exactly as it keeps A's captured_at"
    )

    code, parsed, _ = reader("-StateDir", str(state), "-Json", pin=b, home=fake_home)
    assert code == UNKNOWN
    assert parsed["seven_day"]["used_percentage"] is None, "A's 91% was reported as B's headroom"
    assert "DIFFERENT config root" in parsed["seven_day"]["reason"]


def test_a_root_wired_elsewhere_is_flagged_even_when_it_still_has_an_old_reading(
    fake_home: Path, tmp_path: Path
) -> None:
    """WIRED_ELSEWHERE was unreachable in the one case where it misleads most.

    The diagnosis ran only inside the no-data branch. So a root re-wired to publish into a sibling,
    but still holding its own older ``latest.json``, served that stale percentage as current for
    twenty minutes and then said "no live session is publishing" — which is also false. The session is
    publishing; it is publishing somewhere else, and nothing in the output said so.
    """
    pin = fake_home / ".claude-account-1"
    elsewhere = tmp_path / "sibling" / "mefor-usage"
    (pin / "settings.json").write_text(
        json.dumps(
            {
                "statusLine": {
                    "type": "command",
                    "command": f"# mefor-usage\n$s='c'; $d = '{elsewhere}'",
                }
            }
        ),
        encoding="utf-8",
    )
    # This root DOES have a reading of its own, so the no-data branch never runs.
    state = pin / "mefor-usage"
    state.mkdir()
    now = datetime.now(UTC).isoformat()
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": now,
                "seven_day": {
                    "used_percentage": 20.0,
                    "resets_at_epoch": int(time.time()) + 280000,
                    "captured_at": now,
                },
            }
        ),
        encoding="utf-8",
    )

    code, doc, human = reader(pin=pin, home=fake_home)
    assert "WARNING" in human, f"a mis-wired root reported clean: {human}"
    assert "WAITING WILL NOT FIX THIS" in human
    jcode, parsed, _ = reader("-Json", pin=pin, home=fake_home)
    assert parsed["statusline_state"] == "WIRED_ELSEWHERE"
    assert parsed["wired_state_dir"].lower() == str(elsewhere).lower()
    # THE VERDICT, NOT ONLY THE PROSE -- AND THIS IS THE TEST THAT CAN PIN IT. Both windows here are
    # FRESH, so without the fix the verdict is a clean OK and exit 0 while the same document reports
    # statusline_state=WIRED_ELSEWHERE and the same render prints a WARNING. Two instruments
    # disagreeing inside one run, which is the defect this whole branch exists to remove.
    #
    # The assertion was first written into the no-data test next door, where it could not fail: that
    # one exits 20 because there is nothing to read, whatever the diagnosis does. Caught by reverting
    # the fix and watching the test stay green.
    assert parsed["state"] == "UNKNOWN", parsed
    assert jcode == UNKNOWN, f"mis-wired root with a fresh reading exited {jcode}"
    assert code == UNKNOWN, f"mis-wired root with a fresh reading exited {code}"
    assert "--  OK" not in human, f"the heading claimed OK over a leftover: {human}"


def test_a_root_that_has_no_settings_file_gets_no_backup_line(tmp_path: Path) -> None:
    """A backup path printed for a file that was never copied sends an operator hunting for backups
    that do not exist. Write-SettingsFile reports whether it took one; the caller prints accordingly."""
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    out = install("-ConfigDir", str(fresh), pin=None).stdout
    assert "no backup taken" in out
    assert ".bak-usage-" not in out
    assert not list(fresh.glob("*.bak-usage-*"))

    # And a root that DID have one says so, with a file that really exists.
    out2 = install("-ConfigDir", str(fresh), "-RefreshInterval", "9000", pin=None).stdout
    assert ".bak-usage-" in out2
    assert list(fresh.glob("*.bak-usage-*"))


def test_status_does_not_report_an_unparseable_root_as_carrying_nothing(fake_home: Path) -> None:
    """A corrupt settings.json is not a clean one. It may carry a working statusLine this audit cannot
    see, so "carries none" would steer an operator away from a stray publisher rather than towards it."""
    pin = fake_home / ".claude-account-1"
    (pin / "settings.json").write_text("{ not json", encoding="utf-8")
    out = install("-Status", pin=pin, home=fake_home, collector=None).stdout
    assert "could not be parsed" in out
    # The PER-ROOT line, not the audit's wording: the audit legitimately says "carries no statusLine of
    # ours" about .claude-account-2.lock in the same output, so matching that phrase alone would pass
    # or fail for the wrong directory.
    assert "publishes to  : nothing" not in out


def test_a_pin_naming_a_missing_directory_is_diagnosed_as_missing_not_unwired(
    fake_home: Path,
) -> None:
    """Two states with different fixes. Reported as "no settings.json", the remedy printed is an
    installer invocation the installer REFUSES, so the operator follows the advice, gets a refusal, and
    nothing has named the actual fault."""
    ghost = fake_home / ".claude-account-77"
    _, doc, human = reader("-Json", pin=ghost, home=fake_home)
    assert doc["statusline_state"] == "NO_SUCH_ROOT"
    _, _, human = reader(pin=ghost, home=fake_home)
    assert "NO SUCH DIRECTORY" in human
    assert "Fix CLAUDE_CONFIG_DIR" in human


def test_the_survey_names_a_settings_bearing_root_its_own_predicate_rejected(
    fake_home: Path,
) -> None:
    """The survey enumerates by an anchored, case-sensitive name shape. Without a second pass selected
    by a DIFFERENT rule, it can only ever confirm its own predicate — and a root the predicate rejects
    while it burns quota would be absent from a list the operator reads as complete."""
    # .claude-account-2.lock carries a settings.json and is rejected by the name predicate.
    now = datetime.now(UTC).isoformat()
    state = fake_home / ".claude-account-1" / "mefor-usage"
    state.mkdir()
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": now,
                "seven_day": {
                    "used_percentage": 5.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": now,
                },
            }
        ),
        encoding="utf-8",
    )
    _, _, human = reader("-AllRoots", pin=fake_home / ".claude-account-1", home=fake_home)
    assert "not surveyed" in human, f"the audit pass did not run: {human}"
    assert ".claude-account-2.lock" in human
    # And the heading must not claim completeness it cannot deliver.
    assert "Every config root on this box" not in human


def test_a_correctly_wired_root_that_stopped_publishing_still_warns(fake_home: Path) -> None:
    """TONIGHT'S ACTUAL FAILURE, and the arm the mis-wire warning cannot reach.

    Every root on the box this was written for is wired correctly, names a collector that exists, and
    has published NOTHING for the better part of an hour across nine live sessions. A healthy root
    reports WIRED_HERE, which the mis-wire warning deliberately excludes — so without a second arm this
    case falls through to a bare "reading is N min old", the line a reader skims past.

    The earlier message said "-- no live session is publishing", which at least signalled that
    something was wrong. Deleting it was right (nothing checked it, and it is false when a session is
    publishing into another root) but it left this case with no signal at all. Caught by the Steward
    seat, whose whole concern is that a quiet plausible stale reading is more dangerous than a loud
    failure.
    """
    pin = fake_home / ".claude-account-1"
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0

    state = pin / "mefor-usage"
    state.mkdir(exist_ok=True)
    old = (datetime.now(UTC) - timedelta(minutes=48)).isoformat()
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": old,
                "seven_day": {
                    "used_percentage": 64.0,
                    "resets_at_epoch": int(time.time()) + 280000,
                    "captured_at": old,
                },
            }
        ),
        encoding="utf-8",
    )

    code, doc, human = reader(pin=pin, home=fake_home)
    assert code == UNKNOWN
    assert "WARNING" in human, f"a wired-but-silent root produced no warning:\n{human}"
    assert "wired correctly" in human
    # The causes are offered as alternatives, never asserted -- nothing here can tell them apart.
    assert "cannot tell them apart" in human
    # And the properties the staleness guard already provided must survive alongside it.
    _, parsed, _ = reader("-Json", pin=pin, home=fake_home)
    assert parsed["statusline_state"] == WIRED_HERE
    assert parsed["seven_day"]["used_percentage"] == pytest.approx(64.0), (
        "the number must still show"
    )
    assert parsed["seven_day"]["reading_age_min"] is not None, "its age must still show"
    assert parsed["seven_day"]["projected_at_reset"] is None, (
        "a stale reading must not be projected"
    )


def test_two_installs_in_the_same_second_do_not_destroy_the_only_backup(tmp_path: Path) -> None:
    """A BACKUP THAT HOLDS POST-INSTALL CONTENT IS WORSE THAN NO BACKUP, because the operator is told
    one exists. The stamp has one-second resolution, so two runs inside the same second collided:
    measured on a fixture, run 2 overwrote run 1's pre-install copy with run 1's post-install content,
    and the only original was destroyed by the run that claimed to be preserving it."""
    root = tmp_path / "root"
    root.mkdir()
    settings = root / "settings.json"
    original = json.dumps({"mine": "keep me"})
    settings.write_text(original, encoding="utf-8")

    assert install("-ConfigDir", str(root), pin=None).returncode == 0
    assert install("-ConfigDir", str(root), "-RefreshInterval", "9000", pin=None).returncode == 0

    backups = sorted(root.glob("settings.json.bak-usage-*"))
    assert len(backups) == 2, f"the second run reused the first run's backup name: {backups}"
    # Exactly one of them must still hold the untouched original.
    contents = [b.read_text(encoding="utf-8") for b in backups]
    assert original in contents, f"the pre-install content was destroyed: {contents}"


def test_the_survey_refuses_a_window_carried_from_another_root(fake_home: Path) -> None:
    """THE SURVEY IS THE ONLY PLACE ACCOUNTS ARE COMPARED, so it is where this refusal matters most --
    and it was the one place it did not run.

    Checking only the DOCUMENT stamp passes a carry-forward: the document was written by this root and
    sits under this root, while the numbers inside came from another. Measured before the fix: the
    single-root reader refused both windows with "refusing to report another account's headroom", and
    the survey in the SAME run printed those exact percentages as the other root's own, unlabelled. An
    operator scanning the survey for the account with the most headroom reads one account's number as
    another's.
    """
    a = fake_home / ".claude-account-1"
    b = fake_home / ".claude-account-2"
    state = b / "mefor-usage"

    def fire(pin: Path, payload: dict[str, Any]) -> None:
        proc = run_single(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(COLLECT),
                "-StateDir",
                str(state),
                "-HomeDir",
                str(fake_home),
            ],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=_env(pin),
        )
        assert proc.returncode == 0, proc.stderr

    # A publishes into B's directory, then B's own un-warmed session carries it forward.
    fire(
        a,
        {
            "session_id": "A",
            "rate_limits": {"seven_day": window(88.0, 280000)},
        },
    )
    fire(b, {"session_id": "B"})
    # And A gets a healthy publish of its own, so the survey renders at all.
    (a / "mefor-usage").mkdir(exist_ok=True)
    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(COLLECT),
            "-StateDir",
            str(a / "mefor-usage"),
            "-HomeDir",
            str(fake_home),
        ],
        input=json.dumps(
            {
                "session_id": "A2",
                "rate_limits": {"seven_day": window(12.0, 280000)},
            }
        ),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(a),
    )
    assert proc.returncode == 0, proc.stderr

    _, doc, _ = reader("-AllRoots", "-Json", pin=a, home=fake_home)
    rows = {r["root"].lower(): r for r in doc["roots"]}
    row_b = rows[str(b).lower()]
    assert row_b["seven"] is None, f"A's 88% was printed as B's own: {row_b}"
    assert "DIFFERENT config root" in row_b["note"], row_b
    # A's own row is untouched -- the refusal fires on error, not on the survey as a whole.
    assert rows[str(a).lower()]["seven"] == pytest.approx(12.0)


def test_the_survey_ages_a_row_by_its_windows_not_by_the_document(fake_home: Path) -> None:
    """The collector rewrites the document stamp on EVERY fire, including a pure carry-forward, so it
    dates the last FIRE and not the OBSERVATION. Aged by the document, a six-hour-old reading renders
    as "[seen 0 min ago]" -- a stale number wearing a fresh timestamp, which is the exact shape rule 1
    exists to forbid."""
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    state.mkdir()
    old = (datetime.now(UTC) - timedelta(hours=6)).isoformat()
    now = datetime.now(UTC).isoformat()
    # A document written just now, whose windows were observed six hours ago -- what a carry-forward
    # produces.
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": now,
                "published_by": {"config_root_env": str(pin)},
                "seven_day": {
                    "used_percentage": 33.0,
                    "resets_at_epoch": int(time.time()) + 280000,
                    "captured_at": old,
                    "config_root_env": str(pin),
                },
            }
        ),
        encoding="utf-8",
    )
    _, doc, human = reader("-AllRoots", "-Json", pin=pin, home=fake_home)
    row = next(r for r in doc["roots"] if r["root"].lower() == str(pin).lower())
    assert row["age_min"] > 300, f"the row was aged by the document, not its windows: {row}"
    assert row["stale"] is True, row
    _, _, human = reader("-AllRoots", pin=pin, home=fake_home)
    assert "STALE" in human, human


def test_the_survey_prints_no_number_for_a_window_whose_reset_has_passed(fake_home: Path) -> None:
    """The survey is the only place accounts are compared, so a gone week's number must not show
    as this root's pool. The same rule the single-root read applies."""
    pin = fake_home / ".claude-account-1"
    publish(pin / "mefor-usage", seven=95.0, seven_epoch=int(time.time()) - 300)
    _, doc, _ = reader("-AllRoots", "-Json", pin=pin, home=fake_home)
    row = next(r for r in doc["roots"] if r["root"].lower() == str(pin).lower())
    assert row["seven"] is None, row
    assert "reset has passed" in row["note"], row


def test_rewired_says_which_thing_changed_not_always_the_publish_path(tmp_path: Path) -> None:
    """A LINE THAT CONTRADICTS THE TWO LINES UNDER IT.

    REWIRED is entered whenever the command is not byte-identical, which is a WEAKER fact than any
    single reason for it. The message asserted "published somewhere else" unconditionally, and the
    owner's real run produced:

        replaced a mefor-usage statusLine that published somewhere else
        was: <account-5>/mefor-usage
        now: <account-5>/mefor-usage

    The publish path had not moved at all. The COLLECTOR had. Same defect class as the claim this
    whole branch removes: a sentence stating more than the check behind it established.
    """
    root = tmp_path / "root"
    root.mkdir()
    other_collector = tmp_path / "elsewhere" / "usage-collect.ps1"
    other_collector.parent.mkdir()
    other_collector.write_text("# stand-in", encoding="utf-8")

    # Wired to the RIGHT publish path but a DIFFERENT collector.
    # collector= KEYWORD, not -CollectorPath in args: the helper always adds that flag, so passing it
    # again binds the parameter twice and pwsh refuses it ("specified more than once").
    assert install("-ConfigDir", str(root), pin=None, collector=other_collector).returncode == 0
    first = wired(root / "settings.json")
    assert str(tmp_path / "elsewhere") in first

    out = install("-ConfigDir", str(root), pin=None).stdout
    assert "REWIRED" in out, out
    assert "published somewhere else" not in out, (
        f"the publish path did not move, but the line says it did:\n{out}"
    )
    assert "named a different collector" in out, out
    assert "collector was:" in out and "collector now:" in out, out

    # And the genuine case must still say what it always said.
    root2 = tmp_path / "root2"
    root2.mkdir()
    (root2 / "settings.json").write_text(
        json.dumps(
            {
                "statusLine": {
                    "type": "command",
                    "command": f"# mefor-usage\n$s = '{COLLECT}'; $d = '{tmp_path / 'far-away'}'; x",
                }
            }
        ),
        encoding="utf-8",
    )
    out2 = install("-ConfigDir", str(root2), pin=None).stdout
    assert "published somewhere else" in out2, out2


# ------------------------------------------------------- a cancelled account has no headroom
#
# WHY THIS SECTION EXISTS. The four honesty rules above are all about a reading that is stale, thin, or
# from the wrong account. None of them catches a CANCELLED account, and that case fails in the worst
# possible direction: a dead account stops burning quota, so its last percentage freezes low and its
# publish directory goes quiet -- which is byte-identical to an IDLE account with a full pool. A seat
# comparing roots to find "the one with headroom" is therefore steered straight at the account that has
# none, and the reader's own remedy for a quiet root ("start a NEW session pinned to this root") points
# it at a subscription that no longer exists.
#
# The fix is a marker in the root's publish directory, and these tests pin the four things that would
# make it worthless: that it BEATS a live-looking number, that a damaged marker fails CLOSED, that a
# future-dated cancellation does NOT throw away a pool that is still spendable, and that the survey --
# the one place accounts are compared -- honours it too.

AVAIL = ROOT / "scripts" / "coord" / "account-availability.ps1"
UNAVAILABLE = 21

_PCT = re.compile(r"\d+(?:\.\d+)?\s*%")


def avail(*args: str, home: Path | None = None) -> subprocess.CompletedProcess[str]:
    cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(AVAIL)]
    if home is not None:
        cmd += ["-HomeDir", str(home)]
    cmd += list(args)
    return run_single(
        cmd, capture_output=True, text=True, timeout=TIMEOUT, check=False, env=_env(None)
    )


def tempting(state: Path) -> None:
    """A fresh, LOW reading -- what a cancelled account leaves behind, and the whole hazard.

    Low rather than high on purpose. A frozen 3% is the shape that gets an account CHOSEN; a frozen
    95% would be skipped for the right answer by accident, and a fixture that cannot fail the way the
    defect fails proves nothing about the guard.
    """
    publish(state, seven=3.0)


def test_a_cancelled_account_reports_unavailable_and_never_a_percentage(tmp_path: Path) -> None:
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    tempting(state)

    # Positive control FIRST. Without the marker this root answers OK with a percentage, so the
    # assertions below are measuring the marker rather than an inert fixture that could never say
    # anything else.
    code, doc = read(state)
    assert code == OK, doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(3.0)

    marked = avail("-Mark", "-ConfigDir", str(root), "-Reason", "subscription cancelled")
    assert marked.returncode == 0, marked.stdout

    code, doc = read(state)
    assert code == UNAVAILABLE, doc
    assert doc["state"] == "UNAVAILABLE"
    assert doc["reason"] == "subscription cancelled"
    # THE KEY IS ABSENT, NOT NULL. Emitting it as null would let a consumer that reaches straight
    # for a percentage read this as a window that merely has not published yet.
    assert "seven_day" not in doc, doc

    _, _, human = reader("-StateDir", str(state))
    assert _PCT.search(human) is None, f"a percentage survived under a cancelled account:\n{human}"
    assert "NO SUBSCRIPTION" in human


def test_a_mark_argument_without_mark_refuses_instead_of_prompting(tmp_path: Path) -> None:
    """Vault BACKLOG #3627: ``-Reason`` alone binds the ``Mark`` set without ``-Mark``. Red pre-fix."""
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    rc, err = run_holding_stdin_open(
        [
            "pwsh", "-NoProfile", "-File", str(AVAIL),
            "-HomeDir", str(tmp_path), "-ConfigDir", str(root), "-Reason", "cancelled",
        ],
        cwd=tmp_path,
        env=_env(None),
    )  # fmt: skip
    assert rc != 0, "a Mark argument without -Mark must be refused, not marked"
    assert "-Mark" in err, err
    # Refused means NOTHING written: the marker's publish directory is created on the write path.
    assert not (root / "mefor-usage").exists()


def test_a_damaged_marker_fails_closed_rather_than_reading_as_available(tmp_path: Path) -> None:
    """The file exists because somebody put it there, so the reachable states are "cancelled" and
    "cancelled, and the note about it is damaged". Reading a damaged note as an all-clear is how a
    guard goes silent while still looking present -- and it would do so over the exact numbers the
    marker was written to suppress.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    tempting(state)
    (state / "unavailable.json").write_text("{ not json", encoding="utf-8")

    code, doc = read(state)
    assert code == UNAVAILABLE, doc
    assert doc["marker_state"] == "MALFORMED"
    # Reported as a damaged marker, not as a recorded cancellation: the two need different fixes, and
    # an operator told "cancelled" about an account they never marked has been sent the wrong way.
    _, _, human = reader("-StateDir", str(state))
    assert "damaged" in human
    assert _PCT.search(human) is None, human


def test_a_future_dated_cancellation_leaves_the_pool_readable_and_names_its_end(
    tmp_path: Path,
) -> None:
    """A subscription normally runs to the end of its billing period, and until then the pool is real
    and worth spending. Suppressing the numbers there would throw away a true reading; the END DATE is
    the part the reader would otherwise have no way to know.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    publish(state, seven=61.0)

    when = (datetime.now(UTC) + timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
    out = avail(
        "-Mark",
        "-ConfigDir",
        str(root),
        "-Reason",
        "subscription cancelled",
        "-EffectiveFrom",
        when,
    )
    assert out.returncode == 0, out.stdout

    code, doc = read(state)
    assert code == OK, doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(61.0)
    assert doc["cancellation_pending_from"] == when

    _, _, human = reader("-StateDir", str(state))
    assert "still live until" in human and when in human


def test_a_marker_timestamp_is_reported_in_iso_utc_not_the_boxs_local_format(
    tmp_path: Path,
) -> None:
    """``ConvertFrom-Json`` coerces an ISO field into a [datetime] before our code sees it, and
    stringifying that yields the machine's LOCAL short format -- measured while writing this as
    "09/08/2026 23:29:04": the Z gone, and a day/month order that reads as 9 August to half the world.

    It is the sole audit trail for why an account is being skipped, so an ambiguous date is the wrong
    kind of wrong. Asserted on the RAW JSON TEXT: parsing it back in Python re-coerces the value and
    would let a local-format string pass, which is the instrument answering a different question.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    out = avail("-Mark", "-ConfigDir", str(root), "-Reason", "cancelled")
    assert out.returncode == 0, out.stdout

    proc = run_single(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(READ),
            "-StateDir",
            str(root / "mefor-usage"),
            "-Json",
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=_env(None),
    )
    m = re.search(r'"marked_at":"([^"]*)"', proc.stdout)
    assert m, f"no marked_at in the reader's output: {proc.stdout}"
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", m.group(1)), m.group(1)


def test_the_survey_never_ranks_a_cancelled_root_as_headroom(fake_home: Path) -> None:
    """The survey is the ONLY place accounts are compared, so it is where a cancelled one does its
    damage -- it presents as the emptiest pool in the list.
    """
    live = fake_home / ".claude-account-1"
    dead = fake_home / ".claude-account-2"
    assert install("-ConfigDir", str(live), pin=None, home=fake_home).returncode == 0
    publish(live / "mefor-usage", seven=61.0)
    tempting(dead / "mefor-usage")

    # Positive control: the tempting row really is visible as a percentage before it is marked, or the
    # assertion below passes over a survey that was never printing it.
    _, _, before = reader("-AllRoots", pin=live, home=fake_home)
    assert "3%" in before, before

    out = avail("-Mark", "-ConfigDir", str(dead), "-Reason", "subscription cancelled")
    assert out.returncode == 0, out.stdout

    _, _, after = reader("-AllRoots", pin=live, home=fake_home)
    dead_row = next(x for x in after.splitlines() if str(dead) in x)
    assert "UNAVAILABLE" in dead_row, dead_row
    assert _PCT.search(dead_row) is None, dead_row
    # The live account is untouched -- a guard that suppressed every row would pass the line above.
    assert "61%" in after, after


def test_the_collector_refuses_to_refresh_a_cancelled_roots_document(tmp_path: Path) -> None:
    """Every publish rewrites captured_at, so a session running under a cancelled root would keep that
    root's document looking freshly MEASURED -- disarming the staleness guard on the one account where
    staleness is the truth.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    tempting(state)
    out = avail("-Mark", "-ConfigDir", str(root), "-Reason", "subscription cancelled")
    assert out.returncode == 0, out.stdout

    before = (state / "latest.json").read_text(encoding="utf-8")
    line = collect(state, {"rate_limits": {"seven_day": window(88.0, 3600)}})
    assert "unavailable" in line, line
    assert (state / "latest.json").read_text(encoding="utf-8") == before

    # CONTROL. A guard that suppressed every publish would pass the assertion above, so a live root
    # has to still work in the same test.
    ok = tmp_path / "live"
    collect(ok, {"rate_limits": {"seven_day": window(88.0, 3600)}})
    assert latest(ok)["seven_day"]["used_percentage"] == pytest.approx(88.0)


def test_marking_refuses_a_config_root_that_does_not_exist(tmp_path: Path) -> None:
    """``New-Item -Force`` builds every missing ancestor, so a typo'd path would have this command
    MANUFACTURE a config root nothing can launch from and then declare it cancelled -- a wholly
    fictional account, recorded as fact, with nothing reporting a problem. Same rule the installer
    already enforces.
    """
    ghost = tmp_path / ".claude-account-99"
    out = avail("-Mark", "-ConfigDir", str(ghost), "-Reason", "cancelled")
    assert out.returncode == 1, out.stdout
    assert "REFUSED" in out.stdout
    assert not ghost.exists(), "the refusal created the root it refused"


def test_an_unparseable_effective_from_is_refused_rather_than_treated_as_now(
    tmp_path: Path,
) -> None:
    """Falling back to "now" would mark a still-live account dead -- the opposite of what was asked,
    and indistinguishable from it having worked.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    out = avail("-Mark", "-ConfigDir", str(root), "-Reason", "x", "-EffectiveFrom", "next Tuesday")
    assert out.returncode == 1, out.stdout
    assert not (root / "mefor-usage" / "unavailable.json").exists()


def test_marking_is_reversible_and_clearing_nothing_is_not_an_error(tmp_path: Path) -> None:
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    tempting(state)

    assert avail("-Mark", "-ConfigDir", str(root), "-Reason", "cancelled").returncode == 0
    assert read(state)[0] == UNAVAILABLE
    assert avail("-Clear", "-ConfigDir", str(root)).returncode == 0
    assert read(state)[0] == OK, "clearing the marker did not restore a normal reading"

    # The desired end state is "no marker here", and it already holds. A non-zero exit would make a
    # correct no-op look like a failure to a caller that branches on the code.
    again = avail("-Clear", "-ConfigDir", str(root))
    assert again.returncode == 0, again.stdout
    assert "NOTHING TO CLEAR" in again.stdout


def test_an_unmarked_root_is_untouched_by_any_of_this(tmp_path: Path) -> None:
    """The absent-marker arm is the only silent one, and it is the overwhelmingly normal case. If it
    ever stopped meaning AVAILABLE, every root on the box would go dark at once.
    """
    state = tmp_path / "plain"
    publish(state, seven=61.0)
    code, doc = read(state)
    assert code == OK, doc
    assert doc["seven_day"]["used_percentage"] == pytest.approx(61.0)
    assert doc["cancellation_pending_from"] is None


def test_a_damaged_marker_does_not_stop_a_live_account_publishing(tmp_path: Path) -> None:
    """FAIL CLOSED IN THE READER, FAIL OPEN IN THE WRITER -- and the first version of the collector
    guard got this backwards.

    It suppressed on MALFORMED as well as UNAVAILABLE, so a torn write or a half-flushed marker would
    stop a LIVE account publishing at all, with one status-bar line as the only signal. That is exactly
    what the collector's own comment forbids, and the try/catch around the call did not cover it: the
    guard catches a THROW, not a MALFORMED verdict.

    The asymmetry is deliberate and this test is the only thing pinning it. A damaged marker must still
    REFUSE on the read -- asserted here in the same test, so a fix that simply stopped honouring
    MALFORMED anywhere would fail rather than pass.
    """
    root = tmp_path / ".claude-account-9"
    root.mkdir()
    state = root / "mefor-usage"
    state.mkdir()
    (state / "unavailable.json").write_text("{ torn write", encoding="utf-8")

    line = collect(state, {"rate_limits": {"seven_day": window(42.0, 3600)}})
    assert "unavailable" not in line, f"a damaged marker blanked a live account: {line}"
    assert latest(state)["seven_day"]["used_percentage"] == pytest.approx(42.0)

    # ... and the reader still refuses it, which is where fail-closed belongs.
    code, doc = read(state)
    assert code == UNAVAILABLE, doc
    assert doc["marker_state"] == "MALFORMED"


# ------------------------------------------ BACKLOG #1459: roots that never publish, and why
#
# Measured 2026-09-30 across six live config roots. The account roots that DID publish carry a
# single-quoted command the readers misfiled as legacy. One that never published carries the
# PowerShell-source command the old installer emitted: bash rejects it, and the reader still called it
# WIRED_HERE and told the operator to start a session and wait. The tests below start from those two
# shapes, not from a root the current installer prepared, because that root was never the problem.

HOOK = ROOT / "scripts" / "hooks" / "usage-headroom-inject.ps1"
WIRED_POWERSHELL_SOURCE = "WIRED_POWERSHELL_SOURCE"


def _powershell_source_command(collector: Path, state: Path) -> str:
    """The shape the pre-shell-agnostic installer wrote, rebuilt with this fixture's paths. Its
    `$d` names the root's OWN publish path, which is what made the reader call it WIRED_HERE."""
    return (
        "# mefor-usage\n"
        f"$s = '{collector}'; $d = '{state}'; "
        "if (Test-Path -LiteralPath $s) { & pwsh -NoProfile -File $s -StateDir $d } "
        "else { Write-Output 'mefor-usage: collector missing' }"
    )


def _hook(pin: Path, home: Path) -> str:
    """The spawn hook as a session pinned to ``pin`` runs it: no -StateDir, so the root comes from
    the pin alone. USERPROFILE points the reader's survey at the fixture home, never the real one."""
    env = _env(pin)
    env["USERPROFILE"] = str(home)
    env.pop("CLAUDE_CODE_ENTRYPOINT", None)
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(HOOK)],
        input=json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Agent", "tool_input": {}}),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    ctx: str = json.loads(proc.stdout)["hookSpecificOutput"]["additionalContext"]
    return ctx


def _run_under_bash(
    bash: str, tmp_path: Path, command: str, pin: Path, payload: dict[str, Any]
) -> subprocess.CompletedProcess[str]:
    """Run a wired statusLine string the way Claude Code does: as a bash script, payload on stdin."""
    script = tmp_path / f"statusline-{time.monotonic_ns()}.sh"
    script.write_bytes(command.encode("utf-8"))
    return subprocess.run(
        [bash, script.as_posix()],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=probe_env(Path(bash), _env(pin)),
    )


def test_the_single_quoted_shape_the_publishing_roots_carry_reads_as_wired_here(
    bash: str, fake_home: Path, tmp_path: Path
) -> None:
    """THE ROOTS THAT WORKED WERE MISFILED. Their command names its publish path in single quotes,
    which both shells run, and the readers matched only double quotes or a `$d = '...'` assignment.
    So every publishing root read as WIRED_LEGACY -- "carries no -StateDir" -- beside a -StateDir."""
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    command = f"# mefor-usage\npwsh -NoProfile -File '{COLLECT}' -StateDir '{state}'"
    (pin / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": command}}), encoding="utf-8"
    )
    rc, err = bash_parse(bash, tmp_path, command, "single-quoted.sh")
    assert rc == 0, f"the shape under test is not one bash runs, so this proves nothing: {err!r}"

    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == WIRED_HERE, doc
    assert doc["wired_state_dir"].lower() == str(state).lower(), doc

    status = install("-Status", pin=pin, home=fake_home, collector=None).stdout
    assert "legacy command, no -StateDir" not in status, status
    assert f"collector     : {COLLECT}" in status, status


def test_a_root_the_old_installer_wired_publishes_after_one_reinstall_and_the_hook_reads_it(
    bash: str, fake_home: Path, tmp_path: Path
) -> None:
    """THE CHECK THE ROW ASKS FOR: a real headroom figure at the spawn point, on a root that was NOT
    prepared by the current installer. It starts where a live root was on 2026-09-30 and goes
    through the real installer, the real bash, the real collector and the real hook, which resolves
    the root from the pin alone.

    STEP 1 IS THE CONTROL. Without the defect reproduced first, the green at step 5 could be a
    fixture that was never broken.
    """
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    (pin / "settings.json").write_text(
        json.dumps(
            {
                "statusLine": {
                    "type": "command",
                    "command": _powershell_source_command(COLLECT, state),
                    "refreshInterval": 10000,
                }
            }
        ),
        encoding="utf-8",
    )
    payload = {
        "session_id": "e2e-1459",
        "rate_limits": {"seven_day": window(64.0, 280000)},
    }

    # 1. The defect: bash rejects the old command, pwsh never starts, nothing publishes.
    before = _run_under_bash(bash, tmp_path, wired(pin / "settings.json"), pin, payload)
    assert before.returncode != 0 and "syntax error" in before.stderr, before
    assert not (state / "latest.json").exists()

    # 2. The reader names the cause and the fix, and the hook passes both on. It used to say
    # WIRED_HERE and "start a NEW session", which waiting can never satisfy.
    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert code == UNKNOWN, doc
    assert doc["statusline_state"] == WIRED_POWERSHELL_SOURCE, doc
    assert any(str(pin) in line for line in doc["statusline_remedy"]), doc
    ctx = _hook(pin, fake_home)
    assert "verdict: UNKNOWN" in ctx and WIRED_POWERSHELL_SOURCE in ctx, ctx
    assert str(pin) in ctx, f"the remedy must name the root: {ctx}"
    # The remedy writes a config root outside git, and this text reaches every spawning session.
    assert "OWNER action" in ctx, f"the remedy must not read as a task for the session: {ctx}"
    status = install("-Status", pin=pin, home=fake_home, collector=None).stdout
    assert "publishes NOTHING" in status, status

    # 3. One installer run, which says what it replaced -- not "some other way".
    proc = install("-ConfigDir", str(pin), pin=None, home=fake_home)
    assert proc.returncode == 0, proc.stdout
    assert "REWIRED" in proc.stdout and "that was PowerShell source" in proc.stdout, proc.stdout
    assert "some other way" not in proc.stdout, proc.stdout

    # 4. bash runs the new command and the collector publishes under this root.
    after = _run_under_bash(bash, tmp_path, wired(pin / "settings.json"), pin, payload)
    assert after.returncode == 0, after.stderr
    assert (state / "latest.json").exists(), "bash ran the rewired command and nothing published"

    # 5. The spawn hook prints a real figure, not UNKNOWN.
    ctx = _hook(pin, fake_home)
    assert "verdict: OK" in ctx, ctx
    assert re.search(r"7d\s+64\.0% used", ctx), ctx
    assert WIRED_POWERSHELL_SOURCE not in ctx, ctx


def test_a_powershell_source_root_with_a_stale_reading_still_warns_in_the_text_output(
    fake_home: Path,
) -> None:
    """A REGRESSION THE #1459 CHANGE ITSELF OPENED, caught by its own second review round.

    WIRED_POWERSHELL_SOURCE is deliberately not in $dxUntrusted, and the "wired correctly yet nothing
    fresh" arm fires only for WIRED_HERE. So a root carrying the old command beside an old
    latest.json fell through both arms: the operator saw a bare "reading is N min old" and neither
    the cause nor the fix. Before #1459 that root read WIRED_HERE and at least got a warning.
    """
    pin = fake_home / ".claude-account-1"
    state = pin / "mefor-usage"
    state.mkdir(parents=True)
    (pin / "settings.json").write_text(
        json.dumps(
            {
                "statusLine": {
                    "type": "command",
                    "command": _powershell_source_command(COLLECT, state),
                }
            }
        ),
        encoding="utf-8",
    )
    old = (datetime.now(UTC) - timedelta(minutes=48)).isoformat()
    (state / "latest.json").write_text(
        json.dumps(
            {
                "captured_at": old,
                "seven_day": {
                    "used_percentage": 64.0,
                    "resets_at_epoch": int(time.time()) + 280000,
                    "captured_at": old,
                },
            }
        ),
        encoding="utf-8",
    )

    code, parsed, _ = reader("-Json", pin=pin, home=fake_home)
    assert code == UNKNOWN, parsed
    assert parsed["statusline_state"] == WIRED_POWERSHELL_SOURCE, parsed

    _, _, human = reader(pin=pin, home=fake_home)
    assert "WARNING" in human, f"a PowerShell-source root with a stale reading was silent:\n{human}"
    assert "PowerShell source" in human, human
    assert "install-usage-statusline.ps1" in human and str(pin) in human, (
        f"the warning must carry the fix and name the root:\n{human}"
    )
    assert "Start a NEW session" not in human, human
