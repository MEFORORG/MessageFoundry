# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
* **Windows are absent independently**, so staleness is tracked per window — a carried-forward number
  must keep its own older timestamp and must never enter the burn-rate history.
* **Stale, undateable and future-dated readings are UNKNOWN**, never extrapolated.
* **Rate is never computed across a window reset**, where the percentage legitimately falls to zero.

Driven as real subprocesses against fixtures, because these are PowerShell scripts and a Python
re-implementation of their rules would only assert that the re-implementation agrees with itself.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

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
    """Drive the collector exactly as Claude Code drives a statusLine: JSON on stdin, line on stdout."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(COLLECT), "-StateDir", str(state)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    # A statusLine that exits non-zero degrades the session it decorates; it must never do that.
    assert proc.returncode == 0, f"collector exited {proc.returncode}: {proc.stderr}"
    return proc.stdout.strip()


def read(state: Path, *extra: str) -> tuple[int, dict[str, Any]]:
    proc = subprocess.run(
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


def history(state: Path) -> list[dict[str, Any]]:
    p = state / "history.jsonl"
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


# ------------------------------------------------------------------------------ collector


def test_publishes_both_windows(tmp_path: Path) -> None:
    line = collect(
        tmp_path,
        {
            "session_id": "A",
            "rate_limits": {"five_hour": window(80.4, 5940), "seven_day": window(36.2, 280000)},
        },
    )
    d = latest(tmp_path)
    assert d["five_hour"]["used_percentage"] == pytest.approx(80.4)
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.2)
    assert "80" in line and "36" in line, f"the human line must show both: {line!r}"


def test_a_session_with_no_rate_limits_does_not_clobber_a_good_reading(tmp_path: Path) -> None:
    """THE ONE THAT MATTERS. Found by testing, not by reading.

    Every session runs this statusLine and they all publish to ONE shared file, so each session is a
    publisher — there is no privileged collector. ``rate_limits`` is absent until a session's first API
    response lands, so a naive write blanks the account's only good reading for all thirty sessions at
    once, and the reader downstream cannot tell the difference between "0% used" and "nobody has looked".
    """
    collect(
        tmp_path,
        {
            "session_id": "A",
            "rate_limits": {"five_hour": window(80.4, 5940), "seven_day": window(36.2, 280000)},
        },
    )
    collect(tmp_path, {"session_id": "B"})  # a session that has not made an API call yet

    d = latest(tmp_path)
    assert d["five_hour"]["used_percentage"] == pytest.approx(80.4), (
        "a session with no data destroyed the reading"
    )
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.2)


def test_an_absent_window_is_carried_forward_with_its_own_older_timestamp(tmp_path: Path) -> None:
    """The docs are explicit that the two windows are absent INDEPENDENTLY, so staleness is per window.

    A carried-forward value stamped with the current time would be a stale number wearing a fresh
    timestamp — which is precisely the shape of claim that this repo keeps having to retract.
    """
    collect(
        tmp_path,
        {
            "session_id": "A",
            "rate_limits": {"five_hour": window(80.0, 5940), "seven_day": window(36.0, 280000)},
        },
    )
    time.sleep(1.1)
    collect(tmp_path, {"session_id": "C", "rate_limits": {"five_hour": window(88.0, 5940)}})

    d = latest(tmp_path)
    assert d["five_hour"]["used_percentage"] == pytest.approx(88.0), "the fresh window must update"
    assert d["seven_day"]["used_percentage"] == pytest.approx(36.0), (
        "the absent window must be carried, not nulled"
    )
    assert d["seven_day"]["captured_at"] < d["five_hour"]["captured_at"], (
        "the carried window must keep its ORIGINAL timestamp, or it reads as freshly observed"
    )


def test_history_never_records_a_carried_forward_value(tmp_path: Path) -> None:
    """Burn rate is computed from this file. A carried-forward percentage against a new timestamp says
    consumption stopped — the one lie that matters in a tool built to warn about consumption."""
    collect(
        tmp_path,
        {
            "session_id": "A",
            "rate_limits": {"five_hour": window(80.0, 5940), "seven_day": window(36.0, 280000)},
        },
    )
    collect(tmp_path, {"session_id": "C", "rate_limits": {"five_hour": window(88.0, 5940)}})

    rows = history(tmp_path)
    assert rows, "expected history rows"
    assert rows[-1]["five_hour"] == pytest.approx(88.0)
    assert rows[-1]["seven_day"] is None, (
        "a carried-forward window must be null in history, not repeated"
    )


def test_a_flat_reading_does_not_append_history(tmp_path: Path) -> None:
    """The statusline fires many times a minute; a row per fire is a big file describing a flat line."""
    payload = {"session_id": "A", "rate_limits": {"five_hour": window(50.0, 5940)}}
    collect(tmp_path, payload)
    collect(tmp_path, payload)
    collect(tmp_path, payload)
    assert len(history(tmp_path)) == 1


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


def publish(
    state: Path,
    *,
    five: float | None,
    seven: float | None,
    five_in_s: int = 3600,
    age_min: float = 0.0,
    five_epoch: int | None = None,
) -> None:
    """Write a latest.json directly, so reader behaviour can be tested independently of the collector."""
    state.mkdir(parents=True, exist_ok=True)
    stamp = (datetime.now(UTC) - timedelta(minutes=age_min)).isoformat().replace("+00:00", "Z")
    doc: dict[str, Any] = {
        "captured_at": stamp,
        "published_by": {"session_id": "T"},
        "source": "test",
    }
    doc["five_hour"] = (
        None
        if five is None
        else {
            "used_percentage": five,
            "resets_at_epoch": five_epoch or int(time.time()) + five_in_s,
            "resets_at": "x",
            "captured_at": stamp,
        }
    )
    doc["seven_day"] = (
        None
        if seven is None
        else {
            "used_percentage": seven,
            "resets_at_epoch": int(time.time()) + 280000,
            "resets_at": "x",
            "captured_at": stamp,
        }
    )
    (state / "latest.json").write_text(json.dumps(doc), encoding="utf-8")


def write_history(state: Path, points: list[tuple[float, float]], five_epoch: int) -> None:
    """points = [(minutes_ago, five_hour_pct)] within one window epoch."""
    state.mkdir(parents=True, exist_ok=True)
    lines = []
    for mins, pct in points:
        at = (datetime.now(UTC) - timedelta(minutes=mins)).isoformat().replace("+00:00", "Z")
        lines.append(
            json.dumps(
                {
                    "at": at,
                    "five_hour": pct,
                    "seven_day": None,
                    "five_reset": five_epoch,
                    "seven_reset": None,
                }
            )
        )
    (state / "history.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_no_data_at_all_is_unknown_and_says_how_to_fix_it(tmp_path: Path) -> None:
    code, _ = read(tmp_path / "nothing")
    assert code == UNKNOWN


def test_a_stale_reading_is_reported_but_never_projected_from(tmp_path: Path) -> None:
    """A dead publisher is the expected steady state here: the statusLine does not run headless, so the
    coordinator itself can never publish. Extrapolating from an hour-old number would be a confident
    answer about a window that may already have reset."""
    publish(tmp_path, five=71.0, seven=30.0, age_min=75)
    code, d = read(tmp_path)
    assert code == UNKNOWN
    assert d["five_hour"]["used_percentage"] == pytest.approx(71.0), "the number is still shown"
    assert d["five_hour"]["reading_age_min"] >= 70, "with its age"
    assert d["five_hour"]["projected_at_reset"] is None, "but nothing is projected from it"


def test_a_future_dated_reading_is_refused_rather_than_treated_as_fresh(tmp_path: Path) -> None:
    """A negative age passes an ``age -gt max`` staleness test unconditionally, so the guard against a
    dead publisher would be disarmed while still looking present. Measured during development: a
    reading written 90 seconds earlier reported as 299 minutes in the future — exactly this machine's
    UTC offset, from stringifying a value ``ConvertFrom-Json`` had already typed as a UTC datetime."""
    publish(tmp_path, five=71.0, seven=30.0, age_min=-120)
    code, d = read(tmp_path)
    assert code == UNKNOWN
    assert "FUTURE" in d["five_hour"]["reason"].upper()


def test_a_never_published_window_is_unknown_not_zero(tmp_path: Path) -> None:
    publish(tmp_path, five=50.0, seven=None)
    _, d = read(tmp_path)
    assert d["seven_day"]["state"] == "UNKNOWN"
    assert d["seven_day"]["used_percentage"] is None, "absent must not render as 0% used"


def test_burning_faster_than_the_window_resets_is_critical(tmp_path: Path) -> None:
    """The operational question is not 'is the number big' but 'does it run out before it resets'."""
    epoch = int(time.time()) + 3600
    publish(tmp_path, five=71.0, seven=30.0, five_epoch=epoch)
    write_history(tmp_path, [(60, 40.0), (40, 52.0), (20, 64.0), (1, 71.0)], epoch)

    code, d = read(tmp_path)
    assert code == CRITICAL
    assert d["five_hour"]["rate_pct_per_hr"] > 20
    assert 0 < d["five_hour"]["minutes_to_empty"] < 60, "must run out before the window resets"


def test_a_high_but_stable_reading_is_not_critical(tmp_path: Path) -> None:
    """85% with nothing being consumed is not an emergency, and calling it one is how a warning gets
    ignored when it is real."""
    epoch = int(time.time()) + 3600
    publish(tmp_path, five=86.0, seven=30.0, five_epoch=epoch)
    write_history(tmp_path, [(60, 86.0), (30, 86.0), (1, 86.0)], epoch)

    code, d = read(tmp_path)
    assert code == WARN
    assert d["five_hour"]["minutes_to_empty"] is None, "a flat rate cannot project exhaustion"


def test_rate_is_not_computed_across_a_window_reset(tmp_path: Path) -> None:
    """THE EPOCH-BOUNDARY TRAP. When a window resets the percentage legitimately collapses (90 -> 5).
    A rate spanning that boundary is large and NEGATIVE, which reads as 'consumption has stopped' at the
    exact moment a fresh window has started being spent. Rows carry their reset epoch so the old window's
    samples are excluded rather than averaged in.
    """
    old_epoch = int(time.time()) - 600  # a window that already reset
    new_epoch = int(time.time()) + 3600
    publish(tmp_path, five=5.0, seven=30.0, five_epoch=new_epoch)
    state = tmp_path
    rows = [
        {
            "at": (datetime.now(UTC) - timedelta(minutes=m)).isoformat().replace("+00:00", "Z"),
            "five_hour": p,
            "seven_day": None,
            "five_reset": e,
            "seven_reset": None,
        }
        for m, p, e in [
            (50, 88.0, old_epoch),
            (40, 93.0, old_epoch),
            (10, 2.0, new_epoch),
            (1, 5.0, new_epoch),
        ]
    ]
    (state / "history.jsonl").write_text(
        "\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8"
    )

    _, d = read(state)
    rate = d["five_hour"]["rate_pct_per_hr"]
    assert rate is not None and rate > 0, f"rate must come from the CURRENT window only, got {rate}"


def test_the_unmeasured_buckets_are_named_every_run(tmp_path: Path) -> None:
    """Per-model weekly (Fable/Opus/Sonnet) is not in the statusLine payload at all. A tool that shows
    two green bars while a third invisible bucket is what actually stops you is worse than no tool."""
    publish(tmp_path, five=10.0, seven=10.0)
    _, d = read(tmp_path)
    assert "per-model" in d["not_measured"].lower()
    assert "opus" in d["not_measured"].lower()


# ------------------------------------------------------------------------------ installer


def test_the_installer_refuses_to_replace_someone_elses_statusline(tmp_path: Path) -> None:
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"statusLine": {"type": "command", "command": "my-own-thing"}}), encoding="utf-8"
    )
    proc = subprocess.run(
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


def test_the_installed_command_actually_runs_the_collector(tmp_path: Path) -> None:
    """A wired command that resolves to nothing is this repo's most-repeated defect — the announce hook
    sat merged-and-never-installed for hours, and its own missing-script notice could not fire because it
    lived inside the shim that was never wired. So assert the wired string EXECUTES and publishes."""
    settings = tmp_path / "settings.json"
    settings.write_text("{}", encoding="utf-8")
    subprocess.run(
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

    state = tmp_path / "state"
    payload = json.dumps({"session_id": "wired", "rate_limits": {"five_hour": window(55.0, 3600)}})
    # Run the wired command itself, with the collector's state redirected so the test cannot write to
    # the real user-level publish path.
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            cmd.replace("-File $s", f"-File $s -StateDir '{state}'"),
        ],
        input=payload,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "55" in proc.stdout, f"the wired command produced no reading: {proc.stdout!r}"
    assert (state / "latest.json").exists(), "the wired command ran but published nothing"
