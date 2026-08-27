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
    proc = subprocess.run(
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


def test_the_unmeasured_bucket_is_named_every_run(tmp_path: Path) -> None:
    """The model-scoped weekly bucket (the "Weekly / Fable" bar) is not in the statusLine payload."""
    publish(tmp_path, five=10.0, seven=10.0)
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
    publish(tmp_path, five=10.0, seven=10.0)
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

    state = tmp_path / "mefor-usage"
    # The publish path is baked into the command, so assert it points where this root reads — a
    # recomputed expectation would agree with a wrong wiring.
    assert f"$d = '{state}'" in cmd, f"the wired command names no per-root publish path: {cmd!r}"

    payload = json.dumps({"session_id": "wired", "rate_limits": {"five_hour": window(55.0, 3600)}})
    proc = subprocess.run(
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
# account emails and five separate 5h/7d pools. Publishing them all to one user-level file is
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
    return subprocess.run(
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
    proc = subprocess.run(
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
    probe = subprocess.run(
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
    assert f"$d = '{pa}'" in a
    assert f"$d = '{pb}'" in b
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
                "five_hour": {
                    "used_percentage": 12.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": now,
                },
                "seven_day": {
                    "used_percentage": 30.0,
                    "resets_at_epoch": int(time.time()) + 280000,
                    "captured_at": now,
                },
            }
        ),
        encoding="utf-8",
    )
    code, doc, _ = reader("-Json", pin=pin, home=fake_home)
    # Both windows are fresh, so the verdict is a real OK rather than the UNKNOWN that a partly
    # published document would give — which would let this pass while reading the wrong directory.
    assert code == OK, doc
    assert doc["config_root"].lower() == str(pin).lower()
    assert doc["state_dir"].lower() == str(state).lower()
    assert doc["five_hour"]["used_percentage"] == pytest.approx(12.0)


def test_the_no_data_error_diagnoses_which_state_this_root_is_in(fake_home: Path) -> None:
    """Requirement 4. Five states with five different fixes must not share one message.

    The old message said "not installed or has not run yet" and printed the bare installer command
    with NO root — so following the reader's own advice re-ran the exact invocation that produced the
    false INSTALLED claim.
    """
    pin = fake_home / ".claude-account-1"

    # (a) no settings.json at all
    code, doc, out = reader("-Json", pin=pin, home=fake_home)
    assert code == UNKNOWN
    assert doc["statusline_state"] == "NOT_WIRED_NO_SETTINGS"
    assert doc["config_root"].lower() == str(pin).lower()

    # (b) settings.json with no statusLine
    (pin / "settings.json").write_text("{}", encoding="utf-8")
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == "NOT_WIRED_NO_STATUSLINE"

    # (c) somebody else's statusLine
    (pin / "settings.json").write_text(
        json.dumps({"statusLine": {"type": "command", "command": "theirs"}}), encoding="utf-8"
    )
    _, doc, out = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == "FOREIGN_STATUSLINE"

    # (d) unreadable. The installer REFUSES this root (exit 1) rather than rewriting a file it could
    # not parse, which is why the fixture is reset before arm (e): a bad write here would silently
    # disable every setting in the file, not just this one.
    (pin / "settings.json").write_text("{ not json", encoding="utf-8")
    _, doc, _ = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == "SETTINGS_UNREADABLE"
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 1

    # (e) ours, and pointing where this reader looks -- so the fix really is "start a new session"
    (pin / "settings.json").write_text("{}", encoding="utf-8")
    assert install("-ConfigDir", str(pin), pin=None, home=fake_home).returncode == 0
    _, doc, out = reader("-Json", pin=pin, home=fake_home)
    assert doc["statusline_state"] == "WIRED_HERE"
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
                "five_hour": {
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
    collect(tmp_path, {"session_id": "x", "rate_limits": {"five_hour": window(40.0, 3600)}})
    doc = latest(tmp_path)
    del doc["published_by"]["config_root_env"]
    (tmp_path / "latest.json").write_text(json.dumps(doc), encoding="utf-8")

    code, parsed, _ = reader("-StateDir", str(tmp_path), "-Json", pin=None)
    assert parsed["provenance"] == "UNVERIFIED"
    assert parsed["five_hour"]["used_percentage"] == pytest.approx(40.0), (
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
                "five_hour": {
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
    assert doc["five_hour"]["used_percentage"] == pytest.approx(33.0)


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
                    "five_hour": {
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
    assert rows[str(fake_home / ".claude-account-2").lower()]["five"] == pytest.approx(90.0)
    # The exit code is THIS session's verdict, not a roll-up across accounts.
    assert doc["five_hour"]["used_percentage"] == pytest.approx(10.0)
    assert doc["exit_code"] == code


# --- the collector half, and the shared rule ----------------------------------------------------


def test_the_collector_publishes_under_its_pinned_root_when_given_no_state_dir(
    fake_home: Path,
) -> None:
    """The other end of the shared derivation. A LEGACY wired command passes no ``-StateDir``, so this
    is the path such a root actually takes at run time."""
    pin = fake_home / ".claude-account-2"
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(COLLECT),
            "-HomeDir",
            str(fake_home),
        ],
        input=json.dumps({"session_id": "p", "rate_limits": {"five_hour": window(21.0, 3600)}}),
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
    payload = json.dumps({"session_id": "g", "rate_limits": {"five_hour": window(5.0, 3600)}})
    for args, pin in (
        ([], ghost),  # resolved from the pin
        (["-StateDir", str(ghost / "mefor-usage")], None),  # named explicitly
    ):
        proc = subprocess.run(
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
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(isolated / "usage-collect.ps1"),
            "-HomeDir",
            str(fake_home),
        ],
        input=json.dumps({"session_id": "iso", "rate_limits": {"five_hour": window(7.0, 3600)}}),
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
    proc = subprocess.run(
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
    proc = subprocess.run(
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
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", cmd],
        # BOTH windows, deliberately: with only five_hour the seven_day window is legitimately
        # "never published", the overall verdict is UNKNOWN, and this test would be asserting the
        # partition works by reading a code that means "I could not tell".
        input=json.dumps(
            {
                "session_id": "e2e",
                "rate_limits": {"five_hour": window(64.0, 3600), "seven_day": window(31.0, 280000)},
            }
        ),
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
    assert doc["five_hour"]["used_percentage"] == pytest.approx(64.0)
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
    proc = subprocess.run(
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
    proc = subprocess.run(
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
        proc = subprocess.run(
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

    run(a, {"session_id": "A", "rate_limits": {"five_hour": window(91.0, 3600)}})
    run(b, {"session_id": "B"})  # B has no rate_limits yet, so A's window is carried forward

    doc = latest(state)
    assert doc["published_by"]["config_root_env"].lower() == str(b).lower(), (
        "the document should now be stamped by B -- that is what makes this laundering"
    )
    assert doc["five_hour"]["config_root_env"].lower() == str(a).lower(), (
        "the carried window must keep A's stamp, exactly as it keeps A's captured_at"
    )

    code, parsed, _ = reader("-StateDir", str(state), "-Json", pin=b, home=fake_home)
    assert code == UNKNOWN
    assert parsed["five_hour"]["used_percentage"] is None, "A's 91% was reported as B's headroom"
    assert "DIFFERENT config root" in parsed["five_hour"]["reason"]


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
                "five_hour": {
                    "used_percentage": 20.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": now,
                },
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
                "five_hour": {
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
                "five_hour": {
                    "used_percentage": 64.0,
                    "resets_at_epoch": int(time.time()) + 780,
                    "captured_at": old,
                },
                "seven_day": {
                    "used_percentage": 31.0,
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
    # The two causes are offered as alternatives, never asserted -- nothing here can tell them apart.
    assert "cannot tell them apart" in human
    # And the properties the staleness guard already provided must survive alongside it.
    _, parsed, _ = reader("-Json", pin=pin, home=fake_home)
    assert parsed["statusline_state"] == "WIRED_HERE"
    assert parsed["five_hour"]["used_percentage"] == pytest.approx(64.0), (
        "the number must still show"
    )
    assert parsed["five_hour"]["reading_age_min"] is not None, "its age must still show"
    assert parsed["five_hour"]["projected_at_reset"] is None, (
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
        proc = subprocess.run(
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
            "rate_limits": {"five_hour": window(88.0, 3600), "seven_day": window(77.0, 280000)},
        },
    )
    fire(b, {"session_id": "B"})
    # And A gets a healthy publish of its own, so the survey renders at all.
    (a / "mefor-usage").mkdir(exist_ok=True)
    proc = subprocess.run(
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
                "rate_limits": {"five_hour": window(12.0, 3600), "seven_day": window(9.0, 280000)},
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
    assert row_b["five"] is None, f"A's 88% was printed as B's own: {row_b}"
    assert row_b["seven"] is None, row_b
    assert "DIFFERENT config root" in row_b["note"], row_b
    # A's own row is untouched -- the refusal fires on error, not on the survey as a whole.
    assert rows[str(a).lower()]["five"] == pytest.approx(12.0)


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
                "five_hour": {
                    "used_percentage": 55.0,
                    "resets_at_epoch": int(time.time()) + 3600,
                    "captured_at": old,
                    "config_root_env": str(pin),
                },
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
