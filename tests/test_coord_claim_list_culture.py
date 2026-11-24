# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5871 -- ``claim.ps1 -List`` must read a claim's age the same way on every culture and host.

Two defects in one listing line, both measured before the fix:

* ``Show-List`` did ``[datetime]::Parse($c.claimed)``. ``ConvertFrom-Json`` had already coerced the
  stamp into a ``[datetime]``, so PowerShell turned it back into the invariant ``MM/dd/yyyy`` string
  and ``Parse`` read that under the CURRENT culture. On ``en-GB`` or ``de-DE`` a stamp dated the 13th
  or later threw, and every such row printed ``liveness check FAILED``; an earlier day swapped day and
  month and printed a wrong held age.
* The ``<-- THIS worktree`` marker compared only the path, while ``Get-Mine`` also requires the record
  to come from this machine: two PCs sharing a coordination root can each have a checkout at the same
  path (docs/COORD-SHARED-ROOT.md), and another PC's claim there is not this worktree's.

Every run uses a temp repository whose claim registry lives in its own ``.git``; nothing here reads or
writes the live coordination root.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIM = ROOT / "scripts" / "coord" / "claim.ps1"
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="claim.ps1 needs pwsh on Windows",
)

#: A non-UTC offset, so the stamp's own date and this host's local date can differ. ConvertFrom-Json
#: moves a stamp into local time before claim.ps1 sees it, so the misread is of the LOCAL date.
_OFFSET = timezone(timedelta(hours=9, minutes=30))


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    ).stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    shutil.copy2(CLAIM.parent / "coord-root.ps1", r / "scripts" / "coord" / "coord-root.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-qm", "base")
    return r


def _env() -> dict[str, str]:
    # Never let an inherited root, or a global/system `mefor.claimsRoot`, point a run at shared state.
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_COORD_ROOT"}
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    return env


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _claim(repo: Path, *args: str, culture: str | None = None) -> subprocess.CompletedProcess[str]:
    script = str(repo / "scripts" / "coord" / "claim.ps1")
    if culture is None:
        cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-File", script, *args]
    else:
        # The culture is set in the same runspace the script then runs in, as a day-first host's is,
        # and echoed first so a test can see it took. A switch stays bare: a quoted '-List' binds as a
        # positional value, not as the switch.
        rest = " ".join(a if a.startswith("-") else _ps_quote(a) for a in args)
        cmd = [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"[cultureinfo]::CurrentCulture = {_ps_quote(culture)}; "
            f"Write-Host ('CULTURE=' + [cultureinfo]::CurrentCulture.Name); "
            f"& {_ps_quote(script)} {rest}; exit $LASTEXITCODE",
        ]
    return subprocess.run(
        cmd, cwd=str(repo), capture_output=True, text=True, timeout=TIMEOUT, check=False, env=_env()
    )


def _list_under(repo: Path, culture: str) -> str:
    proc = _claim(repo, "-List", culture=culture)
    assert proc.returncode == 0, proc.stderr
    # Positive control: without it a culture that silently failed to apply would pass on the old code.
    assert f"CULTURE={culture}" in proc.stdout, proc.stdout
    return proc.stdout


def _the_record(repo: Path) -> Path:
    files = sorted((repo / ".git" / "mefor-coord" / "claims").glob("*.json"))
    assert len(files) == 1, files
    return files[0]


def _rewrite(record: Path, **fields: str) -> None:
    data = json.loads(record.read_text(encoding="utf-8"))
    data.update(fields)
    record.write_text(json.dumps(data), encoding="utf-8")


def _stamp_hours_ago(day_past_12: bool) -> tuple[str, int]:
    """A round-trip stamp (what ``ToString("o")`` writes) whole hours ago, in a non-local offset.

    ``day_past_12`` picks the failure mode the old code hit: a day of 13 or later made the month-first
    misread THROW; a day of 12 or less (and not equal to the month) parsed with day and month SWAPPED.
    """
    hours = 30
    while True:
        instant = datetime.now(UTC) - timedelta(hours=hours)
        when = instant.astimezone(_OFFSET)
        # The misread is of the LOCAL date: ConvertFrom-Json moves the stamp into this host's zone first.
        local = instant.astimezone()
        if (local.day > 12) == day_past_12 and local.day != local.month:
            break
        hours += 24
    iso = when.isoformat(timespec="microseconds")  # 26 characters before the offset
    return iso[:26] + "0" + iso[26:], hours


@pytest.mark.parametrize("culture", ["en-GB", "de-DE", "en-US"])
def test_list_reads_the_held_age_on_any_culture_and_offset(repo: Path, culture: str) -> None:
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    stamp, hours = _stamp_hours_ago(day_past_12=True)
    _rewrite(_the_record(repo), claimed=stamp)
    out = _list_under(repo, culture)
    assert "liveness check FAILED" not in out
    assert f"[held {hours}h;" in out, out


def test_a_day_first_culture_still_reads_a_day_12_or_earlier_stamp_unswapped(repo: Path) -> None:
    """The quieter half: on the old code this parsed, with day and month swapped, to a wrong age."""
    stamp, hours = _stamp_hours_ago(day_past_12=False)
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    _rewrite(_the_record(repo), claimed=stamp)
    out = _list_under(repo, "en-GB")
    assert f"[held {hours}h;" in out, out


def test_a_stamp_left_as_a_string_is_read_under_the_invariant_culture(repo: Path) -> None:
    """The month-first short form PowerShell prints a [datetime] as, which ConvertFrom-Json leaves as a
    string. Under en-GB the old current-culture Parse refused it from the 13th; invariant reads it."""
    hours = 30
    while (datetime.now(UTC) - timedelta(hours=hours)).astimezone().day <= 12:
        hours += 24
    local = (datetime.now(UTC) - timedelta(hours=hours)).astimezone()
    stamp = local.strftime("%m/%d/%Y %H:%M:%S")  # no offset: read as this host's local time
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    _rewrite(_the_record(repo), claimed=stamp)
    out = _list_under(repo, "en-GB")
    assert f"[held {hours}h;" in out, out


def test_a_printed_stamp_is_round_trip_iso_not_the_culture_ambiguous_short_form(repo: Path) -> None:
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    stamp, _ = _stamp_hours_ago(day_past_12=False)
    _rewrite(_the_record(repo), claimed=stamp)
    out = _claim(repo, "-Take", "k").stdout  # no -Note, so a re-take, not a refresh
    line = next((ln for ln in out.splitlines() if "You already hold" in ln), out)
    assert "/" not in line.split("(claimed ", 1)[1], line
    assert "T" in line.split("(claimed ", 1)[1], line


def test_an_unreadable_stamp_costs_the_age_not_the_liveness_verdict(repo: Path) -> None:
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    _rewrite(_the_record(repo), claimed="not a date")
    out = _claim(repo, "-List").stdout
    assert "liveness check FAILED" not in out, out
    assert "[held ?h;" in out, out


def test_this_worktree_marker_needs_the_record_to_be_from_this_machine(repo: Path) -> None:
    assert _claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    record = _the_record(repo)

    # Control arm: the claim this worktree took on this machine is marked as its own.
    out = _claim(repo, "-List").stdout
    assert "<-- THIS worktree" in out, out

    # Same path, another PC sharing the root: not this worktree, and the line says where it is.
    _rewrite(record, host="OTHER-PC-5871")
    out = _claim(repo, "-List").stdout
    assert "ON OTHER-PC-5871" in out, out
    assert "<-- THIS worktree" not in out, out
