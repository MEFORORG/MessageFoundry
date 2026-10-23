# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``lane.ps1``'s only-ever-advances guard must not fire on a stamp it wrote itself.

THE GUARD IS CORRECT AND ITS COMPARISON WAS NOT. ``statedUtc`` is written as
``2026-08-29T03:28:22Z`` and ``ConvertFrom-Json`` deserialises that into a ``[datetime]`` with
``Kind=Utc`` -- already right. Passing that object to ``[datetime]::Parse`` coerced it BACK TO A
STRING first (``"8/29/2026 3:28:22 AM"``), and that form carries no zone, so it re-parsed as
``Kind=Unspecified`` and the following ``.ToUniversalTime()`` added the local offset A SECOND TIME.

A stamp written 27 minutes earlier therefore read five hours in the FUTURE and the guard threw. **A
guard written to stop the value moving BACKWARDS moved it FORWARDS by the local offset**, so a seat
that stated its lane could not state it again until that offset had elapsed -- five hours here.

NOTHING SURFACED IT, which is why it wants a test rather than a comment. The Stop hook kept
prompting for a lane level, the command kept refusing, and from a reader's side a frozen lane is
indistinguishable from an unchanged one. It also reads, from the dispatcher's seat, as seats
ignoring the prompt.

TWO ARMS, AND THE SECOND IS THE ONE THAT MATTERS. Deleting the guard would make arm one pass. Arm
two fails unless a genuinely future stamp is still refused, so the pair pins the fix rather than its
absence.

THE FIX UNDER TEST IS NOT MINE. It is PROCESS-IMPROVEMENT's, at f2ebc2e80, which is the commit this
file is written against -- I measured the defect independently and wrote the arms. That fix also
covers a case a bare ``.ToUniversalTime()`` still gets wrong: on ``Kind=Unspecified`` .NET assumes
LOCAL and re-adds the offset, so it uses ``SpecifyKind(..., Utc)`` on the object path and an
invariant-culture ``AssumeUniversal`` parse on the legacy string path.

MEASURED, three states of the script. This is what makes the arms a discriminator rather than two
assertions that happen to hold together:

    lane.ps1 state              arm one (past)   arm two (future)   arms-disagree
    broken (origin/main)        FAIL             pass               FAIL
    the fix at f2ebc2e80        pass             pass               pass
    guard disarmed              pass             FAIL               FAIL

READ THE BROKEN ROW: it refuses BOTH directions. That is the manufactured-non-compliance shape --
the hook nags that a level is stale, the seat runs the command, the command refuses, and from
outside that is indistinguishable from a seat ignoring the prompt.

The script resolves its store from ``git rev-parse --git-common-dir``, so these run it inside a
throwaway repository -- no override parameter needed, and the real coordination directory is never
touched.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from tests._no_prompt import run_holding_stdin_open

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "lane.ps1"


def _env(root: Path | str | None = None) -> dict[str, str]:
    """The suite's environment with MEFOR_COORD_ROOT dropped, so the throwaway repo's own local root
    is the one in use, or set to ``root`` when one is given."""
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_COORD_ROOT"}
    if root is not None:
        env["MEFOR_COORD_ROOT"] = str(root)
    return env


def _pwsh(
    repo: Path, *args: str, root: Path | str | None = None
) -> subprocess.CompletedProcess[str]:
    """Run lane.ps1 in ``repo``, under ``_env(root)``."""
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        # A pwsh child of Python writes the console's OEM code page, not UTF-8, and no single codec
        # matches every box. The asserts look only for ASCII text, so a non-ASCII byte (a path or a
        # localized message) becomes U+FFFD rather than a UnicodeDecodeError hiding the result.
        encoding="utf-8",
        errors="replace",
        cwd=repo,
        env=_env(root),
        # Under pyproject's 60 s pytest-timeout, so a hung pwsh fails this test by name.
        timeout=45,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo with one commit, so ``git rev-parse`` answers."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True)
    (tmp_path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "seed.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "seed"], check=True)
    return tmp_path


def _lane_record(repo: Path) -> Path:
    """The single record lane.ps1 wrote. Located rather than derived: the box key is the script's
    business, and a test that recomputed it would be asserting its own copy of that rule."""
    lanes = repo / ".git" / "mefor-coord" / "lanes"
    files = sorted(p for p in lanes.glob("*.json"))
    assert len(files) == 1, f"expected exactly one lane record, found {[p.name for p in files]}"
    return files[0]


def _restate(repo: Path, stamp: datetime) -> subprocess.CompletedProcess[str]:
    """Force ``statedUtc`` to ``stamp`` in the SAME wire form the script writes, then re-state."""
    rec_path = _lane_record(repo)
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["statedUtc"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    return _pwsh(repo, "-Free", "2", "-InFlight", "2", "-Note", "restate")


def test_a_stamp_this_script_wrote_minutes_ago_does_not_read_as_the_future(repo: Path) -> None:
    """ARM ONE -- the defect. A recent past stamp must not block the next statement."""
    first = _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    assert first.returncode == 0, f"first statement failed: {first.stderr or first.stdout}"

    past = datetime.now(UTC) - timedelta(minutes=30)
    result = _restate(repo, past)

    assert result.returncode == 0, (
        "a statedUtc 30 minutes in the PAST was rejected as being in the future. The guard is "
        "comparing a UTC value against a local clock -- see this module's docstring. "
        f"stderr={result.stderr!r}"
    )
    assert "in the future" not in (result.stderr + result.stdout)


def test_a_genuinely_future_stamp_is_still_refused(repo: Path) -> None:
    """ARM TWO -- the must-not-fire control, and the reason arm one is not satisfied by deletion.

    Removing the guard entirely makes arm one pass. This one fails unless the guard still refuses a
    stamp that really is ahead of now, which is the property it was written for: statedUtc only ever
    advances, so a clock that jumped backwards must not silently rewind the gauge.
    """
    first = _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    assert first.returncode == 0, f"first statement failed: {first.stderr or first.stdout}"

    future = datetime.now(UTC) + timedelta(hours=6)
    result = _restate(repo, future)

    assert result.returncode != 0, "a statedUtc genuinely in the future was accepted"
    assert "in the future" in (result.stderr + result.stdout)


def test_the_two_arms_disagree(repo: Path) -> None:
    """The arms must produce DIFFERENT outcomes on the same code, or they are one case twice.

    Both arms drive the identical path with the identical record shape; only the SIGN of the offset
    differs. If a change ever made them agree -- both passing or both failing -- the pair would still
    look like two tests while testing one thing.
    """
    _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    past = _restate(repo, datetime.now(UTC) - timedelta(minutes=30))
    future = _restate(repo, datetime.now(UTC) + timedelta(hours=6))
    assert (past.returncode == 0) != (future.returncode == 0), (
        f"past rc={past.returncode} future rc={future.returncode} -- the two arms agree, so the "
        "guard is not discriminating on the sign of the offset at all"
    )


@pytest.mark.parametrize(
    "args",
    [(), ("-Free", "1")],
    ids=["bare", "free-only"],
)
def test_a_statement_missing_a_number_refuses_instead_of_prompting(
    repo: Path, args: tuple[str, ...]
) -> None:
    """Vault BACKLOG #3627: the default ``State`` set bound without both numbers. Red pre-fix."""
    rc, err = run_holding_stdin_open(
        ["pwsh", "-NoProfile", "-File", str(_SCRIPT), *args], cwd=repo, env=_env()
    )
    assert rc != 0, "a statement without both numbers must be refused, not written"
    assert "-Free" in err and "-InFlight" in err, err
    # Refused means NOTHING written: the lanes directory is created on the write path.
    assert not (repo / ".git" / "mefor-coord" / "lanes").exists()


# -SHOW IS A STRICT READ: it creates no directory and writes no file on the coordination root. Before
# this change it ran `New-Item -Force` on `<root>\lanes` and `<root>\lanes\.tmp` on every call, so it
# created both on a fresh root and threw on one it could not write. MEASURED 2026-10-22: every test
# below fails against that code. The third passes its first arm, the found record, which is the
# must-not-fire control.


def _tree(top: Path) -> list[str]:
    """Every file and directory under ``top``, as sorted relative paths: the before/after instrument."""
    return sorted(str(p.relative_to(top)) for p in top.rglob("*"))


def _show(repo: Path, root: Path | None = None) -> dict[str, object]:
    proc = _pwsh(repo, "-Show", root=root)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    out: dict[str, object] = json.loads(proc.stdout)
    return out


def test_show_with_no_lanes_dir_creates_nothing_and_says_absent(repo: Path) -> None:
    before = _tree(repo)
    assert any(p.startswith(".git") for p in before), "the instrument must see .git to count"

    rec = _show(repo)

    assert _tree(repo) == before, "lane.ps1 -Show wrote to the repository"
    assert "no lanes directory" in str(rec["absent"]), rec
    assert rec["statedFree"] is None and rec["statedInFlight"] is None


# Everyone (S-1-1-0), so the ACE covers every SID in the token, an elevated one's groups included.
# Hosted CI's first run denied only the user SID, and its write went through.
_EVERYONE = "*S-1-1-0"


def test_show_on_a_root_it_cannot_write_reads_and_writes_nothing(
    repo: Path, tmp_path: Path
) -> None:
    if os.name != "nt":
        pytest.skip("the deny ACE is a Windows ACL")
    shared = tmp_path / "read-only-root"
    shared.mkdir()
    # On the root itself, not inherited, so removing it is enough for cleanup.
    subprocess.run(
        ["icacls", str(shared), "/deny", f"{_EVERYONE}:(AD,WD)"], check=True, capture_output=True
    )
    try:
        write = _pwsh(repo, "-Free", "1", "-InFlight", "0", root=shared)
        # The control: the ACE is what stops a write, so a green -Show below is not vacuous. Where
        # the account writes through it anyway (a privilege that bypasses the ACL), the precondition
        # cannot hold, so this skips rather than fail. The no-lanes-dir test still covers no-write.
        if write.returncode == 0:
            pytest.skip(
                "this account writes through a deny ACE, so a read-only root cannot be staged"
            )
        assert "denied" in write.stderr.lower(), write.stderr
        assert not any(shared.iterdir())

        rec = _show(repo, root=shared)
        assert "no lanes directory" in str(rec["absent"]), rec
        assert not any(shared.iterdir())
    finally:
        # check=False: a cleanup failure must not replace the assertion that is failing.
        subprocess.run(["icacls", str(shared), "/remove:d", _EVERYONE], capture_output=True)


def test_show_prints_a_found_record_unchanged_and_names_a_missing_or_unreadable_one(
    repo: Path,
) -> None:
    assert _pwsh(repo, "-Free", "2", "-InFlight", "1", "-Note", "n").returncode == 0
    rec = _show(repo)
    assert "absent" not in rec, rec
    assert rec["statedFree"] == 2 and rec["statedInFlight"] == 1

    record = _lane_record(repo)
    for body, reason in (("{not json", "could not be read"), ("0", "not a JSON object")):
        record.write_text(body, encoding="utf-8")
        rec = _show(repo)
        assert reason in str(rec["absent"]), (body, rec)
        assert rec["statedFree"] is None, (body, rec)
    record.unlink()
    assert "no lane record at" in str(_show(repo)["absent"])


# [Environment]::MachineName, which lane.ps1 stamps: the NetBIOS name on Windows, the hostname elsewhere.
_THIS_HOST = os.environ.get("COMPUTERNAME") or socket.gethostname()


@pytest.mark.parametrize(
    "body",
    [b"{not json", b"", b"0", b"null", b"[]", b'""', b"1", b"[1, 2]", b"{}",
     json.dumps([{"host": "x"}]).encode(), json.dumps([{"host": _THIS_HOST}]).encode()],
    ids=["bad-json", "empty-file", "zero", "null", "empty-array", "empty-string", "one", "array",
         "empty-object", "one-object-array-other-host", "one-object-array-this-host"],
)  # fmt: skip
def test_a_write_over_an_unreadable_record_is_refused_and_leaves_it(
    repo: Path, body: bytes
) -> None:
    """The host refusal needs the record read. A record FILE that exists but is not a JSON object
    with fields used to read as no record, so the write skipped that refusal and replaced it, or
    crashed on it under StrictMode. It now fails closed. Only a missing file means no record."""
    # The control: with no file at all, the first write goes through.
    assert _pwsh(repo, "-Free", "2", "-InFlight", "1").returncode == 0
    record = _lane_record(repo)
    record.write_bytes(body)
    proc = _pwsh(repo, "-Free", "3", "-InFlight", "0")
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert "REFUSED" in proc.stderr and "could not be read" in proc.stderr, proc.stderr
    assert record.read_bytes() == body, "an unreadable lane record was overwritten"


_BLANK_KEYS = {
    "v", "boxKey", "worktree", "capacity", "statedFree", "statedInFlight", "statedUtc",
    "statedBySessionId", "statedNote", "tipAtStated", "claimHashAtStated", "turnsSinceStated",
    "tipNow", "claimHashNow", "lastTurnUtc", "promptedUtc", "promptCount", "askedByDispatcherUtc",
}  # fmt: skip


@pytest.mark.parametrize("body", ["1", '"x"', "true", "[1, 2]"])
def test_show_never_reuses_the_earlier_read_when_its_own_read_fails(repo: Path, body: str) -> None:
    """-Show's fallback must be a FRESH blank record, never what the earlier read kept.

    A restatement landing between the two reads is a race, so this stages the same split by
    construction instead. A truthy non-object is KEPT by the earlier read (`if (-not $rec)` leaves it)
    and REJECTED by -Show's own read, which is the earlier-read-succeeded, -Show-read-failed case.
    Reusing $rec printed that value with an `absent` reason beside it. MEASURED 2026-10-22: every
    case fails at 73d6668cd and passes with the fresh blank record.
    """
    assert _pwsh(repo, "-Free", "2", "-InFlight", "1").returncode == 0
    record = _lane_record(repo)
    record.write_text(body, encoding="utf-8")
    rec = _show(repo)
    assert "not a JSON object" in str(rec["absent"]), rec
    assert set(rec) == _BLANK_KEYS | {"absent"}, rec
    assert rec["statedFree"] is None and rec["statedInFlight"] is None, rec
