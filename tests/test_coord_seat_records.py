# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the fleet-continuity writer and reader (``scripts/coord/seat.ps1``, ``fleet.ps1``).

These drive the REAL scripts as subprocesses against a throwaway git repo, for the reason
``test_coord_presence.py`` states: a Python re-implementation of the rules would drift from the
scripts silently, and the whole point of this layer is that it must not lie.

**WHAT THIS LAYER IS FOR.** When a Claude account's weekly budget is exhausted the owner opens ONE
session under a different account, with no inherited context, no inherited memory and no realtime
channel to anything that was running. It has to work out what every seat was doing from disk alone.
So the failure that matters is not "the roster is wrong" -- it is "the roster is confidently empty",
which is byte-identical to a healthy quiet fleet.

**THE TESTS THAT CARRY THE WEIGHT**, each pinning a defect measured on a live box rather than a
hypothetical:

* ``test_missing_field_is_absent_not_empty`` -- ``@($null).Count`` is 1 in PowerShell, so a field
  that was never written reads as one element. A count agreed with a plausible wrong answer until
  the shape was dumped, so the shape is what this asserts.
* ``test_untracked_files_are_named_not_just_counted`` -- ``git stash create`` has no ``-u`` and
  captures TRACKED edits only, so the one category that cannot be recovered from anywhere else is
  exactly what it silently omits.
* ``test_inherited_allocations_are_not_attributed_to_this_episode`` -- a worktree path outlives its
  occupant, and matching on path alone hands a replacement someone else's ledger numbers.
* ``test_receipt_answers_and_says_so`` / ``test_receipt_refuses_and_says_so`` -- the reader must
  state what it LOOKED AT, so that an empty roster over a dead writer is distinguishable from an
  empty roster over an idle one -- AND the two runs must be distinguishable from each other.

**EVERY FENCED TEST CONTROLS ITS OWN CONFIG ROOT, AND THAT IS A CORRECTNESS PROPERTY.** The one
reader test this file used to carry asserted only that some keys were present and that one record
was examined, both of which are true whether ``fleet.ps1`` ANSWERED (a fence it could evaluate,
exit 0) or REFUSED (no config root, every state a guess, exit 2). On a CI runner there is no
``~/.claude`` at all, so that test always took the refusing branch and the answering branch -- the
one an operator actually uses -- was never executed anywhere. So the fence fixture below points
``USERPROFILE`` at a registry this file builds, and the refusal is pinned as its own test with its
own exit code.

**MUTATION, NOT ASSERTION-COUNTING.** Every test here was measured RED against a scratchpad copy of
the script under test with the defect reintroduced, and GREEN against the real file. Where the
control is cheap enough to keep, it is kept in the test itself and named as a control:
``test_malformed_records_leave_the_reader_alive`` builds a Get-RecField-less reader and requires it
to die, and ``test_seat_shim_swallows_a_failing_target_and_the_wake_shim_does_not`` requires the
sibling shim to answer 3 on the same rigged target, so a harness that cannot observe a non-zero exit
fails loudly instead of passing both halves.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
SEAT = COORD / "seat.ps1"
FLEET = COORD / "fleet.ps1"
REGISTRY = COORD / "session-registry.ps1"
INSTALLER = COORD / "install-coordination.ps1"
HOOK = ROOT / "scripts" / "hooks" / "seat-record.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 / fleet.ps1 need pwsh on Windows (Process.StartTime, config-root discovery)",
)


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    return out.stdout.strip()


def _git_rc(repo: Path, *args: str) -> int:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    ).returncode


def _pwsh(
    script: Path,
    *args: str,
    cwd: Path,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a script as the harness runs it.

    ``stdin`` is DEVNULL unless a payload is given. That is not tidiness: seat.ps1 reads stdin when
    ``[Console]::IsInputRedirected`` is true, so an INHERITED pipe that nobody closes hangs the
    writer for ever. Measured while writing these tests -- the run never returned.
    """
    kwargs: dict[str, object] = {}
    if stdin is None:
        kwargs["stdin"] = subprocess.DEVNULL
    else:
        kwargs["input"] = stdin
    return subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(script), *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        env=env,
        timeout=180,
        **kwargs,  # type: ignore[arg-type]
    )


def _init_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init", "-q", "-b", "main")
    _git(path, "config", "user.email", "t@example.invalid")
    _git(path, "config", "user.name", "t")
    (path / "tracked.txt").write_text("original\n", encoding="utf-8")
    _git(path, "add", "tracked.txt")
    _git(path, "commit", "-qm", "base")
    return path


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A real git repo with a commit, so merge-base and diff have something to resolve."""
    return _init_repo(tmp_path / "repo")


class Fence:
    """A config root this test file owns, so the liveness fence is an input rather than the box.

    ``Get-ClaudeConfigRoots`` discovers roots under ``$env:USERPROFILE``, so pointing that at a
    fixture makes fence=LIVE, fence=NOT-REGISTERED and fence-absent all reachable and repeatable --
    including on a CI runner, which has none of the real ones.
    """

    def __init__(self, home: Path) -> None:
        self.home = home
        self.sessions = home / ".claude" / "sessions"
        self.sessions.mkdir(parents=True, exist_ok=True)
        self._procs: list[subprocess.Popen[bytes]] = []

    @property
    def env(self) -> dict[str, str]:
        e = dict(os.environ)
        e["USERPROFILE"] = str(self.home)
        return e

    def clear(self) -> None:
        for f in self.sessions.glob("*.json"):
            f.unlink()

    def live(self, session_id: str, cwd: Path) -> int:
        """Register a session whose pid is a process we started, so the fence answers LIVE.

        The fence requires the process to have started BEFORE the session registered (a pid that
        started later is a recycled pid), so ``startedAt`` is stamped after the spawn.
        """
        p = subprocess.Popen(
            ["pwsh", "-NoProfile", "-Command", "Start-Sleep -Seconds 120"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs.append(p)
        time.sleep(0.7)
        self.record(session_id, cwd, pid=p.pid, started_ms=int(time.time() * 1000))
        return p.pid

    def record(self, session_id: str, cwd: Path, pid: int, started_ms: int) -> Path:
        f = self.sessions / f"{pid}-{session_id[:8]}.json"
        f.write_text(
            json.dumps(
                {
                    "sessionId": session_id,
                    "pid": pid,
                    "cwd": str(cwd),
                    "startedAt": started_ms,
                    "kind": "vscode",
                    "entrypoint": "cli",
                    "version": "1.0.0",
                }
            ),
            encoding="utf-8",
        )
        return f

    def stop(self) -> None:
        for p in self._procs:
            with contextlib.suppress(OSError):
                p.kill()


@pytest.fixture
def fence(tmp_path: Path):
    f = Fence(tmp_path / "home")
    yield f
    f.stop()


@pytest.fixture
def nofence(tmp_path: Path) -> Fence:
    """A USERPROFILE with no config root at all -- the fence cannot be evaluated."""
    home = tmp_path / "nohome"
    home.mkdir()
    f = Fence.__new__(Fence)
    f.home = home
    f.sessions = home / "unused"
    f._procs = []
    return f


def _record_path(repo: Path, session: str) -> Path:
    seats = repo / ".git" / "mefor-coord" / "seats"
    hits = list(seats.glob(f"*/{session}.json"))
    assert hits, f"no record written for {session} under {seats}"
    return hits[0]


def _read_record(repo: Path, session: str) -> dict:
    return json.loads(_record_path(repo, session).read_text(encoding="utf-8"))


def _patch_record(repo: Path, session: str, **fields: object) -> None:
    p = _record_path(repo, session)
    rec = json.loads(p.read_text(encoding="utf-8"))
    rec.update(fields)
    p.write_text(json.dumps(rec), encoding="utf-8")


def _write_record(repo: Path, session: str) -> dict:
    r = _pwsh(SEAT, "-Record", "-SessionId", session, cwd=repo)
    assert r.returncode == 0, f"seat.ps1 must exit 0 even on failure; stderr={r.stderr}"
    return _read_record(repo, session)


def _seats_dir(repo: Path) -> Path:
    return repo / ".git" / "mefor-coord" / "seats"


def _box_of(repo: Path, session: str) -> str:
    return _record_path(repo, session).parent.name


def _fleet_json(repo: Path, fence: Fence, *args: str) -> tuple[int, dict]:
    r = _pwsh(FLEET, "-Json", *args, cwd=repo, env=fence.env)
    assert r.stdout.strip(), f"fleet.ps1 -Json emitted nothing; rc={r.returncode} stderr={r.stderr}"
    return r.returncode, json.loads(r.stdout)


def _iso(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _mutant(tmp_path: Path, name: str, script: Path, edits: list[tuple[str, str]]) -> Path:
    """A scratch copy of a coord script with a defect reintroduced, for use as a CONTROL.

    Its siblings are copied beside it because these scripts dot-source by ``$PSScriptRoot``.
    """
    d = tmp_path / f"mutant-{name}"
    d.mkdir(exist_ok=True)
    text = script.read_text(encoding="utf-8")
    for old, new in edits:
        assert old in text, f"mutation anchor vanished from {script.name}: {old[:70]!r}"
        text = text.replace(old, new, 1)
    out = d / script.name
    out.write_text(text, encoding="utf-8")
    for sibling in ("session-registry.ps1", "mail-key.ps1"):
        if (COORD / sibling).exists() and sibling != script.name:
            shutil.copy(COORD / sibling, d / sibling)
    return out


# =================================================================================================
# The writer: shape, involuntary evidence, and the probes rule 6 governs.
# =================================================================================================


def test_writer_exits_zero_and_writes_one_record(repo: Path) -> None:
    rec = _write_record(repo, "sess-aaaa")
    assert rec["sessionKey"] == "sess-aaaa"
    assert rec["branch"] == "main"
    assert rec["worktreeSource"] == "git rev-parse --show-toplevel"


def test_no_session_id_collapses_to_one_record_not_one_per_turn(repo: Path) -> None:
    """A hook runs as a pwsh CHILD whose pid changes every turn.

    Keying an unidentified session on pid would mint roughly one record per turn -- about 60 files
    for a 30-turn session -- and a reader would see 60 seats where there is one. The key is the
    literal string ``nosid`` for exactly that reason.
    """
    for _ in range(3):
        assert _pwsh(SEAT, "-Record", cwd=repo).returncode == 0
    seats = _seats_dir(repo)
    records = list(seats.glob("*/*.json"))
    assert len(records) == 1, [p.name for p in records]
    assert records[0].name == "nosid.json"


def test_missing_field_is_absent_not_empty(repo: Path) -> None:
    """Assert on SHAPE, because a count cannot tell absent from empty here.

    ``@($null).Count`` is 1 in PowerShell, so a field that was never written counts as one element.
    That is not a hypothetical: the ``commits`` field was added to the git-facts helper and never
    wired into the record, and the count agreed with a plausible wrong answer until the type was
    dumped. So every field the reader depends on is asserted PRESENT by key.
    """
    rec = _write_record(repo, "sess-shape")
    for key in (
        "commits",
        "touchedPaths",
        "mergeBase",
        "dirty",
        "stashCovers",
        "stashRef",
        "stashProbe",
        "claims",
        "allocations",
        "poolEpoch",
        "configRootSource",
    ):
        assert key in rec, f"{key} missing from the record entirely -- a reader would see null"


def test_record_keeps_the_reader_s_fields_and_drops_the_scan_only_one(repo: Path) -> None:
    """The same shape rule, run over a record that actually HAS claims and allocations.

    ``stashProbe`` is the field that went to Get-GitFacts and not to the record literal -- invisible
    while every count still agreed. ``rawAt`` is the opposite hazard: it exists only so the
    attribution step gets the ORIGINAL timestamp object rather than a re-parsed string, and it must
    not survive into the record, where a reader would find two spellings of the same instant and no
    statement of which is authoritative.
    """
    coord = repo / ".git" / "mefor-coord"
    (coord / "claims").mkdir(parents=True)
    (coord / "claims" / "docs-x.json").write_text(
        json.dumps({"worktree": str(repo), "claimedAt": _iso(datetime.now(UTC))}),
        encoding="utf-8",
    )
    (coord / "alloc" / "backlog").mkdir(parents=True)
    (coord / "alloc" / "backlog" / "9100.json").write_text(
        json.dumps(
            {
                "number": "9100",
                "kind": "backlog",
                "worktree": str(repo),
                "claimed": _iso(datetime.now(UTC)),
            }
        ),
        encoding="utf-8",
    )
    rec = _write_record(repo, "sess-fields")
    assert "stashProbe" in rec, "the reader tests stashProbe.outcome; absent it reads as null"
    assert rec["claims"] and rec["allocations"], "the rawAt check below would be vacuous otherwise"

    def keys(o: object):
        if isinstance(o, dict):
            for k, v in o.items():
                yield k
                yield from keys(v)
        elif isinstance(o, list):
            for v in o:
                yield from keys(v)

    assert "rawAt" not in set(keys(rec)), "rawAt is scan-only and must not reach the record"


def test_untracked_files_are_named_not_just_counted(repo: Path) -> None:
    """``git stash create`` captures TRACKED edits only -- there is no ``-u``.

    So the single highest-value thing to rescue, a file that exists nowhere but that working
    directory, is exactly what the stash does not cover. A record that stored only a stash sha and a
    dirty count would tell a replacement seat "nothing to recover" about the very work it replaces.
    """
    (repo / "brand_new.txt").write_text("only here\n", encoding="utf-8")
    rec = _write_record(repo, "sess-untracked")

    assert rec["dirty"]["untrackedCount"] == 1
    assert "brand_new.txt" in rec["dirty"]["untracked"]
    # No tracked edits, so there is nothing for the stash to hold -- and the record must SAY that
    # rather than leaving a null the reader could mistake for "clean".
    assert rec["stashSha"] is None
    assert rec["stashCovers"] == "nothing-untracked-only"


def test_tracked_edit_produces_a_recoverable_stash(repo: Path) -> None:
    """The positive control for the test above: the stash must actually work when it applies."""
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    rec = _write_record(repo, "sess-tracked")

    assert rec["stashCovers"] == "tracked-only"
    assert rec["stashSha"]
    assert rec["stashProbe"]["outcome"] == "created"
    # The commit object must really contain the change, not merely exist.
    blob = _git(repo, "show", f"{rec['stashSha']}:tracked.txt")
    assert blob == "modified"
    # ANCHORED, not merely created. `git stash create` writes no ref and no reflog entry, so the
    # object is unreachable from the instant it exists and the next gc revokes the promise silently.
    assert rec["stashRef"], "an unanchored sha is a recovery promise gc can cancel without a word"
    assert _git(repo, "rev-parse", "--verify", rec["stashRef"]) == rec["stashSha"]


def test_clean_tree_says_not_attempted_rather_than_none(repo: Path) -> None:
    """ "Nothing to cover" and "could not ask" must never share a token (rule 6).

    This is the assertion that fails if the two are ever collapsed again: a clean tree is the one
    case where the probe legitimately does not run, and it has to say so in its own word.
    """
    rec = _write_record(repo, "sess-clean")
    assert rec["stashProbe"]["outcome"] == "not-attempted"
    assert rec["stashProbe"]["attempted"] is False
    assert rec["stashProbe"]["reason"] == "no tracked modifications to cover"
    assert rec["stashCovers"] == "nothing-clean"
    assert rec["dirty"]["probe"] == "ok"


def test_index_lock_reports_tracked_edits_as_not_captured(repo: Path) -> None:
    """`git stash create` takes the index lock; `git status` does not (rule 6).

    A sibling agent committing in the same checkout at the instant the Stop hook fires therefore
    fails THAT call and nothing else. Measured before the fix: trackedCount=1 beside
    stashCovers=nothing-untracked-only with no error line at all -- "there is nothing to rescue"
    asserted over a tracked edit held by no commit, no stash and no remote.
    """
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    (repo / "brand_new.txt").write_text("only here\n", encoding="utf-8")
    lock = repo / ".git" / "index.lock"
    lock.write_text("", encoding="utf-8")
    try:
        rec = _write_record(repo, "sess-locked")
    finally:
        lock.unlink()

    assert rec["dirty"]["trackedCount"] == 1, "status must still answer; only the stash is blocked"
    assert rec["stashCovers"] in (
        "tracked-edits-NOT-captured",
        "tracked-edits-NOT-captured-and-untracked-only",
    ), rec["stashCovers"]
    assert rec["stashProbe"]["outcome"] == "failed"
    assert rec["stashProbe"]["exitCode"] is not None, "git's own exit code is the provenance"
    errors = (_seats_dir(repo) / ".writer-errors.txt").read_text(encoding="utf-8")
    assert "stash-probe" in errors, "rule 2: a writer that dies must not die silently"

    # POSITIVE CONTROL, same repo, same tree, lock gone. Without it the assertions above could be
    # satisfied by a writer that never captures anything.
    rec2 = _write_record(repo, "sess-unlocked")
    assert rec2["stashCovers"] == "tracked-only"
    assert rec2["stashProbe"]["outcome"] == "created"


def test_corrupt_index_leaves_the_dirty_counts_null_not_zero(repo: Path) -> None:
    """Zero is a measurement; null is the absence of one, and only one of them is true here."""
    (repo / ".git" / "index").write_bytes(b"NOT AN INDEX" * 8)
    assert _git_rc(repo, "status", "--porcelain") != 0
    assert _git_rc(repo, "rev-parse", "--show-toplevel") == 0, "the writer must still find the box"

    rec = _write_record(repo, "sess-corrupt")
    assert rec["dirty"]["count"] is None
    assert rec["dirty"]["trackedCount"] is None
    assert rec["dirty"]["untrackedCount"] is None
    assert rec["dirty"]["probe"] == "failed"
    assert re.search(r"exit=\d+", rec["dirty"]["probeError"] or ""), rec["dirty"]["probeError"]
    assert rec["stashCovers"] == "unknown-status-probe-failed"
    assert rec["stashProbe"]["outcome"] == "not-attempted-status-failed"


def test_stash_anchor_survives_a_failed_probe_and_is_dropped_on_a_clean_one(repo: Path) -> None:
    """Both arms, because only the PAIR shows the gate is doing work.

    Dropping the anchor is right when the tree is known clean -- an anchor from an earlier turn
    would keep holding edits that have since been committed or discarded. It is wrong when the
    status probe did not answer, because "nothing to cover" was never measured, and deleting the
    ref would destroy the last handle on the previous turn's tracked edits on the strength of a
    measurement that never happened.
    """
    index = repo / ".git" / "index"
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    rec = _write_record(repo, "sess-anchor")
    ref = rec["stashRef"]
    assert ref and _git_rc(repo, "rev-parse", "--verify", "--quiet", ref) == 0

    # ARM A -- status could not answer. The anchor must SURVIVE.
    good_index = index.read_bytes()
    index.write_bytes(b"NOT AN INDEX" * 8)
    r = _pwsh(SEAT, "-Record", "-SessionId", "sess-anchor", cwd=repo)
    assert r.returncode == 0
    assert _read_record(repo, "sess-anchor")["dirty"]["probe"] == "failed"
    assert _git_rc(repo, "rev-parse", "--verify", "--quiet", ref) == 0, (
        "a failed probe must never be read as 'nothing to cover'"
    )

    # ARM B -- status answered CLEAN. The anchor must be DROPPED.
    index.write_bytes(good_index)
    _git(repo, "checkout", "--", "tracked.txt")
    r = _pwsh(SEAT, "-Record", "-SessionId", "sess-anchor", cwd=repo)
    assert r.returncode == 0
    assert _read_record(repo, "sess-anchor")["dirty"]["probe"] == "ok"
    assert _git_rc(repo, "rev-parse", "--verify", "--quiet", ref) != 0, (
        "an anchor left standing outlives what it described"
    )


def test_commits_are_recorded_as_the_involuntary_answer(repo: Path) -> None:
    """Owner ruling 2026-08-14 demoted the voluntary declared half.

    So the record has to answer "what was this seat doing" without anyone declaring anything, and
    commit subjects are what it answers with: written as a side effect of working, dated, and
    describing what was DONE rather than intended.
    """
    _git(repo, "checkout", "-qb", "feature")
    (repo / "tracked.txt").write_text("work\n", encoding="utf-8")
    _git(repo, "commit", "-qam", "do the thing")
    # merge-base resolves against origin/main; without a remote there is none, so pin one locally.
    _git(repo, "update-ref", "refs/remotes/origin/main", _git(repo, "rev-parse", "main"))

    rec = _write_record(repo, "sess-commits")
    assert any("do the thing" in c for c in rec["commits"])
    assert "tracked.txt" in rec["touchedPaths"]


def test_inherited_allocations_are_not_attributed_to_this_episode(repo: Path) -> None:
    """A worktree PATH outlives the session that occupied it.

    Measured on the first record this writer ever produced: 18 backlog allocations resolved to the
    writing worktree, the oldest claimed eight days earlier by a different session in the same
    directory. Handing those to a replacement as "yours" would have it rehome ledger numbers
    belonging to work that finished last week.

    THE FIXTURE SITS FIVE MINUTES FROM THE BOUNDARY, NOT SIX YEARS, AND THAT IS THE TEST.
    The live defect is exactly ONE LOCAL UTC OFFSET wide -- ``ConvertFrom-Json`` hands back a
    [DateTime], ``[string]`` on it yields the culture form with the Z gone, and re-parsing that
    reads it as LOCAL and shifts it by the box's offset. A 2020 timestamp is insensitive to any
    error smaller than six years, so it certified the exact bug the attribution machinery exists to
    prevent. Both arms are asserted from the SAME record: the five-minutes-after allocation is the
    positive control that this instrument can still say ``this-episode`` at all.
    """
    # Turn 1 mints the episode baseline. Everything below is placed relative to what it recorded,
    # so the margin is exact rather than approximate.
    first = _write_record(repo, "sess-alloc")
    episode_start = datetime.strptime(first["episodeStart"], "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=UTC
    )

    alloc = repo / ".git" / "mefor-coord" / "alloc" / "backlog"
    alloc.mkdir(parents=True)

    def put(number: str, at: datetime) -> None:
        (alloc / f"{number}.json").write_text(
            json.dumps(
                {
                    "number": number,
                    "kind": "backlog",
                    "worktree": str(repo).replace("\\", "/"),
                    "claimed": _iso(at),
                }
            ),
            encoding="utf-8",
        )

    put("9001", episode_start - timedelta(minutes=5))
    put("9002", episode_start + timedelta(minutes=5))

    rec = _write_record(repo, "sess-alloc")
    got = {a["number"]: a for a in rec["allocations"]}
    assert "9001" in got, "the allocation must still be REPORTED -- it does sit in this worktree"
    assert got["9001"]["attribution"] == "worktree-inherited", (
        "an allocation claimed FIVE MINUTES before this episode began must never be attributed to "
        "it; a one-UTC-offset parse error is what flips this arm"
    )
    assert got["9002"]["attribution"] == "this-episode", (
        "positive control: five minutes AFTER the baseline is this episode's, so the instrument is "
        "discriminating rather than answering worktree-inherited to everything"
    )


# =================================================================================================
# The writer under contention: rule 5's serialisation and its deadline.
# =================================================================================================


def _prewarmed(inner: str, cwd: Path, trigger: Path) -> subprocess.Popen[bytes]:
    """A rival that is ALREADY RUNNING when the trigger file appears.

    Launching pwsh at the moment of the race is what makes a concurrency test pass vacuously: the
    ~350 ms interpreter start swamps the ~500 ms window under attack, so the rival arrives after the
    subject has finished and the two never overlap.
    """
    script = (
        f"while (-not (Test-Path -LiteralPath '{trigger}')) {{ Start-Sleep -Milliseconds 5 }}; "
        + inner
    )
    return subprocess.Popen(
        ["pwsh", "-NoProfile", "-Command", script],
        cwd=str(cwd),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def test_close_handback_survives_a_concurrent_record(repo: Path, tmp_path: Path) -> None:
    """Last-write-wins over the read-modify-write window silently destroyed a successful -Close.

    Measured before rule 5: firing ``-Close -Handback`` with a rival ``-Record`` starting 120 ms
    later lost the close in 3 of 3 trials -- close exit 0, "wrote <path>" on stdout,
    ``lifecycle=open`` on disk, no error line anywhere, and the roster then calling that seat
    INTERRUPTED. A seat that closed itself was never closed.
    """
    sid = "sess-race"
    _write_record(repo, sid)
    trigger = tmp_path / "go-race.txt"
    rival = _prewarmed(f"& '{SEAT}' -Record -SessionId {sid}", repo, trigger)
    try:
        time.sleep(1.5)  # let the rival's interpreter reach its wait loop
        close = subprocess.Popen(
            ["pwsh", "-NoProfile", "-File", str(SEAT), "-Close", "-Handback", "-SessionId", sid],
            cwd=str(repo),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.12)  # the rival starts INSIDE the close's window, as measured
        trigger.write_text("go", encoding="utf-8")
        assert close.wait(timeout=120) == 0
        assert rival.wait(timeout=120) == 0
    finally:
        rival.kill()

    rec = _read_record(repo, sid)
    assert rec["lifecycle"] == "handed", (
        "the close was overwritten by a rival that read the record before it committed"
    )


def test_concurrent_writers_each_increment_the_writes_counter(repo: Path, tmp_path: Path) -> None:
    """N writers must move the counter by N. Measured before rule 5: 6 writers moved it 1 -> 3."""
    sid = "sess-writes"
    before = _write_record(repo, sid)["writes"]
    trigger = tmp_path / "go-writes.txt"
    rivals = [_prewarmed(f"& '{SEAT}' -Record -SessionId {sid}", repo, trigger) for _ in range(4)]
    try:
        time.sleep(1.8)
        trigger.write_text("go", encoding="utf-8")
        for p in rivals:
            assert p.wait(timeout=120) == 0
    finally:
        for p in rivals:
            p.kill()

    assert _read_record(repo, sid)["writes"] == before + 4, (
        "an unserialised read-modify-write loses every increment but the last"
    )


def test_concurrent_writers_leave_no_temp_files_and_no_lost_heartbeat(
    repo: Path, tmp_path: Path
) -> None:
    """Two collisions the atomic write had to fix, measured on both files.

    A temp path derived from the destination alone means two writers collide ON THE TEMP FILE: the
    loser logged a line and wrote NOTHING, having already done all the work. The per-box heartbeat
    is worse -- ``Set-Content`` truncates in place under an exclusive handle, so the losers left the
    file holding an OLDER timestamp and a reader that AGES it reads a running fleet as a dead one.
    """
    sid = "sess-temp"
    _write_record(repo, sid)
    box = _box_of(repo, sid)
    trigger = tmp_path / "go-temp.txt"
    rivals = [_prewarmed(f"& '{SEAT}' -Record -SessionId {sid}", repo, trigger) for _ in range(5)]
    try:
        time.sleep(1.8)
        trigger.write_text("go", encoding="utf-8")
        for p in rivals:
            assert p.wait(timeout=120) == 0
    finally:
        for p in rivals:
            p.kill()

    errfile = _seats_dir(repo) / ".writer-errors.txt"
    lines = errfile.read_text(encoding="utf-8").splitlines() if errfile.exists() else []
    stages = [ln.split("\t")[2] for ln in lines if len(ln.split("\t")) > 2]
    assert "main" not in stages, f"a writer died on a temp-file collision: {lines}"
    assert "writer-alive" not in stages, f"a writer lost the heartbeat race: {lines}"

    boxdir = _seats_dir(repo) / box
    assert not list(boxdir.glob("*.tmp")), list(boxdir.glob("*.tmp"))
    assert not list(boxdir.glob("*.lock")), list(boxdir.glob("*.lock"))

    hb = _seats_dir(repo) / ".writer-alive" / f"{box}.txt"
    stamp = datetime.strptime(hb.read_text(encoding="utf-8").strip(), "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=UTC
    )
    mtime = datetime.fromtimestamp(hb.stat().st_mtime, tz=UTC)
    assert abs((stamp - mtime).total_seconds()) < 10, (
        "the surviving heartbeat's CONTENT is a different writer's than the file's -- a truncating "
        "write let a loser leave an older instant behind"
    )


def test_writer_never_blocks_on_a_held_lock(repo: Path, tmp_path: Path) -> None:
    """Rule 5's DEADLINE outranks its serialisation, because this runs as a Stop hook.

    A lock that blocks for ever is a worse defect than the race it prevents, so a wait that times
    out PROCEEDS UNLOCKED and records that it did. The write is never skipped: refusing to record
    converts a rare lost field into a guaranteed lost episode.
    """
    sid = "sess-blocked"
    _write_record(repo, sid)
    lock = Path(str(_record_path(repo, sid)) + ".lock")
    holder_script = tmp_path / "holder.ps1"
    holder_script.write_text(
        "param([string]$LockPath,[int]$Seconds)\n"
        "$fs = [System.IO.File]::Open($LockPath, 'CreateNew', 'Write', 'Read')\n"
        "$sw = [System.Diagnostics.Stopwatch]::StartNew()\n"
        "while ($sw.Elapsed.TotalSeconds -lt $Seconds) {\n"
        "  $b = [System.Text.Encoding]::UTF8.GetBytes('held ' + [DateTime]::UtcNow.Ticks)\n"
        "  $fs.Write($b, 0, $b.Length); $fs.Flush($true)\n"
        "  (Get-Item -LiteralPath $LockPath).LastWriteTimeUtc = [DateTime]::UtcNow\n"
        "  Start-Sleep -Milliseconds 250\n"
        "}\n"
        "$fs.Dispose()\n"
        "Remove-Item -LiteralPath $LockPath -Force -EA SilentlyContinue\n",
        encoding="utf-8",
    )
    holder = subprocess.Popen(
        [
            "pwsh",
            "-NoProfile",
            "-File",
            str(holder_script),
            "-LockPath",
            str(lock),
            "-Seconds",
            "9",
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)
        assert lock.exists(), "the holder never took the lock; the test would be vacuous"
        before = _read_record(repo, sid)["writes"]
        r = _pwsh(SEAT, "-Record", "-SessionId", sid, cwd=repo)
        assert r.returncode == 0
        assert _read_record(repo, sid)["writes"] == before + 1, (
            "the body must run whether or not the lock was taken -- rule 5's deadline clause"
        )
        errfile = _seats_dir(repo) / ".writer-errors.txt"
        stages = [
            ln.split("\t")[2]
            for ln in errfile.read_text(encoding="utf-8").splitlines()
            if len(ln.split("\t")) > 2
        ]
        assert stages.count("record-lock") == 1, (
            f"an unserialised update must be reported exactly once; stages={stages}"
        )
    finally:
        holder.kill()
        holder.wait(timeout=30)


def test_orphaned_lock_is_broken_rather_than_waited_on(repo: Path) -> None:
    """A process killed mid-hold -- an exhausted account, a closed terminal, a rebooted box --
    leaves the lock file behind for ever, and nothing else on this box would ever clear it."""
    sid = "sess-orphan"
    _write_record(repo, sid)
    lock = Path(str(_record_path(repo, sid)) + ".lock")
    lock.write_text("99999 orphan", encoding="utf-8")
    old = time.time() - 30
    os.utime(lock, (old, old))

    t0 = time.monotonic()
    r = _pwsh(SEAT, "-Record", "-SessionId", sid, cwd=repo)
    elapsed = time.monotonic() - t0

    assert r.returncode == 0
    assert elapsed < 4.0, f"the orphan was waited out rather than broken ({elapsed:.1f}s)"
    assert not lock.exists(), "the lock file outlived the run that took it"
    errfile = _seats_dir(repo) / ".writer-errors.txt"
    if errfile.exists():
        assert "record-lock" not in errfile.read_text(encoding="utf-8"), (
            "breaking an orphan is the normal path, not a reported failure"
        )


def test_writer_heartbeat_is_separate_from_having_something_to_say(repo: Path) -> None:
    """ "The writer ran" and "the seat had output" are different sentences.

    A reader that cannot separate them reads a silently disabled hook as an idle fleet, and hooks are
    disabled silently by ``disableAllHooks``, org policy and workspace trust alike.
    """
    _pwsh(SEAT, "-Record", cwd=repo)
    alive = _seats_dir(repo) / ".writer-alive"
    assert list(alive.glob("*.txt")), "every invocation must leave a heartbeat"


def test_bad_worktree_writes_nothing_rather_than_a_junk_box(repo: Path, tmp_path: Path) -> None:
    """A git-resolution failure is a NO-WRITE path, never an empty-key path.

    ``mail.ps1`` records that the unguarded version of this "silently mints a NEW box that no reader
    will ever drain", and 11 of 29 mailboxes on one live box were that residue.

    THE SECOND CASE IS THE ONE THAT CAN FAIL. Running from outside any repo cannot mint a junk box
    whatever the guard does, because the SECOND guard (no git common dir) catches it -- so that arm
    alone is satisfied by a writer with rule 1 deleted. Measured: ``git -C ''`` is a NO-OP that
    resolves against the caller's cwd, so a run whose WORKTREE fails to resolve while the CWD is a
    real checkout sails past rule 1 straight into ``ConvertTo-BoxKey`` with an empty path and
    creates the seats layer under a repo it was never recording.
    """
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    r = _pwsh(SEAT, "-Record", cwd=outside)
    assert r.returncode == 0, "must not take the session's Stop hook down with it"
    assert not (outside / ".git").exists()

    # The worktree will not resolve; the cwd is a perfectly good checkout. Rule 1 has to refuse.
    r = _pwsh(SEAT, "-Record", "-Worktree", str(outside), cwd=repo)
    assert r.returncode == 0
    assert "could not resolve a rooted existing worktree" in r.stderr, r.stderr
    assert not (repo / ".git" / "mefor-coord").exists(), (
        "rule 1 was bypassed: the writer built the seats layer for a worktree it could not name"
    )

    # POSITIVE CONTROL, same repo, same instrument: a legitimate run DOES create exactly one box.
    _write_record(repo, "sess-control")
    boxes = [d for d in _seats_dir(repo).iterdir() if d.is_dir() and not d.name.startswith(".")]
    assert len(boxes) == 1, [d.name for d in boxes]


# =================================================================================================
# The reader: the receipt, and the difference between answering and refusing.
# =================================================================================================


def _make_clean_roster(repo: Path, fence: Fence, session: str = "sess-clean-roster") -> None:
    """A fixture in which NO stop condition may fire, so an empty stop list means something.

    Every operand is pinned: the fence is present and has read a record, git lists the worktrees,
    the one live session the fence can see is NOT in this clone, one seat record exists and carries
    a session id, no writer error has ever been logged, and FETCH_HEAD makes origin/main's age
    checkable.
    """
    elsewhere = repo.parent / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    fence.record("00000000-dead-dead-dead-000000000000", elsewhere, pid=4, started_ms=1)
    _write_record(repo, session)
    (repo / ".git" / "FETCH_HEAD").write_text("", encoding="utf-8")


def test_receipt_answers_and_says_so(repo: Path, fence: Fence) -> None:
    """An empty roster and a dead writer produce the same output unless the receipt says otherwise.

    The reader of this output is by construction the person least equipped to notice -- they are
    reading it because they lost the context that would have told them.

    THIS IS THE ANSWERING BRANCH, and it is asserted as such. The version of this test that only
    checked key presence and ``recordsExamined`` passed identically over a fence that had refused,
    which is the branch every CI runner takes, so the path an operator actually uses was executed
    nowhere.
    """
    _make_clean_roster(repo, fence, "sess-receipt")
    rc, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]

    assert rc == 0, "exit 0 is the reader's claim to have been able to evaluate the fence"
    for key in (
        "rootsExamined",
        "fenceAvailable",
        "fenceSessionRecordsRead",
        "fenceCanSee",
        "recordsExamined",
        "recordsUnreadable",
        "liveSessionsWithoutRecord",
        "liveSessionsWithStaleRecord",
        "writerHeartbeatIn",
        "writerHeartbeatNewestAgeMinutes",
        "originMainAgeMinutes",
        "originMainAgeSource",
        "freshWithinMinutes",
        "stopConditions",
    ):
        assert key in receipt, f"receipt must report {key}"
    assert receipt["recordsExamined"] == 1
    assert receipt["fenceAvailable"] is True
    assert receipt["rootsExamined"] == 1
    assert receipt["fenceCanSee"] is True


def test_receipt_refuses_and_says_so(repo: Path, nofence: Fence) -> None:
    """The refusing branch, pinned by its own exit code.

    With no config root holding a sessions/ directory nothing can be fenced, so every state is a
    guess -- the reader must say so in the receipt, in a stop condition, and in the exit code, and
    all three must differ from the answering run above.
    """
    _write_record(repo, "sess-norefuse")
    rc, payload = _fleet_json(repo, nofence)
    receipt = payload["receipt"]

    assert rc == 2, "a refusal that exits 0 is indistinguishable from an answer"
    assert receipt["fenceAvailable"] is False
    assert receipt["rootsExamined"] == 0
    assert any(s.startswith("fenceAvailable=false") for s in receipt["stopConditions"]), receipt[
        "stopConditions"
    ]
    # The evidence is still RENDERED. A stop suppresses the claim of completeness; it is not a crash.
    assert receipt["recordsExamined"] == 1
    assert len(payload["rows"]) == 1


def test_json_emits_arrays_never_null(repo: Path, fence: Fence) -> None:
    """``key in receipt`` passes against the null bug; ``== []`` is what catches it.

    Measured: ``-Json -Raw`` emitted ``"stopConditions": []`` while ``-Json`` -- the DEFAULT, and
    the form most likely to be piped into a file, a ticket or an artifact -- emitted ``null`` for
    the same run, because a statement's output stream UNROLLS an array and an empty one contributes
    zero objects. A machine reader then cannot tell "no stop conditions" from "this instrument does
    not report stop conditions", which is this module's own defect class.
    """
    _make_clean_roster(repo, fence)
    rc, payload = _fleet_json(repo, fence)
    assert rc == 0
    assert payload["receipt"]["stopConditions"] == [], payload["receipt"]["stopConditions"]
    assert isinstance(payload["rows"], list) and payload["rows"]
    assert payload["liveSessionsNotDescribed"] == []


def test_unreadable_record_fires_a_stop(repo: Path, fence: Fence) -> None:
    """A record this roster cannot describe is a SEAT this roster cannot describe.

    It was already counted and already printed; it just entered no stop, so a seats layer in which
    EVERY record was unreadable rendered under "NO STOP CONDITIONS. The roster below is as complete
    as this instrument can establish."
    """
    _make_clean_roster(repo, fence)
    box = _seats_dir(repo) / "probe-box"
    box.mkdir()
    (box / "junk.json").write_text("{not json at all", encoding="utf-8")

    rc, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert rc == 0
    assert receipt["recordsUnreadable"] == 1
    assert receipt["stopConditions"], "an unreadable record must suppress the completeness claim"
    assert any(s.startswith("recordsUnreadable=") for s in receipt["stopConditions"]), receipt[
        "stopConditions"
    ]


def test_writer_errors_fire_a_stop_now_and_not_thirty_days_ago(repo: Path, fence: Fence) -> None:
    """The operand is the RECENT count, and that is correctness rather than softening.

    ``.writer-errors.txt`` is append-only and nothing truncates it, so a stop keyed on the TOTAL
    would fire for ever after the first failure this repo ever had -- and a channel that fires when
    nothing is wrong trains its reader to skip it. This file already paid for that lesson once on
    origin/main staleness. The second half is the anti-crying-wolf property and the one that will
    regress.
    """
    _make_clean_roster(repo, fence)
    errfile = _seats_dir(repo) / ".writer-errors.txt"
    now = datetime.now(UTC)
    line = "{0}\tBOX\tstash-probe\tgit stash create failed\n"

    errfile.write_text(line.format(_iso(now)), encoding="utf-8")
    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["writerErrorLines"] == 1
    assert receipt["writerErrorLinesRecent"] == 1
    assert any(s.startswith("writerErrorLinesRecent=") for s in receipt["stopConditions"]), receipt[
        "stopConditions"
    ]

    errfile.write_text(line.format(_iso(now - timedelta(days=30))), encoding="utf-8")
    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["writerErrorLines"] == 1, "the history must not be hidden"
    assert receipt["writerErrorLinesRecent"] == 0
    assert not any("writerErrorLines" in s for s in receipt["stopConditions"]), (
        f"a month-old failure fired a stop; that is the crying-wolf regression: "
        f"{receipt['stopConditions']}"
    )


def test_malformed_records_leave_the_reader_alive(repo: Path, fence: Fence, tmp_path: Path) -> None:
    """A CRASH IS THE INVERSE OF A STOP, NOT A STRONGER ONE.

    A stop suppresses the claim of completeness and still renders the evidence; an unhandled
    exception suppresses the evidence and renders nothing. Under ``Set-StrictMode -Version Latest``
    a MISSING PROPERTY THROWS, and measured on the shipped file a one-line ``{"a":1}``, a
    whitespace-only file and a ZERO-BYTE file dropped into any box directory each produced exit 1,
    a bare PropertyNotFoundException, and no receipt, no denominator and no roster at all.

    THE NEGATIVE CONTROL RUNS HERE. Without it this test cannot tell a reader that survives from a
    fixture that was never dangerous, so the same three files are put in front of a reader whose
    Get-RecField and unreadable-shape guard have been removed, and it is REQUIRED to die.
    """
    _make_clean_roster(repo, fence)
    box = _seats_dir(repo) / "probe-box"
    box.mkdir()
    cases = {
        "zero.json": ("", "recordsUnreadable"),
        "blank.json": ("   \r\n  ", "recordsUnreadable"),
        "scalar.json": ('{"a":1}', "recordsUnfenceable"),
    }

    blind = _mutant(
        tmp_path,
        "blindreader",
        FLEET,
        [
            (
                "    if ($null -eq $Object) { return $Default }\n"
                "    try {\n"
                "        if ($Object.PSObject.Properties.Name -contains $Name) {\n"
                "            $v = $Object.$Name\n"
                "            if ($null -ne $v) { return $v }\n"
                "        }\n"
                "    } catch { }\n"
                "    return $Default\n",
                "    return $Object.$Name\n",
            ),
            (
                "            if ($null -eq $j -or -not ($j.PSObject.BaseObject -is "
                "[System.Management.Automation.PSCustomObject])) {\n"
                "                $unreadableRecords++\n"
                "                continue\n"
                "            }\n",
                "",
            ),
        ],
    )

    for name, (body, field) in cases.items():
        f = box / name
        f.write_text(body, encoding="utf-8")
        try:
            rc, payload = _fleet_json(repo, fence)
            assert rc == 0, f"{name} took the reader down"
            assert payload["receipt"][field] == 1, (name, field, payload["receipt"])

            control = _pwsh(blind, "-Json", cwd=repo, env=fence.env)
            assert control.returncode == 1, (
                f"the Get-RecField-less control survived {name}; this fixture proves nothing"
            )
            assert control.stdout.strip() == "", (
                f"the control printed a receipt for {name}; it was supposed to die before one"
            )
        finally:
            f.unlink()


def test_fence_can_see_is_measured_not_assumed(repo: Path, fence: Fence) -> None:
    """A FENCE THAT IS PRESENT IS NOT A FENCE THAT CAN SEE.

    ``rootsExamined``/``fenceAvailable`` test that a config root holds a sessions/ DIRECTORY. An
    EMPTY one passes that, and then every record with a session id gets the fence's ordinary
    NOT-REGISTERED answer and lands on INTERRUPTED -- the most destructive verdict available and the
    one that fills the respawn population. MEASURED: a genuinely LIVE session rendered RUNNING with
    its registry record present and INTERRUPTED with the sessions/ directory emptied, both runs
    reporting rootsExamined=1, fenceAvailable=true and "NO STOP CONDITIONS".
    """
    _write_record(repo, "sess-blindfence")
    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["fenceAvailable"] is True, "the DIRECTORY exists, so structure passes"
    assert receipt["fenceSessionRecordsRead"] == 0
    assert receipt["fenceCanSee"] is False
    assert any(s.startswith("fenceSessionRecordsRead=0") for s in receipt["stopConditions"]), (
        receipt["stopConditions"]
    )

    fence.record("11111111-1111-1111-1111-111111111111", repo.parent / "elsewhere", 4, 1)
    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["fenceSessionRecordsRead"] == 1
    assert receipt["fenceCanSee"] is True
    assert not any("fenceSessionRecordsRead=0" in s for s in receipt["stopConditions"]), receipt[
        "stopConditions"
    ]


def test_live_session_in_a_subdirectory_counts_and_a_sibling_checkout_does_not(
    repo: Path, fence: Fence
) -> None:
    """EXACT MATCH OR DESCENDANT, AND THE SEPARATOR IS NOT OPTIONAL.

    A session whose cwd is a SUBDIRECTORY of a worktree is still that worktree's session, and exact
    path equality dropped every one of them -- measured the same night, presence.ps1 counted 13 live
    sessions where a second instrument reached 10, and the checkout just worked in was among the
    three it could not see. The separator is the other half: a bare StartsWith makes
    "MessageFoundry-ledger" a child of "MessageFoundry".
    """
    sub = repo / "messagefoundry" / "parsing"
    sub.mkdir(parents=True)
    fence.live("aaaaaaaa-0000-0000-0000-000000000001", sub)
    _write_record(repo, "sess-sub")
    _, payload = _fleet_json(repo, fence)
    assert payload["receipt"]["liveSessionsInRepo"] == 1, (
        "a session one directory down is still that checkout's session"
    )

    fence.clear()
    ledger = _init_repo(repo.parent / f"{repo.name}-ledger")
    fence.live("aaaaaaaa-0000-0000-0000-000000000002", ledger)
    _, payload = _fleet_json(repo, fence)
    assert payload["receipt"]["liveSessionsInRepo"] == 0, (
        "'<repo>-ledger' is a sibling checkout, not a child of '<repo>'"
    )


def test_stale_record_and_missing_record_are_not_conflated(repo: Path, fence: Fence) -> None:
    """ "A record exists" and "the writer is still recording this seat" are different sentences.

    One record ever written satisfied the first for ever, so a writer that recorded turn 1 and then
    died was byte-identical to one recording every turn. The two counters must never merge: one says
    the roster is SHORT, the other says it is OUT OF DATE, and they call for different actions.
    """
    sid = "aaaaaaaa-0000-0000-0000-000000000003"
    fence.live(sid, repo)
    _write_record(repo, sid)
    _patch_record(repo, sid, asOf=_iso(datetime.now(UTC) - timedelta(hours=3)))

    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["liveSessionsInRepo"] == 1
    assert receipt["liveSessionsWithStaleRecord"] == 1
    assert receipt["liveSessionsWithoutRecord"] == 0, (
        "a stale record is not a missing one; collapsing them loses the distinction that says WHY"
    )
    assert any(s.startswith("liveSessionsWithStaleRecord=") for s in receipt["stopConditions"])


def test_heartbeat_is_read_not_counted(repo: Path, fence: Fence) -> None:
    """Counting files can only ever go UP, so proof-of-life could never go stale or fall.

    seat.ps1 rule 3 writes a UTC instant INSIDE ``seats/.writer-alive/<box>.txt`` on every
    invocation; the reader used to count the files and never open them, so a writer disabled months
    ago read exactly like one that ran a second ago.
    """
    _write_record(repo, "sess-hb")
    box = _box_of(repo, "sess-hb")
    hb = _seats_dir(repo) / ".writer-alive" / f"{box}.txt"
    hb.write_text(_iso(datetime.now(UTC) - timedelta(days=3)), encoding="utf-8")

    _, payload = _fleet_json(repo, fence)
    receipt = payload["receipt"]
    assert receipt["writerHeartbeatIn"] == 1
    age = receipt["writerHeartbeatNewestAgeMinutes"]
    assert age is not None and 4200 < age < 4500, (
        f"the heartbeat's own timestamp was not read; got {age} minutes for a 3-day-old instant"
    )

    shutil.rmtree(_seats_dir(repo) / ".writer-alive")
    _, payload = _fleet_json(repo, fence)
    assert payload["receipt"]["writerHeartbeatNewestAgeMinutes"] is None, (
        "no heartbeat file at all is a different sentence from 'one exists and is old'"
    )


# =================================================================================================
# The reader: roster STATE. Nothing here was pinned before, and a regression that silently drops
# the one seat holding unrecoverable work passed the entire suite.
# =================================================================================================


def test_a_positive_fence_outranks_every_recorded_label(repo: Path, fence: Fence) -> None:
    """ORDER IS THE FIX, NOT JUST THE ARMS.

    fence=LIVE is the only answer measured against the world as it is right now; everything else is
    a label recorded in the past. Two labels used to sit above it. ``lifecycle=handed`` is the worse
    one, because HANDED is IN the respawn population -- a live seat that had run ``-Close -Handback``
    would have had a SECOND session dropped into its occupied worktree.
    """
    sid = "aaaaaaaa-0000-0000-0000-000000000004"
    fence.live(sid, repo)
    _write_record(repo, sid)
    r = _pwsh(SEAT, "-Close", "-Handback", "-SessionId", sid, cwd=repo)
    assert r.returncode == 0
    assert _read_record(repo, sid)["lifecycle"] == "handed", "the fixture must really be handed"

    rc, payload = _fleet_json(repo, fence)
    row = payload["rows"][0]
    assert rc == 0
    assert row["Fence"] == "LIVE"
    assert row["State"] == "RUNNING", (
        "a recorded label masked a measured one; a replacement would be spawned into an occupied "
        "checkout"
    )

    text = _pwsh(FLEET, "-Text", cwd=repo, env=fence.env)
    assert "RESPAWN POPULATION (INTERRUPTED, HANDED): 0" in text.stdout, text.stdout


def test_only_a_fence_that_answered_not_registered_licenses_interrupted(
    repo: Path, fence: Fence, nofence: Fence
) -> None:
    """FOUR OUTCOMES, FOUR TOKENS, and only ONE of them may fill the respawn population.

    These used to collapse into a single literal 'UNKNOWN' with no arm in the switch, so all four
    fell through to ``default { 'INTERRUPTED' }``. The filed fix -- map UNKNOWN to POSSIBLY RUNNING
    -- would have been the OPPOSITE defect: NOT-REGISTERED is also the fence's ordinary answer for
    the entire dead population, so it would have driven the respawn population to zero and
    manufactured the confidently-empty roster this module exists to prevent. This is the exact place
    a wrong fix would undo, so all four arms are pinned together.
    """
    # NOT-REGISTERED -- the fence ANSWERED, and answered "no such session".
    fence.record("11111111-1111-1111-1111-111111111111", repo.parent / "elsewhere", 4, 1)
    _write_record(repo, "aaaaaaaa-0000-0000-0000-00000000000f")
    _, payload = _fleet_json(repo, fence)
    row = payload["rows"][0]
    assert row["Fence"] == "NOT-REGISTERED"
    assert row["State"] == "INTERRUPTED"
    text = _pwsh(FLEET, "-Text", cwd=repo, env=fence.env)
    assert "RESPAWN POPULATION (INTERRUPTED, HANDED): 1" in text.stdout, text.stdout

    # NOT-FENCEABLE -- the record carries no session id (the documented `nosid` hook path).
    shutil.rmtree(_seats_dir(repo))
    assert _pwsh(SEAT, "-Record", cwd=repo).returncode == 0
    _, payload = _fleet_json(repo, fence)
    row = payload["rows"][0]
    assert row["Fence"] == "NOT-FENCEABLE"
    assert row["State"] == "POSSIBLY RUNNING", "an unevaluated fence is not a passed fence"
    assert payload["receipt"]["recordsUnfenceable"] == 1
    text = _pwsh(FLEET, "-Text", cwd=repo, env=fence.env)
    assert "RESPAWN POPULATION (INTERRUPTED, HANDED): 0" in text.stdout, text.stdout

    # FENCE-ERROR -- a registry file caught mid-write makes the fence THROW.
    shutil.rmtree(_seats_dir(repo))
    _write_record(repo, "aaaaaaaa-0000-0000-0000-00000000000e")
    (fence.sessions / "halfwritten.json").write_text('{"a":1}', encoding="utf-8")
    _, payload = _fleet_json(repo, fence)
    row = payload["rows"][0]
    assert row["Fence"] == "FENCE-ERROR"
    assert row["State"] == "POSSIBLY RUNNING", (
        "a session that just launched is the last thing that should read as absent"
    )

    # NO-FENCE -- nothing was asked of anything, so nothing may be concluded.
    rc, payload = _fleet_json(repo, nofence)
    row = payload["rows"][0]
    assert rc == 2
    assert row["Fence"] == "NO-FENCE"
    assert row["State"] == "UNKNOWN-NO-FENCE"


def test_superseded_needs_a_named_predecessor_not_a_shared_checkout(
    repo: Path, fence: Fence
) -> None:
    """SUPERSEDED means "a LATER RECORD OF THIS SEAT replaced this one" and nothing else.

    It used to be computed per BOX -- and the box IS the worktree, while records are keyed per
    (worktree, SESSION). So every other session that had ever recorded in that checkout retired the
    older ones. MEASURED: with three sessions in one box, a seat holding the only copy of an
    untracked file AND a seat the fence reported LIVE both rendered SUPERSEDED under "NO STOP
    CONDITIONS", while the same LIVE session id alone in its own box rendered RUNNING in the same
    run. Both arms are here because the first without the second is satisfied by deleting the rule.
    """
    fence.record("11111111-1111-1111-1111-111111111111", repo.parent / "elsewhere", 4, 1)
    older = "aaaaaaaa-0000-0000-0000-0000000000a1"
    newer = "aaaaaaaa-0000-0000-0000-0000000000a2"
    _write_record(repo, older)
    _write_record(repo, newer)
    box = _box_of(repo, older)

    # ARM 1 -- sharing a checkout supersedes NOTHING. They are different sessions' work.
    _, payload = _fleet_json(repo, fence)
    states = {r["SessionKey"]: r["State"] for r in payload["rows"]}
    assert states == {older: "INTERRUPTED", newer: "INTERRUPTED"}, states
    assert payload["receipt"]["checkoutsWithSeveralRecords"] == 1, (
        "the collision is REPORTED rather than resolved by hiding a row"
    )

    # ARM 2 -- a record that NAMES its predecessor does supersede it, and only it.
    r = _pwsh(SEAT, "-Declare", "-SessionId", newer, "-Predecessor", f"{box}/{older}", cwd=repo)
    assert r.returncode == 0, r.stderr
    _, payload = _fleet_json(repo, fence)
    states = {r["SessionKey"]: r["State"] for r in payload["rows"]}
    assert states[older] == "SUPERSEDED"
    assert states[newer] == "INTERRUPTED"
    text = _pwsh(FLEET, "-Text", cwd=repo, env=fence.env)
    assert "RESPAWN POPULATION (INTERRUPTED, HANDED): 1" in text.stdout, text.stdout


def test_checkout_gone_is_visible_and_out_of_the_respawn_population(
    repo: Path, fence: Fence
) -> None:
    """The record outlives the checkout BY CONSTRUCTION.

    The project's own cleanup runs ``git worktree remove --force`` and does not touch this layer, so
    a vanished checkout used to render byte-identically to a live one -- still INTERRUPTED, still
    counted for respawn -- while -Detail put "WORK AT RISK ... if that checkout is removed they are
    gone" over files that went with the directory. A warning written in the conditional for a
    condition that already holds.
    """
    sid = "aaaaaaaa-0000-0000-0000-0000000000b1"
    fence.record("11111111-1111-1111-1111-111111111111", repo.parent / "elsewhere", 4, 1)
    _write_record(repo, sid)

    _, payload = _fleet_json(repo, fence)
    assert payload["rows"][0]["State"] == "INTERRUPTED", "control: the checkout is there"

    _patch_record(repo, sid, worktree=str(repo.parent / "vanished-worktree"))
    _, payload = _fleet_json(repo, fence)
    row = payload["rows"][0]
    assert row["State"] == "CHECKOUT-GONE"
    assert row["CheckoutGone"] is True
    assert payload["receipt"]["recordsCheckoutGone"] == 1
    text = _pwsh(FLEET, "-Text", cwd=repo, env=fence.env)
    assert "RESPAWN POPULATION (INTERRUPTED, HANDED): 0" in text.stdout, text.stdout
    assert "CHECKOUT-GONE" in text.stdout, "out of the population, but still VISIBLE"


# =================================================================================================
# The reader: -Detail, the surface a human reads before composing a chip by hand.
# =================================================================================================


def _detail(repo: Path, fence: Fence, session: str) -> subprocess.CompletedProcess[str]:
    return _pwsh(
        FLEET,
        "-Detail",
        "-BoxKey",
        _box_of(repo, session),
        "-SessionKey",
        session,
        cwd=repo,
        env=fence.env,
    )


def test_detail_renders_three_different_stash_verdicts(repo: Path, fence: Fence) -> None:
    """A pruned handle and a live one were byte-identical, under a heading telling the reader the
    tracked half is the recoverable one.

    ``git stash create`` writes no ref and no reflog entry, so the object is unreachable from the
    moment it exists. The writer anchors it; this is the READER half, and all three states of that
    anchor have to render differently or the fix is cosmetic.
    """
    sid = "aaaaaaaa-0000-0000-0000-0000000000c1"
    (repo / "tracked.txt").write_text("modified\n", encoding="utf-8")
    rec = _write_record(repo, sid)
    sha, ref = rec["stashSha"], rec["stashRef"]
    assert sha and ref

    anchored = _detail(repo, fence, sid)
    assert anchored.returncode == 0, anchored.stderr
    assert ref in anchored.stdout, anchored.stdout
    assert "still holds it" in anchored.stdout

    _git(repo, "update-ref", "-d", ref)
    unanchored = _detail(repo, fence, sid)
    assert unanchored.returncode == 0
    assert "NO LONGER RESOLVES" not in unanchored.stdout, "the object is still there"
    assert "nothing holds it" in unanchored.stdout
    assert "is GONE" in unanchored.stdout

    _git(repo, "reflog", "expire", "--expire=now", "--all")
    subprocess.run(
        ["git", "-C", str(repo), "gc", "--prune=now"],
        check=True,
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
    )
    assert _git_rc(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}") != 0

    pruned = _detail(repo, fence, sid)
    assert pruned.returncode == 0
    assert "NO LONGER RESOLVES" in pruned.stdout, pruned.stdout
    covers = [
        ln.strip() for ln in pruned.stdout.splitlines() if ln.strip().startswith("stash covers:")
    ]
    assert covers == [
        "stash covers: tracked-only -- AS RECORDED; the object backing it is gone (above)"
    ], (
        f"a bare 'stash covers: tracked-only' under a pruned object reads as a live promise: {covers}"
    )


def test_detail_survives_a_claim_without_an_attribution_key(repo: Path, fence: Fence) -> None:
    """A claim written by an older writer, or one caught mid-write, need not carry ``attribution``.

    Under strict mode reading the absent property throws out of the WHOLE -Detail render, and the
    pre-fix failure printed the LEDGER heading and then died -- so an assertion on the exit code
    alone is not enough. The footer is what proves the render completed.
    """
    sid = "aaaaaaaa-0000-0000-0000-0000000000c2"
    fence.record("11111111-1111-1111-1111-111111111111", repo.parent / "elsewhere", 4, 1)
    _write_record(repo, sid)
    _patch_record(repo, sid, claims=[{"key": "ledger-orphan", "claimedAt": None}])

    out = _detail(repo, fence, sid)
    assert out.returncode == 0, out.stderr
    assert "LEDGER AND CLAIMS" in out.stdout
    assert "ledger-orphan" in out.stdout
    assert "ACCOUNT BOUNDARY" in out.stdout, (
        "the render died after the LEDGER heading; exit code alone would not have shown it"
    )


def test_detail_warns_when_its_roster_fired_a_stop(repo: Path, fence: Fence) -> None:
    """-Detail exits before the receipt is rendered.

    A reader handed a -Detail command who runs only that never learns the roster it came from
    refused. This row's own evidence is unaffected -- what is unknown is what ELSE was running.
    """
    sid = "aaaaaaaa-0000-0000-0000-0000000000c3"
    _make_clean_roster(repo, fence, sid)
    clean = _detail(repo, fence, sid)
    assert clean.returncode == 0
    assert "STOP CONDITION(S) fired" not in clean.stdout, (
        "control: nothing was wrong, so the warning must be absent"
    )

    box = _seats_dir(repo) / "probe-box"
    box.mkdir()
    (box / "junk.json").write_text("{not json", encoding="utf-8")
    warned = _detail(repo, fence, sid)
    assert warned.returncode == 0
    assert "STOP CONDITION(S) fired" in warned.stdout, warned.stdout


# =================================================================================================
# The shared fence, called the way fleet.ps1 calls it.
# =================================================================================================


def test_fence_guards_are_reachable_from_a_strict_mode_caller(tmp_path: Path, fence: Fence) -> None:
    """STRICT MODE IS DYNAMICALLY SCOPED, so this guard's reachability is decided OUTSIDE its file.

    ``Test-RecordLiveness``'s own no-pid and no-startedAt guards read as fixed from a non-strict
    caller and are DEAD CODE from fleet.ps1, which sets ``Set-StrictMode -Version Latest`` before
    dot-sourcing. Measured: a registry record with a non-numeric field threw out of the fence and
    fleet.ps1 exited 1 with a bare PropertyNotFoundException and no receipt at all. A suite that
    calls the fence from a non-strict caller returns UNVERIFIED both before and after the fix, so it
    cannot see this class at all -- the caller's strict mode is the fixture.
    """
    live = subprocess.Popen(
        ["pwsh", "-NoProfile", "-Command", "Start-Sleep -Seconds 60"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.7)
    probe = tmp_path / "strict-fence.ps1"
    probe.write_text(
        "param([int]$LivePid)\n"
        "Set-StrictMode -Version Latest\n"
        "$ErrorActionPreference = 'Stop'\n"
        f'. "{REGISTRY}"\n'
        "$noPid = [pscustomobject]@{ sessionId = 'a'; cwd = 'x' }\n"
        "$noStarted = [pscustomobject]@{ sessionId = 'b'; pid = $LivePid; cwd = 'x' }\n"
        "[ordered]@{\n"
        "  noPid = (Test-RecordLiveness -Record $noPid).State\n"
        "  noStartedAt = (Test-RecordLiveness -Record $noStarted).State\n"
        "  nullRecord = (Test-RecordLiveness -Record $null).State\n"
        "} | ConvertTo-Json\n",
        encoding="utf-8",
    )
    try:
        r = _pwsh(probe, "-LivePid", str(live.pid), cwd=tmp_path)
    finally:
        live.kill()
    assert r.returncode == 0, f"the fence threw out of a strict caller; stderr={r.stderr}"
    got = json.loads(r.stdout)
    assert got["noPid"] == "UNREADABLE", got
    assert got["noStartedAt"] == "UNVERIFIED", got
    assert got["nullRecord"] == "UNREADABLE", got


# =================================================================================================
# The Stop hook. It had no test anywhere: `grep -rn seat-record tests/` returned nothing.
# =================================================================================================


def test_hook_records_a_writer_failure_rather_than_a_clean_turn(repo: Path, tmp_path: Path) -> None:
    """A NON-ZERO EXIT IS NOT AN EXCEPTION, and seat.ps1's no-write paths exit 0 with a message.

    This hook used to run the writer as ``... 2>&1 | Out-Null`` and exit 0, and the justification --
    "seat.ps1 records its own failures" -- is FALSE for exactly the failures that discard hid:
    seat.ps1 leaves its seats directory unresolved until it has a worktree AND a git common dir, and
    its error writer returns early while that is null. MEASURED: a writer that could not start
    reported rc=1 and a real error on stderr when run directly; THROUGH THE HOOK it was rc=0, empty
    stdout, empty stderr, zero files touched -- byte-identical to a healthy quiet turn.
    """
    common = str(repo / ".git")
    outside = tmp_path / "hook-not-a-repo"
    outside.mkdir()

    # POSITIVE CONTROL FIRST: a healthy turn must stay SILENT, or the failure signal is noise.
    payload = json.dumps({"session_id": "hook-sess-ok", "cwd": str(repo)})
    ok = _pwsh(HOOK, "-CommonDir", common, cwd=repo, stdin=payload)
    assert ok.returncode == 0
    assert ok.stdout.strip() == "", f"a healthy turn must print nothing: {ok.stdout!r}"
    assert _record_path(repo, "hook-sess-ok").exists()
    errfile = _seats_dir(repo) / ".writer-errors.txt"
    assert not errfile.exists(), errfile.read_text(encoding="utf-8") if errfile.exists() else ""

    # THE FAILURE: the writer refuses (rule 1) and says so on stderr only. The hook is the surface
    # that still works when the writer's own error path does not.
    bad = json.dumps({"session_id": "hook-sess-bad", "cwd": str(outside)})
    r = _pwsh(HOOK, "-CommonDir", common, cwd=outside, stdin=bad)
    assert r.returncode == 0, "the hook must never fail the turn"
    assert "[seat] this turn was NOT recorded" in r.stdout, r.stdout
    assert errfile.exists(), "the child's diagnostics were discarded again"
    stages = [
        ln.split("\t")[2]
        for ln in errfile.read_text(encoding="utf-8").splitlines()
        if len(ln.split("\t")) > 2
    ]
    assert "hook-writer-failed" in stages, stages


# =================================================================================================
# The installer. -Only selects an EVENT, and Stop carries three independent hooks.
# =================================================================================================

MARKERS = ("mefor-coord", "mefor-announce", "mefor-mail", "mefor-wake", "mefor-seat")


def _settings_fixture(tmp_path: Path) -> Path:
    """A settings file with a FOREIGN hook already in the event we are about to touch."""
    p = tmp_path / "settings-fixture.json"
    p.write_text(
        json.dumps(
            {
                "hooks": {
                    "Stop": [{"hooks": [{"type": "command", "command": "# someone-elses-hook"}]}]
                }
            }
        ),
        encoding="utf-8",
    )
    return p


def _install(settings: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return _pwsh(INSTALLER, "-SettingsPath", str(settings), *args, cwd=settings.parent)


def _commands(settings: Path) -> list[tuple[str, str]]:
    data = json.loads(settings.read_text(encoding="utf-8-sig"))
    out: list[tuple[str, str]] = []
    for event, entries in (data.get("hooks") or {}).items():
        for entry in entries:
            for h in entry.get("hooks", []):
                out.append((event, h.get("command", "")))
    return out


def _marker_command(settings: Path, marker: str) -> str:
    hits = [c for _, c in _commands(settings) if f"# {marker}" in c]
    assert len(hits) == 1, f"expected exactly one {marker} row, got {len(hits)}"
    return hits[0]


def test_install_and_status_list_every_row_and_a_bad_filter_exits_two(tmp_path: Path) -> None:
    """The install path is unchanged by the removal-receipt work above it."""
    settings = _settings_fixture(tmp_path)
    r = _install(settings)
    assert r.returncode == 0, r.stdout + r.stderr
    rows = [c for _, c in _commands(settings)]
    assert len([c for c in rows if any(f"# {m}" in c for m in MARKERS)]) == 7, rows
    assert any("# someone-elses-hook" in c for c in rows), "a foreign hook was collateral"

    st = _install(settings, "-Status")
    assert st.returncode == 0
    listed = [ln for ln in st.stdout.splitlines() if re.match(r"^\s{4}\S+\s+scripts/", ln)]
    assert len(listed) == 7, listed
    assert all("INSTALLED" in ln for ln in listed), listed

    nothing = _install(settings, "-Only", "NoSuchEvent")
    assert nothing.returncode == 2, nothing.stdout


def test_only_stop_uninstall_names_the_three_rows_before_writing(tmp_path: Path) -> None:
    """A REMOVAL THAT TAKES MORE THAN THE OPERATOR NAMED HAS TO SAY SO, BEFORE IT WRITES.

    Measured 2026-08-14 on a fixture: ``-Only Stop -Uninstall`` removed mefor-mail, mefor-seat AND
    mefor-wake -- the async mail drain and the whole urgent-mail push tier went with the recorder --
    and the entire receipt was "REMOVED <path>" plus a root count, naming none of them. The
    operator's natural check afterwards, ``-Status -Only Stop``, then shows three rows MISSING,
    which reads as SUCCESS to someone who asked for a removal.

    THE ASSERTION IS ON THE ROW NAMES, not on the count: a future sixth Stop row would change the
    count legitimately and must not fail this test, while a row silently dropped from the caution
    must.
    """
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0

    r = _install(settings, "-Only", "Stop", "-Uninstall")
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    heads = [
        i
        for i, ln in enumerate(lines)
        if re.search(r"REMOVING 3 ROW\(S\) ACROSS 3 INDEPENDENT HOOKS", ln)
    ]
    assert heads, r.stdout
    head = heads[0]
    writes = [i for i, ln in enumerate(lines) if "REMOVED " in ln]
    assert writes and head < writes[0], "the caution was printed AFTER the file was rewritten"

    tail = [i for i, ln in enumerate(lines) if "If you meant ONE of these" in ln]
    assert tail and tail[0] > head
    block = "\n".join(lines[head + 1 : tail[0]])
    for script, marker in (
        ("mail-drain", "mefor-mail"),
        ("seat-record", "mefor-seat"),
        ("mail-watch", "mefor-wake"),
    ):
        assert re.search(rf"Stop\s+\S*{script}\.ps1\s+{marker}", block), (script, block)


def test_script_seat_record_uninstall_leaves_its_siblings(tmp_path: Path) -> None:
    """The recipe the $SEAT_MARKER comment documents, and the negative control for the row above.

    If this ever starts removing siblings, the documented 2am remedy is wrong again.
    """
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0
    r = _install(settings, "-Script", "seat-record", "-Uninstall")
    assert r.returncode == 0, r.stdout + r.stderr

    rows = [c for _, c in _commands(settings)]
    assert not any("# mefor-seat" in c for c in rows), "the row asked for was not removed"
    assert any("# mefor-mail" in c for c in rows), "the async mail drain went with it"
    assert any("# mefor-wake" in c for c in rows), "the urgent-mail push tier went with it"
    assert any("# someone-elses-hook" in c for c in rows)


def test_a_single_marker_selection_does_not_fire_the_multi_hook_caution(tmp_path: Path) -> None:
    """A warning that fires when nothing is wrong trains the operator to skip it."""
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0
    r = _install(settings, "-Script", "seat-record", "-Uninstall")
    assert not re.search(r"REMOVING \d+ ROW\(S\) ACROSS", r.stdout), r.stdout
    inventory = [ln for ln in r.stdout.splitlines() if "->" in ln]
    assert len(inventory) == 1, inventory
    assert "seat-record.ps1" in inventory[0]


def test_a_removal_names_every_row_it_removed(tmp_path: Path) -> None:
    """The inventory used to be gated on ``-not $Uninstall``.

    So a removal reported only that something had been removed and from how many roots -- never
    WHICH rows. Asserting on 'REMOVED' plus a root count would pass against that version, so the
    assertion is that every removed row's MARKER appears in stdout.
    """
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0
    r = _install(settings, "-Uninstall")
    assert r.returncode == 0
    assert "REMOVED " in r.stdout
    for marker in MARKERS:
        assert f"[{marker}]" in r.stdout, (marker, r.stdout)
    for script in (
        "session-context.ps1",
        "collision_gate.ps1",
        "announce-session.ps1",
        "mail-drain.ps1",
        "seat-record.ps1",
        "mail-watch.ps1",
    ):
        assert script in r.stdout, script


def test_seat_shim_ends_with_exit_zero_and_exits_zero_outside_a_repo(tmp_path: Path) -> None:
    """This entry is user-global and fires at every turn end in every project on the machine.

    Outside a repo the guard is false, nothing in the body runs, and the last thing the shim
    executed is a FAILED ``git rev-parse`` -- so ``pwsh -Command`` exits 1 with an EMPTY stderr,
    git's message having been eaten by ``2>$null``. A hook that cries wolf at every turn end in
    every folder on the box trains the reader to skip the whole Stop channel.
    """
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0
    cmd = _marker_command(settings, "mefor-seat")
    assert cmd.rstrip().endswith("exit 0"), repr(cmd[-60:])

    nongit = tmp_path / "nongit"
    nongit.mkdir()
    # THE CONTROL, IN THE SAME RUN: without it this asserts nothing, because a cwd that happened to
    # be a checkout would take the other branch entirely.
    assert _git_rc(nongit, "rev-parse", "--git-common-dir") != 0, "cwd is a repo; test is vacuous"

    r = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", cmd],
        cwd=str(nongit),
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=120,
    )
    assert r.returncode == 0, (r.returncode, r.stdout, r.stderr)
    assert r.stdout.strip() == "", r.stdout


def test_seat_shim_swallows_a_failing_target_and_the_wake_shim_does_not(tmp_path: Path) -> None:
    """The asymmetry is deliberate and both halves must be pinned together.

    For the WAKE row the exit code IS the payload -- a rewake fires on 2 and only on 2 -- so that
    builder forwards it. The seat row's target disclaims the exit code entirely and reports trouble
    through seats/.writer-errors.txt instead, so its trailing ``exit 0`` is blanket by design. If it
    were ever silently converted to the wake shim's propagating form, a future seat-record failure
    would surface as a failed Stop hook. The wake case is the instrument control: a harness that
    cannot observe a non-zero exit at all would otherwise pass both halves.
    """
    settings = _settings_fixture(tmp_path)
    assert _install(settings).returncode == 0

    rig = _init_repo(tmp_path / "rigged")
    (rig / "scripts" / "coord").mkdir(parents=True)
    (rig / "scripts" / "coord" / "presence.ps1").write_text("# marker\n", encoding="utf-8")
    (rig / "scripts" / "hooks").mkdir(parents=True)
    (rig / "scripts" / "hooks" / "seat-record.ps1").write_text("exit 3\n", encoding="utf-8")
    (rig / "scripts" / "hooks" / "mail-watch.ps1").write_text("exit 3\n", encoding="utf-8")

    def run(marker: str) -> int:
        return subprocess.run(
            ["pwsh", "-NoProfile", "-Command", _marker_command(settings, marker)],
            cwd=str(rig),
            capture_output=True,
            text=True,
            stdin=subprocess.DEVNULL,
            timeout=120,
        ).returncode

    assert run("mefor-wake") == 3, "the control could not observe a non-zero exit at all"
    assert run("mefor-seat") == 0, "the seat shim started propagating its target's exit code"
