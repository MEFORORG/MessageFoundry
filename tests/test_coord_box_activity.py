# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two staleness signals that are really one, and the third that is not.

Readers across this repo treat ``seats/.writer-alive/<box>.txt`` and the seat record's ``asOf`` as
independent corroboration. They are one signal read twice: ``seat.ps1`` writes both inside a single
``-Record``, the heartbeat at its rule 3 touch and ``asOf`` in the record body.

Measured 2026-08-22 across every box on disk: **the two agree to the second in 42 of 42.**

That is not a curiosity. ``seat.ps1``'s own rule 3 records why the heartbeat exists at all -- hooks
are disabled silently by ``disableAllHooks``, by org policy and by workspace trust, and all three
produce exactly the observable of a quiet, healthy fleet. When the writer is not running, both
signals go stale together and a sweep reading them concludes the seat is dead while somebody is
still typing in it.

So ``box-activity.ps1`` adds a signal ``seat.ps1`` does not write: the newest transcript under
``<config-root>/projects/<slug>/``, which Claude Code writes every turn. Measured the same day,
``messagefoundry-096b5d29`` had a transcript 31.50h old against a ``.writer-alive`` 0.14h old -- the
two disagreeing by 31.4 hours, on a real box, on the day this was written.

**Every veto test here is a PAIR.** Asserting only that a fresh transcript vetoes would pass against
a function that always vetoes, which is the safest possible wrong answer and the one that would make
the whole mechanism useless without failing anything. The second half of each pair back-dates the
signal and asserts the veto lifts.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
LIB = (
    "box-activity.ps1",
    "session-registry.ps1",
    "occupancy.ps1",
    "mail-key.ps1",
    "coord-root.ps1",
)
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="box-activity.ps1 needs pwsh on Windows",
)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Scripts, a seats dir, a config root and a git worktree -- none of them the real ones.

    test_coord_seat_prompt.py records why this matters: two stray claims once landed in the live
    registry because a test ran against the live tree.
    """
    box = tmp_path / "scripts" / "coord"
    box.mkdir(parents=True)
    for name in LIB:
        shutil.copy2(COORD / name, box / name)
    (tmp_path / "seats" / ".writer-alive").mkdir(parents=True)
    wt = tmp_path / "wt"
    wt.mkdir()
    subprocess.run(["git", "init", "-q", "-b", "main", str(wt)], check=True, capture_output=True)
    # A legacy seat record (no `host`), which every reader takes as this machine's. The box's local
    # probes are only this PC's to read when the seat is this PC's.
    write_seat_record(tmp_path, host=None)
    return tmp_path


def write_seat_record(sandbox: Path, host: str | None, box: str = "demo-box-0000") -> None:
    d = sandbox / "seats" / box
    d.mkdir(parents=True, exist_ok=True)
    rec: dict[str, object] = {"worktree": str(sandbox / "wt"), "seat": "builder"}
    if host is not None:
        rec["host"] = host
    (d / "s1.json").write_text(json.dumps(rec), encoding="utf-8")


def this_host() -> str:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", "[Environment]::MachineName"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=True,
    )
    return proc.stdout.strip()


def activity(sandbox: Path, **over: object) -> dict:
    """Call Get-BoxActivity and read back its object as JSON."""
    args = {
        "BoxKey": "demo-box-0000",
        "WorktreePath": str(sandbox / "wt"),
        "SeatsDir": str(sandbox / "seats"),
        "ConfigRoot": str(sandbox / "root"),
        "RepoHint": str(sandbox / "wt"),
    }
    args.update({k: str(v) for k, v in over.items()})
    ps = (
        f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
        + "Get-BoxActivity "
        + " ".join(f"-{k} '{v}'" for k, v in args.items())
        + " | ConvertTo-Json -Depth 5"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, f"rc={proc.returncode}\n{proc.stdout}\n{proc.stderr}"
    return json.loads(proc.stdout)


def write_heartbeat(sandbox: Path, age_hours: float, box: str = "demo-box-0000") -> None:
    f = sandbox / "seats" / ".writer-alive" / f"{box}.txt"
    f.write_text("stamp", encoding="utf-8")
    _back_date(f, age_hours)


def write_transcript(sandbox: Path, age_hours: float) -> None:
    slug = str(sandbox / "wt")
    for ch in ":\\/.":
        slug = slug.replace(ch, "-")
    d = sandbox / "root" / "projects" / slug
    d.mkdir(parents=True, exist_ok=True)
    f = d / "turn.jsonl"
    f.write_text('{"t":1}\n', encoding="utf-8")
    _back_date(f, age_hours)


def _back_date(path: Path, age_hours: float) -> None:
    import time

    when = time.time() - age_hours * 3600
    os.utime(path, (when, when))


class TestTheIndependentSignalWins:
    def test_a_fresh_transcript_vetoes_a_stale_writer_alive(self, sandbox: Path) -> None:
        """The hooks-disabled case. Reproduces the 31.4-hour disagreement measured on a live box."""
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=0.02)
        a = activity(sandbox)
        assert a["Veto"] is True, a
        assert a["TranscriptAgeH"] < 1
        assert a["WriterAliveAgeH"] > 24
        assert any("transcript" in w for w in a["Why"]), a["Why"]

    def test_and_it_does_not_veto_once_the_transcript_is_stale_too(self, sandbox: Path) -> None:
        """THE OTHER HALF OF THE PAIR.

        Without this, the test above passes against a function that returns True unconditionally --
        the safest wrong answer, and the one that would silently make the mechanism useless.
        """
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["Veto"] is False, a
        assert a["Why"] == [], a["Why"]

    def test_a_fresh_heartbeat_still_vetoes_on_its_own(self, sandbox: Path) -> None:
        """Adding a signal must not remove one. The heartbeat is weaker, not discarded."""
        write_heartbeat(sandbox, age_hours=0.1)
        write_transcript(sandbox, age_hours=48)
        assert activity(sandbox)["Veto"] is True


class TestTheSignalCountIsHonest:
    def test_writer_alive_is_counted_once_not_twice_with_seat_asof(self, sandbox: Path) -> None:
        """42 of 42 boxes had `.writer-alive` and seat `asOf` equal to the second.

        The function returns no `asOf` accessor at all, so a caller cannot inflate the count by
        reading one clock twice. Heartbeat plus worktree is two, and that is the whole of it.
        """
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["Signals"] == 2, a  # heartbeat + worktree; no transcript written
        assert "AsOf" not in a and "SeatAsOf" not in a

    def test_missing_everything_reports_unevaluable_not_dead(self, sandbox: Path) -> None:
        """`Signals` below two must not read as permission. An unevaluated fence is not a passed one."""
        a = activity(sandbox, WorktreePath=str(sandbox / "nope"), RepoHint=str(sandbox / "nope"))
        assert a["Signals"] < 2, a
        assert a["Evaluable"] is False, a
        assert a["Veto"] is False, "no veto and not evaluable are DIFFERENT answers"

    def test_a_present_worktree_is_a_signal_and_a_veto_is_not_implied_by_it(
        self, sandbox: Path
    ) -> None:
        """Existing is evidence the box is real, not evidence anyone is in it."""
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["WorktreeExists"] is True
        assert a["Signals"] == 3
        assert a["Veto"] is False


class TestLocalProbesOnlyCountForThisPcsSeat:
    """`.writer-alive` lives on the SHARED root; the transcript, the session registry and the worktree
    list are this PC's own disk. Pairing them for a seat on another PC counts an absence this PC could
    never have seen as evidence. BACKLOG #5596."""

    def test_a_seat_on_another_pc_is_not_evaluable_from_here(self, sandbox: Path) -> None:
        """Old code: heartbeat + this PC's worktree list = 2 signals, Evaluable, no veto -- safe to
        disturb a seat it cannot observe."""
        write_seat_record(sandbox, host="ANOTHER-PC-0001")
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["HostHere"] is False, a
        assert a["Signals"] == 1, a
        assert a["Evaluable"] is False, a

    def test_a_seat_naming_this_pc_still_counts_its_local_probes(self, sandbox: Path) -> None:
        """The other half of the pair: a refusal that fired for every host would pass the test above."""
        write_seat_record(sandbox, host=this_host())
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["HostHere"] is True, a
        assert a["Signals"] == 2, a
        assert a["Evaluable"] is True, a

    def test_a_box_with_no_seat_record_names_no_host_and_is_not_evaluable(
        self, sandbox: Path
    ) -> None:
        """No record, no host: this PC cannot tell whether the box is its own."""
        shutil.rmtree(sandbox / "seats" / "demo-box-0000")
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["HostHere"] is False, a
        assert a["Evaluable"] is False, a

    def test_a_fresh_local_transcript_still_vetoes_a_box_with_no_host(self, sandbox: Path) -> None:
        """Not-here stops the local probes COUNTING, never vetoing: a seat that launched before its
        record was written is still seen by its transcript."""
        shutil.rmtree(sandbox / "seats" / "demo-box-0000")
        write_transcript(sandbox, age_hours=0.02)
        a = activity(sandbox)
        assert a["HostHere"] is False, a
        assert a["Veto"] is True, a
        assert a["Evaluable"] is False, a

    def test_a_newest_record_that_is_not_an_object_names_no_host(self, sandbox: Path) -> None:
        """A JSON array is not a seat record. ConvertFrom-Json unrolls a one-element array, so
        without -NoEnumerate its element, which names no host, read as a legacy (this-PC) record."""
        (sandbox / "seats" / "demo-box-0000" / "s1.json").write_text(
            '[{"seat": "builder"}]', encoding="utf-8"
        )
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["HostHere"] is False, a
        assert a["WorktreeExists"] is None, a

    def test_an_empty_explicit_record_host_names_nobody(self, sandbox: Path) -> None:
        """A caller forwarding a missing record's host binds ''; that is not a legacy record."""
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox, RecordHost="")
        assert a["HostHere"] is False, a
        assert a["Evaluable"] is False, a

    def test_an_explicit_record_host_wins_over_the_seat_record(self, sandbox: Path) -> None:
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox, RecordHost="ANOTHER-PC-0001")
        assert a["HostHere"] is False, a
        assert a["Evaluable"] is False, a


class TestAnAbsentRegistryIsNotAnEvaluatedFence:
    """BACKLOG #5596: Get-SessionLiveness answers UNKNOWN both for "the registry has no such record"
    and for "there is no registry to look in" or "the record cannot be parsed yet". Only the first is
    the fence looking."""

    def test_no_registry_at_all_is_not_counted(self, sandbox: Path) -> None:
        """Config root with no sessions/ directory. Old code: fence=UNKNOWN counted, Signals 2."""
        (sandbox / "root").mkdir(exist_ok=True)
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox, SessionId="abcd1234")
        assert a["FenceState"] == "NO-REGISTRY", a
        assert a["Signals"] == 3, a  # heartbeat + transcript + worktree, no fence

    def test_a_registry_without_the_record_is_counted(self, sandbox: Path) -> None:
        """The negative control: a readable registry that holds no such id IS the fence looking."""
        sessions = sandbox / "root" / "sessions"
        sessions.mkdir(parents=True)
        (sessions / "1.json").write_text(
            json.dumps({"pid": 1, "sessionId": "ffff0000", "startedAt": 0}), encoding="utf-8"
        )
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox, SessionId="abcd1234")
        assert a["FenceState"] == "UNKNOWN", a
        assert a["Signals"] == 4, a
        assert a["Veto"] is False, a

    def test_a_fresh_unreadable_record_vetoes(self, sandbox: Path) -> None:
        """A record caught mid-write fails to parse and was dropped, so a session launching right now
        read as no record at all. Old code: UNKNOWN, counted, no veto."""
        sessions = sandbox / "root" / "sessions"
        sessions.mkdir(parents=True)
        (sessions / "2.json").write_text('{"pid": 2, "sessionId": "abcd', encoding="utf-8")
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox, SessionId="abcd1234")
        assert a["FenceState"] == "UNPARSED-REGISTRY", a
        assert a["Veto"] is True, a
        assert any("UNPARSED-REGISTRY" in w for w in a["Why"]), a["Why"]

    def test_an_old_unreadable_record_does_not_veto_but_is_not_counted(self, sandbox: Path) -> None:
        """A record that has been unparseable for days is not a session launching now."""
        sessions = sandbox / "root" / "sessions"
        sessions.mkdir(parents=True)
        bad = sessions / "2.json"
        bad.write_text('{"pid": 2, "sessionId": "abcd', encoding="utf-8")
        _back_date(bad, 48)
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox, SessionId="abcd1234")
        assert a["Veto"] is False, a
        assert a["Signals"] == 3, a


class TestTheFailOpenOutcomesThePreFixCodeGave:
    """BACKLOG #5596, asserted on the outcome alone.

    Several tests in the two classes above assert `HostHere` or a fence state name the fix added
    before they reach the outcome, so against the pre-fix function they stop on a missing key or a
    renamed state rather than on the defect. These pass only the parameters and read only the fields
    `Get-BoxActivity` had before the fix (`Signals`, `Evaluable`, `Veto`, `FenceVeto`), so against
    the pre-fix function each fails on the fail-open answer itself: a seat on another PC counted as
    evaluable, an absent registry counted as an evaluated fence, and a fresh half-written registry
    record that did not veto.
    """

    def test_a_seat_on_another_pc_with_a_stale_heartbeat_is_not_evaluable(
        self, sandbox: Path
    ) -> None:
        """Pre-fix: the shared heartbeat plus this PC's worktree list made Signals 2, Evaluable,
        no veto -- a seat on another PC judged safe to disturb from probes that cannot see it."""
        write_seat_record(sandbox, host="ANOTHER-PC-0001")
        write_heartbeat(sandbox, age_hours=48)
        a = activity(sandbox)
        assert a["Veto"] is False, a
        assert a["Signals"] == 1, a  # the shared heartbeat only
        assert a["Evaluable"] is False, a

    def test_no_registry_is_not_counted_as_the_fence_looking(self, sandbox: Path) -> None:
        """Pre-fix: a config root with no sessions/ directory answered UNKNOWN, counted as an
        evaluated fence, so it and the heartbeat made Signals 2 and an evaluable no-veto result."""
        (sandbox / "root").mkdir(exist_ok=True)
        write_heartbeat(sandbox, age_hours=48)
        nope = str(sandbox / "nope")
        a = activity(sandbox, SessionId="abcd1234", WorktreePath=nope, RepoHint=nope)
        assert a["FenceVeto"] is False, a
        assert a["Veto"] is False, a
        assert a["Signals"] == 1, a  # the heartbeat only; no registry, so no fence
        assert a["Evaluable"] is False, a

    def test_a_fresh_unreadable_registry_record_vetoes(self, sandbox: Path) -> None:
        """Pre-fix: a registry record caught mid-write was dropped, so a session launching right now
        read as no record, counted, and did not veto. The aged twin is
        `test_an_old_unreadable_record_does_not_veto_but_is_not_counted` above."""
        sessions = sandbox / "root" / "sessions"
        sessions.mkdir(parents=True)
        (sessions / "2.json").write_text('{"pid": 2, "sessionId": "abcd', encoding="utf-8")
        write_heartbeat(sandbox, age_hours=48)
        write_transcript(sandbox, age_hours=48)
        a = activity(sandbox, SessionId="abcd1234")
        assert a["FenceVeto"] is True, a
        assert a["Veto"] is True, a
        assert a["Signals"] == 3, a  # heartbeat + transcript + worktree; the fence is not counted


class TestTheTranscriptSlug:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            (
                r"D:\proj\App\.claude\worktrees\demo-1234",
                "D--proj-App--claude-worktrees-demo-1234",
            ),
            (r"D:\proj\App", "D--proj-App"),
            (r"D:\a.b\c", "D--a-b-c"),
            ("", ""),
        ],
    )
    def test_slug_matches_the_directory_claude_code_actually_writes(
        self, sandbox: Path, path: str, expected: str
    ) -> None:
        """Shape verified against the real tree; the rows here are neutral paths on purpose.

        A real home path carries the OS account name, which the forbidden-content gate blocks, and
        it blocked exactly these rows on the first commit attempt. The first row is the live shape
        with the drive and user segments swapped out.

        The doubled separators look like a bug and are not. `D:` and `\\` both map, giving `D--`;
        `\\.claude` is a separator followed by a dot, giving `--claude`.
        """
        ps = (
            f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
            f"ConvertTo-TranscriptSlug -Path '{path}'"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == expected


class TestTheLibraryHasNoSideEffects:
    def test_dot_sourcing_does_not_change_the_callers_strict_mode(self, sandbox: Path) -> None:
        """A dot-sourced file sets StrictMode in its CALLER, and none of its siblings do.

        Caught by breaking a caller: an early draft set `Set-StrictMode -Version Latest`, and the
        harness that loaded it started failing on `$LASTEXITCODE` being unset. A library whose
        synopsis says "defines functions, does nothing" must not re-strictify every script that
        loads it.
        """
        ps = (
            f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
            "if ($null -eq (Get-Variable -Name nope-not-set -EA SilentlyContinue)) { 'lenient' }"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "lenient" in proc.stdout


class TestTheProfileIsReadByItsOwnName:
    """Vault BACKLOG #2985, added item 2. With no -ConfigRoot, Get-TranscriptAgeHours listed
    USERPROFILE with -Path, which reads its argument as a wildcard pattern: a profile named home[1]
    matched only a folder named home1, so the transcript was never found and the signal read as
    UNEVALUABLE. Red before the fix: the bracketed case returned null."""

    def _age(self, sandbox: Path, home: Path | None) -> str:
        env = {k: v for k, v in os.environ.items() if k.upper() != "USERPROFILE"}
        if home is not None:
            env["USERPROFILE"] = str(home)
        ps = (
            f". '{sandbox / 'scripts' / 'coord' / 'box-activity.ps1'}'; "
            "$a = Get-TranscriptAgeHours -WorktreePath 'D:\\proj\\App'; "
            "if ($null -eq $a) { 'null' } else { [string]$a }"
        )
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
            env=env,
            cwd=str(sandbox),
        )
        assert proc.returncode == 0 and not proc.stderr.strip(), proc.stderr
        return proc.stdout.strip()

    @pytest.mark.parametrize("home_name", ["home", "home[1]"])
    def test_a_transcript_under_the_profile_is_found(self, sandbox: Path, home_name: str) -> None:
        d = sandbox / home_name / ".claude" / "projects" / "D--proj-App"
        d.mkdir(parents=True)
        f = d / "turn.jsonl"
        f.write_text('{"t":1}\n', encoding="utf-8")
        _back_date(f, 5)
        assert float(self._age(sandbox, sandbox / home_name)) == pytest.approx(5, abs=0.1)

    def test_an_unset_profile_names_no_root(self, sandbox: Path) -> None:
        """No profile reads as UNEVALUABLE, not as a throw, and not as the current directory."""
        d = sandbox / ".claude" / "projects" / "D--proj-App"
        d.mkdir(parents=True)
        (d / "turn.jsonl").write_text('{"t":1}\n', encoding="utf-8")
        assert self._age(sandbox, None) == "null"
