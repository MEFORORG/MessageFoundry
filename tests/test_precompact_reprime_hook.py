# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The compaction reprime hook must actually reach context, and nothing checked that it ever did.

WHY THIS FILE EXISTS. `scripts/hooks/precompact-reprime.ps1` shipped registered on `PreCompact` and
emitting `{"hookSpecificOutput":{"hookEventName":"PreCompact",...}}`. The harness rejected that
payload on every single fire:

    Hook JSON output validation failed - hookSpecificOutput.hookEventName:
    expected one of "PreToolUse" | "UserPromptSubmit" | "UserPromptExpansion" |
    "SessionStart" | "Setup" | "PreModelSwitch" | ...

Measured live 2026-09-15. `PreCompact` is a real EVENT and is not an accepted
`hookSpecificOutput.hookEventName`, so the reprime text never landed once. The hook was wired, it
ran, it exited 0, and it put nothing back.

NOTHING COULD SEE IT, AND THAT IS THE ACTUAL DEFECT. Before this file, `grep -ri precompact` over the
whole repository returned exactly two paths: the script and `.claude/settings.json`. The script's own
header said "WIRING IS NOT ASSERTED HERE ON PURPOSE", which was true and was read as "not asserted".
A hook that fires and is ignored is indistinguishable from a hook that fires and has nothing to say,
so the only way to tell them apart is to drive the script and read what comes out.

THE SHAPE IS NOT HYPOTHETICAL AND IT RECURRED WHILE THIS FILE WAS BEING WRITTEN. A refactor deleted a
function the script still called; the call threw, the script's own outer handler swallowed it, and
the hook exited 0 in perfect silence. `test_the_output_is_plain_text_and_not_a_rejected_envelope` is
what fails on that, and it fails because it asserts on OUTPUT rather than on exit status.

WHAT IS PINNED, and each is a POSTCONDITION -- the real script is run and its actual output read,
never a re-prediction of what the source ought to print:

  * the payload is plain text, not a hook-output envelope naming an event the harness refuses;
  * it is wired on an event whose exit-0 stdout the vendor documents as reaching context;
  * it speaks on a compaction restart and stays quiet on every other start, which are two arms that
    control each other -- a hook that never spoke would fail the first, and a hook whose scope guard
    was deleted would fail the second;
  * it fails OPEN on an unreadable payload, and DEGRADES rather than dying when a shared library it
    reads is absent, because going silently dead is the fault above;
  * the age it reports is never negative.

Every absence assertion here is paired with a planted positive control, because a detector that
returns nothing over a correct tree is the same observation as a detector that is broken.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
HOOK = _ROOT / "scripts" / "hooks" / "precompact-reprime.ps1"
_SEAT = _ROOT / "scripts" / "coord" / "seat.ps1"
_SETTINGS = _ROOT / ".claude" / "settings.json"
PWSH = shutil.which("pwsh") or shutil.which("powershell")

# The `tooling` marker is NOT written here. tests/conftest.py applies it from
# tests/tooling_manifest.txt, so that one reviewed list is the single definition of the tier.
pytestmark = pytest.mark.skipif(PWSH is None, reason="PowerShell is not on PATH")

_BRANCH = "reprime-fixture"

# The payload a compaction restart delivers. One constant rather than nine copies, so the three
# tests that deliberately vary it read as different at a glance.
_COMPACT_RESTART: dict[str, object] = {"source": "compact", "hook_event_name": "SessionStart"}

# THE EVENTS WHOSE EXIT-0 STDOUT IS ADDED TO CONTEXT, transcribed from the hooks reference:
#
#   "For `UserPromptSubmit`, `UserPromptExpansion`, `SessionStart`, and `PostModelSwitch` hooks,
#    Claude Code adds stdout it treats as plain text to Claude's context."
#
# This is a quoted list from the document that defines it, not an inventory somebody assembled, so
# enumerating it here does not make the completeness claim SDS-3.6 warns about. `PreCompact` is
# absent from it, and the reference documents no context-injection schema for `PreCompact` at all.
#
# `Stop` IS ABSENT AND THAT IS AN OPEN QUESTION, recorded rather than quietly decided. The reference
# does not list it here, while `scripts/hooks/seat-record.ps1` states in its own header that Stop
# output is shown to the model and relies on plain stdout for a diagnostic. Both cannot be right.
# Nothing in this module turns on the answer -- the hook under test is wired on SessionStart, which
# is listed -- so the set stays as quoted and the discrepancy is somebody's follow-up, not a guess
# made here.
_STDOUT_REACHES_CONTEXT = frozenset(
    {"UserPromptSubmit", "UserPromptExpansion", "SessionStart", "PostModelSwitch"}
)

# The exact payload the script used to emit. Kept verbatim as the planted defect for the controls
# below: a detector that cannot find the bug that actually shipped is not protecting anything.
_REJECTED_PAYLOAD = json.dumps(
    {"hookSpecificOutput": {"hookEventName": "PreCompact", "additionalContext": "seat: builder"}}
)

_EVENT_NAME_ASSIGNMENT = re.compile(r"hookEventName\s*=\s*'([^']*)'")
_AGE_LINE = re.compile(r"declared at (\S+) \(([^)]*)\)")


# --------------------------------------------------------------------------- driving the script


@dataclass(frozen=True)
class Worktree:
    """A throwaway git worktree, with the two paths the hook derives cached once.

    Both are constant for the life of the repository and each costs a process spawn, so resolving
    them per call made the suite shell out to git dozens of times for the same two strings.
    """

    path: Path
    top: str
    common: Path


def _git(cwd: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True, text=True, timeout=120, check=True
    )
    return proc.stdout.strip()


@pytest.fixture
def repo(tmp_path: Path) -> Worktree:
    """A real git worktree with one commit, which is what the hook reads its facts out of.

    The commit is not decoration: the hook asks `git rev-list --count HEAD`, which fails on a
    repository with no commits. `--allow-empty` buys that for one spawn, with no file to write and
    nothing to stage, and `-c` supplies the identity without two more `git config` calls.
    """
    root = tmp_path / "wt"
    root.mkdir()
    _git(root, "init", "-b", _BRANCH)
    _git(
        root,
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "user.name=Fixture",
        "commit",
        "--allow-empty",
        "-m",
        "fixture",
    )
    return Worktree(
        path=root,
        top=_git(root, "rev-parse", "--path-format=absolute", "--show-toplevel"),
        common=Path(_git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")),
    )


def run_hook(repo: Worktree, payload: dict[str, object] | None, script: Path = HOOK) -> str:
    """Run the hook inside `repo` with `payload` on stdin, and return its raw stdout.

    `payload=None` sends an empty stdin, which is the shape a caller that pipes nothing produces.
    `script` is varied by exactly one test, which runs a COPY planted where the shared library the
    hook dot-sources cannot be reached.
    """
    assert PWSH is not None  # the module-level skipif guarantees this at runtime
    proc = subprocess.run(
        [PWSH, "-NoProfile", "-File", str(script)],
        input="" if payload is None else json.dumps(payload),
        capture_output=True,
        text=True,
        cwd=repo.path,
        timeout=180,
    )
    # Never failing the turn is a hard property of this hook, asserted on every call rather than
    # once, so no arm below can pass while the script is crashing on that input.
    assert proc.returncode == 0, f"hook exited {proc.returncode}: {proc.stderr}"
    return proc.stdout


def _declaration(
    repo: Worktree,
    *,
    goal: str = "fix the reprime hook",
    branch: str = _BRANCH,
    declared_at: datetime | None = None,
) -> None:
    """Write a declaration for `repo` in the shape `scripts/coord/seat.ps1` writes.

    `declaredAt` is stored as UTC with a trailing `Z`, which is what seat.ps1 emits and what the age
    arithmetic has to survive. The hand-built record is what lets the clock arms below choose an
    age; `test_the_hook_reads_the_record_seat_ps1_actually_writes` is the arm that checks this shape
    against the real writer rather than against itself.
    """
    when = declared_at or (datetime.now(UTC) - timedelta(hours=3))
    seat_dir = repo.common / "mefor-coord" / "seats" / "box"
    seat_dir.mkdir(parents=True, exist_ok=True)
    (seat_dir / "declared.json").write_text(
        json.dumps(
            {
                "seat": "builder",
                "goal": goal,
                "branch": branch,
                "declaredAt": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "worktree": repo.top,
            }
        ),
        encoding="utf-8",
    )


def _age_line(out: str) -> tuple[str, str]:
    """The reported timestamp and age text, or a failure naming what was actually printed."""
    found = _AGE_LINE.search(out)
    assert found is not None, f"no 'declared at ... (...)' line was reported at all: {out}"
    return found.group(1), found.group(2)


# ------------------------------------------------------------------- the payload the harness takes


def _hook_envelope_event(stdout: str) -> str | None:
    """The `hookSpecificOutput.hookEventName` in `stdout`, or None if it is not such an envelope."""
    try:
        parsed = json.loads(stdout)
    except ValueError:
        return None
    if not isinstance(parsed, dict):
        return None
    specific = parsed.get("hookSpecificOutput")
    if not isinstance(specific, dict):
        return None
    name = specific.get("hookEventName")
    return name if isinstance(name, str) else None


def test_the_output_is_plain_text_and_not_a_rejected_envelope(repo: Worktree) -> None:
    """The regression itself, read off the script's actual stdout.

    Asserting "not an envelope" rather than "the event name is in some accepted set" is deliberate.
    The accepted set was only ever observed TRUNCATED, in an error message ending in `| ...`, so any
    list of it written here would be a completeness claim nobody can stand behind. What this hook
    decided instead is checkable with no such list: it emits plain text.

    The non-empty assertion is the one that earns its keep twice. It caught the original defect, and
    it caught a refactor that left the script calling a function that no longer existed.
    """
    _declaration(repo)
    out = run_hook(repo, _COMPACT_RESTART)

    assert out.strip(), "the hook said nothing on a compaction restart; that is the whole defect"
    event = _hook_envelope_event(out)
    assert event is None, (
        f"the hook emitted a hook-output envelope naming {event!r}. Exit-0 stdout is added to "
        "context as PLAIN TEXT for the events that support it, and an envelope naming an event the "
        "harness does not accept is rejected wholesale -- which is how this hook spent its entire "
        "life putting nothing back."
    )


def test_the_envelope_detector_can_actually_fail() -> None:
    """The positive control for the check above.

    Run against the exact payload that shipped. A detector that returns None here cannot see the bug
    it was written for, and the assertion above is passing over a correct file for the wrong reason.
    """
    assert _hook_envelope_event(_REJECTED_PAYLOAD) == "PreCompact"


def test_the_source_names_no_hook_event_at_all() -> None:
    """Grep for the one edit that would put the rejected envelope back.

    The behavioural test above catches the current script, and it cannot see INTENT. The tempting
    change here is small and looks like a fix -- re-adding `hookEventName` with `SessionStart` in it,
    now that the event is right. That would still be wrong: this hook is wired alongside others on
    the same event, and an envelope replaces the plain-text path rather than adding to it.
    """
    names = _EVENT_NAME_ASSIGNMENT.findall(HOOK.read_text(encoding="utf-8"))
    assert not names, f"the script assigns hookEventName again: {names}"


def test_the_source_grep_can_actually_fail(tmp_path: Path) -> None:
    """Positive control for the grep above, against the assignment that shipped."""
    planted = tmp_path / "planted.ps1"
    planted.write_text("    hookEventName     = 'PreCompact'\n", encoding="utf-8")
    assert _EVENT_NAME_ASSIGNMENT.findall(planted.read_text(encoding="utf-8")) == ["PreCompact"]


# ------------------------------------------------------------------------------------ the wiring


def _events_wiring_the_hook() -> list[str]:
    """Every settings.json hook event whose handler list references this script."""
    settings = json.loads(_SETTINGS.read_text(encoding="utf-8"))
    return [
        event
        for event, groups in settings.get("hooks", {}).items()
        for group in groups
        for handler in group.get("hooks", [])
        for token in [handler.get("command", ""), *handler.get("args", [])]
        if isinstance(token, str) and HOOK.name in token
    ]


def test_the_hook_is_wired_on_an_event_whose_stdout_reaches_context() -> None:
    """Being wired is not the property that matters; being wired somewhere the output LANDS is.

    This is deliberately not an assertion that `PreCompact` is absent from the file. A leftover
    registration on an event that cannot carry stdout is harmless once the script keeps quiet there,
    and `test_a_leftover_registration_on_another_event_stays_quiet` is what pins that. Asserting the
    file's shape instead of the behaviour would fail for a reason nobody has to care about.
    """
    events = _events_wiring_the_hook()
    assert events, f"{HOOK.name} is referenced by no hook handler in {_SETTINGS}"
    assert set(events) & _STDOUT_REACHES_CONTEXT, (
        f"{HOOK.name} is wired only on {sorted(set(events))}, and none of those events add exit-0 "
        f"stdout to context. The documented set is {sorted(_STDOUT_REACHES_CONTEXT)}. A hook wired "
        "outside it runs, exits 0, and is discarded -- with no error anywhere."
    )


def test_precompact_is_not_an_event_that_can_carry_this_output() -> None:
    """The fact the whole change turns on, stated once so a future edit cannot quietly assume it.

    Without this, widening the set to include `PreCompact` would let the wiring test above pass over
    a PreCompact-only registration, which is the exact arrangement that shipped.
    """
    assert "PreCompact" not in _STDOUT_REACHES_CONTEXT


# ------------------------------------------------------------------------------------- the scope


def test_a_compaction_restart_restores_the_seat_and_goal(repo: Worktree) -> None:
    _declaration(repo, goal="fix the reprime hook")
    out = run_hook(repo, _COMPACT_RESTART)

    assert "SEAT: builder" in out, f"the seat was not restored: {out}"
    assert "GOAL: fix the reprime hook" in out, f"the goal was not restored: {out}"


def test_every_other_kind_of_start_says_nothing(repo: Worktree) -> None:
    """The other arm of the discriminating pair.

    Together with the test above this separates a working scope guard from both failure shapes: a
    hook that says nothing ever passes this one and fails that one, and a hook with no guard at all
    passes that one and fails this one. Neither test is worth much alone.

    `fork` is here because the guard's property is "not a compaction", not "one of the three starts
    somebody listed" -- a list of the others is one short the day the harness adds another source.
    """
    _declaration(repo)
    for source in ("startup", "resume", "clear", "fork"):
        out = run_hook(repo, {"source": source, "hook_event_name": "SessionStart"})
        assert out == "", f"the hook spoke on a {source} start, which seat-declare-prompt.ps1 owns"


def test_a_leftover_registration_on_another_event_stays_quiet(repo: Worktree) -> None:
    """A PreCompact payload carries no `source`, so the event name is what has to stop it."""
    _declaration(repo)
    out = run_hook(repo, {"hook_event_name": "PreCompact", "trigger": "auto"})
    assert out == "", f"the hook spoke on PreCompact, where its stdout is discarded: {out}"


@pytest.mark.parametrize(
    ("payload", "why"),
    [
        (None, "nothing on stdin at all"),
        ({}, "a payload naming neither the source nor the event"),
        ({"source": "", "hook_event_name": ""}, "both discriminators present and empty"),
    ],
    ids=["no-stdin", "empty-object", "empty-strings"],
)
def test_an_unreadable_payload_fails_open(
    repo: Worktree, payload: dict[str, object] | None, why: str
) -> None:
    """Silence must be a DECISION the hook can defend, never the residue of a failed read.

    The guard goes quiet only when it can positively read a payload saying this is not a compaction.
    A hook that says something unnecessary is a nuisance somebody notices; a hook that silently says
    nothing is the defect this whole module exists to catch.
    """
    _declaration(repo)
    out = run_hook(repo, payload)
    assert out.strip(), f"the hook went silent on {why}, which is the fail-CLOSED direction"


def test_a_missing_shared_library_costs_the_age_and_not_the_reprime(
    repo: Worktree, tmp_path: Path
) -> None:
    """The hook dot-sources `coord/config-roots.ps1` for its UTC helper. A checkout without it must
    still restore the seat, the goal and any held ledger numbers.

    THIS IS NOT A THEORETICAL ARM. Exactly this shape fired while the hook was being written: the
    call to the shared helper threw, the script's outer handler swallowed it, and the whole reprime
    vanished in silence. Running a COPY of the script from a directory with no sibling `coord/` is
    what reproduces a missing library without touching the real tree.
    """
    planted = tmp_path / "scripts" / "hooks" / HOOK.name
    planted.parent.mkdir(parents=True)
    shutil.copy2(HOOK, planted)
    assert not (tmp_path / "scripts" / "coord").exists(), "the library must be unreachable"

    _declaration(repo, goal="survive a missing library")
    out = run_hook(repo, _COMPACT_RESTART, script=planted)

    assert "SEAT: builder" in out, f"the seat was lost with the library: {out}"
    assert "GOAL: survive a missing library" in out, f"the goal was lost with the library: {out}"
    assert "declared at" not in out, f"an age was reported with no helper to compute it: {out}"


# ------------------------------------------------------------- the facts it puts back


def test_the_hook_reads_the_record_seat_ps1_actually_writes(repo: Worktree) -> None:
    """The one arm that does not write its own record, so the two halves cannot drift apart.

    Every other test here hand-builds the declaration in the shape the hook expects, which proves
    the reader is self-consistent and nothing about the writer. If `seat.ps1` renamed a field, the
    hook would stop finding declarations and this module would stay green. Driving the real writer
    once closes that: the record under test is the record the fleet actually produces.
    """
    assert PWSH is not None
    declared = subprocess.run(
        [PWSH, "-NoProfile", "-NonInteractive", "-File", str(_SEAT)]
        + ["-Declare", "-Seat", "builder", "-Goal", "written by the real seat.ps1"],
        cwd=repo.path,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert declared.returncode == 0, f"seat.ps1 -Declare failed: {declared.stderr}"

    out = run_hook(repo, _COMPACT_RESTART)
    assert "GOAL: written by the real seat.ps1" in out, (
        f"the hook could not read a record seat.ps1 wrote. The two halves have drifted: {out}"
    )


def test_a_held_ledger_number_is_reported(repo: Worktree) -> None:
    """The one restored fact with a permanent cost attached: an unfiled number burns with the tree."""
    _declaration(repo)
    alloc = repo.common / "mefor-coord" / "alloc"
    alloc.mkdir(parents=True, exist_ok=True)
    (alloc / "a.json").write_text(
        json.dumps(
            {"number": 4242, "kind": "adr", "title": "a held allocation", "worktree": repo.top}
        ),
        encoding="utf-8",
    )

    out = run_hook(repo, _COMPACT_RESTART)
    assert "#4242" in out, f"the held ledger number was not restored: {out}"
    assert "a held allocation" in out, f"the allocation's title was not restored: {out}"


def test_an_undeclared_worktree_says_so_rather_than_nothing(repo: Worktree) -> None:
    """Legible silence. "Never declared" and "declared, then compacted away" have opposite fixes."""
    (repo.common / "mefor-coord").mkdir(parents=True, exist_ok=True)

    out = run_hook(repo, _COMPACT_RESTART)
    assert "not declared" in out, f"an undeclared worktree rendered as blank: {out}"
    assert "seat.ps1 -Declare" in out, "the hook must repeat the command that fixes it"


def test_a_declaration_from_another_branch_is_flagged_rather_than_adopted(repo: Worktree) -> None:
    """A worktree outlives the session that declared in it, and a stale goal reads as authoritative."""
    _declaration(repo, goal="somebody else's work", branch="a-previous-occupant")

    out = run_hook(repo, _COMPACT_RESTART)
    assert "NOT YOURS" in out, f"a previous occupant's goal was restored as current: {out}"
    assert "a-previous-occupant" in out, "the branch that discriminates them must be named"


# ----------------------------------------------------------------------------- the reported age


def test_a_fresh_declaration_is_not_reported_as_negative(repo: Worktree) -> None:
    """A six-minute-old declaration reported "-0.2 days old". Measured 2026-09-15.

    `ConvertFrom-Json` hands back `declaredAt` as a [datetime] with Kind=Utc, and casting it to a
    string renders the UTC WALL CLOCK with no zone marker. Re-parsing that gives Kind=Unspecified,
    which subtracts as though it were local -- so the age was wrong by exactly the UTC offset, and
    negative anywhere west of Greenwich. The number stayed plausible, which is why it survived.
    """
    _declaration(repo, declared_at=datetime.now(UTC) - timedelta(minutes=6))
    _stamp, age = _age_line(run_hook(repo, _COMPACT_RESTART))

    assert not age.lstrip().startswith("-"), (
        f"a declaration made six minutes ago reports a negative age: {age!r}. "
        "The UTC instant is being compared against a local clock."
    )
    assert "minutes old" in age, f"six minutes should read in minutes: {age!r}"


def test_an_hours_old_declaration_reads_in_hours(repo: Worktree) -> None:
    """The discriminating arm. A hook that printed one constant cannot pass this and the one above."""
    _declaration(repo, declared_at=datetime.now(UTC) - timedelta(hours=5))
    _stamp, age = _age_line(run_hook(repo, _COMPACT_RESTART))

    assert "5 hours old" in age, f"expected roughly five hours: {age!r}"


def test_a_future_timestamp_is_named_as_clock_skew(repo: Worktree) -> None:
    """A negative age is not a small age, and rounding it to zero hides the only fault in the line."""
    _declaration(repo, declared_at=datetime.now(UTC) + timedelta(hours=4))
    out = run_hook(repo, _COMPACT_RESTART)

    assert "FUTURE" in out, f"a timestamp ahead of this clock was not reported as such: {out}"


def test_the_reported_timestamp_carries_its_offset(repo: Worktree) -> None:
    """A bare wall clock for a UTC instant reads as local and is wrong by the offset."""
    _declaration(repo)
    stamp, _age = _age_line(run_hook(repo, _COMPACT_RESTART))

    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})", stamp), (
        f"the timestamp carries no zone and cannot be read unambiguously: {stamp!r}"
    )
