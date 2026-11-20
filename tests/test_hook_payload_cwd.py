# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hooks answer for the worktree their input names, not the one they run in.

Measured 2026-10-12: the desktop app starts a worktree session's CLI with ``--project-config-root
<primary checkout>``. A hook then runs with its working directory, ``CLAUDE_PROJECT_DIR`` and ``git
rev-parse --show-toplevel`` all naming the PRIMARY. Only the ``cwd`` field of the JSON on stdin names
the worktree. ``scripts/hooks/_hookinput.ps1`` reads that field, as UTF-8.

This file holds the helper's own tests and the one changed hook no other test file drives,
``lane-level.ps1``. The hooks that have a test file carry their case there.

Every hook here runs IN the primary, as the app runs it. Each arm that names the worktree has a
control that does not, and the control is what shows the fixture reproduces the fault.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from tests._session_pin import pin_dir, pin_path, seed_pin
from tests._spawn_lock import run_single

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "scripts" / "hooks"
HELPER = HOOKS / "_hookinput.ps1"
LANE = HOOKS / "lane-level.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="the hooks are PowerShell run under pwsh on Windows",
)

# Not ASCII on purpose. The console decoder [Console]::In uses turns this into two box-drawing
# characters, which is the half of the defect a plain ASCII path cannot show.
ACCENTED = "caf\u00e9-linked"


def _git(cwd: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(cwd), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _same_dir(a: str, b: Path) -> bool:
    return os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b))


def _primary_with(tmp_path: Path, worktree_leaf: str) -> tuple[Path, Path]:
    """A primary checkout and one linked worktree. realpath, so 8.3 and long names cannot differ."""
    base = Path(os.path.realpath(tmp_path))
    repo = base / "primary"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "init")
    wt = base / worktree_leaf
    _git(repo, "worktree", "add", "-q", "-b", "linked", str(wt))
    return repo, wt


def _run(script: Path, cwd: Path, stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=str(cwd),
        input=stdin,
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")
    return proc


def _raw(payload: dict[str, Any], *, ascii_escaped: bool = False) -> bytes:
    """The input as the harness writes it: raw UTF-8, never escaped to ASCII."""
    return json.dumps(payload, ensure_ascii=ascii_escaped).encode("utf-8")


# --------------------------------------------------------------------------------------------------
# The helper.
# --------------------------------------------------------------------------------------------------


def _helper(tmp_path: Path, call: str, stdin: bytes) -> dict[str, Any]:
    probe = tmp_path / "probe.ps1"
    probe.write_text(
        # UTF-8 out as well as in, or the probe's own console encoder mangles what the helper read.
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{HELPER}'\n$t = Read-CcxHookInput\n{call} | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, tmp_path, stdin)
    return dict(json.loads(proc.stdout.decode("utf-8")))


def test_the_helper_reads_a_cwd_that_is_not_ascii(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, ACCENTED)
    got = _helper(tmp_path, "Get-CcxHookPayloadCwd -Text $t", _raw({"cwd": str(wt)}))
    assert got["Named"] is True and got["Reason"] == "", got
    assert _same_dir(got["Cwd"], wt), got


def test_the_helper_walks_up_to_the_worktree_root(tmp_path: Path) -> None:
    _, wt = _primary_with(tmp_path, "linked")
    sub = wt / "deep" / "er"
    sub.mkdir(parents=True)
    got = _helper(tmp_path, "@{ Root = Get-CcxWorktreeRoot '" + str(sub) + "' }", _raw({}))
    assert _same_dir(got["Root"], wt), got


def test_the_helper_says_no_cwd_is_not_a_fault(tmp_path: Path) -> None:
    got = _helper(
        tmp_path,
        "Resolve-CcxHookSession -Text $t | Select-Object Named, Dir, Reason",
        _raw({"session_id": "s1"}),
    )
    assert got == {"Named": False, "Dir": None, "Reason": ""}, got


# --------------------------------------------------------------------------------------------------
# Resolve-CcxHookSession: the rules in the helper's header. The Lander's verdicts on korus#223 and
# PR 2328 measured a `cwd` that followed a `cd` into a sibling worktree or another repository, with
# and without a pin, and the hooks answered for wherever it pointed. Every probe here runs IN the
# primary, as the desktop app runs a hook, and each refusal has a control that is not refused.
# --------------------------------------------------------------------------------------------------


def _resolve(
    repo: Path, tmp_path: Path, payload: dict[str, Any], flags: str = "", helper: Path = HELPER
) -> dict[str, Any]:
    probe = tmp_path / "resolve.ps1"
    probe.write_text(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{helper}'\n$t = Read-CcxHookInput\n"
        f"$r = Resolve-CcxHookSession -Text $t {flags}\n"
        "[pscustomobject]@{ Dir = $r.Dir; Reason = $r.Reason; Note = $r.Note; Source = $r.Source;"
        " Pinned = $r.Pinned } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = _run(probe, repo, _raw(payload))
    return dict(json.loads(proc.stdout.decode("utf-8")))


def _other_repo(tmp_path: Path) -> Path:
    other = Path(os.path.realpath(tmp_path)) / "other-repo"
    other.mkdir()
    _git(other, "init", "-q", "-b", "main")
    return other


def _opted_in(tmp_path: Path, worktree_leaf: str = "linked") -> tuple[Path, Path, Path]:
    """A primary that opted in to pins, its linked worktree, and a sibling worktree.

    The helper under test lives in THIS repository, not the fixture's, so it may write a pin there
    only through ``ccx.config.json`` (the opt-in rule in the helper's header)."""
    repo, wt = _primary_with(tmp_path, worktree_leaf)
    (repo / "ccx.config.json").write_text("{}\n", encoding="utf-8")
    sibling = Path(os.path.realpath(tmp_path)) / "sibling"
    _git(repo, "worktree", "add", "-q", "-b", "sibling", str(sibling))
    return repo, wt, sibling


def _launch(session: str, cwd: Path, source: str = "startup") -> dict[str, Any]:
    return {
        "cwd": str(cwd),
        "session_id": session,
        "hook_event_name": "SessionStart",
        "source": source,
    }


def _stop(session: str, cwd: Path) -> dict[str, Any]:
    return {"cwd": str(cwd), "session_id": session, "hook_event_name": "Stop"}


def test_a_pinned_session_answers_for_its_own_worktree(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(repo, tmp_path, _stop("s1", wt))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert got["Reason"] == "" and got["Note"] == "" and got["Source"] == "cwd", got


def test_an_unpinned_cwd_in_a_sibling_is_refused_and_the_hook_stays_put(tmp_path: Path) -> None:
    """THE LANDER'S POINT, ON BOTH PRs: with no pin a sibling's `cwd` was answered for as it stood.

    No pin means the hook cannot tell the session's own worktree from a sibling it moved into, so it
    refuses both and stays in the start checkout, with a Reason to say aloud."""
    repo, _, sibling = _opted_in(tmp_path)
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] is None and got["Source"] == "start", "an unpinned sibling cwd was followed"
    assert "no pin records that this session started in" in got["Reason"], got
    # The control: an unpinned `cwd` inside the start checkout's own worktree is used.
    sub = repo / "sub"
    sub.mkdir()
    here = _resolve(repo, tmp_path, _stop("s1", sub))
    assert here["Dir"] and _same_dir(here["Dir"], sub) and here["Reason"] == "", here


def test_a_cwd_in_another_repository_is_a_fault_without_a_pin(tmp_path: Path) -> None:
    repo, _ = _primary_with(tmp_path, "linked")
    other = _other_repo(tmp_path)
    got = _resolve(repo, tmp_path, {"cwd": str(other), "session_id": "s1"})
    assert got["Dir"] is None, got
    assert "which is in another repository" in got["Reason"], got


def test_a_cwd_under_an_empty_git_file_is_a_fault(tmp_path: Path) -> None:
    """A `.git` that names no git directory is not a checkout. Walking up to it alone accepted it."""
    repo, _ = _primary_with(tmp_path, "linked")
    fake = Path(os.path.realpath(tmp_path)) / "fake"
    fake.mkdir()
    (fake / ".git").write_text("", encoding="utf-8")
    got = _resolve(repo, tmp_path, {"cwd": str(fake), "session_id": "s1"})
    assert got["Dir"] is None and "names no git directory" in got["Reason"], got


def test_after_a_cd_to_a_sibling_the_hook_answers_for_the_pinned_worktree(tmp_path: Path) -> None:
    repo, wt, sibling = _opted_in(tmp_path)
    start = _resolve(repo, tmp_path, _launch("s1", wt))
    assert start["Dir"] and _same_dir(start["Dir"], wt), start
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], wt), "the session showed as its sibling after a cd"
    assert "outside the worktree the session started in" in got["Note"], got
    # The control: another session that STARTED in the sibling is answered for there.
    other = _resolve(repo, tmp_path, _launch("s2", sibling))
    assert other["Dir"] and _same_dir(other["Dir"], sibling), other


def test_after_a_cd_to_another_repository_the_hook_answers_for_the_pinned_worktree(
    tmp_path: Path,
) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    other = _other_repo(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(repo, tmp_path, _stop("s1", other))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert "which is in another repository" in got["Note"], got
    assert not (other / ".git" / "ccx-session-root").exists(), (
        "nothing may be written into that repository"
    )


def test_a_compact_after_a_cd_does_not_move_the_pin(tmp_path: Path) -> None:
    """SessionStart also fires on /compact, wherever a `cd` left the cwd. Only a launch (startup,
    resume, or no source) writes the pin."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    _resolve(repo, tmp_path, _launch("s1", sibling, "compact"))
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], wt), (
        "a compaction re-pinned the session to its sibling"
    )
    # The control: a resume does rewrite it.
    _resolve(repo, tmp_path, _launch("s1", sibling, "resume"))
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], sibling), got


@pytest.mark.parametrize("source", ["clear", "compact"])
def test_a_clear_after_a_cd_never_pins_the_sibling(tmp_path: Path, source: str) -> None:
    """THE HIGH FINDING. /clear mints a NEW session id, so its SessionStart finds no pin, and the old
    rule ("a /clear writes a pin where none exists") pinned whatever sibling a `cd` had reached. A
    /clear or /compact now never pins; the new id follows the no-pin rule until a launch."""
    repo, _, sibling = _opted_in(tmp_path)
    first = _resolve(repo, tmp_path, _launch("fresh", sibling, source))
    assert first["Dir"] is None and first["Pinned"] is None, first
    assert "no pin records" in first["Reason"], first
    got = _resolve(repo, tmp_path, _stop("fresh", sibling))
    assert got["Dir"] is None, "a /clear after a cd pinned the sibling"
    assert not any(pin_dir(repo).glob("*")), "a pin was written"
    # The control: the same `cwd` at a startup is the session's launch, and it pins.
    _resolve(repo, tmp_path, _launch("fresh", sibling))
    got = _resolve(repo, tmp_path, _stop("fresh", sibling))
    assert got["Dir"] and _same_dir(got["Dir"], sibling), got


def test_a_launch_answers_for_its_cwd_and_pins_only_where_opted_in(tmp_path: Path) -> None:
    """The opt-in gate. A user-scope copy of the helper writes no file in a clone that did not opt
    in, yet still answers the launch itself, whose `cwd` is where the session started."""
    repo, wt = _primary_with(tmp_path, "linked")
    pins = pin_dir(repo)
    got = _resolve(repo, tmp_path, _launch("s1", wt))
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    assert not pins.exists(), "a pin was written in a clone that did not opt in"
    # A helper that LIVES in the clone is the clone's own hook, and that is an opt-in too.
    own = repo / "scripts" / "hooks"
    own.mkdir(parents=True)
    shutil.copy(HELPER, own / "_hookinput.ps1")
    _resolve(repo, tmp_path, _launch("s1", wt), helper=own / "_hookinput.ps1")
    assert len(list(pins.glob("*"))) == 1, "the clone's own helper wrote no pin"
    # -ReadOnly never writes, opted in or not.
    _resolve(repo, tmp_path, _launch("s2", wt), "-ReadOnly", helper=own / "_hookinput.ps1")
    assert len(list(pins.glob("*"))) == 1, "a -ReadOnly launch wrote a pin"


def test_a_launch_in_a_clone_no_longer_opted_in_removes_the_old_pin(tmp_path: Path) -> None:
    """The opt-in gate guarded the removal too, so a resume after the opt-in went away kept the
    previous run's pin, and later events answered for that worktree. Removing writes no new file."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", sibling))
    (repo / "ccx.config.json").unlink()
    _resolve(repo, tmp_path, _launch("s1", wt, "resume"))
    assert not pin_path(repo, "s1").exists(), "the previous run's pin survived the launch"
    got = _resolve(repo, tmp_path, _stop("s1", sibling))
    assert got["Dir"] is None, "the stale pin answered for the sibling"
    # The control: a pin naming this launch's own worktree is kept, because an opted-in copy run by
    # another hook on the same event may just have written it.
    seed_pin(repo, wt, "s1")
    _resolve(repo, tmp_path, _launch("s1", wt, "resume"))
    assert pin_path(repo, "s1").exists(), "a launch removed the pin that names its own worktree"


def test_a_pinned_session_with_no_cwd_answers_for_its_pin(tmp_path: Path) -> None:
    """Rule 3 covers an event whose input names no cwd. Staying put there answered for the primary,
    where steer-inject then read the primary's note."""
    repo, wt, _ = _opted_in(tmp_path)
    seed_pin(repo, wt, "s1")
    got = _resolve(repo, tmp_path, {"session_id": "s1", "hook_event_name": "PreToolUse"})
    assert got["Dir"] and _same_dir(got["Dir"], wt) and got["Source"] == "pin", got
    # The control: an unpinned session with no cwd stays put, in silence.
    other = _resolve(repo, tmp_path, {"session_id": "s2", "hook_event_name": "PreToolUse"})
    assert other["Dir"] is None and other["Reason"] == "", other


def test_an_open_stdin_is_a_fault_inside_a_checkout_and_out_of_one(tmp_path: Path) -> None:
    """BACKLOG #5586. Outside every checkout an open stdin used to answer with no Reason, and a caller
    with no Reason falls back: steer-inject to CLAUDE_PROJECT_DIR, which can name the primary. An
    open stdin says nothing about the cwd the input would have named, so it is a fault everywhere."""
    outside = tmp_path / "no-repo"
    outside.mkdir()
    probe = tmp_path / "timeout.ps1"
    probe.write_text(
        # What Read-CcxHookInput leaves behind when stdin is still open at its bound.
        f". '{HELPER}'\n$script:CcxHookInputFault = 'the hook input was still open'\n"
        f"$o = Resolve-CcxHookSession -Text '' -StartDir '{outside}'\n"
        "$r = Resolve-CcxHookSession -Text '' -StartDir $args[0]\n"
        f"$x = Resolve-CcxHookSession -Text '' -StartDir '{outside}' -AllowOutside\n"
        "$script:CcxHookInputFault = ''\n"
        f"$c = Resolve-CcxHookSession -Text '' -StartDir '{outside}'\n"
        "@{ outside = $o.Reason; inside = $r.Reason; anchored = $x.Reason; control = $c.Reason }"
        " | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    repo, _ = _primary_with(tmp_path, "linked")
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe), str(repo)],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    for where in ("outside", "inside", "anchored"):
        assert "still open" in got[where], got
    # The control: the same empty input from a read that closed is no input, not a fault.
    assert got["control"] == "", got


# --------------------------------------------------------------------------------------------------
# BACKLOG #5586: every input the helper cannot use is a Reason. Before, each of these answered with
# no Dir and an empty Reason, which every caller reads as "stay where you started": the primary.
# --------------------------------------------------------------------------------------------------


def _resolve_bytes(repo: Path, tmp_path: Path, stdin: bytes, flags: str = "") -> dict[str, Any]:
    probe = tmp_path / "resolve-raw.ps1"
    probe.write_text(
        "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        f". '{HELPER}'\n$t = Read-CcxHookInput\n"
        f"$r = Resolve-CcxHookSession -Text $t {flags}\n"
        "$p = Get-CcxHookPayloadCwd -Text $t\n"
        "[pscustomobject]@{ Dir = $r.Dir; Named = $r.Named; Reason = $r.Reason;"
        " PNamed = $p.Named; PReason = $p.Reason } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    return dict(json.loads(_run(probe, repo, stdin).stdout.decode("utf-8")))


@pytest.mark.parametrize(
    ("stdin", "why"),
    [
        (b"{not json at all", "not readable JSON"),
        (b"null", "not a JSON object"),
        (b"[1, 2]", "not a JSON object"),
        (b'"just a string"', "not a JSON object"),
        (b'{"cwd": "", "session_id": "s1"}', "blank cwd"),
        (b'{"cwd": "   ", "session_id": "s1"}', "blank cwd"),
        (b'{"cwd": null, "session_id": "s1"}', "blank cwd"),
        (b'[{"cwd": "C:\\\\", "session_id": "s1"}]', "not a JSON object"),
        (b'{"cwd": ".", "session_id": "s1"}', "relative cwd"),
        (b'{"cwd": "\\\\Code", "session_id": "s1"}', "relative cwd"),
        # #5586 item 3: the [string] cast read a one-element array as its element.
        (b'{"cwd": ["C:\\\\"], "session_id": "s1"}', "not a string"),
        (b'{"cwd": {"path": "C:\\\\"}, "session_id": "s1"}', "not a string"),
        (b'{"cwd": 5, "session_id": "s1"}', "not a string"),
        # #5586 item 2: a top-level key named twice in different case is ambiguous. Callers read
        # top-level keys beside these four: seat-unlock reads `reason`.
        (
            b'{"cwd": "C:\\\\", "CWD": "D:\\\\", "session_id": "s1"}',
            "names cwd in keys that differ",
        ),
        (b'{"cwd": "C:\\\\", "session_id": "s1", "Session_Id": "s2"}', "names session_id in keys"),
        (b'{"cwd": "C:\\\\", "source": "clear", "SOURCE": "startup"}', "names source in keys"),
        (
            b'{"cwd": "C:\\\\", "hook_event_name": "Stop", "Hook_Event_Name": "x"}',
            "hook_event_name",
        ),
        (b'{"cwd": "C:\\\\", "reason": "clear", "REASON": "x"}', "names reason in keys"),
        (b'{"cwd": "C:\\\\", "a": 1, "A": 2}', "names a in keys"),
        # A cast would read a one-element array as its element: an array event became SessionStart.
        (b'{"cwd": "C:\\\\", "hook_event_name": ["SessionStart"]}', "hook_event_name that is not"),
        (b'{"cwd": "C:\\\\", "session_id": ["s1"]}', "session_id that is not a string"),
        (b'{"cwd": "C:\\\\", "source": 1}', "source that is not a string"),
        # Still not JSON, even through -AsHashtable.
        (b'{"a": 1, "A": 2', "not readable JSON"),
        (b'[{"a": 1, "A": 2}]', "not a JSON object"),
    ],
)
def test_input_the_helper_cannot_use_is_a_fault(tmp_path: Path, stdin: bytes, why: str) -> None:
    repo, _ = _primary_with(tmp_path, "linked")
    got = _resolve_bytes(repo, tmp_path, stdin)
    assert got["Dir"] is None and got["Named"] is True, got
    assert why in got["Reason"], got
    # Get-CcxHookPayloadCwd -Text agrees. Hooks such as collision_gate call it with -Payload on
    # their own parse, which reads only the cwd field, so this does not speak for them.
    assert got["PNamed"] is True and why in got["PReason"], got


def test_an_object_with_no_cwd_is_still_no_fault(tmp_path: Path) -> None:
    """The control for the arm above: a JSON object with no `cwd` field is an older harness."""
    repo, _ = _primary_with(tmp_path, "linked")
    got = _resolve_bytes(repo, tmp_path, b'{"session_id": "s1"}')
    assert got["Reason"] == "" and got["PReason"] == "" and got["PNamed"] is False, got


@pytest.mark.parametrize(
    "extra",
    [
        '"": 1',
        '"psobject": 1',
        '"ToString": 5, "": 1',
        '"Keys": ["zz"], "": 1',
        '"tool_input": {"Keys": ["zz"], "a": 1, "A": 2}',
        '"tool_input": {"path": "x", "PATH": "y"}',
        '"tool_input": {"list": [{"k": 1, "K": 2}]}',
    ],
)
def test_json_that_only_convertfrom_json_refuses_is_still_read(tmp_path: Path, extra: str) -> None:
    """#5586 item 2: keys below the top level that differ only in case, an empty key, or a reserved
    member name are valid JSON, and a tool's own input can hold any of them. They made
    ConvertFrom-Json throw, and read as "not readable JSON". A key named `Keys` must not stand in for
    the key list when the object is rebuilt."""
    repo, _ = _primary_with(tmp_path, "linked")
    sub = repo / "sub"
    sub.mkdir()
    cwd = json.dumps(str(sub))
    got = _resolve_bytes(repo, tmp_path, f'{{"cwd": {cwd}, "session_id": "s1", {extra}}}'.encode())
    assert got["Reason"] == "" and got["PReason"] == "", got
    assert got["Dir"] and _same_dir(got["Dir"], sub), got


def test_a_date_shaped_session_id_is_still_a_string(tmp_path: Path) -> None:
    """ConvertFrom-Json reads an ISO-8601 string as a date; that is not a non-string input."""
    repo, _ = _primary_with(tmp_path, "linked")
    sub = repo / "sub"
    sub.mkdir()
    payload = {"cwd": str(sub), "session_id": "2026-11-18T10:00:00Z", "source": "2026-11-18"}
    got = _resolve_bytes(repo, tmp_path, _raw(payload))
    assert got["Reason"] == "" and got["PReason"] == "", got
    assert got["Dir"] and _same_dir(got["Dir"], sub), got


def test_a_payload_read_through_the_fallback_keeps_its_other_keys(tmp_path: Path) -> None:
    """The fallback rebuilds the object; callers such as seat-unlock read keys beside `cwd`."""
    repo, _ = _primary_with(tmp_path, "linked")
    probe = tmp_path / "fallback.ps1"
    probe.write_text(
        f". '{HELPER}'\n$t = Read-CcxHookInput\n$r = Resolve-CcxHookSession -Text $t\n"
        "@{ Reason = $r.Reason; Event = $r.Event; Sid = $r.SessionId;"
        " Why = [string]$r.Payload.reason; Kept = [string]$r.Payload.tool_input.keep;"
        " Gone = [bool]$r.Payload.tool_input.PSObject.Properties['a'];"
        " One = $r.Payload.list.Count } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    stdin = (
        b'{"session_id": "s9", "hook_event_name": "Stop", "reason": "logout", "list": ["x"],'
        b' "tool_input": {"keep": "k", "a": 1, "A": 2}, "": 0}'
    )
    got = json.loads(_run(probe, repo, stdin).stdout)
    assert got == {
        "Reason": "",
        "Event": "Stop",
        "Sid": "s9",
        "Why": "logout",
        "Kept": "k",
        "Gone": False,
        "One": 1,
    }, got


def test_a_stdin_read_that_throws_is_a_fault(tmp_path: Path) -> None:
    """A redirected stdin the hook may not read (a write-only handle) used to read as no input."""
    repo, _ = _primary_with(tmp_path, "linked")
    probe = tmp_path / "read-error.ps1"
    probe.write_text(
        f". '{HELPER}'\n$t = Read-CcxHookInput\n"
        "$r = Resolve-CcxHookSession -Text $t\n"
        "@{ Reason = $r.Reason; Err = $script:CcxHookInputFault } | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    sink = tmp_path / "write-only.bin"
    with sink.open("wb") as handle:
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)],
            cwd=str(repo),
            stdin=handle,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert got["Err"], f"the fixture did not make the read throw, so this proves nothing: {got}"
    assert "could not be read" in got["Reason"], got
    assert "could not be read" in proc.stderr, proc.stderr


def test_a_cwd_named_to_a_hook_started_outside_every_checkout_is_a_fault(tmp_path: Path) -> None:
    """Started in no checkout, the hook cannot check a `cwd` against a repository. Staying put in
    silence let steer-inject read CLAUDE_PROJECT_DIR's note instead."""
    _, wt = _primary_with(tmp_path, "linked")
    outside = Path(os.path.realpath(tmp_path)) / "no-repo"
    outside.mkdir()
    got = _resolve(outside, tmp_path, {"cwd": str(wt), "session_id": "s1"})
    assert got["Dir"] is None and "in no checkout this hook can read" in got["Reason"], got
    # mail-drain's -AnchorRepo case: an -AllowOutside caller stays put there in silence, as before.
    anchored = _resolve(
        outside, tmp_path, {"cwd": str(wt), "session_id": "s1"}, "-ReadOnly -AllowOutside"
    )
    assert anchored["Dir"] is None and anchored["Reason"] == "", anchored
    # The controls: no cwd there is no fault, and -AllowOutside still takes a cwd in no checkout.
    assert _resolve(outside, tmp_path, {"session_id": "s1"})["Reason"] == ""
    # A cwd that is the start directory itself is answered by staying put.
    assert _resolve(outside, tmp_path, {"cwd": str(outside), "session_id": "s1"})["Reason"] == ""
    scratch = Path(os.path.realpath(tmp_path)) / "scratch"
    scratch.mkdir()
    took = _resolve(outside, tmp_path, {"cwd": str(scratch)}, "-ReadOnly -AllowOutside")
    assert took["Dir"] and _same_dir(took["Dir"], scratch) and took["Reason"] == "", took


def _short_name(path: Path) -> str:
    """The 8.3 spelling of `path`, or '' where the volume keeps none."""
    import ctypes

    buf = ctypes.create_unicode_buffer(32767)
    n = ctypes.windll.kernel32.GetShortPathNameW(str(path), buf, len(buf))  # type: ignore[attr-defined,unused-ignore]
    return buf.value if 0 < n < len(buf) else ""


def _junction(link: Path, target: Path) -> None:
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        check=True,
        capture_output=True,
    )


def test_a_cd_inside_a_start_folder_outside_every_checkout_is_not_a_fault(tmp_path: Path) -> None:
    """#5586 item 1: started in no checkout, only a `cwd` spelled exactly as the start directory was
    taken, so a `cd` into a subfolder, or a junction spelling of it, was a fault and steer-inject in
    a non-git project stopped delivering."""
    base = Path(os.path.realpath(tmp_path))
    start = base / "start"
    sub = start / "deeper" / "still"
    sub.mkdir(parents=True)
    _junction(base / "jn", start)
    for cwd in (sub, start / "deeper", base / "jn", base / "jn" / "deeper"):
        got = _resolve(start, tmp_path, {"cwd": str(cwd), "session_id": "s1"})
        assert got["Reason"] == "" and got["Dir"] is None, (cwd, got)


def test_an_8dot3_spelling_of_a_start_folder_outside_every_checkout_is_not_a_fault(
    tmp_path: Path,
) -> None:
    """#5586 item 1, the short-name half: a subfolder of the start reached through its 8.3 name."""
    base = Path(os.path.realpath(tmp_path))
    start = base / "no repo long name"
    (start / "deeper").mkdir(parents=True)
    short = _short_name(start)
    if not short or short.lower() == str(start).lower():
        pytest.skip("this volume keeps no 8.3 names, so the short-name branch cannot run here")
    assert "~" in Path(short).name, short
    for cwd in (Path(short), Path(short) / "deeper"):
        got = _resolve(start, tmp_path, {"cwd": str(cwd), "session_id": "s1"})
        assert got["Reason"] == "" and got["Dir"] is None, (cwd, got)


def test_a_cd_inside_a_start_folder_below_an_unreadable_git_is_not_a_fault(tmp_path: Path) -> None:
    """A start below a `.git` this file cannot read (a removed worktree's) is in no checkout it can
    read, and a `cd` into a subfolder there is the same folder, not a move (review round 1)."""
    base = Path(os.path.realpath(tmp_path))
    stale = base / "stale-wt"
    start = stale / "start"
    (start / "sub").mkdir(parents=True)
    (stale / ".git").write_text("gitdir: C:/nonexistent/worktrees/x\n", encoding="utf-8")
    got = _resolve(start, tmp_path, {"cwd": str(start / "sub"), "session_id": "s1"})
    assert got["Reason"] == "" and got["Dir"] is None, got
    # Through a junction to the stale folder, the two roots differ only in spelling (review round 2).
    _junction(base / "jstale", stale)
    for cwd, where in (
        (base / "jstale" / "start" / "sub", start),
        (start / "sub", base / "jstale" / "start"),
    ):
        linked = _resolve(where, tmp_path, {"cwd": str(cwd), "session_id": "s1"})
        assert linked["Reason"] == "" and linked["Dir"] is None, (cwd, where, linked)
    # The control: a sibling of the start inside the same stale folder is still a move.
    (stale / "other").mkdir()
    moved = _resolve(start, tmp_path, {"cwd": str(stale / "other"), "session_id": "s1"})
    assert "in no checkout this hook can read" in moved["Reason"], moved


def test_a_rooted_relative_link_target_resolves_against_the_drive_root(tmp_path: Path) -> None:
    """Windows reads a symlink target `\\x` against the link's drive root, not its folder."""
    base = Path(os.path.realpath(tmp_path))
    link = base / "l"
    leaf = f"mefor-no-such-{base.name}"
    try:
        os.symlink("\\" + leaf, link, target_is_directory=True)
    except OSError as exc:
        pytest.skip(f"this account may not create a symlink: {exc}")
    got = _helper(tmp_path, f"@{{ Real = ConvertTo-CcxRealPath '{link}' }}", _raw({}))
    assert got["Real"].lower() == (base.anchor + leaf).lower(), got


def test_a_cwd_that_leaves_a_start_folder_outside_every_checkout_is_still_a_fault(
    tmp_path: Path,
) -> None:
    """The negative controls for the arm above: a sibling folder, a junction to one, a parent, and
    a folder below the start that holds a checkout are each still a fault."""
    base = Path(os.path.realpath(tmp_path))
    start = base / "start"
    start.mkdir()
    sibling = base / "start-sibling"
    sibling.mkdir()
    _junction(start / "out", sibling)
    nested = start / "nested"
    nested.mkdir()
    _git(nested, "init", "-q", "-b", "main")
    for cwd in (sibling, start / "out", base, nested, nested / ".git"):
        got = _resolve(start, tmp_path, {"cwd": str(cwd), "session_id": "s1"})
        assert "in no checkout this hook can read" in got["Reason"], (cwd, got)
        assert got["Dir"] is None, (cwd, got)


def test_a_launch_that_cannot_replace_the_pin_keeps_no_stale_one(tmp_path: Path) -> None:
    """A swap that failed used to leave the previous run's pin, which then answered for every later
    event. A read-only pin makes the move fail on demand. The helper must still end with the new pin
    or none, never the old one naming the sibling."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", sibling))
    pin = next(pin_dir(repo).glob("*"))
    os.chmod(pin, 0o444)
    try:
        _resolve(repo, tmp_path, _launch("s1", wt, "resume"))
        got = _resolve(repo, tmp_path, _stop("s1", sibling))
        assert not (got["Dir"] and _same_dir(got["Dir"], sibling)), "the stale pin answered"
    finally:
        if pin.exists():
            os.chmod(pin, 0o644)


def _pin_file(repo: Path, worktree: Path) -> Path:
    """The one file under the common dir that names ``worktree``, wherever the helper keeps it."""
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    for f in common.rglob("*"):
        if f.is_file() and f.suffix != ".tmp" and f.stat().st_size < 4096:
            try:
                if _same_dir(f.read_text(encoding="utf-8").strip(), worktree):
                    return f
            except (OSError, UnicodeDecodeError, ValueError):
                continue
    raise AssertionError("the launch wrote no pin naming the worktree")


def test_the_pin_is_never_missing_while_it_is_replaced(tmp_path: Path) -> None:
    """THE MEDIUM FINDING: `Move-Item -Force` deletes and then moves, so a reader between the two saw
    no pin and followed the sibling. Measured on pwsh 7.6.6. One thread relaunches the session in
    alternating worktrees while another checks, as tightly as it can, that the pin file exists."""
    repo, wt, sibling = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    pin = _pin_file(repo, wt)
    probe = tmp_path / "race.ps1"
    probe.write_text(
        "param($h, $a, $b, $pin)\n"
        # The reader runs in a thread until the writer, here, says it is done, so it samples the
        # whole run however the scheduler starts the two.
        "$sync = [hashtable]::Synchronized(@{ done = $false; reads = 0; misses = 0 })\n"
        "$reader = Start-ThreadJob -ArgumentList $sync, $pin -ScriptBlock {\n"
        "    param($sync, $pin)\n"
        "    while (-not $sync.done) {\n"
        "        $sync.reads++\n"
        "        if (-not [System.IO.File]::Exists($pin)) { $sync.misses++ }\n"
        "    }\n"
        "}\n"
        "$t0 = Get-Date\n"
        "while ($sync.reads -eq 0) {\n"
        "    if (((Get-Date) - $t0).TotalSeconds -gt 20) {\n"
        "        throw ('the reader never started: ' + (Receive-Job $reader 2>&1 | Out-String))\n"
        "    }\n"
        "    Start-Sleep -Milliseconds 5\n"
        "}\n"
        "$errs = @()\n"
        "try {\n"
        "    . $h\n"
        "    foreach ($i in 1..300) {\n"
        "        $cwd = if ($i % 2) { $b } else { $a }\n"
        "        $j = @{ cwd = $cwd; session_id = 's1'; hook_event_name = 'SessionStart';"
        " source = 'resume' } | ConvertTo-Json\n"
        "        $null = Resolve-CcxHookSession -Text $j\n"
        "    }\n"
        "} catch { $errs += [string]$_ }\n"
        "$sync.done = $true\n"
        "Receive-Job $reader -Wait -AutoRemoveJob | Out-Null\n"
        "$reads = $sync.reads; $misses = $sync.misses\n"
        "$named = Get-Content -LiteralPath $pin -TotalCount 1\n"
        "@{ reads = $reads; misses = $misses; errors = $errs; named = $named }"
        " | ConvertTo-Json -Compress\n",
        encoding="utf-8",
    )
    proc = run_single(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)]
        + [str(HELPER), str(wt), str(sibling), str(pin)],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT * 3,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    assert got["errors"] == [], f"the writer failed, so this proves nothing: {got}"
    # One read per write at the least, or the window between a delete and a move was barely sampled.
    assert got["reads"] >= 300, f"the reader barely ran, so this proves nothing: {got}"
    assert _same_dir(got["named"], wt), f"the writer did not finish on its last launch: {got}"
    assert got["misses"] == 0, f"a reader found no pin mid-replace: {got}"


def test_a_pin_write_prunes_stale_temp_files_and_keeps_fresh_ones(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    pins = pin_dir(repo)
    pins.mkdir(parents=True)
    stale = pins / "abc.1.dead.tmp"
    fresh = pins / "abc.2.live.tmp"
    stale.write_text("x", encoding="utf-8")
    fresh.write_text("x", encoding="utf-8")
    old = time.time() - 3600
    os.utime(stale, (old, old))
    _resolve(repo, tmp_path, _launch("s1", wt))
    assert not stale.exists(), "a temp file an hour old was left behind"
    assert fresh.exists(), "a temp file a live writer may own was removed"


def test_a_pin_naming_a_removed_worktree_is_ignored(tmp_path: Path) -> None:
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    _git(repo, "worktree", "remove", "--force", str(wt))
    got = _resolve(repo, tmp_path, _stop("s1", repo))
    assert got["Dir"] and _same_dir(got["Dir"], repo), got
    assert got["Pinned"] is None, got


def test_allow_outside_still_prefers_the_pin(tmp_path: Path) -> None:
    """A pinned session that ran `cd` into a scratch directory keeps its own worktree. Only a
    session with nothing pinned is answered for where it stands."""
    repo, wt, _ = _opted_in(tmp_path)
    scratch = Path(os.path.realpath(tmp_path)) / "scratch"
    scratch.mkdir()
    _resolve(repo, tmp_path, _launch("s1", wt))
    got = _resolve(
        repo, tmp_path, {"cwd": str(scratch), "session_id": "s1"}, "-ReadOnly -AllowOutside"
    )
    assert got["Dir"] and _same_dir(got["Dir"], wt), got
    other = _resolve(
        repo, tmp_path, {"cwd": str(scratch), "session_id": "s2"}, "-ReadOnly -AllowOutside"
    )
    assert other["Dir"] and _same_dir(other["Dir"], scratch), other


def test_the_seeded_pin_matches_the_one_a_launch_writes(tmp_path: Path) -> None:
    """tests/_session_pin.py writes pins for the hook tests by hand. Pin it to the real layout."""
    repo, wt, _ = _opted_in(tmp_path)
    _resolve(repo, tmp_path, _launch("s1", wt))
    written = pin_path(repo, "s1")
    assert written.is_file(), "the launch wrote its pin somewhere the seeder does not look"
    assert _same_dir(written.read_text(encoding="utf-8").strip(), wt)


# --------------------------------------------------------------------------------------------------
# lane-level.ps1. It tells a builder lane by its worktree's name, so from the primary it answered for
# neither lane nor dispatcher and said nothing.
# --------------------------------------------------------------------------------------------------


def _lane(repo: Path, payload: dict[str, Any]) -> str:
    out = _run(LANE, repo, _raw(payload)).stdout.decode("utf-8").strip()
    return str(json.loads(out)["hookSpecificOutput"]["additionalContext"]) if out else ""


@pytest.fixture
def builder_lane(tmp_path: Path) -> tuple[Path, Path]:
    repo, wt = _primary_with(tmp_path, "builder-lane")
    (repo / ".git" / "mefor-coord").mkdir()
    return repo, wt


def test_lane_level_nags_the_builder_worktree_the_input_names(
    builder_lane: tuple[Path, Path],
) -> None:
    repo, wt = builder_lane
    seed_pin(repo, wt, "s1")
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": str(wt), "session_id": "s1"})
    assert "[lane] Your lane level is unstated or stale" in text, text


def test_lane_level_without_a_cwd_reads_where_it_runs(builder_lane: tuple[Path, Path]) -> None:
    """The control. The primary is no builder lane, so the same call says nothing at all."""
    repo, _ = builder_lane
    assert _lane(repo, {"hook_event_name": "Stop"}) == ""


def test_lane_level_says_aloud_when_the_cwd_does_not_exist(
    builder_lane: tuple[Path, Path], tmp_path: Path
) -> None:
    repo, _ = builder_lane
    gone = str(Path(os.path.realpath(tmp_path)) / "deleted-worktree")
    text = _lane(repo, {"hook_event_name": "Stop", "cwd": gone})
    assert "[lane] COULD NOT READ THIS SESSION'S WORKTREE" in text, text
    assert "deleted-worktree, which does not exist" in text, text


# --------------------------------------------------------------------------------------------------
# seat-record.ps1, the Stop hook that writes the seat record through seat.ps1 -Record (BACKLOG
# #5961). seat.ps1 took the payload `cwd` as it stood, so after a `cd` the record would land in a
# sibling's box or in another repository's registry. It now answers through the helper's pin.
# --------------------------------------------------------------------------------------------------

SEAT_RECORD = HOOKS / "seat-record.ps1"


def _seat_records(start: Path) -> list[dict[str, Any]]:
    """Every seat record in the registry of the clone ``start`` belongs to."""
    common = Path(_git(start, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    seats = common / "mefor-coord" / "seats"
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted(seats.rglob("*.json"))]


def _record_stop(repo: Path, payload: dict[str, Any]) -> None:
    """Run the Stop hook in the primary, as the app runs it.

    tests/conftest.py drops MEFOR_COORD_ROOT for the whole run, so no record can reach the real
    shared root: each fixture clone's own ``.git/mefor-coord`` is its registry."""
    _run(SEAT_RECORD, repo, _raw(payload))


@pytest.fixture
def seat_clones(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    """A primary, its linked worktree, a sibling worktree, and an unrelated repository."""
    repo, wt, sibling = _opted_in(tmp_path)
    other = _other_repo(tmp_path)
    _git(other, "config", "user.email", "t@example.invalid")
    _git(other, "config", "user.name", "t")
    _git(other, "commit", "-q", "--allow-empty", "-m", "init")
    for clone in (repo, other):
        (clone / ".git" / "mefor-coord").mkdir()
    return repo, wt, sibling, other


def test_the_seat_recorder_records_the_pinned_worktree_its_cwd_names(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    """The control. Without it, a fixture that records nothing would pass the arms below."""
    repo, wt, _, _ = seat_clones
    seed_pin(repo, wt, "s1")
    _record_stop(repo, _stop("s1", wt))
    recs = _seat_records(repo)
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], wt), recs
    # The cwd named the worktree, so the pin did not: the label's negative control.
    assert recs[0]["worktreeSource"] == "git rev-parse --show-toplevel", recs


def test_after_a_cd_to_a_sibling_the_seat_recorder_records_the_pinned_worktree(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    repo, wt, sibling, _ = seat_clones
    seed_pin(repo, wt, "s1")
    _record_stop(repo, _stop("s1", sibling))
    recs = _seat_records(repo)
    assert not any(_same_dir(r["worktree"], sibling) for r in recs), recs
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], wt), recs
    assert recs[0]["worktreeSource"].startswith("session pin"), recs


def test_after_a_cd_to_another_repository_the_seat_recorder_writes_nothing_there(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    repo, wt, _, other = seat_clones
    seed_pin(repo, wt, "s1")
    _record_stop(repo, _stop("s1", other))
    assert _seat_records(other) == []
    recs = _seat_records(repo)
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], wt), recs


def test_an_unpinned_seat_recorder_records_a_sibling_cwd_there(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    """BACKLOG #5954: with no pin, a cwd in a worktree of this repository is recorded at that
    worktree, as seat-record.ps1 says, since only a pin can tell its own worktree from a sibling."""
    repo, _, sibling, _ = seat_clones
    _record_stop(repo, _stop("s1", sibling))
    recs = _seat_records(repo)
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], sibling), recs


def test_an_unpinned_seat_recorder_still_records_the_checkout_it_started_in(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    """The control for the arm above: an unpinned cwd in the start checkout itself is recorded."""
    repo, _, _, _ = seat_clones
    _record_stop(repo, _stop("s1", repo))
    recs = _seat_records(repo)
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], repo), recs


def test_a_pinned_seat_recorder_with_no_cwd_records_its_pin(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    repo, wt, _, _ = seat_clones
    seed_pin(repo, wt, "s1")
    _record_stop(repo, {"session_id": "s1", "hook_event_name": "Stop"})
    recs = _seat_records(repo)
    assert len(recs) == 1 and _same_dir(recs[0]["worktree"], wt), recs
    assert recs[0]["worktreeSource"].startswith("session pin"), recs


def test_seat_ps1_says_why_it_refused_a_cwd(seat_clones: tuple[Path, Path, Path, Path]) -> None:
    """seat.ps1 -Record with no -Worktree refuses a cwd outside its pin rules, and says why on
    stderr: an absent record must be this refusal, not a writer that failed for another reason."""
    repo, _, sibling, _ = seat_clones
    seat = ROOT / "scripts" / "coord" / "seat.ps1"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(seat), "-Record"],
        cwd=str(repo),
        input=_raw(_stop("s1", sibling)),
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert b"the hook input was refused, so nothing was recorded" in proc.stderr, proc.stderr
    assert _seat_records(repo) == []
    # A refusal is not a writer failure: fleet.ps1 counts .writer-errors.txt lines as failures, so
    # an unpinned session must not add one on every Stop.
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    errors = common / "mefor-coord" / "seats" / ".writer-errors.txt"
    assert not errors.exists() or errors.read_text(encoding="utf-8").strip() == "", errors


def _record_seat_direct(repo: Path, payload: dict[str, Any]) -> None:
    """Run seat.ps1 -Record with no -Worktree, the one route on which it refuses input."""
    seat = ROOT / "scripts" / "coord" / "seat.ps1"
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(seat), "-Record"],
        cwd=str(repo),
        input=_raw(payload),
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")


def test_a_refused_seat_record_leaves_one_refusal_line_an_hour(
    seat_clones: tuple[Path, Path, Path, Path],
) -> None:
    """seat.ps1 -Record with no -Worktree writes each refusal to .writer-refusals.txt, one line
    per session key and host per hour, never to .writer-errors.txt. Run directly, because
    seat-record.ps1 answers a refused input itself and never runs seat.ps1 for it."""
    repo, _, sibling, _ = seat_clones
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    seats = common / "mefor-coord" / "seats"
    refusals = seats / ".writer-refusals.txt"
    errors = seats / ".writer-errors.txt"

    _record_seat_direct(repo, _stop("s1", sibling))
    assert refusals.is_file(), "a refused hook input left no .writer-refusals.txt line"
    lines = refusals.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, lines
    cols = lines[0].split("\t")
    assert cols[2] == "s1" and cols[3] == sibling.name, cols

    _record_seat_direct(repo, _stop("s1", sibling))
    assert refusals.read_text(encoding="utf-8").splitlines() == lines, "the hour's limit failed"
    assert not errors.exists() or errors.read_text(encoding="utf-8").strip() == "", errors
    assert _seat_records(repo) == []

    # The controls: the limit is per session key and host, and a line over an hour old, or stamped in the
    # future by a skewed clock, does not hold it.
    _record_seat_direct(repo, _stop("s2", sibling))
    assert len(refusals.read_text(encoding="utf-8").splitlines()) == 2, "another key was silenced"
    for stamp in ("2000-01-01T00:00:00Z", "2999-01-01T00:00:00Z"):
        refusals.write_text("\t".join([stamp, *cols[1:]]) + "\n", encoding="utf-8")
        _record_seat_direct(repo, _stop("s1", sibling))
        got = refusals.read_text(encoding="utf-8").splitlines()
        assert len(got) == 2 and got[1].split("\t")[2] == "s1", (stamp, got)


def _record_stop_in_culture(repo: Path, payload: dict[str, Any], culture: str) -> None:
    """Run seat.ps1 -Record with no -Worktree, with the thread culture set first."""
    seat = ROOT / "scripts" / "coord" / "seat.ps1"
    lit = str(seat).replace("'", "''")
    command = (
        f"[Threading.Thread]::CurrentThread.CurrentCulture = [Globalization.CultureInfo]::new('{culture}'); "
        f"& '{lit}' -Record"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", command],
        cwd=str(repo),
        input=_raw(payload),
        capture_output=True,
        timeout=TIMEOUT,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr.decode("utf-8", "replace")


@pytest.mark.parametrize("culture", ["fi-FI", "th-TH"])
def test_the_refusal_limit_holds_under_a_culture_that_formats_time_differently(
    seat_clones: tuple[Path, Path, Path, Path], culture: str
) -> None:
    """The stamp was formatted in the current culture and parsed in the invariant one. fi-FI writes
    the time separator as '.', and th-TH counts years in the Buddhist era, so the stamp never parsed
    and every refusal added a line. The second refusal within the hour must add none."""
    repo, _, sibling, _ = seat_clones
    common = Path(_git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir"))
    refusals = common / "mefor-coord" / "seats" / ".writer-refusals.txt"

    before = time.strftime("%Y", time.gmtime())
    _record_stop_in_culture(repo, _stop("s1", sibling), culture)
    after = time.strftime("%Y", time.gmtime())
    lines = refusals.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1, lines

    _record_stop_in_culture(repo, _stop("s1", sibling), culture)
    assert refusals.read_text(encoding="utf-8").splitlines() == lines, (culture, "limit failed")
    # The stamp is the invariant form the reader parses: a Gregorian year and ':' separators.
    stamp = lines[0].split("\t")[0]
    assert stamp[:4] in (before, after) and stamp[13] == ":", lines
