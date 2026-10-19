# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The coordination scripts refuse in a Claude Code cloud session instead of writing where nobody reads.

A cloud VM is its own clone, so ``git rev-parse --git-common-dir`` resolves to that clone's ``.git``
and ``<git-common-dir>/mefor-coord`` is a valid directory that no other session ever reads. Before the
guard, ``seat.ps1``, ``mail.ps1``, ``alloc.ps1`` and ``claim.ps1`` would all have "succeeded" into it:
a declaration nobody sees, mail nobody drains, an ADR number the fleet never learns about. The same
refusal now also guards ``handoff.ps1``, ``lane.ps1``, ``owner_log.py``,
``tombstone-retired-backlog-allocator.ps1`` and ``hygiene-report.ps1``, and a census below holds every
script that names the directory to a decision about it.

Each refusal is paired with a control that runs the same call without ``CLAUDE_CODE_REMOTE`` and
must take the normal path, because a refusal test alone also passes against a script that refuses
every call. tests/conftest.py drops the variable from the suite's own environment, so the controls
stay meaningful when the suite itself runs in a cloud VM.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
HOOKS = ROOT / "scripts" / "hooks"
WORKTREE = ROOT / "scripts" / "worktree"
TIMEOUT = 120
REFUSAL_EXIT = 3
REFUSAL_TAIL = (
    ": refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM's .git/mefor-coord"
    " reaches no other session, so nothing was read or recorded."
)
SEAT_DECLARE = ("-Declare", "-Seat", "builder", "-Goal", "cloud refusal test")
# The report's offline shape: no gh, no fetch, no roots beyond the sandbox clone.
HYGIENE_OFFLINE = ("-SkipGh", "-SkipFetch", "-NoExtraRoots")

needs_pwsh = pytest.mark.skipif(shutil.which("pwsh") is None, reason="the scripts run under pwsh")
# The normal paths of these scripts are exercised on Windows by their own suites; the controls here
# follow the same platform gate. The refusals fire before anything platform-specific.
needs_windows = pytest.mark.skipif(
    os.name != "nt", reason="the scripts' normal paths run on Windows"
)


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )


@pytest.fixture(scope="module")
def _template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One clone carrying its OWN copy of scripts/coord, scripts/hooks and scripts/worktree, built
    once per module."""
    r = tmp_path_factory.mktemp("template") / "repo"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "t")
    shutil.copytree(COORD, r / "scripts" / "coord")
    shutil.copytree(HOOKS, r / "scripts" / "hooks")
    shutil.copytree(WORKTREE, r / "scripts" / "worktree")
    (r / "f.txt").write_text("x", encoding="utf-8")
    _git(r, "add", "f.txt")
    _git(r, "commit", "-qm", "base")
    return r


@pytest.fixture
def repo(tmp_path: Path, _template: Path) -> Path:
    """A private copy of the template per test. These scripts anchor on where they live, not on the
    cwd, so the copy is what keeps every write out of the real registry and out of a sibling test."""
    r = tmp_path / "repo"
    shutil.copytree(_template, r, symlinks=True)
    return r


def _coord_dir(repo: Path) -> Path:
    return repo / ".git" / "mefor-coord"


def _run(repo: Path, script: str, *args: str, cloud: bool) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if cloud:
        env["CLAUDE_CODE_REMOTE"] = "true"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(repo / "scripts" / script), *args],
        cwd=str(repo),
        env=env,
        input="",
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


@needs_pwsh
@pytest.mark.parametrize(
    ("script", "args"),
    [
        pytest.param("coord/seat.ps1", SEAT_DECLARE, id="seat-declare"),
        pytest.param("coord/seat.ps1", ("-Close",), id="seat-close"),
        pytest.param("coord/mail.ps1", ("-Status",), id="mail-status"),
        pytest.param("coord/alloc.ps1", ("-List",), id="alloc-list"),
        pytest.param("coord/claim.ps1", ("-List",), id="claim-list"),
        pytest.param("coord/handoff.ps1", ("-Where",), id="handoff-where"),
        pytest.param("coord/lane.ps1", ("-Free", "1", "-InFlight", "0"), id="lane-state"),
        pytest.param("coord/tombstone-retired-backlog-allocator.ps1", (), id="tombstone-write"),
        pytest.param("worktree/hygiene-report.ps1", HYGIENE_OFFLINE, id="hygiene-report"),
    ],
)
def test_each_coordination_script_refuses_in_a_cloud_session(
    repo: Path, script: str, args: tuple[str, ...]
) -> None:
    proc = _run(repo, script, *args, cloud=True)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert proc.stderr.strip() == script.rsplit("/", 1)[-1] + REFUSAL_TAIL, proc.stderr
    assert proc.stdout == "", proc.stdout
    assert not _coord_dir(repo).exists(), "a refused call still created the coordination directory"


@needs_pwsh
def test_mail_send_refuses_before_writing_to_an_explicit_mail_root(
    repo: Path, tmp_path: Path
) -> None:
    """-MailRoot bypasses the git lookup, so this proves the refusal comes before the write itself."""
    root = tmp_path / "mail"
    args = ("-Send", "-To", str(repo), "-Body", "x", "-MailRoot", str(root))
    proc = _run(repo, "coord/mail.ps1", *args, cloud=True)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert not root.exists()


@needs_pwsh
@pytest.mark.parametrize(
    ("script", "args", "override"),
    [
        pytest.param("coord/handoff.ps1", ("-Report",), "-CoordDir", id="handoff-coorddir"),
        pytest.param(
            "coord/tombstone-retired-backlog-allocator.ps1", (), "-GitCommonDir", id="tombstone"
        ),
        pytest.param(
            "worktree/hygiene-report.ps1", HYGIENE_OFFLINE, "-OutDir", id="hygiene-outdir"
        ),
    ],
)
def test_an_explicit_path_override_is_refused_too(
    repo: Path, tmp_path: Path, script: str, args: tuple[str, ...], override: str
) -> None:
    """Each override bypasses the git lookup, so this proves the refusal comes before the write."""
    target = tmp_path / "override"
    proc = _run(repo, script, *args, override, str(target), cloud=True)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert not target.exists()
    assert not _coord_dir(repo).exists()


OWNER_SENT = ("sent", "--item", "t1", "--actor", "builder", "--summary", "cloud refusal test")


def _owner_log(
    tmp_path: Path, ledger: Path, *args: str, remote: str | None
) -> subprocess.CompletedProcess[str]:
    """MEFOR_OWNER_LOG skips the git lookup, so this runs the real script in place, from a cwd that
    is no repository at all."""
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_REMOTE"}
    env["MEFOR_OWNER_LOG"] = str(ledger)
    if remote is not None:
        env["CLAUDE_CODE_REMOTE"] = remote
    return subprocess.run(
        [sys.executable, str(COORD / "owner_log.py"), *args],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


@pytest.mark.parametrize(
    ("args", "remote"),
    [
        pytest.param(OWNER_SENT, "true", id="sent"),
        pytest.param(("status",), "true", id="status"),
        # The PowerShell copies compare with -eq, which ignores case; the Python copy must agree.
        pytest.param(("status",), "TRUE", id="status-upper-case"),
    ],
)
def test_owner_log_refuses_in_a_cloud_session_even_with_its_override(
    tmp_path: Path, args: tuple[str, ...], remote: str
) -> None:
    """MEFOR_OWNER_LOG bypasses the git lookup, so the refusal is proven to come before the write."""
    ledger = tmp_path / "owner-log" / "OWNER-ITEMS.md"
    proc = _owner_log(tmp_path, ledger, *args, remote=remote)
    assert proc.returncode == REFUSAL_EXIT, (proc.stdout, proc.stderr)
    assert proc.stderr.strip() == "owner_log.py" + REFUSAL_TAIL, proc.stderr
    assert proc.stdout == "", proc.stdout
    assert not ledger.parent.exists()


def test_owner_log_writes_its_row_outside_the_cloud(tmp_path: Path) -> None:
    """The control: the row the refusal withholds is really written here."""
    ledger = tmp_path / "owner-log" / "OWNER-ITEMS.md"
    proc = _owner_log(tmp_path, ledger, *OWNER_SENT, remote=None)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "| t1 | request_sent |" in ledger.read_text(encoding="utf-8")


@needs_pwsh
@needs_windows
def test_seat_record_is_not_refused_in_the_cloud(repo: Path) -> None:
    """-Record is a Stop-hook path that must exit 0 on every route, so it is exempt."""
    proc = _run(repo, "coord/seat.ps1", "-Record", cloud=True)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr
    assert proc.returncode == 0, (proc.stdout, proc.stderr)


@needs_pwsh
@needs_windows
@pytest.mark.parametrize(
    ("script", "args"),
    [
        pytest.param("coord/mail.ps1", ("-Status",), id="mail-status"),
        pytest.param("coord/alloc.ps1", ("-List",), id="alloc-list"),
        pytest.param("coord/claim.ps1", ("-List",), id="claim-list"),
        pytest.param("coord/handoff.ps1", ("-Report",), id="handoff-report"),
        pytest.param("coord/lane.ps1", ("-Show",), id="lane-show"),
    ],
)
def test_each_coordination_script_takes_its_normal_path_outside_the_cloud(
    repo: Path, script: str, args: tuple[str, ...]
) -> None:
    proc = _run(repo, script, *args, cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr


@needs_pwsh
@needs_windows
@pytest.mark.parametrize(
    ("script", "args", "written"),
    [
        pytest.param("coord/handoff.ps1", ("-Where",), "handoffs", id="handoff-where"),
        pytest.param("coord/lane.ps1", ("-Free", "1", "-InFlight", "0"), "lanes", id="lane-state"),
        pytest.param(
            "worktree/hygiene-report.ps1", HYGIENE_OFFLINE, "hygiene", id="hygiene-report"
        ),
    ],
)
def test_each_writer_writes_outside_the_cloud(
    repo: Path, script: str, args: tuple[str, ...], written: str
) -> None:
    """The control for each new refusal: the directory the refusal withholds is written here."""
    proc = _run(repo, script, *args, cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    out = _coord_dir(repo) / written
    assert out.is_dir() and any(out.iterdir()), f"{script} wrote nothing under {written}/"


@needs_pwsh
@needs_windows
def test_the_tombstone_check_takes_its_normal_path_outside_the_cloud(repo: Path) -> None:
    """Exit 1 and ABSENT is the normal answer in a clone with no tombstone. The write path needs an
    origin/main the sandbox does not have, so the check is the control."""
    proc = _run(repo, "coord/tombstone-retired-backlog-allocator.ps1", "-Check", cloud=False)
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    assert "ABSENT:" in proc.stdout


@needs_pwsh
@needs_windows
def test_seat_declare_outside_the_cloud_writes_its_record(repo: Path) -> None:
    """The control for the declaration: the record the refusal withholds is really written here."""
    proc = _run(repo, "coord/seat.ps1", *SEAT_DECLARE, cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "refused in a Claude Code cloud session" not in proc.stdout + proc.stderr
    records = list((_coord_dir(repo) / "seats").rglob("*.json"))
    assert records, "seat.ps1 -Declare wrote no record outside the cloud"


@needs_pwsh
def test_the_declare_prompt_hook_prints_one_cloud_line_and_exits_zero(repo: Path) -> None:
    proc = _run(repo, "hooks/seat-declare-prompt.ps1", cloud=True)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    lines = [ln for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1, proc.stdout
    assert "cloud Builder with no seat registry" in lines[0]
    assert "seat.ps1 -Declare -Seat" not in proc.stdout
    assert not _coord_dir(repo).exists(), "the cloud hook stamped a seat record nobody reads"


@needs_pwsh
@needs_windows
def test_the_declare_prompt_hook_prints_the_prompt_outside_the_cloud(repo: Path) -> None:
    proc = _run(repo, "hooks/seat-declare-prompt.ps1", cloud=False)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "seat.ps1 -Declare -Seat" in proc.stdout
    assert "cloud Builder" not in proc.stdout


# Every PowerShell copy of the refusal, inlined rather than shared. No helper is loaded by all of
# them: alloc.ps1, claim.ps1 and the tombstone script dot-source nothing, and about ten fixtures copy
# alloc.ps1 or claim.ps1 alone, so a new dot-source would break them. There is no shared coord-root
# resolver either, and one would be the wrong home: -CoordDir, -MailRoot and MEFOR_OWNER_LOG bypass
# it. The Python copy is held by the behavioural owner_log tests, which need no pwsh.
GUARDED = (
    "coord/seat.ps1",
    "coord/mail.ps1",
    "coord/alloc.ps1",
    "coord/claim.ps1",
    "coord/handoff.ps1",
    "coord/lane.ps1",
    "coord/tombstone-retired-backlog-allocator.ps1",
    "worktree/hygiene-report.ps1",
)
PY_GUARDED = "coord/owner_log.py"


@pytest.mark.parametrize("rel", GUARDED)
def test_each_script_carries_the_one_refusal_line(rel: str) -> None:
    """The guard is inlined, so this holds every copy to one line without pwsh, which also runs
    where the refusal tests skip."""
    name = rel.rsplit("/", 1)[-1]
    text = (ROOT / "scripts" / rel).read_text(encoding="utf-8")
    line = f"[Console]::Error.WriteLine('{name}{REFUSAL_TAIL}')".replace("VM's", "VM''s")
    guard = f"    {line}\n    exit {REFUSAL_EXIT}\n"
    assert text.count(guard) == 1, f"{rel} lost or changed its cloud refusal line"


# Every script under scripts/coord, scripts/hooks and scripts/worktree that names mefor-coord, and
# why it carries no refusal of its own. A new one fails the census until someone decides: a writer a
# cloud session can reach gets the refusal and joins GUARDED, and anything else is classified here.
# The census reads the literal directory name, so a script that reaches it only through another one
# (worktree/new.ps1 through coord/lock.ps1) is covered by that one's entry.
NOT_GUARDED = {
    # Run only by a user-scope hook, which install-coordination.ps1 writes into a config root's
    # settings.json and which a cloud session never loads.
    "hooks/announce-session.ps1": "user-scope hook",
    "hooks/collision_gate.ps1": "user-scope hook",
    "hooks/mail-drain.ps1": "user-scope hook",
    "hooks/mail-watch.ps1": "user-scope hook, retired from the wiring",
    "hooks/wiki-write-prompt.ps1": "user-scope hook",
    "worktree/session-context.ps1": "user-scope hook",
    # Writes state that is correct for the clone it runs in, so it is no dead letter in a VM.
    "coord/lock.ps1": "clone-local mutex around worktree/new.ps1",
    "coord/overlap.ps1": "a cache of its own answer; run by the user-scope hooks above",
    # Reads mefor-coord and writes nothing there, or writes only through a guarded script.
    "coord/claim-adjudicate.ps1": "reader",
    "coord/claim-reconcile.ps1": "reader; -Apply writes only through claim.ps1",
    "coord/fleet.ps1": "reader",
    "hooks/claim_check.py": "reader, commit-msg hook",
    "hooks/ledger_check.py": "reader, pre-commit hook",
    "hooks/lane-level.ps1": "reader",
    "hooks/precompact-reprime.ps1": "reader, project hook",
    "hooks/worktree_gate.ps1": "reader; writes only its own log, outside mefor-coord",
    "worktree/prune-merged.ps1": "reader",
    "worktree/remove.ps1": "reader",
    # Names the directory in prose or prints its path, and writes nothing there.
    "coord/install-coordination.ps1": "mention",
    "coord/install-git-hooks.ps1": "mention",
    "coord/rescue.ps1": "mention",
    "coord/unbacked_check.ps1": "mention",
    "worktree/register-hygiene-task.ps1": "mention",
}


def test_every_script_naming_the_coordination_directory_is_classified() -> None:
    named = {
        p.relative_to(ROOT / "scripts").as_posix()
        for d in (COORD, HOOKS, WORKTREE)
        for p in d.rglob("*")
        if p.suffix in {".ps1", ".py", ".sh"} and b"mefor-coord" in p.read_bytes()
    }
    # A positive control: a census that found nothing would pass the subset check below.
    assert PY_GUARDED in named
    classified = {*GUARDED, PY_GUARDED, *NOT_GUARDED}
    assert sorted(named - classified) == [], "classify these; guard a writer a cloud VM can reach"
    assert sorted(classified - named) == [], "stale census entries"
