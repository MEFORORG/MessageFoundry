# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The worktree hygiene report: read-only, and its cleanup list proposes only what is safe to remove.

Owner ruling 2026-09-26: a scheduled script with zero model calls reports the primary checkout, every
worktree, installed-hook drift, and a proposed cleanup list for the owner to approve. Nothing is
deleted automatically. The properties pinned here each fail silently:

* **It never runs a destructive verb.** Checked by parsing the script, with a positive control: the
  same scanner must flag a snippet that does run one, or a scanner that finds nothing proves nothing.
* **A worktree with uncommitted or unpushed work never lands in the removal list.** It goes to NEEDS
  A HUMAN LOOK. The removal command it does propose is then run here, in the temp repo, to show that
  git accepts it.
* **Merge status comes from one bulk gh call.** When gh is missing the status is UNKNOWN and nothing
  is proposed; the report never guesses.
* **A shallow clone's ahead/behind is a floor**, and says so; a full clone's is not labelled one.

No test here touches the network: gh is a fake script, and origin is a local bare repository.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "worktree" / "hygiene-report.ps1"
REGISTER = ROOT / "scripts" / "worktree" / "register-hygiene-task.ps1"

pytestmark = [
    pytest.mark.skipif(
        shutil.which("pwsh") is None or os.name != "nt",
        reason="hygiene-report.ps1 needs pwsh on Windows (the shared liveness fence reads Process.StartTime)",
    ),
    pytest.mark.timeout(360),
]

#: Every git verb the report may run. An ALLOWLIST, not a denylist: a new destructive verb nobody
#: thought to list is still caught.
READ_ONLY_GIT_VERBS = frozenset(
    {
        "rev-parse",
        "status",
        "fetch",
        "rev-list",
        "diff",
        "log",
        "ls-remote",
        "merge-base",
        "worktree list",
        "remote get-url",
    }
)
DELETE_CMDLETS = frozenset(
    {"remove-item", "rm", "del", "rmdir", "rd", "ri", "erase", "clear-content", "move-item", "mi"}
)
_TWO_WORD = frozenset({"worktree", "remote", "stash", "branch"})


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    )
    return proc.stdout


def _commit(repo: Path, name: str, text: str) -> str:
    (repo / name).write_text(text, encoding="utf-8")
    _git(repo, "add", "--", name)
    _git(repo, "commit", "-qm", f"add {name}")
    return _git(repo, "rev-parse", "HEAD").strip()


# --------------------------------------------------------------------------------------------------
# Static scan: the script's own source
# --------------------------------------------------------------------------------------------------


def _commands(path: Path) -> list[dict[str, Any]]:
    """Every command invocation in a PowerShell file, from the parser rather than a regex.

    A regex over the text would also match the `git worktree remove` lines the report PRINTS for the
    owner. The AST tells an invocation from a string.
    """
    probe = (
        "$ast = [System.Management.Automation.Language.Parser]::ParseFile("
        f"'{path}', [ref]$null, [ref]$null); "
        "$cmds = $ast.FindAll({ param($n) $n -is "
        "[System.Management.Automation.Language.CommandAst] }, $true) | ForEach-Object { "
        "[pscustomobject]@{ name = $_.GetCommandName(); "
        "elems = @($_.CommandElements | ForEach-Object { $_.Extent.Text }) } }; "
        "ConvertTo-Json -InputObject @($cmds) -Depth 4 -Compress"
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", probe],
        capture_output=True,
        text=True,
        timeout=120,
        check=True,
    )
    parsed: list[dict[str, Any]] = json.loads(proc.stdout)
    return parsed


def _git_verb(elems: list[str]) -> str:
    i = 1
    while i < len(elems):
        e = elems[i]
        if e in ("-C", "-c"):
            i += 2
            continue
        # A splat is skipped as if it were an option. occupancy.ps1 splats `-C <path>` only; the
        # report itself may not splat at all, which the test below asserts separately.
        if e.startswith(("-", "@")):
            i += 1
            continue
        if e in _TWO_WORD and i + 1 < len(elems):
            return f"{e} {elems[i + 1]}"
        return e
    return ""


def _violations(path: Path) -> list[str]:
    bad: list[str] = []
    for c in _commands(path):
        name = (c["name"] or "").lower()
        elems = [str(e) for e in c["elems"]]
        if name in DELETE_CMDLETS:
            bad.append(f"delete cmdlet: {' '.join(elems)}")
        if name == "git":
            verb = _git_verb(elems)
            if verb not in READ_ONLY_GIT_VERBS:
                bad.append(f"git verb {verb!r}: {' '.join(elems)}")
            if verb == "fetch" and any(e in ("--prune", "-p", "--prune-tags") for e in elems):
                bad.append(f"fetch that deletes refs: {' '.join(elems)}")
    return bad


#: What the report dot-sources runs inside it, so it is held to the same rule.
DOT_SOURCED = (
    ROOT / "scripts" / "coord" / "occupancy.ps1",
    ROOT / "scripts" / "coord" / "session-registry.ps1",
)


def test_the_report_runs_no_destructive_git_verb_and_no_delete_cmdlet() -> None:
    assert _violations(SCRIPT) == []
    for helper in DOT_SOURCED:
        assert _violations(helper) == [], helper.name
    git_calls = [c for c in _commands(SCRIPT) if (c["name"] or "").lower() == "git"]
    # A scanner that sees no git call at all would pass the line above against any script.
    assert len(git_calls) >= 8, f"the scan found only {len(git_calls)} git calls"
    splats = [c["elems"] for c in git_calls if any(e.startswith("@") for e in c["elems"])]
    assert splats == [], "a splatted git call hides its verb from this scan"

    # A fetch that may start `gc --auto` expires reflogs and prunes worktree records, and a status
    # that takes optional locks rewrites the index prune-merged.ps1 reads as recent activity.
    fetches = [c for c in git_calls if _git_verb(c["elems"]) == "fetch"]
    assert fetches and all("--no-auto-maintenance" in c["elems"] for c in fetches)
    statuses = [c for c in git_calls if _git_verb(c["elems"]) == "status"]
    assert statuses
    for c in statuses:
        assert "--no-optional-locks" in c["elems"], c["elems"]
        assert "--untracked-files=normal" in c["elems"], c["elems"]


def test_the_scanner_flags_a_script_that_does_run_one(tmp_path: Path) -> None:
    """The positive control: the same scanner, on text that is destructive, must fire on each line."""
    bad = tmp_path / "bad.ps1"
    bad.write_text(
        "\n".join(
            [
                'git -C $root worktree remove "C:/x"',
                "git -C $root reset --hard origin/main",
                "git checkout main",
                "git -C $root push origin main",
                "git clean -fdx",
                "git -C $root fetch --prune origin",
                "Remove-Item -Recurse C:/x",
                # A printed string must NOT count: the report prints exactly this for the owner.
                "Write-Output 'git worktree remove C:/y'",
            ]
        ),
        encoding="utf-8",
    )
    found = _violations(bad)
    assert len(found) == 7, found
    assert not any("C:/y" in f for f in found), "a printed string was read as an invocation"


def test_hook_status_is_always_called_with_the_status_switch() -> None:
    """The installer's bare invocation INSTALLS hooks. The report may only ever run -Status."""
    calls = [c for c in _commands(SCRIPT) if "$installer" in c["elems"] and "-File" in c["elems"]]
    assert calls, "the report no longer calls the hook installer"
    for c in calls:
        assert "-Status" in c["elems"], c["elems"]


def test_gh_is_only_asked_to_list() -> None:
    calls = [c for c in _commands(SCRIPT) if c["elems"] and c["elems"][0] == "$Gh"]
    assert len(calls) == 1, "exactly one gh call site, so one call per clone per run"
    assert calls[0]["elems"][1:3] == ["pr", "list"]


# --------------------------------------------------------------------------------------------------
# Running it against a temp repository family
# --------------------------------------------------------------------------------------------------


@dataclass
class Fx:
    root: Path
    origin: Path
    primary: Path
    cfg: Path
    out: Path
    merged: list[dict[str, Any]] = field(default_factory=list)
    paths: dict[str, Path] = field(default_factory=dict)


def _iso(delta: timedelta) -> str:
    return (datetime.now(UTC) - delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _build(tmp: Path) -> Fx:
    origin = tmp / "origin.git"
    subprocess.run(
        ["git", "init", "-q", "--bare", "-b", "main", str(origin)], check=True, capture_output=True
    )
    primary = tmp / "wt" / "repo"
    primary.mkdir(parents=True)
    _git(primary, "init", "-q", "-b", "main")
    _git(primary, "config", "user.email", "t@example.invalid")
    _git(primary, "config", "user.name", "t")
    _git(primary, "remote", "add", "origin", str(origin))
    _commit(primary, "seed.txt", "seed")
    _commit(primary, ".gitignore", ".venv/\n")
    _git(primary, "push", "-q", "origin", "main")

    fx = Fx(tmp, origin, primary, tmp / "cfg", tmp / "out")
    # The liveness fence needs one readable record to be AVAILABLE. A dead pid in a directory that is
    # no checkout: examined, placed nowhere, vetoes nothing.
    (fx.cfg / "sessions").mkdir(parents=True)
    elsewhere = tmp / "elsewhere"
    elsewhere.mkdir()
    (fx.cfg / "sessions" / "999999.json").write_text(
        json.dumps({"pid": 999999, "sessionId": "dead0000-0000", "cwd": str(elsewhere)}),
        encoding="utf-8",
    )

    def worktree(
        slug: str, *, merged_ago: timedelta | None, base: str = "main", fork: bool = False
    ) -> str:
        path = primary.parent / f"repo-{slug}"
        _git(primary, "worktree", "add", "-q", "-b", slug, str(path))
        head = _commit(path, f"{slug}.txt", slug)
        _git(path, "push", "-q", "origin", slug)
        fx.paths[slug] = path
        if merged_ago is not None:
            fx.merged.append(
                {
                    "headRefName": slug,
                    "headRefOid": head,
                    "number": 100 + len(fx.merged),
                    "mergedAt": _iso(merged_ago),
                    "baseRefName": base,
                    "isCrossRepository": fork,
                }
            )
        return head

    old = timedelta(days=3)
    # Merged, clean, pushed; its remote branch was deleted on merge, so only the PR head proves it.
    worktree("m-clean", merged_ago=old)
    _git(primary, "push", "-q", "origin", "--delete", "m-clean")
    # Merged and clean, with a gitignored .venv: git does not list it, so no --force is needed.
    worktree("m-venv", merged_ago=old)
    (fx.paths["m-venv"] / ".venv").mkdir()
    (fx.paths["m-venv"] / ".venv" / "pyvenv.cfg").write_text("home = x\n", encoding="utf-8")
    # Merged, with an uncommitted edit.
    worktree("m-dirty", merged_ago=old)
    (fx.paths["m-dirty"] / "seed.txt").write_text("edited, never committed", encoding="utf-8")
    # Merged, then a local commit nobody pushed.
    worktree("m-unpushed", merged_ago=old)
    _commit(fx.paths["m-unpushed"], "later.txt", "work after the merge")
    # Merged an hour ago: inside the hold.
    worktree("m-recent", merged_ago=timedelta(hours=1))
    # Pushed, never merged.
    worktree("wip", merged_ago=None)
    # Merged, then more commits pushed to the same branch: the name matches, the tip does not.
    worktree("m-moved", merged_ago=old)
    _commit(fx.paths["m-moved"], "follow-up.txt", "work that PR did not land")
    _git(fx.paths["m-moved"], "push", "-q", "origin", "m-moved")
    # A fork PR whose head name collides with ours, and a PR stacked onto another branch.
    worktree("m-fork", merged_ago=old, fork=True)
    worktree("m-stacked", merged_ago=old, base="feature")
    return fx


def _fake_gh(fx: Fx) -> tuple[Path, Path]:
    payload = fx.root / "gh-payload.json"
    payload.write_text(json.dumps(fx.merged), encoding="utf-8")
    log = fx.root / "gh-calls.log"
    fake = fx.root / "fake-gh.ps1"
    fake.write_text(
        f"Add-Content -LiteralPath '{log}' -Value ($args -join ' ')\n"
        f"Get-Content -Raw -LiteralPath '{payload}'\n"
        "exit 0\n",
        encoding="utf-8",
    )
    return fake, log


def _run(
    fx: Fx, *extra: str, repo: Path | None = None, idle: str = "0"
) -> subprocess.CompletedProcess[str]:
    """Run the report. Every fixture worktree was touched seconds ago, so the activity window is
    OFF by default here; the test that pins the window turns it back on."""
    env = {k: v for k, v in os.environ.items() if k != "MEFOR_HYGIENE_GH"}
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(SCRIPT),
            "-RepoRoot",
            str(repo or fx.primary),
            "-OutDir",
            str(fx.out),
            "-ConfigRoot",
            str(fx.cfg),
            "-NoExtraRoots",
            "-IdleHours",
            idle,
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
        env=env,
    )


def _report(fx: Fx) -> dict[str, Any]:
    parsed: dict[str, Any] = json.loads((fx.out / "latest.json").read_text(encoding="utf-8"))
    return parsed


def _rows(rep: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {Path(w["path"]).name: w for w in rep["clones"][0]["worktrees"]}


@pytest.fixture
def fx(tmp_path: Path) -> Fx:
    return _build(tmp_path)


def test_it_writes_both_files_and_proposes_only_the_safe_removals(fx: Fx) -> None:
    fake, log = _fake_gh(fx)
    proc = _run(fx, "-Gh", str(fake), "-GhRepo", "acme/repo")
    assert proc.returncode == 0, proc.stderr

    stamp = datetime.now().strftime("%Y-%m-%d")
    for name in (f"hygiene-{stamp}.md", f"hygiene-{stamp}.json", "latest.md", "latest.json"):
        assert (fx.out / name).is_file(), f"missing {name}; wrote {sorted(os.listdir(fx.out))}"
    assert "Report written:" in proc.stdout

    # One bulk call, not one per worktree.
    calls = log.read_text(encoding="utf-8").splitlines()
    assert len(calls) == 1, calls
    assert calls[0].startswith("pr list --repo acme/repo --state merged")

    rep = _report(fx)
    rows = _rows(rep)
    assert rows["repo-m-clean"]["verdict"] == "REMOVE"
    assert rows["repo-m-clean"]["remoteBranchExists"] is False
    assert rows["repo-m-venv"]["verdict"] == "REMOVE"
    assert "--force" not in rows["repo-m-venv"]["command"], "a gitignored .venv needs no --force"
    assert rows["repo-m-dirty"]["verdict"] == "HUMAN"
    assert any("uncommitted" in r for r in rows["repo-m-dirty"]["reasons"])
    assert rows["repo-m-unpushed"]["verdict"] == "HUMAN"
    assert any("unpushed" in r for r in rows["repo-m-unpushed"]["reasons"])
    assert rows["repo-m-recent"]["verdict"] == "HUMAN"
    assert any("hold" in r for r in rows["repo-m-recent"]["reasons"])
    assert rows["repo-wip"]["merge"] == "NOT MERGED"
    assert rows["repo-wip"]["verdict"] == "KEEP"
    # A name match is not enough: the tip moved on after the merge.
    assert rows["repo-m-moved"]["merge"] == "MERGED"
    assert rows["repo-m-moved"]["verdict"] == "HUMAN"
    assert any("did not land" in r for r in rows["repo-m-moved"]["reasons"])
    # A fork's PR and a stacked PR did not land this branch on main.
    assert rows["repo-m-fork"]["merge"] == "NOT MERGED"
    assert rows["repo-m-stacked"]["merge"] == "NOT MERGED"

    clone = rep["clones"][0]
    removal = {Path(w["path"]).name for w in clone["cleanup"]["remove"]}
    human = {Path(w["path"]).name for w in clone["cleanup"]["human"]}
    assert removal == {"repo-m-clean", "repo-m-venv"}
    assert {"repo-m-dirty", "repo-m-unpushed", "repo-m-recent"} <= human
    assert not removal & human

    # The markdown's command block carries the same two, and never the dirty tree.
    md = (fx.out / "latest.md").read_text(encoding="utf-8")
    block = md.split("### d.", 1)[1].split("```powershell", 1)[1].split("```", 1)[0]
    assert "repo-m-clean" in block and "repo-m-venv" in block
    assert "repo-m-dirty" not in block and "repo-m-unpushed" not in block
    assert "NEEDS A HUMAN LOOK" in md

    # The report changed nothing: every worktree is still registered and still on disk.
    listed = _git(fx.primary, "worktree", "list", "--porcelain")
    for path in fx.paths.values():
        assert path.is_dir()
        assert path.as_posix() in listed

    # And the command it proposed is one git accepts, .venv included, pasted into PowerShell as the
    # report tells the owner to.
    for w in clone["cleanup"]["remove"]:
        subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", w["command"]],
            check=True,
            capture_output=True,
            timeout=120,
        )
        assert not Path(w["path"]).exists()


def test_recent_git_activity_holds_a_merged_worktree_back(fx: Fx) -> None:
    """Every fixture worktree was committed to seconds ago. Inside the default 72 h window none of
    them is proposed; with the window off, the same fixture proposes the clean one (the control)."""
    fake, _ = _fake_gh(fx)
    proc = _run(fx, "-Gh", str(fake), "-GhRepo", "acme/repo", idle="72")
    assert proc.returncode == 0, proc.stderr
    rows = _rows(_report(fx))
    assert rows["repo-m-clean"]["verdict"] == "HUMAN"
    assert any("idle window" in r for r in rows["repo-m-clean"]["reasons"])

    proc = _run(fx, "-Gh", str(fake), "-GhRepo", "acme/repo")
    assert proc.returncode == 0, proc.stderr
    assert _rows(_report(fx))["repo-m-clean"]["verdict"] == "REMOVE"


def test_without_gh_merge_status_is_unknown_and_nothing_is_proposed(fx: Fx) -> None:
    proc = _run(fx, "-Gh", "no-such-gh-command-zz9", "-GhRepo", "acme/repo")
    assert proc.returncode == 0, proc.stderr
    clone = _report(fx)["clones"][0]
    assert clone["gh"]["available"] is False
    assert "unavailable" in clone["gh"]["detail"]
    assert {w["merge"] for w in clone["worktrees"]} == {"UNKNOWN"}
    assert clone["cleanup"]["remove"] == []
    assert "merge status UNKNOWN" in (fx.out / "latest.md").read_text(encoding="utf-8")


def test_a_shallow_clone_labels_ahead_behind_a_floor(fx: Fx, tmp_path: Path) -> None:
    shallow = tmp_path / "shallow"
    subprocess.run(
        ["git", "clone", "-q", "--depth", "1", fx.origin.as_uri(), str(shallow)],
        check=True,
        capture_output=True,
    )
    # origin/main moves on after the shallow clone was cut.
    _commit(fx.primary, "more1.txt", "1")
    _commit(fx.primary, "more2.txt", "2")
    _git(fx.primary, "push", "-q", "origin", "main")

    proc = _run(fx, "-SkipGh", repo=shallow)
    assert proc.returncode == 0, proc.stderr
    p = _report(fx)["clones"][0]["primary"]
    assert p["shallow"] is True
    assert p["countIsFloor"] is True
    assert p["behind"] == 2
    md = (fx.out / "latest.md").read_text(encoding="utf-8")
    assert "at least 2 behind" in md and "floor" in md

    # The control: the full clone is not labelled a floor.
    proc = _run(fx, "-SkipGh")
    assert proc.returncode == 0, proc.stderr
    p = _report(fx)["clones"][0]["primary"]
    assert p["shallow"] is False
    assert p["countIsFloor"] is False
    assert "floor" not in (fx.out / "latest.md").read_text(encoding="utf-8").split("### b.")[0]


def test_the_report_does_not_touch_a_worktrees_index(fx: Fx) -> None:
    """prune-merged.ps1 reads the index mtime as recent activity; a report must not look like a session.

    A tracked file whose mtime moved makes `git status` want to refresh the index. The paired arm
    below shows that plain `git status` DOES rewrite it here, so the first assertion is not vacuous.
    """
    wt = fx.paths["m-clean"]
    index = Path(_git(wt, "rev-parse", "--git-path", "index").strip())
    if not index.is_absolute():
        index = wt / index
    later = time.time() + 5
    os.utime(wt / "m-clean.txt", (later, later))
    before = index.stat().st_mtime_ns

    proc = _run(fx, "-SkipGh", "-SkipFetch")
    assert proc.returncode == 0, proc.stderr
    assert index.stat().st_mtime_ns == before, "the report rewrote a worktree's index"

    time.sleep(1.1)
    _git(wt, "status", "--porcelain")
    assert index.stat().st_mtime_ns != before, "control: plain git status should refresh this index"


@pytest.fixture
def sleeper() -> Iterator[int]:
    """A pid the fence reads as LIVE: started within a second of the record written for it."""
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(900)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=30)


def test_a_session_in_a_merged_clean_worktree_holds_it_back(fx: Fx, sleeper: int) -> None:
    (fx.cfg / "sessions" / f"{sleeper}.json").write_text(
        json.dumps(
            {
                "pid": sleeper,
                "sessionId": "cafe0001-0000",
                "cwd": str(fx.paths["m-venv"]),
                "startedAt": int(time.time() * 1000),
            }
        ),
        encoding="utf-8",
    )
    fake, _ = _fake_gh(fx)
    proc = _run(fx, "-Gh", str(fake), "-GhRepo", "acme/repo")
    assert proc.returncode == 0, proc.stderr
    rows = _rows(_report(fx))
    assert rows["repo-m-venv"]["verdict"] == "HUMAN"
    assert any("session is in it" in r for r in rows["repo-m-venv"]["reasons"])
    # The control in the same run: the unoccupied twin is still proposed.
    assert rows["repo-m-clean"]["verdict"] == "REMOVE"


def test_a_dead_session_record_in_a_worktree_holds_it_back(fx: Fx) -> None:
    """DEAD is no veto, but removing the tree would leave the record unplaceable, and occupancy.ps1
    then switches the fence off for every later run."""
    (fx.cfg / "sessions" / "999998.json").write_text(
        json.dumps({"pid": 999998, "sessionId": "dead1111-0000", "cwd": str(fx.paths["m-venv"])}),
        encoding="utf-8",
    )
    fake, _ = _fake_gh(fx)
    proc = _run(fx, "-Gh", str(fake), "-GhRepo", "acme/repo")
    assert proc.returncode == 0, proc.stderr
    rows = _rows(_report(fx))
    assert rows["repo-m-venv"]["verdict"] == "HUMAN"
    assert any("session record" in r for r in rows["repo-m-venv"]["reasons"])
    assert rows["repo-m-clean"]["verdict"] == "REMOVE"
    assert (fx.out / "last-run.txt").read_text(encoding="utf-8").startswith("OK ")


def test_hook_drift_is_read_through_the_installers_status_mode(fx: Fx) -> None:
    installer = fx.primary / "scripts" / "coord" / "install-git-hooks.ps1"
    installer.parent.mkdir(parents=True)
    installer.write_text(
        "Write-Host \"args: $($args -join ' ')\"\n"
        "Write-Host 'payload    : push_guard.py  installed aaaa / source bbbb'\n"
        "Write-Host '             ^ *** STALE *** the payload that RUNS differs'\n",
        encoding="utf-8",
    )
    proc = _run(fx, "-SkipGh", "-SkipFetch")
    assert proc.returncode == 0, proc.stderr
    hooks = _report(fx)["clones"][0]["hooks"]
    assert hooks["ran"] is True
    assert "args: -Status" in hooks["output"]
    assert any("STALE" in line for line in hooks["flagged"])
    assert not any("installed aaaa" in line for line in hooks["flagged"])
    assert str(installer) in hooks["rearm"]
    # The engine's installer INSTALLS on a bare run, so its remedy carries no -Arm.
    assert not hooks["rearm"].endswith("-Arm")


def test_a_vault_style_installer_gets_arm_in_its_remedy(fx: Fx) -> None:
    """The vault's installer only reports on a bare run and needs -Arm to write. Its remedy must say
    so; the paired arm above shows the engine's does not."""
    installer = fx.primary / "scripts" / "coord" / "install-git-hooks.ps1"
    installer.parent.mkdir(parents=True)
    installer.write_text(
        "param([switch]$Arm, [switch]$Status)\nWrite-Host 'payload : STALE'\n", encoding="utf-8"
    )
    proc = _run(fx, "-SkipGh", "-SkipFetch")
    assert proc.returncode == 0, proc.stderr
    rep = _report(fx)
    assert rep["clones"][0]["hooks"]["rearm"].endswith(" -Arm")
    md = (fx.out / "latest.md").read_text(encoding="utf-8")
    assert md.startswith("# Worktree hygiene report\n\n**Generated ")


# --------------------------------------------------------------------------------------------------
# The registration script: plan only. Nothing here registers a task.
# --------------------------------------------------------------------------------------------------


def _register(*args: str, claudecode: bool) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}
    if claudecode:
        env["CLAUDECODE"] = "1"
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(REGISTER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env=env,
    )


def test_the_task_runs_the_primarys_copy_every_six_hours_by_default() -> None:
    proc = _register("-Json", claudecode=True)
    assert proc.returncode == 0, proc.stderr
    plan = json.loads(proc.stdout)
    report = Path(plan["report"])
    assert report.name == "hygiene-report.ps1"
    assert ".claude" not in report.parts, f"a worktree copy dies with the worktree: {report}"
    assert plan["trigger"]["everyHours"] == 6
    assert plan["runLevel"] == "Limited"
    assert plan["deletesAnything"] is False
    assert "-Apply" not in plan["argument"]

    plan12 = json.loads(_register("-Json", "-EveryHours", "12", claudecode=True).stdout)
    assert plan12["trigger"]["everyHours"] == 12


def test_registration_and_removal_refuse_inside_claude_code() -> None:
    proc = _register(claudecode=True)
    assert proc.returncode == 2
    assert "Claude Code" in proc.stderr

    proc = _register(
        "-Unregister", "-TaskName", "MEFOR-Worktree-Hygiene-TestProbe", claudecode=True
    )
    assert proc.returncode == 2
    assert "Claude Code" in proc.stderr
