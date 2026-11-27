# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""branch-leak-scan.yml scans every commit off main, not only the tip (BACKLOG #5595).

The scan step's shipped ``run:`` body is EXECUTED under ``bash -e`` inside a throwaway git repository,
with ``python`` replaced by a stub scanner that reports any file carrying a synthetic marker. The
regression row is a branch whose first pushed commit adds the marker and whose second removes it: the
tip tree is clean, so a tip-only scan passes, while the content stays public by SHA. A second row
(BACKLOG #8244 item 63) is a later push whose earlier push's run never finished: step 2 rescans what
``before`` reaches off main, so it still finds the earlier commit.

The stub stands in for ``scan_forbidden.py`` only, so these rows measure how the step picks and lays
out what to scan, never the scanner's detectors.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest
from _bash_resolver import probe_env, require_bash

from tests._workflow_contexts import jobs_of, load_workflow

_REPO = Path(__file__).resolve().parents[1]

_WORKFLOW = "branch-leak-scan.yml"
_STEP = "Scan the pushed tree and every pushed commit for forbidden content"
_STEP2 = "Rescan the commits earlier pushes added"
_SENTINEL = ".github/workflows/branch-leak-scan.yml"
_ZERO = "0" * 40
_MARKER = "SYNTHETIC-LEAK-MARKER"

#: Reports each scanned file holding the marker, by its path relative to the scan root it came from,
#: and exits 1 on any hit. Every call's arguments are logged so a row can tell the tip scan from the
#: range scan. A named root that does not exist exits 2, as the real scanner's unreadable path does.
_STUB = f"""#!/usr/bin/env bash
shift
echo "$*" >> "$SCAN_LOG"
[ "$1" = "--path" ] || exit 9
shift
hit=0
for root in "$@"; do
  [ -e "$root" ] || {{ echo "missing root $root" >&2; exit 2; }}
  while IFS= read -r -d '' f; do
    if grep -q '{_MARKER}' "$f"; then echo "HIT ${{f#"$root"/}}"; hit=1; fi
  done < <(find "$root" -path "$root/.git" -prune -o -type f -print0)
done
exit $hit
"""


def _steps() -> list[dict]:
    return jobs_of(_WORKFLOW)["branch-leak-scan"]["steps"]


def _step(name: str) -> dict:
    matches = [s for s in _steps() if s.get("name") == name]
    assert len(matches) == 1, f"expected one step named {name!r}, found {len(matches)}"
    return matches[0]


def _body(name: str = _STEP) -> str:
    body = str(_step(name)["run"])
    assert "${{" not in body, "the scan body interpolates an Actions expression"
    return body


def _git(repo: Path, *args: str) -> str:
    out = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True, timeout=60
    )
    return out.stdout.strip()


def _commit(repo: Path, message: str, files: dict[str, str | None]) -> str:
    for rel, content in files.items():
        target = repo / rel
        if content is None:
            _git(repo, "rm", "-q", rel)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        _git(repo, "add", rel)
    _git(repo, "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


class _Repo:
    def __init__(self, tmp_path: Path) -> None:
        self.path = tmp_path / "repo"
        self.path.mkdir()
        _git(self.path, "init", "-q", "-b", "main")
        _git(self.path, "config", "user.email", "test@example.invalid")
        _git(self.path, "config", "user.name", "test")
        _git(self.path, "config", "core.autocrlf", "false")
        # Step 2 names the workflow file as its always-text root, so the stand-in repo carries one.
        self.main = _commit(
            self.path, "base", {"README.md": "clean\n", _SENTINEL: "name: stand-in\n"}
        )
        _git(self.path, "update-ref", "refs/remotes/origin/main", self.main)
        _git(self.path, "switch", "-q", "-c", "feature")


@pytest.fixture(scope="module")
def bash(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Resolved once per module: the resolver's probes spawn several shells, and on a loaded Windows
    box that cost per row pushed the merge row past the per-test timeout."""
    return require_bash(tmp_path_factory.mktemp("bash-probe"))


def _run_steps(
    bash: str, repo: Path, tmp_path: Path, before: str, after: str, *, steps: tuple[str, ...] = ()
) -> tuple[list[int], str, list[str]]:
    """Run step 1 then step 2, as the job does: step 2 runs whatever step 1 returned."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "python"
    stub.write_text(_STUB, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    log = tmp_path / "scan.log"
    log.write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    env = probe_env(Path(bash), dict(os.environ))
    env.update(
        {
            "MEFOR_FORBIDDEN_TOKENS": "synthetic",
            "PUSH_BEFORE": before,
            "PUSH_AFTER": after,
            "RUNNER_TEMP": runner_temp.as_posix(),
            "SCAN_LOG": log.as_posix(),
            "PATH": f"{stub_dir.as_posix()}{os.pathsep}{env.get('PATH', '')}",
        }
    )
    # The stub must WIN, not merely be first on PATH: Git for Windows' bash can reorder PATH, and a
    # real python here would run a real scanner against nothing (BACKLOG #1216).
    which = subprocess.run(
        [bash, "-c", "command -v python"], capture_output=True, text=True, timeout=60, env=env
    ).stdout.strip()
    assert stub_dir.name in which.replace("\\", "/"), f"the python stub lost to {which!r}"
    rcs: list[int] = []
    out = ""
    for i, name in enumerate(steps or (_STEP, _STEP2)):
        script = tmp_path / f"step{i}.sh"
        script.write_text(_body(name), encoding="utf-8", newline="\n")
        proc = subprocess.run(
            [bash, "-e", script.as_posix()],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=120,
            env=env,
        )
        rcs.append(proc.returncode)
        out += proc.stdout + proc.stderr
    calls = log.read_text(encoding="utf-8").splitlines()
    return rcs, out, calls


def _run(
    bash: str, repo: Path, tmp_path: Path, before: str, after: str
) -> tuple[int, str, list[str]]:
    """The job's verdict: red when either step is, with step 1's code first."""
    rcs, out, calls = _run_steps(bash, repo, tmp_path, before, after)
    return next((rc for rc in rcs if rc), 0), out, calls


def _leak_then_remove(repo: _Repo) -> tuple[str, str]:
    leaked = _commit(repo.path, "add", {"docs/security/note.md": f"{_MARKER}\n"})
    removed = _commit(repo.path, "remove", {"docs/security/note.md": None})
    return leaked, removed


def test_content_added_then_removed_in_one_push_is_found(bash: str, tmp_path: Path) -> None:
    """THE REGRESSION ROW: the tip is clean, the first pushed commit is not."""
    repo = _Repo(tmp_path)
    _leaked, removed = _leak_then_remove(repo)
    rc, out, calls = _run(bash, repo.path, tmp_path, repo.main, removed)
    assert len(calls) == 1 and calls[0].startswith("--path . "), f"one scan, tip first: {calls}"
    assert rc == 1, f"rc={rc}; the pushed range was not scanned\n{out}"
    # The path stays repository-relative inside each commit's scan root, so a path detector keyed on
    # docs/security/ would still match.
    assert "HIT docs/security/note.md" in out, out


def test_a_new_branch_scans_everything_not_on_main(bash: str, tmp_path: Path) -> None:
    repo = _Repo(tmp_path)
    _leaked, removed = _leak_then_remove(repo)
    rc, out, calls = _run(bash, repo.path, tmp_path, _ZERO, removed)
    assert rc == 1, f"rc={rc}\n{out}"
    assert len(calls) == 1, f"step 1 already walked everything, so step 2 has nothing: {calls}"
    assert "step 2, earlier pushes: 0 commit(s)" in out, out


def test_a_force_push_with_an_unknown_before_falls_back_to_main(bash: str, tmp_path: Path) -> None:
    repo = _Repo(tmp_path)
    _leaked, removed = _leak_then_remove(repo)
    rc, out, calls = _run(bash, repo.path, tmp_path, "f" * 40, removed)
    assert rc == 1, f"rc={rc}\n{out}"
    assert len(calls) == 1, f"step 1 already walked everything, so step 2 has nothing: {calls}"


def test_a_later_push_rescans_an_earlier_push_whose_run_never_finished(
    bash: str, tmp_path: Path
) -> None:
    """BACKLOG #8244 item 63: the leak was the earlier push's, and that push's run errored, timed out
    or never started. A ``before..after`` range began after it, so no run ever scanned it. Step 1 is
    this push's commits with the tip, step 2 the earlier ones, in that order."""
    repo = _Repo(tmp_path)
    leaked, removed = _leak_then_remove(repo)
    rc, out, calls = _run(bash, repo.path, tmp_path, leaked, removed)
    assert rc == 1, f"rc={rc}; the earlier push's commit was not rescanned\n{out}"
    assert "HIT docs/security/note.md" in out, out
    assert len(calls) == 2, calls
    assert calls[0] == "--path .", f"step 1 adds nothing but the tip: {calls}"
    assert calls[1].startswith(f"--path {_SENTINEL} ") and leaked in calls[1], calls


def test_each_step_reports_its_own_range(bash: str, tmp_path: Path) -> None:
    """Step 1's verdict is its own step's conclusion, never deferred behind step 2's."""
    repo = _Repo(tmp_path)
    leaked, removed = _leak_then_remove(repo)
    after = _commit(repo.path, "again", {"b.txt": f"{_MARKER}\n"})
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, removed, after)
    assert rcs == [1, 1], f"rcs={rcs}\n{out}"
    assert len(calls) == 2 and after in calls[0] and leaked in calls[1], calls
    assert "HIT b.txt" in out and "HIT docs/security/note.md" in out, out


def test_a_step_one_hit_with_clean_earlier_pushes_reds_only_step_one(
    bash: str, tmp_path: Path
) -> None:
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    after = _commit(repo.path, "two", {"b.txt": f"{_MARKER}\n"})
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, first, after)
    assert rcs == [1, 0], f"rcs={rcs}\n{out}"


def test_step_two_without_step_one_s_record_fails_closed(bash: str, tmp_path: Path) -> None:
    """No recorded range is not an empty range."""
    repo = _Repo(tmp_path)
    leaked, removed = _leak_then_remove(repo)
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, leaked, removed, steps=(_STEP2,))
    assert rcs == [2] and not calls, f"rcs={rcs}, calls={calls}\n{out}"


def test_step_two_runs_after_a_failed_step_one_under_its_own_timeout() -> None:
    names = [s.get("name") for s in _steps()]
    assert names.index(_STEP2) == names.index(_STEP) + 1, names
    step2 = _step(_STEP2)
    assert step2.get("if") == "${{ !cancelled() }}", step2.get("if")
    job_limit = jobs_of(_WORKFLOW)["branch-leak-scan"]["timeout-minutes"]
    assert 0 < step2["timeout-minutes"] < job_limit, (step2.get("timeout-minutes"), job_limit)


def test_a_clean_branch_with_earlier_pushes_passes(bash: str, tmp_path: Path) -> None:
    """The discriminating PASS for step 2: a step 2 that always failed would satisfy the rows above."""
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    after = _commit(repo.path, "two", {"b.txt": "y\n"})
    rc, out, calls = _run(bash, repo.path, tmp_path, first, after)
    assert rc == 0, f"rc={rc}\n{out}"
    assert len(calls) == 2 and after in calls[0] and first in calls[1], calls
    assert "step 2, earlier pushes: 1 commit(s) walked" in out, out


def test_a_force_push_with_a_known_before_rescans_the_dropped_commits(
    bash: str, tmp_path: Path
) -> None:
    """The dropped commits stay public by SHA, and while the old head is here step 2 reaches them."""
    repo = _Repo(tmp_path)
    old = _commit(repo.path, "leak", {"docs/security/note.md": f"{_MARKER}\n"})
    _git(repo.path, "reset", "-q", "--hard", repo.main)
    after = _commit(repo.path, "rewritten", {"a.txt": "x\n"})
    rc, out, calls = _run(bash, repo.path, tmp_path, old, after)
    assert rc == 1 and "HIT docs/security/note.md" in out, f"rc={rc}\n{out}"
    assert len(calls) == 2 and after in calls[0] and old in calls[1], calls


def test_a_clean_push_passes_and_scans_its_commits(bash: str, tmp_path: Path) -> None:
    """The discriminating PASS: a step that always failed would satisfy the rows above."""
    repo = _Repo(tmp_path)
    after = _commit(repo.path, "clean", {"src/a.py": "x = 1\n"})
    rc, out, calls = _run(bash, repo.path, tmp_path, repo.main, after)
    assert rc == 0, f"rc={rc}\n{out}"
    assert len(calls) == 1 and calls[0].startswith("--path . ") and after in calls[0], calls


def test_a_merge_commit_is_scanned_against_its_first_parent(bash: str, tmp_path: Path) -> None:
    """Content a merge itself introduces (an evil merge) is in no other commit's diff."""
    repo = _Repo(tmp_path)
    _git(repo.path, "switch", "-q", "-c", "side", repo.main)
    _commit(repo.path, "side", {"side.txt": "side\n"})
    _git(repo.path, "switch", "-q", "feature")
    _commit(repo.path, "feature", {"feature.txt": "feature\n"})
    _git(repo.path, "merge", "-q", "--no-ff", "--no-commit", "side")
    (repo.path / "merge-only.txt").write_text(f"{_MARKER}\n", encoding="utf-8")
    _git(repo.path, "add", "merge-only.txt")
    _git(repo.path, "commit", "-q", "-m", "merge")
    merged = _git(repo.path, "rev-parse", "HEAD")
    _git(repo.path, "rm", "-q", "merge-only.txt")
    _git(repo.path, "commit", "-q", "-m", "drop")
    after = _git(repo.path, "rev-parse", "HEAD")
    rc, out, _ = _run(bash, repo.path, tmp_path, repo.main, after)
    assert rc == 1 and "HIT merge-only.txt" in out, f"rc={rc}, merge {merged}\n{out}"


def test_a_deleted_branch_scans_nothing(bash: str, tmp_path: Path) -> None:
    repo = _Repo(tmp_path)
    rc, out, _ = _run(bash, repo.path, tmp_path, repo.main, _ZERO)
    assert rc == 0, f"rc={rc}\n{out}"


@pytest.mark.parametrize("bad", ["", "not-a-sha", "ABC123"])
@pytest.mark.parametrize("side", ["before", "after"])
def test_a_malformed_push_sha_fails_closed(side: str, bad: str, bash: str, tmp_path: Path) -> None:
    repo = _Repo(tmp_path)
    head = _git(repo.path, "rev-parse", "HEAD")
    before, after = (bad, head) if side == "before" else (repo.main, bad)
    rc, out, calls = _run(bash, repo.path, tmp_path, before, after)
    assert rc == 2 and not calls, f"rc={rc}, calls={calls}\n{out}"
    assert "step 1 recorded no earlier range" in out, out


def test_no_push_scan_is_cancelled_by_a_later_one() -> None:
    """A force-push can drop the earlier commits from the branch, so a cancelled run's commits may be
    reached by no later run, and a per-ref group without cancel-in-progress still drops an older
    PENDING run. So no group at all."""
    doc = load_workflow(_WORKFLOW)
    assert "concurrency" not in doc, doc.get("concurrency")
    assert all("concurrency" not in job for job in jobs_of(_WORKFLOW).values())


def test_an_orphan_branch_root_commit_is_scanned(bash: str, tmp_path: Path) -> None:
    """A root commit has no parent to diff against. The orphan branch is the realistic leak shape: a
    branch cut from another history, whose first commit can carry what a later commit removes."""
    repo = _Repo(tmp_path)
    _git(repo.path, "switch", "-q", "--orphan", "orphan")
    _commit(repo.path, "root", {"docs/security/note.md": f"{_MARKER}\n"})
    after = _commit(repo.path, "remove", {"docs/security/note.md": None, "a.txt": "x\n"})
    rc, out, _ = _run(bash, repo.path, tmp_path, _ZERO, after)
    assert rc == 1 and "HIT docs/security/note.md" in out, f"rc={rc}\n{out}"


def test_a_push_touching_only_skipped_dirs_is_not_a_refusal(bash: str, tmp_path: Path) -> None:
    """The scanner skips these directories and refuses a scan that examined nothing, so the step must
    not hand it a root holding only skipped files (a rebuilt dist/ bundle, say)."""
    repo = _Repo(tmp_path)
    after = _commit(repo.path, "bundle", {"tool/dist/index.js": "x\n"})
    rc, out, calls = _run(bash, repo.path, tmp_path, repo.main, after)
    assert rc == 0, f"rc={rc}\n{out}"
    assert len(calls) == 1 and after in calls[0], calls


def test_a_committed_real_token_list_is_a_hit(bash: str, tmp_path: Path) -> None:
    """The scanner exempts this path for working-tree scans; in a pushed commit it is the leak."""
    repo = _Repo(tmp_path)
    _commit(repo.path, "oops", {"scripts/security/scan-tokens.local.txt": "x\n"})
    after = _commit(repo.path, "undo", {"scripts/security/scan-tokens.local.txt": None})
    rc, out, _ = _run(bash, repo.path, tmp_path, repo.main, after)
    assert rc == 1 and "scan-tokens.local.txt" in out, f"rc={rc}\n{out}"


def test_checkout_fetches_full_history() -> None:
    checkout = next(s for s in _steps() if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"].get("fetch-depth") == 0, checkout
