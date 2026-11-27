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
import re
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
from _bash_resolver import probe_env, require_bash

from tests._workflow_contexts import jobs_of, load_workflow

_REPO = Path(__file__).resolve().parents[1]

_WORKFLOW = "branch-leak-scan.yml"
_STEP = "Scan the pushed tree and every pushed commit for forbidden content"
_STEP2 = "Rescan the commits earlier pushes added"
_STEP3 = "Name the commit behind each scan hit"
_SENTINEL = ".github/workflows/branch-leak-scan.yml"
_ZERO = "0" * 40
_MARKER = "SYNTHETIC-LEAK-MARKER"

#: Reports each scanned file holding the marker, by its path relative to the scan root it came from,
#: and exits 1 on any hit. Every call's arguments are logged so a row can tell the tip scan from the
#: range scan, and the detector floor it ran under goes to a second log. A named root that does not
#: exist exits 2, as the real scanner's unreadable path does.
_STUB = f"""#!/usr/bin/env bash
shift
echo "$*" >> "$SCAN_LOG"
echo "${{MEFOR_REQUIRE_TOKENS:-unset}} ${{MEFOR_MIN_DETECTORS:-unset}}" >> "$SCAN_LOG.env"
[ "$1" = "--path" ] || exit 9
shift
hit=0
for root in "$@"; do
  [ -e "$root" ] || {{ echo "missing root $root" >&2; exit 2; }}
  while IFS= read -r -d '' f; do
    if grep -q '{_MARKER}' "$f"; then echo "HIT ${{f#"$root"/}}"; hit=1; fi
  done < <(find "$root" -path "$root/.git" -prune -o -type f -print0)
done
if [ "$hit" = 1 ] && [ -n "${{STUB_ECHO:-}}" ]; then echo "$STUB_ECHO"; fi
exit $hit
"""

#: Stands in for git so a row can kill step 1 partway through listing the earlier range: the
#: ``rev-list`` whose first argument is ``$FAIL_REVLIST`` prints only its first line, then exits 128,
#: as a git that died mid-walk does. Every other call goes to the real git.
_GIT_SHIM = """#!/usr/bin/env bash
if [ "${1:-}" = rev-list ] && [ "${2:-}" = "$FAIL_REVLIST" ]; then
  "$REAL_GIT" "$@" | head -n 1
  exit 128
fi
exec "$REAL_GIT" "$@"
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
    bash: str,
    repo: Path,
    tmp_path: Path,
    before: str,
    after: str,
    *,
    steps: tuple[str, ...] = (),
    fail_revlist: str | None = None,
    between: Callable[[Path], None] | None = None,
    tokens: str = "synthetic",
    extra_env: dict[str, str] | None = None,
) -> tuple[list[int], str, list[str]]:
    """Run step 1 then step 2, as the job does: step 2 runs whatever step 1 returned.

    ``fail_revlist`` puts ``_GIT_SHIM`` in front of git; ``between`` is called with ``$RUNNER_TEMP``
    after the first step, to damage what it recorded."""
    stub_dir = tmp_path / "stub"
    stub_dir.mkdir(exist_ok=True)
    stub = stub_dir / "python"
    stub.write_text(_STUB, encoding="utf-8", newline="\n")
    stub.chmod(0o755)
    log = tmp_path / "scan.log"
    log.write_text("", encoding="utf-8")
    (tmp_path / "scan.log.env").write_text("", encoding="utf-8")
    runner_temp = tmp_path / "runner-temp"
    runner_temp.mkdir(exist_ok=True)
    env = probe_env(Path(bash), dict(os.environ))
    prefix = stub_dir.as_posix()
    if fail_revlist is not None:
        real_git = subprocess.run(
            [bash, "-c", "command -v git"], capture_output=True, text=True, timeout=60, env=env
        ).stdout.strip()
        assert real_git, "no git on the bash PATH"
        shim_dir = tmp_path / "gitshim"
        shim_dir.mkdir(exist_ok=True)
        shim = shim_dir / "git"
        shim.write_text(_GIT_SHIM, encoding="utf-8", newline="\n")
        shim.chmod(0o755)
        prefix = f"{shim_dir.as_posix()}{os.pathsep}{prefix}"
        env.update({"REAL_GIT": real_git, "FAIL_REVLIST": fail_revlist})
    env.update(
        {
            "MEFOR_FORBIDDEN_TOKENS": tokens,
            "PUSH_BEFORE": before,
            "PUSH_AFTER": after,
            "RUNNER_TEMP": runner_temp.as_posix(),
            "SCAN_LOG": log.as_posix(),
            "PATH": f"{prefix}{os.pathsep}{env.get('PATH', '')}",
        }
    )
    env.update(extra_env or {})
    if fail_revlist is not None:
        which_git = subprocess.run(
            [bash, "-c", "command -v git"], capture_output=True, text=True, timeout=60, env=env
        ).stdout.strip()
        assert "gitshim" in which_git.replace("\\", "/"), f"the git shim lost to {which_git!r}"
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
        if i == 0 and between is not None:
            between(runner_temp)
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


def _floor_env(tmp_path: Path) -> list[str]:
    return (tmp_path / "scan.log.env").read_text(encoding="utf-8").splitlines()


def test_step_two_fails_closed_when_step_one_dies_listing_the_earlier_range(
    bash: str, tmp_path: Path
) -> None:
    """MEASURED fail-open on 682bde146: step 1 died mid ``rev-list`` (exit 128) and step 2 read the
    partial list it left as the whole earlier range, rescanned only that, and passed. A partial list
    is not a clean range. The leak is in the OLDER earlier commit, so only the full list reaches it."""
    repo = _Repo(tmp_path)
    leaked = _commit(repo.path, "leak", {"docs/security/note.md": f"{_MARKER}\n"})
    before = _commit(repo.path, "remove", {"docs/security/note.md": None, "a.txt": "x\n"})
    after = _commit(repo.path, "more", {"b.txt": "y\n"})
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, before, after, fail_revlist=before)
    assert rcs[0] == 128, f"rcs={rcs}; the shim did not kill step 1\n{out}"
    assert rcs[1] == 2, f"rcs={rcs}; step 2 read a partial earlier range as complete\n{out}"
    assert "did not finish recording it" in out, out
    assert not any(leaked in c for c in calls), calls


def test_step_two_fails_closed_on_a_line_that_is_not_a_commit(bash: str, tmp_path: Path) -> None:
    """A recorded range is a list of commit ids, and a line that is not one is a refusal, never a
    ref the rescan resolves or skips."""
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    before = _commit(repo.path, "two", {"b.txt": "y\n"})
    after = _commit(repo.path, "three", {"c.txt": "z\n"})

    def harm(runner_temp: Path) -> None:
        listing = runner_temp / "branch-leak-scan-earlier.txt"
        lines = listing.read_text(encoding="utf-8").splitlines()
        assert lines == [before, first], lines
        listing.write_text(f"{before}\nHEAD\n", encoding="utf-8", newline="\n")

    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, before, after, between=harm)
    assert rcs == [0, 2] and len(calls) == 1, f"rcs={rcs}, calls={calls}\n{out}"
    assert "not a commit id" in out, out


def test_both_steps_scan_under_security_yml_s_detector_floor(bash: str, tmp_path: Path) -> None:
    """The floor is duplicated into step 2, so it is pinned there by EXECUTION: every scanner call,
    step 1's and step 2's, runs with tokens required and the same per-section minimums as
    security.yml's forbidden-content job. A step 2 that lost its exports would scan under no floor."""
    floors = set(
        re.findall(
            r"export MEFOR_MIN_DETECTORS=(\S+)",
            (_REPO / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8"),
        )
    )
    assert len(floors) == 1, f"security.yml carries more than one floor: {floors}"
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    after = _commit(repo.path, "two", {"b.txt": "y\n"})
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, first, after)
    assert rcs == [0, 0] and len(calls) == 2, f"rcs={rcs}, calls={calls}\n{out}"
    assert _floor_env(tmp_path) == [f"1 {floors.pop()}"] * 2, _floor_env(tmp_path)


def test_step_two_without_the_token_secret_fails_closed(bash: str, tmp_path: Path) -> None:
    """Step 2's OWN check: step 1 runs with the secret and records a range, so a step 2 that lost
    its check would go on to scan it."""
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    after = _commit(repo.path, "two", {"b.txt": "y\n"})
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, first, after, steps=(_STEP,))
    assert rcs == [0], f"rcs={rcs}\n{out}"
    assert (tmp_path / "runner-temp" / "branch-leak-scan-earlier.txt").is_file()
    rcs, out, calls = _run_steps(
        bash, repo.path, tmp_path, first, after, steps=(_STEP2,), tokens=""
    )
    assert rcs == [2] and not calls, f"rcs={rcs}, calls={calls}\n{out}"
    assert "MEFOR_FORBIDDEN_TOKENS is absent" in out, out


_ALL = (_STEP, _STEP2, _STEP3)


def test_an_earlier_push_hit_names_its_commit(bash: str, tmp_path: Path) -> None:
    """The scanner names a content hit by its path inside a commit root, which drops the commit, so
    a responder could not tell which public SHA to assess. Only the commit that carries the hit is
    named; a clean commit in the same range is not."""
    repo = _Repo(tmp_path)
    clean = _commit(repo.path, "clean", {"a.txt": "x\n"})
    leaked = _commit(repo.path, "leak", {"docs/security/note.md": f"{_MARKER}\n"})
    removed = _commit(repo.path, "remove", {"docs/security/note.md": None})
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, removed, removed, steps=_ALL)
    assert rcs == [0, 1, 0], f"rcs={rcs}\n{out}"
    assert f"earlier commit {leaked} carries the hit(s) below" in out, out
    assert f"commit {clean} carries" not in out, out
    named = out.index(f"earlier commit {leaked}")
    assert "HIT docs/security/note.md" in out[named:], out
    # The real scanner prints reasons only unless asked for context; no call may ask.
    assert calls and not any("--show-context" in c for c in calls), calls


def test_a_this_push_hit_names_its_commit(bash: str, tmp_path: Path) -> None:
    repo = _Repo(tmp_path)
    clean = _commit(repo.path, "clean", {"a.txt": "x\n"})
    leaked, removed = _leak_then_remove(repo)
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, repo.main, removed, steps=_ALL)
    assert rcs == [1, 0, 0], f"rcs={rcs}\n{out}"
    assert f"this-push commit {leaked} carries the hit(s) below" in out, out
    assert f"commit {clean} carries" not in out, out


def test_a_hit_in_a_checked_out_file_is_blamed_on_no_commit(bash: str, tmp_path: Path) -> None:
    """Step 2 scans its roots beside the checked-out workflow file, so a hit THERE makes its scan
    red; attribution must not then name every clean earlier commit as carrying it."""
    repo = _Repo(tmp_path)
    clean = _commit(repo.path, "clean", {"a.txt": "x\n"})
    after = _commit(repo.path, "edit", {_SENTINEL: f"# {_MARKER}\n"})
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, clean, after, steps=_ALL)
    assert rcs == [1, 1, 0], f"rcs={rcs}\n{out}"
    assert f"this-push commit {after} carries" in out, out
    assert f"commit {clean} carries" not in out, out


def test_attribution_cannot_start_a_workflow_command(bash: str, tmp_path: Path) -> None:
    """A pushed path can carry a newline, so a hit line the scanner prints can begin with ``::``.
    Attribution re-emits that output, and must not hand the runner a command such as
    ``::stop-commands::``, which would silence every annotation after it. The stub prints the
    hostile line on a hit, standing in for the scanner echoing such a path."""
    repo = _Repo(tmp_path)
    leaked, removed = _leak_then_remove(repo)
    rcs, out, _ = _run_steps(
        bash,
        repo.path,
        tmp_path,
        repo.main,
        removed,
        steps=_ALL,
        extra_env={"STUB_ECHO": "::stop-commands::x"},
    )
    assert rcs[0] == 1, f"rcs={rcs}\n{out}"
    named = out.index(f"this-push commit {leaked} carries the hit(s) below")
    reemitted = out[named:].splitlines()[1:]
    assert reemitted and not any(line.startswith("::") for line in reemitted), out


def test_the_walk_reports_every_refusal_before_it_fails(bash: str, tmp_path: Path) -> None:
    """The first committed token list used to end the walk, so a second one, and every content hit
    behind it, went unreported until that one was fixed and the branch pushed again."""
    repo = _Repo(tmp_path)
    token = "scripts/security/scan-tokens.local.txt"
    one = _commit(repo.path, "oops", {token: "x\n"})
    _commit(repo.path, "undo", {token: None})
    two = _commit(repo.path, "oops again", {token: "y\n", "docs/security/note.md": f"{_MARKER}\n"})
    after = _commit(repo.path, "undo again", {token: None, "docs/security/note.md": None})
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, repo.main, after)
    assert rcs[0] == 1, f"rcs={rcs}\n{out}"
    assert f"branch commit {one} commits {token}" in out, out
    assert f"branch commit {two} commits {token}" in out, out
    assert "HIT docs/security/note.md" in out, f"the walk stopped before the scan\n{out}"
    assert len(calls) == 1, calls


@pytest.mark.parametrize("with_leak", [False, True])
def test_an_unsafe_path_is_refused_and_the_walk_goes_on(
    with_leak: bool, bash: str, tmp_path: Path
) -> None:
    """A tree entry named ``.git`` cannot come through the index, but a hand-built tree carries one,
    and a push delivers it. It is never written out and the step fails 2; the walk still reaches a
    content hit in the same push, and that confirmed leak outranks the refusal, so the step fails 1."""
    repo = _Repo(tmp_path)
    if with_leak:
        _leak_then_remove(repo)

    def plumb(*args: str, stdin: str) -> str:
        # Bytes, not text: text mode on Windows writes CRLF, and each name would gain a CR.
        out = subprocess.run(
            ["git", "-C", str(repo.path), *args],
            input=stdin.encode("utf-8"),
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout
        return out.decode("utf-8").strip()

    def mktree(entries: str) -> str:
        return plumb("mktree", stdin=entries)

    blob = plumb("hash-object", "-w", "--stdin", stdin="x\n")
    inner = mktree(f"100644 blob {blob}\thooks-config\n")
    dotgit = mktree(f"040000 tree {inner}\t.git\n")
    head_tree = _git(repo.path, "rev-parse", "HEAD^{tree}")
    listing = _git(repo.path, "ls-tree", head_tree)
    tree = mktree(f"{listing}\n040000 tree {dotgit}\tsub\n")
    bad = _git(repo.path, "commit-tree", tree, "-p", "HEAD", "-m", "unsafe")
    _git(repo.path, "update-ref", "HEAD", bad)
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, repo.main, bad)
    assert rcs[0] == (1 if with_leak else 2), f"rcs={rcs}\n{out}"
    assert f"branch commit {bad} names an unsafe path" in out, out
    if with_leak:
        assert "HIT docs/security/note.md" in out, f"the walk stopped at the unsafe path\n{out}"
    written = tmp_path / "runner-temp" / "branch-leak-scan-commits" / bad / "sub"
    assert not written.exists(), "the unsafe entry was written out"
