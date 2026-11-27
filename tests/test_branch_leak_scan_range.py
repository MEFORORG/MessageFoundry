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
#: exist exits 2, as the real scanner's unreadable path does. A hit prints the real scanner's report
#: header first. ``$STUB_CRASH`` stands in for an uncaught exception, exit 1 with no report, on every
#: call, or with ``$STUB_CRASH_ON`` only on a call whose arguments contain that text.
_STUB = f"""#!/usr/bin/env bash
shift
echo "$*" >> "$SCAN_LOG"
echo "${{MEFOR_REQUIRE_TOKENS:-unset}} ${{MEFOR_MIN_DETECTORS:-unset}}" >> "$SCAN_LOG.env"
[ "$1" = "--path" ] || exit 9
shift
case "$*" in
  *"${{STUB_CRASH_ON:-}}"*) [ -z "${{STUB_CRASH:-}}" ] || {{ echo "Traceback (most recent call last):" >&2; exit 1; }} ;;
esac
hit=0
for root in "$@"; do
  [ -e "$root" ] || {{ echo "missing root $root" >&2; exit 2; }}
  while IFS= read -r -d '' f; do
    if grep -q '{_MARKER}' "$f"; then
      [ "$hit" = 1 ] || echo "FORBIDDEN CONTENT -- commit blocked (fail closed):"
      echo "HIT ${{f#"$root"/}}"
      hit=1
    fi
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
    transform: Callable[[str], str] | None = None,
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
        body = _body(name)
        script.write_text(transform(body) if transform else body, encoding="utf-8", newline="\n")
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
    # The trap turns the failed listing into a refusal: an internal failure is never a leak (1).
    assert rcs[0] == 2 and "the scan failed internally (exit 128)" in out, (
        f"rcs={rcs}; the shim did not kill step 1\n{out}"
    )
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
    red; attribution must not then name every clean earlier commit as carrying it.

    Step 1 scans the same file as part of the tip, so both steps go red: a deliberate double report.
    Step 2 cannot leave the file out, because step 1 can fail before its scan, and then step 2's is
    the run's only scan of it."""
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

    blob = _plumb(repo.path, "hash-object", "-w", "--stdin", stdin="x\n")
    inner = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\thooks-config\n")
    dotgit = _plumb(repo.path, "mktree", stdin=f"040000 tree {inner}\t.git\n")
    bad = _hand_built_commit(repo.path, "HEAD", f"040000 tree {dotgit}\tsub\n")
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, repo.main, bad)
    assert rcs[0] == (1 if with_leak else 2), f"rcs={rcs}\n{out}"
    assert f"branch commit {bad} names an unsafe path" in out, out
    if with_leak:
        assert "HIT docs/security/note.md" in out, f"the walk stopped at the unsafe path\n{out}"
    written = tmp_path / "runner-temp" / "branch-leak-scan-commits" / bad / "sub"
    assert not written.exists(), "the unsafe entry was written out"


def _plumb(repo: Path, *args: str, stdin: str) -> str:
    # Bytes, not text: text mode on Windows writes CRLF, and each name would gain a CR.
    out = subprocess.run(
        ["git", "-C", str(repo), *args],
        input=stdin.encode("utf-8"),
        capture_output=True,
        check=True,
        timeout=60,
    ).stdout
    return out.decode("utf-8").strip()


def _hand_built_commit(repo: Path, parent: str, entries: str) -> str:
    """A commit on ``parent`` whose tree is ``parent``'s plus ``entries`` (mktree lines), built by
    plumbing so it can hold a tree the index refuses. It moves HEAD and leaves the index alone, so a
    later ``_commit`` would commit from the old index; ``parent`` must have a non-empty tree."""
    listing = _git(repo, "ls-tree", f"{parent}^{{tree}}")
    tree = _plumb(repo, "mktree", stdin=f"{listing}\n{entries}")
    commit = _git(repo, "commit-tree", tree, "-p", parent, "-m", "hand-built")
    _git(repo, "update-ref", "HEAD", commit)
    return commit


@pytest.mark.parametrize("unsafe_dir", ["a", "z"])
def test_a_committed_token_list_outranks_an_unsafe_path_in_either_order(
    unsafe_dir: str, bash: str, tmp_path: Path
) -> None:
    """MEASURED on 7a30cf1f1: a walk that met an unsafe path and a committed token list ended at 2,
    whichever came first, so the step read as a refusal although the token list is a confirmed leak.
    ``a`` sorts before ``scripts`` and ``z`` after it, so diff-tree meets the two in each order."""
    repo = _Repo(tmp_path)
    blob = _plumb(repo.path, "hash-object", "-w", "--stdin", stdin="x\n")
    inner = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\thooks-config\n")
    dotgit = _plumb(repo.path, "mktree", stdin=f"040000 tree {inner}\t.git\n")
    tokens = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\tscan-tokens.local.txt\n")
    security = _plumb(repo.path, "mktree", stdin=f"040000 tree {tokens}\tsecurity\n")
    bad = _hand_built_commit(
        repo.path,
        repo.main,
        f"040000 tree {security}\tscripts\n040000 tree {dotgit}\t{unsafe_dir}\n",
    )
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, repo.main, bad)
    assert f"branch commit {bad} names an unsafe path" in out, out
    assert f"branch commit {bad} commits scripts/security/scan-tokens.local.txt" in out, out
    assert rcs[0] == 1, f"rcs={rcs}; a confirmed leak lost to a refusal\n{out}"


@pytest.mark.parametrize("in_step", [1, 2])
def test_an_internal_failure_on_the_walk_is_a_refusal_not_a_leak(
    in_step: int, bash: str, tmp_path: Path
) -> None:
    """MEASURED on 7a30cf1f1: a hand-built tree naming ``d`` as both a file and a directory makes the
    walk's ``mkdir`` fail under ``set -e``, which exited 1, the code that means a confirmed leak. An
    internal failure is the instrument failing: it is 2, with a message saying so, and never 0."""
    repo = _Repo(tmp_path)
    blob = _plumb(repo.path, "hash-object", "-w", "--stdin", stdin="x\n")
    inner = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\tf\n")
    bad = _hand_built_commit(
        repo.path, repo.main, f"100644 blob {blob}\td\n040000 tree {inner}\td\n"
    )
    if in_step == 1:
        before, after = repo.main, bad
    else:
        # The bad commit is the earlier push's, so only step 2 walks it.
        before = bad
        after = _hand_built_commit(repo.path, bad, f"100644 blob {blob}\tclean.txt\n")
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, before, after)
    assert rcs[in_step - 1] == 2, f"rcs={rcs}\n{out}"
    assert "failed internally" in out and "not a leak verdict" in out, out


@pytest.mark.parametrize(
    "hostile", ["::stop-commands::x", ":::stop-commands::x", "##[cmd]x", "###[cmd]x"]
)
def test_no_step_echoes_scanner_output_as_a_workflow_command(
    hostile: str, bash: str, tmp_path: Path
) -> None:
    """MEASURED on 7a30cf1f1: steps 1 and 2 printed the scanner's output as it came, so a hit line
    echoing a pushed path could hand the runner ``::stop-commands::`` or a ``##[`` command, and the
    attribution step broke up only ``::``. Every step that shows scanner output must break up both.
    The leak sits in both ranges, so all three steps print the stub's hostile line."""
    repo = _Repo(tmp_path)
    _leaked, before = _leak_then_remove(repo)
    after = _commit(repo.path, "again", {"b.txt": f"{_MARKER}\n"})
    rcs, out, _ = _run_steps(
        bash,
        repo.path,
        tmp_path,
        before,
        after,
        steps=_ALL,
        extra_env={"STUB_ECHO": hostile},
    )
    assert rcs == [1, 1, 0], f"rcs={rcs}\n{out}"
    shown = [line for line in out.splitlines() if "stop-commands" in line or "cmd]" in line]
    # Once each from steps 1 and 2, and once for each of the two commit roots step 3 rescans.
    assert len(shown) == 4, f"the stub's line was not shown by every step\n{out}"
    for line in shown:
        bare = line.lstrip()
        assert not bare.startswith(("::", "##[")) and "::" not in bare and "##[" not in bare, line


def test_the_failure_notes_name_what_they_print_and_where_to_read() -> None:
    """The attribution step re-prints each hit's path, and a name hit's path IS the matched text, so
    its comment must say so rather than claim it never prints matched content. The closing note runs
    after the attribution step and must send a responder to it by its real step name."""
    workflow = (_REPO / ".github" / "workflows" / _WORKFLOW).read_text(encoding="utf-8")
    attribution = workflow[workflow.index(f"- name: {_STEP3}") :]
    attribution = attribution[: attribution.index("      - name: ")]
    assert "never the matched content" not in attribution
    assert "name hit's path is itself the matched text" in attribution, attribution
    names = [s.get("name") for s in _steps()]
    note = names[names.index(_STEP3) + 1]
    body = str(_step(str(note))["run"])
    assert f"'{_STEP3}'" in body and "both scan steps" not in body, body


def test_a_scanner_crash_is_a_refusal_not_a_leak(bash: str, tmp_path: Path) -> None:
    """An uncaught Python exception exits 1, the scanner's leak code, with no FORBIDDEN CONTENT
    report. MEASURED on 7a30cf1f1: step 1 read that as a confirmed leak. A crash is the instrument
    failing, so both scan steps refuse (2)."""
    repo = _Repo(tmp_path)
    first = _commit(repo.path, "one", {"a.txt": "x\n"})
    after = _commit(repo.path, "two", {"b.txt": "y\n"})
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, first, after, extra_env={"STUB_CRASH": "1"})
    assert rcs == [2, 2], f"rcs={rcs}\n{out}"
    assert out.count("without a FORBIDDEN CONTENT report") == 2, out


def test_a_crash_on_an_attribution_rescan_names_no_commit(bash: str, tmp_path: Path) -> None:
    """The scan steps find the leak; the per-root rescan crashes. Attribution must not name the
    commit as carrying a hit, and its warning must give the scanner's real exit code."""
    repo = _Repo(tmp_path)
    leaked, removed = _leak_then_remove(repo)
    rcs, out, _ = _run_steps(
        bash,
        repo.path,
        tmp_path,
        repo.main,
        removed,
        steps=_ALL,
        extra_env={"STUB_CRASH": "1", "STUB_CRASH_ON": "attribution-clean.txt"},
    )
    assert rcs == [1, 0, 0], f"rcs={rcs}\n{out}"
    assert "carries the hit(s)" not in out, out
    assert f"this-push commit {leaked} could not be rescanned on its own (scanner exit 1)" in out, (
        out
    )


@pytest.mark.parametrize("hostile", ["##[stop-commands]tok", "q\n::stop-commands::tok"])
def test_a_failed_write_never_prints_the_pushed_path(
    hostile: str, bash: str, tmp_path: Path
) -> None:
    """bash's own error for a failed write, and mkdir's, print the path raw, and the runner reads
    ``##[`` anywhere in a line, or ``::`` at a line start, as a workflow command. A component over
    255 bytes makes the write fail. The step refuses (2) through its EXIT trap, and no line of its
    output carries the command the name holds."""
    repo = _Repo(tmp_path)
    blob = _plumb(repo.path, "hash-object", "-w", "--stdin", stdin="x\n")
    name = hostile + "A" * 300
    inner = _plumb(repo.path, "mktree", "-z", stdin=f"100644 blob {blob}\t{name}\0")
    bad = _hand_built_commit(repo.path, repo.main, f"040000 tree {inner}\tdocs\n")
    rcs, out, _ = _run_steps(bash, repo.path, tmp_path, repo.main, bad)
    assert rcs[0] == 2 and "the scan failed internally" in out, f"rcs={rcs}\n{out}"
    for line in out.splitlines():
        assert "##[stop-commands" not in line, line
        assert not line.lstrip().startswith("::stop-commands"), line
        assert "AAAAAAAAAA" not in line, f"the pushed path was printed: {line}"


def test_an_internal_failure_after_a_found_leak_says_the_scan_did_not_finish(
    bash: str, tmp_path: Path
) -> None:
    """MEASURED on 45cab8d62: the walk met a committed token list (walk_rc=1), then a mkdir failed
    with exit 1, and the trap passed that 1 through silently: the log read as a finished scan that
    found one leak, though the scan never ran. The leak still wins (1), and the log says the scan
    stopped."""
    repo = _Repo(tmp_path)
    blob = _plumb(repo.path, "hash-object", "-w", "--stdin", stdin="x\n")
    inner = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\tf\n")
    dd = _hand_built_commit(
        repo.path, repo.main, f"100644 blob {blob}\td\n040000 tree {inner}\td\n"
    )
    security = _plumb(repo.path, "mktree", stdin=f"100644 blob {blob}\tscan-tokens.local.txt\n")
    scripts = _plumb(repo.path, "mktree", stdin=f"040000 tree {security}\tsecurity\n")
    # On a tree without the d/d pair, so this commit's own diff holds only the token list. The walk
    # meets it first, being the newest.
    listing = _git(repo.path, "ls-tree", f"{repo.main}^{{tree}}")
    tree = _plumb(repo.path, "mktree", stdin=f"{listing}\n040000 tree {scripts}\tscripts\n")
    after = _git(repo.path, "commit-tree", tree, "-p", dd, "-m", "token list")
    rcs, out, calls = _run_steps(bash, repo.path, tmp_path, repo.main, after, steps=(_STEP,))
    assert f"branch commit {after} commits scripts/security/scan-tokens.local.txt" in out, out
    assert rcs == [1] and not calls, f"rcs={rcs}, calls={calls}\n{out}"
    assert "after it had found the leak reported above, and did not finish" in out, out


def test_both_scan_steps_carry_the_same_exit_trap() -> None:
    """The trap is the step's whole failure classification, copied into two steps; they may differ
    only in naming the step."""
    traps = [
        next(line for line in _body(name).splitlines() if line.startswith("trap "))
        for name in (_STEP, _STEP2)
    ]
    assert traps[0].replace("the scan ", "the rescan ") == traps[1], traps


def test_an_unset_variable_in_a_step_is_a_refusal_not_a_leak(bash: str, tmp_path: Path) -> None:
    """MUTATION row: under ``set -u`` an unset variable exits 1 and runs no ERR trap, so a future
    typo would read as a confirmed leak. The EXIT trap maps it to 2. The mutation inserts one such
    read right after the trap is set."""
    repo = _Repo(tmp_path)
    after = _commit(repo.path, "clean", {"a.txt": "x\n"})

    def mutate(body: str) -> str:
        anchor = "\nzero=0000000000000000000000000000000000000000\n"
        assert body.count(anchor) == 1, "the mutation anchor moved"
        return body.replace(anchor, '\n: "$no_such_variable_for_this_test"' + anchor)

    rcs, out, calls = _run_steps(
        bash, repo.path, tmp_path, repo.main, after, steps=(_STEP,), transform=mutate
    )
    assert "no_such_variable_for_this_test" in out, f"the mutation did not fire\n{out}"
    assert rcs == [2] and not calls, f"rcs={rcs}, calls={calls}\n{out}"
    assert "failed internally (exit 1)" in out, out
