# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The refused-subjects gate (BACKLOG #1775), driven against throwaway fixture repositories.

Every red case is paired with a green neighbour, so a gate that refused unconditionally cannot pass
this file: the control commit sits in the same range as the refused one and must not be listed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts.ci import refused_subjects_check as gate
from tests._workflow_contexts import jobs_of, required_contexts, resolve

_REFUSAL = "DO NOT " + "LAND"  # split so this file's own text is not a search hit for the phrase
_VERDICT = "NOT " + "LANDABLE"

# Every test spawns tens of git children, which is slow on Windows; the 60s default is an engine-test
# figure, and a kill mid-fetch reports nothing about the gate.
pytestmark = pytest.mark.timeout(180)


@pytest.fixture
def git_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Pin git's identity and config so the result is a fact about the fixture, not this machine."""
    for key in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(key)
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "gitconfig"))
    for role in ("AUTHOR", "COMMITTER"):
        monkeypatch.setenv(f"GIT_{role}_NAME", "t")
        monkeypatch.setenv(f"GIT_{role}_EMAIL", "t@example.invalid")


def _git(cwd: Path, *args: str) -> str:
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        ["git", *args],  # noqa: S607  # nosec B607
        cwd=str(cwd),
        capture_output=True,
        check=True,
        timeout=120,
    )
    return out.stdout.decode("utf-8", "replace").strip()


def _commit(repo: Path, subject: str, body: str = "") -> str:
    message = subject if not body else f"{subject}\n\n{body}"
    _git(repo, "commit", "-q", "--allow-empty", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _repo(tmp_path: Path, name: str = "repo") -> Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    _commit(repo, "seed")
    return repo


def _branch(repo: Path, *subjects: str) -> tuple[str, str]:
    """Cut a branch from main, commit ``subjects`` on it, return (base, head)."""
    base = _git(repo, "rev-parse", "main")
    _git(repo, "switch", "-q", "-c", "topic")
    head = base
    for subject in subjects:
        head = _commit(repo, subject)
    return base, head


def _run(repo: Path, *args: str, capsys: pytest.CaptureFixture[str]) -> tuple[int, str]:
    code = gate.main(["--repo", str(repo), *args])
    return code, capsys.readouterr().out


# --- the vocabulary -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "subject",
    [
        f"wip(gate): unverified snapshot -- {_REFUSAL}",
        f"verdict(gate): the candidate is {_VERDICT} -- it opens the gate",
        f"wip: round two, {_REFUSAL.lower()} (BACKLOG #1)",
        f"wip: {_VERDICT.title()}",
        f"wip: {_REFUSAL.lower().replace(' ', '-')} snapshot",
        f"wip: {_REFUSAL.replace(' ', '_')}",
        f"[{_VERDICT.replace(' ', '-')}] x",
        f"wip_{_REFUSAL}",
    ],
)
def test_the_refusal_vocabulary_matches_in_either_case_and_any_separator(subject: str) -> None:
    assert gate.is_refused(subject)


@pytest.mark.parametrize(
    "subject",
    [
        "fix(gate): close the four fail-opens",
        "docs: do not landscape the diagram",  # a word that merely starts with the last word
        "feat: land the gate",
    ],
)
def test_ordinary_subjects_are_not_refused(subject: str) -> None:
    assert not gate.is_refused(subject)


# --- the range, both ways -------------------------------------------------------------------------


def test_a_clean_range_passes_and_says_how_many_commits_it_scanned(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    base, head = _branch(repo, "feat: one", "fix: two")
    code, out = _run(repo, "--base", base, "--head", head, "--expected-count", "2", capsys=capsys)
    assert code == gate.EXIT_CLEAN, out
    assert "scanned 2 commit(s)" in out
    assert "count of 2" in out


def test_a_refused_commit_fails_the_range_and_only_it_is_listed(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "main")
    _git(repo, "switch", "-q", "-c", "topic")
    control = _commit(repo, "feat: the control commit")
    refused = _commit(repo, f"wip: snapshot -- {_REFUSAL}")
    code, out = _run(repo, "--base", base, "--head", refused, capsys=capsys)
    assert code == gate.EXIT_REFUSED, out
    assert "1 of 2 commit(s)" in out
    # The listing line, not the bare SHA: the head SHA is also printed in the range, so a bare
    # `refused in out` would pass even with the per-commit listing gone.
    assert f"  {refused}  wip: snapshot" in out
    assert control not in out


def test_a_refused_commit_deep_in_the_range_is_still_found(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The oldest commit of the branch, under clean ones -- a tip-only reader would miss it."""
    repo = _repo(tmp_path)
    base, head = _branch(repo, f"verdict: {_VERDICT}", "feat: later", "fix: latest")
    code, out = _run(repo, "--base", base, "--head", head, capsys=capsys)
    assert code == gate.EXIT_REFUSED, out
    assert "1 of 3 commit(s)" in out


def test_the_phrase_in_a_commit_body_is_not_read(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """Only the subject carries the refusal, so the body is where a quotation belongs."""
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "main")
    _git(repo, "switch", "-q", "-c", "topic")
    head = _commit(repo, "fix(ci): gate refused subjects", body=f"The vocabulary is {_REFUSAL}.")
    code, out = _run(repo, "--base", base, "--head", head, capsys=capsys)
    assert code == gate.EXIT_CLEAN, out


def test_an_annotated_tag_message_is_not_a_commit_subject(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate reads commits, never tag messages -- and a tag passed as ``--head`` is dereferenced."""
    repo = _repo(tmp_path)
    base, head = _branch(repo, "feat: clean")
    _git(repo, "tag", "-a", "t1", "-m", f"tag note {_REFUSAL}", head)
    code, out = _run(repo, "--base", base, "--head", "t1", capsys=capsys)
    assert code == gate.EXIT_CLEAN, out
    assert "scanned 1 commit(s)" in out

    refused = _commit(repo, f"wip -- {_REFUSAL}")
    _git(repo, "tag", "-a", "t2", "-m", "a clean tag message", refused)
    code, out = _run(repo, "--base", base, "--head", "t2", capsys=capsys)
    assert code == gate.EXIT_REFUSED, out


def test_a_subject_carrying_a_line_separator_is_one_commit_not_two(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """A form feed inside a subject must not split it into a phantom commit that hides the refusal."""
    repo = _repo(tmp_path)
    base, head = _branch(repo, f"wip: tab\x0c{_REFUSAL}")
    code, out = _run(repo, "--base", base, "--head", head, "--expected-count", "1", capsys=capsys)
    assert code == gate.EXIT_REFUSED, out
    assert "1 of 1 commit(s)" in out


def test_a_revision_that_looks_like_an_option_is_refused_before_git_sees_it(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    head = _git(repo, "rev-parse", "main")
    code, out = _run(repo, "--base=--upload-pack=x", "--head", head, capsys=capsys)
    assert code == gate.EXIT_UNRESOLVED, out
    assert "must name a commit" in out


def test_on_a_runner_subjects_are_printed_with_workflow_commands_paused(
    tmp_path: Path,
    git_env: None,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A subject is attacker-controlled text; ``::add-mask::`` inside one must print, not execute."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    repo = _repo(tmp_path)
    base, head = _branch(repo, f"{_REFUSAL} ::add-mask::x")
    code, out = _run(repo, "--base", base, "--head", head, capsys=capsys)
    assert code == gate.EXIT_REFUSED, out
    lines = out.splitlines()
    stop = next(i for i, line in enumerate(lines) if line.startswith("::stop-commands::"))
    token = lines[stop].split("::")[2]
    resume = lines.index(f"::{token}::")
    assert any("::add-mask::x" in line for line in lines[stop + 1 : resume])
    assert lines[0].startswith("::error::")


def test_a_count_mismatch_is_a_failure_and_never_a_pass(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    base, head = _branch(repo, "feat: one")
    code, out = _run(repo, "--base", base, "--head", head, "--expected-count", "3", capsys=capsys)
    assert code == gate.EXIT_UNRESOLVED, out
    assert "Nothing was scanned" in out


def test_a_missing_commit_is_a_failure_and_never_a_pass(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _repo(tmp_path)
    base = _git(repo, "rev-parse", "main")
    code, out = _run(repo, "--base", base, "--head", "0" * 40, capsys=capsys)
    assert code == gate.EXIT_UNRESOLVED, out


# --- a shallow checkout, as CI has one ------------------------------------------------------------


def _shallow_pr(tmp_path: Path) -> tuple[Path, str, str]:
    """An origin whose branch starts with a refused commit and whose main moved on, cloned depth 1."""
    origin = _repo(tmp_path, "origin")
    _commit(origin, "main: two")
    _git(origin, "switch", "-q", "-c", "topic")
    _commit(origin, f"wip: snapshot -- {_REFUSAL}")
    _commit(origin, "feat: clean on top")
    head = _commit(origin, "fix: cleaner on top")
    _git(origin, "switch", "-q", "main")
    _commit(origin, "main: three")
    base = _commit(origin, "main: four")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", "--depth=1", "--no-local", origin.as_uri(), str(work))
    assert _git(work, "rev-parse", "--is-shallow-repository") == "true"
    return work, base, head


def test_a_shallow_checkout_is_deepened_until_the_whole_range_is_read(
    tmp_path: Path,
    git_env: None,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Depth 1 cannot reach the refused commit at the bottom of the branch; the gate must deepen."""
    work, base, head = _shallow_pr(tmp_path)
    monkeypatch.setattr(gate, "_DEPTHS", (1,))
    code, out = _run(
        work,
        "--base",
        base,
        "--head",
        head,
        "--expected-count",
        "3",
        "--fetch-remote",
        "origin",
        capsys=capsys,
    )
    assert code == gate.EXIT_REFUSED, out
    assert "1 of 3 commit(s)" in out


def test_without_a_remote_a_shallow_checkout_is_unresolved_not_clean(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    work, base, head = _shallow_pr(tmp_path)
    code, out = _run(work, "--base", base, "--head", head, capsys=capsys)
    assert code == gate.EXIT_UNRESOLVED, out


def _merged_pr(tmp_path: Path) -> tuple[Path, str, str]:
    """A two-commit branch starting with a refused commit, then a merge of main, cloned depth 1.

    The merge is what makes a truncated range dangerous: a shallow fetch reaches the merge base
    through main's side while the branch's own oldest commit is cut off, so a merge base alone
    cannot prove the range is whole.
    """
    origin = _repo(tmp_path, "origin")
    _git(origin, "switch", "-q", "-c", "topic")
    _commit(origin, f"wip: snapshot -- {_REFUSAL}")
    _commit(origin, "feat: clean")
    _git(origin, "switch", "-q", "main")
    _commit(origin, "main: moved")
    _git(origin, "switch", "-q", "topic")
    _git(origin, "merge", "-q", "--no-edit", "main")
    head = _git(origin, "rev-parse", "HEAD")
    _git(origin, "switch", "-q", "main")
    base = _commit(origin, "main: ahead")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", "--depth=1", "--no-local", origin.as_uri(), str(work))
    # Truncate the way a shallow CI fetch can: the merge base is reachable, the refused commit is not.
    _git(work, "fetch", "-q", "--no-tags", "--depth=2", "origin", base, head)
    return work, base, head


def test_a_truncated_range_with_a_merge_base_is_unresolved_without_a_remote(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """No count and no remote: the shallow boundary alone must stop a false pass."""
    work, base, head = _merged_pr(tmp_path)
    assert gate._merge_base(work, base, head) is not None
    assert len(gate.list_range(work, base, head)) == 2  # of the true 3; the refused one is cut off
    code, out = _run(work, "--base", base, "--head", head, capsys=capsys)
    assert code == gate.EXIT_UNRESOLVED, out
    assert "shallow boundary" in out


@pytest.mark.parametrize("with_count", [True, False])
def test_a_truncated_range_is_deepened_until_whole_then_refused(
    tmp_path: Path,
    git_env: None,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    with_count: bool,
) -> None:
    """The shallow boundary drives the deepening, with or without the count, by ``--deepen`` alone."""
    work, base, head = _merged_pr(tmp_path)
    monkeypatch.setattr(gate, "_DEPTHS", (1, 64))
    depths: list[int | None] = []
    real_fetch = gate._fetch

    def spy(repo: Path, remote: str, b: str, h: str, depth: int | None, *, shallow: bool) -> None:
        depths.append(depth)
        real_fetch(repo, remote, b, h, depth, shallow=shallow)

    monkeypatch.setattr(gate, "_fetch", spy)
    count = ["--expected-count", "3"] if with_count else []
    code, out = _run(
        work, "--base", base, "--head", head, *count, "--fetch-remote", "origin", capsys=capsys
    )
    assert code == gate.EXIT_REFUSED, out
    assert "1 of 3 commit(s)" in out
    assert depths and None not in depths, depths  # resolved by deepening, never by unshallow


def test_deepening_never_shortens_a_deeper_shallow_clone(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--depth`` into a clone deeper than it cuts the clone down; the gate must only ever add."""
    origin = _repo(tmp_path, "origin")
    for n in range(6):
        _commit(origin, f"main: {n}")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", "--depth=5", "--no-local", origin.as_uri(), str(work))
    base, head = _branch(origin, "feat: clean")  # created AFTER the clone, so work must fetch it
    before = int(_git(work, "rev-list", "--count", "HEAD"))
    code, out = _run(
        work, "--base", base, "--head", head, "--fetch-remote", "origin", capsys=capsys
    )
    assert code == gate.EXIT_CLEAN, out
    assert int(_git(work, "rev-list", "--count", "HEAD")) >= before


def test_a_full_clone_is_fetched_into_but_never_made_shallow(
    tmp_path: Path, git_env: None, capsys: pytest.CaptureFixture[str]
) -> None:
    """A ``--depth`` fetch would convert a developer's full clone to a shallow one."""
    origin = _repo(tmp_path, "origin")
    work = tmp_path / "work"
    _git(tmp_path, "clone", "-q", "--no-local", origin.as_uri(), str(work))
    base, head = _branch(origin, "feat: clean")  # created AFTER the clone, so work must fetch it
    assert not gate._present(work, head)
    code, out = _run(
        work, "--base", base, "--head", head, "--fetch-remote", "origin", capsys=capsys
    )
    assert code == gate.EXIT_CLEAN, out
    assert _git(work, "rev-parse", "--is-shallow-repository") == "false"


# --- the wiring -----------------------------------------------------------------------------------


def _step() -> dict[str, object]:
    steps = jobs_of("ci.yml")["test"]["steps"]
    hits = [s for s in steps if "refused_subjects_check.py" in str(s.get("run", ""))]
    assert len(hits) == 1, "the refused-subjects step is missing from ci.yml's test job"
    step: dict[str, object] = hits[0]
    return step


def test_the_step_rides_a_required_context() -> None:
    """A new required context would wedge every open pull request, so it must ride an existing one."""
    assert "test (ubuntu-latest, py3.14)" in required_contexts()
    assert resolve("test (ubuntu-latest, py3.14)") == ("ci.yml", "test")
    _step()


def test_the_step_runs_on_pull_requests_only_and_is_not_gated_on_code() -> None:
    cond = str(_step()["if"])
    assert "github.event_name == 'pull_request'" in cond
    assert "runner.os == 'Linux'" in cond
    assert "changes.outputs.code" not in cond, "a docs-only pull request would go unscanned"
    assert "merge_group" not in cond


def test_the_step_passes_the_count_and_a_remote() -> None:
    """Without the count a truncated history can pass; without the remote a shallow one cannot pass."""
    step = _step()
    run = str(step["run"])
    for flag in ("--base", "--head", "--expected-count", "--fetch-remote origin"):
        assert flag in run, flag
    env = step["env"]
    assert isinstance(env, dict)
    assert env["PR_COMMITS"] == "${{ github.event.pull_request.commits }}"
    assert env["PR_BASE_SHA"] == "${{ github.event.pull_request.base.sha }}"
    assert env["PR_HEAD_SHA"] == "${{ github.event.pull_request.head.sha }}"


def test_the_step_is_last_survives_an_earlier_red_and_is_bounded() -> None:
    """A refusal must not hide the leg's lint, type and test results, nor hang the job unnamed.

    Last, so its red skips nothing and its fetch moves no shallow boundary an earlier step reads;
    ``!cancelled()``, so an earlier red does not skip the scan; a step timeout, so a stalled fetch
    fails this step by name.
    """
    step = _step()
    steps = jobs_of("ci.yml")["test"]["steps"]
    assert steps[-1] is step or steps[-1] == step
    assert "!cancelled()" in str(step["if"])
    # It runs after a pytest step that may have used its whole cap, so it must fit what the ubuntu
    # job cap leaves: 43 - 31 leaves 12 minutes, about 5.5 of which setup already spends.
    assert step.get("timeout-minutes") == 5
