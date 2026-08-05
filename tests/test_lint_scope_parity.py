# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pre-commit hooks and the CI gates must lint/scan the SAME files.

They did not, and the divergence was silent in the worst direction: the hooks were BROADER than CI.
`ruff check` in CI named six explicit paths while the pre-commit ruff hook has no `exclude` and so
runs on every changed Python file; bandit in CI scanned `-r messagefoundry tee` while its hook scanned
everything but tests/harness/samples. The result was 99 ruff findings in harness/, tee/, samples/ and
docker/ that were gated locally and by nothing in CI — so touching any file there blocked the commit
on errors that no CI run could report, and that no green build had ever been able to reveal.

The direction matters. A hook LOOSER than CI is an annoyance: CI still catches it. A hook STRICTER
than CI is a trap — it blocks work on a standard the project does not actually enforce, which is
what makes people reach for `--no-verify` and lose every other gate with it.

These tests read both configurations and compare them, so the next person to narrow one has to
narrow the other. They assert the CONTRACT, not any particular scope: widen or narrow freely,
provided both sides move together.

The semgrep arm below is CI-vs-CI, not hook-vs-CI, and that asymmetry is deliberate rather than a
forgotten half: there is no semgrep pre-commit hook to compare against, because semgrep has no
supported Windows install (docs/releases/BACKLOG-MULTISESSION-PLAN.md) and this is a Windows-first
project. So semgrep's scope is pinned to its sibling CI gate, bandit — the two scan the same
checkout in the same job file for the same reason, and a path excluded from one but not the other
means one of them is enforcing a standard the other is not.
"""

from __future__ import annotations

import re
import shlex
from pathlib import Path
from typing import Any

import pytest

yaml = pytest.importorskip("yaml")

_ROOT = Path(__file__).resolve().parents[1]
_PRECOMMIT = _ROOT / ".pre-commit-config.yaml"
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_SECURITY = _ROOT / ".github" / "workflows" / "security.yml"


def _hooks() -> dict[str, dict[str, Any]]:
    cfg = yaml.safe_load(_PRECOMMIT.read_text(encoding="utf-8"))
    return {h["id"]: h for repo in cfg["repos"] for h in repo["hooks"]}


def _ci_step_run(workflow: Path, name_fragment: str) -> str:
    """The `run:` body of the first step whose name contains ``name_fragment``."""
    wf = yaml.safe_load(workflow.read_text(encoding="utf-8"))
    for job in wf["jobs"].values():
        for step in job.get("steps") or []:
            if name_fragment.lower() in str(step.get("name", "")).lower() and "run" in step:
                return str(step["run"])
    raise AssertionError(f"no step matching {name_fragment!r} in {workflow.name}")


def test_ruff_lints_the_whole_repo_on_both_sides() -> None:
    """The hook has no `exclude`, so it lints every changed Python file. CI must do the same.

    An allow-list in CI cannot be kept in step with "everything" by hand — it was six paths while the
    hook covered the repo. `ruff check .` makes pyproject's [tool.ruff] extend-exclude the SINGLE
    definition of scope, which is the only arrangement that cannot drift.
    """
    hook = _hooks()["ruff-check"]
    assert "exclude" not in hook, (
        "the ruff-check hook grew an `exclude` — CI runs `ruff check .` over the whole repo, so an "
        "exclude here makes the hook quietly weaker than the gate it mirrors. Put the exclusion in "
        "pyproject [tool.ruff] extend-exclude, where BOTH sides read it."
    )
    run = _ci_step_run(_CI, "Lint (ruff)")
    assert re.search(r"ruff check\s+\.\s*$", run.strip()), (
        f"CI must lint the whole repo (`ruff check .`) to match the hook; got: {run.strip()!r}"
    )


def test_ruff_format_and_lint_agree_on_scope() -> None:
    """Format was already repo-wide (`ruff format --check .`) while lint was an allow-list. Two ruff
    invocations disagreeing about which files are 'the project' is the same bug in miniature."""
    lint = _ci_step_run(_CI, "Lint (ruff)").strip()
    fmt = _ci_step_run(_CI, "Format check (ruff)").strip()
    assert lint.endswith("."), lint
    assert fmt.endswith("."), fmt


def _bandit_skips(text: str) -> set[str]:
    m = re.search(r"--skip[= ]([A-Z0-9,]+)", text)
    assert m, f"no --skip found in: {text[:200]!r}"
    return set(m.group(1).split(","))


def test_bandit_skips_match() -> None:
    hook_args = " ".join(_hooks()["bandit"].get("args") or [])
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert _bandit_skips(hook_args) == _bandit_skips(ci), (
        "the bandit hook and the CI bandit job disagree about which tests are skipped — one of them "
        "is enforcing a standard the other does not"
    )


def test_bandit_excludes_match() -> None:
    """The hook excludes by regex, CI by comma-separated paths. Compare the PATHS they name.

    CI additionally excludes .venv/node_modules, which pre-commit never passes to a hook (they are
    untracked), so those are ignored rather than required on both sides.
    """
    hook_re = _hooks()["bandit"]["exclude"]
    hook_paths = {p.strip("/") for p in re.findall(r"[\w./-]+/", hook_re)}

    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    m = re.search(r"--exclude[= ]([^\s\\]+)", ci)
    assert m, "CI bandit step has no --exclude"
    # removeprefix, not strip("./"): strip() removes those CHARACTERS from both ends, so "./.venv"
    # would become "venv" and silently fail to match the untracked set below.
    untracked = {".venv", "node_modules"}
    ci_paths = {p.strip().removeprefix("./").rstrip("/") for p in m.group(1).split(",")} - untracked

    assert hook_paths == ci_paths, (
        f"bandit scope drifted: hook excludes {sorted(hook_paths)}, CI excludes {sorted(ci_paths)}. "
        "A path excluded on ONE side only is scanned by one gate and not the other — which is how "
        "scripts/ came to be gated locally and by nothing in CI."
    )


def test_ci_bandit_scans_the_repo_not_an_allow_list() -> None:
    """`-r messagefoundry tee` silently stopped covering scripts/ the moment security tooling moved
    there. Scanning `.` minus explicit excludes cannot go stale that way."""
    ci = _ci_step_run(_SECURITY, "Scan source for insecure patterns")
    assert re.search(r"bandit\s+-r\s+\.", ci), (
        f"CI bandit must scan `-r .` with explicit --exclude, not an allow-list of dirs; got: {ci!r}"
    )


def _ci_command(run: str, program: str) -> str:
    """The single-line form of the `program ...` command inside a multi-line CI step body.

    Joins backslash continuations and DROPS comment lines, so every assertion below is made against
    the argv that actually runs. That is load-bearing rather than tidiness: the first draft of the
    exclude extractor ran its regex over the whole step body and duly reported an exclude named
    ``matches``, mined out of the English sentence "semgrep's --exclude matches GLOBS" in the comment
    above the command. Prose must never be able to change what a gate test measures.
    """
    joined = run.replace("\\\n", " ")
    line = next(
        (
            ln
            for ln in joined.splitlines()
            if ln.strip().startswith(f"{program} ") and not ln.strip().startswith("#")
        ),
        None,
    )
    assert line is not None, f"no `{program} ...` command found in the step body: {run!r}"
    return line.strip()


def _semgrep_command() -> str:
    """The REPO-WIDE semgrep command, from the step selected by its exact name.

    Two couplings a future editor should know about, both deliberate:

    1. This selects by step NAME, so renaming "Run the MessageFoundry rules" breaks both semgrep
       tests here. A loud failure is the point — the alternative is a test that silently starts
       asserting about some other command.
    2. The semgrep job has TWO `run:` steps, and the second (ADR 0144 Inc 3) deliberately scans an
       ALLOW-LIST (samples/config) with a DIFFERENT rules file. A loose fragment would match the
       wrong invocation and assert the opposite of what is intended. Note that no step name in that
       job contains the string "semgrep", so `_ci_step_run(_SECURITY, "semgrep")` raises rather than
       quietly returning one of them.

    The `--config .semgrep` re-check guards (2): even if the name match were retargeted, a step
    pointing at the packaged handler rules is not the gate these tests are about. It is checked
    against the COMMAND, not the step body, so a passing mention of the rules dir in a comment
    cannot satisfy it.
    """
    command = _ci_command(_ci_step_run(_SECURITY, "Run the MessageFoundry rules"), "semgrep")
    assert "--config .semgrep" in command, (
        "the repo-wide semgrep step no longer points at the .semgrep/ project rules, so these tests "
        f"would be asserting scope against a different rule set entirely; got: {command!r}"
    )
    return command


#: Long flags on the semgrep command that CONSUME the following token as their value.
#:
#: Hand-maintained, and that carries a real maintenance obligation: a NEW value-taking flag added to
#: the command without being added here turns its value into a phantom positional "target" and reds
#: ``test_ci_semgrep_scans_the_repo_not_an_allow_list`` — with a message about SCOPE, for a change
#: that had nothing to do with scope. The direction is deliberate (fail loud, make the next flag a
#: considered edit rather than a silent one), but read this set first when that test reds unexpectedly.
_SEMGREP_VALUE_FLAGS = frozenset({"--config", "--exclude", "--include", "--metrics"})


def _semgrep_targets(command: str) -> list[str]:
    """The POSITIONAL targets of the semgrep invocation — i.e. what it is pointed at.

    Deliberately not a regex on the command text: "does it end in a dot?" is a different question
    from "what is this pointed at?", and only the second is the contract. shlex-splits, then drops
    flags and the values consumed by them.

    NOT the whole scope on its own — see ``_semgrep_includes``. `--include` narrows what a positional
    target expands to, so "targets" and "scope" coincide only while no `--include` is present, which
    is why the test asserts both.
    """
    targets: list[str] = []
    skip_next = False
    for token in shlex.split(command)[1:]:  # [1:] drops the `semgrep` program name
        if skip_next:
            skip_next = False
            continue
        if token.startswith("-"):
            flag, sep, _value = token.partition("=")
            skip_next = flag in _SEMGREP_VALUE_FLAGS and not sep
            continue
        targets.append(token)
    return targets


def _semgrep_includes(command: str) -> set[str]:
    """`--include` values, which NARROW the scan to paths matching them.

    Extracted separately because `--include` is the allow-list in disguise: `semgrep ... --include
    messagefoundry --include tee .` scans exactly the two directories BACKLOG #334 exists to retire,
    while the positional target still reads `.`. A targets-only assertion reports green on it.
    """
    return {m.group(1).strip() for m in re.finditer(r"--include[= ]([^\s\\]+)", command)}


def _semgrep_excludes(command: str) -> set[str]:
    """semgrep's excludes are a REPEATED flag taking one glob each; bandit's is one comma list.

    Returns the values VERBATIM. Normalising is left to the caller precisely because a normalisation
    DIFFERENCE between the two gates is one of the things worth asserting — see the `./` check in
    ``test_semgrep_and_bandit_exclude_the_same_paths``, which would be erased by normalising here.
    """
    return {m.group(1).strip() for m in re.finditer(r"--exclude[= ]([^\s\\]+)", command)}


def test_ci_semgrep_scans_the_repo_not_an_allow_list() -> None:
    """`messagefoundry tee` left scripts/ (the security tooling itself), messagefoundry_webconsole/
    and docker/ — 59 tracked .py files the sibling bandit gate already scans — covered by none of the
    project's own dangerous-sink rules. Scanning `.` minus explicit excludes cannot go stale when the
    next package is added."""
    command = _semgrep_command()

    targets = _semgrep_targets(command)
    assert targets == ["."], (
        "CI semgrep must scan `.` with explicit --exclude, not an allow-list of dirs; it scans "
        f"{targets!r}. An allow-list cannot be kept in step with 'the project' by hand — that is "
        "precisely how the old `messagefoundry tee` scope came to miss scripts/."
    )

    # An `--include` re-narrows the scan WITHOUT touching the positional target, so the assertion
    # above stays green through it. That is the whole regression this item exists to prevent, in the
    # one shape a "what is it pointed at?" check cannot see — so it is asserted on its own terms.
    includes = _semgrep_includes(command)
    assert not includes, (
        f"CI semgrep is pointed at `.` but restricted with --include {sorted(includes)}. semgrep's "
        "--include NARROWS the scan to matching paths, so this rebuilds the retired allow-list while "
        "the positional target still reads `.` — the scope regression this test exists to catch, "
        "wearing the argv of the fix."
    )


def test_ci_semgrep_still_fails_the_build_on_a_finding() -> None:
    """Scope is only half the gate: semgrep exits 0 on findings unless `--error` is passed.

    Without it this job reports every match and then goes GREEN — a required context that cannot
    fail, which is strictly worse than the narrow scope it replaced, because the narrow scope at
    least still red on what it did see. `tests/test_security_posture.py`'s neutering scan cannot
    catch this: it matches ADDED idioms (`|| true`, `--exit-zero`), never a REMOVED enforcement flag.
    Widening the scan from 280 to 339 files is what makes this worth its own assertion.
    """
    command = _semgrep_command()
    assert "--error" in command, (
        "the repo-wide semgrep command dropped `--error`, so semgrep exits 0 on findings: every "
        "match across the whole scanned tree would be printed and the required context would still "
        f"report success. Got: {command!r}"
    )


def test_semgrep_and_bandit_exclude_the_same_paths() -> None:
    """The two blocking SAST gates scan the same checkout, so they must agree on what is out of scope.

    Unlike the bandit hook-vs-CI test above, nothing is subtracted here: both sides are CI
    invocations over the identical tree, so .venv/node_modules must appear on BOTH — there is no
    pre-commit "these are untracked anyway" carve-out to grant.

    This does NOT assert that the two excludes have the same MEANING: bandit's are paths, semgrep's
    are globs, and whether semgrep anchors them at the repo root is not settled by reading a string.
    It asserts only that the two gates name the same set, which is the part that drifts — plus the
    one normalisation difference that comparing normalised sets would otherwise hide.
    """
    semgrep_cmd = _semgrep_command()
    semgrep_raw = _semgrep_excludes(semgrep_cmd)

    bandit_cmd = _ci_command(_ci_step_run(_SECURITY, "Scan source for insecure patterns"), "bandit")
    m = re.search(r"--exclude[= ]([^\s\\]+)", bandit_cmd)
    assert m, f"CI bandit step has no --exclude: {bandit_cmd!r}"
    bandit_raw = {p.strip() for p in m.group(1).split(",")}

    # Non-vacuity, BEFORE any comparison: two empty sets compare equal. An extractor that quietly
    # stopped matching — a renamed flag, a reflowed line — would make this test report PASS while
    # comparing nothing at all. Prove each instrument still sees something first.
    assert semgrep_raw, f"the semgrep --exclude extractor matched nothing in: {semgrep_cmd!r}"
    assert bandit_raw, f"the bandit --exclude extractor matched nothing in: {bandit_cmd!r}"

    # The set comparison below normalises `./` off BOTH sides, so on its own it would report parity
    # for `./tests` vs `tests` — two strings that do NOT mean the same thing to the two tools.
    # bandit's --exclude takes PATHS, where `./tests` is fine; semgrep's takes GLOBS, where `./tests`
    # matches nothing and the flag is simply inert. So the most likely way to break this scope is to
    # "fix" the drift by copying bandit's string byte-for-byte. Asserted before the normalisation.
    dot_slash = sorted(p for p in semgrep_raw if p.startswith("./"))
    assert not dot_slash, (
        f"semgrep --exclude values {dot_slash} carry bandit's `./` prefix. semgrep matches --exclude "
        "as a GLOB, so `./tests` excludes nothing and the flag is inert — while the set comparison "
        "in this same test normalises `./` away and would report the two gates in perfect parity."
    )

    semgrep_paths = {p.removeprefix("./").rstrip("/") for p in semgrep_raw}
    bandit_paths = {p.removeprefix("./").rstrip("/") for p in bandit_raw}

    assert semgrep_paths == bandit_paths, (
        f"SAST scope drifted: semgrep excludes {sorted(semgrep_paths)}, bandit excludes "
        f"{sorted(bandit_paths)}. A path excluded from ONE gate only is scanned by one and not the "
        "other, which is the same class of silent divergence that left scripts/ out of CI bandit."
    )
