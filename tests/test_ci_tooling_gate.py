# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The CI `tooling` path-gate, driven directly.

`ci.yml`'s `changes` job decides whether the `tooling` job runs. That job is the ONLY place the
repo-harness tier executes -- the engine legs deselect it with ``-m 'not tooling'`` -- so a defect in
this gate does not fail loudly, it removes the thing that would have failed. `ci-gate` treats a
skipped need as a pass, so the whole workflow still reports green.

**This is not hypothetical, it is a regression this gate already had.** BACKLOG #327 established that
`.gitignore` must be force-classified as CODE, because six of its rules are the sole control keeping
maintainer-internal material out of a public commit and `tests/test_private_paths_stay_ignored.py` is
what asserts they still match. The tier split broke that one layer above #327's fix: `code=true` still
ran the test legs, but they now DESELECT that guard, and `.gitignore` matched no arm of this gate --
so a `.gitignore`-only PR faced the leak guard on no leg at all. Same defect, new route, and nothing
caught it until an adversarial review did. The first case below is that exact PR shape.

**The regex is READ OUT OF `ci.yml`, never copied here**, and the manifest arm is read out of the
manifest -- the same rule `test_ci_docs_only_detector.py` states for its sibling filter. A test
carrying its own copy of the pattern passes forever while the workflow drifts underneath it, which
reproduces the defect this file exists to prevent one level up.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bash_resolver import explain_returncode, require_bash  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_MANIFEST = _ROOT / "tests" / "tooling_manifest.txt"


def _gate_regex() -> str:
    """Pull the tooling arm's `grep -qE '...'` pattern out of the workflow.

    Anchored on the `tooling=true` emission and searched backwards, so renaming the surrounding
    comment cannot silently pick up a different arm. If the shape changes, this raises and the file
    goes red -- which is the correct outcome, not a false pass.
    """
    text = _CI.read_text(encoding="utf-8")
    # `tooling=true` is emitted THREE times: the workflow_dispatch and push early-exits, and the
    # pull_request path arm. Only the last is a path decision -- the first two are unconditional and
    # sit ahead of any grep in the step. rfind, deliberately: anchoring on the first match found no
    # preceding `grep -qE` at all, which is the honest failure this comment exists to prevent
    # recurring as a silent wrong-arm pickup if the block order ever changes.
    emit = text.rfind('echo "tooling=true" >> "$GITHUB_OUTPUT"')
    assert emit > 0, "the tooling arm's GITHUB_OUTPUT emission is gone; this gate was restructured"
    # the LAST grep -qE before that emission is the path arm
    matches = list(re.finditer(r"grep -qE '([^']*)'", text[:emit]))
    assert matches, "no `grep -qE` found before the tooling emission"
    return matches[-1].group(1)


def _manifest_paths() -> set[str]:
    return {
        ln.strip()
        for ln in _MANIFEST.read_text(encoding="utf-8").splitlines()
        if ln.strip() and not ln.lstrip().startswith("#")
    }


def gate(changed: list[str]) -> bool:
    """Mirror of the shell decision. `grep -qE P` on the path arm, `grep -qxFf` on the manifest arm."""
    pattern = re.compile(_gate_regex())
    if any(pattern.search(p) for p in changed):
        return True
    return bool(set(changed) & _manifest_paths())


# (changed paths, expected, why this row exists)
_CASES = [
    ([".gitignore"], True, "BACKLOG #327: the leak guard must face a .gitignore-only PR"),
    ([".gitattributes"], True, "rides along with .gitignore in the alwayscodepath arm"),
    (["messagefoundry/pipeline/engine.py"], False, "engine-only: the entire point of the split"),
    (["tests/test_api_auth.py"], False, "an unlisted engine test is not harness work"),
    (["tests/test_security_static.py"], False, "stay-listed: runs on the engine legs, which run"),
    (["scripts/worktree/new.ps1"], True, "the harness itself"),
    ([".github/workflows/ci.yml"], True, "the workflow files are a listed test's subject"),
    (["CLAUDE.md"], True, "root CLAUDE.md -- `\\.claude/` matches the DIRECTORY, not this file"),
    (["docs/security/THREAT-MODEL.md"], True, "all of docs/, not just BACKLOG and adr"),
    (["pyproject.toml"], True, "test_new_dependency_check reads it"),
    (["ide/package.json"], True, "test_ide_licence_packaging reads ide/"),
    (["LICENSE"], True, "same test reads LICENSE"),
    (["tests/tooling_manifest.txt"], True, "edit the partition, re-run the tier it defines"),
    (["tests/conftest.py"], True, "the hook that applies the marker"),
    # The four rows below pin the arm widened on 2026-08-18, and they are the only thing that does.
    # tests/test_lint_scope_parity.py is a manifest entry whose subject is a three-way agreement: the
    # ruff `rev:` pinned in .pre-commit-config.yaml, the `ruff==` constraints.lock installs, and the
    # cap in pyproject.toml. Measured against this regex as it stood that morning, NEITHER file
    # matched EITHER arm -- so a `pre-commit autoupdate` PR, which by construction rewrites revs and
    # touches nothing else, met that guard on no leg at all: the engine legs deselect it with
    # `-m 'not tooling'`, this job skipped, and ci-gate reads a skipped need as a pass. Dropping
    # either alternative from ci.yml again leaves every other row in this table green, which is the
    # silent-removal shape the module docstring describes, one layer further out.
    ([".pre-commit-config.yaml"], True, "an autoupdate PR must face test_lint_scope_parity"),
    (["constraints.lock"], True, "a lock-only ruff bump edits no other file this gate names"),
    # Two negatives, one per way those two alternatives can go wrong, because neither way reds
    # anything else here. `uv.lock` is the SCOPE guard: ci.yml lists constraints.lock rather than its
    # two siblings because it is the file the test READS, and a widening (an added sibling, or a
    # `\.lock$`-shaped alternative) would run this whole tier on every dependency PR while quietly
    # replacing a reasoned choice. `constraints_lock` is the SHAPE guard: it is not a path and cannot
    # become one, which is exactly why it works -- it matches only if `constraints\.lock` loses its
    # backslash, and an unescaped dot reads as correct in review. The leading `\.` of
    # `\.pre-commit-config\.yaml` gets no equivalent probe: under the `^` anchor an unescaped one
    # matches any single leading character, so every candidate is a path nobody would ever add, and a
    # row nobody believes gets deleted the first time it is inconvenient.
    (["uv.lock"], False, "sibling locks are unlisted: constraints.lock is what the test READS"),
    (["constraints_lock"], False, "not a path: reds only if `constraints\\.lock` loses its escape"),
    (
        ["messagefoundry/api/app.py", "docs/ARCHITECTURE.md"],
        True,
        "MIXED code+docs is the common PR shape and was the gap",
    ),
]


@pytest.mark.parametrize(("changed", "expected", "why"), _CASES)
def test_gate_decides(changed: list[str], expected: bool, why: str) -> None:
    assert gate(changed) is expected, f"{changed} should gate {expected}: {why}"


def test_every_manifest_entry_trips_its_own_gate() -> None:
    """Editing a listed test must run the tier that owns it.

    Covered by the manifest arm rather than the path regex, so this asserts the arm is wired at all --
    without it a manifest entry outside scripts/ or docs/ could be edited with no coverage.
    """
    missed = sorted(p for p in _manifest_paths() if not gate([p]))
    assert not missed, f"these listed tests do not trip the tooling gate when edited: {missed}"


def test_the_regex_is_read_not_copied() -> None:
    """If the arm is renamed or restructured, `_gate_regex` raises rather than passing on a stale copy."""
    assert "gitignore" in _gate_regex(), (
        "the extracted pattern does not mention .gitignore -- either the wrong grep was picked up, or "
        "the BACKLOG #327 arm was removed"
    )


# ---------------------------------------------------------------------------------------------
# The MATRIX half of the gate. The tests above ask "does this tier RUN"; these ask "on how many
# LEGS", which is a separate decision with a separate failure mode.
#
# `tooling_matrix` narrows the tier to ubuntu on a docs-only PR. That is safe only because the tier
# still RUNS -- the 22 document-reading files in the manifest keep their coverage, on one leg instead
# of two. If a future edit ever narrows the FILTER instead, the tests above go red. That is the
# division of labour between the two blocks, and neither can cover for the other.
#
# WHY THESE EXECUTE THE STEP RATHER THAN READING IT. The narrowing lives in shell inside a `run:`
# block, and the value has to be emitted on FIVE arms -- dispatch, push, schedule, docs-only PR, code
# PR. An arm added later without the emission is invisible in review and fatal at run time: fromJSON
# on an unset output kills the job rather than falling back to the full matrix. A text assertion
# would confirm the lines exist; only running the thing confirms every path through it emits one.
# ---------------------------------------------------------------------------------------------

_SOURCE_REPO = "MEFORORG/MessageFoundry"


def _changes_step_script() -> str:
    """The `changes` job's detector step, read out of the workflow rather than restated here."""
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    steps = doc["jobs"]["changes"]["steps"]
    run = next((st["run"] for st in steps if st.get("id") == "f"), None)
    assert run, "the `changes` job has no step with id `f`; this gate was restructured"
    return str(run)


def _run_detector(
    bash: str, cwd: Path, event: str, *, repo: str = _SOURCE_REPO, base_sha: str = ""
) -> dict[str, str]:
    """Execute the real step and return the outputs it wrote, parsed."""
    script = cwd / "detector.sh"
    script.write_text(_changes_step_script(), encoding="utf-8", newline="\n")
    out_file = cwd / "gh_output"
    out_file.write_text("", encoding="utf-8")
    env = dict(os.environ)
    env.update(
        {
            "EVENT_NAME": event,
            "BASE_SHA": base_sha,
            "GITHUB_REPOSITORY": repo,
            "GITHUB_OUTPUT": str(out_file),
        }
    )
    proc = subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv, tmp paths
        [bash, str(script)],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        timeout=180,
        check=False,
    )
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "the `changes` detector step")
        + "\n"
        + proc.stderr.decode("utf-8", "replace")
    )
    parsed: dict[str, str] = {}
    for line in out_file.read_text(encoding="utf-8").splitlines():
        if "=" in line:
            key, _, value = line.partition("=")
            parsed[key] = value
    return parsed


def _git(cwd: Path, *args: str) -> str:
    out = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        ["git", *args], cwd=str(cwd), capture_output=True, check=True, timeout=120
    )
    return out.stdout.decode("utf-8", "replace").strip()


def _pr_repo(cwd: Path, changed: list[str]) -> str:
    """A two-commit repo, so the step's own `git diff BASE...HEAD` has something real to read."""
    _git(cwd, "init", "-q", "-b", "main")
    _git(cwd, "config", "user.email", "t@example.invalid")
    _git(cwd, "config", "user.name", "t")
    (cwd / "seed.txt").write_text("seed\n", encoding="utf-8")
    _git(cwd, "add", "seed.txt")
    _git(cwd, "commit", "-qm", "base")
    base = _git(cwd, "rev-parse", "HEAD")
    for rel in changed:
        target = cwd / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("x\n", encoding="utf-8")
        _git(cwd, "add", rel)
    _git(cwd, "commit", "-qm", "head")
    return base


def test_the_tooling_job_reads_the_matrix_and_does_not_carry_a_literal() -> None:
    """A literal `os: [...]` here would silently undo the narrowing and still look correct."""
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    matrix = doc["jobs"]["tooling"]["strategy"]["matrix"]
    assert isinstance(matrix, str) and "tooling_matrix" in matrix, (
        "the tooling job's matrix is no longer the `changes` output -- a literal list here restores "
        "the full two-leg tier on every docs-only PR, with nothing to say so"
    )


@pytest.mark.parametrize("event", ["workflow_dispatch", "push", "schedule"])
def test_every_non_pr_arm_emits_a_matrix(tmp_path: Path, event: str) -> None:
    """An arm that exits without emitting KILLS the tooling job on fromJSON. It does not skip it."""
    bash = require_bash(tmp_path)
    outputs = _run_detector(bash, tmp_path, event)
    assert "tooling_matrix" in outputs, (
        f"the `{event}` arm exits without writing tooling_matrix. fromJSON on an unset output FAILS "
        "the job -- it does not fall back to a full matrix"
    )
    assert json.loads(outputs["tooling_matrix"])["os"], (
        f"the `{event}` arm emitted an empty os list"
    )


def test_a_docs_only_pr_gets_one_leg_and_a_code_pr_gets_both(tmp_path: Path) -> None:
    """The narrowing itself, end to end, through the step's own git diff.

    Both halves in one test on purpose: the property worth asserting is the DIFFERENCE. A docs-only
    assertion that passed because the full matrix had also collapsed to one leg would be a green
    proving nothing.
    """
    bash = require_bash(tmp_path)

    docs = tmp_path / "docs_pr"
    docs.mkdir()
    base = _pr_repo(docs, ["docs/ARCHITECTURE.md"])
    docs_out = _run_detector(bash, docs, "pull_request", base_sha=base)
    assert docs_out["code"] == "false", "a docs-only PR should short-circuit; the fixture is wrong"
    assert docs_out["tooling"] == "true", (
        "THE FILTER MUST NOT NARROW. 22 manifest files read documents, so a docs PR still runs this "
        "tier -- the change here narrows the MATRIX only"
    )
    docs_legs = json.loads(docs_out["tooling_matrix"])["os"]

    code = tmp_path / "code_pr"
    code.mkdir()
    base = _pr_repo(code, ["messagefoundry/api/app.py"])
    code_out = _run_detector(bash, code, "pull_request", base_sha=base)
    assert code_out["code"] == "true"
    code_legs = json.loads(code_out["tooling_matrix"])["os"]

    assert docs_legs == ["ubuntu-latest"], (
        f"docs-only PR should run one ubuntu leg, got {docs_legs}"
    )
    assert len(code_legs) > len(docs_legs), (
        f"a code PR must run MORE legs than a docs-only one ({code_legs} vs {docs_legs}); equal "
        "lists mean the narrowing is inert and this test would pass forever"
    )
    assert any("windows" in leg for leg in code_legs), (
        "the windows leg is the only one that runs the 337 platform-gated tests, so a code PR that "
        "loses it removes their only coverage"
    )


def test_a_fork_never_pays_for_the_windows_leg(tmp_path: Path) -> None:
    """The rule the `matrix` and `ide_matrix` outputs already follow, asserted for this one too."""
    bash = require_bash(tmp_path)
    outputs = _run_detector(bash, tmp_path, "push", repo="someone/MessageFoundry")
    legs = json.loads(outputs["tooling_matrix"])["os"]
    assert legs == ["ubuntu-latest"], (
        f"a fork should build this tier on ubuntu only, got {legs} -- the 2x-billed Windows leg "
        "would be spending a contributor's own minutes"
    )
