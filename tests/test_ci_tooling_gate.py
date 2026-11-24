# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _bash_resolver import explain_returncode, probe_env, require_bash  # noqa: E402

from tests import _tooling_manifest as tooling_manifest  # noqa: E402
from tests._workflow_contexts import changes_arm_pattern  # noqa: E402

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"


def _gate_regex() -> str:
    """Pull the tooling arm's `grep -qE '...'` pattern out of the workflow.

    Anchored on the `tooling=true` emission and searched backwards, so renaming the surrounding
    comment cannot silently pick up a different arm. If the shape changes, this raises and the file
    goes red -- which is the correct outcome, not a false pass.
    """
    # `tooling=true` is emitted THREE times: the workflow_dispatch and push early-exits, and the
    # pull_request path arm. Only the last is a path decision, which is why the shared reader
    # anchors on the LAST emission; anchoring on the first found no preceding `grep -qE` at all.
    return changes_arm_pattern("tooling", "tooling_manifest")


def gate(changed: list[str]) -> bool:
    """Mirror of the shell decision. `grep -qE P` on the path arm, `grep -qxFf` on the manifest arm.

    The manifest arm goes through the one shared parser (BACKLOG #1434). That parser refuses the
    lines found so far that ci.yml's `grep -vE` would read differently; its docstring lists them.
    Nothing here executes that grep pipeline, so the two are kept close, not proven equal.
    """
    pattern = re.compile(_gate_regex())
    if any(pattern.search(p) for p in changed):
        return True
    return bool(set(changed) & set(tooling_manifest.entries()))


# (changed paths, expected, why this row exists)
_CASES = [
    ([".gitignore"], True, "BACKLOG #327: the leak guard must face a .gitignore-only PR"),
    ([".gitattributes"], True, "rides along with .gitignore in the alwayscodepath arm"),
    (["messagefoundry/pipeline/engine.py"], False, "engine-only: the entire point of the split"),
    (["tests/test_api_auth.py"], False, "an unlisted engine test is not harness work"),
    (["tests/test_security_static.py"], False, "imports the engine, so runs on the engine legs"),
    (["scripts/worktree/new.ps1"], True, "the harness itself"),
    ([".github/workflows/ci.yml"], True, "the workflow files are a listed test's subject"),
    (["CLAUDE.md"], True, "root CLAUDE.md -- `\\.claude/` matches the DIRECTORY, not this file"),
    (["docs/security/THREAT-MODEL.md"], True, "all of docs/, not just BACKLOG and adr"),
    (["pyproject.toml"], True, "test_new_dependency_check reads it"),
    # The new-dependency gate's default sweep also reads every packaging/*/pyproject.toml and a
    # hatch.toml beside any swept pyproject (BACKLOG #5641), so an edit to one must run the tier.
    (
        ["packaging/messagefoundry-toolkit/pyproject.toml"],
        True,
        "test_new_dependency_check sweeps every packaging pyproject",
    ),
    (["hatch.toml"], True, "merged over the root's [tool.hatch] by the gate"),
    (
        ["packaging/messagefoundry-harness/hatch.toml"],
        True,
        "merged over a packaging pyproject's [tool.hatch] by the gate",
    ),
    (
        ["packaging/messagefoundry-webconsole/README.md"],
        False,
        "only the files the gate reads, not the whole packaging tree",
    ),
    (["ide/package.json"], True, "test_ide_licence_packaging reads ide/"),
    (["LICENSE"], True, "same test reads LICENSE"),
    (["tests/tooling_manifest.txt"], True, "edit the partition, re-run the tier it defines"),
    (["tests/conftest.py"], True, "the hook that applies the marker"),
    (["tests/_tooling_manifest.py"], True, "the parser that hook reads the manifest through"),
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
    # anything else here. `uv.lock` is the SCOPE guard: ci.yml lists constraints.lock and
    # requirements.lock because listed tests READ them (requirements.lock since BACKLOG #5472, through
    # test_ci_venv_pinning's runtime-export sweep), and no listed test reads uv.lock by name. A widening to it
    # (or a `\.lock$`-shaped alternative) would run this whole tier on every edit of a lock nothing
    # here reads, while quietly replacing a reasoned choice. `constraints_lock` is the SHAPE guard: it is not a path and cannot
    # become one, which is exactly why it works -- it matches only if `constraints\.lock` loses its
    # backslash, and an unescaped dot reads as correct in review. The leading `\.` of
    # `\.pre-commit-config\.yaml` gets no equivalent probe: under the `^` anchor an unescaped one
    # matches any single leading character, so every candidate is a path nobody would ever add, and a
    # row nobody believes gets deleted the first time it is inconvenient.
    (["uv.lock"], False, "no listed test reads uv.lock by name; constraints.lock is what it READS"),
    (["constraints_lock"], False, "not a path: reds only if `constraints\\.lock` loses its escape"),
    # BACKLOG #5472: each file below is read from the repository by a manifest entry, and before
    # that row none matched an arm, so a PR editing only one met the test that reads it on no leg.
    # NOT CLOSED: a listed test that scans every tracked file, such as
    # test_defaulted_credential_lint, reads paths no arm names, so a PR touching only those meets
    # it first on push-to-main.
    ([".gitleaks.toml"], True, "test_merge_gate_controls reads the gitleaks allowlist"),
    ([".semgrep/messagefoundry.yml"], True, "test_required_contexts scans the semgrep rules"),
    ([".codex/config.toml"], True, "test_codex_bridge reads the Codex hook config"),
    (["ci/locks/release-tools.lock"], True, "test_ci_venv_pinning reads the release lock"),
    (["ci/locks/ci-quality.lock"], True, "test_quality_advisory_invariants reads it"),
    (["ci/locks/ci-scanners.lock"], True, "a sibling under the same ci/locks/ arm"),
    (["requirements.lock"], True, "test_ci_venv_pinning sweeps the runtime exports"),
    (["docker/locks/requirements-core.lock"], True, "one of those runtime exports"),
    (["security/locks/requirements-harness.lock"], True, "one of those runtime exports"),
    # The CI Python pin. A patch bump edits that one file, and the test that reads it is a manifest
    # entry, so without this arm the bump PR would meet that test on no leg.
    (
        ["ci/python-version"],
        True,
        "a patch bump edits only the pin test_ci_tool_and_image_pins reads",
    ),
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
    missed = sorted(p for p in tooling_manifest.entries() if not gate([p]))
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
    # THE CHILD NEEDS REAL UTILITIES, NOT JUST THE INTERPRETER (BACKLOG #1373). The step below runs
    # `git` and `grep`; a PATH without them -- what PowerShell and cmd supply -- fails the child at
    # 127, and the detector's `if echo ... | grep -qE` then takes its ELSE branch and writes
    # `tooling=false`. The test reads that as the workflow filter narrowing, so a harness fault
    # accuses content that was never wrong. `probe_env` appends the interpreter's own directory,
    # where those utilities ship. Same call, same reason, as
    # tests/test_dependabot_automerge_guardrails.py.
    env = probe_env(Path(bash), dict(os.environ))
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


def _legs(matrix: str) -> list[str]:
    """The os of each leg in a `tooling_matrix` output, an `include` list, in order."""
    return [str(leg["os"]) for leg in json.loads(matrix)["include"]]


def test_the_tooling_job_reads_the_matrix_and_does_not_carry_a_literal() -> None:
    """A literal `os: [...]` here would silently undo the narrowing and still look correct."""
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    matrix = doc["jobs"]["tooling"]["strategy"]["matrix"]
    assert isinstance(matrix, str) and "tooling_matrix" in matrix, (
        "the tooling job's matrix is no longer the `changes` output -- a literal list here restores "
        "the full two-leg tier on every docs-only PR, with nothing to say so"
    )


@pytest.mark.parametrize("event", ["workflow_dispatch", "push", "schedule", "merge_group"])
def test_every_non_pr_arm_emits_a_matrix(tmp_path: Path, event: str) -> None:
    """An arm that exits without emitting KILLS the tooling job on fromJSON. It does not skip it."""
    bash = require_bash(tmp_path)
    outputs = _run_detector(bash, tmp_path, event)
    assert "tooling_matrix" in outputs, (
        f"the `{event}` arm exits without writing tooling_matrix. fromJSON on an unset output FAILS "
        "the job -- it does not fall back to a full matrix"
    )
    assert _legs(outputs["tooling_matrix"]), f"the `{event}` arm emitted an empty leg list"


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
    docs_legs = _legs(docs_out["tooling_matrix"])

    code = tmp_path / "code_pr"
    code.mkdir()
    base = _pr_repo(code, ["messagefoundry/api/app.py"])
    code_out = _run_detector(bash, code, "pull_request", base_sha=base)
    assert code_out["code"] == "true"
    code_legs = _legs(code_out["tooling_matrix"])

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
    legs = _legs(outputs["tooling_matrix"])
    assert legs == ["ubuntu-latest"], (
        f"a fork should build this tier on ubuntu only, got {legs} -- the 2x-billed Windows leg "
        "would be spending a contributor's own minutes"
    )


# ---------------------------------------------------------------------------------------------
# THE TEST SHARDS (owner ruling 2026-11-24): windows-2025 runs the tier as 3 test shards, ubuntu as
# one leg. A leg's `shard` and `of` reach scripts/quality/shard_tests.py `--suite tooling`; that
# script's own tests hold the split, these hold the wiring. A leg whose shards had a gap, a second
# `of`, a shared check name or a shared artifact name would drop files, fail the upload, or hide a
# red leg behind its sibling's name, each with every other check here green.
# ---------------------------------------------------------------------------------------------

_HARNESS_STEP = "Harness tests (pytest)"
_GUARD_STEP = "Tooling shards partition pytest's collection"
_RECEIPT_STEP = "Prove the tier actually ran"


def _tooling_step(name: str) -> dict[str, object]:
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    found = [s for s in doc["jobs"]["tooling"]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"expected one {name!r} step in the tooling job, found {len(found)}"
    return dict(found[0])


def _full_matrix(tmp_path: Path) -> list[dict[str, str]]:
    bash = require_bash(tmp_path)
    outputs = _run_detector(bash, tmp_path, "push")
    return list(json.loads(outputs["tooling_matrix"])["include"])


def test_windows_2025_runs_the_tier_in_three_test_shards_and_ubuntu_in_one(tmp_path: Path) -> None:
    """Falsified by dropping `$TW"3"}` from TOOLING_FULL in ci.yml: RED. Restored."""
    legs = _full_matrix(tmp_path)
    assert legs == [
        {"os": "ubuntu-latest", "shard": "1", "of": "1"},
        *({"os": "windows-2025", "of": "3", "shard": str(n)} for n in (1, 2, 3)),
    ], legs
    for os_name in {leg["os"] for leg in legs}:
        mine = [leg for leg in legs if leg["os"] == os_name]
        counts = {leg["of"] for leg in mine}
        assert len(counts) == 1, f"{os_name} legs disagree on the shard count: {counts}"
        assert sorted(int(leg["shard"]) for leg in mine) == list(range(1, int(counts.pop()) + 1))


def test_every_tooling_leg_has_its_own_check_name_and_junit_artifact(tmp_path: Path) -> None:
    """The name is the expression ci-gate's CHECK_NAMES shows as `repo harness tests (*)`; this
    evaluates it per leg. Falsified by naming the job `repo harness tests (${{ matrix.os }})`: RED,
    three windows legs on one name. Restored."""
    doc = yaml.safe_load(_CI.read_text(encoding="utf-8"))
    job = doc["jobs"]["tooling"]
    assert job["name"] == (
        "repo harness tests (${{ matrix.of == '1' && matrix.os || format('{0}, shard {1} of {2}', "
        "matrix.os, matrix.shard, matrix.of) }})"
    )
    legs = _full_matrix(tmp_path)
    names = [
        leg["os"] if leg["of"] == "1" else f"{leg['os']}, shard {leg['shard']} of {leg['of']}"
        for leg in legs
    ]
    assert "ubuntu-latest" in names, "the ubuntu leg's check name changed"
    assert len(set(names)) == len(names), names
    upload = _tooling_step("Upload the tier's junit")
    template = str(dict(upload["with"])["name"])  # type: ignore[call-overload]
    assert (
        template == "tooling-junit-${{ matrix.os }}-shard-${{ matrix.shard }}-of-${{ matrix.of }}"
    )
    artifacts = {
        template.replace("${{ matrix.os }}", leg["os"])
        .replace("${{ matrix.shard }}", leg["shard"])
        .replace("${{ matrix.of }}", leg["of"])
        for leg in legs
    }
    assert len(artifacts) == len(legs), artifacts


def test_each_leg_runs_its_own_shard_of_the_tier() -> None:
    """The selector call, the `@file` argument and the env that feeds both, read off the step."""
    step = _tooling_step(_HARNESS_STEP)
    env = dict(step["env"])  # type: ignore[call-overload]
    assert env["TOOLING_SHARD"] == "${{ matrix.shard }}"
    assert env["TOOLING_OF"] == "${{ matrix.of }}"
    run = str(step["run"])
    assert (
        'shard_tests.py --suite tooling --shard "$TOOLING_SHARD" --of "$TOOLING_OF"'
        " > out/tooling-shard/files.txt"
    ) in run
    pytest_line = next(line for line in run.splitlines() if line.startswith("pytest "))
    assert pytest_line.endswith(" @out/tooling-shard/files.txt"), pytest_line
    for needle in ('-n "$TOOLING_WORKERS"', "--dist loadfile", "-m tooling", "--durations="):
        assert needle in pytest_line, f"{needle!r} left the harness step: {pytest_line}"


def test_the_partition_guard_reads_the_tier_s_selection_on_one_leg(tmp_path: Path) -> None:
    """Falsified by `--of 2` on the guard line: RED on the count. Restored."""
    harness = str(_tooling_step(_HARNESS_STEP)["run"])
    pytest_line = next(line for line in harness.splitlines() if line.startswith("pytest "))
    guard = _tooling_step(_GUARD_STEP)
    condition = str(guard["if"])
    for needle in ("!cancelled()", "steps.tests.outcome == 'success'", "runner.os == 'Linux'"):
        assert needle in condition, condition
    match = re.fullmatch(
        r"python scripts/quality/shard_tests\.py --suite tooling --of (\d+) --check-collection"
        r" -- (.+)",
        str(guard["run"]).strip(),
    )
    assert match, guard["run"]
    shard_counts = {leg["of"] for leg in _full_matrix(tmp_path) if leg["of"] != "1"}
    assert shard_counts == {match.group(1)}, (shard_counts, match.group(1))
    for word in match.group(2).split(" -- ")[0].split():
        assert word in pytest_line, f"the guard selects with {word!r}, the harness step does not"
    assert "-m tooling" in match.group(2)


def test_the_receipt_holds_each_shard_to_its_share_and_a_dead_marker_still_goes_red(
    tmp_path: Path,
) -> None:
    """A dead marker executes nothing on every shard, so the per-shard floor still fires on it.
    Falsified by `return min_executed` in floor_for: RED on the 334-test shard. Restored."""
    step = _tooling_step(_RECEIPT_STEP)
    assert str(step["run"]).endswith('--shards "$TOOLING_OF"'), step["run"]
    assert dict(step["env"])["TOOLING_OF"] == "${{ matrix.of }}"  # type: ignore[call-overload]
    script = _ROOT / "scripts" / "ci" / "tooling_receipt.py"

    def receipt(executed: int, skipped: int, shards: int) -> int:
        report = tmp_path / f"junit-{executed}-{skipped}-{shards}.xml"
        cases = (
            '<testcase name="t"/>' * executed + '<testcase name="s"><skipped/></testcase>' * skipped
        )
        report.write_text(
            f"<testsuites><testsuite>{cases}</testsuite></testsuites>", encoding="utf-8"
        )
        done = subprocess.run(  # noqa: S603  # nosec B603 - this interpreter, fixed argv
            [sys.executable, str(script), "--report", str(report), "--shards", str(shards)],
            capture_output=True,
            timeout=120,
            check=False,
            cwd=str(_ROOT),
        )
        return done.returncode

    assert receipt(0, 2000, 3) == 1, "a dead marker (everything skipped) passed a shard's receipt"
    assert receipt(334, 0, 3) == 0, "a shard that ran its third of the floor went red"
    assert receipt(333, 0, 3) == 1
    assert receipt(334, 0, 1) == 1, "the unsharded leg must keep the whole floor"
    assert receipt(1000, 0, 1) == 0


# ---------------------------------------------------------------------------------------------
# THE REGRESSION ARM for BACKLOG #1373. Everything above asks what the detector decides; this asks
# whether the ANSWER SURVIVES A STRIPPED PATH, which is a separate failure with the same appearance.
#
# The damage shape is what makes it worth an arm of its own. Without the utilities the detector's
# `grep -qE` cannot run, the `if` takes its else branch, the step writes `tooling=false`, and
# `test_a_docs_only_pr_gets_one_leg_and_a_code_pr_gets_both` fails saying THE FILTER MUST NOT
# NARROW -- a sentence about ci.yml, produced by a box that never read ci.yml's answer. A reader
# acting on it edits a workflow that was never wrong. Measured on one variable before the fix: this
# module was 27 passed with coreutils on PATH and 1 failed without.
# ---------------------------------------------------------------------------------------------


def _git_only_path(tmp_path: Path) -> str:
    """A PATH carrying `git` and NOTHING ELSE, synthesised rather than borrowed from the host.

    The item's end-to-end condition is Git's own `cmd` directory on PATH but not its `usr/bin`.
    Reading that off the host reproduces it on Windows and is VACUOUS on Linux, where `git` and
    coreutils share `/usr/bin` -- a green there would prove nothing, on the leg this tier always
    runs. A directory holding one shim has the same shape on every OS.

    ***THE SHEBANG IS LOAD-BEARING, NOT DECORATION -- DO NOT DELETE IT AS REDUNDANT.*** `/bin/sh` is
    ABSOLUTE, so resolving it needs no PATH, which is what lets the shim run on a PATH holding
    nothing but itself. That is the whole mechanism, and it is the shebang that supplies it.

    Measured on this box, one variable, three arms -- a shebang naming a MISSING interpreter is the
    discriminator, because bash's ENOEXEC fallback would read that line as a comment and succeed::

        no shebang                    rc 0     ran via bash's ENOEXEC fallback
        #!/bin/sh                     rc 0     ran via the shebang
        #!/nonexistent/interp         rc 126   "bad interpreter" -- the shebang IS resolved

    So this file does NOT take the ENOEXEC path and never did. Deleting the shebang would MOVE it
    onto that path, which arm 1 shows works here and which nothing in this suite measures anywhere
    else. (126 is `BASH_CANNOT_EXECUTE` in `_bash_resolver`, named there for this exact reason.)
    """
    git = shutil.which("git")
    assert git, "git is not on PATH, so the fixtures in this module could not have been built"
    stub = tmp_path / "gitonly"
    stub.mkdir()
    shim = stub / "git"
    shim.write_text(
        f'#!/bin/sh\nexec "{Path(git).as_posix()}" "$@"\n', encoding="utf-8", newline="\n"
    )
    shim.chmod(0o755)
    return str(stub)


def test_the_tooling_verdict_survives_a_coreutils_less_PATH(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A working interpreter plus a PATH without coreutils must still produce ci.yml's real answer.

    Resolve the interpreter and build the fixture repository FIRST, while PATH is still whole: the
    subject is the CHILD's environment, and stripping the parent's would only measure whether this
    test can find its own tools.
    """
    bash = require_bash(tmp_path)
    repo = tmp_path / "docs_pr"
    repo.mkdir()
    base = _pr_repo(repo, ["docs/ARCHITECTURE.md"])
    stripped = _git_only_path(tmp_path)

    # ANTI-VACUITY, and it runs before the assertion rather than after it. If the stub PATH ever
    # reaches coreutils by some route -- an inherited BASH_ENV, a shim directory that gained a
    # sibling -- the row below passes for the wrong reason and goes on passing forever. So make the
    # instrument say the opposite first: this exact PATH, this exact interpreter, no `probe_env`.
    control = subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv
        [bash, "-c", "grep --version"],
        env={**os.environ, "PATH": stripped},
        capture_output=True,
        timeout=120,
        check=False,
    )
    assert control.returncode != 0, (
        "the stub PATH still reaches `grep`, so this test cannot fail and measures nothing"
    )

    monkeypatch.setenv("PATH", stripped)
    outputs = _run_detector(bash, repo, "pull_request", base_sha=base)
    assert outputs["tooling"] == "true", (
        "a coreutils-less PATH turned the tooling verdict false. The workflow filter is not wrong "
        "-- the child could not run `grep`, so every `if` in the detector took its else branch "
        "(BACKLOG #1373). Route the child env through `probe_env`"
    )
    assert outputs["code"] == "false", (
        "the docs-only short-circuit did not fire, so `git diff` returned nothing through the shim "
        "and the verdict above was reached without reading the fixture at all"
    )
