# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine suite's three shards in ci.yml, held to one another (BACKLOG #5247).

The suite runs as the `test` job's `Tests (pytest)` step, shard 1, and the `test-shards` job's step
of the same name, once per shard of its `shard` matrix axis. Every property below is one the split
can lose SILENTLY: a copy that drifts from the first runs the rest of the suite under different
belts, a shard number or count that disagrees drops or doubles files, a matrix that loses a leg or a
shard drops one, and a guard step whose selection differs from the suite's compares the shards with
the wrong collection. Each test reads the workflow, so a drift fails here, not on a hosted runner.
The selector's own logic is tests/test_quality_shard_tests.py's; the ci-gate step's condition is
tests/test_merge_gate_controls.py's, beside the reader that evaluates it.
"""

from __future__ import annotations

import functools
import json
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests._bash_resolver import explain_returncode, probe_env, require_bash

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_STEP = "Tests (pytest)"
_JOBS = ("test", "test-shards")
#: The env the shard-1 step carries and the others do not, each with its reason. MEFOR_CONNSCALE_LEG
#: arms the connscale herd floor, and the selector holds that smoke in shard 1.
_SHARD_ONE_ONLY_ENV = {"MEFOR_CONNSCALE_LEG"}
#: GitHub's documented workflow file size limit, 500 KB, read as KiB. The other reading, 500,000
#: bytes, is ruled out: a 505,273-byte ci.yml started runs, and one of 514,007 bytes did not.
_WORKFLOW_SIZE_LIMIT = 500 * 1024


@functools.cache
def _jobs() -> dict[str, Any]:
    """Parsed once per process: ci.yml does not change under a test run, and nothing here mutates it."""
    jobs: dict[str, Any] = yaml.safe_load(_CI.read_text(encoding="utf-8"))["jobs"]
    return jobs


def _step(job: str, name: str) -> dict[str, Any]:
    found = [s for s in _jobs()[job]["steps"] if s.get("name") == name]
    assert len(found) == 1, f"expected one {name!r} step in {job!r}, found {len(found)}"
    return found[0]


def _margin(job: str) -> dict[str, Any]:
    found = [s for s in _jobs()[job]["steps"] if "--since" in str(s.get("run", ""))]
    assert len(found) == 1, f"expected one margin check in {job!r}, found {len(found)}"
    return found[0]


def _pytest_argv(run: str) -> list[str]:
    # Continuations joined and an untokenizable line skipped, as the sibling readers in
    # test_ci_faulthandler_belts.py and test_ci_engine_step_excludes_webconsole.py do.
    commands: list[list[str]] = []
    for line in re.sub(r"\\\n[ \t]*", " ", run).splitlines():
        try:
            argv = shlex.split(line, comments=True)
        except ValueError:
            continue
        if any(word == "pytest" or word.endswith("/pytest") for word in argv):
            commands.append(argv)
    assert len(commands) == 1, f"expected one pytest command, found {commands}"
    return commands[0]


def _selection(argv: list[str]) -> list[str]:
    """The `-m` expression and every `--ignore-glob`, as they appear on a command line."""
    picked = [f"-m {argv[i + 1]}" for i, word in enumerate(argv) if word == "-m"]
    return picked + [word for word in argv if word.startswith("--ignore-glob")]


def _matrix_snippet() -> str:
    """The lines of the `changes` job's `f` step that build `matrix` and `shard_matrix`."""
    run = next(s for s in _jobs()["changes"]["steps"] if s.get("id") == "f")["run"]
    lines = str(run).splitlines()
    first = next(i for i, line in enumerate(lines) if line.startswith("U='"))
    last = next(i for i, line in enumerate(lines) if "shard_matrix=" in line)
    return "\n".join(lines[first : last + 1]) + "\n"


def _matrix_shards() -> list[str]:
    """The shards `test-shards` runs, as the `changes` step's loop names them."""
    found = re.findall(r"for shard in ([0-9 ]+); do", _matrix_snippet())
    assert len(found) == 1, found
    return found[0].split()


def test_the_shards_are_numbered_one_to_n() -> None:
    """`test` runs shard 1 and the matrix the rest, so together they are 1..N with no gap."""
    shards = ["1", *_matrix_shards()]
    assert shards == [str(n) for n in range(1, len(shards) + 1)], shards
    assert len(shards) == 3, "the third shard is what the owner ruling built; re-read it first"


def test_every_shard_runs_one_body_under_one_condition_and_one_cap() -> None:
    """A copy that drifts runs the rest of the suite under different flags or belts.

    Falsified by dropping `--max-worker-restart=0` from test-shards's run line: RED. Restored."""
    one, rest = (_step(job, _STEP) for job in _JOBS)
    for key in ("id", "if", "timeout-minutes", "run"):
        assert one.get(key) == rest.get(key), f"the shards' {_STEP!r} steps differ in {key!r}"
    env_one, env_rest = dict(one["env"]), dict(rest["env"])
    for name in _SHARD_ONE_ONLY_ENV:
        env_one.pop(name)
    assert env_one.pop("TEST_SHARD") == "1"
    assert env_rest.pop("TEST_SHARD") == "${{ matrix.shard }}"
    assert env_one == env_rest, "the shards' env differ beyond TEST_SHARD"


def test_each_job_runs_its_own_shard_of_the_count_there_are_shards() -> None:
    """A `--of` that is not the shard count drops or doubles files."""
    count = 1 + len(_matrix_shards())
    for job in _JOBS:
        run = str(_step(job, _STEP)["run"])
        found = re.findall(
            r"shard_tests\.py --suite engine --shard \"\$TEST_SHARD\" --of (\d+)", run
        )
        assert found == [str(count)], (job, found)
        # The list the selector wrote is the list pytest reads.
        assert "> out/test-shard/files.txt" in run
        assert _pytest_argv(run)[-1] == "@out/test-shard/files.txt"


@pytest.fixture(scope="module")
def bash_path(tmp_path_factory: pytest.TempPathFactory) -> str:
    """Resolved once, never a bare `bash`: on hosted Windows that can be the WSL launcher, which
    cannot open a file this process wrote. `require_bash` fails loudly rather than skipping."""
    return require_bash(tmp_path_factory.mktemp("resolve-bash"))


@pytest.mark.parametrize("repo", ["MEFORORG/MessageFoundry", "someone/fork"])
def test_the_shard_matrix_is_every_leg_once_per_shard(
    repo: str, tmp_path: Path, bash_path: str
) -> None:
    """The `changes` step's own lines, run under bash: `shard_matrix` must be every `matrix` leg,
    unchanged, once per shard, on this repository and on a fork. A leg dropped there drops two
    thirds of the suite on that leg, and the job-level checks below cannot see it.

    Falsified by dropping `"$W25"` from ci.yml's repository `LEGS=(...)`: RED on this repository.
    Restored. Also by changing the loop to `for shard in 2; do` in the script this test writes
    only: RED. Restored. The same change made in ci.yml leaves this test GREEN, because
    `_matrix_shards` reads that loop too; test_the_shards_are_numbered_one_to_n catches it."""
    script = tmp_path / "matrix.sh"
    script.write_text(_matrix_snippet(), encoding="utf-8", newline="\n")
    out = tmp_path / "output.txt"
    # The PATH the resolver approved the interpreter under, so the child runs where it was probed;
    # it also supplies utilities if these lines ever call one (BACKLOG #1373).
    env = probe_env(Path(bash_path), dict(os.environ))
    env.update(GITHUB_REPOSITORY=repo, GITHUB_OUTPUT=str(out))
    proc = subprocess.run(
        [bash_path, "-eo", "pipefail", str(script)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        # Under the per-test cap (pyproject's 60 seconds, the lowest a leg sets), so this clean
        # error fires before pytest-timeout ends the process.
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "the `changes` step's matrix lines")
        + "\n"
        + proc.stderr.decode("utf-8", "replace")
    )
    assert out.is_file(), "the matrix lines exited 0 and wrote no GITHUB_OUTPUT"
    outputs = dict(line.split("=", 1) for line in out.read_text(encoding="utf-8").splitlines())
    legs = json.loads(outputs["matrix"])["include"]
    sharded = json.loads(outputs["shard_matrix"])["include"]
    assert len(legs) == (3 if repo == "MEFORORG/MessageFoundry" else 1)
    expected = [dict(leg, shard=shard) for leg in legs for shard in _matrix_shards()]
    assert sharded == expected


def test_the_shard_job_carries_the_suite_s_belts() -> None:
    """The job-level belts: the caps, runner and needs, from the same keys as `test`, and a matrix
    that is `test`'s legs crossed with the shards (the test above). The step's own belts are the
    identical-body test's, and test_ci_faulthandler_belts.py's and test_ci_retry_native_crash.py's,
    which read every shard."""
    jobs = _jobs()
    for key in ("timeout-minutes", "runs-on", "needs", "defaults"):
        assert jobs["test-shards"][key] == jobs["test"][key], key
    strategy = jobs["test-shards"]["strategy"]
    assert strategy == {
        "fail-fast": False,
        "matrix": "${{ fromJSON(needs.changes.outputs.shard_matrix) }}",
    }
    assert jobs["test"]["strategy"]["matrix"] == "${{ fromJSON(needs.changes.outputs.matrix) }}"
    outputs = jobs["changes"]["outputs"]
    assert outputs["shard_matrix"] == "${{ steps.f.outputs.shard_matrix }}"
    name = str(jobs["test-shards"]["name"])
    assert (
        name == "test shard ${{ matrix.shard }} (${{ matrix.os }}, py${{ matrix.python-version }})"
    )


def test_the_shard_job_runs_exactly_where_shard_one_runs_its_suite() -> None:
    """The job-level `if:` is what keeps the shards off a docs-only PR, and it must not keep them
    off anything else. Falsified by dropping `merge_group` from it: RED. Restored."""
    assert _jobs()["test-shards"]["if"] == _step("test", _STEP)["if"]


def test_every_shard_installs_the_same_project() -> None:
    def install(job: str) -> str:
        found = [
            str(s["run"]) for s in _jobs()[job]["steps"] if "uv pip install" in str(s.get("run"))
        ]
        assert len(found) == 1, (job, found)
        return found[0].strip().splitlines()[-1]

    assert install("test") == install("test-shards")


def test_every_shard_judges_its_margin_with_the_same_check() -> None:
    """The 2026-10-29 ruling's softening and its revert apply to the engine suite, which is now
    several steps; one copy reverted without the other would leave the shards on different floors."""
    one, rest = (_margin(job) for job in _JOBS)
    assert one["run"] == rest["run"]
    assert one["env"] == rest["env"]
    assert one.get("if") == rest.get("if") == "always()"


def test_the_partition_guard_reads_the_suite_s_own_selection() -> None:
    """A guard that collects under another `-m` compares the shards with the wrong suite, and one
    that checks another `--of` proves a partition no job runs.

    Falsified by changing the guard's `-m` to `'not tooling'`: RED. Restored."""
    guard = [
        s for s in _jobs()["test-shards"]["steps"] if "--check-collection" in str(s.get("run"))
    ]
    assert len(guard) == 1, guard
    argv = shlex.split(str(guard[0]["run"]))
    assert argv[argv.index("--of") + 1] == str(1 + len(_matrix_shards()))
    assert "--suite" in argv and argv[argv.index("--suite") + 1] == "engine"
    tail = argv[argv.index("--") + 1 :]
    suite = _pytest_argv(str(_step("test", _STEP)["run"]))
    # The WHOLE tail, so a narrowing flag on the guard alone (`-k`, `--deselect`) is a drift too.
    expression = suite[suite.index("-m") + 1]
    globs = [w for w in suite if w.startswith("--ignore-glob")]
    assert tail == ["-m", expression, *globs], (tail, suite)
    assert _selection(suite), "the suite step carries no selection, so this compares nothing"
    # One runner answers for the tree: the ubuntu leg of the first matrix shard, which every repo's
    # matrix keeps.
    first = _matrix_shards()[0]
    assert guard[0].get("if") == (
        "${{ !cancelled() && steps.tests.outcome == 'success' && runner.os == 'Linux' && "
        f"matrix.shard == '{first}' }}}}"
    )
    assert '"os":"ubuntu-latest"' in _CI.read_text(encoding="utf-8")


def test_the_guard_s_glob_is_the_selector_s() -> None:
    """The selector leaves out what the step's `--ignore-glob` drops; two spellings could drift."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "shard_tests", _ROOT / "scripts" / "quality" / "shard_tests.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    globs = [
        w.split("=", 1)[1]
        for w in _pytest_argv(str(_step("test", _STEP)["run"]))
        if w.startswith("--ignore-glob=")
    ]
    assert globs == [module.ENGINE_EXCLUDE_GLOB]


@pytest.mark.parametrize(("job", "shard"), [("test", "1"), ("test-shards", "${{ matrix.shard }}")])
def test_each_shard_uploads_its_junit_under_a_name_no_other_job_uses(job: str, shard: str) -> None:
    """upload-artifact refuses a second artifact of one name in a run, and `if: always()` keeps the
    record of a red run, the one a re-measure most needs. In `test-shards` the shard is part of the
    name, so its two shards on one leg do not collide."""
    argv = _pytest_argv(str(_step(job, _STEP)["run"]))
    junit = next(w for w in argv if w.startswith("--junitxml="))
    assert junit == "--junitxml=out/junit/test-shard-$TEST_SHARD.xml"
    upload = _step(job, f"Upload engine suite junit (shard {shard})")
    assert upload["if"] == "always()"
    assert upload["with"]["path"] == "out/junit/"
    assert upload["with"]["if-no-files-found"] == "ignore"
    name = str(upload["with"]["name"])
    assert (
        name == f"junit-test-shard-{shard}-${{{{ matrix.os }}}}-py${{{{ matrix.python-version }}}}"
    )
    others = [
        str(s["with"]["name"])
        for other, body in _jobs().items()
        for s in body.get("steps") or []
        if other != job
        and "upload-artifact" in str(s.get("uses", ""))
        and "name" in s.get("with", {})
    ]
    assert name not in others


def test_the_shard_job_still_gates_a_merge() -> None:
    """`continue-on-error` on the job, or on a step that runs the suite, the margin check or the
    guard, would make `needs['test-shards'].result` read success on a red run, so no ci-gate step
    fires and two thirds of the engine suite stop blocking merges with every test here still green.
    The same holds if ci-gate stops needing the job.

    Falsified by `continue-on-error: true` on test-shards's `Tests (pytest)` step, then on the job,
    then by dropping `test-shards` from ci-gate's `needs:`: RED each time. Restored."""
    jobs = _jobs()
    job = jobs["test-shards"]
    assert "continue-on-error" not in job, "the test-shards job carries continue-on-error"
    gating = [
        s
        for s in job["steps"]
        if any(
            m in str(s.get("run", "")) for m in ("pytest", "step_margin.py", "--check-collection")
        )
    ]
    # First, so it is the precondition the lint asks for rather than an echo of the subset check below.
    assert gating, "no test-shards step runs the suite, the margin check or the guard"
    names = [str(s.get("name")) for s in gating]
    assert {_STEP, "Step margin -- engine suite"} <= set(names), names
    assert any("--check-collection" in str(s.get("run")) for s in gating), names
    softened = [str(s.get("name")) for s in gating if "continue-on-error" in s]
    assert not softened, f"test-shards steps carry continue-on-error: {softened}"
    assert "test-shards" in jobs["ci-gate"]["needs"]


def test_ci_yml_stays_under_the_workflow_size_limit() -> None:
    """Over the limit GitHub starts no run of the file at all: a zero-job run that fails at once,
    so no required context reports and nothing merges, while every local check stays green. A copy
    of the shard job per shard did that (runs 44232340332 and 44235710713, 2026-11-18)."""
    # The committed form, LF, whatever line endings this checkout wrote.
    size = len(_CI.read_bytes().replace(b"\r\n", b"\n"))
    assert size < _WORKFLOW_SIZE_LIMIT, (
        f"ci.yml is {size} bytes, at or over {_WORKFLOW_SIZE_LIMIT}; GitHub would start no run of it"
    )
