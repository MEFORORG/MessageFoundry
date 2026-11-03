# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine suite's two shards in ci.yml, held to one another (BACKLOG #5247).

The suite runs as the `test` job's `Tests (pytest)` step and the `test-shard2` job's step of the same
name. Every property below is one the split can lose SILENTLY: a second copy that drifts from the
first runs half the suite under different belts, a shard number or count that disagrees drops or
doubles files, and a guard step whose selection differs from the suite's compares the shards with
the wrong collection. Each test reads the workflow, so a drift fails here, not on a hosted runner.
The selector's own logic is tests/test_quality_shard_tests.py's; the ci-gate step's condition is
tests/test_merge_gate_controls.py's, beside the reader that evaluates it.
"""

from __future__ import annotations

import functools
import re
import shlex
from pathlib import Path
from typing import Any

import pytest
import yaml

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_STEP = "Tests (pytest)"
_SHARD_JOBS = {"test": "1", "test-shard2": "2"}
#: The env the shard-1 step carries and shard 2 does not, each with its reason. MEFOR_CONNSCALE_LEG
#: arms the connscale herd floor, and the selector holds that smoke in shard 1.
_SHARD_ONE_ONLY_ENV = {"MEFOR_CONNSCALE_LEG"}


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


def test_both_shards_run_one_body_under_one_condition_and_one_cap() -> None:
    """A second copy that drifts runs half the suite under different flags or belts.

    Falsified by dropping `--max-worker-restart=0` from shard 2's run line: RED. Restored."""
    one, two = (_step(job, _STEP) for job in _SHARD_JOBS)
    for key in ("id", "if", "timeout-minutes", "run"):
        assert one.get(key) == two.get(key), f"the two shards' {_STEP!r} steps differ in {key!r}"
    env_one, env_two = dict(one["env"]), dict(two["env"])
    for name in _SHARD_ONE_ONLY_ENV:
        env_one.pop(name)
    assert {env_one.pop("TEST_SHARD"), env_two.pop("TEST_SHARD")} == {"1", "2"}
    assert env_one == env_two, "the two shards' env differ beyond TEST_SHARD"


def test_each_job_runs_its_own_shard_of_the_count_there_are_shards() -> None:
    """A shard number repeated, or a `--of` that is not the job count, drops or doubles files."""
    for job, shard in _SHARD_JOBS.items():
        step = _step(job, _STEP)
        assert step["env"]["TEST_SHARD"] == shard, job
        run = str(step["run"])
        found = re.findall(
            r"shard_tests\.py --suite engine --shard \"\$TEST_SHARD\" --of (\d+)", run
        )
        assert found == [str(len(_SHARD_JOBS))], (job, found)
        # The list the selector wrote is the list pytest reads.
        assert "> out/test-shard/files.txt" in run
        assert _pytest_argv(run)[-1] == "@out/test-shard/files.txt"


def test_shard_two_carries_the_suite_s_belts() -> None:
    """The job-level belts: the caps, runner, matrix and needs, from the same keys as `test`. The
    step's own belts are the identical-body test's, and test_ci_faulthandler_belts.py's and
    test_ci_retry_native_crash.py's, which read both shards."""
    jobs = _jobs()
    for key in ("timeout-minutes", "runs-on", "strategy", "needs", "defaults"):
        assert jobs["test-shard2"][key] == jobs["test"][key], key


def test_shard_two_runs_exactly_where_shard_one_runs_its_suite() -> None:
    """The job-level `if:` is what keeps shard 2 off a docs-only PR, and it must not keep it off
    anything else. Falsified by dropping `merge_group` from it: RED. Restored."""
    assert _jobs()["test-shard2"]["if"] == _step("test", _STEP)["if"]


def test_both_shards_install_the_same_project() -> None:
    def install(job: str) -> str:
        found = [
            str(s["run"]) for s in _jobs()[job]["steps"] if "uv pip install" in str(s.get("run"))
        ]
        assert len(found) == 1, (job, found)
        return found[0].strip().splitlines()[-1]

    assert install("test") == install("test-shard2")


def test_both_shards_judge_their_margin_with_the_same_check() -> None:
    """The 2026-10-29 ruling's softening and its revert apply to the engine suite, which is now two
    steps; one copy reverted without the other would leave the shards on different floors."""
    one, two = (_margin(job) for job in _SHARD_JOBS)
    assert one["run"] == two["run"]
    assert one["env"] == two["env"]
    assert one.get("if") == two.get("if") == "always()"


def test_the_partition_guard_reads_the_suite_s_own_selection() -> None:
    """A guard that collects under another `-m` compares the shards with the wrong suite.

    Falsified by changing the guard's `-m` to `'not tooling'`: RED. Restored."""
    guard = [
        s for s in _jobs()["test-shard2"]["steps"] if "--check-collection" in str(s.get("run"))
    ]
    assert len(guard) == 1, guard
    argv = shlex.split(str(guard[0]["run"]))
    assert argv[argv.index("--of") + 1] == str(len(_SHARD_JOBS))
    assert "--suite" in argv and argv[argv.index("--suite") + 1] == "engine"
    tail = argv[argv.index("--") + 1 :]
    suite = _pytest_argv(str(_step("test", _STEP)["run"]))
    # The WHOLE tail, so a narrowing flag on the guard alone (`-k`, `--deselect`) is a drift too.
    expression = suite[suite.index("-m") + 1]
    globs = [w for w in suite if w.startswith("--ignore-glob")]
    assert tail == ["-m", expression, *globs], (tail, suite)
    assert _selection(suite), "the suite step carries no selection, so this compares nothing"
    assert guard[0].get("if") == (
        "${{ !cancelled() && steps.tests.outcome == 'success' && runner.os == 'Linux' }}"
    )
    # The matrix's ubuntu leg is the one a fork's matrix keeps, so the guard runs on every repo.
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


@pytest.mark.parametrize("job", sorted(_SHARD_JOBS))
def test_each_shard_uploads_its_junit_under_a_name_no_other_job_uses(job: str) -> None:
    """upload-artifact refuses a second artifact of one name in a run, and `if: always()` keeps the
    record of a red run, the one a re-measure most needs."""
    shard = _SHARD_JOBS[job]
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


def test_ci_gate_needs_shard_two() -> None:
    assert "test-shard2" in _jobs()["ci-gate"]["needs"]
