# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Meta-test: the `docker` path gate admits the engine's start path (vault BACKLOG #3455).

Why the gate names these modules, and what it leaves out, is stated once, in the comment above the
docker arm in ``ci.yml``'s ``changes`` job. This file pins that arm. The invariants, at least these:

1. **Every ENTRYPOINT in the image runs one module, and it trips the gate.** Read out of
   ``docker/Dockerfile``, not restated here.
2. **The engine files PR 2284 changed trip the gate**, each file alone.
3. **Every repo script the ``docker-smoke`` steps run trips the gate, and so does each repo helper
   such a script imports.** Read out of the job's ``run:`` blocks and the scripts' own imports.
4. **The gate admits exactly the named start-path modules, and each exists.** The list below and
   the regex move together, so a widening to ``^messagefoundry/`` is caught here rather than in the
   ubuntu pool's queue, and a renamed module is caught here rather than by the nightly.
5. **It still refuses unrelated paths**, including two shape probes that match only if the regex
   loses its ``\\.py$`` anchor.

THE RUN RATE, measured 2026-11-05 over the 544 commits on engine ``main`` (``4b006afc69``) since
2026-10-04: the arms that predate #3455 fired on 68, the arm as it stands fires on 265, and the old
arms plus ``^messagefoundry/`` would fire on 414. These count commits on ``main``, not pull-request
runs.

The regex is READ OUT OF ``ci.yml``, never copied here, for the reason
``tests/test_ci_tooling_gate.py`` states. Pure text analysis: Python's ``re`` reads this pattern as
GNU ``grep -E`` does, since it uses only groups, alternation, escaped dots and ``^``/``$``.
"""

from __future__ import annotations

import ast
import functools
import json
import re
from pathlib import Path

import pytest

from tests._workflow_contexts import jobs_of

_ROOT = Path(__file__).resolve().parents[1]
_CI = _ROOT / ".github" / "workflows" / "ci.yml"
_DOCKERFILE = _ROOT / "docker" / "Dockerfile"

#: The engine modules on the image's start path that the gate names. ci.yml's comment above the
#: regex says what each is in for. Move this set and that regex together.
START_PATH_MODULES = frozenset(
    {
        "messagefoundry/__init__.py",
        "messagefoundry/__main__.py",
        "messagefoundry/api/__init__.py",
        "messagefoundry/api/app.py",
        "messagefoundry/api/models.py",
        "messagefoundry/api/tls.py",
        "messagefoundry/auth/anchor_path.py",
        "messagefoundry/auth/trust_anchors.py",
        "messagefoundry/config/settings.py",
        "messagefoundry/config/wiring.py",
        "messagefoundry/logging_setup.py",
        "messagefoundry/pki.py",
        "messagefoundry/remotedebug.py",
        "messagefoundry/startupcode.py",
    }
)

#: The engine files engine PR 2284 (7ecc79ceac) changed. It also changed docs/SECURITY.md and two
#: tests, which trip no arm either.
PR_2284_ENGINE_FILES = (
    "messagefoundry/__main__.py",
    "messagefoundry/api/app.py",
    "messagefoundry/auth/trust_anchors.py",
)

#: A repo path a step runs: repo-relative, or under a root the steps reach the checkout by.
#: In-container paths such as /rig/rigadmin.py are not repo paths and are not matched.
_STEP_PATH = re.compile(
    r"(?:\$PWD/|\$GITHUB_WORKSPACE/|\$\{GITHUB_WORKSPACE\}/|/repo/|\./|(?<![\w/.$-]))"
    r"((?:harness|scripts|tests)/[\w./-]+\.(?:py|sh|ps1))"
)
#: A repo module a step runs with ``python -m``.
_STEP_MODULE = re.compile(r"-m\s+((?:harness|scripts|tests)(?:\.\w+)+)")


@functools.cache
def _docker_pattern() -> re.Pattern[str]:
    """The pull-request arm's ``grep -qE`` pattern for ``docker``.

    Anchored on the LAST ``docker=true`` emission: the workflow_dispatch arm emits one first, with
    no grep in front of it. The last ``grep -qE`` before the emission is the arm that decides it.
    """
    text = _CI.read_text(encoding="utf-8")
    emit = text.rfind('echo "docker=true" >> "$GITHUB_OUTPUT"')
    assert emit > 0, "the docker arm's GITHUB_OUTPUT emission is gone; this gate was restructured"
    matches = list(re.finditer(r"grep -qE '([^']*)'", text[:emit]))
    assert matches, "no `grep -qE` found before the docker emission"
    pattern = matches[-1].group(1)
    assert "dockerignore" in pattern, (
        f"the grep picked up before the docker emission is not the docker arm: {pattern}"
    )
    return re.compile(pattern)


def gate(changed: list[str]) -> bool:
    """Mirror of the shell decision: ``echo "$changed" | grep -qE P`` over one path per line."""
    pattern = _docker_pattern()
    return any(pattern.search(path) for path in changed)


def _module_file(module: str) -> str | None:
    """The repo path a dotted module name resolves to, package first, or None."""
    base = module.replace(".", "/")
    for candidate in (f"{base}/__main__.py", f"{base}.py", f"{base}/__init__.py"):
        if (_ROOT / candidate).is_file():
            return candidate
    return None


def _entrypoint_modules() -> set[str]:
    """The repo path of the module each exec-form ENTRYPOINT in the image runs with ``-m``."""
    found: set[str] = set()
    for line in _DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ENTRYPOINT "):
            argv = json.loads(line.removeprefix("ENTRYPOINT "))
            module = str(argv[argv.index("-m") + 1])
            path = _module_file(module)
            assert path, f"an ENTRYPOINT runs `-m {module}`, which names no file in the tree"
            found.add(path)
    assert found, "docker/Dockerfile has no exec-form ENTRYPOINT line; this test has drifted"
    return found


def _repo_imports(path: str) -> set[str]:
    """The ``harness``/``scripts``/``tests`` modules a repo script imports, as repo paths."""
    found: set[str] = set()
    if not path.endswith(".py"):
        return found
    for node in ast.walk(ast.parse((_ROOT / path).read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom):
            names = [node.module or ""]
        elif isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        else:
            continue
        for name in names:
            if name.split(".")[0] in {"harness", "scripts", "tests"}:
                resolved = _module_file(name)
                if resolved:
                    found.add(resolved)
    return found


def _scripts_run_by_docker_smoke() -> set[str]:
    """Repo files the ``docker-smoke`` steps run, and the repo helpers those files import."""
    run: set[str] = set()
    for step in jobs_of("ci.yml")["docker-smoke"]["steps"]:
        executable = "\n".join(
            line
            for line in str(step.get("run", "")).splitlines()
            if not line.lstrip().startswith("#")
        )
        run.update(_STEP_PATH.findall(executable))
        run.update(p for m in _STEP_MODULE.findall(executable) if (p := _module_file(m)))
    return run | {helper for path in run for helper in _repo_imports(path)}


def test_every_entrypoint_module_trips_the_gate() -> None:
    entries = _entrypoint_modules()
    assert len(entries) == 1, f"the image's ENTRYPOINT lines run different modules: {entries}"
    missed = sorted(path for path in entries if not gate([path]))
    assert not missed, f"editing the image's ENTRYPOINT module does not run the smoke: {missed}"


def test_the_pr_2284_engine_files_trip_the_gate() -> None:
    """Each file alone, so dropping any one of the three arms reds here."""
    missed = [path for path in PR_2284_ENGINE_FILES if not gate([path])]
    assert not missed, f"these PR 2284 files no longer run the docker smoke: {missed}"


def test_every_script_the_smoke_steps_run_trips_the_gate() -> None:
    run = _scripts_run_by_docker_smoke()
    floor = {
        "harness/load/rigadmin.py",
        "scripts/ci/make_syslog_ca_crl.py",
        "tests/_phi_gate_provisions.py",
    }
    assert floor <= run, (
        f"the step parsing in _scripts_run_by_docker_smoke has drifted; it found {sorted(run)}"
    )
    missed = sorted(path for path in run if not gate([path]))
    assert not missed, (
        f"the docker-smoke steps run these files, and editing one does not run the job: {missed}"
    )


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        ('python3 ./scripts/ci/check-image.py "$x"', "scripts/ci/check-image.py"),
        ("bash $GITHUB_WORKSPACE/scripts/ci/probe.sh", "scripts/ci/probe.sh"),
        ('-v "$PWD/harness/load/rigadmin.py:/rig/rigadmin.py:ro"', "harness/load/rigadmin.py"),
        ("python /repo/scripts/ci/make_syslog_ca_crl.py /out", "scripts/ci/make_syslog_ca_crl.py"),
    ],
)
def test_the_step_path_reader_on_planted_lines(line: str, expected: str) -> None:
    """The shapes a new smoke step may use, so a new script cannot slip past the reader."""
    assert _STEP_PATH.findall(line) == [expected]


def test_the_step_path_reader_skips_in_container_paths() -> None:
    assert _STEP_PATH.findall("docker exec mefor python /smoke/send_adt.py /rig/rigadmin.py") == []


def test_the_gate_admits_no_other_engine_source() -> None:
    """The regex and START_PATH_MODULES are one list in two places, held equal over the tree.

    A widening shows as "only in the regex". A named module that was renamed or removed, or that
    the regex stopped admitting, shows as "only in the list", because only existing files are
    walked.
    """
    engine = {p.relative_to(_ROOT).as_posix() for p in (_ROOT / "messagefoundry").rglob("*.py")}
    assert len(engine) > len(START_PATH_MODULES), "found too few engine sources; the rglob drifted"
    admitted = {path for path in engine if gate([path])}
    assert admitted == START_PATH_MODULES, (
        "the docker arm admits a different engine set from START_PATH_MODULES. "
        f"Only in the regex: {sorted(admitted - START_PATH_MODULES)}. "
        f"Only in the list: {sorted(START_PATH_MODULES - admitted)}. A module only in the list "
        "may have been renamed: name the one that took over its start-time work, in both places."
    )


@pytest.mark.parametrize(
    ("path", "why"),
    [
        ("README.md", "a docs file reaches no container start"),
        ("docs/BACKLOG.md", "the ledger stub"),
        ("tests/test_api_auth.py", "an engine test runs on the `test` legs, not in the image"),
        ("harness/load/corpus.py", "a harness file the smoke steps do not run"),
        ("messagefoundry/pipeline/engine.py", "an engine module outside the named set"),
        ("messagefoundry/auth/service.py", "left out on purpose; ci.yml's comment says why"),
        ("messagefoundry/api/application.py", "SHAPE: matches only if `app` loses its `\\.py$`"),
        ("messagefoundry/pki_extra.py", "SHAPE: matches only if `pki` loses its `\\.py$`"),
    ],
)
def test_the_gate_refuses(path: str, why: str) -> None:
    assert not gate([path]), f"the docker arm admits {path}: {why}"


@pytest.mark.parametrize(
    "path", ["docker/Dockerfile", ".dockerignore", "pyproject.toml", ".github/workflows/ci.yml"]
)
def test_the_existing_arms_still_trip_the_gate(path: str) -> None:
    """The control for the refusals above: the arms that were there before #3455 still fire."""
    assert gate([path]), f"the docker arm no longer admits {path}"
