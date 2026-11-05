# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Meta-test: the `docker` path gate admits the engine's start path (vault BACKLOG #3455).

``ci.yml``'s ``changes`` job decides whether ``docker-smoke`` runs on a pull request. That job is
the only one that starts ``serve`` the way the image does, and the merge_group and push arms both
write ``docker=false`` (#1830), so the pull-request arm is the only place it can run before a merge.
Engine PR 2284 changed how ``serve`` starts, touched only ``messagefoundry/__main__.py``,
``messagefoundry/api/app.py`` and ``messagefoundry/auth/trust_anchors.py``, matched no arm, and
merged with the job skipped. The nightly run was the first to see the engine refuse the rig's CA.

The invariants, at least these:

1. **The image's ENTRYPOINT module trips the gate.** Read out of ``docker/Dockerfile``, not
   restated here.
2. **The PR 2284 change set trips the gate**, each file alone.
3. **Every repo script the ``docker-smoke`` steps run trips the gate.** Read out of the job's
   ``run:`` blocks.
4. **The gate admits exactly the named start-path modules, and each exists.** The list below and
   the regex move together, so a widening to ``^messagefoundry/`` is caught here rather than in the
   ubuntu pool's queue, and a renamed module is caught here rather than by the nightly.
5. **It still refuses unrelated paths**, including two shape probes that match only if the regex
   loses its ``\\.py$`` anchor.

The regex is READ OUT OF ``ci.yml``, never copied here, for the reason
``tests/test_ci_tooling_gate.py`` states. Pure text analysis: Python's ``re`` reads this pattern as
GNU ``grep -E`` does, since it uses only groups, alternation, escaped dots and ``^``/``$``.
"""

from __future__ import annotations

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
        "messagefoundry/__main__.py",
        "messagefoundry/api/__init__.py",
        "messagefoundry/api/app.py",
        "messagefoundry/api/tls.py",
        "messagefoundry/auth/anchor_path.py",
        "messagefoundry/auth/trust_anchors.py",
        "messagefoundry/config/settings.py",
        "messagefoundry/logging_setup.py",
        "messagefoundry/pki.py",
        "messagefoundry/remotedebug.py",
        "messagefoundry/startupcode.py",
    }
)

#: The files engine PR 2284 changed. The job skipped on it, which is this row's whole defect.
PR_2284_CHANGED = (
    "messagefoundry/__main__.py",
    "messagefoundry/api/app.py",
    "messagefoundry/auth/trust_anchors.py",
)


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


def _entrypoint_module() -> str:
    """The repo path of the module the image's ENTRYPOINT runs with ``-m``."""
    for line in _DOCKERFILE.read_text(encoding="utf-8").splitlines():
        if line.startswith("ENTRYPOINT "):
            argv = json.loads(line.removeprefix("ENTRYPOINT "))
            module = str(argv[argv.index("-m") + 1])
            base = module.replace(".", "/")
            for candidate in (f"{base}/__main__.py", f"{base}.py"):
                if (_ROOT / candidate).is_file():
                    return candidate
            pytest.fail(f"the ENTRYPOINT runs `-m {module}`, which names no file in the tree")
    pytest.fail("docker/Dockerfile has no exec-form ENTRYPOINT line; this test has drifted")


def _scripts_run_by_docker_smoke() -> set[str]:
    """Repo ``.py`` paths named in the ``docker-smoke`` job's ``run:`` blocks, comments stripped."""
    found: set[str] = set()
    for step in jobs_of("ci.yml")["docker-smoke"]["steps"]:
        executable = "\n".join(
            line
            for line in str(step.get("run", "")).splitlines()
            if not line.lstrip().startswith("#")
        )
        # A repo-relative path, or one under the two roots the steps mount the checkout at. An
        # in-container path such as /rig/rigadmin.py is not a repo path and is not matched.
        found.update(
            re.findall(r"(?:\$PWD/|/repo/|(?<![\w/]))((?:harness|scripts)/[\w/]+\.py)", executable)
        )
    return found


def test_the_entrypoint_module_trips_the_gate() -> None:
    entry = _entrypoint_module()
    assert entry in START_PATH_MODULES, f"{entry} is the ENTRYPOINT module and is not named here"


def test_the_pr_2284_change_set_trips_the_gate() -> None:
    """Each file alone, so dropping any one of the three arms reds here."""
    missed = [path for path in PR_2284_CHANGED if not gate([path])]
    assert not missed, f"these PR 2284 files no longer run the docker smoke: {missed}"


def test_every_script_the_smoke_steps_run_trips_the_gate() -> None:
    run = _scripts_run_by_docker_smoke()
    assert {"harness/load/rigadmin.py", "scripts/ci/make_syslog_ca_crl.py"} <= run, (
        f"the step parsing in _scripts_run_by_docker_smoke has drifted; it found {sorted(run)}"
    )
    missed = sorted(path for path in run if not gate([path]))
    assert not missed, (
        f"the docker-smoke steps run these files, and editing one does not run the job: {missed}"
    )


def test_the_gate_admits_no_other_engine_source() -> None:
    """The regex and START_PATH_MODULES are one list in two places, held equal over the tree.

    A widening shows as "only in the regex". A named module that was renamed or removed, or that
    the regex stopped admitting, shows as "only in the list", because only existing files are
    walked. That is also how ``test_the_entrypoint_module_trips_the_gate`` above is enforced.
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
