# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two kinds of CI download are pinned to a name that cannot move (vault BACKLOG #2793).

This holds those two shapes, and the Python pin described below, and nothing wider: runner images,
other `setup-*` versions and apt packages still resolve at run time, and nothing here says
otherwise. The two shapes: ``npx --yes <tool>@<version>`` pinned the top package and resolved every transitive
dependency fresh on each run, and the server-DB legs pulled their service images by tag
(``postgres:16``, ``mssql/server:2022-latest``), which a registry rebuild moves. The npm tools now
install from the committed ``ci/npm-tools/package-lock.json`` (why: that package.json's
description) and the images are pinned by digest (why, and how to move one: ci.yml's
``sqlserver-store`` matrix).

The Python pin (follow-up to engine PR 2485): every ``actions/setup-python`` step that wants the
supported 3.14 reads one exact patch from ``ci/python-version``. When they asked for ``"3.14"``,
each runner used whichever patch it had cached, and a release that reached some runners first
turned pull requests red at random. ``py314-latest-canary.yml`` measures the newest patch, so the
next bump is a deliberate edit to that file.

Every scan prints what it found and carries a floor, because a scan that matches nothing is
indistinguishable from a clean tree.
"""

from __future__ import annotations

import functools
import json
import posixpath
import re
import tomllib
from pathlib import Path
from typing import Any

import yaml

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = _REPO / ".github" / "workflows"
_NPM_TOOLS = _REPO / "ci" / "npm-tools"

_DIGEST = re.compile(r"^(?P<name>[^@\s]+)@sha256:[0-9a-f]{64}$")
_MATRIX_REF = re.compile(r"^\$\{\{\s*matrix\.(?P<key>[A-Za-z0-9_-]+)\s*\}\}$")
#: Commands that fetch an npm package with no lock: npx and the other spellings at least these.
_UNLOCKED_FETCH = re.compile(
    r"(?<![\w-])(npx|bunx|npm\s+(exec|x)|pnpm\s+dlx|yarn\s+dlx)(?![\w-])"
    r"|\bnpm\s+(i|install|add)\b[^\n]*(\s-g\b|--global|--no-save)"
)


@functools.cache
def _workflows() -> dict[str, dict[str, Any]]:
    """Every workflow, parsed once per session: each scan below walks all of them."""
    return {
        path.name: yaml.safe_load(path.read_text(encoding="utf-8"))
        for path in sorted([*_WORKFLOWS.glob("*.yml"), *_WORKFLOWS.glob("*.yaml")])
    }


def _service_images() -> list[tuple[str, str, str]]:
    """Every service image as (workflow, job, image), with a ``${{ matrix.X }}`` reference resolved
    to each value its job's ``matrix.include`` rows give X."""
    found: list[tuple[str, str, str]] = []
    for wf_name, wf in _workflows().items():
        for job_name, job in (wf.get("jobs") or {}).items():
            for service in (job.get("services") or {}).values():
                image = str(service["image"])
                ref = _MATRIX_REF.match(image)
                if ref is None:
                    found.append((wf_name, job_name, image))
                    continue
                rows = job["strategy"]["matrix"]["include"]
                values = [str(row[ref.group("key")]) for row in rows]
                assert values, f"{wf_name}/{job_name}: {image} resolves to no matrix value"
                found.extend((wf_name, job_name, value) for value in values)
    return found


def _run_bodies() -> list[tuple[str, str, str]]:
    """Every step's ``run:`` body, YAML comments excluded by the parser, as (workflow, job, body)."""
    out: list[tuple[str, str, str]] = []
    for wf_name, wf in _workflows().items():
        for job_name, job in (wf.get("jobs") or {}).items():
            for step in job.get("steps") or []:
                if "run" in step:
                    out.append((wf_name, job_name, str(step["run"])))
    return out


def _shell_code(body: str) -> str:
    """A run body with its shell comment lines dropped, so prose about npx is not a hit."""
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))


def test_every_service_image_is_pinned_by_digest() -> None:
    images = _service_images()
    print(f"service images scanned: {images}")
    # Floor: ci.yml's three server-DB jobs and benchmark.yml's two give at least seven.
    assert len(images) >= 7, f"expected at least 7 service images, found {len(images)}"
    unpinned = [entry for entry in images if not _DIGEST.match(entry[2])]
    assert not unpinned, f"service images pulled by a movable tag, not a digest: {unpinned}"


def test_one_image_tag_carries_one_digest_everywhere() -> None:
    """A digest moved at one site and not another would test two different databases under one
    name. The ci.yml comment asks for every site of an image to move in one commit; this holds it."""
    by_name: dict[str, set[str]] = {}
    for _, _, image in _service_images():
        name, _, digest = image.partition("@")
        by_name.setdefault(name, set()).add(digest)
    print(f"digests by image: {by_name}")
    assert len(by_name) >= 3, (
        f"expected postgres and two SQL Server images, found {sorted(by_name)}"
    )
    split = {name: digests for name, digests in by_name.items() if len(digests) > 1}
    assert not split, f"one image tag pinned to different digests: {split}"


def test_no_workflow_runs_npx() -> None:
    bodies = _run_bodies()
    print(f"run bodies scanned: {len(bodies)}")
    assert len(bodies) > 100, f"expected the workflows' run steps, found {len(bodies)}"
    # Controls: the instrument sees each spelling where it appears, and not a comment about one.
    for spelling in (
        "npx --yes a@1",
        "npm exec --yes a@1",
        "npm x a@1",
        "pnpm dlx a",
        "yarn dlx a",
        "npm install -g a@1",
        "npm i --no-save a@1",
    ):
        assert _UNLOCKED_FETCH.search(_shell_code(spelling)), spelling
    assert not _UNLOCKED_FETCH.search(_shell_code("# formerly npx --yes a@1\nnpm ci"))
    hits = [(wf, job) for wf, job, body in bodies if _UNLOCKED_FETCH.search(_shell_code(body))]
    assert not hits, (
        f"npx fetches a tool's dependencies with no lock; install from ci/npm-tools: {hits}"
    )


def _resolved(working_directory: str, relative: str) -> str:
    """``relative`` as the repository path it names from a step's ``working-directory``."""
    return posixpath.normpath(posixpath.join(working_directory, relative))


def test_the_npm_tools_are_installed_from_the_lock_without_scripts() -> None:
    """Both former npx sites install ci/npm-tools with `npm ci --ignore-scripts` and run that copy,
    in the SAME job and in that order, and both paths resolve to ci/npm-tools from the step's
    `working-directory`: a run with no matching install has no node_modules to run."""
    install = re.compile(r"npm ci --prefix (?P<prefix>\S+)[^\n]*--ignore-scripts")
    expected = {
        ("quality-advisory.yml", "jscpd"),
        ("security.yml", "cyclonedx-npm"),
    }
    for wf_name, tool in expected:
        run = re.compile(rf"(?P<path>\S*node_modules/\.bin/{re.escape(tool)})(?![\w-])")
        good_jobs = []
        for job_name, job in _workflows()[wf_name]["jobs"].items():
            installed = False
            for step in job.get("steps") or []:
                wd = str(step.get("working-directory", "."))
                code = _shell_code(str(step.get("run", "")))
                for match in install.finditer(code):
                    installed |= _resolved(wd, match.group("prefix")) == "ci/npm-tools"
                runs = [_resolved(wd, m.group("path")) for m in run.finditer(code)]
                if installed and f"ci/npm-tools/node_modules/.bin/{tool}" in runs:
                    good_jobs.append(job_name)
                    break
        print(f"{wf_name}: jobs installing then running {tool}: {good_jobs}")
        assert good_jobs, (
            f"no {wf_name} job installs ci/npm-tools with `npm ci --ignore-scripts` and then runs "
            f"its {tool}, both resolved from the step's working-directory"
        )


def test_the_npm_tools_lock_pins_every_package_by_integrity() -> None:
    manifest = json.loads((_NPM_TOOLS / "package.json").read_text(encoding="utf-8"))
    declared = manifest["dependencies"]
    print(f"declared npm tools: {declared}")
    assert set(declared) == {"jscpd", "@cyclonedx/cyclonedx-npm"}
    for name, version in declared.items():
        assert re.fullmatch(r"\d+\.\d+\.\d+", version), f"{name} is not pinned exactly: {version!r}"

    lock = json.loads((_NPM_TOOLS / "package-lock.json").read_text(encoding="utf-8"))
    packages = {path: entry for path, entry in lock["packages"].items() if path}
    print(f"locked npm packages: {len(packages)}")
    assert len(packages) > 50, f"expected the tools' transitive tree, found {len(packages)}"
    for name, version in declared.items():
        assert packages[f"node_modules/{name}"]["version"] == version, (
            f"the lock resolved {name} to something other than the declared {version}"
        )
    for path, entry in packages.items():
        if entry.get("link"):
            continue
        assert str(entry.get("integrity", "")).startswith("sha512-"), (
            f"{path} has no sha512 integrity"
        )
        assert str(entry.get("resolved", "")).startswith("https://registry.npmjs.org/"), (
            f"{path} resolves outside the npm registry: {entry.get('resolved')!r}"
        )


_PY_PIN = "ci/python-version"
#: The setup-python steps that ask for something other than the pin, each on purpose. A row here
#: that no step uses fails the scan, so a retired canary cannot leave a stale exemption behind.
_UNPINNED_PYTHON = {
    ("py315-canary.yml", "3.15"),  # the next minor's readiness canary
    ("freethread-smoke.yml", "3.14t"),  # the free-threaded build
    # The newest patch, with check-latest: the pin's other half.
    ("py314-latest-canary.yml", "3.14"),
}


def _setup_python_steps() -> list[tuple[str, str, dict[str, Any], str, list[str] | None]]:
    """Every setup-python step as (workflow, job, with, root, sparse): ``root`` is where its job
    checked out THIS repository before the step, and ``sparse`` that checkout's sparse list."""
    found: list[tuple[str, str, dict[str, Any], str, list[str] | None]] = []
    for wf_name, wf in _workflows().items():
        for job_name, job in (wf.get("jobs") or {}).items():
            root, sparse = ".", None
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                with_ = step.get("with") or {}
                if uses.startswith("actions/checkout@") and "repository" not in with_:
                    root = str(with_.get("path", "."))
                    raw = with_.get("sparse-checkout")
                    sparse = None if raw is None else str(raw).split()
                if uses.startswith("actions/setup-python@"):
                    found.append((wf_name, job_name, dict(with_), root, sparse))
    return found


def _pin_problem(workflow: str, with_: dict[str, Any], root: str, sparse: list[str] | None) -> str:
    """Why this step does not read the pin, or an empty string when it does or is exempt."""
    if "python-version-file" in with_:
        if "python-version" in with_:
            return "names python-version too, and setup-python then ignores the file"
        expected = posixpath.normpath(posixpath.join(root, _PY_PIN))
        if with_["python-version-file"] != expected:
            return f"reads {with_['python-version-file']!r}, not {expected!r}"
        if sparse is not None and not {e.strip("/") for e in sparse} & {"ci", _PY_PIN}:
            return f"its sparse checkout {sparse} does not fetch {_PY_PIN}"
        return ""
    if (workflow, str(with_.get("python-version"))) in _UNPINNED_PYTHON:
        return ""
    return f"asks for {with_.get('python-version')!r} instead of reading {_PY_PIN}"


def _pinned_minor() -> str:
    """The pin's X.Y, after checking the file holds one exact X.Y.Z and a newline."""
    text = (_REPO / _PY_PIN).read_text(encoding="utf-8")
    print(f"{_PY_PIN}: {text!r}")
    # One line only: setup-python installs EVERY non-comment line of a plain version file.
    match = re.fullmatch(r"(?P<minor>\d+\.\d+)\.\d+\n", text)
    assert match, f"{_PY_PIN} must hold one exact X.Y.Z and a newline, found {text!r}"
    return match.group("minor")


def test_the_python_pin_is_one_exact_patch_of_the_supported_minor() -> None:
    minor = _pinned_minor()
    project = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["requires-python"] == f">={minor}", (
        f"{_PY_PIN} pins {minor}, but requires-python is "
        f"{project['requires-python']!r}: CI would test a minor the project does not floor at"
    )


def test_the_hand_written_minors_agree_with_the_pin() -> None:
    """setup-python no longer reads matrix.python-version, so that value is only a label: the
    `py3.14` in the required context names, artifact names and the connscale leg name. Nothing would
    notice a minor bump that moved the pin and left those labels, or the latest canary, behind."""
    minor = _pinned_minor()
    ci = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
    labels = re.findall(r'"python-version":"([^"]*)"', ci)
    for job in _workflows()["ci.yml"]["jobs"].values():
        matrix = (job.get("strategy") or {}).get("matrix")
        rows = matrix.get("include") if isinstance(matrix, dict) else None
        if isinstance(rows, list):
            labels += [str(row["python-version"]) for row in rows if "python-version" in row]
    print(f"ci.yml matrix python-version labels: {labels}")
    # Floor: the three test legs' JSON rows and the three service-smoke include rows.
    assert len(labels) >= 6, f"expected ci.yml's matrix python-version labels, found {labels}"
    assert set(labels) == {minor}, f"ci.yml labels {sorted(set(labels))} but {_PY_PIN} is {minor}"
    canary = _workflows()["py314-latest-canary.yml"]["jobs"]["canary"]["steps"]
    asked = [
        str(s["with"]["python-version"]) for s in canary if "setup-python" in s.get("uses", "")
    ]
    assert asked == [minor], f"the latest canary asks for {asked}, but {_PY_PIN} is {minor}"


def test_every_setup_python_step_reads_the_pin_or_is_exempt_by_name() -> None:
    steps = _setup_python_steps()
    print(f"setup-python steps scanned: {len(steps)}")
    # Floor: 53 steps read the pin on the day it was added, plus the three exempt ones.
    assert len(steps) >= 50, f"expected the workflows' setup-python steps, found {len(steps)}"
    # Controls: the classifier tells each failure shape from a pinned step.
    pinned = {"python-version-file": _PY_PIN}
    engine = {"python-version-file": "engine/ci/python-version"}
    assert not _pin_problem("x.yml", pinned, ".", None)
    assert not _pin_problem("x.yml", engine, "engine", None)
    assert _pin_problem("x.yml", {"python-version": "3.14"}, ".", None)
    assert _pin_problem("x.yml", pinned, "engine", None)
    assert _pin_problem("x.yml", {**pinned, "python-version": "3.14"}, ".", None)
    assert _pin_problem("x.yml", pinned, ".", ["scripts/security"])
    assert not _pin_problem("x.yml", pinned, ".", ["scripts/security", "ci"])
    problems = [
        (wf, job, why)
        for wf, job, with_, root, sparse in steps
        if (why := _pin_problem(wf, with_, root, sparse))
    ]
    assert not problems, f"setup-python steps that bypass {_PY_PIN}: {problems}"
    used = {(wf, str(w.get("python-version"))) for wf, _, w, _, _ in steps if "python-version" in w}
    stale = sorted(_UNPINNED_PYTHON - used)
    assert not stale, f"exemptions no setup-python step uses any more: {stale}"


def test_only_the_latest_canary_uses_check_latest() -> None:
    """Anywhere else, check-latest lets a PR run and its merge-queue run use different patches."""
    steps = _setup_python_steps()
    latest = [(wf, job) for wf, job, with_, _, _ in steps if with_.get("check-latest")]
    print(f"setup-python steps with check-latest: {latest}")
    assert latest == [("py314-latest-canary.yml", "canary")], latest
