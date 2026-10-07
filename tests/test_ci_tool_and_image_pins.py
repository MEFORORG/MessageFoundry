# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two kinds of CI download are pinned to a name that cannot move (vault BACKLOG #2793).

This holds those two shapes and nothing wider: runner images, `setup-*` versions and apt packages
still resolve at run time, and nothing here says otherwise. The two shapes: ``npx --yes <tool>@<version>`` pinned the top package and resolved every transitive
dependency fresh on each run, and the server-DB legs pulled their service images by tag
(``postgres:16``, ``mssql/server:2022-latest``), which a registry rebuild moves. The npm tools now
install from the committed ``ci/npm-tools/package-lock.json`` (why: that package.json's
description) and the images are pinned by digest (why, and how to move one: ci.yml's
``sqlserver-store`` matrix).

Every scan prints what it found and carries a floor, because a scan that matches nothing is
indistinguishable from a clean tree.
"""

from __future__ import annotations

import functools
import json
import posixpath
import re
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
