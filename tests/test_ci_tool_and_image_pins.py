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

The Python pin: every ``actions/setup-python`` step that wants the supported minor reads one exact
patch from ``ci/python-version``. Why, and why ``check-latest`` is allowed in one place only: the
header of ``py314-latest-canary.yml``.

Every scan prints what it found and carries a floor, because a scan that matches nothing is
indistinguishable from a clean tree.
"""

from __future__ import annotations

import functools
import json
import posixpath
import re
import shlex
import tomllib
from pathlib import Path
from typing import Any

import yaml

from tests._workflow_contexts import on_block

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
    # The three ajv packages are the validator cyclonedx-npm's --validate loads (why: the description).
    assert set(declared) == {
        "jscpd",
        "@cyclonedx/cyclonedx-npm",
        "ajv",
        "ajv-formats",
        "ajv-formats-draft2019",
    }
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


#: Shell operators that end one command on a line; a redirection operator takes the next word.
_COMMAND_ENDS = frozenset({";", "&&", "||", "|", "&", "|&"})
#: cyclonedx-npm 7.x's options that take a value; its parser hands them the next word whatever it
#: looks like, so a `--validate` there is a value, not the flag. --omit and --workspace are variadic.
_CYCLONEDX_NPM_VALUE_OPTIONS = frozenset(
    {"--spec-version", "--sv", "--output-format", "--of", "-o", "--output-file", "--mc-type"}
)
_CYCLONEDX_NPM_VARIADIC_OPTIONS = frozenset({"--omit", "-w", "--workspace"})


def _cyclonedx_npm_args(body: str) -> list[list[str]]:
    """Each cyclonedx-npm command in a run body, as its argument words: continuations are joined
    first, as bash does, then each line is split the way the shell would, a `#` comment ending it
    and an operator such as `;` or `&&` ending the command."""
    found: list[list[str]] = []
    for line in body.replace("\\\n", " ").splitlines():
        # Only these lines are lexed: a quote in another line can open a string bash closes later.
        if "node_modules/.bin/cyclonedx-npm" not in line:
            continue
        lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        words = list(lexer)
        for start, word in enumerate(words):
            if not word.endswith("node_modules/.bin/cyclonedx-npm"):
                continue
            args: list[str] = []
            for nxt in words[start + 1 :]:
                if nxt in _COMMAND_ENDS:
                    break
                args.append(nxt)
            found.append(args)
    return found


def _pins_spec_and_validates(args: list[str]) -> bool:
    """Every spec option says 1.6 and the last validate option is `--validate`. The tool's option
    parser lets the last occurrence win, so an earlier right value does not count."""
    specs: list[str] = []
    validate: list[str] = []
    i = 0
    while i < len(args):
        name, eq, value = args[i].partition("=")
        i += 1
        if name and set(name) <= {"<", ">", "&"}:
            i += 1  # a redirection operator; the next word is its target
        elif name in _CYCLONEDX_NPM_VALUE_OPTIONS:
            if not eq:
                value = args[i] if i < len(args) else ""
                i += 1
            if name in ("--spec-version", "--sv"):
                specs.append(value)
        elif name in _CYCLONEDX_NPM_VARIADIC_OPTIONS:
            while not eq and i < len(args) and not args[i].startswith("-"):
                i += 1
        elif args[i - 1] in ("--validate", "--no-validate"):
            validate.append(args[i - 1])
    return bool(specs) and all(s == "1.6" for s in specs) and validate[-1:] == ["--validate"]


def test_every_cyclonedx_npm_run_validates_and_pins_the_spec() -> None:
    """Why both flags: security.yml's comment on the extension SBOM step."""
    # Controls, through the same two functions the scan uses.
    for good_body in (
        "x/node_modules/.bin/cyclonedx-npm --package-lock-only \\\n  --spec-version 1.6 --validate",
        "x/node_modules/.bin/cyclonedx-npm --sv '1.6' --validate --output-file sbom#1.json 2>&1",
        "x/node_modules/.bin/cyclonedx-npm --omit dev optional --spec-version=1.6 --validate",
    ):
        assert [_pins_spec_and_validates(a) for a in _cyclonedx_npm_args(good_body)] == [True], (
            good_body
        )
    for bad_body in (
        "x/node_modules/.bin/cyclonedx-npm --package-lock-only",
        "x/node_modules/.bin/cyclonedx-npm --package-lock-only \\\n  # n\n  --sv 1.6 --validate",
        "x/node_modules/.bin/cyclonedx-npm --output-file --validate --spec-version 1.6",
        "x/node_modules/.bin/cyclonedx-npm --output-file y  # --spec-version 1.6 --validate",
        "x/node_modules/.bin/cyclonedx-npm --output-file y; z --spec-version 1.6 --validate",
        "x/node_modules/.bin/cyclonedx-npm --spec-version 1.6 --validate --sv 1.7",
        "x/node_modules/.bin/cyclonedx-npm --spec-version 1.6 --validate --no-validate",
        "x/node_modules/.bin/cyclonedx-npm --spec-version 1.61 --validate",
        "x/node_modules/.bin/cyclonedx-npm --spec-version=1.6 --validate-only",
    ):
        assert [_pins_spec_and_validates(a) for a in _cyclonedx_npm_args(bad_body)] == [False], (
            bad_body
        )

    calls = [
        (wf, job, args) for wf, job, body in _run_bodies() for args in _cyclonedx_npm_args(body)
    ]
    print(f"cyclonedx-npm runs: {calls}")
    assert calls, "found no cyclonedx-npm run, so this scan checks nothing"
    bad = [entry for entry in calls if not _pins_spec_and_validates(entry[2])]
    assert not bad, f"cyclonedx-npm runs without --spec-version 1.6 and --validate: {bad}"


_PY_PIN = "ci/python-version"
#: The setup-python steps that ask for something other than the pin, each on purpose. A row here
#: that no step uses fails the scan, so a retired canary cannot leave a stale exemption behind.
#: Keyed on the job too, so a second step in an exempt workflow is not exempt by accident.
_UNPINNED_PYTHON = {
    ("py315-canary.yml", "canary", "3.15"),  # the next minor's readiness canary
    ("freethread-smoke.yml", "freethread", "3.14t"),  # the free-threaded build
    # The newest patch, with check-latest: the pin's other half.
    ("py314-latest-canary.yml", "canary", "3.14"),
}

_Step = tuple[str, str, dict[str, Any], str | None, list[str] | None]


def _setup_python_steps() -> list[_Step]:
    """Every setup-python step as (workflow, job, with, root, sparse): ``root`` is where its job
    checked out THIS repository before the step (None when nothing did), and ``sparse`` that
    checkout's sparse list."""
    found: list[_Step] = []
    for wf_name, wf in _workflows().items():
        for job_name, job in (wf.get("jobs") or {}).items():
            root: str | None = None
            sparse: list[str] | None = None
            for step in job.get("steps") or []:
                uses = str(step.get("uses", ""))
                with_ = step.get("with") or {}
                this_repo = str(with_.get("repository", "${{ github.repository }}"))
                if uses.startswith("actions/checkout@") and this_repo == "${{ github.repository }}":
                    root = str(with_.get("path", "."))
                    raw = with_.get("sparse-checkout")
                    sparse = None if raw is None else str(raw).split()
                if uses.startswith("actions/setup-python@"):
                    found.append((wf_name, job_name, dict(with_), root, sparse))
    return found


def _pin_problem(
    workflow: str, job: str, with_: dict[str, Any], root: str | None, sparse: list[str] | None
) -> str:
    """Why this step does not read the pin, or an empty string when it does or is exempt."""
    if "python-version-file" in with_:
        if "python-version" in with_:
            return "names python-version too, and setup-python then ignores the file"
        if root is None:
            return "no checkout of this repository precedes it, so the file is not there"
        expected = posixpath.normpath(posixpath.join(root, _PY_PIN))
        if with_["python-version-file"] != expected:
            return f"reads {with_['python-version-file']!r}, not {expected!r}"
        if sparse is not None and not {e.strip("/") for e in sparse} & {"ci", _PY_PIN}:
            return f"its sparse checkout {sparse} does not fetch {_PY_PIN}"
        return ""
    if (workflow, job, str(with_.get("python-version"))) in _UNPINNED_PYTHON:
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
    `py3.14` in the required context names, artifact names and the connscale leg name. This holds
    ci.yml's matrix labels and the latest canary's version to the pin's minor. It does not read
    step names or prose, so a "Set up Python 3.14" name can still go stale on a minor bump."""
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
    assert not _pin_problem("x.yml", "j", pinned, ".", None)
    assert not _pin_problem("x.yml", "j", engine, "engine", None)
    assert _pin_problem("x.yml", "j", {"python-version": "3.14"}, ".", None)
    assert _pin_problem("x.yml", "j", pinned, "engine", None)
    assert _pin_problem("x.yml", "j", pinned, None, None)
    assert _pin_problem("x.yml", "j", {**pinned, "python-version": "3.14"}, ".", None)
    assert _pin_problem("x.yml", "j", pinned, ".", ["scripts/security"])
    assert not _pin_problem("x.yml", "j", pinned, ".", ["scripts/security", "ci"])
    assert _pin_problem("py314-latest-canary.yml", "other", {"python-version": "3.14"}, ".", None)
    problems = [
        (wf, job, why)
        for wf, job, with_, root, sparse in steps
        if (why := _pin_problem(wf, job, with_, root, sparse))
    ]
    assert not problems, f"setup-python steps that bypass {_PY_PIN}: {problems}"
    used = {
        (wf, job, str(w.get("python-version")))
        for wf, job, w, _, _ in steps
        if "python-version" in w
    }
    stale = sorted(_UNPINNED_PYTHON - used)
    assert not stale, f"exemptions no setup-python step uses any more: {stale}"


def _events_that_skip_the_pin(on: Any) -> list[str]:
    """The events whose ``paths`` filter would not fire on a change to the pin alone."""
    if not isinstance(on, dict):
        return []
    return [
        event
        for event, spec in on.items()
        if isinstance(spec, dict)
        and isinstance(spec.get("paths"), list)
        and not {_PY_PIN, "ci/**", "**"} & {str(p) for p in spec["paths"]}
    ]


def test_a_pin_bump_runs_every_path_filtered_workflow_that_reads_the_pin() -> None:
    """A bump must meet each workflow that reads the pin on its own pull request, not first on the
    next unrelated one after the merge."""
    assert _events_that_skip_the_pin({"pull_request": {"paths": ["src/**"]}}) == ["pull_request"]
    assert not _events_that_skip_the_pin({"pull_request": {"paths": ["src/**", _PY_PIN]}})
    assert not _events_that_skip_the_pin(
        {"pull_request": None, "schedule": [{"cron": "0 0 * * *"}]}
    )
    readers = sorted({wf for wf, _, w, _, _ in _setup_python_steps() if "python-version-file" in w})
    print(f"workflows that read {_PY_PIN}: {readers}")
    assert len(readers) >= 20, f"expected the pinned workflows, found {readers}"
    skipping = {
        wf: events
        for wf in readers
        if (events := _events_that_skip_the_pin(on_block(_workflows()[wf])))
    }
    assert not skipping, f"paths filters that do not fire on {_PY_PIN}: {skipping}"


def test_only_the_latest_canary_uses_check_latest() -> None:
    """Why it is allowed in that one place: the canary's header."""
    steps = _setup_python_steps()
    latest = [(wf, job) for wf, job, with_, _, _ in steps if with_.get("check-latest")]
    print(f"setup-python steps with check-latest: {latest}")
    assert latest == [("py314-latest-canary.yml", "canary")], latest
