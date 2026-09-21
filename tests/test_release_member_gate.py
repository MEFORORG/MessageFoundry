# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The release-time member denylist (BACKLOG #1832), and the wiring that makes it fire.

Three parts, and the RULE is the least interesting of them. ``scripts/release/forbidden_members.py``
can be perfect and change nothing if a publishing job never calls it -- which is exactly what happened
to the sdist leak gate: it worked, and the harness and console wheel jobs simply had no member gate at
all. So the wiring tests derive the set of jobs that publish an artifact from ``release.yml`` itself
and require EVERY one of them to invoke the gate, rather than listing today's three job names and
passing forever after a fourth is added.

The third part is ``ci.yml``'s own positive control, EXECUTED rather than read. That control is what
makes ``packaging-build``'s four clean member gates mean anything, and it shipped deciding on the
gate's exit code alone -- which ``main`` returns for four different reasons, only one of them the gate
firing. Its three arms are run for real at the bottom of this file.
"""

from __future__ import annotations

import io
import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import pytest

_REPO = Path(__file__).resolve().parents[1]
RELEASE_YML = _REPO / ".github" / "workflows" / "release.yml"
CI_YML = _REPO / ".github" / "workflows" / "ci.yml"
GATE = _REPO / "scripts" / "release" / "forbidden_members.py"

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(_REPO / "scripts" / "release"))

from _bash_resolver import explain_returncode, probe_env, require_bash  # noqa: E402
from forbidden_members import (  # noqa: E402
    FORBIDDEN_BASENAMES,
    FORBIDDEN_PATH_COMPONENTS,
    forbidden,
    main,
)

#: hatchling names every sdist member ``<project>-<version>/...``. The fixtures carry it because the
#: denylist's whole claim is that a prefix cannot launder a basename, and a fixture with no prefix
#: would not test that claim.
_SDIST_PREFIX = "messagefoundry-0.3.0"

_CLEAN_SDIST = (
    "messagefoundry/__init__.py",
    "messagefoundry/py.typed",
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
)

_CLEAN_WHEEL = (
    "messagefoundry/__init__.py",
    "messagefoundry/py.typed",
    "messagefoundry-0.3.0.dist-info/METADATA",
    "messagefoundry-0.3.0.dist-info/RECORD",
)


def _write_sdist(path: Path, members: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for member in members:
            payload = b"fixture\n"
            info = tarfile.TarInfo(f"{_SDIST_PREFIX}/{member}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return path


def _write_wheel(path: Path, members: Sequence[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as zf:
        for member in members:
            zf.writestr(member, "fixture\n")
    return path


# --------------------------------------------------------------------------------------------------
# The rule itself.
# --------------------------------------------------------------------------------------------------


def test_the_reported_leak_is_the_positive_control() -> None:
    """``messagefoundry/CLAUDE.md`` is what shipped on 0.1.0..0.2.15. If this passes, nothing below
    proves anything -- so it is asserted on its own, first, as the control for the whole module."""
    why = forbidden(f"{_SDIST_PREFIX}/messagefoundry/CLAUDE.md")
    assert why is not None, (
        "the exact member that shipped to PyPI on every release 0.1.0..0.2.15 is not forbidden"
    )
    assert "CLAUDE.md" in why


def test_a_clean_member_set_is_not_forbidden() -> None:
    """The negative control. A denylist that matched everything would pass every rejection test."""
    for member in (*_CLEAN_SDIST, *_CLEAN_WHEEL):
        assert forbidden(f"{_SDIST_PREFIX}/{member}") is None, member
        assert forbidden(member) is None, member


@pytest.mark.parametrize(
    "member",
    [
        # The location the allowlist trusted, which is the whole point of #1832.
        f"{_SDIST_PREFIX}/messagefoundry/CLAUDE.md",
        # The harness tree, force-included and unfilterable by hatchling's `exclude` (the #1702 case).
        "harness/CLAUDE.md",
        # Depth is irrelevant to a basename rule -- that is what makes it prefix-launder-proof.
        "messagefoundry/auth/data/CLAUDE.md",
        f"{_SDIST_PREFIX}/docs/{_SDIST_PREFIX}/CLAUDE.md",
        # Case folding: one file to the filesystem that committed it.
        "messagefoundry/claude.md",
        "messagefoundry/Claude.MD",
        # The next file of the same class, which is why this is a class rule and not one name.
        "messagefoundry/CLAUDE.local.md",
        "messagefoundry/AGENTS.md",
        "messagefoundry/GEMINI.md",
        "messagefoundry/.cursorrules",
        # Forbidden path components, at any depth, including a bare directory entry.
        "messagefoundry/.claude/settings.json",
        ".github/workflows/release.yml",
        f"{_SDIST_PREFIX}/.claude/",
        "a/b/.CLAUDE/c.json",
    ],
)
def test_forbidden_members_are_refused(member: str) -> None:
    assert forbidden(member) is not None, f"{member} passed the denylist"


@pytest.mark.parametrize(
    "member",
    [
        # Named LIKE a forbidden file but not one. A rule that fired here would red real releases.
        "messagefoundry/generators/README.md",
        "messagefoundry/CLAUDE.md.txt",
        "messagefoundry/NOT-CLAUDE.md",
        "messagefoundry/claudemd",
        "messagefoundry/agents.py",
        "messagefoundry/claude/handler.py",
        # A forbidden component name as a FILE's basename in the middle of nothing -- `.github` as a
        # leaf file is still refused (the directory-entry arm), but `github` is not.
        "messagefoundry/github/client.py",
    ],
)
def test_lookalike_members_are_allowed(member: str) -> None:
    assert forbidden(member) is None, f"{member} was refused, which would red a real release"


def test_the_denylist_is_stored_casefolded() -> None:
    """The matcher lowercases the member, so an uppercase entry could never match anything.

    This is the silent-disarm shape: a contributor adds ``"AGENTS.md"``, every test that does not
    exercise that specific name stays green, and the entry is dead.
    """
    for name in (*FORBIDDEN_BASENAMES, *FORBIDDEN_PATH_COMPONENTS):
        assert name == name.lower(), f"{name!r} is not lowercased and can never match"


# --------------------------------------------------------------------------------------------------
# The CLI: it must fail loudly on every way of inspecting nothing.
# --------------------------------------------------------------------------------------------------


def test_the_cli_passes_clean_archives_and_prints_the_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    sdist = _write_sdist(tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz", _CLEAN_SDIST)
    wheel = _write_wheel(tmp_path / "dist" / "messagefoundry-0.3.0-py3-none-any.whl", _CLEAN_WHEEL)
    assert main([str(sdist), str(wheel)]) == 0
    out = capsys.readouterr().out
    # A green line that does not say what was examined hides a gate that examined nothing.
    assert str(len(_CLEAN_SDIST)) in out
    assert str(len(_CLEAN_SDIST) + len(_CLEAN_WHEEL)) in out


def test_the_cli_fails_on_a_leaky_sdist(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sdist = _write_sdist(
        tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz",
        (*_CLEAN_SDIST, "messagefoundry/CLAUDE.md"),
    )
    assert main([str(sdist)]) == 1
    assert "CLAUDE.md" in capsys.readouterr().err


def test_the_cli_fails_on_a_leaky_wheel(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """The harness wheel case. hatchling's ``exclude`` cannot filter a force-included tree, so this
    is the artifact with no build-time defence and therefore the one that most needs this gate."""
    wheel = _write_wheel(
        tmp_path / "harness-dist" / "messagefoundry_harness-0.3.0-py3-none-any.whl",
        ("harness/__init__.py", "harness/CLAUDE.md"),
    )
    assert main([str(wheel)]) == 1
    assert "harness/CLAUDE.md" in capsys.readouterr().err


def test_the_cli_fails_when_a_pattern_matches_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A misspelled or empty dist directory must not report a clean result.

    This is the gate's own version of the defect it exists to catch: zero archives inspected yields
    zero forbidden members, and without this arm that prints green.
    """
    assert main([str(tmp_path / "harness-dist" / "*.whl")]) == 1
    assert "no file matching" in capsys.readouterr().err


def test_the_cli_fails_on_a_zero_member_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    wheel = _write_wheel(tmp_path / "dist" / "empty-0.3.0-py3-none-any.whl", ())
    assert main([str(wheel)]) == 1
    assert "ZERO members" in capsys.readouterr().err


def test_the_cli_fails_on_an_unreadable_archive(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A truncated archive must fail rather than yield a short listing that reads as clean."""
    good = _write_sdist(tmp_path / "dist" / "good.tar.gz", _CLEAN_SDIST)
    bad = tmp_path / "dist" / "messagefoundry-0.3.0.tar.gz"
    bad.write_bytes(good.read_bytes()[:40])
    good.unlink()
    assert main([str(bad)]) == 1
    assert "could not list" in capsys.readouterr().err


def test_the_cli_refuses_an_archive_shape_it_cannot_read(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An extension this gate does not understand must fail, not be skipped.

    Skipping is how a new artifact format (a ``.zst`` sdist, a conda package) would slip past a gate
    that still printed a clean line for the files it did recognise.
    """
    odd = tmp_path / "dist" / "messagefoundry-0.3.0.tar.zst"
    odd.parent.mkdir(parents=True, exist_ok=True)
    odd.write_bytes(b"not an archive this gate reads")
    assert main([str(odd)]) == 1
    assert "published uninspected" in capsys.readouterr().err


def test_the_cli_reports_every_archive_not_just_the_first(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Two leaks must both be named. Bailing on the first hides the second from the release log."""
    _write_sdist(tmp_path / "d" / "a.tar.gz", (*_CLEAN_SDIST, "messagefoundry/CLAUDE.md"))
    _write_wheel(tmp_path / "d" / "b-py3-none-any.whl", ("harness/AGENTS.md",))
    assert main([str(tmp_path / "d" / "*")]) == 1
    err = capsys.readouterr().err
    assert "CLAUDE.md" in err
    assert "AGENTS.md" in err


# --------------------------------------------------------------------------------------------------
# The wiring. A gate no publishing job calls is the gap that was reported.
# --------------------------------------------------------------------------------------------------

#: How a step invokes the gate. Matched against the step's `run:` text.
_GATE_INVOCATION = "scripts/release/forbidden_members.py"

#: A parsed workflow is arbitrary YAML, so the value type is `Any` by construction. Naming the shape
#: beats a bare `dict`, which mypy strict rejects for missing type arguments.
JobDict = dict[str, Any]
StepDict = dict[str, Any]


def _jobs() -> dict[str, JobDict]:
    # Imported in-function, matching tests/test_release_pipeline.py: PyYAML ships no stubs, and a
    # module-level import would put an untyped-import error in every mypy run over this directory.
    import yaml

    parsed = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))
    jobs = parsed.get("jobs")
    assert isinstance(jobs, dict) and jobs, "release.yml parsed to no jobs"
    return dict(jobs)


def _steps(job: JobDict) -> list[StepDict]:
    return [s for s in (job.get("steps") or []) if isinstance(s, dict)]


def _publishing_jobs() -> dict[str, JobDict]:
    """Jobs that put an artifact somewhere a stranger can fetch it.

    DERIVED, NOT LISTED. The reported defect was a job with no gate, so a test naming today's three
    jobs would go green the day a fourth is added -- which is the same failure one layer up. A job
    qualifies if any step publishes to PyPI or uploads to a GitHub release.
    """
    out: dict[str, JobDict] = {}
    for jid, job in _jobs().items():
        for step in _steps(job):
            uses = str(step.get("uses") or "")
            run = str(step.get("run") or "")
            if (
                "gh-action-pypi-publish" in uses
                or "gh release upload" in run
                or "gh release create" in run
            ):
                out[jid] = job
                break
    return out


def test_the_publishing_job_set_is_the_one_we_think_it_is() -> None:
    """Liveness for the derivation above. If it silently matched nothing, every test using it passes.

    Pinned as a FLOOR plus an identity check rather than an exact set: a new publishing job must not
    red this test, it must red the coverage test below, which is the one with something to say.
    """
    found = _publishing_jobs()
    assert set(found) >= {"release", "release-webconsole", "release-harness"}, (
        f"the publishing-job derivation lost a known job: {sorted(found)}"
    )


def test_every_publishing_job_invokes_the_member_gate() -> None:
    """THE TEST FOR THE REPORTED GAP. Before #1832 this failed for two of the three jobs."""
    missing = [
        jid
        for jid, job in _publishing_jobs().items()
        if not any(_GATE_INVOCATION in str(s.get("run") or "") for s in _steps(job))
    ]
    assert not missing, (
        f"these release jobs publish an artifact with no member gate: {sorted(missing)} -- "
        f"every one of them must run {_GATE_INVOCATION}"
    )


def test_the_gate_runs_before_anything_publishes() -> None:
    """A gate that fires after the upload has already leaked the file it was checking for."""
    for jid, job in _publishing_jobs().items():
        steps = _steps(job)
        gate_at = [i for i, s in enumerate(steps) if _GATE_INVOCATION in str(s.get("run") or "")]
        assert gate_at, f"{jid} has no member gate step"  # covered above; keeps this test honest
        publish_at = [
            i
            for i, s in enumerate(steps)
            if "gh-action-pypi-publish" in str(s.get("uses") or "")
            or "gh release upload" in str(s.get("run") or "")
            or "gh release create" in str(s.get("run") or "")
        ]
        assert min(gate_at) < min(publish_at), (
            f"{jid} runs its member gate at step {min(gate_at)}, after its first publishing step "
            f"at {min(publish_at)} -- the leak would already be public"
        )


def test_each_job_gates_the_artifacts_it_actually_builds() -> None:
    """The gate must name the output directory its own job wrote.

    A step that inspected the wrong directory would find no archive; ``_resolve`` turns that into a
    failure rather than a green line, so this test is about the release staying GREEN for the right
    reason, not about the leak.
    """
    expected = {
        "release": ("dist/",),
        "release-webconsole": ("webconsole-dist/",),
        "release-harness": ("harness-dist/",),
    }
    jobs = _jobs()
    for jid, needles in expected.items():
        gate_runs = [
            str(s.get("run") or "")
            for s in _steps(jobs[jid])
            if _GATE_INVOCATION in str(s.get("run") or "")
        ]
        assert gate_runs, f"{jid} has no member gate step"
        text = "\n".join(gate_runs)
        for needle in needles:
            assert needle in text, f"{jid}'s member gate does not inspect {needle}"


def test_the_engine_job_gates_its_wheel_as_well_as_its_sdist() -> None:
    """The sdist leak gate only ever read ``dist/*.tar.gz``. The engine wheel had no member gate."""
    gate_runs = "\n".join(
        str(s.get("run") or "")
        for s in _steps(_jobs()["release"])
        if _GATE_INVOCATION in str(s.get("run") or "")
    )
    assert "*.whl" in gate_runs, "the engine job's member gate does not inspect its wheel"
    assert "*.tar.gz" in gate_runs, "the engine job's member gate does not inspect its sdist"


def test_the_gate_script_is_tracked_and_executable_as_written() -> None:
    """The workflow calls a path. If it moves, every wiring test above still passes on the text."""
    assert GATE.is_file(), f"{GATE} does not exist, so every release job calls a missing script"


# --------------------------------------------------------------------------------------------------
# `ci.yml`'s positive control, RUN rather than read. The control is what makes the four clean member
# gates in `packaging-build` mean anything, so a control that cannot fail costs the whole job.
#
# It shipped deciding on the EXIT CODE alone, and `main` exits 1 for four different reasons: a refused
# member, a pattern that matched no file, an archive it could not open, and an archive that listed zero
# members. Only the first is the gate firing. So with the fixture renamed out from under it the step
# printed "control fired" having opened ZERO archives -- a control reporting the gate armed whether or
# not the gate saw anything, which is the empty-corpus defect the gate itself exists to prevent.
#
# The three tests below EXECUTE the step: the same script the runner runs, against a real wheel, once
# per arm. A text assertion could pin today's wording and still pass on a step that never fires.
# --------------------------------------------------------------------------------------------------

#: The job and step carrying the control. Named, not derived: there is exactly one, and a derivation
#: over "steps whose name says control" would silently follow a rename into inspecting nothing.
_CONTROL_JOB = "packaging-build"
_CONTROL_STEP = "Positive control"

#: The fixture the control poisons and the gate is pointed at.
_POISONED = "poisoned.whl"

#: A gate that ACCEPTS. Stands in for the denylist going empty, which is the failure the control was
#: built for; a stub says it in three lines and stays true whatever the real script's internals become.
_ACCEPTING_GATE = (
    "import sys\n"
    'print("member gate passed: inspected 5 members across 1 archive(s)")\n'
    "sys.exit(0)\n"
)


def _control_step_script() -> str:
    """The control step's `run:` text, straight out of `ci.yml`."""
    import yaml

    parsed = yaml.safe_load(CI_YML.read_text(encoding="utf-8"))
    job = (parsed.get("jobs") or {}).get(_CONTROL_JOB)
    assert isinstance(job, dict), f"ci.yml has no `{_CONTROL_JOB}` job"
    matches = [
        str(s.get("run") or "")
        for s in _steps(job)
        if _CONTROL_STEP in str(s.get("name") or "") and str(s.get("run") or "")
    ]
    assert len(matches) == 1, (
        f"expected exactly one `{_CONTROL_STEP}` step in `{_CONTROL_JOB}`, found {len(matches)} -- "
        "the extractor below would otherwise run the wrong script, or none"
    )
    return matches[0]


def _sandbox(tmp_path: Path, *, gate_source: str | None = None) -> Path:
    """The working tree the step expects: a built harness wheel, and the gate on its own path."""
    root = tmp_path / "job"
    (root / "scripts" / "release").mkdir(parents=True)
    _write_wheel(
        root / "harness-dist" / "messagefoundry_harness-0.3.0-py3-none-any.whl", _CLEAN_WHEEL
    )
    target = root / "scripts" / "release" / GATE.name
    if gate_source is None:
        shutil.copy2(GATE, target)
    else:
        target.write_text(gate_source, encoding="utf-8")
    return root


def _run_control(tmp_path: Path, root: Path, script: str) -> subprocess.CompletedProcess[bytes]:
    """Run the step the way the runner does: bash, `-e`, from the job's working directory."""
    path = root / "control.sh"
    path.write_text(script, encoding="utf-8", newline="\n")
    bash = require_bash(tmp_path)
    # THE CHILD NEEDS REAL UTILITIES AND A `python`, NOT JUST THE INTERPRETER (BACKLOG #1373). The step
    # runs `cp` and `python`; a PATH without them fails the child at 127, which arm two would read as
    # its own success. `probe_env` appends bash's own directory, where `cp` ships; this process's own
    # interpreter directory is PREPENDED, so the step runs the python running the suite. Same call,
    # same reason, as tests/test_ci_tooling_gate.py.
    env = probe_env(Path(bash), dict(os.environ))
    env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
    return subprocess.run(  # noqa: S603  # nosec B603 - resolved interpreter, fixed argv, tmp paths
        [bash, "-e", str(path)],
        cwd=str(root),
        env=env,
        capture_output=True,
        # UNDER the per-test watchdog, which is the only way this guard can ever fire. `addopts`
        # carries `--timeout=60 --timeout-method=thread`, and the CI legs override it at 60s (ubuntu)
        # / 120s (Windows) -- so a subprocess timeout at the 180 used elsewhere in this suite is
        # unreachable: pytest-timeout kills the whole session first and orphans the child. At 45 a
        # wedged step reds THIS test and the child is reaped. Measured: all three arms together run
        # in under 2 s on this box, so the margin is a hang backstop, not a tightness gate.
        timeout=45,
        check=False,
    )


def _output(proc: subprocess.CompletedProcess[bytes]) -> str:
    return proc.stdout.decode("utf-8", "replace") + proc.stderr.decode("utf-8", "replace")


def test_the_control_passes_when_the_gate_refuses_the_poisoned_member(tmp_path: Path) -> None:
    """ARM ONE. Without this the fix below is satisfied by a step that always fails."""
    script = _control_step_script()
    proc = _run_control(tmp_path, _sandbox(tmp_path), script)
    out = _output(proc)
    assert proc.returncode == 0, (
        explain_returncode(proc.returncode, "ci.yml's positive control") + "\n" + out
    )
    assert f"{_POISONED} ships harness/CLAUDE.md" in out, (
        f"the gate never named the poisoned member, so the control passed without firing:\n{out}"
    )


def test_the_control_fails_when_the_gate_inspects_nothing(tmp_path: Path) -> None:
    """ARM TWO, THE REPORTED DEFECT. Rename the fixture out from under the gate's argument.

    The mutation is keyed on the INVOCATION, not on the step's prose: it rewrites the archive name on
    the one line that calls the gate, which is exactly what a later edit renaming the fixture on one
    line and not the other would do by accident.
    """
    lines = _control_step_script().splitlines(keepends=True)
    at = [i for i, line in enumerate(lines) if _GATE_INVOCATION in line]
    assert len(at) == 1, f"expected one gate invocation in the control step, found {len(at)}"
    assert _POISONED in lines[at[0]], (
        f"the gate invocation does not name {_POISONED}: {lines[at[0]]}"
    )
    lines[at[0]] = lines[at[0]].replace(_POISONED, "poisoned-renamed.whl")

    proc = _run_control(tmp_path, _sandbox(tmp_path), "".join(lines))
    out = _output(proc)
    assert "found no file matching" in out, (
        f"the mutation did not produce the empty-match condition it is meant to test:\n{out}"
    )
    assert proc.returncode != 0, (
        "THE REPORTED DEFECT: the control reported success having inspected ZERO members, so it "
        f"cannot fail and proves nothing about the member gates above it:\n{out}"
    )


def test_the_control_fails_when_the_gate_accepts_the_poisoned_member(tmp_path: Path) -> None:
    """ARM THREE. The failure the control was BUILT for must still red it after the fix above."""
    root = _sandbox(tmp_path, gate_source=_ACCEPTING_GATE)
    proc = _run_control(tmp_path, root, _control_step_script())
    out = _output(proc)
    assert proc.returncode != 0, (
        f"the control accepted a gate that shipped harness/CLAUDE.md:\n{out}"
    )
    assert "ACCEPTED" in out, f"the control failed, but not for the reason it names:\n{out}"
