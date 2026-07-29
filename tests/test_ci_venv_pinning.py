# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard CI's lock-only scratch venvs against an unpinned toolchain install (Scorecard
PinnedDependencies).

Three CI steps build a throwaway venv whose ONLY install is a committed lockfile — fully `==`-pinned
and hash-verified: the DEP-1 install check (`security.yml`, `/tmp/lockcheck` <- `requirements.lock`)
and the two CycloneDX SBOM builds (`release.yml` + `security.yml`, `/tmp/sbomenv` <-
`docker/locks/requirements-core.lock`). All three used to precede that with
`<venv>/bin/pip install --upgrade pip`, an UNPINNED, unverified PyPI fetch; in `release.yml` it sat
inside the job holding `contents: write` + `id-token: write` + `attestations: write`. It bought nothing
— `--require-hashes` rejects any requirement without a hash and therefore performs no dependency
resolution at all, so the pip `ensurepip` provisions is sufficient — so it was deleted rather than
pinned.

Two regressions this pins, neither of which any other test can see (nothing in the suite executes a
workflow — they need a tag push, a schedule, or GitHub OIDC):

1. **Reinstating the bootstrap**, in either spelling — `<venv>/bin/pip install --upgrade pip` or
   `<venv>/bin/python -m pip install --upgrade pip`, the form used elsewhere in these same files.
2. **Hiding it** behind `python -m venv --upgrade-deps`, which downloads pip/setuptools from PyPI
   exactly as unpinned but is invisible to the scanner. That is ADR 0034's rejected option 3 — a
   visible dismissal-with-reason beats an invisible filter.

Deliberately scoped to the LOCK-ONLY venvs. `/tmp/relsmoke` (`release.yml`) legitimately installs
unpinned `packaging` — it exists to prove the freshly built wheel's own declared closure resolves, so
feeding it a lock would defeat its purpose — and is dismissed separately. Pure text checks, no network.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = _REPO / ".github" / "workflows"

#: ``(workflow, scratch venv)`` pairs whose every install must come from a hash-verified lock.
LOCK_ONLY_VENVS = (
    ("release.yml", "/tmp/sbomenv"),
    ("security.yml", "/tmp/sbomenv"),
    ("security.yml", "/tmp/lockcheck"),
)

#: Workflows carrying at least one lock-only scratch venv (for the file-wide ``--upgrade-deps`` check).
_WORKFLOW_FILES = tuple(dict.fromkeys(wf for wf, _ in LOCK_ONLY_VENVS))


def _code_lines(wf: Path) -> list[str]:
    """The workflow's non-comment lines — the rationale comments name the very commands under test."""
    return [
        ln.strip()
        for ln in wf.read_text(encoding="utf-8").splitlines()
        if not ln.strip().startswith("#")
    ]


def _install_re(venv: str) -> re.Pattern[str]:
    """Match an install into ``venv`` in EITHER spelling: ``<venv>/bin/pip install ...`` and
    ``<venv>/bin/python -m pip install ...``. Matching only the first would leave the second — the form
    used for the interpreter-level installs in these same workflows — a silent way back in."""
    return re.compile(rf"{re.escape(venv)}/bin/(?:pip|python\s+-m\s+pip)\s+install\b")


@pytest.mark.parametrize(("workflow", "venv"), LOCK_ONLY_VENVS)
def test_lock_only_scratch_venv_installs_are_hash_pinned(workflow: str, venv: str) -> None:
    wf = _WORKFLOWS / workflow
    lines = _code_lines(wf)

    # Non-vacuity: if a scratch venv is restructured away, fail loudly rather than pass by finding
    # nothing to check.
    assert any(f"python -m venv {venv}" in ln for ln in lines), (
        f"{workflow} no longer creates the {venv} scratch venv — re-point this guard at whatever "
        f"replaced it instead of letting it pass vacuously"
    )

    installs = [ln for ln in lines if _install_re(venv).search(ln)]
    assert installs, f"{workflow} creates {venv} but installs nothing into it"
    for ln in installs:
        assert "--require-hashes" in ln, (
            f"{workflow} installs into the lock-only scratch venv {venv} WITHOUT --require-hashes: "
            f"{ln!r}. Every install into this venv must come from a hash-verified lock — an unpinned "
            f"fetch here runs in a release publishing/signing context or in the DEP-1 gate itself."
        )


@pytest.mark.parametrize("workflow", _WORKFLOW_FILES)
def test_scratch_venvs_do_not_hide_an_unpinned_pip_fetch(workflow: str) -> None:
    """``--upgrade-deps`` is the same unpinned pip download, just invisible to Scorecard."""
    offenders = [ln for ln in _code_lines(_WORKFLOWS / workflow) if "--upgrade-deps" in ln]
    assert not offenders, (
        f"{workflow} uses `venv --upgrade-deps` ({offenders}) — it downloads pip/setuptools from PyPI "
        f"unpinned exactly like the deleted `pip install --upgrade pip`, but the scanner cannot see it. "
        f"ADR 0034 requires a visible dismissal over an invisible filter."
    )


# --- the blocking gates' OWN toolchain -------------------------------------------------------------
#
# The tests above cover the lock-only scratch venvs. They say nothing about how the blocking jobs
# install the scanners THEMSELVES, and that was its own gap: the pip-audit job — whose entire purpose
# is proving nothing unpinned enters the tree — installed its auditor with a bare `pip install
# pip-audit`, the DEP-1 step bootstrapped the resolver with a bare `uv`, semgrep rode a
# compatible-release range, and gitleaks was a `curl | tar` with no integrity check. All four are
# dependency intake that no audited lockfile covers, inside REQUIRED contexts.

#: ``pip install`` invocations in these jobs must name an exact version. Interpreter-level installs
#: (not into a lock-fed venv) can never be hash-verified, so `==` is the available control.
_PINNED_INSTALL_JOBS = ("pip-audit", "bandit", "semgrep")


def _run_bodies(workflow: str, job_key: str) -> list[str]:
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((_WORKFLOWS / workflow).read_text(encoding="utf-8"))
    job = (wf.get("jobs") or {}).get(job_key)
    assert job is not None, (
        f"{workflow} has no job {job_key!r} — re-point this guard at whatever replaced it rather than "
        f"letting it pass vacuously"
    )
    return [str(step["run"]) for step in (job.get("steps") or []) if "run" in step]


@pytest.mark.parametrize("job_key", _PINNED_INSTALL_JOBS)
def test_blocking_jobs_pin_the_tools_they_install(job_key: str) -> None:
    """No bare or range-specified `pip install` inside a blocking security job.

    An unpinned scanner changes its own findings between two runs of the SAME commit, which shows up
    as a mystery red on an unrelated PR — the failure that got bandit pinned to 1.9.4 after an implicit
    upgrade changed `# nosec` parsing and broke a green branch.
    """
    bodies = _run_bodies("security.yml", job_key)
    assert bodies, f"job {job_key!r} has no run steps"

    unpinned: list[str] = []
    for body in bodies:
        for line in body.splitlines():
            code = line.strip()
            if code.startswith("#") or "pip install" not in code:
                continue
            args = code.split("pip install", 1)[1]
            # A requirements-file install is pinned BY the file, and the lock-only-venv tests above
            # already assert --require-hashes on those. Checking the file's name for `==` here would
            # flag `-r requirements.lock` — the most rigorously pinned install in the whole workflow.
            if re.search(r"(?:^|\s)(?:-r|--requirement)\s", args) or "--require-hashes" in args:
                continue
            targets = [token.strip("\"'") for token in args.split() if not token.startswith("-")]
            for target in targets:
                # `pip` itself is the bootstrap the existing dismissal covers; a path target is a
                # local install, not a registry fetch.
                if target == "pip" or target.startswith(("/", ".")):
                    continue
                if "==" not in target:
                    unpinned.append(f"{job_key}: {target!r} in {code!r}")

    assert not unpinned, (
        "a blocking security job installs a tool without an exact `==` pin:\n  "
        + "\n  ".join(unpinned)
        + "\nPin it (and bump deliberately, in a PR that also clears any new findings). A range like "
        "`semgrep~=1.90` silently adopts every new minor, so the gate's behaviour changes without a "
        "diff — and this is dependency intake no lockfile in the repo covers."
    )


def test_release_asset_downloads_in_blocking_jobs_are_checksum_verified() -> None:
    """A version tag says WHICH artifact to fetch, not that the bytes are that artifact.

    `curl … | tar -xz` inside a required gate executes third-party bytes with no integrity check. The
    sbomqs step in this same workflow already verifies against the release's own checksums file, so any
    download here must do the same.
    """
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((_WORKFLOWS / "security.yml").read_text(encoding="utf-8"))
    jobs = wf.get("jobs") or {}

    checked = 0
    offenders: list[str] = []
    for job_key, job in jobs.items():
        # Advisory jobs are out of scope here: they cannot turn a required context green while
        # compromised. `trivy` is deliberately excluded for that reason and noted in its own comment.
        if (job or {}).get("continue-on-error") is True:
            continue
        for step in (job or {}).get("steps") or []:
            raw = str((step or {}).get("run") or "")
            # Comments OUT before matching. A rationale comment in these workflows quotes the very
            # command being prohibited (the gitleaks step explains the `curl | tar` it replaced), so a
            # whole-body match reports the explanation as the offence — a detector counting itself.
            body = "\n".join(line for line in raw.splitlines() if not line.strip().startswith("#"))
            if "releases/download" not in body:
                continue
            checked += 1
            name = (step or {}).get("name") or "<unnamed step>"
            if "sha256sum -c" not in body:
                offenders.append(f"security.yml:{job_key} — step {name!r} verifies no checksum")
            if re.search(r"\|\s*tar\b", body):
                offenders.append(
                    f"security.yml:{job_key} — step {name!r} pipes the download straight into tar, "
                    "so there is no file left to verify"
                )

    # Liveness: if no blocking job downloads a release asset any more, say so rather than pass on an
    # empty scan.
    print(f"[ci-venv-pinning] examined {checked} release-asset download step(s) in blocking jobs")
    assert checked > 0, (
        "no blocking job in security.yml downloads a release asset — if that is now true this guard is "
        "obsolete, but an empty scan must not read as a pass"
    )
    assert not offenders, "unverified release-asset download in a blocking job:\n  " + "\n  ".join(
        offenders
    )
