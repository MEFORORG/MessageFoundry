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

The lock-only venvs are one half. The other half is every OTHER `pip install` on the release path —
`build`, `sigstore`, `cyclonedx-bom`, `packaging`, and the `pip` bootstraps — which resolved whatever
PyPI served at tag time. `sigstore` is the sharp one: its step is unconditional and the very next
command signs the release artifacts with the job's OIDC identity, the same identity that publishes to
PyPI. Those are now version-pinned, and the second half of this module keeps them that way — nothing
else can see the regression, because Dependabot has no updater for an inline `pip install X==Y` in a
workflow (its `uv` ecosystem only reads pyproject.toml + uv.lock), so a stale pin rots invisibly and a
DELETED pin is invisible twice over.

`/tmp/relsmoke` (`release.yml`) stays out of the hash-verified rule — it exists to prove the freshly
built wheel's own declared closure resolves, so feeding it a lock would defeat its purpose — but its
`packaging` install is covered by the version-pin rule below. Pure text checks, no network.
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


# --- the release path: every named package must carry a version ------------------------------------

#: Any `pip install`, in either spelling, into any interpreter or venv.
_PIP_INSTALL = re.compile(r"\bpip\s+install\b")

#: A pinned target names a version. `$PKG_PIN` counts — it is read out of constraints.lock at run time
#: (the quality-advisory.yml ruff-pin pattern), which is MORE current than a literal, not less.
_VERSION_OPS = ("==", "~=", ">=", "<=", "!=")

#: Install targets that legitimately name no version: a path (the artifact under test) and the
#: hash-verified lock installs, where every version is pinned INSIDE the lock.
_EXEMPT_TARGETS = frozenset({"."})

#: Tools whose release-path pin must EXIST — the non-vacuity backstop for the scan above. Deleting a
#: step would otherwise make the scan pass by finding nothing left to check.
RELEASE_PINNED_TOOLS = (
    ("release.yml", "sigstore"),
    ("release.yml", "build"),
    ("release.yml", "pip"),
    ("release.yml", "cyclonedx-bom"),
    ("release.yml", "packaging"),
    ("security.yml", "cyclonedx-bom"),
)


def _install_targets(line: str) -> list[str]:
    """The package tokens a ``pip install`` line names — flags, and the arguments of flags that take
    one, removed. Everything left is something pip will resolve."""
    body = line.split(" install ", 1)[1]
    targets: list[str] = []
    skip_next = False
    for tok in body.split():
        if skip_next:
            skip_next = False
            continue
        if tok in ("-r", "--requirement", "-c", "--constraint", "--index-url", "--extra-index-url"):
            skip_next = True
            continue
        if tok.startswith("-"):
            continue
        targets.append(tok.strip("\"'"))
    return targets


def test_release_path_pip_installs_name_a_version() -> None:
    """EVERY package `release.yml` installs must carry a version specifier.

    A blanket scan, not a name list, so a NEW unpinned install added tomorrow fails too — the failure
    mode a fixed table cannot see. Path installs (``dist/*.whl``) and ``-r <lock>`` installs are
    exempt: the first is the artifact under test, the second is pinned inside the lock.
    """
    lines = [ln for ln in _code_lines(_WORKFLOWS / "release.yml") if _PIP_INSTALL.search(ln)]
    # Non-vacuity: this file HAS a toolchain to pin. If it drops below this, the scan has stopped
    # seeing the installs rather than the installs having become clean.
    assert len(lines) >= 6, (
        f"release.yml now has only {len(lines)} pip installs — the scan is probably no longer "
        f"matching them; re-point it rather than letting it pass on an empty set.\n{lines}"
    )

    unpinned = [
        (ln, target)
        for ln in lines
        for target in _install_targets(ln)
        if target not in _EXEMPT_TARGETS
        and "/" not in target  # a path install (dist/*.whl), not a named package
        and not any(op in target for op in _VERSION_OPS)
    ]
    assert not unpinned, (
        f"release.yml installs these WITHOUT a version: {unpinned}. This workflow's jobs hold "
        f"contents/id-token/attestations: write and sign + publish the release artifacts, so an "
        f"unpinned resolve here takes whatever PyPI serves at tag time (Scorecard "
        f"PinnedDependenciesID; ADR 0034 §3). Pin it, or derive the pin from constraints.lock the "
        f"way the `packaging` installs do."
    )


@pytest.mark.parametrize(("workflow", "package"), RELEASE_PINNED_TOOLS)
def test_release_toolchain_pin_is_present(workflow: str, package: str) -> None:
    """Each release-path tool is still installed, and still pinned wherever it is installed.

    Guards the direction the blanket scan cannot: a pin that vanishes with its step. Every occurrence
    is checked, not just the first — pinning one of the two `build` installs (engine + harness) would
    move the exposure rather than remove it.
    """
    lines = [ln for ln in _code_lines(_WORKFLOWS / workflow) if _PIP_INSTALL.search(ln)]
    hits = [
        (ln, target)
        for ln in lines
        for target in _install_targets(ln)
        if target == package or target.startswith(tuple(f"{package}{op}" for op in _VERSION_OPS))
    ]
    assert hits, (
        f"{workflow} no longer installs {package!r} — if the step was removed on purpose, drop it "
        f"from RELEASE_PINNED_TOOLS in the same commit; otherwise this guard just went blind."
    )
    unpinned = [ln for ln, target in hits if not any(op in target for op in _VERSION_OPS)]
    assert not unpinned, (
        f"{workflow} installs {package!r} unpinned at: {unpinned}. Dependabot cannot bump an inline "
        f"`pip install` in a workflow, so an unpinned one here is never even noticed."
    )
