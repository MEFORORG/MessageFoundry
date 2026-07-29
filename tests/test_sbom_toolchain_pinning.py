# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard the SBOM scratch venv against an unpinned toolchain install (Scorecard PinnedDependencies).

`release.yml` and `security.yml` each build the CycloneDX SBOM from a throwaway venv whose ONLY install
is `docker/locks/requirements-core.lock` — fully `==`-pinned and hash-verified. Both used to precede that
with `/tmp/sbomenv/bin/pip install --upgrade pip`, an UNPINNED, unverified PyPI fetch; in release.yml it
sat inside the job holding `contents: write` + `id-token: write` + `attestations: write`. It bought
nothing (`--require-hashes` performs no resolution, so ensurepip's bundled pip suffices), so it was
deleted rather than pinned.

Nothing in the suite executes either workflow (they need a tag push / a schedule + GitHub OIDC), so a
refactor could reinstate the unpinned install — or "fix" it with `python -m venv --upgrade-deps`, which
performs the SAME unpinned fetch while hiding it from the scanner (ADR 0034 option 3, rejected: a visible
dismissal beats an invisible filter). Pure text checks, no network.
"""

from __future__ import annotations

from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_WORKFLOWS = _REPO / ".github" / "workflows"

# Both workflows that build an SBOM from the hash-locked core runtime in a scratch venv.
SBOM_WORKFLOWS = (_WORKFLOWS / "release.yml", _WORKFLOWS / "security.yml")

VENV_CMD = "python -m venv /tmp/sbomenv"
VENV_PIP = "/tmp/sbomenv/bin/pip install"


def _code_lines(wf: Path) -> list[str]:
    """The workflow's non-comment lines — the rationale comments name the very commands under test."""
    return [
        ln.strip()
        for ln in wf.read_text(encoding="utf-8").splitlines()
        if not ln.strip().startswith("#")
    ]


@pytest.mark.parametrize("wf", SBOM_WORKFLOWS, ids=lambda p: p.name)
def test_sbom_scratch_venv_installs_only_hash_pinned_requirements(wf: Path) -> None:
    lines = _code_lines(wf)

    # Non-vacuity: if the scratch venv is ever restructured away, this test must fail rather than pass
    # by finding nothing to check.
    assert any(VENV_CMD in ln for ln in lines), (
        f"{wf.name} no longer creates the /tmp/sbomenv scratch venv — re-point this guard at whatever "
        f"replaced it instead of letting it pass vacuously"
    )

    installs = [ln for ln in lines if VENV_PIP in ln]
    assert installs, f"{wf.name} creates /tmp/sbomenv but installs nothing into it"
    for ln in installs:
        assert "--require-hashes" in ln, (
            f"{wf.name} installs into the SBOM scratch venv WITHOUT --require-hashes: {ln!r}. Every "
            f"install in this venv must come from a hash-verified lock — an unpinned fetch here runs in "
            f"the release job's publishing/signing context."
        )


@pytest.mark.parametrize("wf", SBOM_WORKFLOWS, ids=lambda p: p.name)
def test_sbom_scratch_venv_does_not_hide_an_unpinned_pip_fetch(wf: Path) -> None:
    """`--upgrade-deps` is the same unpinned pip download, just invisible to Scorecard."""
    offenders = [ln for ln in _code_lines(wf) if "--upgrade-deps" in ln]
    assert not offenders, (
        f"{wf.name} uses `venv --upgrade-deps` ({offenders}) — it downloads pip/setuptools from PyPI "
        f"unpinned exactly like the deleted `pip install --upgrade pip`, but the scanner cannot see it. "
        f"ADR 0034 requires a visible dismissal over an invisible filter."
    )
