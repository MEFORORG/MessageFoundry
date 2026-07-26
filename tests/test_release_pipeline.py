# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Guard the release PIPELINE's load-bearing policy (pyproject sdist allowlist + .github/workflows/release.yml).

Nothing in the test suite executes release.yml (it needs a tag push, GitHub OIDC, a real build/SBOM/sign
run and PyPI Trusted Publishing), so a refactor could silently delete the sdist leak gate, revert the
publish step off Trusted Publishing onto a token, drop the Sigstore/SBOM steps, or let the pyproject
`only-include` allowlist drift out of sync with the workflow's leak-gate regex — and every other test would
still pass. Each test here fails LOUDLY if a guard disappears.

The single highest-value check is the CROSS-CHECK between the two allowlists (pyproject
`[tool.hatch.build.targets.sdist].only-include` and release.yml's leak-gate `grep -vE` regex): that exact
drift is the documented real defect — hatchling's whole-repo VCS sweep leaked docs/security/* to PUBLIC
PyPI on releases 0.1.0..0.2.15. If the two lists silently diverge a private doc can re-leak, so they are
pinned together here.

These are pure text / `re` / `tomllib` checks (no `python -m build`, no network) so they run everywhere the
suite runs. They do NOT and cannot assert the artifacts are actually built/signed/SBOM'd/uploaded — that
remains a CI-leg claim validated by the workflow_dispatch dry-run + a `vX.Y.Z-rc1` pre-release tag.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[1]
PYPROJECT = _REPO / "pyproject.toml"
RELEASE_YML = _REPO / ".github" / "workflows" / "release.yml"

# The canonical package-only sdist allowlist. Pinned here so a change on EITHER side (pyproject or the
# workflow gate) trips a test — the drift that leaked private docs to PyPI must never be silent again.
EXPECTED_ONLY_INCLUDE = {"messagefoundry", "README.md", "CHANGELOG.md", "LICENSE", "NOTICE"}

# A real, git-tracked private security-posture doc — the class of file that leaked on 0.1.0..0.2.15. The
# leak gate MUST reject it. (Chosen from the real tree so the check stays honest, not a synthetic string.)
PRIVATE_CANARY = "docs/security/THREAT-MODEL.md"


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _release() -> str:
    return RELEASE_YML.read_text(encoding="utf-8")


def _only_include() -> list[str]:
    data = _pyproject()
    return data["tool"]["hatch"]["build"]["targets"]["sdist"]["only-include"]


def _leak_gate_regex() -> str:
    """The exact ERE the workflow's leak gate feeds to `grep -vE` (extracted, not hardcoded, so drift on
    either side of the contract is caught). A member that MATCHES is allowed (grep -v drops it); a member
    that does NOT match is a leak and fails the release."""
    m = re.search(r"grep -vE '([^']+)'", _release())
    assert m, "could not find the leak gate's `grep -vE '...'` allowlist regex in release.yml"
    return m.group(1)


def _member_for(entry: str) -> str:
    """Render an `only-include` entry as it appears in the sdist listing AFTER the workflow strips the
    `<name>-<version>/` prefix (`sed -E 's#^[^/]+/##'`). A directory entry contributes child members; a
    file entry contributes itself."""
    if (_REPO / entry).is_dir():
        return f"{entry}/__init__.py"  # representative child member
    return entry


# --- (1) the pyproject pin: sdist is package-only ----------------------------------------------------


def test_pyproject_sdist_only_include_is_package_only() -> None:
    # WITHOUT this allowlist hatchling sweeps the whole repo (docs/, tests/, scripts/, CLAUDE.md, .claude/)
    # into the sdist and release.yml uploads it to PUBLIC PyPI. Pin the exact package-only set.
    assert set(_only_include()) == EXPECTED_ONLY_INCLUDE, (
        f"pyproject sdist only-include drifted from the package-only set.\n"
        f"  expected: {sorted(EXPECTED_ONLY_INCLUDE)}\n  found:    {sorted(_only_include())}\n"
        f"Adding a non-package entry can re-leak private docs to PyPI (the 0.1.0..0.2.15 defect)."
    )


# --- (2) the cross-check: the two allowlists cannot silently drift (highest-value) -------------------


def test_pyproject_and_release_leak_gate_allowlists_cannot_drift() -> None:
    gate = _leak_gate_regex()

    # Every pyproject only-include entry MUST pass the workflow gate (i.e. the gate would NOT flag it as a
    # leak). If someone adds an entry the gate does not allow, the two lists have drifted -> fail here
    # BEFORE a release ships a file the pyproject permits but the gate would reject (or vice-versa).
    for entry in _only_include():
        member = _member_for(entry)
        assert re.match(gate, member), (
            f"only-include entry {entry!r} (sdist member {member!r}) is NOT allowed by release.yml's leak "
            f"gate regex — the pyproject and workflow allowlists have drifted.\n  gate: {gate}"
        )

    # And a known-private path MUST be rejected by the gate (does not match -> counted as a leak). This is
    # the exact class of file that shipped to PyPI on 0.1.0..0.2.15.
    assert (_REPO / PRIVATE_CANARY).is_file(), (
        f"the private-doc canary {PRIVATE_CANARY!r} is missing from the tree — pick another real "
        f"security-posture doc so this rejection check stays grounded"
    )
    assert not re.match(gate, PRIVATE_CANARY), (
        f"release.yml's leak gate WRONGLY allows the private doc {PRIVATE_CANARY!r} into the sdist — the "
        f"private-doc PyPI leak guard is broken.\n  gate: {gate}"
    )


# --- (3) load-bearing workflow canaries (silent-removal tripwires) -----------------------------------


def test_release_load_bearing_canaries_present() -> None:
    rel = _release()
    required = {
        # sdist leak gate + its fail-closed exit
        "leak gate step": "Leak gate — sdist MUST be package-only",
        "leak gate fails the release": "::error::sdist contains non-package files",
        "leak gate exits nonzero": "exit 1",
        # version single-sourced from the package == the tag
        "version==tag single-source": 'want="${GITHUB_REF_NAME#v}"',
        "version==tag comparison": '[ "$built" = "$want" ]',
        # py.typed (WS-3) enforced on a tag push
        "py.typed enforced on tag": "unzip -l dist/*.whl | grep -q 'messagefoundry/py.typed'",
        "py.typed only on a tag": 'GITHUB_REF_TYPE:-}" = "tag"',
        # clean staging dir so twine never sees the *.sigstore bundles
        "dist-pub clean-stage step": "Stage a clean dist for PyPI",
        "dist-pub is wheel+sdist only": "cp dist/*.whl dist/*.tar.gz dist-pub/",
        # SBOM generated FROM the hash-locked CORE runtime via env mode (licenses populate), not a live
        # resolve; then finalized (lifecycle + dynamic version); VEX companion staged (ADR 0149).
        "SBOM from the hash-locked core lock": "--require-hashes -r docker/locks/requirements-core.lock",
        "SBOM via cyclonedx env mode": "cyclonedx_py environment",
        "SBOM finalized (lifecycle+version)": "sbom_finalize.py messagefoundry-sbom.cdx.json",
        "VEX companion staged from source": (
            "cp security/vex/messagefoundry.openvex.json messagefoundry-vex.openvex.json"
        ),
        # Sigstore keyless signing over the artifacts AND the SBOM + VEX (space-separated in the sign cmd)
        "Sigstore keyless sign": "python -m sigstore sign dist/*.tar.gz dist/*.whl",
        "Sigstore signs SBOM + VEX": "messagefoundry-sbom.cdx.json messagefoundry-vex.openvex.json",
        # SLSA build provenance, gated to public repos (skip != fail on a private repo); subjects now also
        # bind the SBOM + VEX (comma-separated in subject-path).
        "SLSA attest action pinned": "uses: actions/attest-build-provenance@",
        "SLSA gated to public repos": "if: ${{ !github.event.repository.private }}",
        "SLSA subjects incl SBOM + VEX": (
            'subject-path: "dist/*.tar.gz, dist/*.whl, '
            'messagefoundry-sbom.cdx.json, messagefoundry-vex.openvex.json"'
        ),
        # PyPI publish via the pinned pypa action, tag-gated, reading the clean staging dir
        "PyPI publish action pinned": "uses: pypa/gh-action-pypi-publish@",
        "PyPI publish reads dist-pub": "packages-dir: dist-pub/",
        # id-token scope for OIDC (Sigstore + Trusted Publishing + provenance)
        "id-token OIDC scope": "id-token: write",
        # deny-all at workflow level (least privilege)
        "workflow deny-all permissions": "permissions: {}",
    }
    missing = [name for name, tok in required.items() if tok not in rel]
    assert not missing, f"release.yml lost these load-bearing guards: {missing}"


# --- (4) the irreversible PyPI upload runs LAST and only on a tag ------------------------------------


def test_release_pypi_publish_is_last_step_and_tag_gated() -> None:
    rel = _release()
    # Isolate the `release` job (up to the next top-level job) so ordering is measured within it.
    release_job = rel.split("\n  release-harness:", 1)[0]

    # Step boundaries are `      - name:` / `      - uses:` at the job's step indent.
    steps = list(re.finditer(r"^      - (?:name|uses): (.+)$", release_job, re.M))
    assert steps, "could not locate any steps in the release job"
    last = steps[-1].group(1)
    assert "Publish to PyPI" in last, (
        f"the PyPI publish must be the LAST step in the release job (nothing may run AFTER the one "
        f"irreversible sink) — last step is instead: {last!r}"
    )

    # The publish must be tag-gated: its `if:` line must guard on a tag ref (so workflow_dispatch dry-runs
    # never publish). Grab the block from the publish step name to end-of-job.
    pub_block = release_job[release_job.index("Publish to PyPI") :]
    assert "if: startsWith(github.ref, 'refs/tags/')" in pub_block, (
        "the PyPI publish step is no longer tag-gated — a branch/workflow_dispatch run could publish"
    )

    # Publish (irreversible) must come AFTER build, leak-gate, sign and the GitHub release.
    def idx(tok: str) -> int:
        i = release_job.find(tok)
        assert i != -1, f"expected marker missing from release job: {tok!r}"
        return i

    order = [
        idx("Build sdist + wheel"),
        idx("Leak gate — sdist MUST be package-only"),
        idx("python -m sigstore sign"),
        idx("Create GitHub release"),
        idx("Publish to PyPI"),
    ]
    assert order == sorted(order), (
        f"release steps are out of order — the irreversible PyPI upload must run last: {order}"
    )


# --- (5) Trusted Publishing (OIDC) — never a token ---------------------------------------------------


def test_release_publish_uses_trusted_publishing_no_token() -> None:
    rel = _release()
    # No API-token / password path may exist anywhere in the release workflow: publishing is OIDC-only.
    for forbidden in (
        "password:",
        "TWINE_PASSWORD",
        "__token__",
        "PYPI_API_TOKEN",
        "api-token",
        "with: password",
    ):
        assert forbidden not in rel, (
            f"release.yml reintroduced a token-based publish path ({forbidden!r}) — publishing must stay "
            f"Trusted Publishing (OIDC), no token"
        )
    # The pinned pypa action + PEP 740 attestations, backed by the job's id-token scope.
    assert "uses: pypa/gh-action-pypi-publish@" in rel, "the Trusted-Publishing action is gone"
    assert "attestations: true" in rel, "PEP 740 attestations disabled on the PyPI publish"
    assert "id-token: write" in rel, "the release job dropped the id-token OIDC scope"


# --- (6) the mirror must never release (rewrite-proof inverted guard) --------------------------------


def test_release_mirror_guard_is_rewrite_proof() -> None:
    rel = _release()
    # publish.ps1 rewrites the PRIVATE slug -> the PUBLIC slug across *.yml when it materializes the mirror.
    # An `== private-slug` test would be rewritten into `== public-slug` and become TRUE on the mirror, so
    # the guard is written as `!= public-slug` (which the rewrite cannot touch). Both release jobs use it.
    assert rel.count("if: github.repository != 'MEFORORG/MessageFoundry'") >= 2, (
        "the rewrite-proof mirror guard (`!= 'MEFORORG/MessageFoundry'`) must gate BOTH the release and "
        "release-harness jobs — a naive `== 'wshallwshall/MessageFoundry'` normalization is rewrite-VULNERABLE"
    )
    # The vulnerable normalization must NOT be present as a job guard.
    assert "if: github.repository == 'wshallwshall/MessageFoundry'" not in rel, (
        "the mirror guard was normalized to a rewrite-VULNERABLE `== private-slug` form"
    )
