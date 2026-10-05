# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Guard the release PIPELINE's load-bearing policy (pyproject sdist allowlist + .github/workflows/release.yml).

Almost none of release.yml can be executed here (it needs a tag push, GitHub OIDC, a real build/SBOM/sign
run and PyPI Trusted Publishing), so a refactor could silently delete the sdist leak gate, revert the
publish step off Trusted Publishing onto a token, drop the Sigstore/SBOM steps, or let the pyproject
`only-include` allowlist drift out of sync with the workflow's leak-gate regex — and every other test would
still pass. Each test here fails LOUDLY if a guard disappears.

ONE STEP IS EXECUTED, and section (7) is why that stopped being optional. Reading a workflow can only
tell you a gate is PRESENT. The leak gate WAS present, well-formed and unable to fire: it decided on the
ABSENCE of `grep` matches instead of on evidence that a listing had happened, so a corrupt tarball, two
tarballs in dist/ (one of them carrying a private doc) and a tarball listing zero members all printed
"sdist is package-only" and exited 0. Every text check in sections (1) to (6) passed on that body, because
every string they look for was in it. Section (7) extracts the step's `run:` block by step name, writes it
to a script, and RUNS it under bash against fixture dist/ directories — so the claim under test becomes
"the gate rejects a leak" rather than "the gate is still spelled the way it was".

The single highest-value check is the CROSS-CHECK between the two allowlists (pyproject
`[tool.hatch.build.targets.sdist].only-include` and release.yml's leak-gate `grep -vE` regex): that exact
drift is the documented real defect — hatchling's whole-repo VCS sweep leaked docs/security/* to PUBLIC
PyPI on releases 0.1.0..0.2.15. If the two lists silently diverge a private doc can re-leak, so they are
pinned together here.

Most sections are pure text / `re` / `tomllib` checks. At least three do more: section (7) shells out to
bash and `tar` over tarballs it builds with `tarfile`; section (8) builds a throwaway venv with
`python -m venv`, plants a synthesized install into it, and runs each separately-built wheel smoke's own
`PYSMOKE` inspection script under that interpreter; and section (9) spawns `sys.executable` to run the
engine wheel smoke's own import probe against a planted checkout. None of them needs `python -m build` or
the network, so they run everywhere the suite runs. They do NOT and cannot assert the artifacts are actually
built/signed/SBOM'd/uploaded — that remains a CI-leg claim validated by the workflow_dispatch dry-run +
a `vX.Y.Z-rc1` pre-release tag.
"""

from __future__ import annotations

import copy
import functools
import gzip
import io
import os
import re
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tomllib
import zipfile
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import pytest
from _bash_resolver import bash_candidates, explain_returncode, require_bash

from tests._force_include import hatch_build
from tests._verify_softeners import verification_softeners
from tests._workflow_contexts import needs_of

_REPO = Path(__file__).resolve().parents[1]
PYPROJECT = _REPO / "pyproject.toml"
RELEASE_YML = _REPO / ".github" / "workflows" / "release.yml"

# The canonical package-only sdist allowlist. Pinned here so a change on EITHER side (pyproject or the
# workflow gate) trips a test — the drift that leaked private docs to PyPI must never be silent again.
EXPECTED_ONLY_INCLUDE = {"messagefoundry", "README.md", "CHANGELOG.md", "LICENSE", "NOTICE"}

# A real, git-tracked private security-posture doc — the class of file that leaked on 0.1.0..0.2.15. The
# leak gate MUST reject it. (Chosen from the real tree so the check stays honest, not a synthetic string.)
PRIVATE_CANARY = "docs/security/THREAT-MODEL.md"


def _executed_shell(text: str) -> str:
    """`text` with comment lines removed — what the runner would actually EXECUTE.

    Both release-shape guards below were fooled by the workflow's own prose: the comments explaining
    the v0.3.1 deadlock contain the literal `gh release create`, so a job chunk read as "creates a
    release" even with the command deleted. Mutation-proven: reverting the console to a bare
    `gh release upload` left the guard GREEN until this stripping was applied. Count executed shell,
    never narration.
    """
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _release() -> str:
    return RELEASE_YML.read_text(encoding="utf-8")


def _only_include() -> list[str]:
    # Through the shared reader (BACKLOG #1836), not a fourth descent of the same dotted path: this
    # module and tests/test_packaging.py both read [tool.hatch.build], one target apart.
    include: list[str] = hatch_build(PYPROJECT)["targets"]["sdist"]["only-include"]
    return include


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
    # The GROUNDEDNESS half — that the canary still names a REAL private doc rather than a path that
    # quietly stopped existing — can only be checked where private docs are present at all. On a public
    # checkout they are deny-listed/vaulted BY DEFINITION, so requiring the file there fails the whole
    # test and takes the actual guard below down with it (which is what it did on the mirror).
    #
    # The discriminator is the private DIRECTORY, not the canary file: keying on the file would be a
    # tautology — "if the canary exists, assert the canary exists" — and would silently stop grounding
    # the check the moment the path went stale, which is the one thing it is for.
    if (_REPO / "docs" / "security").is_dir():
        assert (_REPO / PRIVATE_CANARY).is_file(), (
            f"the private-doc canary {PRIVATE_CANARY!r} is missing from the tree — pick another real "
            f"security-posture doc so this rejection check stays grounded"
        )
    # The REJECTION half is a pure regex check over the path string, so it is valid in every checkout
    # and always runs. It is the assertion that actually guards the 0.1.0..0.2.15 leak class.
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
        # The comparison itself. Was the raw string test `[ "$built" = "$want" ]`; that could not
        # accept a canonical pre-release (0.3.0rc1 vs tag v0.3.0-rc1), so it is now a PEP 440
        # Version() compare. The canary tracks the CHECK existing, not how it is spelled.
        "version==tag comparison": "from packaging.version import InvalidVersion, Version",
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
        # SLSA build provenance; subjects now also bind the SBOM + VEX (comma-separated in
        # subject-path). No closing quote, so a subject appended later does not break it.
        # Its guard is checked on the step itself, not as a whole-file literal: the
        # visibility half by `test_the_attestation_step_keeps_its_visibility_test`, the event-and-ref
        # half by section (4b) (BACKLOG #1805).
        "SLSA attest action pinned": "uses: actions/attest-build-provenance@",
        "SLSA subjects incl SBOM + VEX": (
            'subject-path: "dist/*.tar.gz, dist/*.whl, '
            "messagefoundry-sbom.cdx.json, messagefoundry-vex.openvex.json, "
            "messagefoundry-sbom-windows.cdx.json"
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


#: The two engine SBOMs, each built by its own unprivileged job and shipped by the `release` job:
#: ``(job, runner, file)``. Two runners because the core lock's ``sys_platform`` markers resolve
#: differently on win32 (docs/SUPPLY-CHAIN.md, ADR 0149's 2026-09-30 amendment).
_SBOM_BUILD_JOBS = (
    ("sbom-linux", "ubuntu-latest", "messagefoundry-sbom.cdx.json"),
    ("sbom-windows", "windows-latest", "messagefoundry-sbom-windows.cdx.json"),
)
_ENGINE_SBOMS = tuple(f for _, _, f in _SBOM_BUILD_JOBS)
#: Spelled out rather than read back from the tuple above, so the sink test's "the Windows SBOM left
#: the walk" guard fails if that tuple loses its Windows row.
_WINDOWS_SBOM = "messagefoundry-sbom-windows.cdx.json"


def _run_shell(step: dict) -> str:
    """A step's executed shell, comments dropped, so a rationale comment naming a tool is not a call."""
    return _executed_shell(str(step.get("run") or ""))


@pytest.mark.parametrize(("job_name", "runner", "sbom"), _SBOM_BUILD_JOBS)
def test_each_engine_sbom_is_built_unprivileged_and_handed_to_release(
    job_name: str, runner: str, sbom: str
) -> None:
    """Each engine SBOM is built OUTSIDE the signing job, and only downloaded into it.

    Each assertion names a way it silently goes wrong:

    - the job runs on ITS runner, because only that interpreter resolves the core lock's
      ``sys_platform`` markers as an install there does -- the Windows job moved to Linux is a second
      Linux SBOM with a Windows filename;
    - it holds ``contents: read`` ONLY, so the release-tools install, the core-lock install and
      ``cyclonedx_py environment`` never run beside the signing identity;
    - it runs exactly when ``release`` does: the same job ``if:``, and ``release`` needs it, so a
      release cannot proceed without the file or ship one from a skipped job;
    - its upload refuses a missing file, rather than failing a job later at the download, and is
      kept one day, since the signed copy on the release is the record;
    - the ``release`` job downloads it exactly once. That it builds none itself is the next test.
    """
    jobs = _jobs()
    build, rel = jobs.get(job_name), jobs.get("release")
    assert build and rel, f"release.yml lost its `{job_name}` or `release` job"

    assert build.get("runs-on") == runner, build.get("runs-on")
    assert build.get("permissions") == {"contents": "read"}, build.get("permissions")
    assert _despace(str(build.get("if"))) == _despace(str(rel.get("if"))), (
        f"{job_name} and release must share one job guard: {build.get('if')!r} vs {rel.get('if')!r}"
    )
    assert job_name in needs_of(rel), rel.get("needs")

    built_here = [
        st for st in build.get("steps") or [] if "cyclonedx_py environment" in _run_shell(st)
    ]
    assert len(built_here) == 1, f"{job_name} has {len(built_here)} SBOM build steps"
    uploads = [
        st
        for st in build.get("steps") or []
        if str(st.get("uses", "")).startswith("actions/upload-artifact@")
    ]
    assert len(uploads) == 1, f"{job_name} has {len(uploads)} artifact uploads"
    assert uploads[0]["with"].get("if-no-files-found") == "error", uploads[0]["with"]
    # A hand-off between two jobs of one run; the signed copy on the release is the record (#2521).
    assert uploads[0]["with"].get("retention-days") == 1, uploads[0]["with"]
    artifact = uploads[0]["with"]["name"]
    assert uploads[0]["with"]["path"] == sbom

    steps = rel.get("steps") or []
    downloads = [
        st
        for st in steps
        if str(st.get("uses", "")).startswith("actions/download-artifact@")
        and (st.get("with") or {}).get("name") == artifact
    ]
    assert len(downloads) == 1, (
        f"release downloads the {artifact!r} artifact {len(downloads)} times"
    )


def test_the_release_job_builds_no_sbom_itself() -> None:
    """The signing job only downloads the engine SBOMs; it never generates one.

    This is what the 2026-09-30 move exists for (ADR 0149's amendment): an SBOM build back inside
    ``release`` puts package installs beside its signing identity again, while every sink check still
    passes. Both step kinds are read: a ``run:`` calling ``cyclonedx_py``, and a ``uses:`` CycloneDX
    action, which has no ``run:`` for the first test to see.
    """
    steps = _jobs()["release"].get("steps") or []
    assert steps, "release.yml's `release` job has no steps, so this check would prove nothing"
    in_release = [
        st.get("name") or st.get("uses")
        for st in steps
        if "cyclonedx" in _run_shell(st).lower() or "cyclonedx" in str(st.get("uses", "")).lower()
    ]
    assert not in_release, (
        f"release builds an SBOM itself again, beside its signing identity: {in_release}. Build it "
        f"in an unprivileged job and download it (ADR 0149's 2026-09-30 amendment)."
    )


def test_both_engine_sboms_reach_every_sink() -> None:
    """Both engine SBOMs are signed, SLSA-attested, attached to the GitHub release and uploaded as a
    workflow artifact, each with its Sigstore bundle where it ships. Held together, so neither can drop
    out of one sink while the other still reaches it."""
    steps = _jobs()["release"].get("steps") or []

    def body(pred: Callable[[dict], bool]) -> str:
        hits = [st for st in steps if pred(st)]
        assert len(hits) == 1, f"expected exactly one matching step, found {len(hits)}"
        return _executed_shell(str(hits[0].get("run") or "")) + str(hits[0].get("with") or "")

    # THE SIGN COMMAND ITSELF, continuations joined, not the whole step: the step's `ls -l` names the
    # file's `.sigstore*` bundle too, so a whole-body match stayed green with the file dropped from
    # `sigstore sign`. Measured by that mutation while writing this test.
    signing = body(lambda st: "python -m sigstore sign" in str(st.get("run") or ""))
    sign_cmd = [
        ln for ln in signing.replace("\\\n", " ").splitlines() if "python -m sigstore sign" in ln
    ]
    assert len(sign_cmd) == 1, f"expected one `sigstore sign` command, found {sign_cmd}"
    sinks = {
        "Sigstore signing": sign_cmd[0],
        "SLSA attestation": body(
            lambda st: str(st.get("uses", "")).startswith("actions/attest-build-provenance@")
        ),
        "GitHub release assets": body(lambda st: "gh release create" in str(st.get("run") or "")),
        # The dry-run upload, by its artifact name: the PyPI hand-over to the publish job is an
        # upload-artifact step too (vault BACKLOG #2631), and carries no SBOM.
        "workflow artifact upload": body(
            lambda st: (
                str(st.get("uses", "")).startswith("actions/upload-artifact@")
                and (st.get("with") or {}).get("name") == "release-artifacts"
            )
        ),
    }
    # Both walks below draw from this tuple: the Linux SBOM and the Windows one (PR 1849).
    assert len(set(_ENGINE_SBOMS)) >= 2, f"expected two distinct engine SBOMs: {_ENGINE_SBOMS}"
    assert _WINDOWS_SBOM in _ENGINE_SBOMS, f"the Windows SBOM left the walk: {_ENGINE_SBOMS}"
    missing = [(f, sink) for f in _ENGINE_SBOMS for sink, text in sinks.items() if f not in text]
    assert not missing, f"an engine SBOM does not reach these sinks: {missing}"
    # The Sigstore bundle must ride along wherever the file does, or an operator cannot verify it.
    unbundled = [
        (f, sink)
        for f in _ENGINE_SBOMS
        for sink in ("GitHub release assets", "workflow artifact upload")
        if f"{f}.sigstore" not in sinks[sink]
    ]
    assert not unbundled, f"an engine SBOM ships without its Sigstore bundle: {unbundled}"


#: The two halves every publish/release guard in release.yml must carry.
#:
#: The ref test alone was the defect. `workflow_dispatch` is a trigger on this workflow and it accepts
#: ANY ref the workflow is present on -- a TAG included. On a dispatch picked against a tag
#: `github.ref` IS `refs/tags/...`, so a ref-only guard is satisfied and the step runs. The file's own
#: dry-run promise ("run it manually to dry-run it") is what makes that the likely operator action.
#:
#: DECLARED HERE, ABOVE THEIR FIRST USE, and not beside the section-(4b) test that is their main
#: consumer: section (4) below reads them too, and a module-level name resolved at call time makes
#: that ordering invisible. Moving either test to its own module would have raised `NameError` at run
#: time rather than at review time.
_EVENT_GUARD = "github.event_name == 'push'"
_REF_GUARD = "startsWith(github.ref, 'refs/tags/')"

#: The guard must be the CONJUNCTION of those halves, not merely contain both. Two INDEPENDENT
#: substring tests accept `A || B`, which is strictly WORSE than the ref-only spelling this change
#: removed: a dispatch against ANY ref -- a branch included -- would satisfy it, and both halves are
#: still present so a token-by-token check stays green. Order is left free because it carries no
#: meaning; the operator between the halves carries all of it.
#:
#: COMPARED WITH ALL WHITESPACE REMOVED. `github.event_name=='push' && startsWith(github.ref,'refs/
#: tags/')` is a valid, correctly-ANDed expression that a byte-exact match rejects, and reddening a
#: tag-blocking test over spacing teaches the next author to relax the rule rather than fix a guard.
#: Whitespace is the one thing in a GitHub expression that carries no meaning at all.
_GUARD_CONJUNCTIONS = (
    f"{_EVENT_GUARD} && {_REF_GUARD}",
    f"{_REF_GUARD} && {_EVENT_GUARD}",
)


def _despace(text: str) -> str:
    """``text`` with every run of whitespace removed, for comparing GitHub expressions by meaning."""
    return re.sub(r"\s+", "", text)


# --- (4) the irreversible PyPI upload runs LAST and only on a tag ------------------------------------


def test_release_pypi_publish_is_last_step_and_tag_gated() -> None:
    """The irreversible PyPI upload runs LAST: in its own job, after the whole build job.

    Since vault BACKLOG #2631 limb 1 the publish runs in `publish-pypi`, which needs `release`. So
    "last" has two halves: the build job ends by handing the files over, after build, leak gate,
    sign and the GitHub release; and the publish job ends with the engine upload.

    THE GUARD ITSELF IS SECTION (4b)'s, NOT THIS TEST'S: it parses the YAML, conjoins job and step,
    and covers every publishing step. What stays here is the ORDER.

    This order is load-bearing, not cosmetic: the GitHub release is REVERSIBLE (deletable) and the
    PyPI upload is not (a version number is burned forever). Doing the reversible half first is what
    made the v0.3.1 publisher failure recoverable at all.
    """
    jobs = _jobs()
    steps = jobs["release"]["steps"]
    names = [str(s.get("name") or s.get("uses") or "") for s in steps]

    def at(pred: Callable[[dict], bool], what: str) -> int:
        hits = [i for i, s in enumerate(steps) if pred(s)]
        assert len(hits) == 1, f"expected one {what} step in `release`, found {hits}"
        return hits[0]

    order = [
        at(lambda s: str(s.get("name")) == "Build sdist + wheel", "build"),
        at(lambda s: str(s.get("name", "")).startswith("Leak gate"), "leak gate"),
        at(lambda s: "python -m sigstore sign" in str(s.get("run") or ""), "sign"),
        at(lambda s: str(s.get("name")) == "Create or update the GitHub release", "release"),
        at(lambda s: (s.get("with") or {}).get("name") == "pypi-engine", "hand-over"),
    ]
    assert order == sorted(order) and order[-1] == len(steps) - 1, (order, names)
    assert not any("gh-action-pypi-publish" in str(s.get("uses")) for s in steps), (
        "the build job publishes to PyPI itself; the publish belongs to publish-pypi"
    )

    publish = jobs["publish-pypi"]
    assert needs_of(publish) == ["release"], needs_of(publish)
    last = publish["steps"][-1]
    assert str(last.get("name", "")).startswith("Publish to PyPI"), last
    assert (last.get("with") or {}).get("packages-dir") == "dist-pub/", last


# --- (4b) every mutating step tests the EVENT as well as the ref (BACKLOG #1584) ---------------------

#: Steps in release.yml that mutate a public sink BY PUBLISHING A RELEASE ARTIFACT OR ATTESTING ONE --
#: the four PyPI publishes (the toolkit's since ADR 0201), the four GitHub-release mutations
#: (BACKLOG #1584; the fourth, which takes the engine's draft release out of draft, since vault
#: BACKLOG #2631) and the SLSA
#: build-provenance attestation (BACKLOG #1805). Pinned as a count so a NEW one cannot be added
#: without either carrying the guard pair or landing here deliberately. An empty scan must never read
#: as a pass.
#:
#: Why the attestation is held to the same rule is stated in release.yml, in the comment above the
#: attestation step. Why `python -m sigstore sign` is NOT is stated in the header's "THE DRY-RUN IS
#: NOT SILENT" paragraph. Read a green here as "a dispatch neither publishes nor attests a release
#: artifact", never as "a dispatch writes nothing public".
_EXPECTED_MUTATING_STEPS = 9

#: Actions that publish a release artifact, matched as a `uses:` prefix.
_PUBLISHING_ACTIONS = (
    "pypa/gh-action-pypi-publish@",
    "softprops/action-gh-release@",
    "actions/create-release@",
)

#: Actions that write a GitHub artifact attestation, matched as a `uses:` prefix. Any of them needs the
#: job's `attestations: write`. `actions/attest` is the general action the other two wrap, so a future
#: switch to it, or an added SBOM attestation, is caught rather than silently uncounted.
_ATTESTING_ACTIONS = (
    "actions/attest-build-provenance@",
    "actions/attest-sbom@",
    "actions/attest@",
)

_MUTATING_ACTIONS = _PUBLISHING_ACTIONS + _ATTESTING_ACTIONS

#: …and the same sinks reached from a shell line. `gh release view` is deliberately absent: it reads.
_PUBLISHING_COMMANDS = re.compile(
    r"\bgh release (?:create|edit|upload)\b"
    r"|\b(?:python\s+-m\s+)?twine\s+upload\b"
    r"|\bgh api\b[^\n]*\breleases\b"
)


def _mutating_steps(job: dict) -> list[tuple[str, str]]:
    """``(step name, EFFECTIVE if-expression)`` for every step in ``job`` that publishes or attests.

    Found by what a step DOES, never by its ``name:`` -- the names differ per distribution and a name
    is the one thing in these files that may be reworded freely. The routes it knows are the PyPI
    publish actions (``pypa/gh-action-pypi-publish``, or a bare ``twine upload``), the
    GitHub-release ones (``gh release create|edit|upload``, ``gh api ...releases``, and the two
    common release actions) in an EXECUTED shell line or a ``uses:``, and the GitHub
    artifact-attestation actions in ``_ATTESTING_ACTIONS`` (BACKLOG #1805).

    THAT LIST IS NOT EXHAUSTIVE AND THE PINNED COUNT DOES NOT MAKE IT SO. Measured: a step running
    ``python -m twine upload`` used to slip past entirely, leaving the count at six and the suite
    green -- so "a new publishing step cannot be added without carrying the guard pair" is true only
    of the routes below. A genuinely new route (a fresh action, a REST call spelled another way) is
    invisible here, and the count cannot report what it never counted. Add the route when one
    appears; do not read a green as proof that none did.

    Comments are stripped before matching, for the reason ``_executed_shell`` exists: this workflow's
    rationale prose quotes the very commands being matched (the v0.3.1 deadlock note contains a
    literal ``gh release create``), so a whole-body match would report the explanation as a step.

    The returned guard is the JOB's ``if`` conjoined with the STEP's, because that is what GitHub
    evaluates -- a step runs only when both hold. Reading the step's ``if`` alone would false-accuse
    the DRY-er refactor of hoisting the pair to the job (already the established shape here:
    ``release-webconsole`` gates on the repository and the tag namespace at job level), and would be
    blind to a job condition that admits a dispatch.
    """
    found: list[tuple[str, str]] = []
    job_if = str(job.get("if") or "").strip()
    for raw_step in job.get("steps") or []:
        step = raw_step or {}
        name = step.get("name") or step.get("uses") or "<unnamed step>"
        uses = str(step.get("uses") or "")
        mutates = uses.startswith(_MUTATING_ACTIONS)
        body = _executed_shell(str(step.get("run") or ""))
        releases = _PUBLISHING_COMMANDS.search(body) is not None
        if mutates or releases:
            step_if = str(step.get("if") or "").strip()
            effective = " && ".join(p for p in (job_if, step_if) if p)
            found.append((str(name), effective))
    return found


def test_every_mutating_release_step_gates_on_the_event_and_the_ref() -> None:
    """No mutating step may publish on a `workflow_dispatch`, however the run's ref is spelled.

    The header of release.yml promises a manual run is a dry-run: it "does NOT create a GitHub
    release, does NOT publish to PyPI and does NOT write an SLSA attestation". A guard testing only
    `startsWith(github.ref, 'refs/tags/')`
    does not keep that promise, because a dispatch can be pointed at a tag.

    Scope of the exposure, stated so this test is not read as more than it is: the publish action
    carries `skip-existing: true`, so re-dispatching an ALREADY-PUBLISHED tag is a no-op. What a
    ref-only guard WOULD have admitted is a tag whose version is not yet on PyPI, or an actor holding
    workflow_dispatch permission without tag-push permission. MessageFoundry has zero deployments and
    this workflow has never been dispatched against a tag, so nothing was published this way.

    The attestation arm (BACKLOG #1805) is NOT in that clean state. Its old guard admitted a dispatch
    on any ref, and at least one dispatch did write an attestation; release.yml names the run above
    the attestation step. This test holds only the copy of release.yml in this tree. It cannot
    retract that attestation, and it cannot change an older ref's copy, which a dispatch still runs.

    Scope of the RULE, which is narrower than "no mutating step": it covers the steps that publish a
    release ARTIFACT and, since BACKLOG #1805, the step that writes its SLSA build-provenance
    attestation. At least one public write is left out on purpose, Sigstore's Rekor entry;
    release.yml's header says why, so a green here is not read as a claim about it.

    Mutation: drop either half of any guard, or swap its `&&` for `||`. Red here, naming the step.
    Reverting the attestation step to its visibility-only guard is the #1805 arm.
    """
    yaml = pytest.importorskip("yaml")
    jobs = (yaml.safe_load(_release()) or {}).get("jobs") or {}
    assert jobs, "release.yml declares no jobs — the workflow shape moved"

    checked = 0
    offenders: list[str] = []
    for job_key, job in jobs.items():
        for name, guard in _mutating_steps(job or {}):
            checked += 1
            flat = _despace(guard)
            missing = [tok for tok in (_EVENT_GUARD, _REF_GUARD) if _despace(tok) not in flat]
            if missing:
                offenders.append(
                    f"release.yml:{job_key} — step {name!r} guard {guard!r} omits {missing}"
                )
                continue
            # Both halves present is NOT the requirement — they must be ANDed. `A || B` carries both
            # and fires on a dispatch against any ref, so a token-by-token check would green the
            # widest form of the very defect #1584 closed.
            if not any(_despace(c) in flat for c in _GUARD_CONJUNCTIONS):
                offenders.append(
                    f"release.yml:{job_key} — step {name!r} guard {guard!r} carries both halves but "
                    f"not as a conjunction"
                )
            # A disjunction anywhere in a publish guard needs a human, not a substring test: `||`
            # binds looser than `&&`, so it can re-admit a dispatch from outside the pair above.
            elif "||" in guard:
                offenders.append(
                    f"release.yml:{job_key} — step {name!r} guard {guard!r} contains `||`; a "
                    f"disjunction in a publish guard must be reviewed by hand"
                )

    # Liveness: report what was EXAMINED. "no offenders" and "nothing was scanned" otherwise produce
    # the same green, and this detector keys on step shape, which a refactor can move.
    print(f"[release-pipeline] examined {checked} publishing or attesting step(s) in release.yml")
    # OFFENDERS FIRST, count second. A NEW unguarded step trips both; reported count-first it
    # reads as a bookkeeping nit whose natural fix is to raise the constant, and the real failure
    # surfaces only on the re-run. The actionable assert goes first; the count is the backstop.
    assert not offenders, (
        "a release step that publishes or attests an artifact does not test the EVENT as well as the "
        "ref, so a workflow_dispatch could reach it (BACKLOG #1584, #1805):\n  "
        + "\n  ".join(offenders)
    )
    assert checked == _EXPECTED_MUTATING_STEPS, (
        f"expected {_EXPECTED_MUTATING_STEPS} publishing or attesting steps in release.yml, found "
        f"{checked}. A new publish, `gh release` or attestation step must carry {_EVENT_GUARD!r} AND "
        f"{_REF_GUARD!r}, ANDed; if one was deliberately removed, lower the constant in the same "
        f"commit."
    )


def test_the_attestation_step_keeps_its_visibility_test() -> None:
    """Every attestation step keeps `!github.event.repository.private` in its OWN `if:`, ANDed.

    Section (4b) adds the event-and-ref pair; this keeps the older half. Without it, the step FAILS
    on a private repository ("not available for user-owned private repositories"), and it sits before
    the PyPI publish, so the whole release would abort there. Read from the step's parsed `if:` rather
    than as a whole-file substring, so term order is free (it carries no meaning, as (4b) says) and
    another step's guard cannot stand in for this one.
    """
    yaml = pytest.importorskip("yaml")
    jobs = (yaml.safe_load(_release()) or {}).get("jobs") or {}
    visibility = _despace("!github.event.repository.private")
    found: list[str] = []
    offenders: list[str] = []
    for job_key, job in jobs.items():
        for raw_step in (job or {}).get("steps") or []:
            step = raw_step or {}
            if not str(step.get("uses") or "").startswith(_ATTESTING_ACTIONS):
                continue
            name = str(step.get("name") or step.get("uses"))
            found.append(f"{job_key}:{name}")
            step_if = str(step.get("if") or "")
            if visibility not in _despace(step_if) or "||" in step_if:
                offenders.append(f"release.yml:{job_key} — step {name!r} guard {step_if!r}")
    # Liveness: an empty scan must not read as a pass.
    assert found, "no attestation step found in release.yml — the detector matched nothing"
    assert not offenders, (
        "an attestation step lost its repository-visibility test, or ORs it, so it would fail and "
        "abort the release on a private repository:\n  " + "\n  ".join(offenders)
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


def test_release_jobs_are_gated_ON_the_source_repo() -> None:
    """Both release jobs must run on MEFORORG/MessageFoundry, and nowhere else.

    THIS ASSERTION USED TO BE THE EXACT OPPOSITE, and that is the point. Before the cutover this repo
    was the published MIRROR, the mirror had to never release, and publish.ps1 rewrote the private slug
    to the public one across *.yml — so the guard was written `!= public-slug` to be rewrite-proof, and
    this test pinned that form.

    Both premises died at the cutover: publish.ps1 is retired, and MEFORORG is now the SOURCE. The old
    assertion therefore kept the release pipeline gated OFF the only repo that can publish — PyPI
    Trusted Publishing is bound to MEFORORG/MessageFoundry + release.yml — so no tag could ever ship,
    and the test made that look intentional. A test can outlive the premise it encodes; this one did.
    """
    rel = _release()
    assert rel.count("if: github.repository == 'MEFORORG/MessageFoundry'") >= 2, (
        "both the `release` and `release-harness` jobs must be gated ON the source repo "
        "(`== 'MEFORORG/MessageFoundry'`), or a pushed tag silently skips and nothing publishes"
    )
    # The pre-cutover inversion must never come back: it skips on the only repo that can release.
    assert "if: github.repository != 'MEFORORG/MessageFoundry'" not in rel, (
        "the pre-cutover mirror guard (`!= 'MEFORORG/MessageFoundry'`) is back — that disables releases "
        "entirely, because MEFORORG is the source repo now, not the mirror"
    )
    # The private vault must never be a release target either.
    assert "wshallwshall" not in rel, "release.yml must not reference the retired private vault"


def test_the_github_release_step_is_idempotent() -> None:
    """A re-run must be able to repeat the release step, or a publish failure wedges the tag forever.

    The step sits BEFORE the irreversible PyPI upload (deliberately — see the ordering test above), so
    when it was a bare `gh release create` the first publish failure was terminal: the release now
    existed, so every re-run died on "a release with the same tag name already exists" and SKIPPED the
    publish. The retry could not even reach the thing it was retrying. v0.3.1 needed a human to delete
    a public release before attempt 4 could get through.
    """
    rel = _release()
    assert "gh release view" in rel, (
        "the release step no longer probes for an existing release — a re-run will fail on 'already "
        "exists' and skip the PyPI publish below it"
    )
    assert "gh release edit" in rel and "--clobber" in rel, (
        "create-or-update is incomplete: an existing release must be edited and its assets replaced "
        "(--clobber), since a re-run regenerates every artifact with fresh signatures"
    )
    # `gh release edit --prerelease` (bare) only ever SETS the flag; demoting needs an explicit value.
    assert "--prerelease=true" in rel and "--prerelease=false" in rel, (
        "edit uses a bare --prerelease, so a re-run could never demote a mis-marked pre-release"
    )


def test_no_self_referential_slug_rewrite_survives() -> None:
    """The README slug rewrite is GONE, and no `sed s#X#X#` may come back.

    publish.ps1 rewrote the private slug to the public one across *.yml — including this workflow —
    so at the cutover both sides of the substitution collapsed to the same string, leaving a no-op
    sed followed by a guard that failed if that string was present. The README names it 19 times, so
    the step failed on EVERY tag push: the v0.3.0 tag died there and the repo has no releases.
    """
    rel = _release()
    assert "- name: Rewrite README repo slug" not in rel, (
        "the mirror-era README slug rewrite is back — there is one repo now, so it rewrites nothing, "
        "and its 'left private-repo links' guard then fails on every tag"
    )
    assert not re.search(r"sed[^\n]*s([#/|])([^\n#/|]+)\1\2\1", rel), (
        "a self-referential sed (s#X#X#) is present — it cannot transform anything, and paired with "
        "a grep guard it fails unconditionally"
    )


def test_both_wheel_smokes_compare_versions_not_strings() -> None:
    """Tag-vs-built comparison must normalise (PEP 440), in BOTH the engine and harness jobs.

    The trigger only fires on `vX.Y.Z` / `vX.Y.Z-*`, so a pre-release tag must carry a hyphen, while
    hatchling and PyPI normalise `0.3.0-rc1` to `0.3.0rc1`. A raw string compare therefore cannot be
    satisfied by a canonical version — and in the HARNESS job it can never be satisfied at all, since
    its `built` comes out of the INSTALLED distribution's metadata (BACKLOG #1701 replaced the wheel-
    FILENAME read that stood here), and the backend canonicalised that string on the way in.
    """
    rel = _release()
    assert '[ "$built" = "$want" ]' not in rel, (
        "a raw string compare of tag vs built version is back; it rejects canonical pre-release "
        "versions (0.3.0rc1 != 0.3.0-rc1) and blocks every rc tag"
    )
    # DERIVED, not hardcoded. This read `== 2` and broke the day a third wheel job (the separately
    # versioned console) was added — a guard that must be edited whenever the thing it guards grows is
    # a guard that gets its number bumped without thought. The property worth pinning is "EVERY wheel
    # smoke normalises", so derive the expected set of smokes rather than a literal.
    wheel_builds = rel.count("python -m build --wheel")
    assert wheel_builds >= 2, f"expected the harness + console wheel builds, found {wheel_builds}"

    # ASKED PER STEP, because a TOTAL over the file cannot express that property and this one silently
    # stopped doing so. It counted `from packaging.version import` occurrences against `wheel_builds +
    # 1`, which held only while each smoke normalised in exactly one place — the tag compare. The
    # console and harness INSPECTION scripts now normalise too (they compare a source literal, and a
    # lockstep pin, against metadata the backend canonicalised: BACKLOG #1701, #1585), so the total
    # moved to 5 while every underlying claim got STRONGER. A total also never bound the right thing:
    # three comparisons in one job and none in another satisfied it exactly as well as one each.
    smokes = {
        # `.get("run") or ""` rather than `step["run"]`, matching _wheel_smoke_steps(): a smoke step
        # written with `uses:` must fail the assertion below with its own message, not a KeyError.
        # Keyed by job AND step: the `release` job holds two smokes since ADR 0201 (engine, toolkit).
        f"{name}/{step.get('name')}": str(step.get("run") or "")
        for name, job in _jobs().items()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and str(step.get("name") or "").startswith("Smoke-check")
    }
    assert len(smokes) == wheel_builds + 1, (
        f"expected one smoke step per wheel-building job ({wheel_builds}) plus the engine's, found "
        f"{sorted(smokes)}. A wheel job without a smoke step publishes an artifact nothing read."
    )
    for name, run in sorted(smokes.items()):
        assert "from packaging.version import" in run, (
            f"{name}'s smoke compares versions as strings. Every version comparison on the release "
            f"path must normalise (PEP 440): the tag carries a hyphen a pre-release cannot be "
            f"spelled without, and the backend canonicalises everything it writes into metadata, so "
            f"a string compare rejects `0.3.0-rc1` against `0.3.0rc1` — the same release."
        )

    # NAMED SHAPES, because the import check above only proves a step normalises SOMEWHERE. Each
    # wheel smoke now normalises in TWO places — its inspection's own version check, and its tag
    # compare — so reverting ONE of them, and deleting the import it no longer needs, leaves the
    # other import behind and that loop green. Measured before this was added: per step, the engine
    # holds 1 occurrence and the console and harness 2 each.
    #
    # These are the two string compares actually removed (BACKLOG #1701, #1585), named one at a time
    # so a revert says WHICH came back. Scanned over CODE ONLY: the workflow quotes both shapes in
    # the comments explaining why they went, and a guard that fires on its own documentation gets
    # the documentation deleted rather than the guard respected.
    code = "\n".join(line for line in rel.splitlines() if not line.lstrip().startswith("#"))
    for shape, what in (
        ("!= dist.version", "the console's installed __version__ against its wheel metadata"),
        ('f"=={dist.version}"', "the harness's lockstep pin against the version it ships at"),
    ):
        assert shape not in code, (
            f"a raw string compare of {what} is back ({shape}). Those two sides are normalised "
            f"differently by construction — the build backend canonicalises what it writes into "
            f"metadata and leaves the source spelling alone — so this rejects `0.3.0-rc1` against "
            f"`0.3.0rc1`, the same release, at the last gate before the PyPI upload."
        )


# --- the separately-versioned web console (ASVS 15.2.4) --------------------------------------------


@functools.cache
def _jobs() -> dict:
    import yaml

    return yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))["jobs"]


def test_the_console_and_engine_tag_namespaces_are_mutually_exclusive() -> None:
    """The console is SEPARATELY VERSIONED (its own ``__version__`` root, changelog and PyPI cadence —
    docs/WEBCONSOLE-PACKAGE.md), so it fires on ``webconsole-v*`` while the engine fires on ``v*``.

    If the two guards ever overlap the damage is silent and asymmetric: an engine tag would publish the
    console at a version nobody chose, and a console tag would publish the ENGINE at the console's
    version. Both are wrong in a way the version-check steps cannot catch, because each checks its own
    wheel against the same tag.

    Mutation: drop either ``startsWith(github.ref_name, 'webconsole-')`` clause. Red here.
    """
    jobs = _jobs()
    engine, console = jobs["release"]["if"], jobs["release-webconsole"]["if"]
    assert "!startsWith(github.ref_name, 'webconsole-')" in engine, (
        "the engine release job would fire on a console tag and ship the engine at the console's version"
    )
    assert (
        "startsWith(github.ref_name, 'webconsole-')" in console and "!startsWith" not in console
    ), "the console release job is not gated to its own tag namespace"


def test_the_console_release_does_not_depend_on_the_engine_release() -> None:
    """``release-harness`` is deliberately lockstep and so carries ``needs: release``. The console is
    deliberately NOT: an engine release must not drag it along, and a console release must not wait on
    one. A ``needs`` on any engine job would silently couple two cadences the design separates.

    It does need ``tag-provenance`` (vault BACKLOG #2631), which belongs to neither cadence: it
    checks the tagged commit, whichever namespace the tag is in. That is the ONLY job it may need.
    """
    needs = needs_of(_jobs()["release-webconsole"])
    assert needs == ["tag-provenance"], (
        f"release-webconsole needs {needs}; it must need the provenance gate and nothing else -- "
        "the console has its own cadence, so it must not depend on the engine release"
    )


def test_the_console_version_check_reads_the_console_tag_not_the_engine_tag() -> None:
    """The strip must be ``webconsole-v``, not ``v``. With the wrong prefix ``want`` keeps the
    ``webconsole-`` text, no PEP 440 parse succeeds, and the job fails on EVERY console tag by
    construction — the exact shape of the bug the harness job carried until it was fixed."""
    body = RELEASE_YML.read_text(encoding="utf-8")
    console = body[body.index("release-webconsole:") : body.index("release-harness:")]
    assert '"${GITHUB_REF_NAME#webconsole-v}"' in console, (
        "the console version check must strip the console tag prefix, not the engine's"
    )
    # The second half — that the version under test is the CONSOLE's — used to be pinned as the
    # literal `messagefoundry_webconsole-`, which was the wheel-FILENAME regex the step ran. BACKLOG
    # #1701 deleted that read: the step now installs the wheel and asks the installed distribution.
    # So the assertion moved to the name it looks up rather than the filename it used to parse.
    assert 'DIST = "messagefoundry-webconsole"' in console, (
        "it must read the CONSOLE distribution's version, not the engine's"
    )


def test_the_console_publish_uses_trusted_publishing_and_is_tag_gated() -> None:
    """Same bar as the engine and harness: OIDC, never an API token, and never on a branch push.

    The ``PUBLISH_WEBCONSOLE`` variable gate is deliberate — the build and version-check run on every
    console tag so the path is exercised before it is armed. Flipping the variable is what actually
    creates the PyPI project and CLAIMS the name (ASVS 15.2.4): a registered *pending* publisher grants
    permission to publish but reserves nothing.
    """
    body = RELEASE_YML.read_text(encoding="utf-8")
    console = body[body.index("release-webconsole:") : body.index("release-harness:")]
    assert "pypa/gh-action-pypi-publish@" in console, (
        "the console must publish via the pinned action"
    )
    assert "id-token: write" in console, "Trusted Publishing needs the OIDC identity"
    assert not re.search(r"password:|PYPI_.*TOKEN|api-token", console), (
        "the console publish must not use an API token — Trusted Publishing only"
    )
    assert (
        "startsWith(github.ref, 'refs/tags/')" in console and "vars.PUBLISH_WEBCONSOLE" in console
    ), "the console publish must be tag-gated AND variable-gated"


def test_a_job_without_needs_release_must_create_its_own_github_release() -> None:
    """The asymmetry that broke the console job on first write, and would break the next one too.

    ``release-harness`` may use a bare ``gh release upload`` because ``needs: release`` guarantees the
    engine already created the GitHub release. ``release-webconsole`` deliberately has NO ``needs`` (it
    fires on its own tag namespace), so on a console tag no release exists — a bare upload fails with
    "release not found", the job dies BEFORE its publish step, and the one job whose purpose is to
    claim the PyPI name can never claim it.

    Derived, not hardcoded to the console: ANY release job that uploads assets without depending on the
    engine release must create-or-update its own. Mutation: replace the console's create-or-update with
    a bare ``gh release upload``. Red here.
    """
    import yaml

    body = RELEASE_YML.read_text(encoding="utf-8")
    jobs = yaml.safe_load(body)["jobs"]
    names = list(jobs)
    # Job chunks are sliced on the LINE-ANCHORED `^  <name>:` header. `body.index(f"{name}:")` -- what
    # this did first -- matches the earliest substring anywhere, including the header comment prose, so
    # every chunk started at the top of the file and contained every job. The guard then found a
    # `gh release create` in all of them and passed while the console job carried a bare upload: it did
    # not catch the exact defect it was written for. Proven by mutation before this fix, not assumed.
    starts = {
        m.group(1): m.start()
        for m in re.finditer(r"^  ([a-z][\w-]*):$", body, re.M)
        if m.group(1) in jobs
    }
    assert set(starts) == set(jobs), (
        f"could not line-anchor every job: {sorted(set(jobs) - set(starts))}"
    )
    problems: list[str] = []
    for i, name in enumerate(names):
        nxt = names[i + 1] if i + 1 < len(names) else None
        chunk = _executed_shell(body[starts[name] : (starts[nxt] if nxt else len(body))])
        if "gh release upload" not in chunk and "gh release create" not in chunk:
            continue  # attaches nothing to a GitHub release
        if "release" in needs_of(jobs[name]):
            continue  # the engine release ran first and created it
        if "gh release create" not in chunk:
            problems.append(name)
    assert not problems, (
        f"release job(s) that attach assets without `needs: release` and without creating the release "
        f"themselves: {problems}. On their own tag no GitHub release exists, so the upload fails and "
        f"the job dies before its publish step."
    )


def test_every_release_creating_job_is_rerunnable() -> None:
    """A bare ``gh release create`` turns one PyPI failure into a permanent retry deadlock: every
    re-run dies on "a release with the same tag name already exists" and SKIPS the publish, so the
    re-run cannot test the fix it exists to verify. Observed on v0.3.1.

    Mutation: drop the ``gh release view`` / ``gh release edit`` arm from any creating job. Red here.
    """
    # COMMENT LINES ARE STRIPPED FIRST. The workflow's own prose explains the v0.3.1 deadlock and names
    # `gh release create` twice while doing so; counting raw occurrences therefore found 4 "creators"
    # against 2 real ones and failed on documentation. Count executed shell, not narration.
    # Through the module's ONE stripper. This was a second inline copy of `_executed_shell`, and two
    # implementations of one rule drift the first time either is fixed — that helper will eventually
    # learn about heredocs (this workflow embeds `#`-commented Python in `<<'PYVER'` blocks) and an
    # inline twin would silently keep the old behaviour.
    body = RELEASE_YML.read_text(encoding="utf-8")
    code = _executed_shell(body)
    creators = code.count("gh release create")
    assert creators, "no job creates a GitHub release — the workflow shape moved"
    assert code.count("gh release view") >= creators, (
        f"{creators} job(s) run `gh release create` but only {code.count('gh release view')} check for "
        f"an existing release first — a re-run will deadlock before the publish step"
    )


# --- (7) the leak gate EXECUTED against fixture sdists (not read — RUN) -------------------------------

#: Located by step NAME, and by a PREFIX rather than the whole string: the full name carries an em dash,
#: and pinning punctuation here would break the harness on a cosmetic edit while the gate it guards was
#: fine. Section (3)'s canary already pins the full name, so nothing is lost by being lenient here.
_LEAK_GATE_STEP_PREFIX = "Leak gate"

#: hatchling names every sdist member `<project>-<version>/...`, and the gate strips that first path
#: component before matching the allowlist. The fixtures must carry it or they would be testing a shape
#: no real sdist has.
_SDIST_PREFIX = "messagefoundry-0.3.0"

#: What a package-only sdist legitimately contains. One member per allowlist branch a real build
#: produces, so the positive control exercises the allowlist rather than one lucky path.
_CLEAN_MEMBERS = (
    "messagefoundry/__init__.py",
    "messagefoundry/py.typed",
    "PKG-INFO",
    "pyproject.toml",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
)


def _step_script_by_prefix(prefix: str, what: str) -> str:
    """The ``run:`` block of the one step whose name starts with ``prefix``, from the PARSED workflow.

    Exactly one step may match. Two would mean the extractor is choosing between them arbitrarily, and a
    harness that silently exercises the wrong step is worse than no harness at all.

    ONE COPY, deliberately. This was written twice — once for the leak gate, once for the wheel smoke —
    and two extractors for one invariant drift apart the first time either is fixed.
    """
    steps = [
        step
        for job in _jobs().values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and str(step.get("name") or "").startswith(prefix)
    ]
    assert len(steps) == 1, (
        f"expected exactly one release.yml step whose name starts with {prefix!r}, found "
        f"{len(steps)} — the tests grading {what} cannot know which one they are looking at"
    )
    run = steps[0].get("run")
    assert isinstance(run, str) and run.strip(), f"the {what} step has no `run:` script"
    return run


def _leak_gate_script() -> str:
    """The leak gate's ``run:`` block."""
    return _step_script_by_prefix(_LEAK_GATE_STEP_PREFIX, "the leak gate")


def _write_sdist(path: Path, members: Sequence[str]) -> None:
    """A gzip tarball at ``path`` holding ``members`` under the ``<project>-<version>/`` prefix."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as tf:
        for member in members:
            payload = b"fixture\n"
            info = tarfile.TarInfo(f"{_SDIST_PREFIX}/{member}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


def _posix_tool_env() -> dict[str, str]:
    """``os.environ`` with every candidate bash's own bin directory on the FRONT of PATH.

    The extracted step calls ``tar``, ``sed`` and ``grep``. On a GitHub runner those are simply there;
    on Windows they live beside the interpreter in Git's ``usr/bin``, and nothing puts that directory
    on PATH unless the parent process is ALREADY a Git Bash. Measured on this box: launched from
    PowerShell, ``Git/usr/bin/bash.exe`` resolves only ``tar`` (Windows ships one in system32) and the
    step dies on ``sed: command not found`` — a HARNESS fault that would read as a finding about the
    gate, and one that every rejection test would happily accept as a non-zero exit.

    Derived from ``bash_candidates()`` rather than a hardcoded install path, so it follows the same git
    anchor the resolver uses instead of becoming a second, silently different one. On Linux this
    re-prepends ``/usr/bin``, which is a no-op.
    """
    env = dict(os.environ)
    tool_dirs = [str(candidate.parent) for candidate in bash_candidates() if candidate.is_file()]
    env["PATH"] = os.pathsep.join([*tool_dirs, env.get("PATH", "")])
    return env


def _run_leak_gate(bash: str, workdir: Path, script: Path, env: dict[str, str]) -> tuple[int, str]:
    """Run the extracted step from ``workdir`` the way the runner would; return (rc, combined output).

    ``bash -e`` IS THE RUNNER'S DEFAULT, and using exactly it is the point. The step sets no ``shell:``
    and neither the workflow nor the job sets ``defaults.run.shell``, so Actions runs it as
    ``bash -e {0}`` — WITHOUT ``pipefail``. Adding ``-o pipefail`` here would test a shell the release
    never uses, and would paper over the precise blindness this section exists to detect.

    Output is decoded as UTF-8 explicitly: the gate's own error line contains an em dash, and letting a
    Windows console's cp1252 default decode it would turn an assertion about the gate's message into an
    assertion about the harness's locale.
    """
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, "-e", str(script)],
        cwd=str(workdir),
        env=env,
        capture_output=True,
        timeout=60,
    )
    return proc.returncode, (proc.stdout + proc.stderr).decode("utf-8", "replace")


@pytest.fixture
def leak_gate(tmp_path: Path) -> tuple[str, Path, dict[str, str]]:
    r"""A usable bash, plus the extracted step written to disk as BYTES.

    NO ``skipif`` ON ``shutil.which("bash")`` (BACKLOG #1216; ``tests/_bash_resolver.py`` is the single
    source, and every private copy of that guard kept the defect). It asks whether A bash exists, not
    whether the one it found can read the fixture this process just wrote — on Windows, PATH order often
    answers with ``C:\Windows\System32\bash.exe``, the WSL launcher, which lives in a different
    filesystem namespace. ``require_bash`` probes git-derived candidates with a live read-back and fails
    LOUDLY when none can do the job.

    Loud is doubly right here. A skip in the one test that proves a publish gate CAN FIRE is a green
    that proves nothing — the same silent-control shape (ADR 0158) as the defect this section was
    written for, rebuilt one layer up in the harness meant to catch it.

    WRITTEN AS BYTES, never ``write_text``. On Windows ``write_text`` translates ``\n`` to ``\r\n``, bash
    then reads ``shopt -s nullglob\r``, and every case below fails for a harness reason while reading as
    a finding about the gate.
    """
    script = tmp_path / "leak_gate.sh"
    script.write_bytes(_leak_gate_script().encode("utf-8"))
    env = _posix_tool_env()
    # The SAME env for resolution and for the run. Resolving under one PATH and executing under another
    # would mean the controls certified an interpreter the script never actually gets.
    return require_bash(tmp_path, env), script, env


def test_the_extracted_leak_gate_script_is_actually_the_gate() -> None:
    """Liveness for the extractor. If it ever returns another step's script — or an empty one — the
    execution tests below would exercise the wrong thing and stay green while doing it.

    GRADED OVER EXECUTED SHELL, and the token list changed with it. This asked for ``tar tzf``, which
    the gate has not run since ``--ignore-zeros`` landed — the only occurrence left is the COMMENT
    explaining why plain ``tar tzf`` is unsafe. So the liveness check for the whole of section (7)
    was resting on narration: delete the listing and leave the prose, and it still passed. The
    module's own ``_executed_shell`` helper exists for exactly this and neither this check nor its
    sibling was calling it.
    """
    script = _executed_shell(_leak_gate_script())
    # `--ignore-zeros` and `-tzf` as INDEPENDENT tokens, never the concatenation: `tar -tzf
    # --ignore-zeros` is the same command and would red this whole section for a cosmetic edit, which
    # is the trap `_LEAK_GATE_STEP_PREFIX`'s own comment warns about one screen down.
    for token in ("dist/*.tar.gz", "--ignore-zeros", "-tzf", "grep -vE"):
        assert token in script, (
            f"the step extracted as the leak gate does not contain {token!r}; the extractor is picking "
            f"up the wrong step, so section (7) would be testing something else entirely"
        )


def test_the_leak_gate_passes_a_package_only_sdist(
    leak_gate: tuple[str, Path, dict[str, str]], tmp_path: Path
) -> None:
    """POSITIVE CONTROL, and it is what makes every rejection test below mean anything.

    Those all assert a NON-ZERO exit. A harness that cannot run the script at all — no bash, no ``tar``,
    a CRLF script, the wrong working directory — exits non-zero on all of them, and they all pass while
    measuring nothing. That is the same false green the gate itself was shipping, rebuilt one layer up.
    This is the only test in the section that can fail in that direction, so the others are evidence
    only while it holds.
    """
    bash, script, env = leak_gate
    work = tmp_path / "clean"
    _write_sdist(work / "dist" / f"{_SDIST_PREFIX}.tar.gz", _CLEAN_MEMBERS)

    rc, out = _run_leak_gate(bash, work, script, env)
    assert rc == 0, (
        f"the leak gate REJECTED a package-only sdist, so every rejection test below is measuring a "
        f"broken harness rather than the gate.\n  {explain_returncode(rc, 'the leak gate step')}\n{out}"
    )
    # A pass must name what it inspected. "it exited 0" is exactly what the old body did while
    # inspecting nothing, so the count is the part that makes a green readable as evidence.
    assert f"inspected {len(_CLEAN_MEMBERS)} members" in out, (
        f"the leak gate passed without reporting how many members it inspected — a green that cannot "
        f"say what it looked at is the original defect's own signature.\n{out}"
    )


def _fixture_private_doc_in_the_sdist(dist: Path) -> None:
    _write_sdist(dist / f"{_SDIST_PREFIX}.tar.gz", [*_CLEAN_MEMBERS, PRIVATE_CANARY])


def _fixture_corrupt_sdist(dist: Path) -> None:
    tarball = dist / f"{_SDIST_PREFIX}.tar.gz"
    _write_sdist(tarball, _CLEAN_MEMBERS)
    whole = tarball.read_bytes()
    tarball.write_bytes(whole[: len(whole) // 2])  # truncated mid-stream: gzip cannot finish it


def _fixture_two_sdists_one_leaking(dist: Path) -> None:
    _write_sdist(dist / f"{_SDIST_PREFIX}.tar.gz", _CLEAN_MEMBERS)
    _write_sdist(dist / f"{_SDIST_PREFIX}rc1.tar.gz", [*_CLEAN_MEMBERS, PRIVATE_CANARY])


def _fixture_empty_dist(dist: Path) -> None:
    dist.mkdir(parents=True, exist_ok=True)


def _fixture_sdist_listing_zero_members(dist: Path) -> None:
    _write_sdist(dist / f"{_SDIST_PREFIX}.tar.gz", [])


def _fixture_someone_elses_sdist(dist: Path) -> None:
    dist.mkdir(parents=True, exist_ok=True)
    with tarfile.open(dist / "otherproject-1.0.tar.gz", "w:gz") as tf:
        for member in ("otherproject-1.0/PKG-INFO", "otherproject-1.0/README.md"):
            payload = b"fixture\n"
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))


def _tar_bytes(members: Sequence[str]) -> bytes:
    """An UNCOMPRESSED tar of ``members`` under the sdist prefix, for callers that truncate or concatenate.

    Same prefixing as :func:`_write_sdist` -- these fixtures differ in how the STREAM is assembled, not
    in what a member is called, and a fixture that roots its members differently would be rejected by
    the gate's identity check before reaching the behaviour under test.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        for member in members:
            payload = b"fixture\n"
            info = tarfile.TarInfo(f"{_SDIST_PREFIX}/{member}")
            info.size = len(payload)
            tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def _fixture_prefix_laundered_private_doc(dist: Path) -> None:
    """A private doc that laundered itself through the OLD per-line prefix strip.

    `docs/messagefoundry/security/PRIVATE.md` under the real root became
    `messagefoundry/security/PRIVATE.md` once each line had its own first component removed, and the
    allowlist trusts anything starting `messagefoundry/`.
    """
    _write_sdist(
        dist / f"{_SDIST_PREFIX}.tar.gz",
        [*_CLEAN_MEMBERS, "docs/messagefoundry/security/PRIVATE.md"],
    )


def _fixture_concatenated_gzip_streams(dist: Path) -> None:
    """A clean sdist with a SECOND gzip stream appended, carrying a private doc.

    Plain `tar tzf` stops at the first end-of-archive marker and exits 0, so the second stream's
    members never reach the allowlist while their bytes ship inside the published file.
    """
    dist.mkdir(parents=True, exist_ok=True)
    clean = gzip.compress(_tar_bytes(list(_CLEAN_MEMBERS)))
    hidden = gzip.compress(_tar_bytes(["docs/security/PRIVATE.md"]))
    (dist / f"{_SDIST_PREFIX}.tar.gz").write_bytes(clean + hidden)


def _fixture_truncated_archive(dist: Path) -> None:
    """A tar cut in half and THEN gzipped: a valid gzip of a short tar.

    Measured against the real gate before the fix: `tar` listed a partial member set, exited 0, and
    warned about nothing. The cut is a whole multiple of 512, so block alignment does not reveal it.
    """
    dist.mkdir(parents=True, exist_ok=True)
    raw = _tar_bytes([*_CLEAN_MEMBERS, *(f"messagefoundry/m{i}.py" for i in range(40))])
    (dist / f"{_SDIST_PREFIX}.tar.gz").write_bytes(gzip.compress(raw[: len(raw) // 2]))


#: Each case pairs a dist/ builder with fragments ONLY THAT CASE can produce. Asserting merely "it
#: failed" would let all six fail for one shared wrong reason and still report six passes — and three of
#: the six (corrupt, two tarballs, zero members) are the exact inputs the previous gate body passed, so
#: a revert has to come back red HERE, on the message, not only on a status.
_REJECTIONS: list[tuple[Callable[[Path], None], list[str]]] = [
    # The leak class itself: 0.1.0..0.2.15 shipped docs/security/* to public PyPI.
    (
        _fixture_private_doc_in_the_sdist,
        ["::error::sdist contains non-package files", PRIVATE_CANARY],
    ),
    # `tar` fails; the old body read its empty output as "no members outside the allowlist".
    (_fixture_corrupt_sdist, ["could not list", "nothing was inspected"]),
    # Two matches made `sd` multiline, so the tar argument was malformed and nothing was listed. The
    # count is asserted because it is the only thing separating this message from the empty-dist one.
    (_fixture_two_sdists_one_leaking, ["needs exactly one sdist", "found 2"]),
    # Zero matches: the same precondition, the other direction.
    (_fixture_empty_dist, ["needs exactly one sdist", "found 0"]),
    # A listing that succeeds and yields nothing is not a clean sdist, it is no evidence at all.
    (_fixture_sdist_listing_zero_members, ["ZERO members", "nothing was inspected"]),
    # An allowlist check over another project's tarball passes trivially and says nothing about the
    # artifact this job is about to publish. The gate rejects on the archive's single ROOT, not on
    # "some member mentions messagefoundry" -- an adversarial pass defeated the latter with a tarball
    # whose members were `evilpkg-9.9/messagefoundry/...`, which satisfied a second-component test.
    (_fixture_someone_elses_sdist, ["found root 'otherproject-1.0'", "not messagefoundry-"]),
    # The same root check closes prefix laundering: `docs/messagefoundry/security/PRIVATE.md` inside
    # an sdist rooted at messagefoundry-<version>/ used to strip to `messagefoundry/security/...` and
    # be trusted, because the strip ran per line instead of removing one known prefix.
    (
        _fixture_prefix_laundered_private_doc,
        ["private-doc leak guard tripped", "docs/messagefoundry/security/PRIVATE.md"],
    ),
    # `tar tzf` stops at the first end-of-archive marker and exits 0, so a second gzip stream appended
    # to a clean sdist hid a private doc from the listing while shipping its bytes. --ignore-zeros.
    (
        _fixture_concatenated_gzip_streams,
        ["private-doc leak guard tripped", "docs/security/PRIVATE.md"],
    ),
    # A tar truncated and THEN gzipped is a valid gzip of a short tar: tar lists a partial member set
    # and exits 0 with no warning. Publishing it burns the version number on PyPI forever.
    (_fixture_truncated_archive, ["does not end in a tar end-of-archive marker"]),
]


@pytest.mark.parametrize(
    ("build_dist", "must_say"),
    _REJECTIONS,
    ids=[case[0].__name__.removeprefix("_fixture_") for case in _REJECTIONS],
)
def test_the_leak_gate_rejects(
    build_dist: Callable[[Path], None],
    must_say: list[str],
    leak_gate: tuple[str, Path, dict[str, str]],
    tmp_path: Path,
) -> None:
    """Each input must fail the release AND say which check caught it.

    The message is asserted, not just the status, because these six inputs are the ones a blind gate
    gets wrong in the SAME direction. Run them against the pre-fix body: three exit 0 printing
    "package-only", one dies on a bare ``ls`` with no annotation at all, and one trips only by luck
    because its own members happened to sit outside the allowlist. Pinning the fragment is what makes
    each case testify about its own precondition instead of about an exit status alone.
    """
    bash, script, env = leak_gate
    work = tmp_path / "case"
    build_dist(work / "dist")

    rc, out = _run_leak_gate(bash, work, script, env)
    assert rc != 0, (
        f"the leak gate PASSED an sdist it must reject — this is the false green that let private docs "
        f"reach public PyPI on 0.1.0..0.2.15.\n{out}"
    )
    missing = [fragment for fragment in must_say if fragment not in out]
    assert not missing, (
        f"the leak gate failed (rc={rc}) but not for the reason under test — missing {missing} from its "
        f"output. A rejection that cannot name its own cause is indistinguishable from a rejection for "
        f"an unrelated harness fault.\n  {explain_returncode(rc, 'the leak gate step')}\n{out}"
    )


# --- (8) the SEPARATELY-BUILT wheel smokes install the artifact and INSPECT it (BACKLOG #1701) -------
#
# SCOPE, STATED ONCE AND NOT RESTATED IN EVERY TEST NAME BELOW: this section covers the jobs that build
# a wheel of their OWN distribution -- release-webconsole and release-harness. It does NOT cover the
# ENGINE job's smoke. That exclusion is real, it is asserted explicitly by
# `test_the_engine_smoke_is_the_gap_these_guards_do_not_close`, and BACKLOG #1583 is the row that closes
# it. #1583 is PARTLY landed: PR 1297 gave the engine smoke its `-I`, and section (9) below now pins
# that half. What is still open is the install -- the engine smoke resolves the engine's whole
# dependency tree FROM PYPI inside a job holding `id-token: write`. So do not read a green here as
# "every release smoke installs with --no-deps"; the engine's does not.

#: The heredoc tag carrying each smoke step's inspection script. Named, not sliced by line number, so
#: an edit above it cannot silently change what the execution tests below run.
_SMOKE_HEREDOC = re.compile(r"<<'PYSMOKE'\n(.*?)\nPYSMOKE\n", re.S)

#: The version the synthesized installs below are built at. Arbitrary, but deliberately NOT the version
#: in the tree: a fixture that happens to match the real one cannot show the check read the fixture.
_SMOKE_VERSION = "7.7.7"

#: The toolkit distribution (ADR 0201), built and smoked inside the engine's `release` job.
_TOOLKIT_DIST = "messagefoundry-toolkit"


@functools.cache
def _wheel_smoke_steps() -> dict[str, dict]:
    """Every separately-built wheel's smoke step, keyed by the DISTRIBUTION its script installs.

    KEYED BY DISTRIBUTION, NOT JOB, SINCE ADR 0201. The toolkit wheel is built and smoked inside the
    engine's `release` job, so one job now holds two smoke steps: the engine's (no PYSMOKE script,
    the stated gap below) and the toolkit's. A job-keyed map could not hold both. A job that builds
    N wheels with ``python -m build --wheel`` must carry exactly N PYSMOKE smoke steps.

    DERIVED from ``python -m build --wheel``, never a list of job names, for the same reason
    :func:`test_both_wheel_smokes_compare_versions_not_strings` counts instead of pinning a number:
    that test read ``== 2`` and broke the day the console job arrived. A fourth distribution is
    covered here the day it lands, not the day somebody remembers this file.

    The engine job builds with a bare ``python -m build`` (sdist AND wheel) and so is not selected.
    That is the section's stated gap, not an accident of the predicate -- see the module note above.

    Cached: three ``@pytest.mark.parametrize`` decorators call this at COLLECTION time and every
    execution test calls it again, and it is a pure function of one file. Callers only read the
    returned mapping. Uncached, one run of this module parsed the 911-line workflow 33 times.

    Because those decorators call it at collection, the assertions below surface as a COLLECTION
    ERROR for the whole module rather than as one named test failure. That is deliberate: if the
    workflow's job shape has moved far enough that this cannot find the wheel jobs, every other test
    in the module is asking about a file it no longer understands. The message says which.
    """
    found: dict[str, dict] = {}
    for name, job in _jobs().items():
        steps = [s for s in (job.get("steps") or []) if isinstance(s, dict)]
        builds = sum(str(s.get("run") or "").count("python -m build --wheel") for s in steps)
        if not builds:
            continue
        smoke = [
            s
            for s in steps
            if str(s.get("name") or "").startswith("Smoke-check")
            and "<<'PYSMOKE'" in str(s.get("run") or "")
        ]
        assert len(smoke) == builds, (
            f"job {name!r} builds {builds} wheel(s) but has {len(smoke)} 'Smoke-check...' step(s) "
            f"with a PYSMOKE inspection -- a wheel with no smoke publishes an artifact nothing read"
        )
        for step in smoke:
            m = _SMOKE_HEREDOC.search(str(step.get("run") or ""))
            assert m, f"step {step.get('name')!r} has no PYSMOKE heredoc"
            dist, _pkg = _smoke_names(m.group(1))
            assert dist not in found, f"two smoke steps install {dist!r}"
            found[dist] = step
    # A floor, so an empty match can never pass vacuously: the console, the harness and the toolkit.
    assert len(found) >= 3, (
        f"expected the console, harness and toolkit smokes, found {sorted(found)}"
    )
    return found


def _smoke_script(job: str) -> str:
    """The inspection script ``job``'s smoke step feeds to its throwaway venv's interpreter."""
    step = _wheel_smoke_steps()[job]
    m = _SMOKE_HEREDOC.search(str(step.get("run") or ""))
    assert m, (
        f"step {step.get('name')!r} has no PYSMOKE heredoc — a smoke that runs no script against the "
        f"installed wheel is back to reading the filename"
    )
    return m.group(1)


def _smoke_names(script: str) -> tuple[str, str]:
    """``(distribution, import package)`` read out of the script ITSELF, so the fixtures are built
    for whatever the workflow actually installs rather than for a second copy kept here."""
    dist = re.search(r'^DIST = "([^"]+)"', script, re.M)
    pkg = re.search(r'^PKG = "([^"]+)"', script, re.M)
    assert dist and pkg, (
        "each smoke script must name its DIST and PKG so this harness can build one"
    )
    return dist.group(1), pkg.group(1)


def test_the_extracted_smoke_scripts_are_actually_the_smokes() -> None:
    """Liveness for the extractor, exactly as section (7) has for the leak gate. If it ever returns
    the wrong block — or an unparseable one — every execution test below would exercise something
    else entirely and stay green while doing it."""
    for job in _wheel_smoke_steps():
        script = _smoke_script(job)
        compile(script, f"<{job} smoke>", "exec")  # it must at least be Python
        _smoke_names(script)  # and it must name what it installs
        for token in ("sys.prefix", "distribution(DIST)", "dist.version"):
            assert token in script, (
                f"{job}'s smoke script does not contain {token!r}; the extractor is picking up the "
                f"wrong block, so the execution tests below would be testing something else"
            )


def test_the_engine_smoke_is_the_gap_these_guards_do_not_close() -> None:
    """The exclusion, made a MEASUREMENT instead of a footnote (BACKLOG #1583).

    The `release` job also builds a wheel and also has a step named `Smoke-check the built wheel`, and
    everything in this section passes over it. Its smoke installs WITH dependencies -- resolving the
    engine's whole tree from PyPI inside a job holding `id-token: write`.

    THE ISOLATION HALF IS NO LONGER PART OF THIS GAP, and saying so is the whole reason this docstring
    was rewritten. #1583 landed in two pieces: PR 1297 added `-I` to the engine smoke's import probe,
    so the checkout no longer answers the version question there. Section (9) below is what guards
    that half now, statically and behaviourally, which is why this test must NOT also assert `-I` is
    absent -- two tests in one file would then require opposite things of the same line, and the file
    could never be green. What remains open is the install, and that is what this test still pins.

    The dependency half is #1583's, deliberately untouched here. This test exists so the boundary is
    visible from inside the file rather than only from a pull request description, and so a FOURTH job
    cannot slip into the same gap unnoticed: it pins the excluded set to exactly one job, by name.

    When the rest of #1583 lands, this test is what tells you to fold the engine job into
    `_wheel_smoke_steps`.
    """
    # By STEP, not by job, since ADR 0201 put the toolkit's covered smoke in the same `release` job
    # as the engine's uncovered one.
    covered = {id(step) for step in _wheel_smoke_steps().values()}
    uncovered = sorted(
        (name, str(step.get("name")))
        for name, job in _jobs().items()
        for step in (job.get("steps") or [])
        if isinstance(step, dict)
        and str(step.get("name") or "").startswith("Smoke-check")
        and id(step) not in covered
    )
    assert [job for job, _step in uncovered] == ["release"], (
        f"the release smokes these guards do NOT cover are {uncovered}, expected exactly one, in "
        f"['release']. A new smoke step is escaping section (8) -- either bring it into "
        f"_wheel_smoke_steps (it should build with `python -m build --wheel`) or record why not."
    )
    assert uncovered[0][1].startswith(_WHEEL_SMOKE_STEP_PREFIX), uncovered

    engine = _executed_shell(
        str(
            next(
                s for s in _jobs()["release"]["steps"] if "Smoke-check" in str(s.get("name") or "")
            )["run"]
        )
    )
    assert "--no-deps" not in engine, (
        "the engine smoke has gained --no-deps, so the rest of BACKLOG #1583 is fixed -- fold the "
        "engine job into _wheel_smoke_steps() and delete this test rather than leaving the stronger "
        "guards pointed away from it. Isolated mode is deliberately NOT asserted here: PR 1297 "
        "already landed `-I` on this step and section (9) pins it, so a check for its absence would "
        "contradict a sibling test in this same file"
    )


def test_each_wheel_smoke_installs_the_built_wheel_into_a_throwaway_venv() -> None:
    """The defect BACKLOG #1701 names: both steps parsed the wheel FILENAME and never opened the file.

    A filename proves the artifact is NAMED right. It says nothing about whether the force-include
    that pulls each package tree in from two directories up produced anything, and a wheel carrying
    no package tree is named exactly like a good one.

    The venv must be a throwaway rather than the job's own interpreter (ADR 0034): both jobs hold
    ``contents: write`` + ``id-token: write``, and the steps after the smoke attach the wheel to a
    GitHub release and publish it to PyPI.
    """
    for job, step in _wheel_smoke_steps().items():
        shell = _executed_shell(str(step["run"]))
        assert "python -m venv /tmp/" in shell, (
            f"{job}'s smoke does not create a throwaway venv — an install here lands in the "
            f"interpreter that then publishes the artifact"
        )
        assert re.search(r"/tmp/\S+/bin/pip install --quiet --no-deps \S+\.whl", shell), (
            f"{job}'s smoke does not install its own built wheel into that venv with --no-deps. "
            f"--no-deps is load-bearing, not an optimisation: both distributions depend on the "
            f"engine, so a full install resolves it FROM PYPI inside a job holding id-token: write"
        )


def test_each_wheel_smoke_inspects_the_wheel_in_isolated_mode() -> None:
    """``-I`` is the half most easily lost, and the only one no execution test below can pin.

    Both steps run from the repo root, which carries a source copy of each package, so without
    isolated mode the CHECKOUT answers every question and the wheel is never touched. (``-P`` or
    ``PYTHONSAFEPATH`` would serve; ``-E`` alone is a silent no-op.) The checkout-shadow test below
    deliberately runs WITHOUT ``-I`` -- it drives the script's own in-venv assertion -- so nothing
    else in this file would notice the flag going missing from the workflow.

    The filename read is pinned here too, because it names the defect and gives a targeted message.
    (`test_a_wheel_smoke_accepts_a_correctly_built_wheel` would also catch its return: that fixture
    puts no wheel file on disk at all, so a `glob.glob(...)[0]` raises IndexError.)
    """
    for job, step in _wheel_smoke_steps().items():
        shell = _executed_shell(str(step["run"]))
        assert "glob.glob(" not in shell, (
            f"{job}'s smoke is reading the wheel FILENAME again (BACKLOG #1701) — that proves the "
            f"artifact is named right and nothing else"
        )
        # PINNED TO THE PYSMOKE INVOCATION, not to `-I` appearing anywhere in the step. Each step
        # runs TWO isolated interpreters (the inspection, then the PEP 440 compare), so a bare
        # `/bin/python -I` search stayed GREEN when -I was deleted from the inspection: the compare's
        # own copy satisfied it. Measured by mutation before this was narrowed.
        assert re.search(r"/bin/python -I - <<'PYSMOKE'", shell), (
            f"{job}'s smoke runs its INSPECTION without -I, so the repo checkout is on sys.path and "
            f"would shadow the wheel it is meant to inspect"
        )


# --- the smokes EXECUTED against synthesized installs (not read - RUN) ------------------------------


def _write_install(
    purelib: Path,
    dist: str,
    pkg: str,
    version: str,
    *,
    package_files: dict[str, str] | None,
    recorded_files: dict[str, str] | None = None,
    requires: list[str] | None = None,
    provides_extra: list[str] | None = None,
) -> None:
    """Materialise an installed distribution in ``purelib``, the way a wheel install leaves one.

    ``package_files`` maps a path under ``<pkg>/`` to its text; ``None`` ships no package tree at all.
    ``recorded_files`` is written to disk as well and becomes the ONLY package content RECORD claims,
    so an install whose recorded set and whose importable module disagree can be driven at all.
    ``requires`` overrides ``Requires-Dist``; the default is the lockstep pin the harness smoke
    checks (the console's script ignores it, so one default serves both). ``provides_extra`` writes
    the ``Provides-Extra`` lines a wheel carries when its pyproject declares
    ``[project.optional-dependencies]``, and it is LOAD-BEARING rather than decoration: the harness
    smoke decides that a requirement is an extra's, and not the base install's, by asking whether an
    extra the wheel DECLARES turns that requirement's marker true. A fixture that writes the marker
    and omits the declaration describes a wheel no build backend produces, and would exercise the
    wrong branch.

    ``recorded_files`` MUST be written to disk, and that is a measured constraint rather than tidiness:
    ``importlib.metadata.Distribution.files`` SILENTLY DROPS every RECORD row whose file is missing
    (CPython filters the listing through an existence check). A fixture that records a path it never
    creates is therefore indistinguishable from one that records nothing, and the "RECORD names
    someone else's file" case collapsed into the "RECORD names nothing" case until this was found.
    """
    written: list[str] = []
    if package_files is not None:
        for rel, text in package_files.items():
            target = purelib / pkg / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
            written.append(f"{pkg}/{rel}")
    if recorded_files is not None:
        for rel, text in recorded_files.items():
            target = purelib / pkg / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        written = [f"{pkg}/{rel}" for rel in recorded_files]
    # PEP 427 escapes every run of separators to a single underscore; `dist.replace("-", "_")` is
    # right only for the names in play today and wrong for one carrying a dot.
    info = purelib / f"{re.sub(r'[-_.]+', '_', dist)}-{version}.dist-info"
    info.mkdir(parents=True, exist_ok=True)
    # The default is each LOCKSTEP distribution's own correct pin: the toolkit's names no extra (ADR
    # 0201), the harness's names [harness]. The console's script reads neither.
    default = (
        f"messagefoundry=={version}"
        if dist == _TOOLKIT_DIST
        else f"messagefoundry[harness]=={version}"
    )
    declared = [default] if requires is None else requires
    info.joinpath("METADATA").write_text(
        "".join(
            [
                "Metadata-Version: 2.1\n",
                f"Name: {dist}\n",
                f"Version: {version}\n",
                # Before Requires-Dist, which is the order hatchling writes them in.
                *(f"Provides-Extra: {extra}\n" for extra in provides_extra or []),
                *(f"Requires-Dist: {req}\n" for req in declared),
            ]
        ),
        encoding="utf-8",
    )
    rows = [*written, f"{info.name}/METADATA", f"{info.name}/RECORD"]
    info.joinpath("RECORD").write_text("".join(f"{row},,\n" for row in rows), encoding="utf-8")


def _good_package(pkg: str, version: str) -> dict[str, str]:
    """A package tree both smokes accept: a real ``__init__.py`` carrying ``__version__`` (what the
    console reads back) and a real ``__main__.py`` exposing ``main`` (what the harness imports)."""
    return {
        "__init__.py": f'__version__ = "{version}"\n',
        "__main__.py": "def main(argv=None):\n    return 0\n",
    }


@pytest.fixture(scope="session")
def venv_template(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One ``--without-pip`` venv, built once and COPIED per case.

    Measured on this box: creating a venv is 0.207s and copying one is 0.011s, and this section needs
    a dozen and a half. Copy-per-case rather than a shared venv, deliberately: every rejection here
    asserts a NON-ZERO exit, so a package tree left behind by an earlier case would defeat the next
    one and the leak would show up as a pass. Each case gets its own physical site-packages.

    ``packaging`` is planted in it because the real step installs it there first, from the
    constraints.lock pin, and the harness script reads ``Requires-Dist`` through
    ``packaging.requirements``. Copied rather than pip-installed: this fixture must not touch an
    index, and the venv is deliberately ``--without-pip``.
    """
    root = tmp_path_factory.mktemp("venv-template") / "venv"
    subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [sys.executable, "-m", "venv", "--without-pip", str(root)],
        check=True,
        capture_output=True,
        timeout=300,
    )
    import packaging

    purelib = Path(
        sysconfig.get_path(
            "purelib", vars={"base": str(root), "platbase": str(root), "installed_base": str(root)}
        )
    )
    shutil.copytree(Path(packaging.__file__).parent, purelib / "packaging")
    # Loud, not silent: without this the harness script dies on ImportError and every rejection test
    # would pass for that reason instead of the one under test.
    assert (purelib / "packaging" / "requirements.py").is_file(), (
        f"packaging was not planted in the smoke venv template at {purelib}"
    )
    return root


def _clone_venv(template: Path, root: Path) -> tuple[Path, Path]:
    """A private copy of ``template`` at ``root``; returns ``(interpreter, purelib)``.

    ``purelib`` is derived IN PROCESS rather than by asking the copied interpreter: the template was
    built by ``sys.executable``, so this interpreter's own scheme is the copy's scheme, and the
    positive control is what proves the path is right (it writes the fixture there and the script has
    to find it). That saves a subprocess launch per case.
    """
    shutil.copytree(template, root)
    exe = next(
        (p for p in (root / "Scripts" / "python.exe", root / "bin" / "python") if p.exists()), None
    )
    assert exe is not None, f"the venv copy at {root} has no interpreter"
    purelib = sysconfig.get_path(
        "purelib", vars={"base": str(root), "platbase": str(root), "installed_base": str(root)}
    )
    return exe, Path(purelib)


def _run_smoke(
    exe: Path, script: str, workdir: Path, *, isolated: bool = True
) -> tuple[int, str, str]:
    """Run ``script`` the way the step does; return (rc, stdout, combined output).

    STDOUT IS RETURNED SEPARATELY BECAUSE THE STEP READS IT SEPARATELY: the shell captures it as
    ``built=$(...)`` and everything else the script says goes to stderr, so a diagnostic that leaked
    onto stdout would silently become the version the release compares against the tag.

    ``-I`` matches the workflow. The one caller that drops it is the checkout-shadow control, which
    exists to prove the in-venv assertion fires rather than that the flag is spelled right.
    """
    argv = [str(exe), *(["-I"] if isolated else []), "-"]
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        argv,
        input=script.encode("utf-8"),
        cwd=str(workdir),
        capture_output=True,
        timeout=120,
    )
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        (proc.stdout + proc.stderr).decode("utf-8", "replace"),
    )


def _prepared(job: str, template: Path, tmp_path: Path) -> tuple[str, str, str, Path, Path]:
    """``(script, dist, pkg, interpreter, purelib)`` — the prelude every execution test below shares."""
    script = _smoke_script(job)
    dist, pkg = _smoke_names(script)
    exe, purelib = _clone_venv(template, tmp_path / "venv")
    return script, dist, pkg, exe, purelib


@pytest.mark.parametrize("job", sorted(_wheel_smoke_steps()))
def test_a_wheel_smoke_accepts_a_correctly_built_wheel(
    job: str, venv_template: Path, tmp_path: Path
) -> None:
    """POSITIVE CONTROL, and it is what makes every rejection below mean anything.

    Those all assert a NON-ZERO exit. A harness that cannot run the script at all — a venv that did
    not copy, a fixture written to the wrong directory — exits non-zero on every one of them, and
    they all pass while measuring nothing. This is the only case here that can fail in the other
    direction, so the rejections are evidence only while it holds.
    """
    script, dist, pkg, exe, purelib = _prepared(job, venv_template, tmp_path)
    _write_install(
        purelib, dist, pkg, _SMOKE_VERSION, package_files=_good_package(pkg, _SMOKE_VERSION)
    )

    rc, stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc == 0, (
        f"{job}'s smoke REJECTED a well-formed install, so every rejection below is measuring a "
        f"broken harness rather than the smoke.\n{out}"
    )
    # EXACTLY the version, and nothing else: the step captures stdout as `built` and compares it
    # against the tag, so a diagnostic line printed here would become part of the version.
    assert stdout.strip() == _SMOKE_VERSION, (
        f"{job}'s smoke must print the INSTALLED distribution's version on stdout, alone.\n{out}"
    )
    # And it must have looked at something. A green that cannot say what it inspected is the
    # original defect's own signature (section 7 carries the same rule for the leak gate).
    assert f"{pkg}/ members" in out, (
        f"{job}'s smoke passed without reporting how much of the package tree it found.\n{out}"
    )


def _no_package_tree(purelib: Path, dist: str, pkg: str) -> None:
    """The force-include produced nothing. Installs cleanly, named exactly like a good wheel."""
    _write_install(purelib, dist, pkg, _SMOKE_VERSION, package_files=None)


def _namespace_directory_with_no_module(purelib: Path, dist: str, pkg: str) -> None:
    """The shape the row's own prescription would have missed.

    ``harness/`` is a PEP 420 NAMESPACE package, so a bare ``import harness`` SUCCEEDS against a
    directory holding no modules and its ``__file__`` is None. Both smokes therefore reach for
    something with a real origin instead of importing the package root.
    """
    _write_install(
        purelib, dist, pkg, _SMOKE_VERSION, package_files={"README.txt": "not a module\n"}
    )


def _record_lists_no_package_members(purelib: Path, dist: str, pkg: str) -> None:
    """Files on disk, none of them recorded: the installed distribution cannot say what it shipped."""
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        recorded_files={},
    )


def _record_does_not_list_the_module_it_resolved(purelib: Path, dist: str, pkg: str) -> None:
    """RECORD is non-empty but names OTHER files: the import name is occupied by something else.

    This is the shape that makes the RECORD guard more than a restatement of the import check. The
    module resolves, it sits inside the venv, and the distribution under test never shipped it -- the
    real-world version being a second distribution that owns the same import name.
    """
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        recorded_files={"somethingelse.py": "# shipped by a different distribution\n"},
    )


#: Each shape pairs an install builder with a fragment that shape produces. NOTE the first two
#: SHARE a message, by measurement rather than by oversight: both scripts route "no tree at all" and
#: "a namespace directory with no module" to the same guard, and neither distinguishes them. The
#: second shape is kept anyway because it is a DIFFERENT INPUT -- the one a bare `import harness`
#: would have passed -- not because its message discriminates. Everything else here does.
_SMOKE_REJECTIONS: list[tuple[Callable[[Path, str, str], None], str]] = [
    (_no_package_tree, "no package tree"),
    (_namespace_directory_with_no_module, "no package tree"),
    (_record_lists_no_package_members, "RECORD lists no"),
    (_record_does_not_list_the_module_it_resolved, "belongs to something else on sys.path"),
]


@pytest.mark.parametrize("job", sorted(_wheel_smoke_steps()))
@pytest.mark.parametrize(
    ("build_install", "must_say"),
    _SMOKE_REJECTIONS,
    ids=[case[0].__name__.lstrip("_") for case in _SMOKE_REJECTIONS],
)
def test_a_wheel_smoke_rejects(
    job: str,
    build_install: Callable[[Path, str, str], None],
    must_say: str,
    venv_template: Path,
    tmp_path: Path,
) -> None:
    """Every one of these installs cleanly, is named correctly, and must fail the release.

    Run them against the pre-#1701 step and all four pass: it read the version out of the FILENAME,
    so nothing it did could depend on the wheel's contents at all.
    """
    script, dist, pkg, exe, purelib = _prepared(job, venv_template, tmp_path)
    build_install(purelib, dist, pkg)

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, (
        f"{job}'s smoke PASSED a {build_install.__name__.lstrip('_')} wheel — the release would ship "
        f"it.\n{out}"
    )
    assert must_say in out, (
        f"{job}'s smoke failed but not for the reason under test (missing {must_say!r}). A rejection "
        f"that cannot name its own cause is indistinguishable from a rejection for an unrelated "
        f"harness fault.\n{out}"
    )


@pytest.mark.parametrize("job", sorted(_wheel_smoke_steps()))
def test_a_wheel_smoke_refuses_a_module_resolved_outside_the_smoke_venv(
    job: str, venv_template: Path, tmp_path: Path
) -> None:
    """The checkout-shadow guard, driven rather than read.

    Both steps run from the repo root, which carries a source copy of each package. Drop ``-I`` and
    the cwd goes on sys.path ahead of the venv, so the CHECKOUT answers every question and the wheel
    is never opened — a smoke that then passes is reporting on the tree it was built from. The venv
    here holds a perfectly good install; the shadow is the thing that must be caught.
    """
    script, dist, pkg, exe, purelib = _prepared(job, venv_template, tmp_path)
    _write_install(
        purelib, dist, pkg, _SMOKE_VERSION, package_files=_good_package(pkg, _SMOKE_VERSION)
    )
    shadow = tmp_path / "checkout"
    (shadow / pkg).mkdir(parents=True)
    for rel, text in _good_package(pkg, "9.9.9").items():
        (shadow / pkg / rel).write_text(text, encoding="utf-8")

    rc, _stdout, out = _run_smoke(exe, script, shadow, isolated=False)
    assert rc != 0, (
        f"{job}'s smoke accepted a module resolved from the CHECKOUT instead of the smoke venv — it "
        f"would report on the source tree and never open the wheel.\n{out}"
    )
    assert "OUTSIDE the smoke venv" in out, (
        f"{job}'s smoke failed on a shadowed import but not for that reason.\n{out}"
    )


def test_the_console_smoke_compares_its_version_root_against_the_wheel_metadata(
    venv_template: Path, tmp_path: Path
) -> None:
    """The console step's name promises "the console's OWN __version__", so it must read it.

    Job-specific by construction: the console is the one distribution whose version root ships inside
    its own wheel (``messagefoundry_webconsole/__init__.py``). The harness reads the ENGINE's
    ``__init__.py``, which the harness wheel does not contain, so there is nothing there to read back.
    """
    script, dist, pkg, exe, purelib = _prepared(
        "messagefoundry-webconsole", venv_template, tmp_path
    )
    _write_install(purelib, dist, pkg, _SMOKE_VERSION, package_files=_good_package(pkg, "9.9.9"))

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, (
        f"the console smoke accepted a wheel whose installed __version__ (9.9.9) disagrees with its "
        f"metadata ({_SMOKE_VERSION}) — the step's own promise goes unchecked.\n{out}"
    )
    assert "9.9.9" in out and _SMOKE_VERSION in out, (
        f"the console smoke rejected the mismatch without naming both versions.\n{out}"
    )


@pytest.mark.parametrize(
    ("requires", "why"),
    [
        (["messagefoundry[harness]==0.0.1"], "a pin at the wrong version"),
        (["messagefoundry[harness]>=" + _SMOKE_VERSION], "a range instead of a pin"),
        (["messagefoundry==" + _SMOKE_VERSION], "the [harness] extra dropped"),
        ([], "no requirement on the engine at all"),
        # BACKLOG #1585 (a): an exact pin wearing an environment marker. The first is TRUE wherever
        # this suite runs, so it proves a marker is refused even when it would install the engine
        # here; the second is the shape that passes on ubuntu and installs nothing on Windows.
        (
            ["messagefoundry[harness]==" + _SMOKE_VERSION + '; python_version >= "3"'],
            "an exact pin gated by a marker true on this runner",
        ),
        (
            ["messagefoundry[harness]==" + _SMOKE_VERSION + '; sys_platform == "linux"'],
            "an exact pin gated by a platform marker",
        ),
    ],
    ids=["wrong-version", "range", "no-extra", "absent", "marker-true-here", "platform-marker"],
)
def test_the_harness_smoke_checks_the_lockstep_pin_on_the_built_artifact(
    requires: list[str], why: str, venv_template: Path, tmp_path: Path
) -> None:
    """BACKLOG #1585's invariant, checked where it becomes irreversible.

    ``tests/test_packaging.py`` asserts the pin in the pyproject, and that runs in ci.yml. NOTHING in
    release.yml runs a test suite, and a tag can be cut from a commit the merge queue never gated --
    so the built wheel is the last place the claim is checkable before the PyPI upload burns the
    version forever. The harness smoke already holds the metadata open, so it asks.

    Job-specific: the console is deliberately NOT lockstep (its own version root, its own cadence),
    so its dependency on the engine is correctly unpinned and its script does not look.
    """
    script, dist, pkg, exe, purelib = _prepared("messagefoundry-harness", venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        requires=requires,
    )

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, (
        f"the harness smoke published a wheel with {why} — a lockstep distribution that does not name "
        f"the engine it ships with drags an arbitrary engine onto the operator's box.\n{out}"
    )
    assert "1585" in out, (
        f"the harness smoke rejected {why} without naming the row that explains it.\n{out}"
    )


# --- an extra's requirement is not the lockstep pin (BACKLOG #1585) ---------------------------------

#: What ``dev = ["messagefoundry[dev]"]`` becomes in wheel metadata. Not hypothetical: that exact
#: table is already in packaging/messagefoundry-webconsole/pyproject.toml, so the harness is one
#: copied stanza away from shipping a second ``messagefoundry`` line.
_EXTRA_GATED_ENGINE = 'messagefoundry[dev]; extra == "dev"'

#: A second engine requirement that NO extra gates, and whose marker is false everywhere this suite
#: can run (there is no Python 2 interpreter to run it on). It is the armed control for the filter
#: being NARROW: skipping it would mean the filter drops any requirement its environment happens to
#: exclude, and a drifted pin wearing a platform marker would then reach PyPI unchecked.
_MARKER_GATED_ENGINE = 'messagefoundry==0.0.1; python_version < "3.0"'


def test_the_harness_smoke_does_not_count_a_requirement_an_extra_gates(
    venv_template: Path, tmp_path: Path
) -> None:
    """A correct wheel that also declares an extra must PASS, and the failure it used to raise landed
    after the engine was on PyPI.

    ``[project.optional-dependencies]`` reaches ``Requires-Dist`` as ``<req>; extra == "<name>"``, a
    line a plain install never pulls in. The scan here counted those, insisted on exactly one, and so
    turned any such table into ``declares 2 requirements on the engine``.

    WHAT MAKES IT WORSE THAN AN ORDINARY RED, and why this test lives here rather than in
    ``tests/test_packaging.py``: that suite reads ``project.dependencies`` and an extra is not in it,
    so ci.yml stays GREEN. The step carries ``needs: release``, so the red arrives at TAG TIME with
    the engine already published and the version burnt. The defect is in the workflow's scan, so the
    only test that can catch it before the tag is one that RUNS that scan.
    """
    script, dist, pkg, exe, purelib = _prepared("messagefoundry-harness", venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        requires=["messagefoundry[harness]==" + _SMOKE_VERSION, _EXTRA_GATED_ENGINE],
        provides_extra=["dev"],
    )

    rc, stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc == 0, (
        f"the harness smoke rejected a correctly pinned wheel because it also declares an extra "
        f"naming the engine. The release would red AFTER the PyPI upload.\n{out}"
    )
    assert stdout.strip() == _SMOKE_VERSION, (
        f"the harness smoke must still print the installed version on stdout, alone.\n{out}"
    )


@pytest.mark.parametrize(
    ("requires", "why"),
    [
        (
            ["messagefoundry[harness]==0.0.1", _EXTRA_GATED_ENGINE],
            "a drifted pin standing beside an extra-gated requirement",
        ),
        (
            ["messagefoundry[harness]>=" + _SMOKE_VERSION, _EXTRA_GATED_ENGINE],
            "a range standing beside an extra-gated requirement",
        ),
        (
            [_EXTRA_GATED_ENGINE],
            "an extra-gated requirement AS the only mention of the engine",
        ),
        (
            ["messagefoundry[harness]==" + _SMOKE_VERSION, _MARKER_GATED_ENGINE],
            "a second engine requirement no extra gates",
        ),
    ],
    ids=["drift-beside-extra", "range-beside-extra", "extra-only", "second-not-an-extra"],
)
def test_the_extra_filter_did_not_disarm_the_lockstep_check(
    requires: list[str], why: str, venv_template: Path, tmp_path: Path
) -> None:
    """The half worth not losing: the filter must skip an EXTRA, and nothing else.

    The three arms above put the extra-gated line beside a pin that is wrong, missing, or the only
    thing there, so a filter that swallowed the real pin along with the extra would show up as a
    PASS. The fourth arm is the over-broad control: its marker is false in this interpreter too, but
    no declared extra turns it true, so it is still counted. Drop that distinction -- skip every
    requirement whose marker is false here -- and a drifted pin wearing ``; sys_platform == "win32"``
    sails past a step that only ever runs on ubuntu.

    Read beside ``test_the_harness_smoke_does_not_count_a_requirement_an_extra_gates``, which is the
    positive control: without it every arm here passes on a smoke that rejects everything.
    """
    script, dist, pkg, exe, purelib = _prepared("messagefoundry-harness", venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        requires=requires,
        provides_extra=["dev"],
    )

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, (
        f"the harness smoke PASSED {why} — the filter that lets an extra through is swallowing the "
        f"lockstep pin with it, and BACKLOG #1585's check is disarmed.\n{out}"
    )
    assert "1585" in out, (
        f"the harness smoke rejected {why} without naming the row that explains it.\n{out}"
    )


# --- the same release, spelled two ways (BACKLOG #1701, #1585) --------------------------------------

#: What a build backend writes into ``Version:``. ALWAYS canonical -- PEP 440 normalisation is the
#: backend's job, and `tests/test_version.py::test_installed_metadata_matches_dunder_version` records
#: the same fact for the engine ("a pre-release __version__ like 0.1.0-rc1 becomes 0.1.0rc1 in
#: metadata").
_PRERELEASE_METADATA = "0.3.0rc1"

#: What an AUTHOR may type, and both are supported here rather than tolerated. `tests/test_version.py
#: ::test_version_is_semver` admits the hyphen, and the release trigger only fires on
#: `v[0-9]+.[0-9]+.[0-9]+-*`, so a pre-release TAG cannot be spelled any other way.
#:
#: The canonical arm is the ARMED CONTROL, not padding: it exercises the identical fixture, install
#: and script, so a red on the hyphenated arm beside a green here is attributable to the SPELLING.
#: Both arms failing means the harness broke, which is the failure a bare one-arm test hides.
_PRERELEASE_SPELLINGS = (_PRERELEASE_METADATA, "0.3.0-rc1")
_PRERELEASE_IDS = ["canonical", "hyphenated"]


@pytest.mark.parametrize("spelling", _PRERELEASE_SPELLINGS, ids=_PRERELEASE_IDS)
def test_the_console_smoke_accepts_every_supported_prerelease_spelling(
    spelling: str, venv_template: Path, tmp_path: Path
) -> None:
    """The console's source literal and its metadata are NORMALISED DIFFERENTLY, by construction.

    ``dist.version`` comes out of ``Version:``, which the backend canonicalises;
    ``__version__`` is whatever was typed into ``messagefoundry_webconsole/__init__.py``. Comparing
    the two as raw strings therefore rejects a wheel that is perfectly well-formed, and it rejects
    it at the LAST gate before the PyPI upload burns the version.

    This is the defect the sibling tag-vs-built compare was already fixed for (see
    :func:`test_both_wheel_smokes_compare_versions_not_strings`): the same trap, one comparison over.
    """
    script, dist, pkg, exe, purelib = _prepared(
        "messagefoundry-webconsole", venv_template, tmp_path
    )
    _write_install(
        purelib,
        dist,
        pkg,
        _PRERELEASE_METADATA,
        package_files=_good_package(pkg, spelling),
    )

    rc, stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc == 0, (
        f"the console smoke REJECTED __version__ {spelling!r} against metadata "
        f"{_PRERELEASE_METADATA!r} -- the same release, and PEP 440 says so. A pre-release could "
        f"not be published while this holds.\n{out}"
    )
    # The shell captures stdout as `built=$(...)` and compares THAT against the tag, so a script that
    # accepted the install but printed the source spelling would move the failure rather than remove
    # it: the tag compare would then normalise a string this step never vouched for.
    assert stdout.strip() == _PRERELEASE_METADATA, (
        f"the console smoke printed {stdout.strip()!r}, not the metadata version "
        f"{_PRERELEASE_METADATA!r} the release compares against the tag.\n{out}"
    )


@pytest.mark.parametrize("spelling", _PRERELEASE_SPELLINGS, ids=_PRERELEASE_IDS)
def test_the_harness_smoke_accepts_every_supported_prerelease_pin_spelling(
    spelling: str, venv_template: Path, tmp_path: Path
) -> None:
    """``Requires-Dist`` keeps the spelling the pyproject was written in; ``Version:`` does not.

    Measured: ``str(Requirement("messagefoundry[harness]==0.3.0-rc1").specifier)`` is
    ``"==0.3.0-rc1"`` -- ``packaging`` preserves the raw version in a specifier, and
    ``str(Requirement(...))`` round-trips it, so a hyphen typed into
    ``packaging/messagefoundry-harness/pyproject.toml`` reaches the built metadata intact while
    ``Version:`` beside it has been canonicalised.

    So an ``f"=={dist.version}"`` string compare reds the lockstep check on exactly the releases
    that need it most, and the operator sees a "pin drifted" error naming two versions that are the
    same one.
    """
    script, dist, pkg, exe, purelib = _prepared("messagefoundry-harness", venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _PRERELEASE_METADATA,
        package_files=_good_package(pkg, _PRERELEASE_METADATA),
        requires=[f"messagefoundry[harness]=={spelling}"],
    )

    rc, stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc == 0, (
        f"the harness smoke called `messagefoundry[harness]=={spelling}` a drift from "
        f"{_PRERELEASE_METADATA} -- it is the same version, and the lockstep premise holds.\n{out}"
    )
    assert stdout.strip() == _PRERELEASE_METADATA, (
        f"the harness smoke printed {stdout.strip()!r}, not {_PRERELEASE_METADATA!r}.\n{out}"
    )


def test_the_console_smoke_still_rejects_a_different_prerelease(
    venv_template: Path, tmp_path: Path
) -> None:
    """The control for the two accepting tests above: normalising must not flatten rc1 into rc2.

    Those assert ``rc == 0`` on every arm, so a script that stopped comparing at all would satisfy
    them both. The existing mismatch case uses 9.9.9 against 7.7.7, which a broken check would also
    have to pass -- but it is nowhere near the pre-release territory this change moved, and a fix
    that over-normalised would land exactly there.
    """
    script, dist, pkg, exe, purelib = _prepared(
        "messagefoundry-webconsole", venv_template, tmp_path
    )
    _write_install(
        purelib,
        dist,
        pkg,
        _PRERELEASE_METADATA,
        package_files=_good_package(pkg, "0.3.0rc2"),
    )

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, (
        f"the console smoke accepted __version__ 0.3.0rc2 against metadata "
        f"{_PRERELEASE_METADATA} -- those are different releases, and PEP 440 orders them.\n{out}"
    )
    assert "0.3.0rc2" in out and _PRERELEASE_METADATA in out, (
        f"the console smoke rejected the mismatch without naming both versions.\n{out}"
    )


@pytest.mark.parametrize(
    ("requires", "why"),
    [
        (["messagefoundry[harness]==0.3.0rc2"], "a pin at a DIFFERENT pre-release"),
        (
            ["messagefoundry[harness]==0.3.0.*"],
            "a wildcard, which matches 0.3.0.post1 and is no pin",
        ),
        (["messagefoundry[harness]>=0.3.0-rc1"], "a range wearing the supported spelling"),
    ],
    ids=["other-prerelease", "wildcard", "range-hyphenated"],
)
def test_the_harness_smoke_still_rejects_a_pin_that_is_not_the_shipped_version(
    requires: list[str], why: str, venv_template: Path, tmp_path: Path
) -> None:
    """Normalising the PIN must not soften the operator or the version it is compared against.

    The wildcard arm is the one that needs saying. ``Version("0.3.0.*")`` RAISES, so a fix that
    simply wrapped both sides in ``Version()`` would report "unparseable version" and drop BACKLOG
    #1585 along with the instruction naming the file to edit -- telling the operator the wheel is
    corrupt when the pyproject is merely wrong. It must reject, and it must reject as a DRIFT.
    """
    script, dist, pkg, exe, purelib = _prepared("messagefoundry-harness", venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _PRERELEASE_METADATA,
        package_files=_good_package(pkg, _PRERELEASE_METADATA),
        requires=requires,
    )

    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, f"the harness smoke published a wheel with {why}.\n{out}"
    assert "1585" in out, (
        f"the harness smoke rejected {why} without naming the row that explains it -- the operator "
        f"is told the artifact is broken rather than which file to fix.\n{out}"
    )


# --- (9) the wheel smoke must import the WHEEL; a rejected sdist must not ship as an artifact -------

#: The engine's wheel-smoke step, located by name PREFIX for the same reason the leak gate is: the
#: full name carries an arrow glyph, and pinning punctuation would break this on a cosmetic edit.
_WHEEL_SMOKE_STEP_PREFIX = "Smoke-check the built wheel"

#: The step id the artifact upload's guard dereferences, and the exact exclusion it must carry.
_LEAK_GATE_ID = "leak-gate"
_LEAK_GATE_EXCLUSION = f"steps.{_LEAK_GATE_ID}.outcome != 'failure'"

#: ``if:`` expressions that let a step run after an EARLIER step in the same job failed. Anything
#: else ANDs with the implicit ``success()``, so a gate failure already skips it.
_SURVIVES_A_FAILED_STEP = ("always()", "!cancelled()", "failure()")

#: A version no build can produce, planted in a fake checkout so it can only have come from there.
_SHADOW_VERSION = "9999.0.0+checkoutshadow"


def _squeeze(expr: str) -> str:
    """``expr`` with all whitespace removed — GitHub expressions are whitespace-insensitive."""
    return re.sub(r"\s+", "", expr)


@pytest.mark.parametrize(
    ("requires", "why"),
    [
        (["messagefoundry==0.0.1"], "a pin at the wrong version"),
        (["messagefoundry>=" + _SMOKE_VERSION], "a range instead of a pin"),
        (["messagefoundry[harness]==" + _SMOKE_VERSION], "an extra added"),
        ([], "no requirement on the engine at all"),
        (
            ["messagefoundry==" + _SMOKE_VERSION, "hl7apy>=1.3"],
            "a second dependency beside the engine pin",
        ),
    ],
    ids=["wrong-version", "range", "extra", "absent", "second-dependency"],
)
def test_the_toolkit_smoke_checks_the_lockstep_pin_on_the_built_artifact(
    requires: list[str], why: str, venv_template: Path, tmp_path: Path
) -> None:
    """ADR 0201 AC-7 where it becomes irreversible. The toolkit uploads BEFORE the engine, so a wheel
    this smoke lets through is on PyPI before anything else can object."""
    script, dist, pkg, exe, purelib = _prepared(_TOOLKIT_DIST, venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files=_good_package(pkg, _SMOKE_VERSION),
        requires=requires,
    )
    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, f"the toolkit smoke published a wheel with {why}.\n{out}"
    assert "ADR 0201" in out, f"the toolkit smoke rejected {why} without naming the ADR.\n{out}"


def test_the_toolkit_smoke_refuses_a_wheel_without_its_console_script_target(
    venv_template: Path, tmp_path: Path
) -> None:
    """The console script names ``messagefoundry_toolkit.__main__:main``. The smoke cannot import it
    under --no-deps, because it imports the engine, so it checks RECORD shipped the file."""
    script, dist, pkg, exe, purelib = _prepared(_TOOLKIT_DIST, venv_template, tmp_path)
    _write_install(
        purelib,
        dist,
        pkg,
        _SMOKE_VERSION,
        package_files={"__init__.py": f'__version__ = "{_SMOKE_VERSION}"\n'},
    )
    rc, _stdout, out = _run_smoke(exe, script, tmp_path)
    assert rc != 0, f"the toolkit smoke passed a wheel with no __main__.py.\n{out}"
    assert "console script would fail" in out, out


def _release_steps() -> list[dict]:
    """The `release` job's steps, in order. Indexes returned below refer to this list."""
    return [s for s in _jobs()["release"]["steps"] if isinstance(s, dict)]


def _release_step_index(pred: Callable[[dict], bool], what: str) -> int:
    """Index of the one `release` step matching ``pred``.

    ONE locator for the toolkit tests below, for the reason ``_step_script_by_prefix`` gives: two
    copies of one lookup drift apart the first time either is fixed. A predicate over a step's shell
    reads it through ``_executed_shell`` (see ``_runs``), so a comment quoting a command cannot match.
    """
    hits = [i for i, s in enumerate(_release_steps()) if pred(s)]
    assert len(hits) == 1, f"expected one {what} step in `release`, found {hits}"
    return hits[0]


def _named(prefix: str) -> Callable[[dict], bool]:
    """A predicate for the step whose name (or ``uses:``) starts with ``prefix``."""
    return lambda s: str(s.get("name") or s.get("uses") or "").startswith(prefix)


def _runs(needle: str) -> Callable[[dict], bool]:
    """A predicate for the step whose EXECUTED shell contains ``needle``."""
    return lambda s: needle in _executed_shell(str(s.get("run") or ""))


def test_the_toolkit_uploads_before_the_engine_from_the_publish_job() -> None:
    """ADR 0201 section 1: the toolkit's first upload claims its name, and the engine names it.

    So the toolkit is built, gated and smoked in the `release` job before the reversible GitHub
    release and the hand-over; and in `publish-pypi` its upload is tag-gated like every publish
    (section 4b) and runs immediately before the engine's, so a failure in it skips the engine's.
    A separate job gated on a repository variable would reopen the window the order closes.
    """
    steps = _release_steps()
    names = [str(s.get("name") or s.get("uses") or "") for s in steps]

    def at(prefix: str) -> int:
        return _release_step_index(_named(prefix), f"step starting {prefix!r}")

    build = at("Build the toolkit wheel")
    gate = at("Member gate — the toolkit wheel")
    smoke = at("Smoke-check the toolkit wheel")
    github_release = at("Create or update the GitHub release")
    handover = at("Hand the PyPI files to the publish job")
    assert build < gate < smoke < github_release < handover, names
    assert "toolkit-dist/" in str(steps[handover]["with"]["path"]).split(), steps[handover]

    publish = _jobs()["publish-pypi"]
    pnames = [str(s.get("name") or s.get("uses") or "") for s in publish["steps"]]
    toolkit_upload = next(
        i for i, n in enumerate(pnames) if n.startswith("Publish messagefoundry-toolkit")
    )
    assert toolkit_upload == len(pnames) - 2 and pnames[-1].startswith("Publish to PyPI"), (
        "the toolkit upload must be the step immediately before the engine's, which stays last"
    )
    upload = publish["steps"][toolkit_upload]
    assert upload.get("with", {}).get("packages-dir") == "toolkit-dist/", upload
    assert upload.get("with", {}).get("skip-existing") is True, (
        "skip-existing keeps a re-run after a failed engine upload from dying on the toolkit's "
        "already-uploaded file (the v0.3.1 deadlock)"
    )
    for cond in (str(upload.get("if") or ""), str(publish.get("if") or "")):
        assert "PUBLISH_" not in cond, (
            "the toolkit upload is gated on a repository variable -- ADR 0201 rejects that, because "
            "an unset variable lets an engine that names the toolkit reach PyPI with the name "
            "unclaimed"
        )
    # Never into dist/: that would pull the toolkit into the engine smoke and the staged upload.
    assert "--outdir toolkit-dist" in str(steps[build].get("run") or "")


#: The step that moves the toolkit's Sigstore bundle out of toolkit-dist/ and then proves the
#: directory holds only wheels. Matched as a name prefix.
_TOOLKIT_BUNDLE_STEP_PREFIX = "Move the toolkit Sigstore bundle out of toolkit-dist/"


def test_the_toolkit_wheel_is_signed_attested_and_shipped_with_its_bundle() -> None:
    """BACKLOG #1192: the toolkit wheel gets the engine wheel's provenance, by explicit name.

    It lives in toolkit-dist/, so no `dist/*` glob reaches it. Each assertion names one sink it
    could silently drop out of: the Sigstore call, the SLSA subjects, the GitHub release assets and
    the dry-run upload. The bundle must also LEAVE toolkit-dist/ before the toolkit's PyPI publish,
    which uploads that directory whole: `sigstore sign` writes the bundle beside its input, and twine
    rejects a bundle, so a bundle left there fails the upload that claims the toolkit's name. What
    the move step DOES is graded by running it, in the tests after this one.
    """
    steps = _release_steps()
    sign = _release_step_index(_runs("python -m sigstore sign"), "Sigstore")
    lines = _executed_shell(str(steps[sign]["run"])).replace("\\\n", " ").splitlines()
    sign_lines = [ln.split() for ln in lines if "python -m sigstore sign" in ln]
    assert len(sign_lines) == 1, sign_lines
    assert "toolkit-dist/*.whl" in sign_lines[0], sign_lines[0]

    move = _release_step_index(_named(_TOOLKIT_BUNDLE_STEP_PREFIX), "toolkit bundle move")
    attest = _release_step_index(
        lambda s: str(s.get("uses") or "").startswith("actions/attest-build-provenance@"), "SLSA"
    )
    subjects = [p.strip() for p in str(steps[attest]["with"]["subject-path"]).split(",")]
    assert "toolkit-dist/*.whl" in subjects, subjects

    release = _release_step_index(_runs("gh release upload"), "GitHub release")
    assets = re.search(r"assets=\((.*?)\)", _executed_shell(str(steps[release]["run"])), re.S)
    assert assets, "the GitHub release step lost its `assets=( ... )` array"
    assert {"toolkit-dist/*.whl", "toolkit-sigstore/*.sigstore*"} <= set(assets.group(1).split())

    upload = _release_step_index(
        lambda s: (
            "upload-artifact" in str(s.get("uses") or "")
            and (s.get("with") or {}).get("name") == "release-artifacts"
            and "toolkit-dist/" in str((s.get("with") or {}).get("path") or "")
        ),
        "dry-run upload",
    )
    assert "toolkit-sigstore/" in str(steps[upload]["with"]["path"]).split(), steps[upload]

    handover = _release_step_index(_named("Hand the PyPI files to the publish job"), "hand-over")
    assert sign < move < attest < release < handover, (sign, move, attest, release, handover)


@pytest.fixture
def toolkit_bundle_step(tmp_path: Path) -> tuple[str, Path, dict[str, str]]:
    """A usable bash and the bundle-move step, written as BYTES, for the leak-gate fixture's
    reasons: ``require_bash`` fails loudly, and ``write_text`` would hand bash CRLF lines.

    The step re-runs the member gate as ``python scripts/release/forbidden_members.py``, so THIS
    interpreter's directory goes first on PATH, as tests/test_release_member_gate.py's
    ``_run_control`` does, and each work directory gets a copy of the real gate script (see
    ``_toolkit_dist``). The gate is stdlib-only, so any 3.14 runs it the same way.
    """
    script = tmp_path / "toolkit_bundle.sh"
    body = _step_script_by_prefix(_TOOLKIT_BUNDLE_STEP_PREFIX, "the toolkit bundle move")
    script.write_bytes(body.encode("utf-8"))
    env = _posix_tool_env()
    env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent), env["PATH"]])
    return require_bash(tmp_path, env), script, env


_TOOLKIT_WHEEL_NAME = "messagefoundry_toolkit-0.4.0-py3-none-any.whl"
_TOOLKIT_BUNDLE_NAME = f"{_TOOLKIT_WHEEL_NAME}.sigstore.json"
_SECOND_TOOLKIT_WHEEL = "messagefoundry_toolkit-0.4.1-py3-none-any.whl"


def _toolkit_dist(root: Path, names: Sequence[str], leak: bool = False) -> Path:
    """A work directory with the real member gate script and a toolkit-dist/ holding ``names``.

    A ``.whl`` name gets a real zip, which the re-run gate lists; ``leak`` adds a member that gate
    refuses. Any other name gets a small plain file.
    """
    gate = root / "scripts" / "release" / "forbidden_members.py"
    gate.parent.mkdir(parents=True)
    shutil.copyfile(_REPO / "scripts" / "release" / "forbidden_members.py", gate)
    (root / "toolkit-dist").mkdir()
    for name in names:
        path = root / "toolkit-dist" / name
        if name.endswith(".whl"):
            with zipfile.ZipFile(path, "w") as zf:
                zf.writestr("messagefoundry_toolkit/__init__.py", "")
                if leak:
                    zf.writestr("messagefoundry_toolkit/CLAUDE.md", "internal\n")
        else:
            path.write_bytes(b"fixture\n")
    return root


def test_the_toolkit_bundle_step_moves_the_bundle_and_passes_a_wheel_only_dir(
    toolkit_bundle_step: tuple[str, Path, dict[str, str]], tmp_path: Path
) -> None:
    """POSITIVE CONTROL for the refusals below. A harness that cannot run the step at all exits
    non-zero on every refusal, so those are evidence only while this passes. The gate's own
    success line proves the re-run gate really ran, rather than a shim that exits 0."""
    bash, script, env = toolkit_bundle_step
    work = _toolkit_dist(tmp_path / "ok", [_TOOLKIT_WHEEL_NAME, _TOOLKIT_BUNDLE_NAME])

    rc, out = _run_leak_gate(bash, work, script, env)
    assert rc == 0, out
    assert "member gate passed" in out, out
    assert [p.name for p in (work / "toolkit-dist").iterdir()] == [_TOOLKIT_WHEEL_NAME]
    assert [p.name for p in (work / "toolkit-sigstore").iterdir()] == [_TOOLKIT_BUNDLE_NAME]


@pytest.mark.parametrize(
    ("names", "leak", "expected"),
    [
        # mv exits non-zero on an unmatched glob and names it.
        ([_TOOLKIT_WHEEL_NAME], False, "toolkit-dist/*.sigstore*"),
        ([_TOOLKIT_BUNDLE_NAME], False, "it holds: nothing"),
        ([_TOOLKIT_WHEEL_NAME, _TOOLKIT_BUNDLE_NAME, "stray.txt"], False, "stray.txt"),
        ([_TOOLKIT_WHEEL_NAME, _TOOLKIT_BUNDLE_NAME, ".hidden"], False, ".hidden"),
        (
            [_TOOLKIT_WHEEL_NAME, _SECOND_TOOLKIT_WHEEL, _TOOLKIT_BUNDLE_NAME],
            False,
            _SECOND_TOOLKIT_WHEEL,
        ),
        ([_TOOLKIT_WHEEL_NAME, _TOOLKIT_BUNDLE_NAME], True, "maintainer-internal"),
    ],
    ids=["no-bundle", "no-wheel", "stray-file", "hidden-file", "two-wheels", "leaking-wheel"],
)
def test_the_toolkit_bundle_step_refuses(
    toolkit_bundle_step: tuple[str, Path, dict[str, str]],
    tmp_path: Path,
    names: list[str],
    leak: bool,
    expected: str,
) -> None:
    """Each case is graded on its OWN message, so a refusal for some other reason (a harness
    fault, or another arm catching it) does not read as this arm working."""
    bash, script, env = toolkit_bundle_step
    work = _toolkit_dist(tmp_path / "bad", names, leak=leak)

    rc, out = _run_leak_gate(bash, work, script, env)
    assert rc != 0, f"the step passed a toolkit-dist/ it should refuse ({expected!r}):\n{out}"
    assert expected in out, out


#: The engine smoke's import probe. ``flags`` is what the step passes the interpreter BEFORE ``-c``;
#: the behavioural test below runs that exact list rather than a copy of it, so a revert in the
#: workflow arrives here as a failure instead of leaving a test that still asserts the old string.
_VERSION_PROBE = re.compile(
    r'^\s*built=\$\(\S*python[0-9.]*(?P<flags>(?:\s+-[A-Za-z]+)*)\s+-c\s+"import messagefoundry;',
    re.M,
)


def _engine_wheel_smoke_script() -> str:
    """The engine wheel-smoke's EXECUTED shell — comments stripped.

    Graded through ``_executed_shell`` for the reason that helper was written: this workflow explains
    itself at length, so a check over the raw block is satisfied by a comment quoting the snippet it
    is looking for. Move the empty-version guard into prose and a raw check stays green while the
    dry-run arm is back to proving nothing.
    """
    return _executed_shell(
        _step_script_by_prefix(_WHEEL_SMOKE_STEP_PREFIX, "the engine wheel smoke")
    )


def _wheel_smoke_import_flags() -> list[str]:
    """The interpreter flags the engine smoke passes before ``-c``, e.g. ``['-I']``."""
    m = _VERSION_PROBE.search(_engine_wheel_smoke_script())
    assert m, (
        "could not find the engine wheel smoke's `built=$(... python ... -c \"import messagefoundry;"
        " ...\")` line — the step's shape moved, so the isolation check below is measuring nothing"
    )
    return m.group("flags").split()


def test_the_engine_wheel_smoke_passes_an_isolating_flag() -> None:
    """The static half. Whether the flag WORKS is the behavioural test below; this says one is there.

    The interpreter was ALREADY a clean venv, which is exactly why the defect survived review: for
    ``python -c`` ``sys.path[0]`` is the empty string, meaning the CURRENT WORKING DIRECTORY, and the
    release job's cwd is the repository checkout. ``import messagefoundry`` therefore resolved to the
    checkout's source tree, so a release WOULD ship a wheel missing the package entirely with this
    smoke check green.

    Spelling is not graded beyond "contains I or P" — the behavioural arms decide which routes are
    actually closed, and ``-P`` fails them because it leaves ``PYTHONPATH`` open.
    """
    flags = _wheel_smoke_import_flags()
    isolating = [flag for flag in flags if set("IP") & set(flag.lstrip("-"))]
    assert isolating, (
        f"the engine wheel smoke imports messagefoundry with no interpreter isolation (flags: "
        f"{flags or 'none'}), so the checkout's source tree is back on sys.path ahead of the "
        f"installed wheel and the check cannot fail on a broken wheel"
    )


def test_the_engine_wheel_smoke_refuses_an_empty_version_read() -> None:
    """Split from the isolation check so a PR that breaks both is told about both in one run.

    Matched on SHAPE, not on one shell spelling: ``[[ -z "$built" ]]``, ``[ -z "${built}" ]`` and
    ``test -z "$built"`` are all the same guard, and pinning the punctuation reds this for a rewrite
    that changed nothing.
    """
    script = _engine_wheel_smoke_script()
    assert re.search(r'-z\s+"?\$\{?built', script), (
        "the wheel smoke no longer rejects an empty __version__ read — on the workflow_dispatch "
        "dry-run (the arm that exists to validate this path before a tag) an empty version is not "
        "compared against anything, so the step would exit 0 having proved nothing"
    )
    assert "::error::" in script, (
        "the empty-version guard no longer emits a ::error:: annotation, so a failure here would be "
        "invisible in the run summary"
    )


def _plant_a_checkout(root: Path, version: str = _SHADOW_VERSION) -> Path:
    """A directory shaped like the repository checkout the release job runs in."""
    pkg = root / "messagefoundry"
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    return root


def _run_probe(
    flags: Sequence[str],
    cwd: Path,
    code: str,
    *,
    no_site: bool = True,
    pythonpath: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run ``code`` under ``flags`` from ``cwd``.

    ``no_site`` adds ``-S``, which is how the shadow arms stay attributable — see the test's
    docstring. The site-reachability arm turns it OFF, because it asks the opposite question.
    """
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    if pythonpath is not None:
        env["PYTHONPATH"] = str(pythonpath)
    return subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [sys.executable, *(["-S"] if no_site else []), *flags, "-c", code],
        cwd=str(cwd),
        env=env,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )


_IMPORT_CODE = "import messagefoundry; print(messagefoundry.__version__)"

#: A second planted tree, reached only through ``PYTHONPATH``. ``-P`` leaves that route open and
#: ``-I`` (which implies ``-E``) closes it, so this is what separates the two.
_PYTHONPATH_VERSION = "8888.0.0+viapythonpath"


def test_the_engine_wheel_smoke_cannot_read_its_version_from_the_checkout(tmp_path: Path) -> None:
    """FOUR ARMS, one variable: the workflow's own flag list, run against planted source trees.

    Reading the step can only say a flag is spelled there. Arm 1 is the finding: from a directory
    holding intact source the bare command prints the SOURCE version and exits 0. Arm 2 is the fix.

    ARM 3 IS WHY ARM 2 MEANS ANYTHING, AND IT ASKS THE HARDER QUESTION. Arm 2 asserts a NON-ZERO
    exit, and flags that break the interpreter exit non-zero too — ``-IX`` dies on a missing ``-X``
    argument, and ``-I -S`` starts fine but puts the relsmoke venv's site-packages, where the WHEEL
    WAS JUST INSTALLED, off sys.path. Both satisfy arm 2 and the static flag check while killing
    every release run. So arm 3 keeps ``site`` on and imports ``packaging``, which is the dependency
    this very step installs into the venv and imports a few lines later: it fails for either shape.

    ARM 4 IS WHY THE FLAG IS ``-I`` AND NOT ``-P``. ``-P`` drops the cwd and stops there, so a
    ``PYTHONPATH`` naming any source tree walks straight back in; ``-I`` implies ``-E`` and ignores
    it. The workflow's comment makes that claim, and without this arm nothing grades it — ``-P``
    passes arms 1 to 3 identically.

    ``-S`` on arms 1, 2 and 4 is the attribution. It takes site-packages out of the picture, so
    ``messagefoundry`` can come from exactly ONE planted place, and the only thing separating the
    runs is the flag list under test. Without it, this box's editable install answers the import on
    every arm and they would all pass for a reason unrelated to the fix.
    """
    flags = _wheel_smoke_import_flags()
    work = _plant_a_checkout(tmp_path / "checkout")

    bare = _run_probe([], work, _IMPORT_CODE)
    assert _SHADOW_VERSION in bare.stdout, (
        f"CONTROL ARM FAILED: with no isolation flags the planted checkout should answer the import, "
        f"and it did not — so the arms below are measuring a broken harness, not the workflow's flags."
        f"\n  rc={bare.returncode}\n  stdout={bare.stdout!r}\n  stderr={bare.stderr!r}"
    )

    guarded = _run_probe(flags, work, _IMPORT_CODE)
    assert guarded.returncode != 0 and _SHADOW_VERSION not in guarded.stdout, (
        f"the engine wheel smoke's flags ({flags or 'none'}) still let the CHECKOUT answer "
        f"`import messagefoundry`. A release WOULD then ship a wheel missing the package with this "
        f"smoke check green, because the version it printed came from source, not from the wheel."
        f"\n  rc={guarded.returncode}\n  stdout={guarded.stdout!r}\n  stderr={guarded.stderr!r}"
    )

    alive = _run_probe(flags, work, "import packaging; print('site ok')", no_site=False)
    assert alive.returncode == 0 and "site ok" in alive.stdout, (
        f"the engine wheel smoke's flags ({flags or 'none'}) leave an INSTALLED distribution "
        f"unreachable (or the interpreter refuses them outright), so the arm above proved nothing "
        f"and the release step would die on every run. The wheel is installed into the relsmoke "
        f"venv's site-packages and this same step imports `packaging` from it a few lines later."
        f"\n  rc={alive.returncode}\n  stdout={alive.stdout!r}\n  stderr={alive.stderr!r}"
    )

    other = _plant_a_checkout(tmp_path / "elsewhere", _PYTHONPATH_VERSION)
    via_env = _run_probe(flags, work, _IMPORT_CODE, pythonpath=other)
    assert _PYTHONPATH_VERSION not in via_env.stdout, (
        f"the engine wheel smoke's flags ({flags or 'none'}) let PYTHONPATH put a source tree ahead "
        f"of the installed wheel — `-P` alone does this, which is exactly why the workflow passes "
        f"`-I`. The step would read its version from whatever that variable names."
        f"\n  rc={via_env.returncode}\n  stdout={via_env.stdout!r}\n  stderr={via_env.stderr!r}"
    )


def test_no_step_survives_a_leak_gate_rejection_in_the_release_job() -> None:
    """An archive the leak gate REFUSED TO PUBLISH must not be handed out as a workflow artifact.

    The gate fails the release before the PyPI upload, so publication stops. The artifact upload
    carried a bare ``if: always()`` and uploaded the whole of ``dist/`` regardless — so on a
    packaging regression a deploying project WOULD find the rejected archive downloadable by any
    signed-in reader of this public repository, which is the one place the refused bytes must not
    go. No such upload has been established to have happened; this pins the shape.

    DERIVED over every step after the gate, not hardcoded to the one that has the defect: a guard
    naming a single step is a guard that has to be remembered when a second one is added. The
    sibling jobs are out of scope for a measured reason rather than an assumed one —
    ``release-harness`` carries ``needs: release`` so a failed release skips it entirely, and
    ``release-webconsole`` is gated on a ``webconsole-`` ref that is mutually exclusive with this
    job's; neither ever holds the engine's ``dist/``.

    Mutation: drop the exclusion from the upload's ``if:``, or the ``id:`` from the gate. Red here.
    """
    steps = [step for step in _jobs()["release"]["steps"] if isinstance(step, dict)]
    gates = [
        i
        for i, step in enumerate(steps)
        if str(step.get("name") or "").startswith(_LEAK_GATE_STEP_PREFIX)
    ]
    assert len(gates) == 1, f"expected exactly one leak gate step in the release job, found {gates}"
    gate_at = gates[0]

    assert steps[gate_at].get("id") == _LEAK_GATE_ID, (
        f"the leak gate lost its `id: {_LEAK_GATE_ID}`. THIS FAILS SILENTLY IN PRODUCTION: with no "
        f"such step id the expression below resolves to an empty string, `'' != 'failure'` is true, "
        f"and the upload is back to a plain always() while still LOOKING guarded."
    )
    assert "continue-on-error" not in steps[gate_at], (
        "the leak gate acquired `continue-on-error`, which removes the gate's blocking power "
        "entirely: its CONCLUSION becomes success, the job is not failed, and every later step's "
        "implicit success() passes — so a rejected sdist WOULD be signed, attached to the release "
        "and published to PyPI. The upload guard below keys on `outcome` and would still skip, which "
        "makes this failure look handled when it is the worst version of the defect."
    )
    assert "if" not in steps[gate_at], (
        f"the leak gate acquired an `if:` ({steps[gate_at].get('if')!r}). A SKIPPED gate is not a "
        f"failed one: its outcome is 'skipped', so the upload's `!= 'failure'` passes AND every "
        f"later step's implicit success() passes too — Sigstore signs, the release is created and "
        f"PyPI publishes an sdist that nothing ever listed. The gate must be unconditional."
    )

    early = [
        str(step.get("name") or step.get("uses") or "?")
        for step in steps[:gate_at]
        if "upload-artifact" in str(step.get("uses") or "")
    ]
    assert not early, (
        f"artifact upload(s) sit BEFORE the leak gate: {early}. A step placed before the gate runs "
        f"whatever the gate would have decided, so no `if:` can save it — the archive would be "
        f"handed out before anything had read it."
    )

    after = steps[gate_at + 1 :]
    assert any("upload-artifact" in str(step.get("uses") or "") for step in after), (
        "no artifact upload sits after the leak gate any more — the subject of this guard moved, so "
        "re-derive which steps can still hand out an archive the gate rejected"
    )

    # WHITESPACE-INSENSITIVE, because GitHub is. `${{ ! cancelled() }}` is a valid spelling that a
    # literal `!cancelled()` substring test misses, so a new always()-class step could be added after
    # the gate with this guard green; and `steps.leak-gate.outcome!='failure'` is equally valid and
    # would be reported as an offender. Both directions are wrong, so squeeze before matching.
    # AND `||` MUST BE ABSENT, because a substring test alone grades the wrong thing: both
    # `always() || steps.leak-gate.outcome != 'failure'` and
    # `always() && (steps.leak-gate.outcome != 'failure' || true)` CONTAIN the exclusion and are
    # unconditionally true, so the guard is dead while the text still reads right. One character is
    # the whole mutation. Nothing after this gate has a legitimate `||`, so refuse it outright.
    wanted = _squeeze(_LEAK_GATE_EXCLUSION)
    offenders: list[str] = []
    for step in after:
        raw = str(step.get("if") or "")
        cond = _squeeze(raw)
        if not any(_squeeze(token) in cond for token in _SURVIVES_A_FAILED_STEP):
            continue  # ANDs with the implicit success(), so a gate failure already skips it
        if wanted in cond and "||" not in cond:
            continue
        offenders.append(f"{step.get('name') or step.get('uses') or '?'} (if: {raw})")
    assert not offenders, (
        f"release step(s) after the leak gate still run when it REJECTED the sdist: {offenders}.\n"
        f"Each must AND in `{_LEAK_GATE_EXCLUSION}`, with no `||` anywhere in the expression.\n"
        f"The `!= 'failure'` spelling is deliberate and `== 'success'` is NOT equivalent: when an "
        f"EARLIER step failed the gate never runs, its outcome is the empty string, and only the "
        f"`!=` form still uploads — which is the always() behaviour this step exists for. That "
        f"choice has a known cost, recorded beside the `if:` in release.yml; do not flip it here."
    )


def test_the_sbomqs_pin_blocks_and_only_the_score_is_advisory() -> None:
    """A pin failure BLOCKS the release; only the SBOM score stays advisory (BACKLOG #1698).

    Owner ruling 2026-09-30 (BACKLOG #1698). The sbomqs download, its in-repo SHA-256 check and the
    install used to share ONE step with the score, under a step-level ``continue-on-error: true``.
    So the event the pin exists to catch -- a substituted or re-uploaded tarball -- ended as a green
    release with no warning. The step is now split: the verify-and-install half blocks, and the
    scoring half keeps ``continue-on-error`` because SBOM quality is a signal, not a gate (ADR 0149).

    Mutation: ``test_the_sbomqs_split_refuses_each_way_back_to_a_green_pin_failure`` below applies
    each one to a copy of this job.
    """
    import yaml

    workflow = yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))
    assert "defaults" not in workflow, (
        "release.yml acquired workflow-level `defaults`. If it sets a shell, that shell can drop "
        "bash's errexit under the sbomqs install step (BACKLOG #1698); check it and extend this test."
    )
    assert _sbomqs_split_offences(_jobs()["release"]) == []


def _sbomqs_split_offences(job: dict) -> list[str]:
    """Why ``job`` lets an sbomqs pin failure pass as a green release; empty when it blocks.

    Located by CONTENT, not by name, so a rename cannot blind this: the blocking half is the step
    that fetches the sbomqs release asset, and the advisory half is the step that runs
    ``sbomqs score``. Each must be exactly one step. Factored out so the mutation arms below run it
    on edited copies of the live job, not only on the live file, where it can only be seen passing.
    """
    steps = [step for step in job.get("steps") or [] if isinstance(step, dict)]

    def _body(step: dict) -> str:
        return _executed_shell(str(step.get("run") or ""))

    installs = [
        i
        for i, step in enumerate(steps)
        if "releases/download" in _body(step) and "sbomqs" in _body(step)
    ]
    scores = [i for i, step in enumerate(steps) if "sbomqs score" in _body(step)]
    if len(installs) != 1 or len(scores) != 1:
        return [
            f"expected one sbomqs download step and one `sbomqs score` step in `release`, found "
            f"downloads at {installs} and scores at {scores}"
        ]
    install_at, score_at = installs[0], scores[0]
    install, score = steps[install_at], steps[score_at]
    name = install.get("name")
    body = _body(install)
    offences: list[str] = []
    if "continue-on-error" in job:
        offences.append(
            f"the `release` job acquired job-level `continue-on-error` "
            f"({job.get('continue-on-error')!r}). A pin failure would still stop this job, but no "
            "longer the workflow, so a job that `needs: release` could still run (BACKLOG #1698)."
        )
    if install_at == score_at:
        offences.append(
            "the sbomqs download and the score share one step again. Whatever `continue-on-error` "
            "that step carries is then wrong for one half: set, a pin failure is a green release; "
            "unset, a low SBOM score blocks one (owner ruling 2026-09-30, BACKLOG #1698; ADR 0149)."
        )
    if "sha256sum -c" not in body:
        offences.append(
            f"step {name!r} fetches sbomqs but no longer runs `sha256sum -c`, so the blocking half "
            "blocks on nothing"
        )
    if "continue-on-error" in install:
        offences.append(
            f"step {name!r} acquired `continue-on-error` ({install.get('continue-on-error')!r}). A "
            "pin mismatch would then end as a green release with no warning, which the owner ruled "
            "out on 2026-09-30 (BACKLOG #1698)."
        )
    if "if" in install:
        offences.append(
            f"step {name!r} acquired an `if:` ({install.get('if')!r}). A SKIPPED verification is "
            "not a failed one, and the score below would then run whatever binary was already on "
            "the runner's PATH."
        )
    # One layer down from `continue-on-error`: a `shell:` that drops bash's `-e` lets every line
    # after a failed check run. The default shell keeps it.
    shells = [
        ("step `shell:`", install.get("shell")),
        ("job `defaults.run.shell`", ((job.get("defaults") or {}).get("run") or {}).get("shell")),
    ]
    offences.extend(
        f"step {name!r} runs under a {where} ({shell!r}), which can drop bash's errexit; the "
        "default shell keeps it, so a failed check stops the step"
        for where, shell in shells
        if shell is not None
    )
    # Inside the body: `|| true`, `set +e`, a check run as a condition. Round-2 review finding 3
    # (BACKLOG #1698): each passed every check above while a mismatch carried on to install. The
    # helper is the one the in-repo pin rule in tests/test_ci_venv_pinning.py reads.
    offences.extend(
        f"step {name!r} lets a failed pin check carry on: {reason}"
        for reason in verification_softeners(body)
    )
    if "||" in body:
        offences.append(
            f"step {name!r} carries a `||` fallback. The owner ruled that a pin failure blocks "
            "(2026-09-30, BACKLOG #1698), so the install step has no fallback to fall to."
        )
    if score.get("continue-on-error") is not True:
        offences.append(
            f"step {score.get('name')!r} lost `continue-on-error: true`. The SBOM score is a "
            "signal, not a gate (ADR 0149), so a low score must not block a release."
        )
    if install_at != score_at and "releases/download" in _body(score):
        offences.append(
            f"step {score.get('name')!r} downloads a release asset under `continue-on-error`, "
            "which is the shape this split removed: a fetch in an advisory step cannot block on "
            "its pin"
        )
    if install_at > score_at:
        offences.append("the sbomqs score runs before the step that installs sbomqs")
    return offences


def _release_step(job: dict, needle: str) -> dict:
    """The one step in ``job`` whose executed shell contains ``needle``."""
    found = [
        step
        for step in job["steps"]
        if isinstance(step, dict) and needle in _executed_shell(str(step.get("run") or ""))
    ]
    assert len(found) == 1, f"expected one step running {needle!r}, found {len(found)}"
    return found[0]


def _edit_install_body(old: str, new: str) -> Callable[[dict], None]:
    def mutate(job: dict) -> None:
        step = _release_step(job, "sha256sum -c")
        assert old in step["run"], f"the mutation's anchor {old!r} is gone from the live step"
        step["run"] = step["run"].replace(old, new)

    return mutate


def _set_on_install(key: str, value: object) -> Callable[[dict], None]:
    def mutate(job: dict) -> None:
        _release_step(job, "sha256sum -c")[key] = value

    return mutate


def _drop_score_softening(job: dict) -> None:
    del _release_step(job, "sbomqs score")["continue-on-error"]


def _fold_score_into_install(job: dict) -> None:
    score = _release_step(job, "sbomqs score")
    install = _release_step(job, "sha256sum -c")
    install["run"] += score["run"]
    install["continue-on-error"] = True
    job["steps"].remove(score)


def _set_job_shell(job: dict) -> None:
    job["defaults"] = {"run": {"shell": "bash {0}"}}


def _set_job_continue_on_error(job: dict) -> None:
    job["continue-on-error"] = True


_SBOMQS_VERIFY = 'echo "${SBOMQS_SHA256}  ${asset}" | sha256sum -c -'


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (_set_on_install("continue-on-error", True), "acquired `continue-on-error`"),
        (_set_on_install("if", "false"), "acquired an `if:`"),
        (_set_on_install("shell", "bash {0}"), "step `shell:`"),
        (_set_job_shell, "job `defaults.run.shell`"),
        (_drop_score_softening, "lost `continue-on-error: true`"),
        (_fold_score_into_install, "share one step again"),
        (_edit_install_body(_SBOMQS_VERIFY, _SBOMQS_VERIFY + " || true"), "carry on"),
        (_edit_install_body(_SBOMQS_VERIFY, _SBOMQS_VERIFY + " || :"), "carry on"),
        (_edit_install_body(_SBOMQS_VERIFY, "set +e\n" + _SBOMQS_VERIFY), "carry on"),
        (
            _edit_install_body(_SBOMQS_VERIFY, f"if ! {_SBOMQS_VERIFY}; then echo bad; fi"),
            "carry on",
        ),
        (
            _edit_install_body("tar -xzf", 'test -s "${asset}" || exit 1\ntar -xzf'),
            "carries a `||` fallback",
        ),
        (_edit_install_body(_SBOMQS_VERIFY, "trap 'exit 0' EXIT\n" + _SBOMQS_VERIFY), "carry on"),
        (_set_job_continue_on_error, "job-level `continue-on-error`"),
    ],
    ids=[
        "continue-on-error",
        "if-false",
        "step-shell-without-e",
        "job-shell-without-e",
        "score-made-blocking",
        "folded-back-into-one-step",
        "or-true",
        "or-colon",
        "set-plus-e",
        "as-a-condition",
        "any-or-fallback",
        "exit-trap",
        "job-continue-on-error",
    ],
)
def test_the_sbomqs_split_refuses_each_way_back_to_a_green_pin_failure(
    mutate: Callable[[dict], None], needle: str
) -> None:
    """Each mutation of the LIVE release job that lets a pin failure pass must be refused.

    Round-2 review finding 3 (BACKLOG #1698): ``sha256sum -c - || true`` in the install step passed
    the split test, because the test asked only whether the check was PRESENT and the step
    UNSOFTENED at step level. The mutations run on a deep copy of the parsed workflow, so the arms
    exercise the real step, and a drift in it moves them.
    """
    job = copy.deepcopy(_jobs()["release"])
    mutate(job)
    offences = _sbomqs_split_offences(job)
    assert any(needle in o for o in offences), f"expected {needle!r} among {offences}"


def _security_jobs() -> dict:
    import yaml

    path = _REPO / ".github" / "workflows" / "security.yml"
    return yaml.safe_load(path.read_text(encoding="utf-8"))["jobs"]


#: A stand-in for sbomqs: it logs each call to ``calls.log`` and fails a `score` of the file named by
#: ``FAIL_SCORE``, so a score step's control flow runs exactly as written with no binary to download.
_SBOMQS_STUB = (
    '#!/bin/sh\necho "$*" >> calls.log\n'
    'if [ "$1" = score ] && [ "$3" = "${FAIL_SCORE:-}" ]; then exit 1; fi\nexit 0\n'
)


def _run_score_step(tmp_path: Path, body: str, fail: str) -> tuple[int, list[str]]:
    """Run a score step's scoring lines, from ``rc=0`` on, under the runner's ``bash -e`` with the
    stub; return (exit code, the sbomqs calls it made). The lines above ``rc=0`` install the binary."""
    assert "rc=0" in body, "the score step no longer starts its scores at `rc=0`"
    tail = re.sub(
        r"(?m)^(\s*)(?:/usr/local/bin/)?sbomqs ", r"\1./sbomqs ", body[body.index("rc=0") :]
    )
    (tmp_path / "sbomqs").write_bytes(_SBOMQS_STUB.encode("utf-8"))
    (tmp_path / "sbomqs").chmod(0o755)
    script = tmp_path / "score.sh"
    # Bytes, never write_text: on Windows a translated \r\n breaks every line of the script.
    script.write_bytes(tail.encode("utf-8"))
    env = {**_posix_tool_env(), "FAIL_SCORE": fail}
    rc, _ = _run_leak_gate(require_bash(tmp_path, env), tmp_path, script, env)
    assert rc not in (126, 127), explain_returncode(rc, "the score step")
    log = tmp_path / "calls.log"
    return rc, log.read_text(encoding="utf-8").splitlines() if log.is_file() else []


#: Each workflow's two-SBOM score step: how to find it, the binary it must call, then the SBOM scored
#: first and second. The release calls the binary its BLOCKING install verified, by absolute path, so
#: no other `sbomqs` earlier on PATH can stand in for it.
_SCORE_STEPS = {
    "release": (
        lambda: _release_step(_jobs()["release"], "sbomqs score"),
        "/usr/local/bin/sbomqs",
        "messagefoundry-sbom.cdx.json",
        "messagefoundry-sbom-windows.cdx.json",
    ),
    "security": (
        lambda: _release_step(_security_jobs()["sbom"], "sbomqs score"),
        "sbomqs",
        "sbom-python.cdx.json",
        "sbom-ide.cdx.json",
    ),
}


@pytest.mark.parametrize("workflow", sorted(_SCORE_STEPS))
@pytest.mark.parametrize(
    ("fail", "pre_fix", "step_fails", "second_scored"),
    [
        ("first", False, True, True),
        ("second", False, True, True),
        ("", False, False, True),
        # The pre-fix body: the one arm where the hypothesis is false, so the test can fail.
        ("first", True, True, False),
    ],
    ids=["first-fails", "second-fails", "none-fail", "pre-fix-body-skips-the-second"],
)
def test_a_failing_sbomqs_score_does_not_skip_the_other_sbom(
    tmp_path: Path, workflow: str, fail: str, pre_fix: bool, step_fails: bool, second_scored: bool
) -> None:
    """BACKLOG #2521 finding 3. Under the runner's ``bash -e``, a failing first score used to end the
    step before the second SBOM was scored, and ``continue-on-error`` hid it. Each step must score
    both whatever either does, and still end non-zero when one failed, so the run shows it.
    """
    find, binary, first, second = _SCORE_STEPS[workflow]
    body = str(find()["run"])
    for sbom in (first, second):
        assert re.search(rf"(?m)^\s*{re.escape(binary)} score -b {re.escape(sbom)}\b", body), sbom
    if pre_fix:
        assert " || rc=1" in body, "the pre-fix mutation's anchor is gone from the live step"
        body = body.replace(" || rc=1", "")
    rc, calls = _run_score_step(tmp_path, body, {"first": first, "second": second}.get(fail, ""))
    assert (rc != 0) is step_fails, (rc, calls)
    assert f"score -b {first}" in calls, calls
    assert (f"score -b {second}" in calls) is second_scored, calls


def test_the_windows_sbom_dry_run_scores_it_with_the_released_sbomqs_version() -> None:
    """BACKLOG #2521 finding 4. security.yml's `sbom-windows` job is the pre-tag dry-run for this
    workflow's Windows SBOM, and it once never ran sbomqs on it, so sbomqs first read that file at a
    tag. Its score step must read the file the job builds, at the version the release pins."""
    step = _release_step(_security_jobs()["sbom-windows"], "sbomqs.exe score")
    body = _executed_shell(str(step["run"]))
    assert "score -b sbom-python-windows.cdx.json" in body
    assert "sha256sum -c" in body, "the Windows sbomqs download is not verified"

    def version(text: str) -> str:
        found = re.findall(r"^\s*VER=(\S+)$", text, re.MULTILINE)
        assert len(set(found)) == 1, found
        return found[0]

    install = _release_step(_jobs()["release"], "sha256sum -c")
    assert version(body) == version(_executed_shell(str(install["run"])))


def test_the_harness_smoke_runs_the_install_resolution_check() -> None:
    """The install legs of BACKLOG #1585 must run on the BUILT wheel, and nothing else shows it.

    ``tests/test_packaging.py`` runs ``scripts/release/harness_resolution_check.py`` on a synthetic
    wheel. The call on the real artifact lives only in release.yml, which runs at tag time, after
    the engine is already on PyPI. So a deleted line or a path typo there would pass every PR check
    and first fail, or silently not run, on a release. This pins the call and the path.

    Mutation: delete the call, rename the script, or soften it with ``|| true``. Red here.
    """
    script = "scripts/release/harness_resolution_check.py"
    assert (_REPO / script).is_file(), f"{script} is gone, but release.yml still calls it"
    steps = [
        step
        for step in _jobs()["release-harness"]["steps"]
        if isinstance(step, dict)
        and str(step.get("name") or "").startswith("Smoke-check the harness wheel")
    ]
    assert len(steps) == 1, f"expected one harness wheel smoke step, found {len(steps)}"
    calls = [
        line.strip()
        for line in _executed_shell(str(steps[0].get("run") or "")).splitlines()
        if script in line
    ]
    assert calls == [f"/tmp/harnesssmoke/bin/python -I {script} harness-dist/*.whl"], (
        f"the harness wheel smoke must run {script} on the built wheel, in the smoke venv, "
        f"unsoftened; found {calls}"
    )
    assert "continue-on-error" not in steps[0], "the harness wheel smoke acquired continue-on-error"


# --- (10) the GitHub release body is bounded before `gh release` sees it -----------------------------

#: The step that bounds a release body. Loaded by path, the way the workflow runs it.
_NOTES_SCRIPT = _REPO / "scripts" / "release" / "release_notes.py"
_NOTES_CALL = "python scripts/release/release_notes.py notes.md"
#: GitHub's ceiling on a release body: the API answers `body is too long (maximum is 125000
#: characters)` (cli/cli issue 7815). The REST docs state no limit, so this is the observed figure.
_GITHUB_BODY_CEILING = 125_000


def _notes_module() -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_mefor_release_notes", _NOTES_SCRIPT)
    assert spec is not None and spec.loader is not None, f"cannot load {_NOTES_SCRIPT}"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _notes_steps() -> list[tuple[str, str]]:
    """(step name, executed shell) for every step that hands `notes.md` to `gh release`."""
    found = [
        (str(step.get("name")), _executed_shell(str(step.get("run") or "")))
        for job in _jobs().values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and "--notes-file notes.md" in str(step.get("run") or "")
    ]
    assert found, "no release.yml step passes --notes-file notes.md -- the workflow shape moved"
    return found


def test_every_release_body_is_bounded_between_its_extraction_and_gh_release() -> None:
    """The 0.5.0 CHANGELOG section is about 256,000 characters and GitHub refuses a body over
    125,000. The step sits before the PyPI publish, so an unbounded body stops the release there.

    Order is the claim, not presence: the bound must run after the last write to `notes.md` and
    before the first `gh release` call, and nothing after it may touch `notes.md` except as the
    `--notes-file` it hands over. Mutation: move the call below `gh release view`. Red here.
    """
    for name, code in _notes_steps():
        assert _NOTES_CALL in code, f"{name!r} hands notes.md to gh release without bounding it"
        bound_at = code.index(_NOTES_CALL)
        last_write = max(code.rfind("> notes.md"), code.rfind(">notes.md"))
        first_gh = code.index("gh release ")
        assert last_write < bound_at < first_gh, (
            f"{name!r}: the bound must sit after the last write to notes.md and before gh release"
        )
        assert "--full-url" in code[bound_at:first_gh], f"{name!r}: a cut body must link the rest"
        after = code[bound_at + len(_NOTES_CALL) :]
        assert after.count("notes.md") == after.count("--notes-file notes.md"), (
            f"{name!r}: something touches notes.md after the bound, other than --notes-file"
        )


def _notes_prefix(run: str) -> str:
    """The step's lines up to and including the bound call and its continuation lines."""
    lines = run.splitlines()
    start = next(i for i, ln in enumerate(lines) if _NOTES_CALL in ln)
    end = start
    while lines[end].rstrip().endswith("\\"):
        end += 1
    return "\n".join(lines[: end + 1]) + "\n"


#: (step-name prefix, the changelog the step reads, its tag, the link a shrunk body must end with).
_NOTES_CASES = {
    "engine": (
        "Create or update the GitHub",
        "CHANGELOG.md",
        "v9.9.9",
        "https://github.com/MEFORORG/MessageFoundry/blob/v9.9.9/CHANGELOG.md",
    ),
    "console": (
        "Create or update the console GitHub",
        "packaging/messagefoundry-webconsole/CHANGELOG.md",
        "webconsole-v9.9.9",
        "https://github.com/MEFORORG/MessageFoundry/blob/webconsole-v9.9.9/"
        "packaging/messagefoundry-webconsole/CHANGELOG.md",
    ),
}


def _run_notes_prefix(tmp_path: Path, case: str, changelog: str, *, bounded: bool = True) -> str:
    """Run a release step's notes-building lines under bash; return notes.md as written."""
    step, changelog_path, tag, _ = _NOTES_CASES[case]
    prefix = _notes_prefix(_step_script_by_prefix(step, "release notes"))
    if not bounded:
        # The mutation arm: the same lines with the bound call deleted.
        prefix = prefix[: prefix.index(_NOTES_CALL)]
    work = tmp_path / "work"
    (work / "scripts" / "release").mkdir(parents=True)
    shutil.copy2(_NOTES_SCRIPT, work / "scripts" / "release" / "release_notes.py")
    (work / changelog_path).parent.mkdir(parents=True, exist_ok=True)
    (work / changelog_path).write_bytes(changelog.encode("utf-8"))
    script = tmp_path / "notes.sh"
    script.write_bytes(prefix.encode("utf-8"))
    env = _posix_tool_env()
    env["PATH"] = os.pathsep.join([str(Path(sys.executable).parent), env["PATH"]])
    env["GITHUB_REF_NAME"] = tag
    env["GITHUB_REPOSITORY"] = "MEFORORG/MessageFoundry"
    bash = require_bash(tmp_path, env)
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, no shell, test-local paths
        [bash, "-e", str(script)], cwd=str(work), env=env, capture_output=True, timeout=60
    )
    out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
    assert proc.returncode == 0, (
        f"the notes lines failed ({explain_returncode(proc.returncode)}):\n{out}"
    )
    return (work / "notes.md").read_bytes().decode("utf-8")


def _changelog(entries: int) -> str:
    """A changelog whose 9.9.9 section holds ``entries`` entries, each a bold title and a body,
    then a Security block with a BREAKING entry at the very end, where a plain cut would lose it.
    Non-ASCII on purpose: the heading carries an em dash, as the real one does."""
    body = "".join(
        f"- **Entry {i}.** Body starts here.\n  " + "x" * 110 + "\n  - nested detail\n"
        for i in range(entries)
    )
    return (
        "# Changelog\n\n## [Unreleased]\n\n## [9.9.9] — 2026-09-30\n\n### Added\n"
        f"{body}\n### Security\n- **BREAKING — the last entry\n  wraps its title.** Body.\n"
        "\n## [9.9.8]\n- old\n"
    )


@pytest.mark.parametrize("case", sorted(_NOTES_CASES))
def test_an_over_long_release_body_keeps_every_title_and_links_the_full_section(
    tmp_path: Path, case: str
) -> None:
    """Executed, not read: each step's own lines on a section well over GitHub's ceiling."""
    link = _NOTES_CASES[case][3]
    changelog = _changelog(2_000)
    unbounded = _run_notes_prefix(tmp_path / "control", case, changelog, bounded=False)
    # The control: without the bound, this fixture is a body GitHub would refuse.
    assert len(unbounded) > _GITHUB_BODY_CEILING, len(unbounded)
    notes = _run_notes_prefix(tmp_path / "bounded", case, changelog)
    limit = _notes_module().DEFAULT_LIMIT
    assert len(notes) <= limit < _GITHUB_BODY_CEILING, len(notes)
    assert notes.startswith("## [9.9.9] — 2026-09-30\n"), notes[:80]
    assert notes.rstrip().endswith(f"[CHANGELOG.md]({link})."), notes[-300:]
    assert "- old" not in notes, "the next version's section leaked into the notes"
    # Titles survive, bodies do not, and the last block survives whole.
    assert "- **Entry 1999.**\n" in notes
    assert "Body starts here" not in notes and "nested detail" not in notes
    assert "### Security\n\n- **BREAKING — the last entry\n  wraps its title.**\n" in notes


@pytest.mark.parametrize("case", sorted(_NOTES_CASES))
def test_a_release_body_within_the_bound_is_left_exactly_as_extracted(
    tmp_path: Path, case: str
) -> None:
    notes = _run_notes_prefix(tmp_path / "bounded", case, _changelog(3))
    control = _run_notes_prefix(tmp_path / "control", case, _changelog(3), bounded=False)
    assert notes == control
    assert "CHANGELOG.md](" not in notes


def test_headlines_that_still_do_not_fit_are_cut_at_a_line_end_on_or_under_the_limit() -> None:
    mod = _notes_module()
    url = "https://example.invalid/CHANGELOG.md"
    tail = mod.footer(url, cut=True)
    text = "".join(f"- **line {i:05d}**\n" for i in range(2_000))
    assert mod.headlines(text) == text  # nothing to drop, so only a cut can shrink it
    for limit in (len(tail) + 1, 500, 5_000, len(text) - 1):
        out = mod.bound(text, url, limit)
        assert len(out) <= limit, (limit, len(out))
        assert out.endswith(tail)
        kept = out[: -len(tail)]
        assert text.startswith(kept)
        # Whole lines only, unless not even one fits.
        if limit - len(tail) >= len("- **line 00000**"):
            assert all(len(ln) == len("- **line 00000**") for ln in kept.splitlines()), kept[-40:]
    assert mod.bound(text, url, len(text)) is text
    with pytest.raises(ValueError, match="no room"):
        mod.bound(text, url, 10)


def test_headlines_keep_headings_and_titles_and_drop_bodies() -> None:
    mod = _notes_module()
    text = (
        "## [1.0.0]\n### Fixed\n- **Short.** Body on the title line.\n  more body\n"
        "- **Long title\n  over two lines.** Body.\n- plain entry, first line kept\n  its body\n"
        "- **Unclosed\n  a\n  b\n  c\n  d\n"
    )
    assert mod.headlines(text) == (
        "## [1.0.0]\n\n### Fixed\n\n- **Short.**\n- **Long title\n  over two lines.**\n"
        "- plain entry, first line kept\n- **Unclosed\n"
    )


def test_headlines_keep_a_versions_preamble_paragraph() -> None:
    """The console's preamble names the engine it pairs with; a shrunk page must keep it."""
    mod = _notes_module()
    text = (
        "## [0.4.0]\n\n**Requires engine 0.5.0.** Seam `x`,\nsecond line.\n\n"
        "### Added\n- **Entry.** Body.\n  more\n\nA closing paragraph.\n"
    )
    assert mod.headlines(text) == (
        "## [0.4.0]\n\n**Requires engine 0.5.0.** Seam `x`,\nsecond line.\n\n"
        "### Added\n\n- **Entry.**\n\nA closing paragraph.\n"
    )


def test_a_shrunk_body_that_fits_says_titles_only_and_one_that_is_cut_says_so() -> None:
    mod = _notes_module()
    url = "https://example.invalid/CHANGELOG.md"
    text = "".join(f"- **T{i}.** " + "b" * 200 + "\n" for i in range(100))
    fits = mod.bound(text, url, len(text) - 1)
    assert fits.endswith(mod.footer(url, cut=False)), fits[-200:]
    assert "- **T99.**" in fits
    cut = mod.bound(text, url, 1_000)
    assert len(cut) <= 1_000 and cut.endswith(mod.footer(url, cut=True)), cut[-200:]


# --- (12) nothing is built from a commit that is not on main (vault BACKLOG #2631, limb 2) -----------
#
# scripts/release/tag_provenance.py holds the rule; tests/test_release_tag_provenance.py grades it.
# These tests hold the WIRING: the gate runs on a tag push, before every job that builds a release
# artifact, and in a job that holds no write scope.

_PROVENANCE_JOB = "tag-provenance"
_PROVENANCE_CALL = "python scripts/release/tag_provenance.py"


def _upstream(job_key: str) -> set[str]:
    """Every job ``job_key`` waits on, directly or through another job's ``needs:``."""
    jobs = _jobs()
    seen: set[str] = set()
    todo = needs_of(jobs[job_key])
    while todo:
        key = todo.pop()
        if key not in seen:
            seen.add(key)
            todo.extend(needs_of(jobs[key]))
    return seen


def _writes(job: dict) -> list[str]:
    """The write scopes a job holds. Every job in release.yml names its own; `permissions: {}`
    at the workflow level means a job naming none holds none."""
    return sorted(k for k, v in (job.get("permissions") or {}).items() if v == "write")


def test_the_provenance_gate_runs_on_a_tag_push_and_holds_no_write_scope() -> None:
    """The gate's step runs the script on a tag push. Its JOB carries no event guard, because a
    skipped job skips every job that needs it, which would end the dispatch dry-run. And the job
    writes nothing: it only reads the server.

    Mutation: guard the job on the event, drop the step's guard, or add a write scope. Red here.
    """
    job = _jobs()[_PROVENANCE_JOB]
    assert _EVENT_GUARD not in str(job.get("if") or ""), (
        f"{_PROVENANCE_JOB} is guarded on the event at job level, so a dispatch skips it and every "
        "build job that needs it: the dry-run would build nothing"
    )
    steps = [s for s in job.get("steps") or [] if _PROVENANCE_CALL in str(s.get("run") or "")]
    assert len(steps) == 1, f"expected one step running {_PROVENANCE_CALL}, found {len(steps)}"
    guard = _despace(str(steps[0].get("if") or ""))
    assert any(_despace(c) in guard for c in _GUARD_CONJUNCTIONS) and "||" not in guard, (
        f"the provenance step's guard {steps[0].get('if')!r} is not the event-and-ref pair, so it "
        "would not run on a tag push, or would run on a dispatch from an unmerged branch"
    )
    assert not _writes(job), f"{_PROVENANCE_JOB} holds write scope(s) {_writes(job)}; it only reads"


def test_every_job_that_can_publish_waits_on_the_provenance_gate() -> None:
    """DERIVED, not listed: any job holding a write scope or the OIDC identity can sign or
    publish, so it must wait on the gate, directly or through another job.

    Liveness: at least the three release jobs must be found, or the derivation matched nothing.
    Mutation: drop `tag-provenance` from `release`'s or `release-webconsole`'s `needs:`. Red here.
    """
    privileged = {
        key
        for key, job in _jobs().items()
        if key != _PROVENANCE_JOB and (_writes(job) or "id-token" in (job.get("permissions") or {}))
    }
    assert len(privileged) >= 3, sorted(privileged)
    assert privileged >= {"release", "release-webconsole", "release-harness"}, sorted(privileged)
    missing = sorted(key for key in privileged if _PROVENANCE_JOB not in _upstream(key))
    assert not missing, (
        f"job(s) {missing} can sign or publish without waiting on {_PROVENANCE_JOB}, so they would "
        "release a commit that is not on main (vault BACKLOG #2631)"
    )


# --- (13) no asset is added to a published GitHub release (vault BACKLOG #2631, limb 6) --------------
#
# An immutable release refuses any asset change once it is published. So the engine's release is a
# draft until every job that attaches an asset has run, and then one job publishes it. The console's
# release is created by one call that carries its one asset. A re-run never uploads to a published
# release. The structural tests hold the shape; the executed tests run each step against a stand-in
# `gh` that records what it was asked to do.

_PUBLISH_JOB = "publish-github-release"


def _gh_release_jobs(verbs: str) -> set[str]:
    """Jobs whose EXECUTED shell runs `gh release <verb>` for any verb in ``verbs``."""
    pattern = re.compile(rf"\bgh release (?:{verbs})\b")
    return {
        key
        for key, job in _jobs().items()
        if any(pattern.search(_executed_shell(str(s.get("run") or ""))) for s in job["steps"])
    }


def test_only_the_publish_job_takes_a_release_out_of_draft_and_it_runs_last() -> None:
    """The engine release is created as a draft, one job publishes it, and that job waits on
    every other job that attaches an asset to the engine release.

    Mutation: drop `--draft` from the create, drop `release-harness` from the publish job's
    `needs:`, or publish from any other job. Red here.
    """
    jobs = _jobs()
    create = _step_script_by_prefix("Create or update the GitHub release", "the engine release")
    creates = [ln for ln in _executed_shell(create).splitlines() if "gh release create" in ln]
    assert creates and all("--draft" in ln for ln in creates), (
        f"the engine release is not created as a draft: {creates}. The harness job attaches after "
        "it, so a published release would have an asset added after publication"
    )

    publishers = {
        key
        for key, job in jobs.items()
        if any("--draft=false" in _executed_shell(str(s.get("run") or "")) for s in job["steps"])
    }
    # The console job may too: it finishes ITS OWN release when an interrupted create left a draft.
    assert publishers == {_PUBLISH_JOB, "release-webconsole"}, (
        f"jobs that take a release out of draft: {sorted(publishers)}; only {_PUBLISH_JOB} (and the "
        "console job, for its own release) may"
    )
    # The console job may publish only because its own `if:` keeps it off engine tags.
    console_if = _despace(str(jobs["release-webconsole"].get("if") or ""))
    assert "startsWith(github.ref_name,'webconsole-')" in console_if and "||" not in console_if, (
        "release-webconsole may take a release out of draft, so it must stay on console tags"
    )
    # A status function would run the publish job after a job it needs had FAILED, publishing a
    # draft with that job's asset missing. The implicit success() is the control.
    publish_if = str(jobs[_PUBLISH_JOB].get("if") or "")
    overrides = [
        f for f in ("always()", "cancelled()", "failure()", "success()") if f in publish_if
    ]
    assert not overrides, f"{_PUBLISH_JOB}'s `if:` overrides the needs' success with {overrides}"
    # Every job that attaches to a release, except the console's, which makes its own in one call.
    attaching = _gh_release_jobs("create|upload") - {"release-webconsole"}
    assert attaching >= {"release", "release-harness"}, sorted(attaching)
    late = sorted(attaching - _upstream(_PUBLISH_JOB))
    assert not late, (
        f"job(s) {late} attach to the engine release but {_PUBLISH_JOB} does not wait on them, so "
        "the release could be published before their asset is on it"
    )
    assert not _gh_release_jobs("create|upload") & {_PUBLISH_JOB}, (
        f"{_PUBLISH_JOB} itself attaches an asset; it must only publish"
    )


#: A stand-in for `gh`. It records each call, answers `release view` from FAKE_RELEASE (absent,
#: draft or published) and FAKE_ASSETS, and does nothing else.
_FAKE_GH = """#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$GH_LOG"
if [ "$1" = release ] && [ "$2" = view ]; then
  if [ "$FAKE_RELEASE" = absent ]; then echo "release not found" >&2; exit 1; fi
  if [ "$FAKE_RELEASE" = broken ]; then echo "HTTP 502: Bad Gateway" >&2; exit 1; fi
  case "$*" in *isDraft*) if [ "$FAKE_RELEASE" = draft ]; then echo true; else echo false; fi ;; esac
  case "$*" in *assets*) [ -z "$FAKE_ASSETS" ] || printf '%s\\n' $FAKE_ASSETS ;; esac
fi
exit 0
"""

_TAG = "v0.0.1"
_HARNESS_WHEEL = "messagefoundry_harness-0.0.1-py3-none-any.whl"


def _run_release_step(
    tmp_path: Path, prefix: str, state: str, assets: str = ""
) -> tuple[int, str, list[str]]:
    """Run one release step's ``run:`` block under `bash -e` with the stand-in `gh` first on PATH.

    Returns (exit code, output, the `gh` calls). The work directory holds what each step reads:
    a CHANGELOG section, the notes script, and one file per asset directory.
    """
    work = tmp_path / "work"
    bin_dir = tmp_path / "bin"
    for sub in ("scripts/release", "dist", "toolkit-dist", "harness-dist", "webconsole-dist"):
        (work / sub).mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(exist_ok=True)
    shutil.copyfile(
        _REPO / "scripts" / "release" / "release_notes.py",
        work / "scripts" / "release" / "release_notes.py",
    )
    (work / "CHANGELOG.md").write_bytes(b"## [0.0.1]\n- **Entry.** Body.\n")
    for name in (
        "dist/messagefoundry-0.0.1.tar.gz",
        f"harness-dist/{_HARNESS_WHEEL}",
        "webconsole-dist/messagefoundry_webconsole-0.0.1-py3-none-any.whl",
    ):
        (work / name).write_bytes(b"fixture\n")
    (bin_dir / "gh").write_bytes(_FAKE_GH.encode("utf-8"))
    (bin_dir / "gh").chmod(0o755)
    script = tmp_path / "step.sh"
    script.write_bytes(_step_script_by_prefix(prefix, prefix).encode("utf-8"))
    log = tmp_path / "gh.log"
    log.write_bytes(b"")

    env = _posix_tool_env()
    env["PATH"] = os.pathsep.join([str(bin_dir), str(Path(sys.executable).parent), env["PATH"]])
    env.update(
        GH_LOG=str(log).replace("\\", "/"),
        FAKE_RELEASE=state,
        FAKE_ASSETS=assets,
        GITHUB_REF_NAME=_TAG,
        GITHUB_REPOSITORY="example/example",
    )
    bash = require_bash(tmp_path, env)
    rc, out = _run_leak_gate(bash, work, script, env)
    # A stand-in `gh` that bash cannot find or run would read as the step refusing.
    assert rc not in (126, 127), explain_returncode(rc, f"the {prefix!r} step") + "\n" + out
    calls = log.read_bytes().decode("utf-8").splitlines()
    return rc, out, calls


def _uploads(calls: Sequence[str]) -> list[str]:
    return [c for c in calls if c.startswith(("release upload", "release create"))]


@pytest.mark.parametrize(
    ("prefix", "state", "assets", "ok", "uploads"),
    [
        # The engine release: created as a draft, edited while a draft, untouched once published.
        ("Create or update the GitHub release", "absent", "", True, ["release create"]),
        ("Create or update the GitHub release", "draft", "", True, ["release upload"]),
        ("Create or update the GitHub release", "published", "", True, []),
        # The harness wheel: onto the draft; a published release must already carry it.
        ("Attach the harness wheel", "draft", "", True, ["release upload"]),
        ("Attach the harness wheel", "published", _HARNESS_WHEEL, True, []),
        ("Attach the harness wheel", "published", "something-else.whl", False, []),
        # The console: one call creates it with its asset; a re-run touches nothing.
        ("Create or update the console GitHub release", "absent", "", True, ["release create"]),
        ("Create or update the console GitHub release", "published", "", True, []),
        # An interrupted create left a draft: attach to it (then publish, graded separately).
        ("Create or update the console GitHub release", "draft", "", True, ["release upload"]),
        # A read that fails for any reason but "not found" refuses rather than guessing "absent".
        ("Create or update the GitHub release", "broken", "", False, []),
        ("Create or update the console GitHub release", "broken", "", False, []),
    ],
    ids=[
        "engine-new",
        "engine-draft-rerun",
        "engine-published-rerun",
        "harness-draft",
        "harness-published-has-wheel",
        "harness-published-missing-wheel",
        "console-new",
        "console-rerun",
        "console-interrupted-draft",
        "engine-read-error",
        "console-read-error",
    ],
)
def test_no_release_step_uploads_to_a_published_release(
    tmp_path: Path, prefix: str, state: str, assets: str, ok: bool, uploads: list[str]
) -> None:
    """EXECUTED, so the claim is what each step DOES against each release state.

    The `engine-new` and `harness-draft` cases are the positive controls: they prove the stand-in
    `gh` is reached and records an upload, so an empty upload list elsewhere means the step chose
    not to upload. Mutation: drop the published arm of any step. Red here.
    """
    rc, out, calls = _run_release_step(tmp_path, prefix, state, assets)
    assert (rc == 0) is ok, f"exit {rc}:\n{out}\ncalls: {calls}"
    made = _uploads(calls)
    assert [c.split(" " + _TAG)[0] for c in made] == uploads, f"gh calls: {calls}\n{out}"
    if state == "published":
        assert not made, f"a step uploaded to a published release: {made}"
    if state == "absent" and "console" not in prefix:
        assert all("--draft" in c for c in made), f"the engine release was not a draft: {made}"
    if state == "draft" and "console" in prefix:
        assert calls[-1] == f"release edit {_TAG} --draft=false", f"draft left unpublished: {calls}"
    if state == "broken":
        assert "refusing to guess" in out and "HTTP 502" in out, out


@pytest.mark.parametrize(("state", "edits"), [("draft", 1), ("published", 0)])
def test_the_publish_step_publishes_a_draft_and_leaves_a_published_release_alone(
    tmp_path: Path, state: str, edits: int
) -> None:
    rc, out, calls = _run_release_step(tmp_path, "Publish the draft GitHub release", state)
    assert rc == 0, out
    published = [c for c in calls if c == f"release edit {_TAG} --draft=false"]
    assert len(published) == edits, f"gh calls: {calls}"
    assert not _uploads(calls), calls


# --- (14) every PyPI publish runs in a publish-only job that names `pypi` (vault BACKLOG #2631) ------
#
# The environment key sits on a whole job. Put on a job that also builds, an approval on the
# environment would gate the build too, and a tags-only environment would refuse the dispatch
# dry-run at the job. So the key belongs on jobs that only publish, and those jobs never run on a
# dispatch at all.

_ENVIRONMENT = "pypi"
_PUBLISH_ACTION = "pypa/gh-action-pypi-publish@"
_VERIFY_PREFIX = "The downloaded files are the ones the build job gated"


def _environment(job: dict) -> str | None:
    env = job.get("environment")
    return str(env.get("name")) if isinstance(env, dict) else (str(env) if env else None)


def _publish_jobs() -> dict[str, dict]:
    jobs = {
        key: job
        for key, job in _jobs().items()
        if any(str(s.get("uses") or "").startswith(_PUBLISH_ACTION) for s in job["steps"])
    }
    # Liveness: the engine-and-toolkit, console and harness publishes.
    assert len(jobs) >= 3, sorted(jobs)
    return jobs


def test_every_pypi_publish_runs_in_a_publish_only_job_that_names_the_environment() -> None:
    """Mutation: drop `environment: pypi` from a publish job, put a build or checkout step in one,
    or give one a write scope. Red here. The dispatch guard is the next test but one."""
    problems: list[str] = []
    for key, job in _publish_jobs().items():
        if _environment(job) != _ENVIRONMENT:
            problems.append(f"{key} publishes to PyPI without `environment: {_ENVIRONMENT}`")
        if job.get("permissions") != {"id-token": "write"}:
            problems.append(f"{key} holds {job.get('permissions')}, not only id-token: write")
        for step in job["steps"]:
            uses = str(step.get("uses") or "")
            if uses.startswith("actions/checkout@"):
                problems.append(f"{key} checks out the repository")
            if "run" in step and not str(step.get("name", "")).startswith(_VERIFY_PREFIX):
                problems.append(f"{key} runs a command: {step.get('name')!r}")
    assert not problems, "\n".join(problems)


def test_only_publish_jobs_name_the_environment() -> None:
    """A build job naming it would put the approval in front of the build and the dry-run."""
    named = {key for key, job in _jobs().items() if _environment(job)}
    assert named == set(_publish_jobs()), (
        f"jobs naming an environment: {sorted(named)}; only the publish jobs "
        f"{sorted(_publish_jobs())} may"
    )


def test_a_dispatch_never_schedules_a_job_that_names_the_environment() -> None:
    """The `pypi` environment admits only tags and waits for a reviewer. A dispatch from a branch
    that reached a job naming it would be refused there, so the dry-run would fail. Every such job
    carries the event-and-ref pair at JOB level, with no status function that could widen it.

    Liveness: the publish jobs must be found. Mutation: move a job's pair to its steps, add
    `|| always()`, or name the environment on a job without the pair. Red here.
    """
    named = {key: job for key, job in _jobs().items() if _environment(job)}
    assert named, "no job names an environment; the derivation matched nothing"
    problems = []
    for key, job in named.items():
        guard = _despace(str(job.get("if") or ""))
        if not any(_despace(c) in guard for c in _GUARD_CONJUNCTIONS) or "||" in guard:
            problems.append(f"{key}: `if:` {job.get('if')!r} lacks the event-and-ref pair")
        widened = [f for f in ("always()", "cancelled()", "failure()") if f in guard]
        if widened:
            problems.append(f"{key}: `if:` widens the guard with {widened}")
    assert not problems, "\n".join(problems)


def test_the_engine_release_is_published_only_after_the_engine_is_on_pypi() -> None:
    """Before the split, the engine's PyPI publish sat inside `release`, so the draft was
    published only after it. The publish job keeps that order: a refused approval or a failed
    upload leaves the GitHub release a draft. Mutation: drop `publish-pypi` from
    `publish-github-release`'s `needs:`. Red here."""
    assert "publish-pypi" in _upstream(_PUBLISH_JOB), sorted(_upstream(_PUBLISH_JOB))


def test_each_publish_job_checks_the_digests_its_producer_recorded() -> None:
    """The chain from the gated files to the published ones: the publish job needs its producer,
    reads that producer's `pypi-digests` output, and checks it before any publish step; the
    producer's output comes from its digest step, which digests the directories it hands over;
    and every directory published was handed over."""
    jobs = _jobs()
    bodies = set()
    for key, job in _publish_jobs().items():
        steps = job["steps"]
        verify = [
            i for i, s in enumerate(steps) if str(s.get("name", "")).startswith(_VERIFY_PREFIX)
        ]
        publishes = [
            i for i, s in enumerate(steps) if str(s.get("uses") or "").startswith(_PUBLISH_ACTION)
        ]
        assert len(verify) == 1 and verify[0] < min(publishes), (key, verify, publishes)
        bodies.add(steps[verify[0]]["run"])
        m = re.fullmatch(
            r"\$\{\{\s*needs\.([\w-]+)\.outputs\.pypi-digests\s*\}\}",
            str(steps[verify[0]]["env"]["EXPECTED"]),
        )
        assert m, steps[verify[0]]["env"]
        producer = m.group(1)
        assert producer in needs_of(job), (key, needs_of(job))
        prod = jobs[producer]
        assert prod["outputs"]["pypi-digests"] == "${{ steps.pypi-digests.outputs.sha256 }}"
        digest = next(s for s in prod["steps"] if s.get("id") == "pypi-digests")
        handover = next(
            s
            for s in prod["steps"]
            if str(s.get("uses") or "").startswith("actions/upload-artifact@")
            and str((s.get("with") or {}).get("name", "")).startswith("pypi-")
        )
        handed = set(str(handover["with"]["path"]).split())
        digested = set(re.findall(r"([\w-]+/)\*", digest["run"]))
        assert handed == digested, (producer, handed, digested)
        fetched = next(
            s for s in steps if str(s.get("uses") or "").startswith("actions/download-artifact@")
        )
        assert fetched["with"]["name"] == handover["with"]["name"], (key, fetched["with"])
        # WHERE THE FILES LAND. upload-artifact roots an artifact at the common ancestor of its
        # paths, so ONE directory is stored without its own name, and several top-level ones keep
        # theirs. Each handed-over directory must land at its own name, or the digest manifest and
        # `packages-dir` point at nothing on a real tag; a dispatch never downloads, so only this
        # catches it.
        target = str(fetched["with"].get("path") or ".").rstrip("/") or "."
        for directory in handed:
            name = directory.rstrip("/")
            landed = target if len(handed) == 1 else f"{target}/{name}".removeprefix("./")
            assert landed == name, (key, directory, "lands at", landed)
        for i in publishes:
            assert steps[i]["with"]["packages-dir"] in handed, (key, steps[i]["with"])
    assert len(bodies) == 1, "the publish jobs' digest checks differ; they must be one body"


def _run_verify(tmp_path: Path, files: dict[str, bytes], manifest: str) -> tuple[int, str]:
    work = tmp_path / "work"
    for name, data in files.items():
        (work / name).parent.mkdir(parents=True, exist_ok=True)
        (work / name).write_bytes(data)
    work.mkdir(exist_ok=True)
    script = tmp_path / "verify.sh"
    # The engine publish job's copy; the test above holds every copy to the same body.
    body = next(
        s["run"]
        for s in _jobs()["publish-pypi"]["steps"]
        if str(s.get("name", "")).startswith(_VERIFY_PREFIX)
    )
    script.write_bytes(body.encode("utf-8"))
    env = {
        **_posix_tool_env(),
        "EXPECTED": manifest,
        "RUNNER_TEMP": str(tmp_path).replace("\\", "/"),
    }
    rc, out = _run_leak_gate(require_bash(tmp_path, env), work, script, env)
    assert rc not in (126, 127), explain_returncode(rc, "the digest check") + "\n" + out
    return rc, out


def _sha(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


_FILES = {"dist-pub/a.whl": b"wheel\n", "toolkit-dist/b.whl": b"toolkit\n"}
_MANIFEST = "\n".join(f"{_sha(d)}  {n}" for n, d in _FILES.items())


@pytest.mark.parametrize(
    ("files", "manifest", "ok", "needle"),
    [
        (_FILES, _MANIFEST, True, "verified 2 file(s)"),
        ({**_FILES, "dist-pub/a.whl": b"other\n"}, _MANIFEST, False, "FAILED"),
        ({**_FILES, "dist-pub/extra.whl": b"x\n"}, _MANIFEST, False, "not exactly the gated set"),
        ({"dist-pub/a.whl": _FILES["dist-pub/a.whl"]}, _MANIFEST, False, "toolkit-dist/b.whl"),
        (_FILES, "", False, "handed over no digests"),
    ],
    ids=["match", "changed-byte", "extra-file", "missing-file", "no-digests"],
)
def test_the_digest_check_refuses_anything_but_the_gated_files(
    tmp_path: Path, files: dict[str, bytes], manifest: str, ok: bool, needle: str
) -> None:
    """EXECUTED. `match` is the positive control for the four refusals."""
    rc, out = _run_verify(tmp_path, files, manifest)
    assert (rc == 0) is ok, f"exit {rc}:\n{out}"
    assert needle in out, out
