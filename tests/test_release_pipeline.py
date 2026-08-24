# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

Sections (1) to (6) are pure text / `re` / `tomllib` checks; section (7) additionally shells out to bash
and `tar` over tarballs it builds with `tarfile`. Neither needs `python -m build` or the network, so they
run everywhere the suite runs. They do NOT and cannot assert the artifacts are actually
built/signed/SBOM'd/uploaded — that remains a CI-leg claim validated by the workflow_dispatch dry-run +
a `vX.Y.Z-rc1` pre-release tag.
"""

from __future__ import annotations

import gzip
import io
import os
import re
import subprocess
import tarfile
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest
from _bash_resolver import bash_candidates, explain_returncode, require_bash

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
    # The boundary is DERIVED rather than the name of whichever job happened to follow: this read
    # `rel.split("\n  release-harness:")`, so inserting release-webconsole between the two silently
    # widened the slice to include it and the assertion then measured the WRONG job's last step.
    _start = rel.index("\n  release:") + 1
    _next = re.search(r"^  [a-z][\w-]*:$", rel[_start:], re.M | re.I)
    _after = re.search(
        r"^  [a-z][\w-]*:$", rel[_start + (_next.end() if _next else 0) :], re.M | re.I
    )
    assert _after, "could not find the job after `release` — the workflow shape moved"
    release_job = rel[_start:][: (_next.end() if _next else 0) + _after.start()]

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
    #
    # This order is load-bearing, not cosmetic: the GitHub release is REVERSIBLE (deletable) and the
    # PyPI upload is not (a version number is burned forever). Doing the reversible half first is what
    # made the v0.3.1 publisher failure recoverable at all — a failed publish left a release we could
    # delete and retry, rather than an un-retryable PyPI version with no release.
    def idx(tok: str) -> int:
        i = release_job.find(tok)
        assert i != -1, f"expected marker missing from release job: {tok!r}"
        return i

    order = [
        idx("Build sdist + wheel"),
        idx("Leak gate — sdist MUST be package-only"),
        idx("python -m sigstore sign"),
        idx("Create or update the GitHub release"),
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
    its `built` is parsed out of the already-normalised wheel FILENAME.
    """
    rel = _release()
    assert '[ "$built" = "$want" ]' not in rel, (
        "a raw string compare of tag vs built version is back; it rejects canonical pre-release "
        "versions (0.3.0rc1 != 0.3.0-rc1) and blocks every rc tag"
    )
    # DERIVED, not hardcoded. This read `== 2` and broke the day a third wheel job (the separately
    # versioned console) was added — a guard that must be edited whenever the thing it guards grows is
    # a guard that gets its number bumped without thought. The property worth pinning is "EVERY wheel
    # smoke normalises", so count the jobs that actually build a wheel and require one comparison each,
    # plus the engine's own. A new wheel job carrying a string compare now fails HERE.
    wheel_builds = rel.count("python -m build --wheel")
    assert wheel_builds >= 2, f"expected the harness + console wheel builds, found {wheel_builds}"
    assert rel.count("from packaging.version import") == wheel_builds + 1, (
        f"every wheel smoke must compare PEP 440 versions — {wheel_builds} wheel-building job(s) plus "
        f"the engine smoke require {wheel_builds + 1} comparisons, found "
        f"{rel.count('from packaging.version import')}. Fixing only one moves the failure rather than "
        f"removing it."
    )


# --- the separately-versioned web console (ASVS 15.2.4) --------------------------------------------


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
    one. A ``needs`` here would silently couple two cadences the design separates."""
    assert "needs" not in _jobs()["release-webconsole"], (
        "release-webconsole must not depend on the engine release — the console has its own cadence"
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
    assert "messagefoundry_webconsole-" in console, "it must read the CONSOLE wheel's version"


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
        if "release" in (jobs[name].get("needs") or []):
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
    body = RELEASE_YML.read_text(encoding="utf-8")
    code = "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith("#"))
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


def _leak_gate_script() -> str:
    """The leak gate's ``run:`` block, taken from the PARSED workflow rather than sliced out of the text.

    Exactly one step may match. Two would mean the extractor is choosing between them arbitrarily, and a
    harness that silently exercises the wrong step is worse than no harness at all.
    """
    steps = [
        step
        for job in _jobs().values()
        for step in (job.get("steps") or [])
        if isinstance(step, dict) and str(step.get("name") or "").startswith(_LEAK_GATE_STEP_PREFIX)
    ]
    assert len(steps) == 1, (
        f"expected exactly one release.yml step whose name starts with {_LEAK_GATE_STEP_PREFIX!r}, "
        f"found {len(steps)} — the execution tests below cannot know which one to run"
    )
    run = steps[0].get("run")
    assert isinstance(run, str) and run.strip(), (
        "the leak gate step has no `run:` script to execute"
    )
    return run


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
    execution tests below would exercise the wrong thing and stay green while doing it."""
    script = _leak_gate_script()
    for token in ("dist/*.tar.gz", "tar tzf", "grep -vE"):
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
