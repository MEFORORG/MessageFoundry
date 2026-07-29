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
