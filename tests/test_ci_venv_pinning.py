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

SCOPE, stated so it is a boundary rather than an oversight: the version-pin rule is the RELEASE path.
`security.yml` keeps its `--upgrade pip` bootstraps, registered in `SECURITY_YML_ACCEPTED_UNPINNED`
rather than pinned, so a NEW unpinned install there still fails — the exception is enumerated, not
open-ended. Two `security.yml` installs are held to the release rule anyway: the SBOM step, because
ADR 0034 makes it the pre-tag dry-run for `release.yml`'s and the two must stay the same command; and
the scanners the blocking jobs install for themselves (below).

**Correction, 2026-07-29.** This module previously registered `uv` and `pip-audit` as accepted-unpinned
on the reasoning that `security.yml`'s jobs are "schedule/dispatch-only" and "produce nothing anyone
installs". The first half is **wrong**: `security.yml` triggers on `pull_request` and seven of its jobs
are REQUIRED contexts, `pip-audit` among them. So those two installs were unpinned dependency intake
inside the very gate whose purpose is proving nothing unpinned enters the tree, running on every PR —
and `uv` is the resolver that produces every lockfile that job then audits, so an implicit upgrade can
change the exported set and red the `git diff --exit-code` for a reason unrelated to the change. Both
are now `==`-pinned and removed from the registry. `semgrep` is pinned exactly for the same reason a
range is not a pin here: a new 1.x can add rules or change taint propagation and red a green PR.

The gitleaks/trivy downloads are the non-pip half of the same intake, covered by
`test_release_asset_downloads_in_blocking_jobs_are_checksum_verified` at the end of this module.

**Amendment, 2026-07-29 — the CI toolchain moved into a PEP 735 dependency group.**

A version pin does not satisfy Scorecard's `PinnedDependenciesID`; this repo's own alert data proves it
(`bandit==1.9.4` is alert #74 and `zizmor==1.5.2` is alert 96, both exactly pinned and both flagged,
while the two `--require-hashes` installs are flagged in neither the open nor the dismissed set). So
`bandit`, `pip-audit`, `zizmor`, `mutmut`, `diff-cover` and `pytest-cov` now live in
`pyproject.toml`'s `[dependency-groups]`, flow into `uv.lock`, and are `uv export`ed to
`ci/locks/ci-scanners.lock` / `ci/locks/ci-quality.lock` WITH hashes. The workflows install them with
`pip install --require-hashes -r <lock>`. `bandit` and `pip-audit` were consequently dropped from
`RELEASE_PINNED_TOOLS` — deliberately, in this same commit, exactly as that check's own failure
message instructs.

**The blindness that creates, and what closes it.** `_install_targets()` skips `-r` *and its
argument*, so `pip install --require-hashes -r ci/locks/ci-scanners.lock` names ZERO targets: it
passes every scan in the first half of this module by being invisible to it, not by being verified.
`test_lock_installed_toolchain_*` and `test_*_moved_tool*` below are what actually look at those
lines. In particular `test_lock_installed_toolchain_locks_are_in_the_dep1_set` is the guard against
ADR 0034 §3's stated failure mode — a hand-maintained lock outside the DEP-1 export/resync machinery
rotting into a pinned, stale, *unpatched* toolchain, which is worse posture than floating.

**What moving those two rows out of `RELEASE_PINNED_TOOLS` cost, and what pays it back.** That table was
the only check that rejected a *floor* (`_PIN_OPS` deliberately excludes `>=`), so its removal left the
`==` requirement on `bandit`/`pip-audit`/`zizmor` enforced by nothing: asserting the name is declared
does not see a floor, and asserting the *exported lock* is `==`-pinned cannot see one either, because
`uv export` writes `bandit==1.9.4` from `bandit>=1.9.4` just as readily. `EXACT_GROUP_PINS` /
`FLOOR_BY_DESIGN` restore it at the declaration, where the decision now lives. Three further holes the
2026-07-29 adversarial pass found and this module now closes, each verified by injecting the regression:
the install-site COUNT (five sites collapsed onto three table rows, so four were individually
deletable), the export SELECTOR (`--group` for `--only-group` pulls the whole project runtime into a
blocking scanner's install closure while staying pinned, hashed and byte-identical under DEP-1), and
group names LEAKING into the four runtime exports (`--no-dev` only filters the group literally named
`dev`, so it is not the protection it looks like).

`semgrep` is deliberately NOT in a group and stays a version-pinned inline install: it hard-conflicts
with the project's own `[otel]` extra, and the only resolution (`[tool.uv] conflicts`) would declare a
shipped product extra and a CI scanner permanently mutually exclusive. Recorded as a reasoned residual
in ADR 0034 §3, which is why it is still in `RELEASE_PINNED_TOOLS`.
"""

from __future__ import annotations

import re
import tomllib
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

#: Any `pip install`, in any spelling that reaches a shell: `pip install`, `pip3 install`,
#: `python -m pip install`, `<venv>/bin/pip install`, and with flags BEFORE the subcommand
#: (`pip --quiet install X`). Matching only `pip install` would let any of the others through, and a
#: line this regex does not match is a line the scan below never examines — a silent hole, not a
#: failure.
_PIP_INSTALL = re.compile(r"\bpip3?\s+(?:-\S+\s+)*install\b")

#: A PIN. `==` fixes the version; `~=X.Y.Z` fixes everything but the patch. `$PKG_PIN` counts — it is
#: read out of constraints.lock at run time (the quality-advisory.yml ruff-pin pattern), which is MORE
#: current than a literal, not less.
#:
#: `>=`, `<=` and `!=` are deliberately NOT here. They are FLOORS, not pins: `pip install
#: "sigstore>=4.4.0"` resolves whatever PyPI serves at tag time, which is exactly the exposure this
#: module exists to prevent (ADR 0034 §3 calls it "the highest residual in the group … runs with the
#: OIDC identity used to publish"). Accepting them would have let that regression pass green under a
#: test named `test_release_toolchain_pin_is_present`. If a genuine range is ever wanted here, exempt
#: it by name — do not widen this tuple.
_PIN_OPS = ("==", "~=")

#: Every PEP 508/440 operator that can bind a version to a NAME. Used only to recognise that a token
#: like `sigstore>=4.4.0` is still a `sigstore` install — so an unpinned one is reported as unpinned
#: rather than as a missing step.
_SPEC_OPS = ("===", "==", "~=", ">=", "<=", "!=", "<", ">", "@", "[")

#: Install targets that legitimately name no version: a path (the artifact under test) and the
#: hash-verified lock installs, where every version is pinned INSIDE the lock.
_EXEMPT_TARGETS = frozenset({"."})

#: VCS/URL scheme prefixes. A target pip fetches over the network by URL is unpinnable BY CONSTRUCTION
#: — there is no version specifier to add — so it is always reported, never shape-exempted.
_REMOTE_SCHEMES = ("git+", "hg+", "svn+", "bzr+")

#: Tools whose release-path pin must EXIST — the non-vacuity backstop for the scan above. Deleting a
#: step would otherwise make the scan pass by finding nothing left to check.
RELEASE_PINNED_TOOLS = (
    ("release.yml", "sigstore"),
    ("release.yml", "build"),
    ("release.yml", "pip"),
    ("release.yml", "cyclonedx-bom"),
    ("release.yml", "packaging"),
    ("security.yml", "cyclonedx-bom"),
    # The scanners the BLOCKING jobs install for themselves. These run on every `pull_request` and
    # three of them back required contexts, so they are held to the release rule despite not being on
    # the release path — see the 2026-07-29 correction in the module docstring.
    #
    # `uv` is the resolver that produces every lock this repo commits, so it cannot be hash-locked BY
    # that lock (circular by construction) and stays an inline `==` pin. `semgrep` stays inline by
    # decision (the `[otel]` conflict — see the amendment). `bandit` and `pip-audit` were HERE until
    # 2026-07-29 and are now installed from `ci/locks/ci-scanners.lock` instead; they are checked by
    # `LOCK_INSTALLED_TOOLCHAINS` + `MOVED_TO_A_GROUP` below, not by this table.
    ("security.yml", "uv"),
    ("security.yml", "semgrep"),
)

#: `security.yml`'s OWN unpinned installs, registered rather than pinned. Only the `pip` bootstraps
#: remain: `python -m pip install --upgrade pip` alongside a pinned tool, where pip is the installer
#: rather than an input to any gate's verdict. Registering it means a NEW unpinned install added to
#: that file still reds `test_security_yml_unpinned_installs_are_registered` — the exception is a
#: decision someone made, not a gap nobody noticed. (`pip` also appears PINNED in that file's SBOM
#: step, which must stay byte-identical to release.yml's — see the twin test below.)
#:
#: `uv` and `pip-audit` were HERE until 2026-07-29 and are now pinned instead; the reasoning that put
#: them here — that this file's jobs are schedule/dispatch-only — was factually wrong (it triggers on
#: `pull_request` and `pip-audit` is a required context). See the module docstring.
#:
#: TWO `--upgrade pip` bootstraps are left in the file, not one — counted, because an inventory that
#: undercounts is how a residual becomes invisible: the `uv` install in the DEP-1 step, and the
#: `semgrep` install (`python -m pip install --upgrade pip "semgrep==1.172.0"`, whose *semgrep* pin is
#: registered above in `RELEASE_PINNED_TOOLS` while its unpinned `pip` half is registered HERE). The
#: other two went away with their steps rather than being pinned: the `bandit` and `pip-audit` installs
#: are now `pip install --require-hashes -r ci/locks/ci-scanners.lock`, and that lock hash-pins `pip`
#: itself — so a hash-verified pip arrives in the same command that used to fetch an unverified one.
SECURITY_YML_ACCEPTED_UNPINNED = frozenset({"pip"})

#: How many `--upgrade pip` bootstraps `security.yml` is KNOWN to still carry. An exact count, not a
#: floor: `SECURITY_YML_ACCEPTED_UNPINNED` registers the *name* `pip`, so it cannot distinguish two
#: accepted bootstraps from twenty. Both survivors are named in the docstring above and in ADR 0034 §3's
#: residuals table; a third must be a decision, and lowering this number is the receipt for removing one.
SECURITY_YML_PIP_BOOTSTRAPS = 2

#: ``(workflow, lock, install sites)`` triples where a CI toolchain is installed from a hash-pinned
#: `uv export`.
#:
#: These lines are INVISIBLE to every scan in the first half of this module: `_install_targets` skips
#: `-r` and its argument, so `pip install --require-hashes -r <lock>` names zero packages and passes by
#: not being looked at. The tests below are the ones that look.
#:
#: THE COUNT IS LOAD-BEARING, not decoration. Five install sites collapse onto three (workflow, lock)
#: pairs — `security.yml` installs `ci-scanners.lock` twice (the pip-audit step and the bandit step) and
#: `quality-advisory.yml` installs `ci-quality.lock` twice (the coverage job and the mutation job). An
#: `assert lines` non-vacuity check is satisfied by ONE surviving line, so deleting either of a pair
#: leaves its job installing nothing while every check here stays green. Measured: with only "≥1", four
#: of the five sites were individually deletable at zero test cost — and the coverage job's failure mode
#: is silent (`pytest -q --cov` dies on `unrecognized arguments`, `|| true` swallows it, and the
#: diff-coverage step reports "skipped" and exits 0).
LOCK_INSTALLED_TOOLCHAINS = (
    ("security.yml", "ci/locks/ci-scanners.lock", 2),
    ("zizmor.yml", "ci/locks/ci-scanners.lock", 1),
    ("quality-advisory.yml", "ci/locks/ci-quality.lock", 2),
)

#: Tools that MOVED from an inline `pip install <tool>==<version>` into a PEP 735 dependency group. Two
#: directions need guarding, and neither is visible to anything else: the declaration silently
#: disappearing from `pyproject.toml` while the lock still carries the name as somebody else's
#: transitive, and a future edit re-adding an inline `pip install bandit` beside the lock install.
MOVED_TO_A_GROUP = ("bandit", "pip-audit", "zizmor", "mutmut", "diff-cover", "pytest-cov")

#: Moved tools whose `[dependency-groups]` spec must be an EXACT `==` pin, and why the exactness is the
#: contract rather than a preference. This exists because moving `bandit` and `pip-audit` out of
#: `RELEASE_PINNED_TOOLS` deleted the ONLY check that rejected a floor: `test_moved_tools_are_declared_*`
#: asserts the NAME is declared, and `test_lock_installed_toolchain_lock_is_pinned_and_hashed` inspects
#: the EXPORTED lock — which `uv export` writes fully `==`-pinned from a `>=` spec just as readily, so it
#: is structurally blind to the difference. Verified: rewriting all three scanner specs to `>=` re-locked,
#: re-exported byte-identically, and passed every guard in this repo.
#:
#: The failure that buys: a floor means Dependabot's weekly `uv` PR moves a blocking gate's version
#: inside `uv.lock` with NO `pyproject.toml` diff to review, `dependabot-lock-resync.yml` re-exports and
#: stages the new lock automatically, and a required gate's findings baseline changes GREEN.
EXACT_GROUP_PINS = ("bandit", "pip-audit", "zizmor", "diff-cover", "mutmut")

#: The counterpart: moved tools deliberately declared as a FLOOR. Enumerated so "floor by design" and
#: "floor nobody noticed" cannot look the same.
#:
#: `pytest-cov` — nothing parses its output; it only has to emit a `coverage.xml` that `diff-cover`
#: reads, so it is floored at the current major and left free for Dependabot to move.
#: `pytest-timeout` — deliberately the IDENTICAL spec to `[project.optional-dependencies].dev`, so the
#: hashed toolchain install cannot re-point the plugin the coverage run already executes under.
FLOOR_BY_DESIGN = ("pytest-cov", "pytest-timeout")


def _install_targets(line: str) -> list[str]:
    """The package tokens a ``pip install`` line names — flags, and the arguments of flags that take
    one, removed. Everything left is something pip will resolve.

    Anchored on the same regex that selected the line, rather than splitting on a literal ``"
    install "``: the literal disagrees with the regex on `pip\tinstall` and on flags placed before the
    subcommand, and disagreeing means an IndexError instead of a readable failure.
    """
    match = _PIP_INSTALL.search(line)
    if match is None:  # pragma: no cover - callers filter on the same regex
        return []
    return _tokens_after(line[match.end() :])


def _tokens_after(rest: str) -> list[str]:
    """The install targets in the tail of an install command — flags, and the arguments of flags that
    take one, removed. Shared by the ``pip`` and ``pipx`` scans so the two cannot disagree about what
    counts as a target."""
    targets: list[str] = []
    skip_next = False
    for tok in rest.split():
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


def _is_remote(target: str) -> bool:
    """A URL / VCS target. Checked BEFORE any path shape test: a remote wheel URL ends in ``.whl`` and
    contains ``/`` exactly like the local artifact under test, so a shape test alone would exempt the
    one class of target that can never carry a pin."""
    return "://" in target or target.startswith(_REMOTE_SCHEMES)


def _needs_a_pin(target: str) -> bool:
    """True when pip resolves this target from an index (so it must name a version) or fetches it from
    the network (so it can never be pinned and is always reported)."""
    if target in _EXEMPT_TARGETS:
        return False
    if _is_remote(target):
        return True
    return "/" not in target and not any(op in target for op in _PIN_OPS)


def test_release_path_pip_installs_name_a_version() -> None:
    """EVERY package `release.yml` installs must carry a version specifier.

    A blanket scan, not a name list, so a NEW unpinned install added tomorrow fails too — the failure
    mode a fixed table cannot see. Local path installs (``dist/*.whl``) and ``-r <lock>`` installs are
    exempt: the first is the artifact under test, the second is pinned inside the lock. A URL or
    ``git+`` target is NOT exempt — it is unpinnable and therefore always reported.
    """
    lines = [ln for ln in _code_lines(_WORKFLOWS / "release.yml") if _PIP_INSTALL.search(ln)]
    # Non-vacuity: this file HAS a toolchain to pin, and the floor is the ACTUAL count, not a slack
    # one — at `>= 6` two whole install steps could be deleted before the check noticed. Consolidating
    # installs is fine; re-point this number in the same commit so the decision stays deliberate.
    assert len(lines) >= 8, (
        f"release.yml now has only {len(lines)} pip installs — either the scan has stopped matching "
        f"them or steps were removed; re-point this floor rather than letting it pass on a shrunken "
        f"set.\n" + "\n".join(lines)
    )

    unpinned = [
        (ln, target) for ln in lines for target in _install_targets(ln) if _needs_a_pin(target)
    ]
    assert not unpinned, (
        f"release.yml installs these WITHOUT a pin: {unpinned}. This workflow's jobs hold "
        f"contents/id-token/attestations: write and sign + publish the release artifacts, so an "
        f"unpinned resolve here takes whatever PyPI serves at tag time (Scorecard "
        f"PinnedDependenciesID; ADR 0034 §3). Pin it with `==`/`~=`, or derive the pin from "
        f"constraints.lock the way the `packaging` installs do. `>=` is NOT a pin. A URL/git+ target "
        f"cannot be pinned at all — install it from an index instead."
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
        # _SPEC_OPS, not _PIN_OPS, on purpose: `sigstore>=4.4.0` must be recognised AS a sigstore
        # install so the pin check below reports it. Matching on _PIN_OPS alone would read it as "the
        # step is gone" — a different, misleading failure.
        if target == package or target.startswith(tuple(f"{package}{op}" for op in _SPEC_OPS))
    ]
    assert hits, (
        f"{workflow} no longer installs {package!r} — if the step was removed on purpose, drop it "
        f"from RELEASE_PINNED_TOOLS in the same commit; otherwise this guard just went blind."
    )
    unpinned = [ln for ln, target in hits if not any(op in target for op in _PIN_OPS)]
    assert not unpinned, (
        f"{workflow} installs {package!r} without a `==`/`~=` pin at: {unpinned}. Dependabot cannot "
        f"bump an inline `pip install` in a workflow, so an unpinned one here is never even noticed; "
        f"a `>=` floor resolves to whatever PyPI serves at tag time and is not a pin."
    )


def test_security_yml_unpinned_installs_are_registered() -> None:
    """`security.yml`'s remaining unpinned installs are a registered set, so a new one still fails.

    The disclosure matters: `security.yml` keeps `--upgrade pip` bootstraps alongside its now-pinned
    tools, where pip is the installer rather than an input to any gate's verdict. Recording that is the
    difference between a scope boundary and an oversight.
    """
    lines = [ln for ln in _code_lines(_WORKFLOWS / "security.yml") if _PIP_INSTALL.search(ln)]
    assert lines, "security.yml has no pip installs — this guard is no longer looking at anything"
    unregistered = sorted(
        {
            target
            for ln in lines
            for target in _install_targets(ln)
            if _needs_a_pin(target) and target not in SECURITY_YML_ACCEPTED_UNPINNED
        }
    )
    assert not unregistered, (
        f"security.yml gained unpinned install target(s) {unregistered}. Pin them, or add them to "
        f"SECURITY_YML_ACCEPTED_UNPINNED with the reason — the point of the registry is that the "
        f"exception is a decision someone made, not a gap nobody noticed."
    )


# --- the CI toolchain installed from a hash-pinned dependency-group lock ---------------------------


def _dist_name(spec: str) -> str:
    """The distribution name from a PEP 508 requirement string (`"mutmut==3.6.0"` -> `"mutmut"`)."""
    match = re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]*", spec.strip())
    return match.group(0) if match else ""


def _dependency_groups() -> dict[str, list[str]]:
    """``[dependency-groups]`` -> group name -> its requirement STRINGS.

    PEP 735 lets an entry be a ``{include-group = "other"}`` table rather than a requirement string;
    those are dropped here (the included group is iterated on its own anyway).
    """
    groups = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8")).get(
        "dependency-groups"
    )
    assert groups, (
        "pyproject.toml declares no [dependency-groups] — the CI toolchain lost its source"
    )
    return {
        name: [spec for spec in (specs or []) if isinstance(spec, str)]
        for name, specs in groups.items()
    }


def _group_spec(package: str) -> str:
    """The PEP 508 spec ``package`` is declared with in ``[dependency-groups]``.

    Raises rather than returning a default: "the declaration is gone" and "the declaration is unpinned"
    must not produce the same result.
    """
    for specs in _dependency_groups().values():
        for spec in specs:
            if _dist_name(spec) == package:
                return spec.strip()
    raise AssertionError(f"{package!r} is not declared in any [dependency-groups] entry")


def _project_declared_names() -> set[str]:
    """Every distribution declared in ``[project]`` — runtime deps plus every extra.

    A name declared BOTH in `[project]` and in a dependency group (today: `pytest-timeout`, held
    deliberately identical to the `dev` extra) legitimately appears in the runtime exports, so the leak
    check below must not treat it as a leak.
    """
    project = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8")).get(
        "project", {}
    )
    specs: list[str] = list(project.get("dependencies") or [])
    for extra_specs in (project.get("optional-dependencies") or {}).values():
        specs.extend(extra_specs or [])
    return {_dist_name(spec) for spec in specs if _dist_name(spec)}


def _names_target(line: str, package: str) -> bool:
    """Does this `pip install` line name ``package`` as a target (bare, or with a version spec)?"""
    return any(
        target == package or target.startswith(tuple(f"{package}{op}" for op in _SPEC_OPS))
        for target in _install_targets(line)
    )


def _locked_requirements(lock: Path) -> list[tuple[str, int]]:
    """Each requirement in a `uv export`, paired with how many `--hash=sha256:` lines it OWNS.

    Structural, per requirement, rather than a whole-file substring search. A `"--hash=sha256:" in
    text` check passes on a lock carrying 33 pinned packages and ONE hash — which is precisely the
    unverified-install shape it is supposed to be catching. (Learned the hard way: that weaker form
    stayed green under an injected regression while the six sibling guards all went red.)

    `uv export` emits `name==version \\` followed by indented `--hash=` continuations, then an optional
    `# via ...` comment.

    Any OTHER leading-dash directive is a hard failure rather than a skip. `-e .`, `--index-url`,
    `--extra-index-url` and `--find-links` all change what pip actually resolves, and a directive that is
    neither counted as a requirement nor rejected is invisible to the very guard whose point is not being
    fooled by a lock's shape.
    """
    out: list[tuple[str, int]] = []
    for raw in lock.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("--hash="):
            if out:  # a hash before any requirement would be malformed; ignore rather than crash
                name, count = out[-1]
                out[-1] = (name, count + 1)
        elif line.startswith("-"):
            raise AssertionError(
                f"{lock.name} carries the directive {line!r}, which is neither a requirement nor a "
                f"`--hash=` line. An index redirect or an editable/project line changes what pip "
                f"resolves and would otherwise pass through this parser uncounted — decide about it "
                f"here rather than letting it be silently ignored."
            )
        else:
            out.append((line.removesuffix("\\").strip(), 0))
    return out


def _exported_names(export: Path) -> list[str]:
    """The `name==version` requirement lines of ANY `uv export`, hashed or not.

    Deliberately separate from `_locked_requirements`: that one is strict about directives because it
    guards a `--require-hashes` install, whereas `constraints.lock` is legitimately `--no-hashes` and is
    only read here for WHICH names it contains.
    """
    return [
        line.removesuffix("\\").strip()
        for raw in export.read_text(encoding="utf-8").splitlines()
        if (line := raw.strip()) and not line.startswith(("#", "-"))
    ]


@pytest.mark.parametrize(("workflow", "lock", "sites"), LOCK_INSTALLED_TOOLCHAINS)
def test_lock_installed_toolchain_install_is_hash_verified(
    workflow: str, lock: str, sites: int
) -> None:
    """Installing FROM a hashed lock buys nothing unless `--require-hashes` is actually passed.

    Without the flag pip treats the file as an ordinary requirements list, ignores every `--hash=`
    line, and is free to resolve a different artifact — a silently unpinned install that still reads
    like a pinned one at a glance.

    The site COUNT is asserted exactly, not as "at least one": see LOCK_INSTALLED_TOOLCHAINS. A `>= 1`
    check is satisfied by one survivor of a pair, so it cannot see a job losing its only install.
    """
    lines = [
        ln for ln in _code_lines(_WORKFLOWS / workflow) if _PIP_INSTALL.search(ln) and lock in ln
    ]
    print(f"[ci-venv-pinning] {workflow}: {len(lines)} install site(s) for {lock}")
    # Non-vacuity AND completeness: a renamed lock, a restructured step, or a DELETED sibling install
    # must fail loudly rather than pass by matching only what is left.
    assert len(lines) == sites, (
        f"{workflow} installs {lock} at {len(lines)} site(s), expected {sites}. If a job legitimately "
        f"gained or lost its toolchain install, update the count in LOCK_INSTALLED_TOOLCHAINS in the "
        f"same commit — a job silently left with no install still passes every other check here, and "
        f"in the coverage job it fails INVISIBLY (`|| true` swallows the missing --cov plugin)."
    )
    for ln in lines:
        assert "--require-hashes" in ln, (
            f"{workflow} installs {lock} WITHOUT --require-hashes: {ln!r}. The hashes in the lock are "
            f"inert unless the flag is passed, so this is an unpinned install wearing a lock's clothes."
        )


@pytest.mark.parametrize(("workflow", "lock", "sites"), LOCK_INSTALLED_TOOLCHAINS)
def test_lock_installed_toolchain_lock_is_pinned_and_hashed(
    workflow: str, lock: str, sites: int
) -> None:
    """The lock itself must be fully `==`-pinned AND carry hashes.

    Blocks substituting a `--no-hashes` export (the shape `constraints.lock` legitimately has, because
    pip rejects hashes in a `--constraint` file): that would keep the filename, keep the
    `--require-hashes` flag, and fail closed at install time instead of silently — but the failure
    would first appear in CI rather than here.
    """
    path = _REPO / lock
    assert path.is_file(), f"{workflow} installs {lock}, which is not committed"
    reqs = _locked_requirements(path)
    total_hashes = sum(n for _, n in reqs)
    print(
        f"[ci-venv-pinning] {lock}: {len(reqs)} requirements, {total_hashes} hashes "
        f"({sites} install site(s) in {workflow})"
    )
    assert reqs, (
        f"{lock} declares no requirements — an empty lock installs nothing and proves nothing"
    )
    unpinned = [name for name, _ in reqs if "==" not in name]
    assert not unpinned, f"{lock} has requirement lines without an `==` pin: {unpinned}"
    # EVERY requirement, not "the file contains a hash somewhere" — see _locked_requirements.
    unhashed = [name for name, count in reqs if count == 0]
    assert not unhashed, (
        f"{lock} pins these with `==` but carries NO `--hash=` line for them: {unhashed}. Under "
        f"`--require-hashes` pip would reject the file outright, so this is a CI break rather than a "
        f"silent hole — but a lock exported with `--no-hashes` defeats the whole point of routing the "
        f"toolchain through uv.lock (ADR 0034 §3), and it should fail here rather than in the runner."
    )


@pytest.mark.parametrize("lock", sorted({lock for _, lock, _ in LOCK_INSTALLED_TOOLCHAINS}))
def test_lock_installed_toolchain_locks_are_in_the_dep1_set(lock: str) -> None:
    """Each toolchain lock must be REGENERATED and diff-gated by DEP-1, not hand-maintained.

    This is the guard against ADR 0034 §3's stated failure mode: "a hand-maintained fifth lock outside
    that machinery would rot into a pinned, STALE, UNPATCHED toolchain — worse posture than floating".
    A hash-pinned toolchain is only an improvement while something keeps it fresh.

    Only the gate half is asserted here; `tests/test_dep1_lock_resync_lockstep.py` then forces the
    Dependabot resync to export, short-circuit on, and stage the identical set.

    THE SELECTOR IS PART OF THE CONTRACT, not just the `-o` path. A `.*` between `uv export` and `-o`
    accepts `--group` in place of `--only-group`, and `--group` is additive: it emits the PROJECT's whole
    closure plus the group. Measured — `uv export --group ci-scanners -o ci/locks/ci-scanners.lock` grows
    the lock from 33 to 69 requirements, pulling `fastapi`, `uvicorn`, `hl7`, `httpx` and `aiosqlite`
    into what the BLOCKING bandit and zizmor jobs install — and it is fully `==`-pinned and fully hashed,
    so it passed every other guard here, passed the resync lockstep, and re-exported byte-identically
    under DEP-1. Nothing went red. The group name is also required to MATCH the lock's stem: without it,
    `--only-group ci-quality -o ci/locks/ci-scanners.lock` is equally green.
    """
    group = Path(lock).stem
    body = (_WORKFLOWS / "security.yml").read_text(encoding="utf-8")
    pattern = rf"^\s*uv export --only-group {re.escape(group)} --format requirements\.txt -o {re.escape(lock)}\s*$"
    assert re.search(pattern, body, re.MULTILINE), (
        f"security.yml's DEP-1 step does not export {lock} with exactly "
        f"`uv export --only-group {group} --format requirements.txt -o {lock}`. Either nothing "
        f"regenerates it (so the drift gate never compares it, and a stale hash-pinned toolchain is "
        f"worse than a floating one), or the SELECTOR changed: `--group` is additive and would pull the "
        f"whole project runtime into a scanner's install closure while staying pinned, hashed and "
        f"byte-identical under DEP-1."
    )


@pytest.mark.parametrize("lock", sorted({lock for _, lock, _ in LOCK_INSTALLED_TOOLCHAINS}))
def test_each_group_pin_reaches_its_own_lock(lock: str) -> None:
    """Every spec declared in group `<stem>` must appear `==`-pinned in `ci/locks/<stem>.lock`.

    The second half of the selector guard, from the other direction: this is what catches a lock exported
    from the WRONG group (the filename says `ci-scanners`, the export said `--only-group ci-quality`) and
    a pin bumped in `pyproject.toml` without a re-export — which would leave the declared version and the
    installed version disagreeing, with `pyproject.toml` reading as the source of truth it no longer is.
    """
    group = Path(lock).stem
    specs = _dependency_groups().get(group)
    assert specs, f"[dependency-groups] has no `{group}` entry, but {lock} is exported from it"
    locked = {name.split("==", 1)[0] for name, _ in _locked_requirements(_REPO / lock)}
    text = (_REPO / lock).read_text(encoding="utf-8")
    print(f"[ci-venv-pinning] {group}: {len(specs)} declared spec(s) checked against {lock}")
    for spec in specs:
        name = _dist_name(spec)
        assert name in locked, (
            f"{lock} does not contain {name!r}, which `[dependency-groups].{group}` declares. The lock "
            f"was exported from a different group, or is stale — re-run the DEP-1 exports."
        )
        if "==" in spec:
            version = spec.split("==", 1)[1].strip().strip("\"'")
            assert re.search(rf"^{re.escape(name)}=={re.escape(version)}\b", text, re.MULTILINE), (
                f"`[dependency-groups].{group}` declares {spec!r} but {lock} pins a different version. "
                f"A pin bumped without a re-export means pyproject.toml no longer describes what CI "
                f"installs — re-run the DEP-1 exports in the same commit."
            )


@pytest.mark.parametrize("package", EXACT_GROUP_PINS)
def test_moved_tool_pins_are_exact_not_floors(package: str) -> None:
    """A moved tool's `[dependency-groups]` spec must be `==`, not a floor.

    NOTHING ELSE CHECKS THIS. Moving `bandit`/`pip-audit` out of `RELEASE_PINNED_TOOLS` removed the only
    guard that rejected a floor (`_PIN_OPS` excludes `>=` by design), and the two replacements are blind
    to it: one asserts the NAME is declared, the other inspects the EXPORTED lock — and `uv export`
    writes `bandit==1.9.4` from `bandit>=1.9.4` just as readily. Verified end to end: rewriting all three
    scanner specs to `>=` re-locked, re-exported the two toolchain locks BYTE-IDENTICALLY, and passed
    every guard in this repo.

    Why exactness rather than freshness: each of these versions is the CONTRACT of a gate that can red a
    PR — bandit's `# nosec` parsing is a blocking gate's findings baseline, zizmor's gate asserts a clean
    baseline so a new rule reds an unrelated PR, and the mutation job SHELL-PARSES mutmut's human-readable
    output. A floor lets Dependabot's weekly `uv` PR move any of them with no `pyproject.toml` diff to
    review, since the resync re-exports the lock automatically.
    """
    spec = _group_spec(package)
    assert re.fullmatch(rf"{re.escape(package)}==\d+(\.\d+)*", spec), (
        f"`[dependency-groups]` declares {spec!r}; {package} must be an EXACT `==` pin. `>=` is a FLOOR: "
        f"it re-resolves inside uv.lock on any re-lock, and the exported lock looks identically pinned "
        f"either way. If a floor is genuinely wanted, move {package!r} to FLOOR_BY_DESIGN with the "
        f"reason — do not relax this pattern."
    )


@pytest.mark.parametrize("package", FLOOR_BY_DESIGN)
def test_floored_group_pins_stay_declared(package: str) -> None:
    """The counterpart to EXACT_GROUP_PINS: a floor is a decision, so it must be an enumerated one.

    Asserts only that the entry still EXISTS and is not accidentally exact-pinned without the reason
    moving with it. The point is that reading these two tables together tells you every group spec's
    intended shape — so "floor by design" can never be mistaken for "floor nobody noticed".
    """
    spec = _group_spec(package)
    print(f"[ci-venv-pinning] floor by design: {spec}")
    assert re.fullmatch(rf"{re.escape(package)}(>=|~=)\d+(\.\d+)*", spec), (
        f"`{package}` is listed in FLOOR_BY_DESIGN but declared as {spec!r}. If it was deliberately "
        f"tightened to an exact pin, move it to EXACT_GROUP_PINS with its reason in the same commit."
    )


def test_dependency_groups_do_not_leak_into_the_runtime_exports() -> None:
    """No CI-toolchain name may appear in the four PRE-EXISTING DEP-1 artifacts.

    This is the load-bearing invariant `pyproject.toml` asserts in prose and nothing enforced: the groups
    must stay NON-DEFAULT, because a default group lands in `requirements.lock`, in the container image
    locks that feed BOTH SBOM builds, and in what `pip-audit` audits AS RUNTIME.

    `--no-dev` is NOT the protection it looks like. `uv export --help`: it disables "the development
    dependency group" — the group literally named `dev` — so it does not filter any other default group.
    Measured: adding `default-groups = ["ci-scanners"]` puts `bandit`, `pip-audit` and `zizmor` into
    `requirements.lock` (98 -> 121 requirements) AND into `docker/locks/requirements-core.lock`
    (41 -> 69), the SBOM input, past its `--no-dev`. The two `--all-extras` exports pass neither
    `--no-dev` nor `--no-default-groups`, so they are unguarded by construction — including against the
    most natural mistake available, a group named `dev` mirroring the existing `dev` EXTRA, which is uv's
    implicit default group. In every one of those cases the whole suite still passes and DEP-1 merely
    demands a re-export, then blesses the leak.

    A name declared in BOTH `[project]` and a group is exempt: `pytest-timeout` is deliberately held to
    the identical spec as the `dev` extra, so its presence in the runtime exports is correct.
    """
    runtime_exports = (
        "requirements.lock",
        "constraints.lock",
        "docker/locks/requirements-core.lock",
        "docker/locks/requirements-sqlserver.lock",
    )
    groups = _dependency_groups()
    project_names = _project_declared_names()
    toolchain = {
        _dist_name(spec)
        for specs in groups.values()
        for spec in specs
        if _dist_name(spec) and _dist_name(spec) not in project_names
    }
    assert toolchain, "no CI-toolchain-only names to check — this guard would pass vacuously"
    print(
        f"[ci-venv-pinning] checked {len(runtime_exports)} runtime exports for "
        f"{len(toolchain)} toolchain-only name(s): {sorted(toolchain)}"
    )

    leaks: list[str] = []
    for export in runtime_exports:
        path = _REPO / export
        assert path.is_file(), f"{export} is missing — the DEP-1 artifact set changed"
        names = {name.split("==", 1)[0] for name in _exported_names(path)}
        print(f"[ci-venv-pinning]   {export}: {len(names)} requirements")
        leaks += [f"{export}: {name}" for name in sorted(toolchain & names)]
    assert not leaks, (
        "a [dependency-groups] name reached a RUNTIME export:\n  "
        + "\n  ".join(leaks)
        + "\nThe CI toolchain must stay in NON-DEFAULT groups. Check for a `[tool.uv] default-groups` "
        "entry, or a group named `dev` (uv's implicit default group). A leaked name is in the release "
        "SBOM, the container image locks, and what pip-audit reports as this project's runtime."
    )


@pytest.mark.parametrize("package", MOVED_TO_A_GROUP)
def test_moved_tools_are_declared_in_a_dependency_group(package: str) -> None:
    """Each moved tool is still DECLARED in `[dependency-groups]`, not merely present in the lock.

    The direction this catches: the declaration is deleted while the exported lock still carries the
    name as some other tool's transitive. The install keeps working, the version stops being ours to
    choose, and every other check here still passes.
    """
    groups = tomllib.loads((_REPO / "pyproject.toml").read_text(encoding="utf-8")).get(
        "dependency-groups"
    )
    assert groups, (
        "pyproject.toml declares no [dependency-groups] — the CI toolchain lost its source"
    )
    declared = {
        _dist_name(spec)
        for specs in groups.values()
        for spec in specs or []
        # PEP 735 lets an entry be a `{include-group = "..."}` table rather than a requirement string.
        if isinstance(spec, str)
    }
    print(f"[ci-venv-pinning] [dependency-groups] declares: {sorted(declared)}")
    assert package in declared, (
        f"{package!r} is installed from a ci/locks lock but is no longer declared in any "
        f"[dependency-groups] entry ({sorted(declared)}). It may still resolve as a transitive of "
        f"another tool — in which case its version is no longer a decision this repo makes."
    )


#: `pipx install <tool>` — the OTHER installer in this repo's workflows, and one `_PIP_INSTALL` cannot
#: see (it anchors on `pip`/`pip3`, so `pipx` never matches). Not hypothetical: `quality-advisory.yml`
#: already installs `ruff` with `pipx` twice, so it is in-repo idiom rather than a shape nobody would
#: reach for. `pipx` has no `--require-hashes`, so a moved tool arriving this way is unpinnable.
_PIPX_INSTALL = re.compile(r"\bpipx\s+(?:-\S+\s+)*install\b")


def _pipx_targets(line: str) -> list[str]:
    """The package tokens a ``pipx install`` line names — same token walk as `_install_targets`."""
    match = _PIPX_INSTALL.search(line)
    if match is None:
        return []
    return _tokens_after(line[match.end() :])


def test_no_moved_tool_is_reinstalled_inline() -> None:
    """No moved tool may ALSO be installed by an inline `pip install <tool>` or `pipx install <tool>`.

    The regression: someone adds `pip install bandit` beside the lock install (to debug, or because a
    lock refresh was inconvenient). Both run, the last one wins, and the version that actually executes
    is the unpinned one — while every hash-pinning check above still passes, because they only ever
    look at the lock line.

    TWO blind spots were closed here rather than left implied. (1) The scan covered only the three
    workflows in `LOCK_INSTALLED_TOOLCHAINS`, so `pip install bandit` added to `ci.yml` or `codeql.yml`
    was invisible — it now sweeps EVERY workflow. (2) `_PIP_INSTALL` does not match `pipx install`, which
    this repo already uses, so that spelling defeated the guard entirely.
    """
    workflows = sorted(_WORKFLOWS.glob("*.yml"))
    assert workflows, f"no workflows found under {_WORKFLOWS} — this guard would pass vacuously"
    print(
        f"[ci-venv-pinning] swept {len(workflows)} workflow(s) for inline installs of "
        f"{len(MOVED_TO_A_GROUP)} moved tool(s)"
    )
    offenders = [
        f"{wf.name}: {package} named inline in {ln!r}"
        for wf in workflows
        for ln in _code_lines(wf)
        if _PIP_INSTALL.search(ln) or _PIPX_INSTALL.search(ln)
        for package in MOVED_TO_A_GROUP
        if _names_target(ln, package)
        or any(
            target == package or target.startswith(tuple(f"{package}{op}" for op in _SPEC_OPS))
            for target in _pipx_targets(ln)
        )
    ]
    assert not offenders, (
        "a tool routed through a hash-pinned dependency group is ALSO installed inline:\n  "
        + "\n  ".join(offenders)
        + "\nRemove the inline install; bump the pin in pyproject.toml's [dependency-groups] and "
        "re-export instead. (`pipx` has no --require-hashes at all, so that spelling cannot be pinned.)"
    )


def test_security_yml_pip_bootstrap_count_is_exact() -> None:
    """`security.yml` carries exactly `SECURITY_YML_PIP_BOOTSTRAPS` unpinned `--upgrade pip` fetches.

    `SECURITY_YML_ACCEPTED_UNPINNED` registers the NAME `pip`, so it cannot tell two accepted bootstraps
    from twenty — and the inventory in this module claimed ONE while the file carried TWO (the `uv` install
    in the DEP-1 step and the `semgrep` install). ADR 0034 §3 is the register a future session reads before
    re-dismissing a Scorecard alert, so an inventory that undercounts is how a real finding becomes
    invisible. Counted here so the number cannot drift out of the prose again.
    """
    lines = [ln for ln in _code_lines(_WORKFLOWS / "security.yml") if "--upgrade pip" in ln]
    print(f"[ci-venv-pinning] security.yml --upgrade pip bootstraps: {len(lines)}")
    for ln in lines:
        print(f"[ci-venv-pinning]   {ln}")
    assert len(lines) == SECURITY_YML_PIP_BOOTSTRAPS, (
        f"security.yml has {len(lines)} `--upgrade pip` bootstrap(s), expected "
        f"{SECURITY_YML_PIP_BOOTSTRAPS}: {lines}. Each surviving one is a Scorecard "
        f"PinnedDependenciesID finding that ADR 0034 §3 must name as a residual. Removing one is good "
        f"news — lower the constant. ADDING one needs a reason in that residuals table."
    )


# --- the non-pip half of the same intake: fetched release assets ----------------------------------


def test_release_asset_downloads_in_blocking_jobs_are_checksum_verified() -> None:
    """A version tag says WHICH artifact to fetch, not that the bytes received are that artifact.

    `curl … | tar -xz` inside a required gate executes third-party bytes with no integrity check, and
    it is dependency intake no lockfile in this repo covers — the same class the pip rules above
    address, arriving by a different route. The sbomqs step in this same workflow already verifies
    against the release's own checksums file, so this was unfinished scope rather than an accepted
    risk, and that step is the template any download here must follow.

    Scoped to BLOCKING jobs. An advisory job cannot turn a required context green while compromised,
    so `trivy` (`continue-on-error: true`, schedule/dispatch-gated) is deliberately out — worth
    hardening, but not on this rule.
    """
    yaml = pytest.importorskip("yaml")
    wf = yaml.safe_load((_WORKFLOWS / "security.yml").read_text(encoding="utf-8"))
    jobs = wf.get("jobs") or {}

    checked = 0
    offenders: list[str] = []
    for job_key, job in jobs.items():
        if (job or {}).get("continue-on-error") is True:
            continue
        for step in (job or {}).get("steps") or []:
            raw = str((step or {}).get("run") or "")
            # Comments OUT before matching. The rationale comments in these workflows quote the very
            # command being prohibited — the gitleaks step explains the `curl | tar` it replaced — so a
            # whole-body match reports the explanation as the offence: a detector counting itself.
            body = "\n".join(ln for ln in raw.splitlines() if not ln.strip().startswith("#"))
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

    # Liveness: report what was EXAMINED. "no offenders" and "nothing was scanned" otherwise produce
    # the same green.
    print(f"[ci-venv-pinning] examined {checked} release-asset download step(s) in blocking jobs")
    assert checked > 0, (
        "no blocking job in security.yml downloads a release asset — if that is now true this guard is "
        "obsolete, but an empty scan must not read as a pass"
    )
    assert not offenders, "unverified release-asset download in a blocking job:\n  " + "\n  ".join(
        offenders
    )


def test_sbom_install_is_byte_identical_in_release_and_security() -> None:
    """The two CycloneDX installs must be the SAME command.

    Nothing in PR CI executes `release.yml` (tag push only, ADR 0034 "What no test can see"), so the
    documented way to validate its SBOM step before cutting a tag is to dispatch `security.yml`'s sbom
    job and read that log. That check is only evidence while the two commands are identical — the
    moment they drift, the dry-run proves something about a command the release does not run.
    """
    installs = {}
    for workflow in ("release.yml", "security.yml"):
        matches = [
            ln
            for ln in _code_lines(_WORKFLOWS / workflow)
            if _PIP_INSTALL.search(ln) and "cyclonedx-bom" in ln
        ]
        assert len(matches) == 1, (
            f"{workflow} has {len(matches)} cyclonedx-bom install lines, expected exactly 1 — "
            f"re-point this twin check rather than letting it compare the wrong pair.\n{matches}"
        )
        installs[workflow] = matches[0]
    assert installs["release.yml"] == installs["security.yml"], (
        "the SBOM install commands have drifted:\n"
        f"  release.yml : {installs['release.yml']}\n"
        f"  security.yml: {installs['security.yml']}\n"
        "ADR 0034 makes security.yml's sbom job the pre-tag dry-run for release.yml's. Keep both "
        "lines identical, or replace that dry-run route with one that actually covers the release."
    )


def test_constraints_lock_still_carries_the_packaging_pin() -> None:
    """`release.yml` derives its `packaging` pin from this line — and `exit 1`s without it, ON A TAG.

    `packaging` is not a declared dependency anywhere in `pyproject.toml`; it survives in
    `constraints.lock` only as a transitive of the dev extra's test tooling (`pytest`,
    `pytest-rerunfailures`). A routine Dependabot bump that drops that edge would take the line with
    it, and the first thing to notice would be the tag push itself — the single most expensive moment
    to discover it (release.yml's own header documents this repo's half-published v0.3.1 incident).
    This is the PR-time canary for a fail-closed check that otherwise fires only during a release.
    """
    body = (_REPO / "constraints.lock").read_text(encoding="utf-8")
    pins = re.findall(r"^packaging==\S+", body, re.MULTILINE)
    assert len(pins) == 1, (
        f"expected exactly one `packaging==` line in constraints.lock, found {pins}. release.yml "
        f"resolves its pin with `sed … | head -1`, so zero lines hard-fail the next tag push and "
        f"two would silently pick the first."
    )
