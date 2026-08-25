# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 15.2.4: no shipped text may instruct an install that resolves an UNCLAIMED name.

The defect this guards was live in **shipped code**, not just docs: ``api/app.py``'s ``serve_ui``
RuntimeError told the operator to run ``pip install messagefoundry[webconsole]`` — an extra
``pyproject.toml`` deliberately withholds until the wheel is published, so the command simply failed.
Three docs additionally told users to ``pip install "messagefoundry-webconsole"`` from an index the
distribution has never been published to.

That second shape is the one the requirement is actually about. An install instruction naming a
distribution nobody has claimed is a **dependency-confusion primitive**: whoever registers the name on
PyPI first gets their code executed at install time — an sdist runs its build backend during
``pip install`` — on every user who follows our own documentation, before any engine process exists and
therefore beyond the reach of every runtime control in the product.

**Scope, honestly.** Correcting our instructions removes *our contribution* to that risk. It does not
remove the risk: only claiming the name does. This module is the half that can be automated.

Two properties, both derived from source rather than hardcoded:

1. **Every extra named in an install instruction must exist** in ``[project.optional-dependencies]``.
2. **No unpublished distribution may be named in an index-resolving install command.** A path install
   (``pip install -e packaging/...``) resolves no index and is always fine; a bare-name install is
   only fine once the name is published.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: Distributions this repository builds that are **not yet published to any index**. Until a name is
#: claimed, no shipped text may tell a user to install it by bare name.
#:
#: **Currently empty, and that is the goal state, not a disabled guard.** All three distributions this
#: repo builds are registered on PyPI (`messagefoundry`, `messagefoundry-harness`,
#: `messagefoundry-webconsole` -- the last claimed 2026-07-29 by the first `webconsole-v*` release,
#: closing the ASVS 15.2.4 exposure where README.md instructed an index install of an unclaimed name).
#: An empty set means "nothing unpublished is being advertised", which is exactly what should hold.
#:
#: The set exists for the NEXT distribution: add its name here the moment `packaging/<name>/` lands and
#: before any doc references it, then remove it once the first release claims the name.
#: `test_a_new_distribution_must_be_classified` fails if a packaged distribution is neither listed here
#: nor demonstrably published, so this cannot silently rot back to vacuous.
_UNPUBLISHED_DISTRIBUTIONS: frozenset[str] = frozenset()

#: Distribution names registered on PyPI and published by this repo's release workflow. Listing one
#: here asserts the name is CLAIMED -- the property that makes a bare-name install instruction safe.
_PUBLISHED_DISTRIBUTIONS = frozenset({"messagefoundry-harness", "messagefoundry-webconsole"})

#: Files whose install commands are shipped to, or executed by, someone other than a maintainer.
#: CI workflows and internal handoffs are excluded deliberately: they install from the source tree by
#: path, run only in our own checkout, and are not instructions anyone pastes into a deployment.
_SHIPPED_TEXT_GLOBS = (
    "docs/*.md",
    "README.md",
    "messagefoundry/**/*.py",
    "packaging/messagefoundry-webconsole/README.md",
)

#: An install command naming a bare distribution -- i.e. one pip will resolve against an INDEX.
#: ``-e <path>`` / a path argument is deliberately not matched: it resolves no index.
_BARE_NAME_INSTALL = re.compile(
    r"""(?:pip|uv\s+pip|uv)\s+(?:install|add)         # the verb
        (?P<flags>(?:\s+--?[\w-]+(?:[= ]\S+)?)*)      # any flags
        \s+["']?(?P<name>[A-Za-z][\w.-]*)             # the distribution name
        (?P<extras>\[[^\]]*\])?                       # optional [extras]
    """,
    re.VERBOSE,
)

#: ``messagefoundry[...]`` where the extras are LITERAL. ``[{extra}]`` / ``[{_EXTRA}]`` are f-string
#: placeholders whose value is filled at runtime from the module's own constant, so they name no extra
#: at rest and are excluded by the ``{`` exclusion in the character class -- not by an allow-list,
#: which would have to be maintained.
_EXTRA_REF = re.compile(r"messagefoundry\[(?P<extras>[^\]{}]+)\]")


def _declared_extras() -> frozenset[str]:
    data = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    return frozenset(data.get("project", {}).get("optional-dependencies", {}))


#: Not install instructions, and excluded with a reason rather than silently.
#: ``BACKLOG.md`` is a historical ledger -- it records what past items PROPOSED (including a
#: ``[console]`` extra that was never declared), and rewriting history to satisfy a lint would destroy
#: the record this project relies on. Nobody pastes an install command out of a closed backlog item.
_NOT_INSTRUCTIONS = frozenset({"BACKLOG.md"})


def _shipped_files() -> list[Path]:
    seen: list[Path] = []
    for pattern in _SHIPPED_TEXT_GLOBS:
        seen.extend(sorted(_ROOT.glob(pattern)))
    # docs/security/** is vaulted and not shipped; skip it if a local checkout has it materialized.
    return [
        p
        for p in seen
        if "security" not in p.parts and p.name not in _NOT_INSTRUCTIONS and p.is_file()
    ]


def test_the_scan_actually_examined_something() -> None:
    """Liveness receipt. Every assertion below is a `not found` over a file set built from globs, and
    a glob that stops matching turns this module into a wall of green that checks nothing."""
    files = _shipped_files()
    assert len(files) >= 20, f"the shipped-text scan matched only {len(files)} files: {files}"
    assert _declared_extras(), "pyproject declares no optional-dependencies -- the parse broke"


def test_every_extra_named_in_shipped_text_is_declared() -> None:
    """Mutation: restore ``pip install messagefoundry[webconsole]`` in ``api/app.py``. Red: named
    below, because ``webconsole`` is not in ``[project.optional-dependencies]``."""
    declared = _declared_extras()
    problems: list[str] = []
    for path in _shipped_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in _EXTRA_REF.finditer(line):
                for extra in (e.strip() for e in m["extras"].split(",")):
                    if extra and extra not in declared:
                        rel = path.relative_to(_ROOT).as_posix()
                        problems.append(f"{rel}:{lineno} names undeclared extra [{extra}]")
    assert not problems, (
        f"shipped text names extras pyproject does not declare: {problems}. Declared: "
        f"{sorted(declared)}. An install instruction for a non-existent extra simply fails for the "
        f"operator who pastes it."
    )


def test_no_shipped_text_installs_an_unpublished_distribution_by_name() -> None:
    """The dependency-confusion half (ASVS 15.2.4).

    Mutation: restore ``pip install "messagefoundry-webconsole==0.1.0"`` in docs/INSTALL-GUIDE.md.
    Red: named below. A path install of the same distribution stays green, which is the distinction
    that matters -- ``-e packaging/messagefoundry-webconsole`` resolves no index and cannot be hijacked.
    """
    problems: list[str] = []
    for path in _shipped_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for m in _BARE_NAME_INSTALL.finditer(line):
                if "-e" in m["flags"] or "--editable" in m["flags"]:
                    continue
                name = m["name"].lower().replace("_", "-")
                if name in _UNPUBLISHED_DISTRIBUTIONS:
                    rel = path.relative_to(_ROOT).as_posix()
                    problems.append(f"{rel}:{lineno} installs unpublished {name!r} by name")
    assert not problems, (
        f"shipped text instructs an INDEX install of a distribution we have not published: "
        f"{problems}. Whoever registers that name on PyPI first executes code at install time on "
        f"every user who follows it. Use a path install until the name is claimed, then remove it "
        f"from _UNPUBLISHED_DISTRIBUTIONS here."
    )


def test_the_unpublished_list_does_not_rot() -> None:
    """An entry that has since been published would silently keep flagging correct instructions, and
    one that was deleted without being published would silently stop guarding. Pin it to a name this
    repository actually builds."""
    packaging_dirs = {p.name for p in (_ROOT / "packaging").iterdir() if p.is_dir()}
    unknown = sorted(_UNPUBLISHED_DISTRIBUTIONS - packaging_dirs)
    assert not unknown, (
        f"_UNPUBLISHED_DISTRIBUTIONS names distributions this repo does not build: {unknown}"
    )


def test_a_new_distribution_must_be_classified() -> None:
    """Stops the guard rotting back to vacuous now that the unpublished set is empty.

    Every distribution under `packaging/` must be either (a) listed in `_UNPUBLISHED_DISTRIBUTIONS`,
    so shipped text may not instruct an index install of it, or (b) known-published, so it may. A NEW
    `packaging/<name>/` that is neither fails here -- which is the window the ASVS 15.2.4 exposure
    lived in: a distribution existed, docs referenced it by name, and nobody had claimed the name.

    Mutation: add a `packaging/<new>/` directory without touching this file. Red: named below.
    """
    packaged = {
        p.name for p in (_ROOT / "packaging").iterdir() if p.is_dir() and not p.name.startswith(".")
    }
    unclassified = sorted(packaged - _UNPUBLISHED_DISTRIBUTIONS - _PUBLISHED_DISTRIBUTIONS)
    assert not unclassified, (
        f"packaged distribution(s) classified as neither unpublished nor published: {unclassified}. "
        f"Add each to _UNPUBLISHED_DISTRIBUTIONS (and keep docs on a path install) until its name is "
        f"registered, then move it to _PUBLISHED_DISTRIBUTIONS. An unclaimed name that shipped docs "
        f"reference by name is the dependency-confusion window (ASVS 15.2.4)."
    )


#: A name that will never be published, used ONLY to exercise the detector. The parametrized cases
#: below used the real `messagefoundry-webconsole`, so the day that name was claimed on PyPI three of
#: them inverted and the guard-the-guard failed for being RIGHT. The discrimination under test is
#: path-vs-index, which has nothing to do with which names happen to be published.
_SYNTHETIC_UNPUBLISHED = "messagefoundry-notreal"


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        (f'pip install "{_SYNTHETIC_UNPUBLISHED}==0.1.0"', True),
        (f"pip install {_SYNTHETIC_UNPUBLISHED}", True),
        (f"uv pip install {_SYNTHETIC_UNPUBLISHED}", True),
        (f"pip install -e packaging/{_SYNTHETIC_UNPUBLISHED}", False),
        (f"uv pip install --system -e packaging/{_SYNTHETIC_UNPUBLISHED}", False),
        ('pip install "messagefoundry==0.1.0"', False),
        # A PUBLISHED name must NOT be flagged, whatever form it takes -- the whole point of claiming
        # a name is that a bare-name install of it becomes safe to instruct.
        ('pip install "messagefoundry-webconsole==0.2.15"', False),
        ("pip install messagefoundry-webconsole", False),
    ],
)
def test_the_detector_separates_index_installs_from_path_installs(line: str, flagged: bool) -> None:
    """Guard-the-guard, and the reason it is worth having: the whole value of the check above is the
    path-vs-index distinction. A detector that flagged both would be turned off; one that flagged
    neither would be decorative. This pins the boundary in both directions, with no file I/O, so it
    keeps working wherever the suite runs -- and against a SYNTHETIC unpublished name, so it does not
    invert the day a real name is claimed."""
    unpublished = _UNPUBLISHED_DISTRIBUTIONS | {_SYNTHETIC_UNPUBLISHED}
    hits = [
        m
        for m in _BARE_NAME_INSTALL.finditer(line)
        if "-e" not in m["flags"]
        and "--editable" not in m["flags"]
        and m["name"].lower().replace("_", "-") in unpublished
    ]
    assert bool(hits) is flagged, f"{line!r}: expected flagged={flagged}, got {bool(hits)}"


def test_the_synthetic_probe_name_is_not_a_real_distribution() -> None:
    """The probe above is only meaningful while its name is fictional. If a `packaging/` directory ever
    uses it, the parametrized expectations silently stop testing what they claim to."""
    packaged = {p.name for p in (_ROOT / "packaging").iterdir() if p.is_dir()}
    assert _SYNTHETIC_UNPUBLISHED not in packaged, (
        f"{_SYNTHETIC_UNPUBLISHED!r} is now a real distribution — pick another fictional probe name"
    )


# --- BACKLOG #1193 (ASVS 15.2.4): the README's signing claim must match the workflow -------------


def _release_publish_jobs() -> dict[str, str]:
    """Each top-level job in ``release.yml`` that publishes a distribution, name -> its YAML text.

    Read as TEXT rather than parsed YAML: the question is which STEPS a job contains, and the job
    boundary is a top-level two-space key, which is unambiguous here and needs no dependency.
    """
    path = _ROOT / ".github" / "workflows" / "release.yml"
    lines = path.read_text(encoding="utf-8").splitlines()
    starts: list[tuple[int, str]] = []
    for i, line in enumerate(lines):
        m = re.match(r"^  ([a-z][A-Za-z0-9_-]*):$", line)
        if m:
            starts.append((i, m.group(1)))
    jobs: dict[str, str] = {}
    for idx, (line_no, name) in enumerate(starts):
        end = starts[idx + 1][0] if idx + 1 < len(starts) else len(lines)
        body = "\n".join(lines[line_no:end])
        if "pypi-publish" in body or "attestations: true" in body:
            jobs[name] = body
    return jobs


def test_readme_does_not_claim_signing_coverage_the_release_workflow_does_not_provide() -> None:
    """README must not tell every reader that EVERY release is Sigstore-signed when two are not.

    Measured: only the engine job runs Sigstore signing, ``attest-build-provenance`` and the SBOM.
    ``release-webconsole`` and ``release-harness`` carry none of those steps -- they set
    ``attestations: true`` on the publish action, which is the PyPI-side PEP 740 attestation and a
    different artifact from a GitHub attestation. A reader who installs the console wheel (the README
    lists that command directly above this note) and runs ``gh attestation verify`` against it finds
    nothing, having been told the opposite.

    Derived rather than prose-pinned: if someone later adds signing to the console job the unscoped
    claim becomes TRUE, and this test stops objecting to it on its own.
    """
    jobs = _release_publish_jobs()
    signing = re.compile(r"sigstore|attest-build-provenance|cyclonedx", re.IGNORECASE)
    signed = {name for name, body in jobs.items() if signing.search(body)}

    # POSITIVE CONTROLS, both directions: the parse found the jobs, and the detector can SEE signing
    # where signing exists. Without these a broken job-splitter yields an empty unsigned set and this
    # test passes while measuring nothing.
    assert len(jobs) >= 3, f"the release-job parse found {len(jobs)} publish jobs; expected 3+"
    assert signed, (
        "no publish job appears to sign -- the detector matched nothing, so its silence is meaningless"
    )

    unsigned = set(jobs) - signed
    if not unsigned:
        return  # every published artifact is signed; an unscoped claim would be true

    readme = (_ROOT / "README.md").read_text(encoding="utf-8")
    assert "ENGINE wheel only" in readme, (
        "README must say which artifacts the signing covers, because it does not cover all of them: "
        f"unsigned publish jobs are {sorted(unsigned)}"
    )
