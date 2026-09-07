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
#:
#: BACKLOG #1193: the set scanned ZERO files of two of the three distributions this repo builds. Both
#: ship code that raises operator-facing errors, exactly like the ``api/app.py`` RuntimeError this
#: module exists because of, so the console and harness trees are now scanned too. They are green
#: today -- the point is that the next install instruction written into either one is covered.
_SHIPPED_TEXT_GLOBS = (
    "docs/*.md",
    "README.md",
    "messagefoundry/**/*.py",
    "messagefoundry_webconsole/**/*.py",
    "harness/**/*.py",
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


def _packaged_import_trees() -> frozenset[str]:
    """The repo-root import package each `packaging/<dist>/` builds, read from its own build config.

    Derived, not listed: both second distributions force-include a tree from the repo root into the
    wheel (`../../harness` -> `harness`), and the wheel TARGET is the import package's name. A list
    here would be a second definition of which trees ship, free to drift from the build.
    """
    trees: set[str] = set()
    for pyproject in sorted((_ROOT / "packaging").glob("*/pyproject.toml")):
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        wheel = data.get("tool", {}).get("hatch", {}).get("build", {}).get("targets", {})
        include = wheel.get("wheel", {}).get("force-include", {})
        trees.update(str(target).split("/")[0] for target in include.values())
    return frozenset(trees)


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


def test_every_packaged_distribution_has_its_code_tree_scanned() -> None:
    """The blind spot BACKLOG #1193 found, pinned so it cannot reopen.

    Each distribution under `packaging/` ships an import package, and each such tree must contribute
    files to the scan. Stated as a per-tree count rather than a total, because a total stays healthy
    while one tree silently drops to zero -- which is exactly what happened.

    Mutation: delete `messagefoundry_webconsole/**/*.py` from `_SHIPPED_TEXT_GLOBS`. Red: named below.
    """
    scanned = _shipped_files()
    trees = {"messagefoundry"} | _packaged_import_trees()
    assert len(trees) >= 3, f"the packaging parse found only {sorted(trees)} -- it broke"
    empty = sorted(
        tree
        for tree in trees
        if (_ROOT / tree).is_dir() and not any(f.is_relative_to(_ROOT / tree) for f in scanned)
    )
    assert not empty, (
        f"these shipped code trees contribute ZERO files to the scan: {empty}. An install "
        f"instruction written into one of them is invisible to every assertion in this module."
    )


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


# --- BACKLOG #1193 (ASVS 15.2.4): no tracked text may assert a CLAIMED name is unclaimed ---------
#
# The arm this module was missing. Five shipped artifacts went on asserting `messagefoundry-webconsole`
# was unpublished for weeks after the first release claimed the name, while every install-command
# assertion above stayed green -- because none of them reads a factual CLAIM about publication state,
# only the commands. A reader who trusted those five got the pre-claim world: install by path, the
# name is claimable by anyone, no publishing job exists.
#
# Derived from `_PUBLISHED_DISTRIBUTIONS`, so it inverts on its own if a name is ever reclassified.


#: Files the PROSE arm reads that the install-command scan deliberately does not. The install-command
#: set is "text somebody pastes"; a factual claim about whether a name is claimed is wrong wherever it
#: is written -- an owner-only release checklist and a workflow comment included, which is where two of
#: the five lived.
_PROSE_ONLY_GLOBS = ("packaging/*/*.md", ".github/workflows/release.yml")

#: Ledgers and decision records are excluded for the same reason `BACKLOG.md` is excluded above: they
#: record what was true when written, and rewriting history to satisfy a lint destroys the record.
_PROSE_NOT_ASSERTIONS = frozenset({"BACKLOG.md", "CHANGELOG.md"})

#: Phrasings that assert a distribution is not published. Deliberately narrow: each is a claim about
#: PUBLICATION STATE, not merely a sentence containing "publish". Every alternative here is one that
#: was measured to fire on one of the five retired sites; none is speculative.
#:
#: "unclaimed" is EXCLUDED, on evidence rather than caution. It was tried, and it fired on
#: `packaging/messagefoundry-webconsole/README.md`, whose sentence says the opposite -- that claiming
#: the name "forecloses the dependency-confusion substitution an unclaimed name invites". The word
#: also carries an unrelated sense throughout the bootstrap-admin lifecycle. A detector that flags a
#: correct sentence is one somebody switches off, and it caught none of the five.
_UNPUBLISHED_ASSERTION = re.compile(
    r"""
      un-?published
    | not \s+ (?:yet\s+)? published
    | never \s+ been \s+ published
    | does \s+ not \s+ reserve \s+ the \s+ name
    | claimable \s+ by \s+ anyone
    | until \s+ the \s+ owner \s+ publishes
    """,
    re.IGNORECASE | re.VERBOSE,
)


def _published_name_spellings() -> frozenset[str]:
    """Every spelling a published distribution is referred to by: its name and its import name."""
    return frozenset(
        set(_PUBLISHED_DISTRIBUTIONS)
        | {name.replace("-", "_") for name in _PUBLISHED_DISTRIBUTIONS}
    )


def _prose_blocks(text: str) -> list[tuple[int, str]]:
    """Blank-line-delimited blocks of ``text``, as ``(first line number, block text)``.

    A claim and the name it is about routinely sit on different lines -- a wrapped Markdown
    blockquote, a multi-line ``#`` comment. Line-at-a-time matching misses every one of the five
    sites this arm exists for, and a fixed +/-N window has no principled size. A blank line is where
    the author already said one thought ended.
    """
    blocks: list[tuple[int, str]] = []
    current: list[str] = []
    start = 1
    for lineno, line in enumerate(text.splitlines(), 1):
        if line.strip():
            if not current:
                start = lineno
            current.append(line)
        elif current:
            blocks.append((start, "\n".join(current)))
            current = []
    if current:
        blocks.append((start, "\n".join(current)))
    return blocks


def _prose_files() -> list[Path]:
    """The shipped-text set plus the prose-only globs, DEDUPLICATED -- the console README is in both,
    and a file read twice reports the same site twice."""
    seen = list(_shipped_files())
    for pattern in _PROSE_ONLY_GLOBS:
        seen.extend(sorted(_ROOT.glob(pattern)))
    return sorted({p for p in seen if p.is_file() and p.name not in _PROSE_NOT_ASSERTIONS})


def _unpublished_claims(files: list[Path]) -> list[str]:
    """Blocks that assert a PUBLISHED distribution is unpublished, as ``path:line`` problems.

    The name is looked for in the claim's block AND its two neighbours. Measured, and the reason the
    window is not one block: `docs/SERVICE.md` said *"The wheel is not published to an index yet, so
    install it by path:"* and then named the distribution in the fenced command underneath, one blank
    line away. A single-block rule found four of the five sites and missed that one.
    """
    spellings = _published_name_spellings()
    problems: list[str] = []
    for path in files:
        blocks = _prose_blocks(path.read_text(encoding="utf-8"))
        for index, (lineno, block) in enumerate(blocks):
            if not _UNPUBLISHED_ASSERTION.search(block):
                continue
            window = "\n".join(text for _, text in blocks[max(index - 1, 0) : index + 2])
            named = sorted(s for s in spellings if s in window)
            if named:
                rel = path.name if not path.is_relative_to(_ROOT) else path.relative_to(_ROOT)
                problems.append(f"{Path(rel).as_posix()}:{lineno} calls {named} unpublished")
    return problems


def test_the_prose_scan_actually_examined_something() -> None:
    """Liveness receipt, and it must be its own: `_prose_files` adds globs the shipped set has not."""
    files = _prose_files()
    assert len(files) >= 25, f"the prose scan matched only {len(files)} files"
    assert any(p.suffix == ".yml" for p in files), "the workflow glob matched nothing"
    assert _published_name_spellings(), (
        "no distribution is classified published -- the derive broke"
    )


def test_no_tracked_text_asserts_a_published_distribution_is_unpublished() -> None:
    """The arm that would have caught all five (BACKLOG #1193).

    Mutation: restore `release.yml`'s "does NOT reserve the name" comment, or
    `docs/SERVICE.md`'s "The wheel is not published to an index yet". Red: named below.
    """
    problems = _unpublished_claims(_prose_files())
    assert not problems, (
        f"tracked text asserts a distribution is unpublished while this module classifies it "
        f"PUBLISHED: {problems}. Published: {sorted(_PUBLISHED_DISTRIBUTIONS)}. Correct the prose -- "
        f"do NOT add the name back to _UNPUBLISHED_DISTRIBUTIONS to make this pass, which is the same "
        f"defect inverted: a classification edited to agree with whichever artifact is convenient."
    )


@pytest.mark.parametrize(
    ("block", "flagged"),
    [
        # The five real shapes, reduced. Each spans lines, which is why blocks and not lines.
        ("# grants permission to publish but does NOT reserve the\n# name", False),  # names nothing
        (
            "# `messagefoundry-webconsole` is registered as PENDING\n"
            "# ... does NOT reserve the name: claimable by anyone",
            True,
        ),
        ("The messagefoundry-webconsole wheel is\nnot published to an index yet", True),
        (
            "an instruction to fetch an UNPUBLISHED distribution\nnamed messagefoundry_webconsole",
            True,
        ),
        # A published name discussed WITHOUT a publication-state claim stays green.
        ("Install it with pip install messagefoundry-webconsole alongside the engine", False),
        # The bootstrap-admin sense of "unclaimed" must never fire, even beside a distribution name.
        (
            "messagefoundry-harness talks to the API; an unclaimed bootstrap admin\n"
            "is disabled after 72h",
            False,
        ),
        # The measured false positive that removed "unclaimed" from the pattern: this sentence, in
        # packaging/messagefoundry-webconsole/README.md, asserts the OPPOSITE of what it was flagged for.
        (
            "The messagefoundry-webconsole name is registered on PyPI. Claiming it forecloses\n"
            "the dependency-confusion substitution an unclaimed name invites.",
            False,
        ),
        # A genuinely unpublished thing that is not one of our distributions stays green.
        ("The security corpus is not published in this repository", False),
    ],
)
def test_the_prose_detector_needs_both_a_claim_and_a_published_name(
    block: str, flagged: bool
) -> None:
    """Guard-the-guard, both directions. A detector that fired on every "publish" would be turned off;
    one that needed the claim and the name on the SAME LINE would have caught none of the five."""
    named = any(s in block for s in _published_name_spellings())
    hit = bool(_UNPUBLISHED_ASSERTION.search(block)) and named
    assert hit is flagged, f"{block!r}: expected flagged={flagged}, got {hit}"


def test_the_prose_arm_fires_on_the_text_it_was_written_for(tmp_path: Path) -> None:
    """NEGATIVE CONTROL against a FILE, not a string. The arm's silence over the tree is only
    evidence if the same function, over the same file machinery, still reports a real site.

    Reconstructs `release.yml`'s retired comment -- the claim and the name on different lines, which
    is what defeats a line-at-a-time scan -- and asserts `_unpublished_claims` names it with the right
    line number. Without this, the assertion above is a `not found` never seen to find anything.
    """
    staged = tmp_path / "probe.md"
    staged.write_text(
        "# heading\n"
        "\n"
        "`messagefoundry-webconsole` is registered on PyPI as a PENDING Trusted Publisher,\n"
        "which does NOT reserve the name.\n",
        encoding="utf-8",
    )
    found = _unpublished_claims([staged])
    assert found == ["probe.md:3 calls ['messagefoundry-webconsole'] unpublished"], found


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
