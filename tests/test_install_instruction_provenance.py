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
#: claimed, no shipped text may tell a user to install it by bare name. Remove an entry here the day
#: the name is registered -- and note that reserving it is sufficient; an empty project cannot be
#: squatted.
_UNPUBLISHED_DISTRIBUTIONS = frozenset({"messagefoundry-webconsole"})

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


@pytest.mark.parametrize(
    ("line", "flagged"),
    [
        ('pip install "messagefoundry-webconsole==0.1.0"', True),
        ("pip install messagefoundry-webconsole", True),
        ("uv pip install messagefoundry-webconsole", True),
        ("pip install -e packaging/messagefoundry-webconsole", False),
        ("uv pip install --system -e packaging/messagefoundry-webconsole", False),
        ('pip install "messagefoundry==0.1.0"', False),
    ],
)
def test_the_detector_separates_index_installs_from_path_installs(line: str, flagged: bool) -> None:
    """Guard-the-guard, and the reason it is worth having: the whole value of the check above is the
    path-vs-index distinction. A detector that flagged both would be turned off; one that flagged
    neither would be decorative. This pins the boundary in both directions, with no file I/O, so it
    keeps working wherever the suite runs."""
    hits = [
        m
        for m in _BARE_NAME_INSTALL.finditer(line)
        if "-e" not in m["flags"]
        and "--editable" not in m["flags"]
        and m["name"].lower().replace("_", "-") in _UNPUBLISHED_DISTRIBUTIONS
    ]
    assert bool(hits) is flagged, f"{line!r}: expected flagged={flagged}, got {bool(hits)}"
