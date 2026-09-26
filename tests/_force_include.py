# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One definition of hatchling's ``[tool.hatch]`` table, and of the wheel map inside it.

At least four guards read the ``build`` sub-table and each walked the TOML by hand. Several want the
same ``force-include`` map, for different projections of it:

* ``tests/test_packaging.py`` takes the KEYS -- the repo paths a wheel pulls from (BACKLOG #1702) --
  and separately reads the table's ``exclude`` list;
* ``tests/test_install_instruction_provenance.py`` takes the VALUES -- the import tree each wheel
  lands them at, which is how it derives the code trees its scan must cover (BACKLOG #1193);
* ``tests/test_packaged_tree_denylist.py`` takes the PAIRS, to walk each shipped tree at the path it
  lands on, and reads the root project's ``exclude`` list beside them;
* ``tests/test_release_pipeline.py`` wants the sdist target's ``only-include``, one target over.

So :func:`hatch_build` is the descent they share and :func:`wheel_force_include` is the one
resolution rule the force-include readers need on top of it. **"At least" is load-bearing** (SDS-3.6):
the count was written as three while a fourth reader already existed, so the number is a floor and a
new caller does not make this paragraph wrong.

**A FOURTH READER WANTED A SIBLING TABLE, NOT THE BUILD ONE, so the scope here is `[tool.hatch]` and
no longer `[tool.hatch.build]`.** The harness lockstep-pin check (BACKLOG #1585) needs
``[tool.hatch.version].path`` -- the module a project's version is read out of -- which is one table
over from everything above. It is here rather than in that test because
``test_no_test_module_walks_the_hatch_build_table_for_itself`` (BACKLOG #1836) is deliberately wider
than the defect it was filed for: it refuses a hand descent through ``hatch`` ANYWHERE in a test
module, on the reasoning that two readings of one table are free to disagree silently whichever key
they land on. Widening this module is what satisfies that guard; spelling the access differently to
slip past its regex would defeat it while looking like a pass.

**The two force-include copies already disagreed, and the disagreement was silent.** One read only
``[tool.hatch.build.targets.wheel.force-include]``; the other also fell back to the global
``[tool.hatch.build.force-include]``. hatchling reads the global table whenever the target omits the
key -- the natural spelling when one map should serve both the wheel and the sdist -- so a
distribution written that way would have kept the ``#1702`` guard working while quietly dropping out
of the provenance scan, with nothing failing (BACKLOG #1836).

**PRESENCE, NOT TRUTHINESS, and that is not what a ``target or fallback`` would do.**
``BuilderConfig.force_include`` branches on ``'force-include' in self.target_config`` and only then
reads ``self.build_config``, so a target table that declares an EMPTY map means an empty map -- it
does not re-open the global one. The difference is narrow and it is exactly the kind of thing one
shared reader exists to get right once.

**READ, NOT INFERRED, because three places in this repository had asserted hatchling's behaviour and
none could check it** -- the backend is a build-isolation dependency and is installed in no
interpreter here. At the pinned ``hatchling==1.32.4`` every ``[build-system]`` table names (re-read
at the move from 1.32.0: ``builders/config.py`` is byte-identical, and ``plugin/interface.py`` gained
nine lines of example code in the ``BuilderInterface`` docstring above these sites, plus typing-only
edits below them, so every line cited here moved by nine and none changed):

* ``src/hatchling/builders/config.py:679`` is the ``in self.target_config`` test above;
* ``src/hatchling/builders/plugin/interface.py`` calls ``include_path`` at exactly two sites, ``:213``
  in ``recurse_project_files`` and ``:278`` in ``recurse_explicit_files``. ``recurse_forced_files``
  (``:218``) is neither, which is why ``exclude`` cannot filter a force-included file and why the
  harness map is enumerated rather than excluded (BACKLOG #1702).

**"Unfiltered" is the wrong word for that last one, and the overstatement is worth not inheriting.**
``recurse_forced_files`` does filter, at **at least three** sites in its directory branch -- a floor
rather than a list, because the first draft of this paragraph named two of them and stopped
(SDS-3.6, and it caught this file): ``EXCLUDED_DIRECTORIES`` at ``:231``, ``EXCLUDED_FILES`` at
``:235``, and ``path_is_reserved`` at ``:240``. The claim that survives all three is the one that
matters -- **no include or exclude OPTION reaches a force-included path**, because those flow through
``include_path`` and none of the three is it.

**Do not upgrade that to "nothing an author configures", which is what the draft said.** The first two
are fixed lists, but ``path_is_reserved`` reads ``build_reserved_paths``, and ``config.py:838-848``
populates that **from the force-include map itself** -- so the third filter is derived from the
author's own configuration, just not from an include/exclude option. Its job there is to stop a mapped
DIRECTORY walk re-adding a path another entry already claims.

Re-read it the same way if the pin moves, rather than trusting the line numbers above::

    pip download hatchling==1.32.4 --no-deps --no-binary :all: -d .

**Not covered here, deliberately:** which distributions exist. The two force-include readers each
glob ``packaging/*`` for their own reasons, written down where they happen, and folding those
together would decide a question this module was not asked. **That split is safe for a reason, not
by luck:** the readings could disagree silently because every liveness floor stayed satisfied either
way, whereas a NARROWING of discovery reds on both sides -- each floor is tight against the two
distributions that exist. The widening case used to be the silent one, and the derived floor in
``test_every_packaged_distribution_has_its_code_tree_scanned`` is what closed it.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

__all__ = ["hatch_build", "version_path", "wheel_force_include"]


def _hatch(pyproject: Path) -> dict[str, Any]:
    """The ``[tool.hatch]`` table of ``pyproject``, or an empty one."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    hatch: dict[str, Any] = data.get("tool", {}).get("hatch", {})
    return hatch


def hatch_build(pyproject: Path) -> dict[str, Any]:
    """The ``[tool.hatch.build]`` table of ``pyproject``, or an empty one."""
    build: dict[str, Any] = _hatch(pyproject).get("build", {})
    return build


def version_path(pyproject: Path) -> Path:
    """The module whose ``__version__`` hatchling reads ``pyproject``'s version from.

    RESOLVED against the PROJECT directory, which is what hatchling does and is the whole reason a
    caller cannot just join it to the repo root: every distribution under ``packaging/`` writes this
    as a path climbing back out of its own project dir.

    RAISES rather than returning a default, unlike :func:`hatch_build` above, and the asymmetry is
    deliberate. An absent build table means "this project configures nothing", which is a real answer
    every caller can use. An absent version root has no such answer -- there is no module to read --
    so a caller handed one would be asserting about a path nothing declared.
    """
    hatch = _hatch(pyproject)
    try:
        declared = hatch["version"]["path"]
    except KeyError as exc:
        raise KeyError(
            f"{pyproject} declares no [tool.hatch.version].path, so it names no module for this "
            f"check to read a version out of"
        ) from exc
    return (pyproject.parent / declared).resolve()


def wheel_force_include(pyproject: Path) -> dict[str, str]:
    """The ``force-include`` map that reaches the WHEEL, resolved hatchling's way.

    Keys are sources as written in the file -- relative to the PROJECT directory, not the repo root.
    Resolving them is the caller's job, because only one call site needs it.
    """
    build = hatch_build(pyproject)
    target: dict[str, Any] = build.get("targets", {}).get("wheel", {})
    if "force-include" in target:
        declared: dict[str, str] = target["force-include"]
        return declared
    fallback: dict[str, str] = build.get("force-include", {})
    return fallback
