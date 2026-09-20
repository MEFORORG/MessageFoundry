# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One definition of hatchling's ``[tool.hatch.build]`` table, and of the wheel map inside it.

Three guards read that table and each walked the TOML by hand. Two of them want the same
``force-include`` map, for opposite projections of it:

* ``tests/test_packaging.py`` takes the KEYS -- the repo paths a wheel pulls from (BACKLOG #1702) --
  and separately reads the table's ``exclude`` list;
* ``tests/test_install_instruction_provenance.py`` takes the VALUES -- the import tree each wheel
  lands them at, which is how it derives the code trees its scan must cover (BACKLOG #1193);
* ``tests/test_release_pipeline.py`` wants the sdist target's ``only-include``, one target over.

So :func:`hatch_build` is the descent all three share and :func:`wheel_force_include` is the one
resolution rule the first two need on top of it.

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
interpreter here. At the pinned ``hatchling==1.32.0`` every ``[build-system]`` table names:

* ``src/hatchling/builders/config.py:679`` is the ``in self.target_config`` test above;
* ``src/hatchling/builders/plugin/interface.py`` calls ``include_path`` at exactly two sites, ``:204``
  in ``recurse_project_files`` and ``:269`` in ``recurse_explicit_files``. ``recurse_forced_files``
  (``:209``) is neither, which is why ``exclude`` cannot filter a force-included file and why the
  harness map is enumerated rather than excluded (BACKLOG #1702).

**"Unfiltered" is the wrong word for that last one, and the overstatement is worth not inheriting.**
``recurse_forced_files`` does filter, just not by anything an author configures: ``EXCLUDED_DIRECTORIES``
at ``:222`` and ``EXCLUDED_FILES`` at ``:226``, both fixed lists, against a plain ``os.path`` walk. The
true statement is narrower and is the one that matters -- **no include or exclude OPTION reaches a
force-included path.**

Re-read it the same way if the pin moves, rather than trusting the line numbers above::

    pip download hatchling==1.32.0 --no-deps --no-binary :all: -d .

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

__all__ = ["hatch_build", "wheel_force_include"]


def hatch_build(pyproject: Path) -> dict[str, Any]:
    """The ``[tool.hatch.build]`` table of ``pyproject``, or an empty one."""
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    build: dict[str, Any] = data.get("tool", {}).get("hatch", {}).get("build", {})
    return build


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
