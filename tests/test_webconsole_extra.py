# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's ``[webconsole]`` extra, and the two lock exports that leave the console out.

``packaging/messagefoundry-webconsole/RELEASE.md`` step 1 declares the extra, and
``docs/WEBCONSOLE-PACKAGE.md`` says why it is a floor with no ceiling. ``security.yml``'s DEP-1 step
exports ``requirements.lock`` and ``constraints.lock`` with ``--all-extras``, so without
``--no-emit-package`` both would carry the console, as an ``-e`` line now that uv resolves it from
the tree; the comment beside those exports says what that would break.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from messagefoundry.security.audit_all_platforms import option_lines, read_lock, requirement_lines

_ROOT = Path(__file__).resolve().parent.parent
_CONSOLE = "messagefoundry-webconsole"


def _pinned_names(lock: Path) -> set[str]:
    """The distribution names a uv requirements export pins, read as the DEP-1 audit reads it."""
    return {
        canonicalize_name(line.split("==", 1)[0].strip())
        for line in requirement_lines(read_lock(lock))
    }


def test_the_webconsole_extra_is_a_floor_with_no_ceiling() -> None:
    """RED when: the extra is removed, gains a second requirement, a marker, or any bound but ``>=``."""
    extras = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "optional-dependencies"
    ]
    assert "webconsole" in extras, "the engine no longer declares the [webconsole] extra"
    specs = extras["webconsole"]
    assert len(specs) == 1, f"[webconsole] should name the console alone, found {specs}"
    req = Requirement(specs[0])
    assert canonicalize_name(req.name) == _CONSOLE, specs
    assert req.marker is None, f"a marker leaves some installs with no floor: {specs[0]}"
    operators = {spec.operator for spec in req.specifier}
    assert operators == {">="}, f"[webconsole] must be a floor with no ceiling, found {specs[0]}"


def test_the_floor_names_the_in_tree_console_version() -> None:
    """RED when: the console's ``__version__`` moves without the extra's floor, or the reverse.

    uv resolves the extra to the in-tree console (``[tool.uv.sources]``) and does not compare the
    floor with that console's version: measured, ``uv lock`` passed with the floor at ``>=0.6.0`` and
    the console at 0.5.0. So nothing else catches a release PR that bumps one and not the other, and
    the engine wheel would then publish a floor that does not name the console it was released with.
    """
    spec = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"][
        "optional-dependencies"
    ]["webconsole"][0]
    floor = next(s.version for s in Requirement(spec).specifier if s.operator == ">=")
    init = (_ROOT / "messagefoundry_webconsole" / "__init__.py").read_text(encoding="utf-8")
    match = re.search(r"""^__version__\s*=\s*["']([^"']+)["']""", init, re.M)
    assert match, "no __version__ line in messagefoundry_webconsole/__init__.py"
    assert floor == match[1], (
        f"[webconsole] floor is {floor} but the in-tree console is {match[1]}; the release PR "
        "raises both together (packaging/messagefoundry-webconsole/RELEASE.md step 1)"
    )


def test_the_lock_resolves_the_in_tree_console() -> None:
    """RED when: ``[tool.uv.sources]`` stops pointing the extra at the in-tree console, so uv.lock
    and ``uv sync`` would install a PyPI console built for another engine seam."""
    packages = tomllib.loads((_ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    console = [p for p in packages if p["name"] == _CONSOLE]
    assert len(console) == 1, f"uv.lock should resolve one console package, found {console}"
    assert console[0]["source"] == {"editable": "packaging/messagefoundry-webconsole"}, console[0]


def test_the_all_extras_exports_leave_the_console_out() -> None:
    """RED when: a committed all-extras lock pins the console, as an export without
    ``--no-emit-package messagefoundry-webconsole`` writes it."""
    # The positive control: uv.lock does carry the console, so its absence below is the export
    # flag's doing, not a lock that never resolved the extra.
    packages = tomllib.loads((_ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    assert any(p["name"] == _CONSOLE for p in packages), "uv.lock resolves no console package"
    for name in ("requirements.lock", "constraints.lock"):
        text = read_lock(_ROOT / name)
        names = _pinned_names(_ROOT / name)
        assert "fastapi" in names, f"{name} parsed to no pins; the parser no longer reads it"
        # An export without the flag writes the in-tree console as `-e ./packaging/...`, which the
        # parser files under option lines, not requirements; so both kinds are checked.
        carried = [ln for ln in option_lines(text) if _CONSOLE in ln] + (
            [_CONSOLE] if _CONSOLE in names else []
        )
        assert not carried, (
            f"{name} carries the first-party console: {carried}; security.yml says why not"
        )
