# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine's ``[webconsole]`` extra, and the two lock exports that leave the console out.

``packaging/messagefoundry-webconsole/RELEASE.md`` step 1 declares the extra, and
``docs/WEBCONSOLE-PACKAGE.md`` says why it is a floor with no ceiling. ``security.yml``'s DEP-1 step
exports ``requirements.lock`` and ``constraints.lock`` with ``--all-extras``, so without
``--no-emit-package`` both would pin the console; the comment beside those exports says what each
pin would break.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from messagefoundry.security.audit_all_platforms import read_lock, requirement_lines

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


def test_the_all_extras_exports_leave_the_console_out() -> None:
    """RED when: a committed all-extras lock pins the console, as an export without
    ``--no-emit-package messagefoundry-webconsole`` writes it."""
    # The positive control: uv.lock does carry the console, so its absence below is the export
    # flag's doing, not a lock that never resolved the extra.
    packages = tomllib.loads((_ROOT / "uv.lock").read_text(encoding="utf-8"))["package"]
    assert any(p["name"] == _CONSOLE for p in packages), "uv.lock resolves no console package"
    for name in ("requirements.lock", "constraints.lock"):
        names = _pinned_names(_ROOT / name)
        assert "fastapi" in names, f"{name} parsed to no pins; the parser no longer reads it"
        assert _CONSOLE not in names, (
            f"{name} pins the first-party console; security.yml says why not"
        )
