# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The package root is lazy (BACKLOG #1675): `import messagefoundry` must not drag in the
authoring surface.

Before this, the root eagerly imported 17 modules -- `config.wiring` alone re-exporting 37 names --
so any `import messagefoundry` cost 65 engine modules and 272 modules in total. Every caller that
wanted only `__version__` (api/app.py, api/metrics.py, pipeline/update_check.py, scaffold.py,
support/bundle.py, verify/checks.py, __main__.py) paid all of it.

The three questions here are separate, and each has its own failure mode:

1. Does the root still import eagerly? Measured in a CLEAN interpreter, because the pytest process
   has already imported half the engine and would report zero cost for anything.
2. Does every exported name still resolve? A wrong module in `_LAZY_EXPORTS` is invisible until
   someone touches that one name at runtime, so the whole surface is walked here.
3. Does an UNKNOWN name still raise AttributeError? This is the one that breaks the build if it is
   got wrong: `from messagefoundry import pki` reaches the submodule only because the import
   machinery falls back to importing it after getattr raises."""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

import messagefoundry

#: Names reached as `from messagefoundry import <name>` where <name> is a SUBMODULE, not an export.
#: None of these is in `__all__`, none is in `_LAZY_EXPORTS`, and each one works only via the
#: AttributeError fallback. Derived by grepping `from messagefoundry import` across engine, tests
#: and harness; the engine call sites are lens_schema.py (actions, diagnostics), api/tls.py (pki)
#: and __main__.py (pki, service).
_SUBMODULE_IMPORTS = (
    "actions",
    "checks",
    "credential",
    "diagnostics",
    "logging_setup",
    "pki",
    "redaction",
    "secretscrub",
    "service",
    "service_status",
    "store",
)

#: What a clean interpreter is allowed to import. `messagefoundry` itself and nothing else -- an
#: exact set rather than a ceiling, so adding ONE eager `from messagefoundry.x import y` back to the
#: root fails here instead of being absorbed by headroom.
_ALLOWED_EAGER = {"messagefoundry"}

#: Ceiling on TOTAL new modules, to catch a heavy third-party import at the root that the
#: messagefoundry-only set above would miss. Measured 16 after this change, 272 before it.
_TOTAL_MODULE_CEILING = 40

_PROBE = """
import json, sys
before = set(sys.modules)
__import__(%r)
after = set(sys.modules)
new = after - before
print(json.dumps({
    "engine": sorted(n for n in new if n == "messagefoundry" or n.startswith("messagefoundry.")),
    "total": len(new),
}))
"""


def _import_cost(module: str) -> tuple[list[str], int]:
    """Import `module` in a FRESH interpreter and report what it cost.

    A subprocess is not decoration. Everything in this suite has already imported the engine, so
    measuring in-process would report zero cost for a root that eagerly imports the world."""
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE % module],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"probe failed for {module}: {proc.stderr}"
    payload = json.loads(proc.stdout)
    engine: list[str] = payload["engine"]
    total: int = payload["total"]
    return engine, total


def test_importing_the_root_pulls_in_no_other_engine_module() -> None:
    """The row itself. Paired with a POSITIVE CONTROL, because a probe that has quietly stopped
    counting anything reports a perfectly lazy root and a broken one identically."""
    control_engine, control_total = _import_cost("messagefoundry.config.wiring")
    assert len(control_engine) > 30, (
        "the probe cannot see eager imports at all -- importing config.wiring directly reported "
        f"only {control_engine}, so the lazy-root reading below proves nothing"
    )
    assert control_total > 100, f"probe undercounts totals: config.wiring reported {control_total}"

    engine, total = _import_cost("messagefoundry")
    assert set(engine) == _ALLOWED_EAGER, (
        f"`import messagefoundry` eagerly imported {sorted(set(engine) - _ALLOWED_EAGER)}. "
        "The root is meant to be a PEP 562 lazy surface; move the import into _LAZY_EXPORTS, or, "
        "if it genuinely must be eager, widen _ALLOWED_EAGER here and say why."
    )
    assert total <= _TOTAL_MODULE_CEILING, (
        f"`import messagefoundry` now costs {total} modules (ceiling {_TOTAL_MODULE_CEILING}, "
        f"measured 16). Something heavy reached the root without adding an engine module."
    )


def test_version_stays_eager() -> None:
    """Seven modules import `__version__` at module level and must not pay for a lazy hop."""
    assert "__version__" in vars(messagefoundry)
    assert "__version__" not in messagefoundry._LAZY_EXPORTS
    assert "__version__" in messagefoundry.__all__


def test_lazy_exports_covers_all_exactly() -> None:
    """The map and `__all__` must not drift in either direction.

    A name in `__all__` but not the map is an AttributeError for a config author; a name in the map
    but not `__all__` is a lazy export nobody declared."""
    assert set(messagefoundry._LAZY_EXPORTS) == set(messagefoundry.__all__) - {"__version__"}
    assert len(messagefoundry.__all__) == len(set(messagefoundry.__all__)), "duplicate in __all__"


@pytest.mark.parametrize("name", sorted(messagefoundry.__all__))
def test_every_exported_name_resolves(name: str) -> None:
    """Walk the WHOLE surface through `__getattr__`.

    A mistyped module in `_LAZY_EXPORTS` raises nothing at import time and nothing in mypy -- it
    fails the first time a config author touches that one name, in production. This is the only
    thing that catches it."""
    value = getattr(messagefoundry, name)
    if name == "__version__":
        return
    module_name = messagefoundry._LAZY_EXPORTS[name]
    owner = sys.modules[module_name]
    assert getattr(owner, name) is value, f"{name} is not the object {module_name} defines"


def test_unknown_name_raises_attribute_error() -> None:
    """The guard the submodule fallback rests on. `__getattr__` returning None, or raising KeyError
    from the bare dict lookup, would turn every `from messagefoundry import <submodule>` below into
    an ImportError -- and the import machinery reports that as a missing module, not as a bug
    here."""
    with pytest.raises(AttributeError, match="has no attribute 'no_such_export'"):
        messagefoundry.no_such_export  # noqa: B018


@pytest.mark.parametrize("name", _SUBMODULE_IMPORTS)
def test_submodule_still_importable_from_the_root(name: str) -> None:
    """`from messagefoundry import <name>` for a SUBMODULE, which no lazy map entry covers."""
    module = __import__("messagefoundry", fromlist=[name])
    assert getattr(module, name).__name__ == f"messagefoundry.{name}"


def test_submodule_names_are_not_shadowed_by_the_lazy_map() -> None:
    """A map entry sharing a submodule's name would silently win over the submodule.

    `_LAZY_EXPORTS` is consulted first, so `"store": "..."` in the map would make
    `from messagefoundry import store` bind an export instead of the module."""
    collisions = sorted(set(_SUBMODULE_IMPORTS) & set(messagefoundry._LAZY_EXPORTS))
    assert not collisions, f"lazy exports shadow these submodules: {collisions}"


def test_star_import_still_binds_the_whole_surface() -> None:
    """`from messagefoundry import *` is a real generated-config shape (lens.py emits config that
    uses it, and test_lens_rewrite_v2 exercises it), and under PEP 562 it works ONLY because
    `__all__` is still declared -- a star-import consults `__all__` and pulls each name through
    `__getattr__`. Drop `__all__` on the theory that `_LAZY_EXPORTS` supersedes it and star-import
    silently binds nothing, with no other test in this file noticing."""
    namespace: dict[str, object] = {}
    exec("from messagefoundry import *", namespace)  # noqa: S102
    bound = {name for name in namespace if not name.startswith("__")}
    missing = sorted(set(messagefoundry.__all__) - {"__version__"} - bound)
    assert not missing, f"star-import bound nothing for: {missing}"
    assert namespace["Send"] is messagefoundry.Send


def test_dir_still_advertises_the_surface() -> None:
    """`dir()` drives tab-completion and help(); PEP 562 laziness must not empty it."""
    listed = dir(messagefoundry)
    assert set(messagefoundry.__all__) <= set(listed)
    assert listed == sorted(listed)
