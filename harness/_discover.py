# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Module discovery shared by the harness's family packages (drivers, sinks, endpoints, scenarios).

Each of those packages holds one module per transport family, and a later family is added by
dropping a file in, never by editing a shared table. That is what lets several people (or agents)
add families at once without colliding on one dict. A module whose name starts with ``_`` is a
helper and is skipped, the same rule the engine's config loader applies to ``_*.py``.

Discovery imports each module, so a family module must import its optional extras lazily (inside
the function that needs them). A family that cannot import at all is a real error and raises.
"""

from __future__ import annotations

import importlib
import pkgutil
from collections.abc import Iterator
from types import ModuleType


def family_modules(package: str) -> Iterator[ModuleType]:
    """Yield every public submodule of ``package``, sorted by name so the order is stable."""
    pkg = importlib.import_module(package)
    names = sorted(
        info.name
        for info in pkgutil.iter_modules(pkg.__path__)
        if not info.name.startswith("_") and not info.ispkg
    )
    for name in names:
        yield importlib.import_module(f"{package}.{name}")
