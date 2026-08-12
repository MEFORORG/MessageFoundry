# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Emit a STABLE, deterministic text snapshot of the engine-side seam contract the web console
(``messagefoundry-webconsole``, Option B / ADR 0065) depends on.

This is the enforced version-skew HANDSHAKE. The console is separately versioned and pins itself
against ``api._ui_seam.ENGINE_UI_SEAM``; a silent, incompatible change to the injected contract
(a renamed handler field, a re-signatured ``api.security`` dep, a DTO field the console renders that
was renamed) would break the console at RUNTIME within a supported seam -- mypy at the engine's
``deps = UiDeps(...)`` site catches builder-signature drift, but NOT a Pydantic DTO field rename
(that breaks render, not import). The engine test ``tests/test_webconsole_seam_snapshot.py``
regenerates this snapshot and diffs it against the golden ``tests/golden/webconsole_seam.snapshot``,
failing CI on any unbumped incompatible change.

**The surface is DISCOVERED, not curated** (BACKLOG #1220). It used to be five hand-maintained
tuples, and three of them had drifted: 25 rendered DTOs were unlisted, ``api.security`` was missing
two symbols while carrying five stale ones, and an ``AuthService`` member the console calls was
absent. A hand-maintained list cannot detect its own omissions -- the gate's coverage IS the list, so
there is no outside vantage point from which a missing entry looks like anything. See
``scripts/seam_discovery.py`` for the walk and the fail-loud boundary.

The snapshot captures:
  1. ``ENGINE_UI_SEAM``, the value both sides pin against;
  2. the ``api._ui_seam`` dataclass field names (``UiDeps`` / ``CoreHandlers`` / ``AdminHandlers``)
     via ``dataclasses.fields`` -- the injected handler/reference bundle shape;
  3. the cross-seam surface the console consumes OUTSIDE the injected bundle, discovered from its own
     imports and uses: ``api.security`` deps, ``AuthService`` members (methods AND properties), and
     the ``app.state`` attributes it sets/reads;
  4. the DTO FIELD SETS the console renders, closed over nested models -- one level of field names
     was not enough, because a nested model's fields never appeared at all;
  5. the ENUM MEMBER sets and ``Literal`` VALUE sets those DTOs expose. Field names alone are not the
     contract: ``UploadedFileList.scope`` is a ``Literal`` the console renders as
     ``_SCOPE_NOTES[data.scope]``, so renaming a literal would KeyError at runtime while a
     field-name-only snapshot stayed byte-identical.

Run ``python scripts/webconsole_seam_snapshot.py`` to print the current snapshot; redirect it over the
golden to refresh it after an intentional, seam-bumped contract change.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import inspect
import sys
from pathlib import Path
from typing import Any

from messagefoundry.api import security
from messagefoundry.api._ui_seam import (
    ENGINE_UI_SEAM,
    AdminHandlers,
    CoreHandlers,
    UiDeps,
)
from messagefoundry.auth.service import AuthService

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONSOLE_DIR = _REPO_ROOT / "messagefoundry_webconsole"
_ENGINE_DIR = _REPO_ROOT / "messagefoundry"


def _load_discovery() -> Any:
    """Load the sibling discovery module by path.

    ``scripts/`` is not an importable package. Registering in ``sys.modules`` BEFORE
    ``exec_module`` is required, not cosmetic: ``@dataclass(slots=True)`` resolves its own module
    through ``sys.modules`` while the decorator runs, and an unregistered module makes that lookup
    return ``None`` and raise.
    """
    name = "_mf_seam_discovery"
    cached = sys.modules.get(name)
    if cached is not None:
        return cached
    spec = importlib.util.spec_from_file_location(name, Path(__file__).parent / "seam_discovery.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_HEADER = (
    "# messagefoundry-webconsole ENGINE SEAM CONTRACT SNAPSHOT",
    "#",
    "# Deterministic serialization of the engine-side contract the web console depends on (ADR 0065).",
    "# Regenerate with: python scripts/webconsole_seam_snapshot.py",
    "# This is a GOLDEN gate: any diff means the seam contract changed - see the test's failure hint.",
    "# The surface below is DISCOVERED from the console's own imports and uses, never enumerated",
    "# by hand (BACKLOG #1220) - so a newly rendered DTO is covered with nobody editing a list.",
)


def _dataclass_fields(dc: type) -> list[str]:
    """Field names in declaration order (the injected bundle shape)."""
    return [f.name for f in dataclasses.fields(dc)]


def _dto_fields(dto: type) -> list[str]:
    """Sorted field names of a rendered DTO (Pydantic model or dataclass).

    ``model_computed_fields`` is unioned in because a computed field is rendered exactly like a
    declared one; omitting it would be the same class of blind spot as the curated tuples.
    """
    from pydantic import BaseModel

    if isinstance(dto, type) and issubclass(dto, BaseModel):
        return sorted(set(dto.model_fields) | set(dto.model_computed_fields))
    if dataclasses.is_dataclass(dto):
        return sorted(f.name for f in dataclasses.fields(dto))
    raise TypeError(f"unsupported DTO type for {dto!r}: not a Pydantic model or dataclass")


def _member(obj: Any) -> str:
    """Render a seam member.

    Properties are rendered rather than skipped. ``inspect.signature`` RAISES on a property, and that
    limitation is why the retired ``_AUTH_SERVICE_METHODS`` tuple held methods only -- the renderer's
    capability had silently defined what counted as the contract, while the console read
    ``auth.action_step_up_required`` and five other properties across the seam.
    """
    if isinstance(obj, property):
        if obj.fget is None:
            return "property (write-only)"
        return f"property -> {inspect.signature(obj.fget).return_annotation!r}"
    if callable(obj):
        return str(inspect.signature(obj))
    return f"attribute: {type(obj).__name__}"


def build_snapshot() -> str:
    """Assemble the full deterministic snapshot text (newline-terminated)."""
    discovery = _load_discovery()
    surface = discovery.discover(_CONSOLE_DIR, _ENGINE_DIR)
    dto_classes = discovery.discover_dto_classes(_CONSOLE_DIR)
    by_name = {f"{d.__module__}.{d.__qualname__}": d for d in dto_classes}

    lines: list[str] = list(_HEADER)

    lines += ["", "## ENGINE_UI_SEAM", str(ENGINE_UI_SEAM)]

    for name, dc in (
        ("UiDeps", UiDeps),
        ("CoreHandlers", CoreHandlers),
        ("AdminHandlers", AdminHandlers),
    ):
        lines += ["", f"## dataclass messagefoundry.api._ui_seam.{name}"]
        lines += _dataclass_fields(dc)

    lines += ["", "## api.security surface (imported directly by the console, outside UiDeps)"]
    for symbol in surface.security_symbols:
        lines.append(f"{symbol}: {_member(getattr(security, symbol))}")

    lines += ["", "## AuthService members reached by the console"]
    for name in surface.auth_service_methods:
        lines.append(f"{name}: {_member(getattr(AuthService, name))}")

    lines += ["", "## app.state attributes the console sets/reads"]
    lines += list(surface.app_state_attrs)

    lines += ["", "## DTO fields rendered by the console (closed over nested models)"]
    for qualname in surface.dtos:
        fields = ", ".join(_dto_fields(by_name[qualname]))
        lines.append(f"{qualname}: {fields}")

    lines += ["", "## enum members reachable from those DTOs"]
    for name, members in sorted(discovery.enums_in_surface(dto_classes).items()):
        lines.append(f"{name}: {', '.join(members)}")

    lines += ["", "## Literal value sets on those DTOs"]
    for name, values in sorted(discovery.literals_in_surface(dto_classes).items()):
        lines.append(f"{name}: {', '.join(values)}")

    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    print(build_snapshot(), end="")
