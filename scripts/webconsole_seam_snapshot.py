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

Usage:
  ``python scripts/webconsole_seam_snapshot.py``           print the snapshot
  ``python scripts/webconsole_seam_snapshot.py --digest``  print the derived seam value only
  ``python scripts/webconsole_seam_snapshot.py --write``   rewrite ENGINE_UI_SEAM AND the golden

Use ``--write``, never a shell redirect over the golden. A redirect writes the golden and never
``ENGINE_UI_SEAM``, in EVERY shell, and it fails GREEN rather than red: ``build_snapshot`` prints
whatever seam is imported, so a redirected golden AGREES with a stale or hand-typed constant and
``test_webconsole_seam_snapshot_matches_golden`` passes. Measured against a fabricated
``deadbeefdeadbeef``, only ``test_the_stored_seam_equals_the_derived_digest`` refused it.

The encoding damage is a SECOND hazard layered on that one, and it is shell-specific, so it must not
be read as the reason: Windows PowerShell 5.1's ``>`` emits UTF-16LE with a BOM, which the test
cannot decode as UTF-8 at all, while ``pwsh`` 7 and Git Bash write a clean file and still leave the
constant stale. An earlier version of this note gave only the encoding reason, which licensed the
redirect for anyone not on 5.1 -- the failure it was warning against.
"""

from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import inspect
import re
import sys
from pathlib import Path
from typing import Any

_REPO_ROOT = Path(__file__).resolve().parents[1]
_CONSOLE_DIR = _REPO_ROOT / "messagefoundry_webconsole"
_ENGINE_DIR = _REPO_ROOT / "messagefoundry"

# ANCHOR ON THE SCRIPT, NOT ON WHATEVER sys.path OFFERS (BACKLOG #1439). It is the same rule
# scripts/coord/alloc.ps1 states for `git` (BACKLOG #1060), and the same insert the siblings
# scripts/bench/stage_residency.py and scripts/tray/make_icons.py already carry. This file measures
# the engine/console contract of the repository it LIVES IN; without the insert it measured whichever
# engine the interpreter happened to find, and said nothing about the difference.
#
# Python puts the SCRIPT's directory on sys.path[0], never the current directory, so `scripts/` led
# the path and no entry offered `messagefoundry` until site-packages. In a worktree with no .venv of
# its own -- the normal state for these sessions -- the interpreter reached for is the primary
# checkout's, whose site-packages holds a path-based editable install (`_editable_impl_*.pth`
# containing the PRIMARY checkout's root). So `import messagefoundry` resolved to the PRIMARY tree
# while the discovery walk below read _CONSOLE_DIR and _ENGINE_DIR out of THIS one.
#
# The failure was silent and it pointed the wrong way. Measured 2026-09-03 in a worktree with no
# .venv of its own: `--write` printed the unchanged digest, rewrote both files with it, and
# reported success, while tests/test_webconsole_seam_snapshot.py (which runs under pytest,
# with the repo root already on sys.path) kept failing against a digest the script had never
# computed. The script's own success output is what misled -- a reader concludes the GATE is broken
# and starts "fixing" a gate that was right. This is the SDS-3.8 shape: an instrument answering a
# question adjacent to the one asked.
#
# Inserted at 0, so it wins over that .pth entry. tests/test_webconsole_seam_snapshot.py::
# test_the_script_run_by_path_computes_the_same_digest holds the property from outside, in a
# subprocess, because nothing INSIDE this process can observe which tree it failed to import.
sys.path.insert(0, str(_REPO_ROOT))

from messagefoundry.api import security  # noqa: E402
from messagefoundry.api._ui_seam import (  # noqa: E402
    ENGINE_UI_SEAM,
    AdminHandlers,
    CoreHandlers,
    UiDeps,
)
from messagefoundry.auth.service import AuthService  # noqa: E402


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
    "# Regenerate with: python scripts/webconsole_seam_snapshot.py --write",
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


def contract_sections() -> list[tuple[str, list[tuple[str, str]]]]:
    """``(section title, [(key, value)])`` for the CONTRACT surface.

    **This function never reads ``ENGINE_UI_SEAM``.** That is what keeps the derived seam out of its
    own digest input, and it is an exclusion BY CONSTRUCTION rather than by filtering -- there is no
    "strip the seam line" step that could quietly stop matching. A reader checks the property by
    confirming the name does not appear in this function, not by trusting a regex.

    Keys are section-qualified and sorted within their section, because discovered names arrive in
    AST and filesystem order and that is the one place a derived value could move without the
    contract changing.
    """
    discovery = _load_discovery()
    surface = discovery.discover(_CONSOLE_DIR, _ENGINE_DIR)
    dto_classes = discovery.discover_dto_classes(_CONSOLE_DIR)
    by_name = {f"{d.__module__}.{d.__qualname__}": d for d in dto_classes}

    sections: list[tuple[str, list[tuple[str, str]]]] = []

    for name, dc in (
        ("UiDeps", UiDeps),
        ("CoreHandlers", CoreHandlers),
        ("AdminHandlers", AdminHandlers),
    ):
        # Declaration order, NOT sorted: the injected bundle's field order is part of its shape.
        sections.append(
            (
                f"dataclass messagefoundry.api._ui_seam.{name}",
                [(f, "") for f in _dataclass_fields(dc)],
            )
        )

    sections.append(
        (
            "api.security surface (imported directly by the console, outside UiDeps)",
            [(s, _member(getattr(security, s))) for s in surface.security_symbols],
        )
    )
    sections.append(
        (
            "AuthService members reached by the console",
            [(m, _member(getattr(AuthService, m))) for m in surface.auth_service_methods],
        )
    )
    sections.append(
        (
            "app.state attributes the console sets/reads",
            [(a, "") for a in surface.app_state_attrs],
        )
    )
    sections.append(
        (
            "DTO fields rendered by the console (closed over nested models)",
            [(q, ", ".join(_dto_fields(by_name[q]))) for q in surface.dtos],
        )
    )
    sections.append(
        (
            "enum members reachable from those DTOs",
            [(n, ", ".join(v)) for n, v in sorted(discovery.enums_in_surface(dto_classes).items())],
        )
    )
    sections.append(
        (
            "Literal value sets on those DTOs",
            [
                (n, ", ".join(v))
                for n, v in sorted(discovery.literals_in_surface(dto_classes).items())
            ],
        )
    )
    return sections


def contract_digest() -> str:
    """The seam value: a 16-hex-character SHA-256 of the discovered contract surface.

    NOT a security control -- it is a change detector, so what is needed is accidental-collision
    avoidance across the distinct contract surfaces this project will ever produce, not preimage
    resistance. Anyone able to craft a colliding surface already has commit access to ``_ui_seam.py``,
    where writing the constant directly is strictly easier.

    64 bits, by the birthday bound ``N^2 / 2^(b+1)``: at N = 10,000 distinct surfaces (about 500x the
    ~20 seam moves to date) the collision probability is 2.7e-12. 32 bits would be 1 in 86, which is
    why this is not truncated further. SHA-256 rather than a non-approved digest because the engine
    renders a ``fips_mode`` attestation and a non-approved hash in the shipped surface invites a FIPS
    question for no benefit.
    """
    payload = "\n".join(
        f"{title}\t{key}\t{value}"
        for title, records in contract_sections()
        for key, value in records
    )
    return hashlib.sha256((payload + "\n").encode("utf-8")).hexdigest()[:16]


def build_snapshot() -> str:
    """Assemble the full deterministic snapshot text (newline-terminated)."""
    lines: list[str] = list(_HEADER)
    lines += ["", "## ENGINE_UI_SEAM", str(ENGINE_UI_SEAM)]
    for title, records in contract_sections():
        lines += ["", f"## {title}"]
        lines += [f"{key}: {value}" if value else key for key, value in records]
    return "\n".join(lines) + "\n"


_SEAM_FILE = _REPO_ROOT / "messagefoundry" / "api" / "_ui_seam.py"
_GOLDEN_FILE = _REPO_ROOT / "tests" / "golden" / "webconsole_seam.snapshot"
_SEAM_LINE = re.compile(r'^ENGINE_UI_SEAM: str = "[0-9a-f]{16}"$', re.MULTILINE)


def write_seam_and_golden() -> str:
    """Rewrite the constant and the golden to the current derived digest. Returns the digest.

    Deliberately does NOT touch ``messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS``. That constant
    is the independent half of a two-wheel handshake, and a tool that writes both sides turns the
    handshake into a self-consistent tautology -- it would remove the one place a human states "this
    console build is compatible with this engine contract". The failure message spells out the
    one-line edit instead.

    Refuses rather than guesses if the constant line does not match EXACTLY once: a source-rewriting
    tool that guesses is worse than one that stops.
    """
    source = _SEAM_FILE.read_text(encoding="utf-8")
    matches = _SEAM_LINE.findall(source)
    if len(matches) != 1:
        raise SystemExit(
            f"refusing to rewrite {_SEAM_FILE}: expected exactly one line matching "
            f"{_SEAM_LINE.pattern!r}, found {len(matches)}"
        )

    digest = contract_digest()
    _SEAM_FILE.write_text(
        _SEAM_LINE.sub(f'ENGINE_UI_SEAM: str = "{digest}"', source), encoding="utf-8", newline="\n"
    )

    # Rebuild with the NEW value in scope. The digest itself does not depend on the seam (see
    # contract_sections), but the snapshot's first section prints it.
    globals()["ENGINE_UI_SEAM"] = digest
    # Written explicitly rather than via a shell redirect, which would write this file and never the
    # constant rewritten above it. See the module docstring for why that fails green.
    _GOLDEN_FILE.write_text(build_snapshot(), encoding="utf-8", newline="\n")
    return digest


if __name__ == "__main__":
    if "--digest" in sys.argv:
        print(contract_digest())
    elif "--write" in sys.argv:
        value = write_seam_and_golden()
        print(f"ENGINE_UI_SEAM = {value}")
        print(f"  rewrote {_SEAM_FILE.relative_to(_REPO_ROOT).as_posix()}")
        print(f"  rewrote {_GOLDEN_FILE.relative_to(_REPO_ROOT).as_posix()}")
        print("  NOW SET THE CONSOLE SIDE BY HAND, in the same commit:")
        print("    messagefoundry_webconsole/__init__.py")
        print(f'      SUPPORTED_ENGINE_SEAMS: frozenset[str] = frozenset({{"{value}"}})')
    else:
        print(build_snapshot(), end="")
