# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Single project-root anchoring for the whole config bundle (ADR 0050).

One *logical* configuration bundle — the ``--config`` graph dir, the sibling ``environments/`` value
files, the per-instance ``messagefoundry.toml``, and the store DB — historically resolved against
**three independent filesystem roots** (``--config``, CWD-for-``environments/``, bare-CWD for
``messagefoundry.toml`` / the DB). The worst footgun is a ``serve`` launched from a non-repo working
directory (the NSSM case): it silently reads *no* ``env()`` values and creates the DB in the wrong
place, with no loud startup error.

This module pins every member to ONE **project root** ``R`` with a single, shared precedence rule —
**explicit absolute path > project-root > CWD** — so a deployment sets the root once and everything is
found under it. ``R`` itself comes from ``--project-root`` (CLI) **or** ``[environments].base_dir``
(env/file); they are the *same* merged value (``--project-root`` is written into
``cli["environments"]["base_dir"]`` by the CLI). Unset → no root → every member falls back to CWD,
**exactly today's behavior** — the anchor is opt-in and backward-compatible.

**One ordering caveat (scoped limit).** ``--config`` / ``--service-config`` must be resolved *before*
``load_settings`` (they tell it where to read), so they can only follow the **CLI** ``--project-root`` —
a root set *only* via a file/env ``[environments].base_dir`` cannot retro-anchor them (it would be a
chicken-and-egg pre-read of the very file we are locating). Every member resolved *after* the settings
load — ``[store].path``, the ``environments/`` value dir, and the startup diagnostics — honors the
**merged** root from *either* source. So a file-only ``base_dir`` anchors the env values, the DB, and
the diagnostics; use ``--project-root`` to additionally anchor ``--config`` / ``--service-config``.

The resolution is done *at the call site* (``serve`` / the offline subcommands) **before** the strings
reach ``load_config`` / ``load_settings``, so neither the wiring loader nor the settings loader is
modified: a relative member (whether it came from a flag or a config file) is taken against ``R``; an
already-absolute member is used as-is. ``codesets/`` / ``connections.toml`` stay anchored under the
resolved ``--config`` dir (ADR 0007) — once ``--config`` follows the root, so do they.

The fail-loud half lives in :func:`graph_references_env`: it lets ``serve`` (and the offline gate)
distinguish a graph that *needs* the value file from a zero-``env()`` deployment that legitimately
ships none, so a missing ``<env>.toml`` under an *explicit* root only hard-fails when the graph
actually references ``env()`` (ADR 0050 §2 / AC-3). PHI-safe by construction: this module only ever
handles file paths and env-reference *keys*, never values or message bodies.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any

from messagefoundry.config.environments import is_drive_relative, resolve_values_base_dir
from messagefoundry.config.wiring import EnvRef

if TYPE_CHECKING:
    from messagefoundry.config.wiring import Registry

_log = logging.getLogger(__name__)

__all__ = [
    "resolve_project_root",
    "anchor_under_root",
    "graph_references_env",
    "referenced_env_keys_in_graph",
]


def resolve_project_root(project_root: str | None, *, cwd: Path) -> Path | None:
    """The bundle anchor ``R`` from ``--project-root`` / ``[environments].base_dir``, or ``None``.

    An empty/unset value yields ``None`` — no root, so every member keeps its CWD-relative default
    (the historical behavior, unchanged). A set value is resolved by :func:`resolve_values_base_dir`,
    which reuses the existing drive-relative guard (ADR 0050 AC-8): a relative anchor is taken against
    ``cwd``; a fully-absolute one is used as-is; a rooted-but-not-truly-absolute anchor (a Windows
    drive-relative ``/repo``) warns rather than silently inheriting the launch drive.
    """
    if not project_root:
        return None
    return resolve_values_base_dir(project_root, cwd=cwd)


def anchor_under_root(value: str | None, root: Path | None, *, cwd: Path) -> str | None:
    """Resolve one bundle member (``--config`` / ``--service-config`` / ``--db`` / ``[store].path``).

    Precedence (ADR 0050 §1, ratified): an **explicit absolute** path is honored as-is even when a root
    is set; a **relative** value resolves under ``root`` when one is set. With **no root** the value is
    returned **unchanged** — the historical CWD-relative resolution then happens downstream exactly as
    today (no eager rewrite, so an existing deployment's stored ``[store].path`` string is byte-for-byte
    preserved). ``None`` passes through ``None`` so an unset flag still falls through to its own default
    (e.g. ``[store].path`` from the settings file).

    A relative ``--db`` (indistinguishable, post-merge, from a file-set relative ``[store].path``) thus
    follows the root, while an absolute one stays put — letting a deployment keep the DB on a separate
    fast volume by making ``[store].path`` absolute (AC-7). ``cwd`` is accepted for a symmetric, explicit
    signature (and future use); with no root it is intentionally not applied.

    A **drive-relative** member (a leading-slash ``/data/mf.db`` on Windows, AC-8 generalized from the
    root to every member) is the one trap: ``Path('C:/repo') / '/data/mf.db'`` *discards* the root
    (because the member parses as rooted), silently landing on the LAUNCH drive. We warn and strip the
    leading separators so the member stays under ``root`` (root-honoring, never an escape) — mirroring
    the loud-not-silent stance of :func:`resolve_values_base_dir` for the root itself.
    """
    if value is None or root is None:
        return value  # no root: keep today's exact string (CWD-relative downstream, unchanged)
    p = Path(value)
    if p.is_absolute():
        return value  # explicit absolute path bypasses the root (preserve the exact string)
    if is_drive_relative(value):
        # Rooted-but-not-truly-absolute (Windows drive-relative): root / p would discard the root and
        # escape onto the launch drive. Warn (paths only — PHI-safe) and keep it under the root.
        _log.warning(
            "config path %r is drive-relative, not fully absolute — anchoring its tail under the "
            "project root %s so resolution does not silently depend on the launch drive. Use a "
            "fully-qualified path (on Windows, drive-qualified, e.g. C:/repo/mf.db) or a plain "
            "relative path.",
            value,
            root,
        )
        # Drop the leading root marker(s) so the join keeps the tail under R rather than discarding R.
        tail = PurePath(value)
        parts = tail.parts[1:] if tail.parts and tail.parts[0] in ("/", "\\") else tail.parts
        return str(root.joinpath(*parts))
    return str(root / p)


def _iter_settings_values(registry: Registry) -> Iterable[Any]:
    """Every settings value across the graph that could hold an :class:`EnvRef`.

    Connection ``spec.settings`` (inbound + outbound), the live-lookup connection settings
    (``db_lookup`` / ``fhir_lookup``), and each reference set's source settings all carry ``env()``
    references as dict values (see the ``env()`` examples in ``wiring.py``). Routers/Handlers author
    *logic*, not transport settings, so they hold no ``EnvRef`` — they are not scanned.
    """
    for inbound_conn in registry.inbound.values():
        yield from _mapping_values(inbound_conn.spec.settings)
    for outbound_conn in registry.outbound.values():
        yield from _mapping_values(outbound_conn.spec.settings)
    for db_lookup in registry.lookups.values():
        yield from _mapping_values(db_lookup.settings)
    for fhir_lookup in registry.fhir_lookups.values():
        yield from _mapping_values(fhir_lookup.settings)
    for ref in registry.references.values():
        yield from _mapping_values(ref.source.settings)


def _mapping_values(settings: Mapping[str, Any]) -> Iterable[Any]:
    """Flatten a settings mapping's values, descending one level into a nested list (e.g. ``recipients``)
    so an ``EnvRef`` carried inside a list value is still seen."""
    for value in settings.values():
        if isinstance(value, (list, tuple)):
            yield from value
        else:
            yield value


def referenced_env_keys_in_graph(registry: Registry) -> list[str]:
    """The sorted, de-duplicated ``env()`` keys the whole loaded graph references.

    The graph-wide analogue of :func:`messagefoundry.config.wiring.referenced_env_keys` (which is
    per-settings-dict). Empty ⇒ a zero-``env()`` deployment — the case ADR 0050 AC-3 must never
    regress to a hard failure.
    """
    return sorted({v.key for v in _iter_settings_values(registry) if isinstance(v, EnvRef)})


def graph_references_env(registry: Registry) -> bool:
    """Whether the loaded graph contains at least one ``env()`` reference (ADR 0050 §2 / AC-3 gate).

    This is the precondition that — together with an *explicit* project root and an absent
    ``<env>.toml`` — turns a missing value file into a hard startup failure. A graph with **zero**
    ``env()`` uses keeps the shipped silent-empty contract of ``load_environment_values`` and is never
    failed for a missing file.
    """
    return any(isinstance(v, EnvRef) for v in _iter_settings_values(registry))
