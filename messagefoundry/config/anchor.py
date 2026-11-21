# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
actually references ``env()`` (ADR 0050 §2 / AC-3); :func:`explicit_root_value_file_guard`
runs the same rule at each reload. PHI-safe by construction: this module only ever
handles file paths and env-reference *keys*, never values or message bodies.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePath
from typing import TYPE_CHECKING, Any

from messagefoundry.config.environments import (
    SnapshotEnvValuesProvider,
    is_drive_relative,
    resolve_values_base_dir,
)
from messagefoundry.config.wiring import EnvRef, WiringError
from messagefoundry.redaction import safe_exc

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.wiring import Registry

_log = logging.getLogger(__name__)

__all__ = [
    "resolve_project_root",
    "anchor_under_root",
    "anchored_store_path",
    "anchor_settings_store_path",
    "graph_references_env",
    "referenced_env_keys_in_graph",
    "explicit_root_value_file_guard",
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
    if value is None or root is None or value == ":memory:":
        # No root: keep today's exact string (CWD-relative downstream, unchanged). SQLite's
        # `:memory:` names no file; joined, it would become one under the root (an NTFS stream on
        # Windows), a durable store where an in-memory one was asked for.
        return value
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


def anchored_store_path(store_path: str, root: Path | None, *, cwd: Path) -> str:
    """``store_path`` with a relative value taken under the project root ``root``.

    The rule ``serve`` and at least the offline store commands apply to ``[store].path`` after the
    settings load (BACKLOG #5926, #5927), so a command run away from the root names the store serve
    opens, where both see the same root (:func:`anchor_settings_store_path` says where they do
    not): a relative path, whether it came from ``--db`` or the settings file, follows the root, an
    absolute one stays put (AC-1/AC-7), and with no root the string is returned unchanged, to
    resolve against the working directory as it always has. The join is :func:`anchor_under_root`'s,
    so a leading-slash drive-relative path warns and stays under the root, as every other bundle
    member does, and SQLite's ``:memory:`` sentinel is returned unchanged.

    It is not backend-gated, because ``serve`` is not: a server backend never opens this path, but
    the generated TLS pair's state dir is derived from it (``generated_state_dir``), and a gated
    copy would name a different pair from the one serve uses.
    """
    # A str in is a str out (only None maps to None); the `or` only narrows the type.
    return anchor_under_root(store_path, root, cwd=cwd) or store_path


def anchor_settings_store_path(settings: ServiceSettings | None, *, cwd: Path) -> None:
    """Apply :func:`anchored_store_path` to loaded settings in place, under the root the loaded
    ``[environments].base_dir`` names. ``None`` (a command that tolerates a settings file it could
    not load, such as ``support-bundle``) is a no-op.

    What it does NOT cover: only ``serve`` and ``supervise`` take ``--project-root``. An offline
    command sees the base_dir the settings file or the environment sets, and nothing else, so it
    names the store serve opens only where serve's root comes from the same place, or where the
    path is absolute. A service started with ``--project-root`` and a relative ``[store].path`` in
    a file with no base_dir, or a different one, is not matched; pass an absolute ``--db``.

    Call it straight after the load and BEFORE any guard that tests the path, an existence check
    or a refusal, or the guard tests a different file from the one the command then opens."""
    if settings is None:
        return
    root = resolve_project_root(settings.environments.base_dir or None, cwd=cwd)
    settings.store.path = anchored_store_path(settings.store.path, root, cwd=cwd)


def _iter_settings_values(registry: Registry) -> Iterable[Any]:
    """Every settings value across the graph that could hold an :class:`EnvRef` this graph resolves.

    Connection ``spec.settings`` (inbound + outbound), the live-lookup connection settings
    (``db_lookup`` / ``fhir_lookup``), and each reference set's source settings all carry ``env()``
    references as dict values (see the ``env()`` examples in ``wiring.py``). Routers/Handlers author
    *logic*, not transport settings, so they hold no ``EnvRef`` — they are not scanned.

    A ``deployed=False`` connection counts only for the settings its guarded directories come
    from (BACKLOG #5775). It is never built (ADR 0111 AC-1), so counting all of it failed the AC-3
    check under an explicit root for a connection that is switched off. The ``.processed`` archive
    sweep's guard still resolves those directory settings on every connection, deployed or not
    (``RegistryRunner.archive_guard_dirs``), and with a value missing there it deletes nothing, so
    they still count. Turning the connection on is a config change that takes a reload, and a
    reload runs the same check again (:func:`explicit_root_value_file_guard`).
    """
    from messagefoundry.transports.base import guard_dir_settings

    for _kind, _name, settings, deployed in registry.settings_carriers():
        if deployed:
            yield from _mapping_values(settings)
    for ic in registry.inbound.values():
        if not ic.deployed:
            yield from _mapping_values(guard_dir_settings(ic.spec.type, ic.spec.settings) or {})
    for oc in registry.outbound.values():
        if not oc.deployed:
            guarded = guard_dir_settings(oc.spec.type, oc.spec.settings, outbound=True)
            yield from _mapping_values(guarded or {})


def _mapping_values(settings: Mapping[str, Any]) -> Iterable[Any]:
    """Flatten a settings mapping's values, descending one level into a nested list (e.g. ``recipients``)
    so an ``EnvRef`` carried inside a list value is still seen."""
    for value in settings.values():
        if isinstance(value, (list, tuple)):
            yield from value
        else:
            yield value


def referenced_env_keys_in_graph(registry: Registry) -> list[str]:
    """The sorted, de-duplicated ``env()`` keys the loaded graph references, on its deployed
    connections, in a switched-off connection's directory settings, and on every lookup and
    reference set (:func:`_iter_settings_values`).

    The graph-wide analogue of :func:`messagefoundry.config.wiring.referenced_env_keys` (which is
    per-settings-dict). Empty ⇒ a zero-``env()`` deployment — the case ADR 0050 AC-3 must never
    regress to a hard failure.
    """
    return sorted({v.key for v in _iter_settings_values(registry) if isinstance(v, EnvRef)})


def graph_references_env(registry: Registry) -> bool:
    """Whether the loaded graph contains at least one ``env()`` reference it resolves, so not one
    on a ``deployed=False`` connection alone (ADR 0050 §2 / AC-3 gate, :func:`_iter_settings_values`).

    This is the precondition that — together with an *explicit* project root and an absent
    ``<env>.toml`` — turns a missing value file into a hard startup failure. A graph with **zero**
    ``env()`` uses keeps the shipped silent-empty contract of ``load_environment_values`` and is never
    failed for a missing file.
    """
    return any(isinstance(v, EnvRef) for v in _iter_settings_values(registry))


def explicit_root_value_file_guard(
    settings: ServiceSettings | None, provider: Callable[[], Mapping[str, Any]] | None
) -> Callable[[Registry], None] | None:
    """The AC-3 check as a registry guard, so a reload is judged by it as the start is.

    ``serve`` runs AC-3 at start (``_emit_anchor_diagnostics``). Since a ``deployed=False``
    connection's ``env()`` counts only in part (:func:`_iter_settings_values`), a start can pass it
    with such a connection, and a later reload that turns the connection on would then run it on
    the values a missing file leaves, ``env(default=...)`` and ``MEFOR_VALUE_*`` alone, with no
    refusal (BACKLOG #5775, from engine PR 3107). This guard refuses that reload with the same
    rule: an explicit project root, a graph that references ``env()``, and no value file.

    ``settings`` is the resolved service configuration; its ``[environments].base_dir`` is the
    explicit root, set by ``--project-root`` or the settings file, as ``serve`` reads it. The value
    file is the one ``provider`` reads (:attr:`SnapshotEnvValuesProvider.value_file`). Returns
    ``None``, no check, where there is no explicit root, or no provider naming a value file, as for
    an embedder that hands the engine its values directly.

    The engine runs its guard at the first load and on every reload, a dry run included, over the
    whole graph before an engine shard's filter, so every engine shard reaches one verdict. Where
    the load's config snapshot covers the value file, presence is the snapshot's, the read the
    reload's values were parsed from; else it is a stat of the file. The refusal names paths only,
    never a value."""
    if settings is None or not settings.environments.base_dir:
        return None
    if not isinstance(provider, SnapshotEnvValuesProvider):
        return None
    value_file = provider.value_file
    if value_file is None:
        return None

    def _refuse_missing_value_file(registry: Registry) -> None:
        if not graph_references_env(registry):
            return  # zero-env() graph: the silent-empty contract is preserved (AC-3).
        fault = ""
        try:
            present = _value_file_present(registry, value_file)
        except OSError as exc:
            fault = safe_exc(exc)
        if fault:
            # Raised outside the handler, so it carries no exception chain.
            raise WiringError(
                f"the graph references env() and the value file {value_file} could not be "
                f"checked: {fault}"
            )
        if not present:
            raise WiringError(
                f"the graph references env() but no value file was found at {value_file}, and "
                "[environments].base_dir names an explicit project root. Create the file, or "
                "correct [environments].base_dir and restart."
            )

    return _refuse_missing_value_file


def _value_file_present(registry: Registry, value_file: Path) -> bool:
    """Whether ``value_file`` is there for this load: as its config snapshot read it where the
    snapshot covers it, else as a stat finds it now. Raises ``OSError`` for a fault, never reading
    one as no file (:func:`~messagefoundry.config.snapshot.is_regular_file`)."""
    from messagefoundry.config.snapshot import is_regular_file

    snapshot = registry.config_snapshot
    if snapshot is not None and snapshot.covers_environment_file(value_file):
        return snapshot.environment_file(value_file) is not None
    return is_regular_file(value_file)
