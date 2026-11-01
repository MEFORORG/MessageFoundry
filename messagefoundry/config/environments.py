# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-environment **values** for ``env()`` lookups in the message graph (DEV/PROD).

The code-first graph references environment-specific values via ``env("key")`` (see
:mod:`messagefoundry.config.wiring`); this module gathers those values for the running instance's
environment. Non-secret values live in a flat TOML table ``<dir>/<env>.toml`` (versioned in the
repo, diffable, reviewable); secrets are supplied as ``MEFOR_VALUE_<KEY>`` environment variables
or as files of that name in the secrets directory (never the file), and **env overrides the file**,
and the secrets directory overrides both.

This module only *gathers* the values; a referenced key that ends up undefined is surfaced **loud**
later, when the engine builds the connector (:func:`messagefoundry.config.wiring.resolve_env_settings`)
— so a missing value can never silently become a blank host. Keys are lower-cased: ``env("epic_host")``
matches ``epic_host`` in the file and ``MEFOR_VALUE_EPIC_HOST`` in the environment.

**Where the value files live (the anchor).** The value directory (``[environments].dir``, default
``environments``) is resolved against a *base directory*. By default that base is the process working
directory (``Path.cwd()``) — historical behavior, unchanged. A standalone **config repo** (ADR 0017)
keeps ``environments/`` at the repo root (a sibling of the ``--config`` dir), so a ``serve`` launched
from anywhere but the repo root — most notably **under NSSM**, whose working dir is rarely the repo —
would otherwise silently read *no* env values. :func:`resolve_values_base_dir` lets a deployment pin
that base explicitly (``[environments].base_dir`` / ``serve --project-root``) so resolution no longer
depends on the launch directory. Leaving it empty keeps the cwd default.
"""

from __future__ import annotations

import logging
import tomllib
from abc import ABC, abstractmethod
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from messagefoundry.config.snapshot import ConfigSnapshot

from messagefoundry.engine_secrets import VALUE_PREFIX, open_secrets_directory

__all__ = [
    "VALUE_ENV_PREFIX",
    "EnvironmentValuesReader",
    "SnapshotEnvValuesProvider",
    "ValuesRead",
    "environment_values_from_bytes",
    "is_drive_relative",
    "load_environment_values",
    "resolve_values_base_dir",
    "values_file_path",
]

#: Env-var prefix for environment values (esp. secrets): MEFOR_VALUE_EPIC_HOST -> key "epic_host".
VALUE_ENV_PREFIX = VALUE_PREFIX

_log = logging.getLogger(__name__)


class SnapshotEnvValuesProvider(ABC):
    """An engine ``env_values_provider`` that can also read a reload's values from that reload's
    config snapshot (vault BACKLOG #2596). A provider opts in by subclassing, never by having a
    method of the right name. ``serve``'s provider is one."""

    __slots__ = ()

    @abstractmethod
    def __call__(self) -> Mapping[str, Any]:
        """The values, read from disk: at start, and on a reload that read no snapshot."""

    @abstractmethod
    def from_snapshot(self, snapshot: ConfigSnapshot) -> Mapping[str, Any] | None:
        """The values, with a value file ``snapshot`` covers parsed from its bytes, or ``None``
        when the value file this provider reads is outside the snapshot
        (:meth:`~messagefoundry.config.snapshot.ConfigSnapshot.covers_environment_file`). On
        ``None`` the engine calls the provider plainly and, on a released reload, checks the digest
        again."""


class ValuesRead(Protocol):
    """A read of one value file's environment values, from disk, or with ``snapshot`` from the
    bytes it read, raising :class:`~messagefoundry.config.snapshot.NotInSnapshot` for a value file
    outside it."""

    def __call__(
        self,
        *,
        base_dir: Path,
        dir_name: str,
        environment: str,
        snapshot: ConfigSnapshot | None = None,
    ) -> dict[str, Any]: ...


class EnvironmentValuesReader(SnapshotEnvValuesProvider):
    """A :class:`SnapshotEnvValuesProvider` over one value file,
    ``<base_dir>/<dir_name>/<environment>.toml``, read by ``read``. ``serve`` passes its own read,
    which vets the file's owner and access list and names the file in a refusal."""

    __slots__ = ("_read", "base_dir", "dir_name", "environment")

    def __init__(
        self, read: ValuesRead, *, base_dir: Path, dir_name: str, environment: str
    ) -> None:
        self._read = read
        self.base_dir = base_dir
        self.dir_name = dir_name
        self.environment = environment

    def __call__(self) -> dict[str, Any]:
        return self._read(
            base_dir=self.base_dir, dir_name=self.dir_name, environment=self.environment
        )

    def from_snapshot(self, snapshot: ConfigSnapshot) -> dict[str, Any] | None:
        from messagefoundry.config.snapshot import NotInSnapshot

        try:
            return self._read(
                base_dir=self.base_dir,
                dir_name=self.dir_name,
                environment=self.environment,
                snapshot=snapshot,
            )
        except NotInSnapshot:
            # A path only, never a value. The default layout keeps the value file outside the
            # config directory, so this is the usual line there, and it says why the release then
            # takes a second digest.
            _log.info(
                "environment value file %s is outside the config snapshot; the reload reads it "
                "from disk",
                values_file_path(self.base_dir, self.dir_name, self.environment),
            )
            return None


def is_drive_relative(value: str) -> bool:
    """Whether ``value`` is rooted-looking (leading ``/`` or ``\\``) but not *truly* absolute here.

    The classic Windows footgun: ``/repo`` parses as **drive-relative**, so ``cwd / "/repo"`` silently
    inherits ``cwd``'s drive (``C:\\repo``) and any path built on it again depends on the launch
    directory — defeating an anchor. POSIX has no such case (a leading ``/`` *is* absolute there), so
    this is ``False`` off Windows. Shared by :func:`resolve_values_base_dir` (the root) and the
    bundle-member anchor (``config.anchor.anchor_under_root``) so the same guard covers both (ADR 0050
    AC-8, generalized from the root to every member).
    """
    return bool(value) and value[0] in ("/", "\\") and not Path(value).is_absolute()


def resolve_values_base_dir(base_dir: str, *, cwd: Path) -> Path:
    """Anchor for the per-environment value directory (``[environments].dir``).

    With ``base_dir`` empty (the default), the value files resolve against ``cwd`` — the process
    working directory, preserving the original behavior. With it set (``[environments].base_dir`` or
    ``serve --project-root``), they resolve against that anchor instead, so env-value resolution does
    not depend on where ``serve`` was launched (the standalone-config-repo / NSSM footgun). A
    **relative** anchor is taken against ``cwd``.

    An **absolute** anchor is used as-is — but only if it is *fully* absolute on the running platform.
    On **Windows** that means **drive-qualified** (``C:/repo``): a leading-slash path like ``/repo`` is
    *drive-relative*, so ``cwd / "/repo"`` silently inherits ``cwd``'s drive (``C:\\repo``) and
    resolution again depends on the launch directory — defeating the anchor. Such a not-truly-absolute
    rooted anchor is logged as a warning rather than trusted; the path is still returned (no behavior
    change), but the operator is told to fully-qualify it.
    """
    if not base_dir:
        return cwd
    # A rooted-looking anchor that isn't truly absolute on this platform (the classic case: a
    # drive-relative "/repo" on Windows) still resolves against cwd, re-introducing the very
    # launch-directory dependence the anchor exists to remove. Surface it loud instead of silently.
    if is_drive_relative(base_dir):
        _log.warning(
            "environments base_dir %r is not fully absolute on this platform — it resolves against "
            "the working directory (%s), so env-value resolution still depends on where the process "
            "was launched. Use a fully-qualified path (on Windows, drive-qualified, e.g. C:/repo).",
            base_dir,
            cwd,
        )
    return cwd / base_dir


def values_file_path(base_dir: str | Path, dir_name: str, environment: str) -> Path:
    """The value file :func:`load_environment_values` reads, ``<base_dir>/<dir_name>/<env>.toml``.

    One rule, so the ``serve`` and ``supervise`` start checks vet the file the load reads (vault
    BACKLOG #2626)."""
    return Path(base_dir) / dir_name / f"{environment}.toml"


def load_environment_values(
    *,
    base_dir: str | Path,
    dir_name: str,
    environment: str,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    """Resolve this instance's environment values.

    Reads ``<base_dir>/<dir_name>/<environment>.toml`` (a flat table of scalars and arrays with no
    table in them) if present, then overlays ``MEFOR_VALUE_<KEY>`` env vars (env wins), then a ``MEFOR_VALUE_<KEY>`` file in the secrets
    directory (the directory wins; :mod:`messagefoundry.engine_secrets`). A missing file is **not** an error here —
    referenced-but-undefined keys fail loud when a connector is built, not at gather time.
    :func:`environment_values_from_bytes` says what it refuses.
    """
    path = values_file_path(base_dir, dir_name, environment)
    return environment_values_from_bytes(
        path.read_bytes() if path.is_file() else None, path=path, environ=environ
    )


def _tables_in_array(array: list[Any]) -> list[str]:
    """The index path of each table inside ``array``: ``1`` for an item, ``0.1`` for an item of a
    nested array. No depth cap, because a capped walk would stop at a depth a value file can reach,
    and what it missed would load."""
    found: list[str] = []
    stack: list[tuple[str, list[Any]]] = [("", array)]
    while stack:
        prefix, items = stack.pop()
        for index, item in enumerate(items):
            if isinstance(item, dict):
                found.append(f"{prefix}{index}")
            elif isinstance(item, list):
                stack.append((f"{prefix}{index}.", item))
    return found


def environment_values_from_bytes(
    file_bytes: bytes | None, *, path: Path, environ: Mapping[str, str]
) -> dict[str, Any]:
    """:func:`load_environment_values` over the value file's bytes already read, ``None`` when there
    is no file. ``path`` only names the file in a warning. A released reload parses the bytes its
    approval digest covered this way, rather than reading the file again (vault BACKLOG #2596).

    Raises ``ValueError`` on a table anywhere inside an array value, in the inline or the
    ``[[tables]]`` spelling, referenced or not (BACKLOG #1820). :func:`~messagefoundry.config.wiring.resolve_env_settings`
    hands a value over whole, so an env marker in such a table is never resolved and a connector
    that ``str()``s the item would carry its ``default=``. Today no setting takes a list of tables,
    so any table is refused, not just a marker: a marker with one more key, or nested past the wiring
    scan's depth, reaches ``str()`` the same way. The check sits here because at least the disk read
    and the snapshot read both pass through this function. Only the file can hold an array here: the
    overlay and the secrets directory supply strings. At least a mapping handed in directly, such as
    ``Engine(env_values=...)``, never comes through this function, so it is not checked.

    The message names the key and index only, because ``messagefoundry check`` prints it as it is."""
    values: dict[str, Any] = {}
    if file_bytes is not None:
        data = tomllib.loads(file_bytes.decode("utf-8"))
        tables = [
            f"{key!r} item {where}"
            for key, value in data.items()
            if isinstance(value, list)
            for where in _tables_in_array(value)
        ]
        if tables:
            # One offender and a count, and short, because safe_exc cuts at about 200 characters on
            # the serve path. The walk's order is not file order, so it is not called the first.
            raise ValueError(
                f"a value file may not hold a table inside an array ({len(tables)} found, "
                f"including {tables[0]}) - nothing resolves it. Use scalar items or remove the key."
            )
        for key, value in data.items():
            if isinstance(value, dict):
                # Nested tables are reserved (future grouping); a value must be a scalar/array today.
                _log.warning("environment values %s: ignoring nested table [%s]", path, key)
                continue
            # Keys are matched lower-cased (so a file key, an env() reference, and a MEFOR_VALUE_*
            # override all agree regardless of source casing). Warn if two file keys collide once
            # folded, rather than silently letting the last win.
            norm = key.lower()
            if norm in values:
                _log.warning(
                    "environment values %s: keys collide once lower-cased (%r); last one wins",
                    path,
                    key,
                )
            values[norm] = value

    for name, value in environ.items():
        if name.startswith(VALUE_ENV_PREFIX):
            key = name[len(VALUE_ENV_PREFIX) :].lower()
            if key:
                values[key] = value  # env (incl. secrets) overrides the file

    # The secrets directory overrides both (vault BACKLOG #2595, ADR 0214): a file named
    # MEFOR_VALUE_<KEY> there supplies that value. Unset, nothing is read; unusable, it refuses.
    directory = open_secrets_directory(environ)
    if directory is not None:
        for name, value in directory.read_values().items():
            values[name[len(VALUE_ENV_PREFIX) :].lower()] = value

    return values
