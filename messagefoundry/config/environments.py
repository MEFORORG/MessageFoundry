# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-environment **values** for ``env()`` lookups in the message graph (DEV/PROD).

The code-first graph references environment-specific values via ``env("key")`` (see
:mod:`messagefoundry.config.wiring`); this module gathers those values for the running instance's
environment. Non-secret values live in a flat TOML table ``<dir>/<env>.toml`` (versioned in the
repo, diffable, reviewable); secrets are supplied as ``MEFOR_VALUE_<KEY>`` environment variables
(never the file), and **env overrides the file**.

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
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = [
    "VALUE_ENV_PREFIX",
    "is_drive_relative",
    "load_environment_values",
    "resolve_values_base_dir",
]

#: Env-var prefix for environment values (esp. secrets): MEFOR_VALUE_EPIC_HOST -> key "epic_host".
VALUE_ENV_PREFIX = "MEFOR_VALUE_"

_log = logging.getLogger(__name__)


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


def load_environment_values(
    *,
    base_dir: str | Path,
    dir_name: str,
    environment: str,
    environ: Mapping[str, str],
) -> dict[str, Any]:
    """Resolve this instance's environment values.

    Reads ``<base_dir>/<dir_name>/<environment>.toml`` (a flat key→scalar table) if present, then
    overlays ``MEFOR_VALUE_<KEY>`` env vars (env wins). A missing file is **not** an error here —
    referenced-but-undefined keys fail loud when a connector is built, not at gather time.
    """
    values: dict[str, Any] = {}

    path = Path(base_dir) / dir_name / f"{environment}.toml"
    if path.is_file():
        with path.open("rb") as fh:
            data = tomllib.load(fh)
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

    return values
