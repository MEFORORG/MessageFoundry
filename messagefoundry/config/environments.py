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
"""

from __future__ import annotations

import logging
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Any

__all__ = ["VALUE_ENV_PREFIX", "load_environment_values"]

#: Env-var prefix for environment values (esp. secrets): MEFOR_VALUE_EPIC_HOST -> key "epic_host".
VALUE_ENV_PREFIX = "MEFOR_VALUE_"

_log = logging.getLogger(__name__)


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
