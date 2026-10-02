# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The one map of where the harness config graphs listen and write, shared by both ends.

A served graph under ``harness/config/`` reads its ports and directories from here, and a scenario
reads the same names to know where to inject and where to listen. Keeping both ends on one table is
what stops a graph and its scenarios drifting apart.

Each value resolves in this order: an explicit override (a scenario run's ``--endpoint KEY=VALUE``,
or a test's own mapping), then the environment variable ``MEFOR_HARNESS_<KEY>``, then the default.
The defaults are the fixed ports and directories the harness has always documented, so
``python -m messagefoundry serve --config harness/config`` behaves as before. Tests set the
environment variables to ephemeral ports and temporary directories, so the REAL graph runs under
test rather than a copy of it.

One module per family (``coverage.py``, and later ``tcp.py`` and so on) declares its own endpoints
in ``ENDPOINTS``; they are discovered, so a new family adds a file rather than editing this one.
Stdlib only: a config graph imports this at engine load time.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from functools import cache

from harness._discover import family_modules

#: The prefix every endpoint's environment variable carries.
ENV_PREFIX = "MEFOR_HARNESS_"


#: The three shapes an endpoint value takes. A test rig gives every ``port`` an ephemeral port and
#: every ``path`` a temporary directory, and leaves a ``host`` alone.
PORT = "port"
PATH = "path"
HOST = "host"


@dataclass(frozen=True)
class Endpoint:
    """One named address: a port, a directory, or a host."""

    key: str
    shape: str
    default: str
    description: str

    def __post_init__(self) -> None:
        if self.shape not in (PORT, PATH, HOST):
            raise ValueError(f"endpoint {self.key!r} has unknown shape {self.shape!r}")

    @property
    def env(self) -> str:
        return ENV_PREFIX + self.key.upper()


@cache
def registry() -> Mapping[str, Endpoint]:
    """Every declared endpoint by key. A key declared twice is an error, not a silent override."""
    found: dict[str, Endpoint] = {}
    for module in family_modules(__name__):
        for endpoint in getattr(module, "ENDPOINTS", ()):
            if endpoint.key in found:
                raise ValueError(f"harness endpoint {endpoint.key!r} is declared twice")
            found[endpoint.key] = endpoint
    return found


class Endpoints:
    """Resolved endpoint values for one run: overrides, then the environment, then defaults."""

    def __init__(
        self,
        overrides: Mapping[str, str] | None = None,
        *,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._overrides = dict(overrides or {})
        self._environ = os.environ if environ is None else environ
        unknown = sorted(set(self._overrides) - set(registry()))
        if unknown:
            raise KeyError(f"unknown harness endpoint(s): {', '.join(unknown)}")

    def value(self, key: str) -> str:
        endpoint = registry()[key]
        if key in self._overrides:
            return self._overrides[key]
        return self._environ.get(endpoint.env, "") or endpoint.default

    def port(self, key: str) -> int:
        raw = self.value(key)
        try:
            port = int(raw)
        except ValueError:
            raise ValueError(
                f"harness endpoint {key!r} must be a port number, got {raw!r}"
            ) from None
        if not 0 < port < 65536:
            raise ValueError(f"harness endpoint {key!r} is out of the port range: {port}")
        return port

    @property
    def host(self) -> str:
        return self.value("host")


def value(key: str) -> str:
    """The environment-resolved value of ``key`` (no overrides): what a served graph binds."""
    return Endpoints().value(key)


def port(key: str) -> int:
    """The environment-resolved port for ``key``, validated."""
    return Endpoints().port(key)
