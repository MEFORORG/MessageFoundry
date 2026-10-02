# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Serve the REAL ``harness/config`` graphs in-process, on ephemeral ports and temporary dirs.

The graphs read their ports and directories from ``harness/endpoints/`` through
``MEFOR_HARNESS_<KEY>`` environment variables, so a test can run exactly the config an operator
serves, not a copy of it, without colliding with a fixed port. :func:`ephemeral_overrides` picks
the values; :func:`serve_harness_config` sets the variables, starts the engine and API, and puts
the environment back on the way out.

Shared by the harness scenario, hostile-content and fuzz tests. The readiness logic deliberately
reaches ``uvicorn.Server``, ``threading.Thread`` and ``time`` through their modules, so
``test_server_readiness_uses_one_budget_and_always_cleans_up`` can drive it with fakes.
"""

from __future__ import annotations

import os
import socket
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

import uvicorn

from harness import endpoints as harness_endpoints
from harness.endpoints import PATH, PORT, Endpoints
from messagefoundry.api import create_managed_app

REPO = Path(__file__).resolve().parents[1]
HARNESS_CONFIG = REPO / "harness" / "config"

#: One budget for a slow startup, rather than restarting it.
START_TIMEOUT_SECONDS = 40.0


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


def ephemeral_overrides(tmp_path: Path) -> dict[str, str]:
    """A value for every declared endpoint: a fresh port for each port, a directory under
    ``tmp_path`` for each path. Hosts keep their loopback default."""
    overrides: dict[str, str] = {}
    for key, endpoint in harness_endpoints.registry().items():
        if endpoint.shape == PORT:
            overrides[key] = str(free_port())
        elif endpoint.shape == PATH:
            overrides[key] = str(tmp_path / "io" / key)
    return overrides


@contextmanager
def _environment(values: Mapping[str, str]) -> Iterator[None]:
    saved = {k: os.environ.get(k) for k in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, old in saved.items():
            if old is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = old


@contextmanager
def serve_harness_config(
    tmp_path: Path, overrides: Mapping[str, str], *, config_dir: Path = HARNESS_CONFIG
) -> Iterator[tuple[str, Endpoints]]:
    """Serve ``config_dir`` with ``overrides`` applied; yield the API URL and the endpoints."""
    registry = harness_endpoints.registry()
    env = {registry[key].env: value for key, value in overrides.items()}
    with _environment(env):
        app = create_managed_app(
            db_path=tmp_path / "harness.db", config_dir=config_dir, poll_interval=0.05
        )
        api_port = free_port()
        uv = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=api_port, log_level="warning")
        )
        thread = threading.Thread(target=uv.run, daemon=True)
        thread.start()
        deadline = time.monotonic() + START_TIMEOUT_SECONDS
        try:
            while True:
                if not thread.is_alive():
                    raise RuntimeError(f"server exited during startup (api_port={api_port})")
                if uv.started:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError(
                        f"server startup timed out after {START_TIMEOUT_SECONDS:g}s "
                        f"(api_port={api_port})"
                    )
                time.sleep(min(0.05, remaining))
            yield f"http://127.0.0.1:{api_port}", Endpoints(overrides)
        finally:
            uv.should_exit = True
            thread.join(timeout=10)
