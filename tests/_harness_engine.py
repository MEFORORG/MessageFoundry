# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Serve the REAL ``harness/config`` graphs in-process, on ephemeral ports and temporary dirs.

The graphs read their ports and directories as engine environment values, which the engine
overlays from ``MEFOR_VALUE_HARNESS_<KEY>`` variables (``harness/endpoints/`` names them), so a test
can run exactly the config an operator serves, not a copy of it, without colliding with a fixed
port. :func:`ephemeral_overrides` picks
the values; :func:`serve_harness_config` sets the variables, starts the engine and API, and puts
the environment back on the way out.

Written to be shared by every harness test that needs a served graph. The readiness logic
deliberately reaches ``uvicorn.Server``, ``threading.Thread`` and ``time`` through their modules, so
``test_server_readiness_uses_one_budget_and_always_cleans_up`` can drive it with fakes.
"""

from __future__ import annotations

import os
import random
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
from messagefoundry.config.environments import load_environment_values
from messagefoundry.config.settings import EgressSettings, load_settings

REPO = Path(__file__).resolve().parents[1]
HARNESS_CONFIG = REPO / "harness" / "config"

#: One budget for a slow startup, rather than restarting it.
START_TIMEOUT_SECONDS = 40.0


#: The port window the served harness graphs take their listeners from. A port the KERNEL assigns
#: (``bind(0)``) and then releases can be handed to an unrelated socket a moment later, and a served
#: harness graph releases about thirty of them before the engine binds them; under pytest-xdist that
#: collided often enough to fail a run. This window sits below every OS ephemeral floor (Linux
#: 32768, Windows and macOS 49152), so the kernel never hands one out, and above the connscale
#: windows that end at 31700 (tests/_connscale_ports.py, which records how the band was measured).
PORT_LO = 31700
PORT_HI = 32700

#: The narrowest slice a worker gets. One served graph takes about thirty ports (every PORT endpoint
#: plus the API), so a slice must hold more than one graph's worth or a single graph could be handed
#: the same port twice. Past the worker count the window can hold at this width, workers share
#: slices, and the random start below keeps them apart.
MIN_SLICE = 64

_cursor: int | None = None


def _worker_slice() -> range:
    """This pytest-xdist worker's share of the window. Outside xdist the whole window is one slice."""
    worker = os.environ.get("PYTEST_XDIST_WORKER", "")
    count = int(os.environ.get("PYTEST_XDIST_WORKER_COUNT", "1") or "1")
    index = int(worker[2:]) if worker.startswith("gw") and worker[2:].isdigit() else 0
    slots = max(1, min(count, (PORT_HI - PORT_LO) // MIN_SLICE))
    width = (PORT_HI - PORT_LO) // slots
    start = PORT_LO + (index % slots) * width
    return range(start, start + width)


def free_port() -> int:
    """The next port in this worker's slice that binds right now. The walk starts at a RANDOM point in
    the slice, once per process, so two processes on one host -- two worktrees running the harness
    tests at once, or two workers sharing a slice -- do not draw the same sequence; it then walks in
    order and wraps. Raises :class:`RuntimeError` when no port in the slice binds."""
    global _cursor
    ports = _worker_slice()
    if _cursor is None or _cursor not in ports:
        _cursor = ports.start + random.randrange(len(ports))
    for _ in range(len(ports)):
        port = _cursor
        _cursor = ports.start + (_cursor - ports.start + 1) % len(ports)
        probe = socket.socket()
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            probe.close()
        return port
    raise RuntimeError(f"no free port in {ports.start}-{ports.stop - 1}")


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


#: The ``[egress]`` section the served graphs run under. ``allowed_http`` names the loopback host, so
#: the HTTP-family outbounds of ``harness/config/http.py`` pass the REAL ``[egress].allowed_http``
#: gate rather than an unset one (an unset list is permissive). No other family's outbound reads it.
HARNESS_EGRESS_TOML = '[egress]\nallowed_http = ["127.0.0.1"]\n'


def harness_egress(
    tmp_path: Path,
    toml: str = HARNESS_EGRESS_TOML,
    environ: Mapping[str, str] | None = None,
) -> EgressSettings:
    """``[egress]`` as the settings loader ``serve`` uses resolves it from a settings file holding
    ``toml``, plus ``environ`` (empty by default, so a developer's own ``MEFOR_*`` cannot leak in)."""
    path = tmp_path / "harness-settings.toml"
    path.write_text(toml, encoding="utf-8")
    return load_settings(config_path=path, environ=environ or {}).egress


@contextmanager
def serve_harness_config(
    tmp_path: Path,
    overrides: Mapping[str, str],
    *,
    config_dir: Path = HARNESS_CONFIG,
    egress: EgressSettings | None = None,
) -> Iterator[tuple[str, Endpoints]]:
    """Serve ``config_dir`` with ``overrides`` applied; yield the API URL and the endpoints.
    ``egress`` defaults to :func:`harness_egress`."""
    registry = harness_endpoints.registry()
    env = {registry[key].env: value for key, value in overrides.items()}
    with _environment(env):
        # What `serve --env dev` does: environments/dev.toml overlaid with MEFOR_VALUE_* variables.
        # Without an active environment the engine resolves every env() to its default and the
        # overrides above would reach nothing.
        values = load_environment_values(
            base_dir=REPO, dir_name="environments", environment="dev", environ=os.environ
        )
        app = create_managed_app(
            db_path=tmp_path / "harness.db",
            config_dir=config_dir,
            poll_interval=0.05,
            env_values=values,
            allow_no_auth=True,  # the harness reads the API with no session
            egress_settings=harness_egress(tmp_path) if egress is None else egress,
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
