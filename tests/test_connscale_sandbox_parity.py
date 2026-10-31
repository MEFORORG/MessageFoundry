# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A connscale sandbox worker builds the same graph as its engine (BACKLOG #3132, step 3).

The connscale graph used to take its shape from ``MEFOR_CONNSCALE_*`` alone. A
``[sandbox].mode = "subprocess"`` worker never receives a ``MEFOR_`` name, so it built the default
shape. The two controls below pin that defect on the env route: the count and the name prefix
change names, so the engine refuses the worker; the transform changes no name, so the worker comes
up and quietly runs ``cheap``. The generated per-step config directory is the fix, pinned with all
three knobs at a non-default value at once.

These spawn real sandbox workers, one per test. Synthetic HL7 only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from harness.config.connscale._shape import make_connscale_shape
from harness.load.connscale.stepconfig import GRAPH_MODULE, graph_module_text, write_step_config_dir
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    graph_shape,
)

RAW = "MSH|^~\\&|SEND|F|RECV|F|20240101120000||ADT^A01|CS3132|P|2.3\rPID|1||900001||DOE^JANE\r"

_ENV_KNOBS = (
    "MEFOR_CONNSCALE_COUNT",
    "MEFOR_CONNSCALE_BASE_PORT",
    "MEFOR_CONNSCALE_SINK_HOST",
    "MEFOR_CONNSCALE_SINK_PORT",
    "MEFOR_CONNSCALE_SINK_PORTS",
    "MEFOR_CONNSCALE_TRANSFORM",
    "MEFOR_CONNSCALE_NAME_PREFIX",
)


@pytest.fixture(autouse=True)
def _no_shape_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _ENV_KNOBS:
        monkeypatch.delenv(name, raising=False)


def _msh(payload: object, field: int) -> str:
    """MSH-``field`` of a delivered payload, read (never mutated) by splitting the MSH segment."""
    segment = str(payload).split("\r", 1)[0]
    # MSH-1 is the separator itself, so MSH-n is the n-1th piece of the split.
    return segment.split("|")[field - 1]


def _worker_transform(registry: Registry, config_dir: str, inbound: str, handler: str) -> object:
    """Run ``handler`` in a real worker that must match the engine's graph, and return what it sent."""
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=60.0, startup_seconds=60.0),
        inbound=inbound,
        config_dir=config_dir,
        env=None,
        graph=lambda: graph_shape(registry),
    )
    try:
        deliveries, _, _, _ = transform_one(
            registry, handler, RAW, sandbox=session, run_context=RunContext()
        )
    finally:
        session.close()
    assert len(deliveries) == 1
    return deliveries[0].payload


def test_the_generated_step_directory_builds_the_engines_graph_in_the_worker(
    tmp_path: Path,
) -> None:
    shape = make_connscale_shape(
        count=7, base_port=24600, sink_port=24700, transform="edit", name_prefix="E1"
    )
    config_dir = str(write_step_config_dir(tmp_path / "step", shape))
    registry = load_config(config_dir)
    # The engine's graph carries all three knobs, with no MEFOR_CONNSCALE_* in the environment.
    assert len(registry.inbound) == 7
    assert "IB_E1_CS_00006" in registry.inbound
    assert "IB_CS_00000" not in registry.inbound

    # COUNT and NAME_PREFIX: the worker's names must equal the engine's, or the session refuses it.
    sent = _worker_transform(registry, config_dir, "IB_E1_CS_00003", "H_E1_CS_00003")
    # TRANSFORM changes no name, so only the worker's answer shows it ran `edit`.
    assert _msh(sent, 4) == "MEFOR_CONNSCALE"
    assert _msh(sent, 6) == "SINK_00003"
    assert _msh(sent, 10) == "CS3132"  # the control id the correlation sink matches on survives


def test_control_the_env_route_count_and_prefix_refuse_the_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The defect the generated directory replaces: the engine builds 7 prefixed connections, the
    worker builds the default 50 unprefixed ones, and the shape check refuses it."""
    monkeypatch.setenv("MEFOR_CONNSCALE_COUNT", "7")
    monkeypatch.setenv("MEFOR_CONNSCALE_NAME_PREFIX", "E1")
    monkeypatch.setenv("MEFOR_CONNSCALE_BASE_PORT", "24600")
    monkeypatch.setenv("MEFOR_CONNSCALE_SINK_PORT", "24700")
    registry = load_config("harness/config/connscale")
    assert len(registry.inbound) == 7

    with pytest.raises(SandboxError) as refused:
        _worker_transform(registry, "harness/config/connscale", "IB_E1_CS_00003", "H_E1_CS_00003")
    assert "its graph differs from the engine's" in str(refused.value)


def test_control_the_env_route_transform_passes_the_check_and_runs_cheap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The silent half: ``edit`` changes no name, so the worker passes the shape check and answers
    from the default ``cheap`` transform. The engine, in-process, would have rewritten MSH-4. The
    count is left at its default, so the names match; that is the only way past the check."""
    monkeypatch.setenv("MEFOR_CONNSCALE_TRANSFORM", "edit")
    registry = load_config("harness/config/connscale")
    in_process, _, _, _ = transform_one(registry, "H_CS_00001", RAW, run_context=RunContext())
    assert _msh(in_process[0].payload, 4) == "MEFOR_CONNSCALE"

    sent = _worker_transform(registry, "harness/config/connscale", "IB_CS_00001", "H_CS_00001")
    assert _msh(sent, 4) == "F"  # the receipt unchanged: the worker ran `cheap`


def test_the_generated_module_writes_every_knob_as_a_literal(tmp_path: Path) -> None:
    shape = make_connscale_shape(
        count=12,
        base_port=3000,
        sink_host="127.0.0.2",
        sink_port=3100,
        sink_ports=3,
        transform="edit",
        name_prefix="E2",
    )
    text = graph_module_text(shape)
    for literal in (
        "count=12",
        "base_port=3000",
        "sink_host='127.0.0.2'",
        "sink_port=3100",
        "sink_ports=3",
        "transform='edit'",
        "name_prefix='E2'",
    ):
        assert literal in text
    # The environment is not read: no MEFOR_ name is in the module at all.
    assert "MEFOR_" not in text
    written = write_step_config_dir(tmp_path / "d", shape)
    assert sorted(p.name for p in written.iterdir()) == [GRAPH_MODULE]


def test_the_generator_refuses_a_shape_the_env_route_refuses(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="overlaps the sink port range"):
        make_connscale_shape(count=200, base_port=2650, sink_port=2700)
    with pytest.raises(ValueError, match="NAME_PREFIX"):
        make_connscale_shape(name_prefix="E 1")
    with pytest.raises(ValueError, match="TRANSFORM"):
        make_connscale_shape(transform="slow")
