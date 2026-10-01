# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A sandbox worker whose graph differs from the engine's does not come up (vault BACKLOG #2587).

The worker loads the config directory again, in its own process, under an allowlisted environment.
A config module that reads the environment can therefore build a different graph there. These tests
pin that the difference is loud and fails closed, and that the documented way to hand the worker a
variable, ``[sandbox].pass_environment``, is real and refuses the engine's own secrets.

Synthetic HL7 only. The variable these configs read holds a marker, never a secret.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from messagefoundry.config import settings
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sandbox import (
    GraphShape,
    SandboxError,
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    graph_differences,
    graph_shape,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore
from tests.test_child_process_environment import _SECRET_NAMES
from tests.test_sandbox import RAW

_VARIABLE = "SITE_GRAPH_VARIANT"

#: A graph whose SHAPE depends on a variable the worker is not given: how many handlers it has.
#: ``h_0`` exists either way, so a dispatch to it succeeds in a worker that built a smaller graph,
#: and nothing in the answer says the two graphs differ.
_GRAPH = f"""
import os
from messagefoundry import inbound, outbound, router, handler, MLLP, Send

COUNT = int(os.environ.get("{_VARIABLE}", "1"))

inbound("IB_PARITY", MLLP(port=19461), router="r")
outbound("OB_PARITY", MLLP(host="127.0.0.1", port=19462))


@router("r")
def r(msg):
    return "h_0"


def _make(index):
    @handler("h_" + str(index))
    def h(msg):
        return Send("OB_PARITY", "COUNT=" + str(COUNT))


for _index in range(COUNT):
    _make(_index)
"""


@pytest.fixture
def config_dir(tmp_path: Path) -> str:
    (tmp_path / "graph.py").write_text(_GRAPH, encoding="utf-8")
    return str(tmp_path)


def _dispatch(registry: Registry, config_dir: str, *passed: str, compare: bool = True) -> str:
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0, pass_environment=passed),
        inbound="IB_PARITY",
        config_dir=config_dir,
        env=None,
        graph=graph_shape(registry) if compare else None,
    )
    try:
        deliveries, _, _, _ = transform_one(
            registry, "h_0", RAW, sandbox=session, run_context=RunContext()
        )
    finally:
        session.close()
    return str(deliveries[0].payload)


def test_a_worker_whose_graph_differs_from_the_engines_is_refused(
    config_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(_VARIABLE, "3")
    registry = load_config(config_dir)
    assert sorted(registry.handlers) == ["h_0", "h_1", "h_2"]  # the engine's graph

    # What the comparison is for: with it off, the worker answers from a one-handler graph and
    # nothing says so.
    assert _dispatch(registry, config_dir, compare=False) == "COUNT=1"

    with pytest.raises(SandboxError) as refused:
        _dispatch(registry, config_dir)

    text = str(refused.value)
    assert "IB_PARITY" in text
    assert "allowlist" in text
    assert "[sandbox].pass_environment" in text
    assert "handlers" in text


def test_the_same_graph_comes_up_when_the_variable_is_passed(
    config_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the refusal, and the documented remedy: the same config, the same variable,
    and the worker is given it."""
    monkeypatch.setenv(_VARIABLE, "3")
    registry = load_config(config_dir)
    assert _dispatch(registry, config_dir, _VARIABLE) == "COUNT=3"


def test_a_graph_that_reads_nothing_it_lacks_comes_up(
    config_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The second control: with the variable unset in the engine too, both sides take the default."""
    monkeypatch.delenv(_VARIABLE, raising=False)
    registry = load_config(config_dir)
    assert _dispatch(registry, config_dir) == "COUNT=1"


async def test_the_runner_hands_each_session_the_graph_it_is_serving(
    config_dir: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The production wiring, not a hand-built session: the runner's own sessions carry the shape of
    its registry, share one copy of it, and take a new one when a reload swaps the registry."""
    monkeypatch.setenv(_VARIABLE, "2")
    registry = load_config(config_dir)
    store = await MessageStore.open(tmp_path / "parity.db")
    try:
        runner = RegistryRunner(
            registry,
            store,
            sandbox_policy=SandboxPolicy(mode=SandboxMode.SUBPROCESS),
            sandbox_config_source=(config_dir, None),
        )
        first = runner._sandbox_for("IB_PARITY")
        second = runner._sandbox_for("IB_OTHER")
        assert first is not None and second is not None
        assert first._graph == graph_shape(registry)
        assert first._graph is second._graph

        monkeypatch.setenv(_VARIABLE, "1")
        runner.registry = load_config(config_dir)
        runner._sandbox_sessions.clear()  # what a reload does
        after = runner._sandbox_for("IB_PARITY")
        assert after is not None and after._graph == graph_shape(runner.registry)
        assert after._graph != first._graph
    finally:
        await store.close()


# --- the comparison ------------------------------------------------------------------------------


def _shape(**changes: object) -> GraphShape:
    base: dict[str, object] = {
        "bindings": {"IB_A": "r"},
        "inbound": frozenset({"IB_A", "IB_B"}),
        "routers": frozenset({"r"}),
        "handlers": frozenset({"h"}),
        "accepts": frozenset({"h"}),
        "outbound": frozenset({"OB"}),
    }
    return GraphShape(**{**base, **changes})  # type: ignore[arg-type]


def test_an_equal_shape_has_no_difference() -> None:
    assert graph_differences(_shape(), _shape()) == []


@pytest.mark.parametrize(
    ("changes", "expected"),
    [
        ({"inbound": frozenset({"IB_A"})}, "inbound connections"),
        ({"bindings": {"IB_A": "other", "IB_B": "r"}}, "router bindings"),
        ({"routers": frozenset({"r", "r2"})}, "routers"),
        ({"handlers": frozenset()}, "handlers"),
        ({"accepts": frozenset()}, "accepts= predicates"),
        ({"outbound": frozenset({"OB", "OB2"})}, "outbound connections"),
    ],
)
def test_each_part_of_the_shape_is_compared(changes: dict[str, object], expected: str) -> None:
    assert graph_differences(_shape(), _shape(**changes)) == [expected]


def test_an_engine_shard_compares_only_the_bindings_it_holds() -> None:
    """A shard holds its own inbounds and only the NAMES of the others. The worker loads the whole
    config, so its extra bindings are not a difference."""
    worker = _shape(bindings={"IB_A": "r", "IB_B": "r"})
    assert graph_differences(_shape(), worker) == []


def test_the_shape_crosses_the_pipe_and_back() -> None:
    ready, detail, shape = codec.decode_boot_reply(codec.encode_ready(_shape()))
    assert (ready, detail, shape) == (True, "", _shape())


def test_the_shape_of_a_loaded_graph(config_dir: str, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_VARIABLE, raising=False)
    shape = graph_shape(load_config(config_dir))
    assert shape == GraphShape(
        bindings={"IB_PARITY": "r"},
        inbound=frozenset({"IB_PARITY"}),
        routers=frozenset({"r"}),
        handlers=frozenset({"h_0"}),
        accepts=frozenset(),
        outbound=frozenset({"OB_PARITY"}),
    )


# --- the setting ---------------------------------------------------------------------------------


def test_pass_environment_takes_ordinary_names() -> None:
    names = ["SITE_GRAPH_VARIANT", "TENANT_COUNT"]
    assert settings.SandboxSettings(pass_environment=tuple(names)).pass_environment == tuple(names)
    assert settings.SandboxSettings().pass_environment == ()
    # The environment layer delivers the setting as one comma-separated string.
    from_env = settings.SandboxSettings.model_validate({"pass_environment": " A_NAME , B_NAME "})
    assert from_env.pass_environment == ("A_NAME", "B_NAME")


@pytest.mark.parametrize(
    "name",
    [
        *sorted(_SECRET_NAMES),
        "mefor_value_partner_password",
        "MEFOR_STORE_BACKEND",
        "MEFOR_SANDBOX_MODE",
        "MEFOR_ALLOW_INSECURE_TLS",
        "MEFOR_ANYTHING_AT_ALL",
    ],
)
def test_pass_environment_refuses_the_engines_own_names(name: str) -> None:
    with pytest.raises(ValidationError) as refused:
        settings.SandboxSettings(pass_environment=(name,))
    assert "pass_environment" in str(refused.value)


@pytest.mark.parametrize("name", ["", "A=B", "HAS SPACE", "1LEADING", "TRAILING\n"])
def test_pass_environment_refuses_what_is_not_a_variable_name(name: str) -> None:
    with pytest.raises(ValidationError):
        settings.SandboxSettings(pass_environment=(name,))
