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

import dataclasses
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config import settings, wiring
from messagefoundry.config.run_context import RunContext
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Registry, WiringError, config_code_digest, load_config
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
from messagefoundry.pipeline.sharding import filter_registry_for_shard
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
        graph=(lambda: graph_shape(registry)) if compare else None,
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
    assert "reload" in text
    # What differs, and on which side: the engine has two handlers the worker never built.
    assert "handlers (engine only: h_1, h_2)" in text


def test_a_config_module_edited_on_disk_refuses_the_worker_though_every_name_matches(
    config_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Vault BACKLOG #2724 item 3. The engine loaded the config, then a Handler's body changed on
    disk with no reload. Every name is the same, so only the digest of the modules' bytes can tell.
    The control is the comparison on the same edit with the digest taken out of the engine's shape:
    the worker then comes up and answers from the edited body, which is the divergence this
    refuses."""
    monkeypatch.delenv(_VARIABLE, raising=False)
    registry = load_config(config_dir)
    graph = Path(config_dir) / "graph.py"
    graph.write_text(_GRAPH.replace('"COUNT="', '"EDITED="'), encoding="utf-8")

    with pytest.raises(SandboxError) as refused:
        _dispatch(registry, config_dir)
    text = str(refused.value)
    assert "config module content (the engine loaded" in text
    assert "reload" in text
    # Only the bytes differ, so the refusal does not send the operator after a variable.
    assert "pass_environment" not in text

    blind = dataclasses.replace(graph_shape(registry), code_digest=None)
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_PARITY",
        config_dir=config_dir,
        env=None,
        graph=lambda: blind,
    )
    try:
        deliveries, _, _, _ = transform_one(
            registry, "h_0", RAW, sandbox=session, run_context=RunContext()
        )
    finally:
        session.close()
    assert str(deliveries[0].payload) == "EDITED=1"


def test_a_module_rewritten_while_the_load_runs_refuses_the_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest is read before the modules run. A rewrite in between would let a worker pass the
    comparison with code its digest does not describe, so the load is refused. The control is
    the same load with nothing rewritten."""
    monkeypatch.delenv(_VARIABLE, raising=False)
    (tmp_path / "graph.py").write_text(_GRAPH, encoding="utf-8")
    assert load_config(tmp_path).code_digest is not None
    real = wiring._exec_module

    def rewrite_then_run(path: Path, helpers: Any) -> None:
        path.write_text(_GRAPH + "\n# edited\n", encoding="utf-8")
        real(path, helpers)

    monkeypatch.setattr(wiring, "_exec_module", rewrite_then_run)
    with pytest.raises(WiringError, match="changed on disk while they were loading"):
        load_config(tmp_path)


def test_a_module_unreadable_after_the_load_is_not_called_an_edit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(_VARIABLE, raising=False)
    (tmp_path / "graph.py").write_text(_GRAPH, encoding="utf-8")
    real = wiring._exec_module
    real_read = Path.read_bytes
    ran: list[bool] = []

    def refuse_after_the_load(self: Path) -> bytes:
        if ran and self.name == "graph.py":
            raise PermissionError("held open")
        return real_read(self)

    def run(path: Path, helpers: Any) -> None:
        real(path, helpers)
        ran.append(True)

    monkeypatch.setattr(wiring, "_exec_module", run)
    monkeypatch.setattr(Path, "read_bytes", refuse_after_the_load)
    with pytest.raises(WiringError, match="could not be read again"):
        load_config(tmp_path)


def test_an_unreadable_module_leaves_no_digest_and_says_so(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    (tmp_path / "graph.py").write_text("X = 1\n", encoding="utf-8")
    real = Path.read_bytes

    def refuse(self: Path) -> bytes:
        if self.name == "graph.py":
            raise PermissionError("held open")
        return real(self)

    monkeypatch.setattr(Path, "read_bytes", refuse)
    with caplog.at_level("WARNING", logger="messagefoundry.config.wiring"):
        assert config_code_digest(tmp_path) is None
    assert "not compared" in caplog.text and "held open" in caplog.text


def test_the_code_digest_covers_each_module_a_load_may_run(tmp_path: Path) -> None:
    """A ``_`` helper counts, as the loader runs it when a sibling imports it. A file that is not a
    config module does not, and the digest is of bytes, not of a listing."""
    (tmp_path / "graph.py").write_text("X = 1\n", encoding="utf-8")
    first = config_code_digest(tmp_path)
    assert first is not None and len(first) == 64
    assert config_code_digest(tmp_path) == first
    (tmp_path / "notes.txt").write_text("not config\n", encoding="utf-8")
    assert config_code_digest(tmp_path) == first
    (tmp_path / "_helper.py").write_text("Y = 1\n", encoding="utf-8")
    with_helper = config_code_digest(tmp_path)
    assert with_helper != first
    (tmp_path / "_helper.py").write_text("Y = 2\n", encoding="utf-8")
    assert config_code_digest(tmp_path) not in (first, with_helper)


def test_an_engine_shard_keeps_the_code_digest(config_dir: str) -> None:
    registry = load_config(config_dir)
    assert registry.code_digest == config_code_digest(Path(config_dir))
    assert filter_registry_for_shard(registry, "any").code_digest == registry.code_digest


def test_a_refused_worker_is_not_started_again_for_the_same_graph(
    config_dir: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mismatch cannot clear while the engine serves the same graph, so the next message is
    refused without starting another interpreter. A new engine graph is tried afresh."""
    monkeypatch.setenv(_VARIABLE, "3")
    registry = load_config(config_dir)
    serving = [graph_shape(registry)]
    session = SandboxSession(
        SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=30.0),
        inbound="IB_PARITY",
        config_dir=config_dir,
        env=None,
        graph=lambda: serving[0],
    )
    try:
        with pytest.raises(SandboxError) as first:
            session._spawn()
        assert session._generation == 1
        with pytest.raises(SandboxError) as second:
            session._spawn()
        assert session._generation == 1  # no second worker was started
        assert str(second.value) == str(first.value)

        # The engine now serves the one-handler graph the worker builds: tried again, and it starts.
        monkeypatch.delenv(_VARIABLE)
        serving[0] = graph_shape(load_config(config_dir))
        session._spawn()
        assert session._generation == 2
    finally:
        session.close()


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
            egress=EgressSettings(deny_by_default=False),
        )
        first = runner._sandbox_for("IB_PARITY")
        second = runner._sandbox_for("IB_OTHER")
        assert first is not None and second is not None
        assert first._graph is not None and second._graph is not None
        assert first._graph() == graph_shape(registry)
        assert first._graph() is second._graph()

        # A session that outlives a registry swap, in either direction, compares with the registry
        # being served when its worker starts, never with the one it was made under.
        monkeypatch.setenv(_VARIABLE, "1")
        swapped = load_config(config_dir)
        runner.registry = swapped
        assert first._graph() == graph_shape(swapped)
        assert first._graph() != graph_shape(registry)

        # Dropping the sessions, as a reload and a failed reload's rollback both do.
        await runner._close_sandbox_sessions()
        assert runner._sandbox_sessions == {}
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
    (difference,) = graph_differences(_shape(), _shape(**changes))
    assert difference.startswith(expected + " (")


_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64


def test_the_code_digest_is_compared_whenever_the_engine_has_one() -> None:
    """A worker of the same build that reports no digest could not read its modules, so it is
    refused rather than passed. An engine with none, a graph built in code, compares names only."""
    ours, theirs = _shape(code_digest=_DIGEST_A), _shape(code_digest=_DIGEST_B)
    assert graph_differences(ours, theirs) == [
        "config module content (the engine loaded aaaaaaaaaaaa, the worker loaded bbbbbbbbbbbb)"
    ]
    assert graph_differences(ours, _shape(code_digest=_DIGEST_A)) == []
    assert graph_differences(ours, _shape()) == [
        "config module content (the engine loaded aaaaaaaaaaaa, the worker loaded none: it could "
        "not read them)"
    ]
    assert graph_differences(_shape(), theirs) == []


def test_a_difference_names_a_few_of_the_names_and_the_side_that_has_them() -> None:
    worker = _shape(handlers=frozenset({"h", "w1", "w2", "w3", "w4"}), routers=frozenset())
    assert graph_differences(_shape(), worker) == [
        "routers (engine only: r)",
        "handlers (worker only: w1, w2, w3 and 1 more)",
    ]
    rebound = _shape(bindings={"IB_A": "other"})
    assert graph_differences(_shape(), rebound) == ["router bindings (of inbound: IB_A)"]


def test_an_engine_shard_compares_only_the_bindings_it_holds() -> None:
    """A shard holds its own inbounds and only the NAMES of the others. The worker loads the whole
    config, so its extra bindings are not a difference."""
    worker = _shape(bindings={"IB_A": "r", "IB_B": "r"})
    assert graph_differences(_shape(), worker) == []


def test_the_shape_crosses_the_pipe_and_back() -> None:
    assert codec.decode_boot_reply(codec.encode_ready(_shape())) == (_shape(), "")
    with_digest = _shape(code_digest=_DIGEST_A)
    assert codec.decode_boot_reply(codec.encode_ready(with_digest)) == (with_digest, "")
    assert codec.decode_boot_reply(codec.encode_bootfail("why")) == (None, "why")


@pytest.mark.parametrize("digest", ["A" * 64, "a" * 63, "not hex\n" * 8, "g" * 64])
def test_a_code_digest_from_the_worker_must_be_a_sha256(digest: str) -> None:
    """The worker writes it, and the engine prints its start into a refusal."""
    with pytest.raises(codec.SandboxCodecError):
        codec.decode_boot_reply(codec.encode_ready(_shape(code_digest=digest)))


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
        code_digest=config_code_digest(Path(config_dir)),
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
