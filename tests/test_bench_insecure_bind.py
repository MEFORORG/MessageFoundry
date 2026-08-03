# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""STRUCTURAL tests for the two-box off-loopback bind override (ADR 0073 cert + ADR 0075 batch_ab).

A ``serve``/``serve --shard`` subprocess that binds its inbound MLLP listener on a NON-loopback
interface (the two-box rig binds ``0.0.0.0`` so off-box senders reach the inbound ports) trips serve's
off-loopback plaintext-MLLP exposure gate (ADR 0002 §0) and is REFUSED at start without
``--allow-insecure-bind``. Both node start methods — ``EngineNode.start`` (reused by failover +
batch-engine) and ``ShardCertNode.start`` — must add that dev override when, and ONLY when, the bind
host is non-loopback; a co-located loopback bind keeps a byte-identical argv. These fake
``create_subprocess_exec`` so no real engine spawns.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from harness.load.failover import EngineNode, _insecure_bind_args
from harness.load.shardcert import ShardCertNode


class _FakeProc:
    """A stand-in subprocess: records nothing, satisfies the node stop()/kill() lifecycle."""

    def __init__(self) -> None:
        self.returncode: int | None = None
        self.pid = 4321

    def terminate(self) -> None:
        self.returncode = 0

    def kill(self) -> None:
        self.returncode = -9

    async def wait(self) -> int:
        self.returncode = self.returncode if self.returncode is not None else 0
        return self.returncode


def _capture_exec(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    """Fake ``asyncio.create_subprocess_exec`` (used by BOTH start methods) to capture the argv without
    spawning a real engine."""
    captured: dict[str, Any] = {}

    async def fake_exec(*argv: Any, **kw: Any) -> _FakeProc:
        captured["argv"] = list(argv)
        return _FakeProc()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_exec)
    return captured


def test_insecure_bind_args_gate() -> None:
    # No bind host / a loopback bind → co-located default → NO flag (byte-identical argv).
    assert _insecure_bind_args({}) == []
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "127.0.0.1"}) == []
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "127.0.0.5"}) == []
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "localhost"}) == []
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "::1"}) == []
    # A non-loopback bind (0.0.0.0 / a NIC IP) → the dev override.
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "0.0.0.0"}) == ["--allow-insecure-bind"]
    assert _insecure_bind_args({"MEFOR_INBOUND_BIND_HOST": "10.0.0.5"}) == ["--allow-insecure-bind"]


async def test_engine_node_adds_flag_for_nonloopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_exec(monkeypatch)
    node = EngineNode(
        "n", 9000, env={"MEFOR_INBOUND_BIND_HOST": "0.0.0.0"}, config_dir="cfg", cwd=Path(".")
    )
    await node.start()
    await node.stop()
    assert "--allow-insecure-bind" in captured["argv"]


async def test_engine_node_no_flag_for_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_exec(monkeypatch)
    node = EngineNode(
        "n", 9000, env={"MEFOR_INBOUND_BIND_HOST": "127.0.0.1"}, config_dir="cfg", cwd=Path(".")
    )
    await node.start()
    await node.stop()
    assert "--allow-insecure-bind" not in captured["argv"]


async def test_engine_node_no_flag_when_bind_host_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    # The failover two-node run binds loopback (its _node_env sets no MEFOR_INBOUND_BIND_HOST), so its
    # argv stays byte-identical to before this fix.
    captured = _capture_exec(monkeypatch)
    node = EngineNode("n", 9000, env={}, config_dir="cfg", cwd=Path("."))
    await node.start()
    await node.stop()
    assert "--allow-insecure-bind" not in captured["argv"]


async def test_shardcert_node_adds_flag_for_nonloopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_exec(monkeypatch)
    node = ShardCertNode(
        "0", 9000, env={"MEFOR_INBOUND_BIND_HOST": "0.0.0.0"}, config_dir="cfg", cwd=Path(".")
    )
    await node.start()
    await node.stop()
    assert "--allow-insecure-bind" in captured["argv"]
    # The shard flag is still injected alongside the override.
    assert "--shard" in captured["argv"] and "0" in captured["argv"]


async def test_shardcert_node_no_flag_for_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = _capture_exec(monkeypatch)
    node = ShardCertNode(
        "0", 9000, env={"MEFOR_INBOUND_BIND_HOST": "127.0.0.1"}, config_dir="cfg", cwd=Path(".")
    )
    await node.start()
    await node.stop()
    assert "--allow-insecure-bind" not in captured["argv"]
    assert (
        "--shard" in captured["argv"]
    )  # co-located shard run still injects --shard, just no override
