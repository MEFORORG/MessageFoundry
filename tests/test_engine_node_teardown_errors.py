# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``EngineNode.kill``/``stop`` survive a root that refuses the signal, and ``stop`` always tears down.

Ending a node's job kills its root, so the ``kill()`` that follows can land on a process Windows is
already ending, and Windows raises ``PermissionError`` there rather than ``ProcessLookupError``. And
``stop()`` must end the job and close the log even when the graceful wait raises or is cancelled,
or the tree and the temp log outlive the node. Fake processes, so this runs on every platform.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, cast

import pytest

from harness.load.failover import EngineNode


class _RefusingProc:
    """A root that is still listed as running but refuses every signal, as a dying one does."""

    pid = 4242
    returncode: int | None = None

    def kill(self) -> None:
        raise PermissionError(5, "Access is denied")

    def terminate(self) -> None:
        raise PermissionError(5, "Access is denied")

    async def wait(self) -> int:
        self.returncode = 1
        return 1


class _CancelledWaitProc(_RefusingProc):
    def terminate(self) -> None:
        pass

    async def wait(self) -> int:
        raise asyncio.CancelledError


def _node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, proc: Any
) -> tuple[EngineNode, list[str]]:
    node = EngineNode("fo-t", 8801, env={"PATH": "/x"}, config_dir="unused", cwd=tmp_path)
    ended: list[str] = []
    monkeypatch.setattr(node, "_end_tree", lambda: ended.append("end"))
    node._proc = cast("asyncio.subprocess.Process", proc)
    return node, ended


def test_kill_tolerates_a_root_that_refuses_with_PermissionError(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node, ended = _node(tmp_path, monkeypatch, _RefusingProc())
    node.kill()
    assert ended == ["end"]


async def test_stop_tolerates_a_root_that_refuses_with_PermissionError(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node, ended = _node(tmp_path, monkeypatch, _RefusingProc())
    log_path = Path(node._log.name)
    await node.stop()
    assert ended == ["end"]
    assert node._log.closed
    assert not log_path.exists()


async def test_stop_tears_down_even_when_the_wait_is_cancelled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node, ended = _node(tmp_path, monkeypatch, _CancelledWaitProc())
    log_path = Path(node._log.name)
    with pytest.raises(asyncio.CancelledError):
        await node.stop()
    assert ended == ["end"]
    assert node._log.closed
    assert not log_path.exists()
