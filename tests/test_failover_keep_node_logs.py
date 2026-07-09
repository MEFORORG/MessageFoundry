# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Unit tests for the bench-only ``MEFOR_BENCH_KEEP_NODE_LOGS`` node-log sink (no live engine).

The failover/shardcert harness normally writes each ``serve`` subprocess's stdout to a
``tempfile.NamedTemporaryFile`` and unlinks it in :meth:`EngineNode.stop`, which discards the
throttled per-delivery phase-timing summary before a rig run can read it. The knob (default OFF)
persists each node's stdout to ``<dir>/<node_id>.log`` and skips the unlink. These tests exercise the
sink-selection logic directly on :class:`~harness.load.failover.EngineNode` — no subprocess, no
network — and prove that unset behavior is unchanged.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from harness.load.failover import EngineNode


def test_keep_node_logs_unset_uses_tempfile(tmp_path: Path) -> None:
    # Unset => byte-identical to the original behavior: a NamedTemporaryFile-style temp path carrying
    # the harness prefix, deleted on stop().
    node = EngineNode(
        "fo-a", 8801, env={"PATH": "/x"}, config_dir="harness/config/load", cwd=tmp_path
    )
    assert node._keep_log is False
    log_path = Path(node._log.name)
    assert log_path.name.startswith("mefor-failover-fo-a-")
    assert log_path.suffix == ".log"
    assert log_path.parent == Path(tempfile.gettempdir())
    assert log_path.exists()  # NamedTemporaryFile materializes the file immediately

    # The stop() unlink guard removes it when keep-logs is OFF; mimic it and confirm it's gone.
    node._log.close()
    if not node._keep_log:
        log_path.unlink(missing_ok=True)
    assert not log_path.exists()


def test_keep_node_logs_set_persists_to_dir(tmp_path: Path) -> None:
    keep_dir = tmp_path / "node-logs"
    node = EngineNode(
        "fo-a",
        8801,
        env={"MEFOR_BENCH_KEEP_NODE_LOGS": str(keep_dir)},
        config_dir="harness/config/load",
        cwd=tmp_path,
    )
    assert node._keep_log is True
    assert keep_dir.is_dir()  # os.makedirs(..., exist_ok=True) created the sink dir
    expected = keep_dir / "fo-a.log"
    assert Path(node._log.name) == expected

    # Write a byte, then run the same unlink guard stop() uses: keep mode must LEAVE the file present.
    node._log.write(b"phase-timing line\n")
    node._log.close()
    if not node._keep_log:
        expected.unlink(missing_ok=True)
    assert expected.exists()
    assert expected.read_bytes() == b"phase-timing line\n"
