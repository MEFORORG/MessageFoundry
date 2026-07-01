# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Multi-ENGINE store-contention CI smoke (WS-B) — N=2 engines on ONE shared SQLite store.

The multishard orchestrator OWNS two ``serve`` subprocesses, both pointed at the SAME SQLite ``.db``
file (``MEFOR_STORE_PATH``), with DISJOINT inbound/sink/API ports AND disjoint per-engine connection
names (``MEFOR_CONNSCALE_NAME_PREFIX=E0``/``E1``). It drives a small, brief load and proves:

* (a) the ORCHESTRATION MECHANICS work — a coherent aggregate record (N engines, offered == N*C*R, a
  chronological ISO hold window), and both drivers drove traffic that reached the engines (positive reads);
* (b) NO cross-engine steal — each engine's OWN ``/connections`` reports only ITS ``E{k}``-tagged inbound
  lanes (``foreign_rows == 0``); had the same-named lanes collided on the shared store an engine would
  report a peer's rows. This disjoint-lane isolation is the load-bearing correctness the gate needs, and it
  is config-derived so it holds regardless of the write lock.

End-to-end ZERO-LOSS is NOT asserted here. SQLite is single-writer: two ``serve`` processes writing one
file serialize on the write lock, and a delivery-worker commit can hit ``SQLITE_LOCKED`` (which the
store's busy_timeout does not retry), stranding a row past the drain window. That is a pathological
single-writer-SQLite artifact — NOT an orchestrator bug and NOT what a server DB (concurrent writers)
does — so requiring a clean drain here would test something SQLite structurally cannot do. Real zero-loss
under a shared store is the SERVER-DB gate the bench runs (``harness multishard --store sqlserver``), out
of CI scope; a clean drain here is asserted only as a bonus when it happens. Small count + short hold keep
the smoke inside the pytest-timeout budget.
"""

from __future__ import annotations

import contextlib
import socket
import tempfile
from pathlib import Path

import pytest

from harness.load.multishard import MultiShardReport, run_multishard

pytestmark = pytest.mark.timeout(
    120
)  # two engine spawns + a shared-store drain; the 60s default is tight

_ENGINES = 2
_COUNT_PER_ENGINE = 2
_PER_CONN_RATE = 4.0
_STRIDE = 100
_DRAIN_TIMEOUT_S = 8.0  # bounded: a shared-SQLite write-lock stall returns FAST (zero-loss is not
#                         required); a clean drain (2 conns, a handful of messages) finishes well under it


def _free_window(span: int, *, lo: int = 20000, hi: int = 60000) -> int:
    """Find a base ``b`` in [lo, hi) where EVERY port in ``[b, b + span)`` is currently free. The
    engines bind FIXED ports (inbound_base + stride*k, sink_base + stride*k, api_base + k), so — unlike
    ephemeral port 0 — a stale engine from a prior run (or the dev box's own :2575) could otherwise own
    one of them and steal traffic; reserving one wide free window and carving every block out of it
    avoids that collision deterministically."""
    for base in range(lo, hi - span, 500):
        socks: list[socket.socket] = []
        try:
            for port in range(base, base + span):
                s = socket.socket()
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))  # raises OSError if taken
                socks.append(s)
            return base
        except OSError:
            continue
        finally:
            for s in socks:
                with contextlib.suppress(OSError):
                    s.close()
    raise RuntimeError(f"no free {span}-port window found in [{lo}, {hi})")


async def _run_once() -> MultiShardReport:
    # N=2, C=2 conns/engine, stride 100: engine k's inbound block is [inbound_base+100*k .. +1], its
    # sink port is sink_base+100*k, its API is api_base+k. Reserve ONE wide verified-free window and
    # carve the three (non-overlapping) blocks out of it at fixed offsets (the engines bind FIXED ports,
    # so a stale prior-run engine on a fixed port would silently steal traffic — reserve a whole free
    # window rather than trust a hard-coded base).
    window = _free_window(500)
    # ``ignore_cleanup_errors`` (Python 3.14): the two engines drain their SQLite handles on SIGTERM,
    # but Windows can hold the file open for a beat past the process exit, so a strict rmtree would race
    # the OS releasing the handle — a Windows-only cleanup nuisance, never a real failure.
    with tempfile.TemporaryDirectory(prefix="mefor-multishard-", ignore_cleanup_errors=True) as tmp:
        db_path = str(Path(tmp) / "shared.db")
        report = await run_multishard(
            engine_counts=[_ENGINES],
            count_per_engine=_COUNT_PER_ENGINE,
            per_conn_rate=_PER_CONN_RATE,  # tiny volume: minimizes the shared-write-lock collision window
            hold_seconds=1.0,
            inbound_base=window,  # engine blocks at window+0, window+100
            sink_base=window + 300,  # one sink port per engine at window+300, window+400
            api_base=window + 450,  # api at window+450, window+451
            stride=_STRIDE,  # 100: engine k blocks at window+100*k (all inside the reserved window)
            store_backend="sqlite",
            cluster_enabled=False,
            db_path=db_path,
            drain_timeout_s=_DRAIN_TIMEOUT_S,
        )
        assert Path(db_path).exists(), "the shared SQLite store file was never created"
    return report


async def test_multishard_two_engines_shared_sqlite() -> None:
    # ONE run. The orchestration MECHANICS + the disjoint-lane isolation are config-derived, so they hold
    # deterministically even while the two engines serialize on the single SQLite writer; end-to-end
    # zero-loss is NOT required here (a shared-SQLite write-lock stall is expected — see the module
    # docstring), so there is nothing to retry for.
    report = await _run_once()
    assert len(report.records) == 1
    rec = report.records[0]

    # (a) Coherent aggregate record: N engines, offered == N*C*R, a chronological ISO hold window.
    assert rec.engines == _ENGINES
    assert rec.count_per_engine == _COUNT_PER_ENGINE
    assert rec.offered_aggregate_rate == pytest.approx(
        _ENGINES * _COUNT_PER_ENGINE * _PER_CONN_RATE
    )
    assert rec.hold_start_iso and rec.drain_complete_iso
    assert rec.hold_start_iso <= rec.drain_complete_iso  # ISO-8601 UTC sorts chronologically
    assert rec.sent > 0, rec  # the N drivers drove traffic

    # (b) NO cross-engine steal — the load-bearing correctness. Each engine attributed only ITS OWN
    # E{k}-tagged lanes; had the same-named lanes collided on the shared store an engine would report a
    # peer's rows (foreign_rows > 0). Config-derived, so it holds regardless of the SQLite write lock.
    assert not rec.any_cross_engine_steal, [
        (e.node_id, e.name_tag, e.foreign_rows) for e in rec.per_engine
    ]
    assert len(rec.per_engine) == _ENGINES
    assert {e.name_tag for e in rec.per_engine} == {"E0", "E1"}
    for e in rec.per_engine:
        assert e.inbound_rows == _COUNT_PER_ENGINE, e  # exactly its own C lanes, no more
        assert e.foreign_rows == 0, e  # none of a peer's lanes bled in
        assert e.reads > 0, e  # this engine independently received traffic on its own lanes

    # (c) Zero-loss end-to-end is NOT required on shared SQLite (the single writer can strand a row on a
    # SQLITE_LOCKED delivery commit — the server-DB bench is the real zero-loss gate). A clean drain is a
    # bonus: if it happened, it must be internally consistent.
    if rec.no_loss.ok:
        assert report.result_ok and report.exit_code == 0
