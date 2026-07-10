# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A dead-simple cross-process **file-drop** coordination channel for the WS-C two-box shardcert drive.

The N-active certification's throughput/sizing half runs the engine fleet on one box and the load
generator (senders + correlation sink) on another — physically isolated so the driver never steals CPU
from the engine (the attribution-policy requirement). Splitting a single ``run_shardcert`` orchestrator
across the box boundary needs the two halves to rendezvous, and WS-C deliberately kept that to the
**bare minimum**: exactly **two messages**, no kill leg crossing the wire.

1. the ENGINE half brings the shard fleet up (serial health-gate + inbound preflight), then posts
   :data:`SHARDS_READY` carrying the topology the driver needs (the inbound base port, the API ports to
   poll ``/stats`` on, the single sink port to bind, the shard set, and which shard — if any — will be
   killed);
2. the DRIVER half waits for :data:`SHARDS_READY`, binds its correlation sink **locally**, opens its
   senders against the engine box, then posts :data:`DRIVE_START` with its ``T0`` (drive-start instant)
   and begins driving;
3. the ENGINE half waits for :data:`DRIVE_START` and — for the kill leg — arms a **local** SIGKILL
   timer relative to the moment it observes ``DRIVE_START`` (so it fires ``kill_fraction × hold`` into
   the driver's hold **without** comparing monotonic clocks across boxes).

That is the entire protocol. There is **no** remote-kill hook: the SIGKILL stays an engine-box-local PID
operation on a timer. The channel carries metadata only (ports, shard ids, timestamps) — never message
bodies or control-id lists (PHI rule).

Transport is a directory of small JSON files (default :data:`DEFAULT_COORD_DIR`, override via the
``MEFOR_COORD_DIR`` env or a CLI flag) written atomically (temp file + ``os.replace``) so a reader never
observes a half-written payload. A message is a single file ``<run_id>.<name>.json``; posting is
idempotent (last write wins) and reading is a non-destructive poll, which is all a two-message
handshake needs. It is intentionally NOT a general message bus — two named messages, one direction each.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any

#: The two handshake message names (the whole protocol). ``SHARDS_READY`` flows engine→driver,
#: ``DRIVE_START`` flows driver→engine.
SHARDS_READY = "SHARDS_READY"
DRIVE_START = "DRIVE_START"

#: The batch_ab two-box matrix drive (ADR 0075 Bench B) reuses this SAME two-message, one-direction-each
#: discipline, but PER CELL: the engine posts :data:`BATCH_CELL_READY` for a ``(batch_mode, count, trial)``
#: cell (engine→driver) and the driver posts :data:`BATCH_CELL_DONE` when it has driven + aggregated that
#: cell (driver→engine). The pair is scoped to a per-cell ``run_id`` (base run id + the cell id) via
#: :meth:`FileDropCoord.for_run`, so the whole matrix stays in lockstep without a general message bus.
BATCH_CELL_READY = "BATCH_CELL_READY"
BATCH_CELL_DONE = "BATCH_CELL_DONE"

#: The WS-C multi-process SIZING drive (PR-C) over-provisions the CLIENT tier into K sender + M sink
#: CHILD processes, all rendezvousing on this SAME file-drop channel under ONE ``run_id`` (the drive
#: coordinator's). The sink half is PER-CHILD-INDEX: the m-th sink posts ``f"{SINK_BOUND}.{m}"`` once its
#: contiguous port chunk is bound, and ``f"{SINK_DONE}.{m}"`` — carrying its final delivered/inversion/
#: repeat tally + its bound ports — once it observes :data:`DRIVE_COMPLETE`. Counts + the synthetic
#: ``{shard}_{dest}`` topology labels only — never control-ids / message bodies (PHI rule).
SINK_BOUND = "SINK_BOUND"
SINK_DONE = "SINK_DONE"
#: Posted by the multi-process drive coordinator once it has drained the engine's REMOTE ``/stats`` — the
#: signal every sink waits for before recording its final tally and posting ``SINK_DONE.<m>``.
DRIVE_COMPLETE = "DRIVE_COMPLETE"

#: The SENDER half of the multi-process drive: sender-worker ``j`` owns a contiguous slice of the
#: ``G = shards*lanes`` inbound bands, opens one persistent MLLP connection per owned band, posts
#: ``f"{DRIVER_ARMED}.{j}"`` once every one is open + proven reachable, waits for :data:`DRIVE_GO`, drives
#: its slice for the hold, then posts ``f"{DRIVER_DONE}.{j}"`` with its sent/acked/ack-latency tally.
#: Counts only — never control-ids / message bodies (PHI rule).
DRIVER_ARMED = "DRIVER_ARMED"
DRIVER_DONE = "DRIVER_DONE"
#: Posted by the coordinator (alongside the engine-facing :data:`DRIVE_START`) to RELEASE the armed
#: sender-workers into their hold in lockstep — the fan-out analogue of the two-box driver simply
#: starting to drive right after it posts DRIVE_START.
DRIVE_GO = "DRIVE_GO"

#: The turnkey two-box SIZING LADDER (PR-C2) automates the manual per-rung ceiling hunt: an
#: ``shardcert-engine-ladder`` (engine box) and an ``shardcert-drive-ladder`` (load-gen box) iterate the
#: SAME fixed rung plan in lockstep, meeting per rung under a per-rung ``run_id`` via
#: :meth:`FileDropCoord.for_run` (``"<base>.r<i>"``) — the exact per-cell scope the batch matrix drive was
#: designed around. Four coordination messages ride the SAME file-drop channel; all carry counts + the
#: synthetic topology only (never control-ids / message bodies — PHI rule):
#:
#: * :data:`ENGINE_DRAINED` (engine→drive, per rung) — the **reliable drain gate**. The engine posts it
#:   after its DIRECT store-truth read confirms the pipeline drained (``stranded``/``dead`` from the store,
#:   NOT the unreliable remote poller), so the drive tallies its sinks ONLY after a teardown-frozen tail
#:   would have been fully absorbed. This is the "post-hold drain window" that lets the ladder tell true
#:   congestion-collapse from a latency tail (a rung that drains within the window is sustainable, not
#:   collapsed). Default-off on the standalone two-box halves (so the C1 cert path stays byte-identical);
#:   the ladder turns it on.
#: * :data:`ENGINE_RUNG_REPORT` (engine→drive, per rung, ``f"{ENGINE_RUNG_REPORT}"`` under the rung
#:   ``run_id``) — the engine box's per-rung store-truth verdict + its LOCAL per-shard send_ack/mark_done
#:   phase-timing aggregate (read off the persisted ``MEFOR_BENCH_KEEP_NODE_LOGS`` node logs after
#:   teardown). The drive-ladder reads it back over the shared coord dir to fold into the ONE consolidated
#:   report — the store-truth authority never leaves the engine box, only its metadata summary does.
#: * :data:`LADDER_STOP` (drive→engine) — the early-stop signal: once the drive classifies a rung as not
#:   sustained (the first ceiling rung), it posts this so the engine skips the remaining climb rungs. It is
#:   an OPTIMISATION, not a correctness gate: the engine polls it non-blocking between rungs, and if the
#:   signal is lost both halves simply finish the bounded fixed plan (no hang).
#: * :data:`LADDER_SOAK` (drive→engine) — after the climb, the drive picks the soak rate (the highest
#:   sustained rung, or an override) and posts it so the engine arms one final long-hold soak rung under
#:   ``run_id`` ``"<base>.soak"`` — or ``{"skip": true}`` when there is no sustained rung to soak.
#: * :data:`RUNG_ABORTED` (drive→engine, PER-RUNG) — the drive posts this on the RUNG coord the instant it
#:   aborts a rung (a broken rendezvous / timeout). It tells the engine that its sinks were torn down mid-
#:   delivery, so the drain failure it is about to see is a HARNESS artifact, not a product collapse: the
#:   engine marks that rung's store-truth INVALID rather than posting a fabricated collapse (B3). Orthogonal
#:   to :data:`LADDER_STOP` (the between-rungs skip optimisation) — this is per-rung and rides the rung coord.
ENGINE_DRAINED = "ENGINE_DRAINED"
ENGINE_RUNG_REPORT = "ENGINE_RUNG_REPORT"
LADDER_STOP = "LADDER_STOP"
LADDER_SOAK = "LADDER_SOAK"
RUNG_ABORTED = "RUNG_ABORTED"

#: Default coord directory. A Windows path because the rig runs on Windows Server; override with the
#: ``MEFOR_COORD_DIR`` env var or the ``--coord-dir`` CLI flag for a POSIX box or a shared mount.
DEFAULT_COORD_DIR = r"C:\mefor_coord"


def default_coord_dir() -> str:
    """The coord dir: ``MEFOR_COORD_DIR`` if set, else :data:`DEFAULT_COORD_DIR`."""
    return os.environ.get("MEFOR_COORD_DIR", DEFAULT_COORD_DIR)


class FileDropCoord:
    """A two-message file-drop rendezvous scoped to one ``run_id`` under one directory.

    The two boxes share the directory (a mount, a synced folder, or — for the co-located structural
    tests — the same local temp dir). ``post`` writes atomically; ``read`` is a non-destructive poll;
    ``await_message`` polls until the file appears or a timeout elapses. Nothing here binds a socket or
    imports the engine, so a single-PC test can round-trip both messages against a temp dir.
    """

    def __init__(self, coord_dir: str | os.PathLike[str], *, run_id: str = "shardcert") -> None:
        self._dir = Path(coord_dir)
        self._run_id = run_id

    @property
    def directory(self) -> Path:
        return self._dir

    @property
    def run_id(self) -> str:
        return self._run_id

    def for_run(self, run_id: str) -> FileDropCoord:
        """A sibling coord under the SAME directory but a different ``run_id`` — the per-cell scope the
        batch two-box matrix drive rendezvous on. Both halves derive the identical ``run_id`` (base run id
        + the cell id) from the profile-driven cell iteration, so they meet per cell without a shared bus."""
        return FileDropCoord(self._dir, run_id=run_id)

    def _path(self, name: str) -> Path:
        return self._dir / f"{self._run_id}.{name}.json"

    def post(self, name: str, payload: dict[str, Any]) -> None:
        """Atomically write ``payload`` as the ``name`` message (temp file + ``os.replace`` so a reader
        never sees a partial JSON object). Creates the coord dir if absent. Last write wins."""
        self._dir.mkdir(parents=True, exist_ok=True)
        target = self._path(name)
        # A PID/nanos-suffixed temp keeps two concurrent posters (never expected, but cheap to defend)
        # from clobbering each other's temp before the atomic replace.
        tmp = target.with_name(f"{target.name}.{os.getpid()}.{time.perf_counter_ns()}.tmp")
        tmp.write_text(json.dumps(payload), encoding="utf-8")
        os.replace(tmp, target)  # atomic on Windows + POSIX for same-filesystem paths

    def read(self, name: str) -> dict[str, Any] | None:
        """Return the ``name`` message payload, or ``None`` if it hasn't been posted (or is mid-write /
        unreadable — the caller just keeps polling)."""
        path = self._path(name)
        try:
            raw = path.read_text(encoding="utf-8")
        except OSError:
            return None
        try:
            data = json.loads(raw)
        except ValueError:
            return None  # a torn read (should not happen with atomic writes) → poll again
        return data if isinstance(data, dict) else None

    async def await_message(
        self, name: str, *, timeout: float, interval: float = 0.25
    ) -> dict[str, Any]:
        """Poll for the ``name`` message until it appears; raise :class:`CoordTimeout` after ``timeout``
        seconds. The poll interval is short (default 0.25s) so the handshake latency is negligible vs a
        multi-second hold."""
        loop = asyncio.get_running_loop()
        deadline = loop.time() + timeout
        while loop.time() < deadline:
            payload = self.read(name)
            if payload is not None:
                return payload
            await asyncio.sleep(interval)
        raise CoordTimeout(
            f"coord message {name!r} not received within {timeout}s (dir={self._dir})"
        )

    def clear(self) -> None:
        """Remove both shardcert handshake files for this ``run_id`` (a fresh run must not read a stale
        one)."""
        self.clear_messages(SHARDS_READY, DRIVE_START)

    def clear_messages(self, *names: str) -> None:
        """Remove the named message files for this ``run_id`` — the first-mover half clears the pair it
        will re-post so a fresh run (or a fresh cell) never reads a stale prior-run drop."""
        for name in names:
            with_missing_ok_unlink(self._path(name))


class CoordTimeout(TimeoutError):
    """A handshake message never arrived within its timeout."""


def with_missing_ok_unlink(path: Path) -> None:
    """``Path.unlink(missing_ok=True)`` but tolerant of a concurrent unlink (best-effort cleanup)."""
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass
