# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Active-passive **failover under load** — the Gate #3 capstone the steady-state harness can't give.

Where :mod:`harness.load.runner` drives one already-running engine, this orchestrator OWNS the engines'
lifecycle: it starts **two** ``messagefoundry serve`` processes against ONE shared server DB
(``[cluster].enabled`` on Postgres or SQL Server), drives the profile's load at the leader, **SIGKILLs
the current primary mid-load**, and measures what a failover actually costs:

* **promotion time** — kill → the survivor's ``GET /cluster/status`` reports ``role == "primary"`` (the
  control-plane signal);
* **functional recovery time** — kill → forward progress resumes (the survivor's DB-backed ``/stats``
  ``done`` count climbs past its kill-instant value). The pass SLO is ``≤ recovery_ttl_multiple × the
  lease TTL`` (relative, so it stays valid whatever timings a profile sets);
* **no loss (acknowledged)** — every message the engine accept-ACKed reached the sink (``acked ⊆
  delivered``, via :class:`~harness.load.failover_track.FailoverTracker`), with nothing stranded
  (``in_pipeline == 0``) and no dead-letters;
* **bounded duplicates** — at-least-once re-deliveries (``sink_received − engine done``) under a rate cap;
* **per-lane FIFO** — first arrivals per engine outbound DESTINATION (the lane, recovered from MSH-6 —
  the MLLP connector opens a fresh connection per delivery, so the lane is the destination, not the
  socket) stay monotonic. The single hub at ``pool_size = 1`` makes harness send order == engine
  insertion order, so a new seq arriving below a lane's high-water is a genuine ordering break.

This run is also the **first live proof** of the on-promotion in-flight recovery path
(``reset_stale_inflight`` for SQL Server, the lease-reclaim sweep for Postgres) under a real crash — see
``docs/CLUSTERING.md`` and the engine's ``_start_graph``.

The harness reaches the engines only over MLLP (the sender/sink) and the HTTP API (``/health``,
``/cluster/status``, ``/stats``); it never imports the engine in-process (it shells out to ``serve``, as a
deployment would) and never touches the store. All metrics are aggregate — never message bodies or
control-id lists (PHI rule). Two nodes on one host share the **same** inbound MLLP ports: only the leader
binds them, so the sender hits a fixed port and reconnects through the rebind — the floating-VIP collapsed
to "one binder, one port".
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import sys
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import IO, Any

import httpx

from harness.load.corpus import build_corpus
from harness.load.correlator import Correlator
from harness.load.failover_track import FailoverTracker, LeadershipTracker
from harness.load.governor import RateGovernor
from harness.load.ids import ControlIds
from harness.load.metrics import Counters, Histogram, LiveMetrics
from harness.load.profile import Failover, LoadProfile, Phase
from harness.load.report import EXIT_OK, EXIT_SLO_VIOLATION, SloCheck
from harness.load.sender import ConnectionPool, Dispatcher
from harness.load.sink import CorrelationSink

_STOP_GRACE = 5.0
_SETTLE = 0.5  # let the final ACKs/arrivals settle before the truly-final engine sample


class FailoverError(RuntimeError):
    """A failover-run setup/orchestration failure (a node didn't start, no leader elected, etc.)."""


# --- one engine node (a serve subprocess) ------------------------------------


@dataclass(frozen=True)
class NodeStats:
    """A point-in-time read of one node's DB-backed ``/stats`` (shared across the cluster, so any LIVE
    node returns the same queue view — it survives a peer's death)."""

    done: int  # outbound rows delivered (status=done) — cumulative; the forward-progress signal
    dead: int  # dead-lettered rows
    pending: int
    inflight: int
    in_pipeline: int  # NOT-DONE rows across ALL stages (ingress+routed+outbound) — the drain gauge


class EngineNode:
    """Supervises one ``messagefoundry serve`` subprocess and reads its API over HTTP.

    The node is configured entirely via env (``MEFOR_CLUSTER_*`` + ``MEFOR_STORE_*`` + the load-shape
    ``MEFOR_LOAD_*``) plus ``--port`` for its API. ``kill()`` is a faithful crash (SIGKILL / Windows
    ``TerminateProcess``): the DB connections drop so any uncommitted staged-handoff transaction rolls
    back and committed-but-inflight rows are stranded for the survivor's on-promotion recovery."""

    def __init__(
        self, node_id: str, api_port: int, *, env: Mapping[str, str], config_dir: str, cwd: Path
    ) -> None:
        self.node_id = node_id
        self.api_port = api_port
        self.url = f"http://127.0.0.1:{api_port}"
        self._env = dict(env)
        self._config_dir = config_dir
        self._cwd = cwd
        self._proc: asyncio.subprocess.Process | None = None
        # Bench-only (default OFF): when MEFOR_BENCH_KEEP_NODE_LOGS names a directory, persist this
        # node's captured stdout to <dir>/<node_id>.log and do NOT unlink it on stop() — so a rig run
        # can read each shard's throttled phase-timing summary after the fleet is torn down. Unset =>
        # byte-identical to the original tmp-file behavior (deleted on stop). Touches only the harness
        # log sink, never the engine subprocess under test, so measurement fidelity is unaffected.
        self._log: IO[bytes]
        keep_dir = env.get("MEFOR_BENCH_KEEP_NODE_LOGS")
        if keep_dir:
            os.makedirs(keep_dir, exist_ok=True)
            self._keep_log = True
            self._log = open(  # noqa: SIM115 — closed in stop()
                os.path.join(keep_dir, f"{node_id}.log"), "wb"
            )
        else:
            self._keep_log = False
            self._log = tempfile.NamedTemporaryFile(  # noqa: SIM115 — closed in stop()
                prefix=f"mefor-failover-{node_id}-", suffix=".log", delete=False
            )

    async def start(self) -> None:
        self._proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "messagefoundry",
            "serve",
            "--config",
            self._config_dir,
            "--port",
            str(self.api_port),
            "--env",
            "dev",  # synthetic-only env: quiets the prod no-key / open-egress advisories
            env=self._env,
            cwd=str(self._cwd),
            stdout=self._log,
            stderr=asyncio.subprocess.STDOUT,
        )

    @property
    def alive(self) -> bool:
        return self._proc is not None and self._proc.returncode is None

    @property
    def pid(self) -> int | None:
        """The engine subprocess PID, or ``None`` if not started / already reaped. Used by the
        connection-scale harness's OS-side FD sampler (B11)."""
        return self._proc.pid if self._proc is not None else None

    def kill(self) -> None:
        """SIGKILL — the faithful crash. No-op if already gone."""
        if self._proc is not None and self._proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                self._proc.kill()

    async def stop(self) -> None:
        """Graceful shutdown for cleanup (SIGTERM → uvicorn lifespan stop → the node expires its lease);
        escalates to SIGKILL if it doesn't exit, then closes the log file."""
        proc = self._proc
        if proc is not None and proc.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10.0)
            except (TimeoutError, asyncio.TimeoutError):
                with contextlib.suppress(ProcessLookupError):
                    proc.kill()
                with contextlib.suppress(Exception):
                    await proc.wait()
        with contextlib.suppress(Exception):
            self._log.close()
        # The startup-failure tail is captured into the FailoverError before teardown, so the log file is
        # no longer needed once the node is stopped — unlink it rather than leak one per node per run.
        # Bench keep-logs mode (MEFOR_BENCH_KEEP_NODE_LOGS) deliberately preserves it for post-run
        # phase-timing extraction.
        if not self._keep_log:
            with contextlib.suppress(OSError):
                Path(self._log.name).unlink()

    def log_tail(self, limit: int = 4000) -> str:
        """The end of this node's captured stdout/stderr — for diagnosing a failed start in CI."""
        try:
            data = Path(self._log.name).read_bytes()
        except OSError:
            return ""
        return data[-limit:].decode("utf-8", "replace")

    # --- API reads (auth is disabled on the test nodes, so no token is needed) ---

    async def healthy(self, client: httpx.AsyncClient) -> bool:
        return (await _get_json(client, f"{self.url}/health")) is not None

    async def role(self, client: httpx.AsyncClient) -> str | None:
        """``"primary"`` / ``"standby"`` / ``"single-node"`` from ``/cluster/status``; ``None`` if the
        node is unreachable (down, killed, or still starting)."""
        data = await _get_json(client, f"{self.url}/cluster/status")
        role = data.get("role") if data else None
        return role if isinstance(role, str) else None

    async def stats(self, client: httpx.AsyncClient) -> NodeStats | None:
        data = await _get_json(client, f"{self.url}/stats")
        if data is None:
            return None
        by = data.get("outbox_by_status", {})
        by = by if isinstance(by, dict) else {}
        return NodeStats(
            done=int(by.get("done", 0)),
            dead=int(by.get("dead", 0)),
            pending=int(by.get("pending", 0)),
            inflight=int(by.get("inflight", 0)),
            in_pipeline=int(data.get("in_pipeline", 0)),
        )


async def _get_json(client: httpx.AsyncClient, url: str) -> dict[str, Any] | None:
    """GET ``url`` and return the JSON object, or ``None`` on any error / non-200 (a killed or
    still-starting node just refuses the connection — that's expected, never raised)."""
    try:
        resp = await client.get(url)
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    try:
        body = resp.json()
    except ValueError:
        return None
    return body if isinstance(body, dict) else None


# --- run configuration -------------------------------------------------------


@dataclass(frozen=True)
class FailoverPorts:
    """Every port the two-node scenario needs. The caller (CLI or test) reserves them; the inbound MLLP
    ports are shared by both nodes (only the leader binds), the API ports are per-node."""

    inbound_adt: int  # the single driven hub
    inbound_results: int  # bound by the leader but not driven
    inbound_other: int  # bound by the leader but not driven
    sink: int  # base correlation-sink port (the harness binds it)
    sink_count: int  # contiguous sink ports
    api_a: int
    api_b: int


# --- the report --------------------------------------------------------------


@dataclass(frozen=True)
class FailoverReport:
    profile: str
    db_backend: str | None
    killed_node: str | None
    promoted_node: str | None
    promotion_seconds: float | None
    recovery_seconds: float | None
    # counters
    sent: int
    acked: int
    nak: int
    timeouts: int
    deferred: int
    sink_received: int
    engine_delivered: int  # final DB ``done`` minus the pre-load baseline
    intake_gap: int  # sent − acked: the un-ACKed-at-kill reconnect window (expected, not loss)
    acked_not_delivered: int  # the headline loss number (must be 0)
    duplicates: int  # at-least-once re-deliveries (sink_received − engine_delivered)
    dup_rate: float
    lane_inversions: int
    lanes_observed: int  # distinct destination lanes (≥2 ⇒ the ordering check is non-vacuous)
    max_concurrent_leaders: int
    leader_samples: int  # H6: how many times the leader-set size was observed (non-vacuity proof)
    in_pipeline_final: int
    dead_final: int
    # The in_pipeline_final split at the drain deadline — the decisive failover-recovery diagnostic:
    # PENDING = re-pended (by the on-promotion lease-blind recovery), awaiting (re)claim → a residue here
    # is a discovery/claim gap; INFLIGHT = claimed-not-completed or a stranded lease never re-pended → a
    # residue here is a recovery gap (the dead leader's rows never became claimable).
    pending_final: int
    inflight_final: int
    lease_ttl_seconds: float
    slos: list[SloCheck]
    result_ok: bool
    exit_code: int
    notes: list[str]

    def to_json_dict(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "kind": "failover",
            "profile": self.profile,
            "db_backend": self.db_backend,
            "result": "PASS" if self.result_ok else "FAIL",
            "exit_code": self.exit_code,
            "failover": {
                "killed_node": self.killed_node,
                "promoted_node": self.promoted_node,
                "promotion_seconds": self.promotion_seconds,
                "recovery_seconds": self.recovery_seconds,
                "lease_ttl_seconds": self.lease_ttl_seconds,
                "max_concurrent_leaders": self.max_concurrent_leaders,
                "leader_samples": self.leader_samples,
            },
            "totals": {
                "sent": self.sent,
                "acked": self.acked,
                "nak": self.nak,
                "timeouts": self.timeouts,
                "deferred": self.deferred,
                "sink_received": self.sink_received,
                "engine_delivered": self.engine_delivered,
            },
            "no_loss": {
                "acked_not_delivered": self.acked_not_delivered,
                "intake_gap": self.intake_gap,
                "in_pipeline_final": self.in_pipeline_final,
                "dead_final": self.dead_final,
            },
            "duplicates": {"count": self.duplicates, "rate": round(self.dup_rate, 5)},
            "ordering": {
                "lane_inversions": self.lane_inversions,
                "lanes_observed": self.lanes_observed,
            },
            "slo": [
                {"name": c.name, "threshold": c.threshold, "observed": c.observed, "ok": c.ok}
                for c in self.slos
            ],
            "notes": self.notes,
        }

    def render_console(self) -> str:
        lines: list[str] = []
        lines.append(
            f"Failover-load report -- profile {self.profile!r} (backend {self.db_backend or '?'})"
        )
        lines.append("")
        prom = "n/a" if self.promotion_seconds is None else f"{self.promotion_seconds:.2f}s"
        rec = "TIMEOUT" if self.recovery_seconds is None else f"{self.recovery_seconds:.2f}s"
        lines.append(
            f"failover: killed={self.killed_node} promoted={self.promoted_node} "
            f"promotion={prom} recovery={rec} (lease_ttl={self.lease_ttl_seconds}s) "
            f"max_concurrent_leaders={self.max_concurrent_leaders} "
            f"(over {self.leader_samples} leadership samples)"
        )
        lines.append(
            f"traffic: sent={self.sent} acked={self.acked} nak={self.nak} timeouts={self.timeouts} "
            f"deferred={self.deferred} sink_received={self.sink_received} "
            f"engine_delivered={self.engine_delivered}"
        )
        lines.append(
            f"no-loss: acked_not_delivered={self.acked_not_delivered} (intake_gap={self.intake_gap}, "
            f"in_pipeline={self.in_pipeline_final} [pending={self.pending_final} "
            f"inflight={self.inflight_final}], dead={self.dead_final})"
        )
        lines.append(
            f"duplicates: {self.duplicates} ({self.dup_rate * 100:.2f}%) | "
            f"ordering: lane_inversions={self.lane_inversions} over {self.lanes_observed} lane(s)"
        )
        lines.append("")
        lines.append("SLOs:")
        for c in self.slos:
            lines.append(
                f"  [{'PASS' if c.ok else 'FAIL'}] {c.name}: observed={c.observed} threshold={c.threshold}"
            )
        for note in self.notes:
            lines.append(f"note: {note}")
        violated = sum(1 for c in self.slos if not c.ok)
        lines.append("")
        lines.append(
            f"RESULT: {'PASS' if self.result_ok else 'FAIL'}"
            f"{'' if self.result_ok else f' ({violated} violated)'} -> exit {self.exit_code}"
        )
        return "\n".join(lines)


# --- orchestration -----------------------------------------------------------


async def run_failover_load(
    profile: LoadProfile,
    *,
    ports: FailoverPorts,
    config_dir: str = "harness/config/load",
    sink_host: str = "127.0.0.1",
    db_backend: str | None = None,
    base_env: Mapping[str, str] | None = None,
    cwd: Path | None = None,
    id_prefix: str | None = None,
    election_timeout: float = 30.0,
) -> FailoverReport:
    """Run the two-node primary-kill scenario and return a :class:`FailoverReport`.

    ``base_env`` supplies the shared-DB connection (``MEFOR_STORE_*``); it defaults to the process
    environment. ``id_prefix`` defaults to a run-scoped value (so a stale prior run's undrained rows on a
    reused server DB can't parse as this run's seqs and mask loss / inflate dups). The profile MUST carry a
    ``[load.failover]`` table, exactly one ``[[load.target]]``, and exactly one (last) measured phase."""
    fo = profile.failover
    if fo is None:
        raise FailoverError("the profile has no [load.failover] table — not a failover profile")
    if len(profile.targets) != 1:
        raise FailoverError(
            "a failover profile must declare exactly one [[load.target]] (single-stream FIFO ordering)"
        )
    prefix_phases, measured = _split_phases(profile)
    base_env = dict(os.environ if base_env is None else base_env)
    cwd = cwd or Path.cwd()
    profile = replace(
        profile,
        targets=(replace(profile.targets[0], host="127.0.0.1", port=ports.inbound_adt),),
    )

    notes: list[str] = []
    phase_task: asyncio.Task[None] | None = None
    monitor: asyncio.Task[_KillOutcome] | None = None
    # Run-scoped control-id prefix (pid + monotonic ns) unless the caller pinned one — keeps a re-run
    # against a long-lived shared DB from colliding with a prior run's seqs (mirrors the --load CLI).
    if id_prefix is None:
        id_prefix = f"FO{os.getpid():x}{time.perf_counter_ns():x}"[:16]
    ids = ControlIds(prefix=id_prefix)
    corpus = await asyncio.to_thread(build_corpus, profile, ids)
    metrics = LiveMetrics(Counters(), Histogram(), Histogram())
    correlator = Correlator(profile.correlator_capacity, metrics)
    tracker = FailoverTracker()
    sink = CorrelationSink(
        ids,
        correlator,
        metrics,
        host=sink_host,
        ports=tuple(ports.sink + i for i in range(ports.sink_count)),
        tracker=tracker,
    )
    pools = [
        (t, ConnectionPool(t, profile.pool_size, correlator, metrics, tracker=tracker))
        for t in profile.targets
    ]
    dispatcher = Dispatcher(pools, seed=profile.seed)

    nodes = [
        EngineNode(
            f"fo-{tag}",
            api,
            env=_node_env(base_env, node_id=f"fo-{tag}", ports=ports, fo=fo, sink_host=sink_host),
            config_dir=config_dir,
            cwd=cwd,
        )
        for tag, api in (("a", ports.api_a), ("b", ports.api_b))
    ]

    async with httpx.AsyncClient(timeout=4.0) as client:
        try:
            await sink.start()
            for node in nodes:
                await node.start()
            await _await_all_healthy(nodes, client, timeout=election_timeout)
            leader = await _await_single_leader(nodes, client, timeout=election_timeout)
            notes.append(f"elected {leader.node_id} as the initial primary")
            await _await_port("127.0.0.1", ports.inbound_adt, timeout=15.0)
            done_baseline = await _live_stats(nodes, client)
            done_at_start = done_baseline.done if done_baseline else 0

            dispatcher.start()
            stop = asyncio.Event()
            for phase in prefix_phases:
                await _run_one_phase(
                    profile,
                    metrics,
                    RateGovernor(corpus, dispatcher, metrics.counters),
                    phase,
                    stop,
                )

            # The measured phase runs in the background; partway through, kill the current primary.
            governor = RateGovernor(corpus, dispatcher, metrics.counters)
            phase_task = asyncio.create_task(
                _run_one_phase(profile, metrics, governor, measured, stop)
            )
            kill_delay = max(0.0, fo.kill_at_fraction * measured.duration_s)
            await asyncio.sleep(kill_delay)
            primary = await _current_primary(nodes, client)
            if primary is None:
                raise FailoverError("no primary to kill at the scheduled kill time")
            survivor = next(n for n in nodes if n is not primary)
            kill_ns = time.perf_counter_ns()
            primary.kill()
            notes.append(f"SIGKILLed primary {primary.node_id} at kill time")
            # Measure promotion + functional recovery in the BACKGROUND so a slow-but-successful recovery
            # (e.g. delivery that only resumes during the post-load drain) is MEASURED, not a false timeout.
            monitor_deadline = 4.0 * fo.leader_lease_ttl_seconds + profile.drain_timeout_s + 30.0
            monitor = asyncio.create_task(
                _monitor_failover(primary, survivor, client, kill_ns, monitor_deadline, notes)
            )
            await phase_task

            # Stop offering; drain the survivor's pipeline (DB-backed gauge, so it survives the failover).
            await dispatcher.stop(_STOP_GRACE)
            await asyncio.sleep(_SETTLE)
            await _await_drain(survivor, client, timeout=profile.drain_timeout_s)
            outcome = (
                await monitor
            )  # recovery was observed during the phase/drain (or hit the deadline)
            final = await survivor.stats(client)
            if final is None:
                raise FailoverError("could not read the survivor's final /stats for reconciliation")
            return _build_report(
                profile,
                db_backend,
                metrics.counters,
                tracker,
                outcome,
                final,
                done_at_start,
                fo,
                notes,
            )
        finally:
            for task in (phase_task, monitor):
                if task is not None and not task.done():
                    task.cancel()
                    with contextlib.suppress(asyncio.CancelledError, Exception):
                        await task
            with contextlib.suppress(Exception):
                await dispatcher.stop(_STOP_GRACE)
            with contextlib.suppress(Exception):
                await sink.stop()
            for node in nodes:
                with contextlib.suppress(Exception):
                    await node.stop()


@dataclass
class _KillOutcome:
    killed: EngineNode
    survivor: EngineNode
    promotion_seconds: float | None
    recovery_seconds: float | None
    max_concurrent_leaders: int
    leader_samples: int  # how many times the leader-set size was observed (non-vacuity proof, H6)


async def _monitor_failover(
    killed: EngineNode,
    survivor: EngineNode,
    client: httpx.AsyncClient,
    kill_ns: int,
    deadline_s: float,
    notes: list[str],
) -> _KillOutcome:
    """Time the survivor's promotion + functional recovery after the kill. Runs in the BACKGROUND
    (concurrently with the rest of the measured phase + the post-load drain) so a slow-but-successful
    recovery is measured rather than timing out a fixed pre-drain window. ``done`` is DB-backed, so it
    survives the dead primary; the recovery baseline is taken at PROMOTION (not at the kill) so a delivery
    the dying primary committed just before SIGKILL can't be mistaken for the survivor's progress.

    The CONTINUOUS single-leader SLO (H6): every poll observes BOTH nodes' roles and folds the count of
    simultaneous primaries into a :class:`LeadershipTracker`, so a split-brain that flickers *between*
    promotion and recovery is caught — not just the one pair sampled at promotion. The high-water (and a
    non-vacuity sample count) flow into the report's ``single_leader`` SLO."""
    leaders = LeadershipTracker()
    promotion_ns: int | None = None
    recovery_ns: int | None = None
    done_at_promotion = 0
    start = time.perf_counter()
    while time.perf_counter() - start < deadline_s:
        # H6 continuous single-leader invariant: sample BOTH nodes' roles every poll and record how many
        # are simultaneously primary right now. >= 2 at any sample is split-brain (a HARD SLO violation);
        # the killed node should stop reporting primary the instant it dies, so the count is normally 0
        # (post-kill, pre-promotion) then 1 (after the survivor promotes) — never 2.
        survivor_role = await survivor.role(client)
        killed_role = await killed.role(client)
        leaders.observe((survivor_role == "primary") + (killed_role == "primary"))
        role = survivor_role
        if promotion_ns is None and role == "primary":
            promotion_ns = time.perf_counter_ns()
            prom = await survivor.stats(client)
            done_at_promotion = prom.done if prom else 0
            notes.append(f"{survivor.node_id} promoted to primary")
        if promotion_ns is not None and recovery_ns is None:
            cur = await survivor.stats(client)
            if cur is not None and cur.done > done_at_promotion:
                recovery_ns = time.perf_counter_ns()
                notes.append("forward progress resumed (engine delivered new rows post-promotion)")
                break
        await asyncio.sleep(0.2)

    promotion_s = None if promotion_ns is None else (promotion_ns - kill_ns) / 1e9
    recovery_s = None if recovery_ns is None else (recovery_ns - kill_ns) / 1e9
    if recovery_s is None:
        notes.append(f"functional recovery NOT observed within {deadline_s:.0f}s of the kill")
    if leaders.two_or_more_leader_samples:
        notes.append(
            f"SPLIT-BRAIN: observed two primaries simultaneously in "
            f"{leaders.two_or_more_leader_samples} of {leaders.samples} samples"
        )
    # max(1, ...): the cluster had exactly one leader before the kill, so the reported high-water is at
    # least 1 even though the post-kill / pre-promotion window legitimately samples 0 leaders. The SLO
    # bar is "<= 1", so this floor never masks a real >= 2 split-brain.
    return _KillOutcome(
        killed,
        survivor,
        promotion_s,
        recovery_s,
        max(1, leaders.max_concurrent_leaders),
        leaders.samples,
    )


def _build_report(
    profile: LoadProfile,
    db_backend: str | None,
    counters: Counters,
    tracker: FailoverTracker,
    outcome: _KillOutcome,
    final: NodeStats,
    done_at_start: int,
    fo: Failover,
    notes: list[str],
) -> FailoverReport:
    c = counters.snapshot()
    engine_delivered = max(0, final.done - done_at_start)
    duplicates = max(0, c.sink_received - engine_delivered)
    dup_rate = duplicates / engine_delivered if engine_delivered else 0.0
    acked_not_delivered = tracker.acked_not_delivered()
    intake_gap = max(0, c.sent - c.acked)
    no_loss_ok = acked_not_delivered == 0 and final.in_pipeline == 0 and final.dead == 0
    recovery_bound = fo.recovery_ttl_multiple * fo.leader_lease_ttl_seconds

    slos = [
        SloCheck(
            "promotion_observed",
            True,
            outcome.promotion_seconds is not None,
            outcome.promotion_seconds is not None,
        ),
        SloCheck(
            "functional_recovery_seconds",
            round(recovery_bound, 2),
            -1.0 if outcome.recovery_seconds is None else round(outcome.recovery_seconds, 2),
            outcome.recovery_seconds is not None and outcome.recovery_seconds <= recovery_bound,
        ),
        # H6 continuous single-leader invariant: ≤ 1 simultaneous primary across EVERY sample. Non-vacuous
        # by construction — a monitor that never observed the cluster (leader_samples == 0) FAILS rather
        # than silently certifying "single leader" off zero evidence (mirrors the lanes_observed ≥ 2 guard).
        SloCheck(
            "single_leader",
            1,
            outcome.max_concurrent_leaders,
            outcome.leader_samples > 0 and outcome.max_concurrent_leaders <= 1,
        ),
        SloCheck("no_acknowledged_loss", 0, acked_not_delivered, no_loss_ok),
        SloCheck("per_lane_ordering", 0, tracker.lane_inversions, tracker.lane_inversions == 0),
        SloCheck("max_dup_rate", fo.max_dup_rate, round(dup_rate, 5), dup_rate <= fo.max_dup_rate),
    ]
    if fo.max_promotion_seconds is not None:
        slos.append(
            SloCheck(
                "max_promotion_seconds",
                fo.max_promotion_seconds,
                -1.0 if outcome.promotion_seconds is None else round(outcome.promotion_seconds, 2),
                outcome.promotion_seconds is not None
                and outcome.promotion_seconds <= fo.max_promotion_seconds,
            )
        )
    if c.acked == 0:
        notes.append("WARNING: zero messages were ACKed — the run sent no load the engine accepted")
    result_ok = all(s.ok for s in slos) and c.acked > 0
    return FailoverReport(
        profile=profile.name,
        db_backend=db_backend,
        killed_node=outcome.killed.node_id,
        promoted_node=outcome.survivor.node_id,
        promotion_seconds=outcome.promotion_seconds,
        recovery_seconds=outcome.recovery_seconds,
        sent=c.sent,
        acked=c.acked,
        nak=c.nak,
        timeouts=c.timeouts,
        deferred=c.deferred,
        sink_received=c.sink_received,
        engine_delivered=engine_delivered,
        intake_gap=intake_gap,
        acked_not_delivered=acked_not_delivered,
        duplicates=duplicates,
        dup_rate=dup_rate,
        lane_inversions=tracker.lane_inversions,
        lanes_observed=tracker.lanes_observed,
        max_concurrent_leaders=outcome.max_concurrent_leaders,
        leader_samples=outcome.leader_samples,
        in_pipeline_final=final.in_pipeline,
        dead_final=final.dead,
        pending_final=final.pending,
        inflight_final=final.inflight,
        lease_ttl_seconds=fo.leader_lease_ttl_seconds,
        slos=slos,
        result_ok=result_ok,
        exit_code=EXIT_OK if result_ok else EXIT_SLO_VIOLATION,
        notes=notes,
    )


# --- helpers -----------------------------------------------------------------


def _split_phases(profile: LoadProfile) -> tuple[list[Phase], Phase]:
    measured_idx = [i for i, p in enumerate(profile.phases) if p.measured]
    if len(measured_idx) != 1:
        raise FailoverError(
            "a failover profile must have exactly one measured (sustained/soak) phase — "
            f"found {len(measured_idx)}"
        )
    mi = measured_idx[0]
    if mi != len(profile.phases) - 1:
        raise FailoverError("the measured phase must be the LAST phase of a failover profile")
    return list(profile.phases[:mi]), profile.phases[mi]


def _node_env(
    base: Mapping[str, str], *, node_id: str, ports: FailoverPorts, fo: Failover, sink_host: str
) -> dict[str, str]:
    env = dict(base)
    env["MEFOR_CLUSTER_ENABLED"] = "true"
    env["MEFOR_CLUSTER_NODE_ID"] = node_id
    env["MEFOR_CLUSTER_HEARTBEAT_SECONDS"] = repr(fo.heartbeat_seconds)
    env["MEFOR_CLUSTER_LEADER_FENCE_TIMEOUT_SECONDS"] = repr(fo.leader_fence_timeout_seconds)
    env["MEFOR_CLUSTER_LEADER_LEASE_TTL_SECONDS"] = repr(fo.leader_lease_ttl_seconds)
    env["MEFOR_AUTH_ENABLED"] = "false"  # no token needed for the harness's API reads
    # A clustered node drives concurrent background work against the pool (the validator requires >= 2,
    # >= 3 for Postgres). Force headroom regardless of what the CI store env set.
    try:
        pool = int(env.get("MEFOR_STORE_POOL_SIZE", "0"))
    except ValueError:
        pool = 0
    env["MEFOR_STORE_POOL_SIZE"] = str(max(pool, 5))
    # A failover run is a CORRECTNESS check, not a max-throughput run — keep fan-out modest so the shared
    # DB isn't the bottleneck (the caller/CI can still override the fan-out via base_env).
    env.setdefault("MEFOR_LOAD_FANOUT", "3")
    env.setdefault("MEFOR_LOAD_RESULTS_FANOUT", "2")
    # FORCE the `edit` transform: it stamps MSH-6 = SINK_{lane}_{index} on each delivery, which is the
    # per-lane FIFO ordering key (the MLLP connector opens a fresh connection per delivery, so the lane is
    # the destination, not the socket). `cheap` is pass-through and would leave every lane indistinguishable.
    env["MEFOR_LOAD_TRANSFORM"] = "edit"
    # The load-shape system-under-test ports (both nodes bind the same inbound ports; only the leader
    # actually opens them, so there's no conflict on one host).
    env["MEFOR_LOAD_ADT_PORT"] = str(ports.inbound_adt)
    env["MEFOR_LOAD_RESULTS_PORT"] = str(ports.inbound_results)
    env["MEFOR_LOAD_OTHER_PORT"] = str(ports.inbound_other)
    env["MEFOR_LOAD_SINK_HOST"] = sink_host
    env["MEFOR_LOAD_SINK_PORT"] = str(ports.sink)
    env["MEFOR_LOAD_SINK_PORTS"] = str(ports.sink_count)
    return env


async def _run_one_phase(
    profile: LoadProfile,
    metrics: LiveMetrics,
    governor: RateGovernor,
    phase: Phase,
    stop: asyncio.Event,
) -> None:
    # Fresh per-phase histograms (mirrors the steady-state runner) so the failover tail isn't charged to
    # any earlier phase; the counters + tracker span the whole run.
    metrics.ack = Histogram()
    metrics.e2e = Histogram()
    await governor.run_phase(phase, profile.mix_for(phase), stop)


async def _await_all_healthy(
    nodes: list[EngineNode], client: httpx.AsyncClient, *, timeout: float
) -> None:
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        if all([await n.healthy(client) for n in nodes]):
            return
        for n in nodes:
            if not n.alive:
                raise FailoverError(f"node {n.node_id} exited during startup:\n{n.log_tail()}")
        await asyncio.sleep(0.25)
    dead = "\n\n".join(f"--- {n.node_id} ---\n{n.log_tail()}" for n in nodes)
    raise FailoverError(f"nodes did not become healthy within {timeout}s:\n{dead}")


async def _await_single_leader(
    nodes: list[EngineNode], client: httpx.AsyncClient, *, timeout: float
) -> EngineNode:
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        roles = [await n.role(client) for n in nodes]
        leaders = [n for n, r in zip(nodes, roles) if r == "primary"]
        if len(leaders) == 1:
            return leaders[0]
        if len(leaders) > 1:
            raise FailoverError(
                f"split-brain at election: {[n.node_id for n in leaders]} both primary"
            )
        await asyncio.sleep(0.25)
    raise FailoverError(f"no single leader elected within {timeout}s")


async def _current_primary(nodes: list[EngineNode], client: httpx.AsyncClient) -> EngineNode | None:
    for n in nodes:
        if await n.role(client) == "primary":
            return n
    return None


async def _live_stats(nodes: list[EngineNode], client: httpx.AsyncClient) -> NodeStats | None:
    for n in nodes:
        s = await n.stats(client)
        if s is not None:
            return s
    return None


async def _await_drain(node: EngineNode, client: httpx.AsyncClient, *, timeout: float) -> None:
    """Poll the survivor's DB-backed ``/stats`` until the whole pipeline is empty (``in_pipeline == 0``)
    and ``done`` stops climbing across a poll. Logs nothing on timeout — the reconciliation's
    ``in_pipeline_final`` surfaces an undrained pipeline as loss."""
    prev = await node.stats(client)
    start = time.perf_counter()
    while time.perf_counter() - start < timeout:
        await asyncio.sleep(0.5)
        cur = await node.stats(client)
        if cur is None:
            continue
        if cur.in_pipeline == 0 and prev is not None and cur.done == prev.done:
            return
        prev = cur


async def _await_port(host: str, port: int, *, timeout: float) -> None:
    """Wait until a TCP connect to ``host:port`` succeeds (the leader has bound its inbound listener)."""
    start = time.perf_counter()
    last: Exception | None = None
    while time.perf_counter() - start < timeout:
        try:
            reader, writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            last = exc
            await asyncio.sleep(0.25)
            continue
        writer.close()
        with contextlib.suppress(OSError):
            await writer.wait_closed()
        return
    raise FailoverError(
        f"inbound port {host}:{port} never became reachable within {timeout}s: {last}"
    )
