# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale CI smoke (B11) — a fast, hermetic end-to-end run on SQLite.

The harness OWNS a fresh engine subprocess per sweep step (EngineNode), serving ``harness/config/
connscale`` with ``MEFOR_CONNSCALE_COUNT`` env-set, and drives a tiny connection-count sweep. It
proves the harness SPINS N connections, NO-LOSS reconcile holds, the FD counter moves MONOTONICALLY
with N (wall #4 exists and scales), the additive engine fields are present (back-compat shim works),
and the executor boot-shim populates wall #1 / the reload probe returns a finite number.

THE EMPTY-CLAIM COUNTER (WALL #3) IS NO LONGER GATED FOR MONOTONICITY, AND THE SENTENCE ABOVE
USED TO SAY IT WAS (BACKLOG #1211). The vs-N gate was DELETED rather than widened: a harvest of
894 lane transitions found it broken five ways at once, so nothing in CI now asserts that the
empty-claims curve rises with N at all. That is a real reduction in coverage, named here rather
than left for a later reader to discover by accident. What the run DOES assert about wall #3, in
``test_the_empty_claim_counter_moved_at_the_base_connection_count``, is a sign test at the BASE
connection count only: every ``per_lane`` lane that produced a reading at the sweep's lowest N
produced a STRICTLY POSITIVE one, plus a run-level bound that at least one lane was graded at all.
Pooled lanes are never graded, because the prediction behind the reading assumes one worker set per
lane per stage.

WHAT IS STILL MEASURED IS UNCHANGED; ONLY THE VERDICT SHRANK. ``empty_claims_per_msg`` is computed
on every record and RECORDED on every run, pass or fail, to the job summary and to the readings
JSON (``_record_ratio_readings``, which runs in the fixture so a green run is recorded as fully as
a red one). The PREDICTED HERD FLOOR for the base reading rides along in both emitters. That floor
is RECORDED, NOT GATED, by owner ruling: it reproduces four harvested medians closely and still
missed its own pre-landing counterfactual on a leg that passed, so gating on it would have reddened
a green leg. Arming it from its own distribution is BACKLOG #1415.

THE MASTER TEST PLAN'S COVERAGE ROW FOR THIS MODULE IS STALE, AND IT IS NOT IN THIS REPOSITORY ANY
MORE. It lived in ``docs/testing/master-test-plan/17-performance-and-scale.md``; commit 921db74a1
(PR #714) untracked that whole directory under ADR 0160's D1 test, and only
``docs/testing/VERIFY.md`` survives here. The row therefore now lives in the separate vault
repository and cannot be edited from an engine checkout. Be precise about what that means: that the
file LEFT this repository is measured; the vault copy's CURRENT TEXT has not been read from here,
so the row is unverified rather than known to be wrong. Until someone reconciles it there, THIS
DOCSTRING is the nearest in-repo statement of what the run actually covers, which is why the
paragraphs above spell out the loss and not only the replacement.

It does NOT regression-cover wall #1 (executor) or wall #2 (pool) as REAL curves: at small N on
SQLite the pool wall is a documented no-op and the executor is under-threshold — stated honestly here.
The Postgres CI leg (pool_size forced to 1-2) gives the acquire-wait wall real small-N coverage.

A small N (12 → 24) keeps it inside the pytest-timeout budget; the shipped ``connscale-smoke`` profile
(N=50/100), run via the ``--connscale`` CLI in CI, is the larger-N variant.
"""

from __future__ import annotations

import json
import os
import pathlib
import sys
import tempfile
import warnings
from collections.abc import Sequence

import pytest

from harness.load.connscale.intake_audit import MOMENT_POST_MORTEM
from harness.load.connscale.probe import ProbeDegraded
from harness.load.connscale.profile import load_connscale_profile_text
from harness.load.connscale.report import (
    ConnScaleRecord,
    ConnScaleReport,
    herd_floor_readings,
)
from harness.load.connscale.runner import _MONOTONIC_TOLERANCE, run_connscale
from tests._connscale_ports import (
    INBOUND_PORT_HI,
    INBOUND_PORT_LO,
    require_contiguous,
    reserve_api_and_sink_bases,
    reserve_contiguous_ports,
)

pytestmark = pytest.mark.timeout(120)  # the per-test 60s default is too tight for two engine spawns

# The connection-count sweep; its max sets the contiguous inbound-port width (BACKLOG #1014).
_SMOKE_COUNTS = (12, 24)

# The three port families this run consumes -- inbound, API and sink -- are all reserved as whole
# contiguous ranges by tests/_connscale_ports.py, which is where the windows and the rationale for
# them live (BACKLOG #1014 for the inbound family, #1103 for the other two).


def _smoke_profile(base_port: int) -> object:
    # Small N (12 → 24) + short holds so the smoke fits the pytest budget; both sweep modes by default.
    return load_connscale_profile_text(f"""
[connscale]
name = "smoke-it"
counts = {list(_SMOKE_COUNTS)}
sweep_mode = "both"
aggregate_rate = 24.0
per_conn_rate = 1.0
hold_seconds = 1.5
connect_batch = 8
connect_batch_pause_s = 0.0
poll_interval_s = 0.25
drain_timeout_s = 30.0
base_port = {base_port}
transform = "cheap"
reload_probe = true
store_backend = "sqlite"
corpus_count_per_trigger = 5

[connscale.slo]
zero_loss = true
fd_monotonic = true
empty_claims_base_reading = true
""")


def _is_budget_exhausted(cause: str) -> bool:
    """Is this recorded cause one where the probe SPENT its whole timeout budget?

    Delegates to the probe's own :class:`ProbeDegraded` rather than listing members here, so the
    tolerable set cannot drift member-by-member away from the definition. An UNRECOGNISED cause is
    treated as not-tolerable: a new degrade path must be classified deliberately, and defaulting the
    unknown to "tolerate" is how a fresh probe defect would arrive already excused."""
    try:
        return ProbeDegraded(cause).is_budget_exhausted
    except ValueError:
        return False


def _assert_fd_probe(records: Sequence[ConnScaleRecord]) -> None:
    """Assert wall #4 to the strength the OS probe's contract actually supports — no more, no less.

    This used to be a bare ``assert r.fd_count_peak is not None and r.fd_count_peak > 0, r`` inside the
    loop above, with no tolerance for a probe that honestly could not measure. ``fd_count_peak`` is
    ``None`` on every one of the probe's degrade paths, and only some of them implicate anything under
    test — so a starved runner whose process-table walk timed out reddened a REQUIRED context as though
    the ENGINE were at fault, and did it with a message that named no mechanism. The record now carries
    the cause, so this can state a verdict instead of a value check.

    The tolerable/not line is the probe's own (``ProbeDegraded.is_budget_exhausted``), NOT a second
    vocabulary invented here. It is the same line ``tests/test_connscale_cpu_probe.py`` draws from the
    seconds a failed walk actually spent: budget exhausted is COULD NOT MEASURE, anything faster is
    MEASURED AND BROKEN.

    Four properties, and none is weaker than the old assertion wherever the probe worked:

    1. Where the probe READ, the count must be positive — the wall exists. Unchanged.
    2. Where it did not, the record must NAME a cause. An unattributable gap FAILS. A tolerance that
       swallowed it would buy a green by destroying the only evidence of what went wrong, which is the
       failure mode this whole change exists to remove.
    3. A cause that is not budget-exhausted FAILS — a walk that returned zero rows, a failed
       enumeration, a snapshot with no root row, a per-PID read that ran and parsed nothing. A broken
       probe must not hide behind the tolerance written for a slow one.
    4. A budget-exhausted cause is tolerated PER RECORD but not for the run: at least one step must have
       measured, so a probe that never works anywhere still cannot pass. That is the same bound
       assertion (5) below already places on the reload probe."""
    for r in records:
        if r.fd_count_peak is not None:
            assert r.fd_count_peak > 0, r
            continue
        causes = tuple(r.fd_probe_degraded)
        scope = f"{r.fd_probe_degraded_ticks} of {r.fd_probe_ticks} probe tick(s) degraded"
        assert causes, (
            f"UNATTRIBUTED GAP -- wall #4 read nothing at {r.sweep_mode}@N={r.count} and the record "
            f"names no cause ({scope}). A gap that cannot say which probe path produced it is not "
            f"evidence about the engine in either direction, and is deliberately NOT tolerated: "
            f"tolerating it is what made one starved runner and one broken enumerator the same "
            f"artifact. Record: {r}"
        )
        broken = tuple(c for c in causes if not _is_budget_exhausted(c))
        assert not broken, (
            f"PROBE DEFECT -- wall #4 read nothing at {r.sweep_mode}@N={r.count} because {broken} "
            f"({scope}; all causes {causes}). None of those is an exhausted timeout budget: the probe "
            f"RAN and produced nothing usable, which is a defect in the probe itself and is reported "
            f"as a failure rather than downgraded to a tolerated gap. Record: {r}"
        )
    # Every step degraded, and (given the loop above) every cause was an exhausted budget. Each such
    # step alone measures the RUNNER rather than this tree, but a run in which the FD probe never once
    # read is not evidence that wall #4 exists -- so the tolerance stops here instead of buying a green
    # over zero measurements.
    detail = "; ".join(
        f"{r.sweep_mode}@N={r.count} {r.fd_probe_degraded_ticks}/{r.fd_probe_ticks} "
        f"{tuple(r.fd_probe_degraded)}"
        for r in records
    )
    # THE BOUND IS AT THE SLO'S GRANULARITY, NOT THE RUN'S, AND THE DIFFERENCE IS A REAL DEFECT THAT
    # SHIPPED HERE FIRST. The obvious form -- "at least one record measured" -- is not enough, because
    # the per-record assertion this replaced was doing DOUBLE DUTY: it was also the only thing
    # guaranteeing `fd_count_monotonic` had two readings in a group to COMPARE. `_monotonic_slo`
    # SKIPS None readings (runner.py, "Missing readings (None) are skipped, not failed"), so with a
    # run-wide bound it can return ok=True observed='monotonic' having compared NOTHING -- and a real
    # FD collapse then passes. Measured on this smoke: forcing every step after the first to
    # WALK_TIMEOUT left one group with a single reading, PAIRS ACTUALLY COMPARED=0, and the SLO still
    # reported monotonic; a 1000-handle collapse at N=12 with both N=24 steps degraded passed the same
    # way, while the unforced control compared 2 pairs and a genuine 1000->100 drop correctly failed.
    #
    # So require that some (sweep_mode, claim_mode) group -- the SAME key `_monotonic_slo` groups on
    # (BACKLOG #1101) -- actually has a pair. Grouping on sweep_mode alone would re-introduce the bug
    # one level up: two readings split across claim modes are never compared with each other.
    #
    # NOT MIRRORED FROM assertion (5). An earlier version of this justified the run-wide bound as "the
    # same bound the reload probe already has". Same SHAPE, wrong ANALOGY: `reload_seconds` feeds no
    # monotonicity SLO, so a single reading there costs nothing. `fd_count_peak` feeds one.
    measured_per_group: dict[tuple[str, str], int] = {}
    for r in records:
        if r.fd_count_peak is not None:
            key = (r.sweep_mode, r.claim_mode)
            measured_per_group[key] = measured_per_group.get(key, 0) + 1
    assert any(n >= 2 for n in measured_per_group.values()), (
        f"WALL #4 NEVER COMPARED -- no (sweep_mode, claim_mode) group has two measured readings, so "
        f"`fd_count_monotonic` compared zero pairs and its green says nothing. Measured readings per "
        f"group: {measured_per_group or '{}'} [{detail}]. A single step timing out is tolerated; a run "
        f"in which the FD wall is never compared against itself is not, because the SLO that is "
        f"supposed to cover it silently passes over an empty set."
    )


def _assert_intake_audit(records: Sequence[ConnScaleRecord]) -> None:
    """Assert the BACKLOG #1292 discriminator on every step, in the order its verdicts matter.

    Four properties, each pinning a different way this could go quietly wrong:

    1. NO step is ``engine_suspect``. This is the finding the item is about: the engine framed an
       accept-ACK for a message and its own stopped, committed store has no row for it.
    2. EVERY step's audit is CONCLUSIVE. A PROBE_UNUSABLE result is not a pass -- it means the
       instrument could not answer, and an instrument that silently stops answering leaves the
       original unattributable failure in place while looking green.
    3. EVERY step's sweep read rows (``store_total > 0``) against a step that sent messages. This is
       the positive control: a set comparison against an empty set is clean for the wrong reason.
    4. The authoritative audit is the POST-MORTEM one. A live read could be explained away as early
       sampling; a read of a stopped engine's store cannot, and mislabelling one as the other would
       destroy the only distinction the second moment exists to make.
    """
    for r in records:
        audit = r.intake_audit
        assert not audit.engine_suspect, (
            f"COUNT-AND-LOG INVARIANT -- {r.sweep_mode}@N={r.count}: {audit.summary()}. The engine "
            f"accept-ACKed those sends and its own stopped, committed store has no messages row for "
            f"them, so a deploying site would be able to lose an acknowledged message at intake. "
            f"The sequence numbers above name them; this is reproducible, not statistical."
        )
        assert audit.conclusive, (
            f"INTAKE AUDIT COULD NOT ANSWER -- {r.sweep_mode}@N={r.count}: {audit.summary()}. The "
            f"discriminator is the whole point of this step's no-loss coverage, so a probe that did "
            f"not run or could not read is reported as a failure rather than tolerated: tolerating "
            f"it restores exactly the unattributable red this check exists to replace."
        )
        assert audit.moment == MOMENT_POST_MORTEM, audit
        assert audit.store_total > 0, (
            f"INTAKE AUDIT POSITIVE CONTROL -- {r.sweep_mode}@N={r.count} sent {r.sent} message(s) "
            f"and the store sweep read {audit.store_total} row(s): {audit.summary()}. A clean set "
            f"comparison over an empty read says nothing about intake."
        )


# --- the one expensive run, shared by every property below ----------------------------------------


#: Overrides where a LOCAL run appends its readings. Named so a variance-gathering sweep can
#: point every run at one file instead of hunting a temp path per invocation.
_LOCAL_READINGS_ENV = "MEFOR_CONNSCALE_READINGS"

#: Where a local run lands when neither variable is set. Named once so a test can assert the
#: write happened without re-deriving the path -- a second copy of it here would be a second
#: definition, free to drift from the one the emitter actually uses.
_DEFAULT_READINGS_PATH = pathlib.Path(tempfile.gettempdir()) / "connscale-readings.md"

#: Where the MACHINE-READABLE copy goes. `out/` is gitignored and is where this repo's load
#: harness already drops its reports, so CI can upload this the same way it uploads those.
_READINGS_JSON_ENV = "MEFOR_CONNSCALE_READINGS_JSON"
_DEFAULT_JSON_PATH = pathlib.Path("out") / "connscale" / "empty_claims.json"


def _append_step_summary(text: str) -> None:
    """Append to the job summary, which renders whether the job passed or failed.

    APPEND, never truncate: ``$GITHUB_STEP_SUMMARY`` accumulates across every step of the job, so
    overwriting it would eat another step's output.

    A write that fails WARNS rather than raising. The reading is diagnostics, and turning a
    diagnostics failure into a red leg on an unrelated pull request is the disease BACKLOG #1211 is
    treating, not a cure for it. It is not swallowed either -- a silent emitter and a working one
    would be indistinguishable.

    OFF CI there is no job summary, so the readings go to a FILE and a warning names it. Precedence
    is ``$GITHUB_STEP_SUMMARY`` first, then ``$MEFOR_CONNSCALE_READINGS``, then a temp file -- CI
    keeps its existing behaviour untouched, and a local sweep can aim every run at one file.
    """
    path = os.environ.get("GITHUB_STEP_SUMMARY") or os.environ.get(_LOCAL_READINGS_ENV)
    if not path:
        # A LOCAL RUN GETS A REAL FILE, and the earlier stderr fallback was wrong about why it did
        # not need one. pytest captures at the FILE DESCRIPTOR by default and DISCARDS the capture
        # when the test PASSES -- which is precisely the run this emitter exists to record, since an
        # excursion-only sample is selected on the outcome. Measured both ways on this repo: a
        # passing test's stderr marker appears 0 times under default capture and 1 time under -s.
        # The warning names the file because warnings survive that same capture and a reading nobody
        # can find is not a reading.
        path = str(_DEFAULT_READINGS_PATH)
        warnings.warn(f"connscale readings appended to {path}", stacklevel=2)
    try:
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(text)
    except OSError as exc:
        warnings.warn(
            f"could not record connscale readings to the step summary: {exc}", stacklevel=2
        )


def _record_ratio_readings(report: ConnScaleReport) -> None:
    """Persist every ``empty_claims_per_msg`` reading this run produced (BACKLOG #1211).

    The SLO records a number only once it has already left its band, so the only samples that ever
    survived a run were the excursions -- and a sample selected on having excursioned cannot measure
    the distribution it came from. #1211 needs the variance before anyone may touch the band, so the
    readings are written here, from the FIXTURE, which runs before any assertion and therefore records
    a passing run and a failing one alike.

    The tolerance is IMPORTED, not typed in. A second copy of 0.25 here would be a second definition
    of the band, and the emitted floor could then drift away from the one the SLO actually enforces.

    THAT LAST CLAUSE NO LONGER HOLDS FOR THIS METRIC, AND THE IMPORT SURVIVES ANYWAY. Since the
    empty-claims band was retired (BACKLOG #1211) no SLO grades ``empty_claims_per_msg`` against
    ``_MONOTONIC_TOLERANCE``; the renderer says so on the table it prints, and an OUTSIDE BAND row
    there fails nothing. The width is still imported rather than retyped for a different reason:
    holding it at the value the harvested readings were measured under is what keeps new rows
    directly comparable with those already harvested. ``fd_count_monotonic`` does still enforce the
    same constant, so a second copy here would remain a second definition regardless.
    """
    _append_step_summary(
        report.render_readings_markdown(
            "empty_claims_per_msg",
            lambda r: r.empty_claims_per_msg,
            tolerance=_MONOTONIC_TOLERANCE,
            context=_run_context(),
            base_count=min(_SMOKE_COUNTS),
        )
    )
    _write_readings_json(
        report.readings_payload(
            "empty_claims_per_msg",
            lambda r: r.empty_claims_per_msg,
            tolerance=_MONOTONIC_TOLERANCE,
            context=_run_context(),
            base_count=min(_SMOKE_COUNTS),
        )
    )


def _write_readings_json(payload: dict[str, object]) -> None:
    """Persist the readings where a TOOL can fetch them (BACKLOG #1211).

    THE MARKDOWN COPY IS UNREADABLE BY ANY TOOL AND THAT IS THE WHOLE PROBLEM. It goes to
    ``$GITHUB_STEP_SUMMARY``, and no GitHub API exposes a step summary -- measured 2026-08-27 from
    two directions: the jobs endpoint carries no summary-bearing key, and the rendered page answers
    "Sign in to view logs" even on a public repository. So every passing run has been recording its
    values and then losing them, which defeats the point of recording a passing run.

    An uploaded artifact IS fully API-reachable via ``gh run download``, and this repo's load
    harness already proves the pattern. The workflow uploads ``out/connscale/``.

    Same failure discipline as the markdown: a write that fails WARNS and never raises. Turning a
    diagnostics failure into a red leg on an unrelated pull request is the disease #1211 treats.
    """
    target = pathlib.Path(os.environ.get(_READINGS_JSON_ENV) or _DEFAULT_JSON_PATH)
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    except OSError as exc:
        warnings.warn(f"could not write connscale readings JSON: {exc}", stacklevel=2)


def _run_context() -> dict[str, str]:
    """What a later reader needs to tell one run's samples from another's.

    ONE definition, read by BOTH emitters. Two copies would drift, and a reader diffing the two tables
    a single run produces would then be chasing a difference in the context rather than in the data.

    #1211's question is whether the ratio moves with runner contention, so the core count is part of
    the reading rather than trivia.
    """
    return {
        "runner_os": os.environ.get("RUNNER_OS", "local"),
        "cpus": str(os.cpu_count()),
        "run_id": os.environ.get("GITHUB_RUN_ID", "-"),
        "sha": os.environ.get("GITHUB_SHA", "-")[:8] or "-",
    }


def _record_diagnostics(report: ConnScaleReport) -> None:
    """Persist the band-less diagnostic fields this run produced (BACKLOG #1366).

    THE RATIO SAYS THAT SOMETHING MOVED; THESE SAY WHICH. Without them a connscale failure is
    permanently undiagnosable from CI alone -- drain-tail and reload-probe separate ONLY on
    `drain_seconds` against `reload_seconds`, and contention separates from probe-cost ONLY on the FD
    probe's tick counts. Those readings existed on every record already and never left the `test` job,
    which uploads no artifacts.

    Emitted from the FIXTURE for the same reason #1211's readings are: it runs before any assertion, so
    a passing run is recorded as fully as a failing one. A field that appears only on failure cannot
    establish what its normal range is, which is the defect #1211 exists to fix one metric over.

    NO BAND AND NO VERDICT -- see `render_diagnostics_markdown`. None of these has an SLO, so any
    threshold printed beside them would be manufactured by the renderer.
    """
    _append_step_summary(report.render_diagnostics_markdown(context=_run_context()))


@pytest.fixture(scope="module")
async def smoke_report() -> ConnScaleReport:
    """ONE ``run_connscale`` sweep for the whole module (BACKLOG #1331).

    THE SWEEP SPAWNS AN ENGINE SUBPROCESS PER STEP, so re-running it per property would multiply this
    module's cost by the number of properties — which is precisely why they were welded into a single
    test to begin with. Sharing the run buys the separate NAMES without buying a second sweep.

    MODULE-SCOPED AND ASYNC ON PURPOSE. ``pyproject.toml`` sets
    ``asyncio_default_fixture_loop_scope = "session"``, so this still runs on the suite's one shared
    loop. Do NOT "simplify" it to ``asyncio.run()``: that opens a SECOND loop, which is the exact
    cross-loop split that setting exists to prevent, and its comment says so.

    The setup cost lands on whichever test pytest runs first. That is the same work the module's
    ``timeout(120)`` already covered when it was inline, so the budget is unchanged, not tightened.
    """
    # Reserve a contiguous inbound-port block (BACKLOG #1014). The sweep's max connection count
    # needs that many contiguous inbound ports, and the engine binds base_port + i for each. A
    # RANDOM anchor de-correlates concurrent worktrees so they no longer contend for one fixed
    # block; contiguity is asserted at the acquisition site, and the allocator fails loudly if no
    # free block can be found (never a silent fixed fallback).
    inbound_ports = reserve_contiguous_ports(
        max(_SMOKE_COUNTS), lo=INBOUND_PORT_LO, hi=INBOUND_PORT_HI
    )
    base_port = require_contiguous(inbound_ports, max(_SMOKE_COUNTS), "inbound")
    profile = _smoke_profile(base_port)

    # ... and reserve the API and sink RANGES the same way (BACKLOG #1103). Both are derived by
    # increment from their base -- the runner binds api_port + step for EVERY sweep step, the sink
    # binds sink_port + i for every sink port -- so reserving only the base, as this test used to,
    # left every port after the first merely assumed free. Two CI reds came of that assumption, on
    # PRs that could not reach this code at all. All three families now come from disjoint windows
    # below the OS ephemeral floors, so the kernel cannot hand one out after it is probed.
    api_port, sink_port = reserve_api_and_sink_bases(profile, sink_ports=1)  # type: ignore[arg-type]

    report = await run_connscale(
        profile,  # type: ignore[arg-type]
        engine_api_port_base=api_port,
        sink_host="127.0.0.1",
        sink_port=sink_port,
        sink_ports=1,
        install_executor_shim=True,
    )
    # In the FIXTURE, so the readings are recorded before any assertion can fail the module.
    _record_ratio_readings(report)
    _record_diagnostics(report)
    return report


# --- the properties, ONE NAME EACH ----------------------------------------------------------------
#
# BACKLOG #1331: these were one test named ``test_connscale_smoke_end_to_end`` over at least six
# separate properties. It sits on three of the thirteen required contexts, so every occurrence is
# merge-blocking -- and because one name covered all of them, TWO SEATS HITTING IT TWICE SAW TWO
# UNRELATED BUGS RATHER THAN ONE RECURRING PROBLEM, and nobody owned it. The assertions below are
# UNCHANGED; only their names are new. A failing context now says which property broke without
# anyone reading the module.
#
# DECOMPOSITION ONLY -- this deliberately does NOT attempt to fix the underlying flake. The item is
# explicit that the cause is uncharacterised and that the intake arm does not fail by a constant
# (1 of 36 in one run, 17 of 36 in another), so any bound tweak here would be untested against the
# wide case and would manufacture a green rather than earn one.


def test_the_sweep_produces_one_record_per_mode_and_count(smoke_report: ConnScaleReport) -> None:
    """A record per (sweep_mode, N): both modes x {12, 24} = 4 rows."""
    assert len(smoke_report.records) == 4
    modes = {(r.sweep_mode, r.count) for r in smoke_report.records}
    assert modes == {
        ("fixed_aggregate", 12),
        ("fixed_aggregate", 24),
        ("fixed_per_conn", 12),
        ("fixed_per_conn", 24),
    }


def test_no_loss_reconciles_at_every_step(smoke_report: ConnScaleReport) -> None:
    """No-loss at each N (sent == engine_read, engine_written == sink_received, backlog drained).

    THIS IS THE INTAKE-LOSS ARM the item names -- ``engine_read 35 below confirmed sent 36``. When this
    context reds, read the failure here rather than anywhere else in the module.
    """
    for r in smoke_report.records:
        assert r.sent > 0, r
        assert r.no_loss.ok, (r.sweep_mode, r.count, r.no_loss.detail)


def test_no_accept_acked_message_is_absent_from_the_stopped_engines_store(
    smoke_report: ConnScaleReport,
) -> None:
    """BACKLOG #1292 -- the PER-MESSAGE intake audit, asserted INDEPENDENTLY of the count check above.

    Strictly ADDITIONAL, not a restatement: the count check compares totals and forgives an
    unconfirmed send, so a message the engine ACCEPT-ACKed and then has no row for passes it whenever
    that message also happened to be excused as a timeout. This asserts the thing the count check
    cannot: that no accept-ACKed message is absent from the engine's own committed store.
    """
    _assert_intake_audit(smoke_report.records)


def test_the_fd_curve_is_monotonic_in_n(smoke_report: ConnScaleReport) -> None:
    """Curve monotonicity smoke for wall #4 (a LOOSE >= per mode; CI runners are noisy): FD count at
    N=24 >= N=12 minus the jitter band. Asserted via the report's monotonicity SLO.

    THIS IS THE THROUGHPUT-SLO ARM the item names, distinct from the intake arm above. Nothing
    measured shows the two share a root cause; separate names keep that question open instead of
    quietly answering it.

    THE EMPTY-CLAIMS ARM USED TO BE WELDED INTO THIS TEST AND IS NOW ITS OWN, BECAUSE THE TWO STOPPED
    ASSERTING THE SAME SHAPE (BACKLOG #1211). One name per property is this module's own doctrine
    (#1331), and it matters more here than usual: while the two shared a name, a red said only that
    one of two unrelated propositions failed.
    """
    slo_by_name = {c.name: c for c in smoke_report.slos}
    assert slo_by_name["fd_count_monotonic"].ok, slo_by_name["fd_count_monotonic"].observed


def test_the_empty_claim_counter_moved_at_the_base_connection_count(
    smoke_report: ConnScaleReport,
) -> None:
    """Wall #3, asserted only as far as a hosted runner can measure it (BACKLOG #1211).

    TWO ASSERTIONS, AND THE SECOND IS REQUIRED RATHER THAN BELT-AND-BRACES. The SLO reports ok=True
    over a run that graded NOTHING -- deliberately, following ``intake_audit``, so a profile the gate
    cannot apply to does not manufacture a red. That makes the SLO alone satisfiable by an empty set,
    which this module already records as a real defect for wall #4: forcing every FD probe to time out
    left PAIRS ACTUALLY COMPARED=0 while ``fd_count_monotonic`` still reported monotonic. So the
    run-level bound lives here, where the metric genuinely runs.

    It is not a hypothetical hole. Across the 454 CI legs harvested for #1211, 14 (3.1 percent) lost a
    whole lane to unreadable readings and the old SLO reported ``monotonic`` having compared only the
    other one. No leg lost BOTH, which is why this bound is a bound and not a flake.
    """
    slo_by_name = {c.name: c for c in smoke_report.slos}
    check = slo_by_name["empty_claims_base_reading"]
    assert check.ok, check.observed

    readings = herd_floor_readings(
        smoke_report.records, lambda r: r.empty_claims_per_msg, base_count=min(_SMOKE_COUNTS)
    )
    graded = [r for r in readings if r.ok is not None]
    assert graded, (
        f"WALL #3 NEVER GRADED -- no lane produced a readable empty-claims-per-message reading at "
        f"N={min(_SMOKE_COUNTS)}, so the SLO's green says nothing. Lanes and why each was skipped: "
        f"{[(r.label, r.not_graded) for r in readings] or 'no lanes at all'}."
    )


def test_the_additive_engine_fields_are_populated(smoke_report: ConnScaleReport) -> None:
    """The additive engine fields are present + non-None where the shim/probe ran (back-compat
    works): the executor boot-shim populates wall #1, and the FD probe reads the engine PID."""
    assert smoke_report.shim_installed
    for r in smoke_report.records:
        assert r.executor_queue_depth_peak is not None, r  # the shim installed the default executor
        assert r.executor_busy_peak is not None, r
        # Wall #3 is separated, never summed into one number; both halves are non-negative.
        assert r.idle_poll_per_s >= 0.0 and r.wake_fanout_per_s >= 0.0


def test_the_fd_probe_measured_or_named_why_it_could_not(smoke_report: ConnScaleReport) -> None:
    """Wall #4 (FD), asserted only as far as this module is ENTITLED to. See ``_assert_fd_probe``."""
    _assert_fd_probe(smoke_report.records)


def test_the_reload_probe_measured_at_least_one_step(smoke_report: ConnScaleReport) -> None:
    """The reload-latency probe (wall #5) times an O(connections) quiesce-and-swap. Like the other
    OS-side probes it is best-effort and gap-tolerant BY DESIGN: a reload fired mid-hold at the highest
    connection count can occasionally exceed the client timeout under peak load, and the probe records a
    gap (None) rather than a fabricated number (see harness/load/connscale/probe.py time_reload). Require
    it to have MEASURED at least one step (the probe is wired and works) and to be finite wherever present
    — asserting a number at EVERY step would be stricter than the probe's own contract and flakes on slow
    CI runners."""
    measured_reloads = [
        r.reload_seconds for r in smoke_report.records if r.reload_seconds is not None
    ]
    assert measured_reloads, [(r.sweep_mode, r.count) for r in smoke_report.records]
    assert all(s >= 0.0 for s in measured_reloads)


def test_the_pool_wall_is_absent_rather_than_zero_on_sqlite(smoke_report: ConnScaleReport) -> None:
    """Wall #2 (pool) is a documented no-op on SQLite — recorded as absent (None), not a fake 0."""
    for r in smoke_report.records:
        assert r.pool_wait_p99_ms is None, r
        assert r.pool_idle_min is None, r


def test_the_run_reports_overall_success(smoke_report: ConnScaleReport) -> None:
    """The runner's own verdict, kept separate from the individual properties above: this can red
    while every property passes (or the reverse), and merging the two hid which had happened."""
    assert smoke_report.result_ok and smoke_report.exit_code == 0


@pytest.mark.skipif(sys.platform != "win32" and sys.platform != "linux", reason="OS FD probe path")
def test_fd_sampler_reads_self() -> None:
    # The FD sampler reads a live PID (this test process) — a positive handle/fd count — and returns
    # None for a definitely-dead PID, never raising.
    import os

    from harness.load.connscale.probe import FdSampler

    live = FdSampler(os.getpid()).sample()
    assert live is None or live > 0  # None only if the OS tool is unavailable on this runner
    dead = FdSampler(2**31 - 1).sample()  # an implausible PID
    assert dead is None


# The port-allocator's own guards (contiguity, fail-loud exhaustion, the too-narrow window, and
# #1103's "every port the sweep will use was reserved") live in tests/test_connscale_ports.py,
# beside the allocator they cover.
