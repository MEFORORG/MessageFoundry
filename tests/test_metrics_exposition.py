# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine-owned Prometheus text renderer is byte-identical to the prometheus_client one it replaced.

``/metrics`` used to be rendered by ``prometheus_client.generate_latest`` over a custom collector.
The engine now renders the exposition itself (``messagefoundry/api/metrics.py``), so the base install
no longer carries the library. A scraper must not see the difference, so the proof is BYTES:

* ``tests/golden/metrics_exposition_*.prom`` were written by the prometheus_client renderer
  (``prometheus_client`` 0.26.0, the locked version) from the two snapshots built below, BEFORE the
  library was removed from the render path. The engine renderer must reproduce them exactly.
* The golden files are only as good as the snapshots, so a differential test also renders arbitrary
  families (hostile HELP text, hostile label values, every special float) through both renderers.
  prometheus_client stays a DEVELOPMENT dependency (the ``dev`` extra) for exactly this, and for its
  parser, which the other metrics tests read the exposition with.

The golden files are pinned ``text=auto eol=lf`` in ``.gitattributes``: a CRLF checkout would
otherwise rewrite the bytes this test compares. That pin normalizes line endings on the way in, so
a snapshot built here must never put a raw carriage return in a label value. The exposition writes
a CR verbatim, and the pin would strip it from a CRLF pair in the stored golden.
"""

from __future__ import annotations

import math
import random
import re
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

import pytest
from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.metrics_core import Metric
from prometheus_client.parser import text_string_to_metric_families
from prometheus_client.utils import floatToGoString

from messagefoundry.api.metrics import (
    DEFAULT_LATENCY_BUCKETS,
    METRICS_CONTENT_TYPE,
    _Family,
    _format_value,
    _MetricsCollector,
    _render_exposition,
    _render_snapshot,
    _Snapshot,
)
from messagefoundry.pipeline.sync_reply import SyncReplyMetrics
from messagefoundry.store.pool_metrics import AcquireWaitSummary, PoolStatus
from messagefoundry.store.store import (
    ClaimProcStatus,
    DestinationMetrics,
    InboundMetrics,
    LatencyHistogram,
)

_GOLDEN = Path(__file__).resolve().parent / "golden"
_FULL = _GOLDEN / "metrics_exposition_full.prom"
_MINIMAL = _GOLDEN / "metrics_exposition_minimal.prom"

# A label value carrying every character the exposition escapes (backslash, double quote, newline)
# plus a non-ASCII one, which must pass through as UTF-8.
_HOSTILE = 'IB_q"uote\\back\nline-\u00e9'


def full_snapshot() -> _Snapshot:
    """Every family the exporter can emit, with values that reach every float-format branch."""
    replies = SyncReplyMetrics("IB_HTTP")
    replies.totals = {"reply": 7, "timeout": 2, "degraded": 1}
    replies.wait_seconds_sum, replies.wait_count, replies.live = 5.0, 10, 3
    idle_replies = SyncReplyMetrics(_HOSTILE)  # no turns yet: mean wait 0.0, no status series
    return _Snapshot(
        version='0.4.0+"build"\\x\n',
        inbound={
            "IB_ACME_ADT": InboundMetrics(read=12, errored=0, last_at=None),
            _HOSTILE: InboundMetrics(read=3, errored=1, last_at=5.0),
        },
        destinations={
            ("IB_ACME_ADT", "OB_ARCHIVE"): DestinationMetrics(
                queue_depth=4,
                written=100,
                dead=2,
                oldest_pending_at=900.0,
                recent_done=0,
                last_done_at=None,
            ),
            # oldest_pending_at after `now`: a negative age, which the format must carry as-is.
            ("IB_ACME_ADT", _HOSTILE): DestinationMetrics(
                queue_depth=0,
                written=0,
                dead=0,
                oldest_pending_at=1000.5,
                recent_done=0,
                last_done_at=None,
            ),
            ("IB_ACME_ADT", "OB_EMPTY"): DestinationMetrics(
                queue_depth=0,
                written=0,
                dead=0,
                oldest_pending_at=None,
                recent_done=0,
                last_done_at=None,
            ),
        },
        latency=[
            LatencyHistogram(
                channel_id="IB_ACME_ADT",
                destination_name="OB_ARCHIVE",
                bucket_counts=tuple(range(len(DEFAULT_LATENCY_BUCKETS))),
                sum_seconds=12.75,
                count=15,
            ),
            LatencyHistogram(
                channel_id=_HOSTILE,
                destination_name="OB_ODD",
                bucket_counts=(0,) * len(DEFAULT_LATENCY_BUCKETS),
                sum_seconds=float("-inf"),
                count=0,
            ),
        ],
        outbox_by_status={"pending": 3, "dead": 1},
        in_pipeline=7,
        now=1000.0,
        host_cpu_percent=float("nan"),
        host_mem_used_bytes=16_000_000_000.0,  # repr has no exponent; Go's format does
        host_mem_total_bytes=1_234_567.0,
        process_rss_bytes=0.5,
        pool=PoolStatus(
            backend="postgres",
            max_size=10,
            size=10,
            idle=0,
            acquire_wait=AcquireWaitSummary(
                count=42,
                p50_ms=1.5,
                p95_ms=20.0,
                p99_ms=float("inf"),
                max_ms=1e20,
                mean_ms=3.0,
            ),
        ),
        committed_txns=123_456_789,
        body_copies=0,
        fenced_writes=1,
        claim_proc=ClaimProcStatus(
            effective=True, degraded_reason=None, head_forms={"claim_ingress": "verbatim"}
        ),
        sync_replies={"IB_HTTP": replies, _HOSTILE: idle_replies},
    )


def minimal_snapshot() -> _Snapshot:
    """The emptiest scrape: every optional family absent, every labelled family sample-less."""
    return _Snapshot(
        version="test",
        inbound={},
        destinations={},
        latency=[],
        outbox_by_status={},
        in_pipeline=0,
        now=0.0,
    )


# --- the golden bytes ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("build", "golden"),
    [(full_snapshot, _FULL), (minimal_snapshot, _MINIMAL)],
    ids=["full", "minimal"],
)
def test_the_renderer_reproduces_the_library_bytes(
    build: Callable[[], _Snapshot], golden: Path
) -> None:
    """RED when: any byte of the scrape differs from what prometheus_client wrote for this snapshot."""
    assert _render_snapshot(build()) == golden.read_bytes()


def test_the_full_golden_exercises_every_formatting_branch() -> None:
    """RED when: the full golden stops covering a branch, so matching it would prove less.

    Equality with a golden file proves only what the file contains. This is its positive control.
    """
    body = _FULL.read_bytes()
    for needle in (
        b'\\"',  # an escaped double quote in a label value
        b"\\\\",  # an escaped backslash
        b"\\n",  # an escaped newline
        "\u00e9".encode(),  # non-ASCII label text passed through as UTF-8
        b" NaN\n",
        b" +Inf\n",
        b" -Inf\n",
        b" 1.6e+10\n",  # the exponent form Go uses and Python's repr does not
        b" -0.5\n",  # a negative gauge
        b'le="+Inf"',
        b"_bucket{",
        b"_count{",
        b"_sum{",
        b"# TYPE messagefoundry_http_sync_replies_total counter\n",  # a counter passed WITH _total
        b"# TYPE messagefoundry_store_pool_saturated gauge\n",
        b"# TYPE messagefoundry_store_claim_proc_effective gauge\n",
    ):
        assert needle in body, f"{_FULL.name} no longer contains {needle!r}"
    # The minimal golden's point is the sample-less families: HELP and TYPE with no lines under them.
    assert b"# TYPE messagefoundry_queue_depth gauge\n# HELP " in _MINIMAL.read_bytes()


def test_the_content_type_is_the_one_the_library_sent() -> None:
    assert METRICS_CONTENT_TYPE == "text/plain; version=1.0.0; charset=utf-8"


# --- the same algorithm, not just the same fixture ------------------------------------------------


class _AsLibraryFamilies:
    """Hands the engine's families to prometheus_client as its own ``Metric`` objects, unchanged."""

    def __init__(self, families: Iterable[_Family]) -> None:
        self._families = list(families)

    def collect(self) -> Iterator[Metric]:
        for family in self._families:
            metric = Metric(family.name, family.documentation, family.type)
            for sample in family.samples:
                metric.add_sample(sample.name, dict(sample.labels), sample.value)
            yield metric


def _library_render(families: Iterable[_Family]) -> bytes:
    registry = CollectorRegistry()
    registry.register(_AsLibraryFamilies(families))
    return generate_latest(registry)


def _hostile_families() -> list[_Family]:
    help_text = 'a \\ backslash, a "quote", a\nnewline and \u00e9'
    counter = _Family("x_events_total", help_text, "counter", labels=["connection", "status"])
    counter.add_metric([_HOSTILE, "ok"], 3.0)
    counter.add_metric(["", '\\"\n'], 0.0)
    gauge = _Family("x_level", help_text, "gauge", labels=["destination"])
    for value in (0.0, -0.0, 1.0, -1.0, 1e-7, 123456.0, 1234567.0, 1e22, -1e22, math.pi):
        gauge.add_metric([repr(value)], value)
    for value in (math.inf, -math.inf, math.nan):
        gauge.add_metric([str(value)], value)
    unlabelled = _Family("x_plain", "", "gauge")
    unlabelled.add_metric([], 42.0)
    histogram = _Family("x_seconds", help_text, "histogram", labels=["connection"])
    histogram.add_histogram([_HOSTILE], [("0.5", 1.0), ("1.0", 2.0), ("+Inf", 3.0)], 1.25)
    # Declared out of name order, and a histogram label that sorts AFTER `le`. The engine's own
    # families happen to declare labels in sorted order, so without these the golden files cannot
    # tell sorted output from declaration-order output.
    unsorted = _Family("x_unsorted", "labels declared out of order", "gauge", ["version", "status"])
    unsorted.add_metric(["v1", "ok"], 1.0)
    late = _Family("x_late_seconds", "a label after le", "histogram", labels=["version"])
    late.add_histogram(["v1"], [("0.5", 0.0), ("+Inf", 2.0)], 3.5)
    empty = _Family("x_nothing", "no samples", "counter", labels=["connection"])
    return [counter, gauge, unlabelled, histogram, unsorted, late, empty]


def test_a_family_refuses_samples_of_the_wrong_shape() -> None:
    """RED when: a histogram takes a plain sample, or a gauge takes buckets, and renders it anyway."""
    with pytest.raises(TypeError):
        _Family("x_seconds", "", "histogram").add_metric([], 1.0)
    with pytest.raises(TypeError):
        _Family("x_level", "", "gauge").add_histogram([], [("+Inf", 1.0)], 1.0)
    with pytest.raises(ValueError):
        _Family("x_level", "", "gauge", labels=["connection"]).add_metric([], 1.0)


def test_hostile_families_render_as_the_library_renders_them() -> None:
    """RED when: escaping, label order, value formatting or counter naming departs from the library.

    A failure right after a prometheus-client upgrade means the LIBRARY changed its output. The golden
    files, not the current library, are the contract a scraper sees.
    """
    families = _hostile_families()
    assert _render_exposition(families) == _library_render(families)


def test_the_full_snapshot_renders_as_the_library_renders_it() -> None:
    families = list(_MetricsCollector(full_snapshot()).collect())
    assert _render_exposition(families) == _library_render(families)


def test_value_formatting_matches_the_library_across_magnitudes() -> None:
    """RED when: ``_format_value`` and prometheus_client's ``floatToGoString`` disagree on a value."""
    rng = random.Random(20260930)
    values = [0.0, -0.0, math.inf, -math.inf, math.nan, 5e-324, 1.7976931348623157e308]
    values += [10.0**e for e in range(-12, 25)] + [-(10.0**e) for e in range(-12, 25)]
    values += [rng.uniform(-1e9, 1e9) for _ in range(500)]
    values += [rng.lognormvariate(0, 12) for _ in range(500)]
    values += [float(rng.randrange(10**12)) for _ in range(200)]
    assert len(values) >= 1000, f"only {len(values)} values to compare; the sample shrank"
    mismatched = [v for v in values if _format_value(v) != floatToGoString(v)]
    assert not mismatched, f"formatted differently from the library: {mismatched[:5]}"


# --- what a scraper reads back --------------------------------------------------------------------


def test_the_library_parser_reads_back_every_hostile_label() -> None:
    text = _render_snapshot(full_snapshot()).decode()
    parsed = {f.name: f for f in text_string_to_metric_families(text)}
    received = {
        s.labels["connection"]: s.value for s in parsed["messagefoundry_messages_received"].samples
    }
    assert received == {"IB_ACME_ADT": 12.0, _HOSTILE: 3.0}
    build = parsed["messagefoundry_build_info"].samples[0]
    assert build.labels == {"version": full_snapshot().version}
    assert math.isnan(parsed["messagefoundry_host_cpu_percent"].samples[0].value)


_LEGACY_METRIC_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
_LEGACY_LABEL_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*")


@pytest.mark.parametrize("build", [full_snapshot, minimal_snapshot], ids=["full", "minimal"])
def test_every_name_is_legacy_so_the_renderer_needs_no_name_escaping(
    build: Callable[[], _Snapshot],
) -> None:
    """RED when: a family or label name needs the escaping prometheus_client did and we do not.

    The library rewrites a metric or label name outside the legacy character set. The engine
    renderer writes names verbatim, which is correct only while every name is legacy-valid.
    """
    for family in _MetricsCollector(build()).collect():
        assert _LEGACY_METRIC_NAME.fullmatch(family.exposed_name), family.exposed_name
        for sample in family.samples:
            assert _LEGACY_METRIC_NAME.fullmatch(sample.name), sample.name
            for label in sample.labels:
                assert _LEGACY_LABEL_NAME.fullmatch(label), (family.name, label)
