# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Host CPU/mem gauges on the Prometheus surface (BACKLOG #74).

Verifies the host gauges are emitted, carry real values, and add NO labels — so the strict
``{connection, destination, status, version, le}`` PHI label allowlist (test_metrics_exporter.py) is
untouched.
"""

from __future__ import annotations

from prometheus_client import CollectorRegistry, generate_latest
from prometheus_client.parser import text_string_to_metric_families

from messagefoundry.api.metrics import _MetricsCollector, _read_host_metrics, _Snapshot

_HOST_METRICS = {
    "messagefoundry_host_cpu_percent",
    "messagefoundry_host_memory_used_bytes",
    "messagefoundry_host_memory_total_bytes",
    "messagefoundry_process_resident_memory_bytes",
}


def test_read_host_metrics_returns_sane_values() -> None:
    hm = _read_host_metrics()
    # psutil is a hard dependency, so on any normal runner these are populated and positive.
    assert hm.mem_total_bytes is not None and hm.mem_total_bytes > 0
    assert hm.mem_used_bytes is not None and 0 < hm.mem_used_bytes <= hm.mem_total_bytes
    assert hm.process_rss_bytes is not None and hm.process_rss_bytes > 0
    assert hm.cpu_percent is not None and hm.cpu_percent >= 0.0


def _snapshot(**host: float | None) -> _Snapshot:
    return _Snapshot(
        version="test",
        inbound={},
        destinations={},
        latency=[],
        outbox_by_status={},
        in_pipeline=0,
        now=0.0,
        **host,
    )


def test_host_gauges_rendered_unlabeled() -> None:
    snap = _snapshot(
        host_cpu_percent=12.5,
        host_mem_used_bytes=1000.0,
        host_mem_total_bytes=4000.0,
        process_rss_bytes=500.0,
    )
    reg = CollectorRegistry()
    reg.register(_MetricsCollector(snap))
    families = {f.name: f for f in text_string_to_metric_families(generate_latest(reg).decode())}

    for name in _HOST_METRICS:
        assert name in families, f"missing host gauge {name}"
        for sample in families[name].samples:
            assert sample.labels == {}, f"{name} must be label-less, got {sample.labels}"
    assert families["messagefoundry_host_cpu_percent"].samples[0].value == 12.5


def test_host_gauges_absent_when_psutil_unavailable() -> None:
    # A snapshot with no host readings (psutil.Error path) emits none of the host gauges.
    reg = CollectorRegistry()
    reg.register(_MetricsCollector(_snapshot()))
    rendered = generate_latest(reg).decode()
    for name in _HOST_METRICS:
        assert name not in rendered
