# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""STRUCTURAL wiring tests for the DRIVER-ONLY connscale-remote tool (WS-C, ADR 0073) — the
client-isolated two-box drive that meters ALREADY-RUNNING engines over the network and never spawns
one. These prove it wires correctly OFFLINE on one PC: disjoint inbound/sink band validation; one
driver per band dialing the ENGINE box at its own inbound base; the correlation sink bound LOCALLY on
the load-gen box over the union of the per-band sink ports; the poller reading the REMOTE engine
``/stats`` URLs; and the ``connscale-remote`` CLI threading its flags. Every network collaborator is
faked — there is no real cross-box packet flow here (that + the sizing number is the AWS rig's job).
"""

from __future__ import annotations

import types
from collections.abc import Sequence
from typing import Any

import pytest

from harness.load.connscale import remote as rr
from harness.load.connscale.runner import ConnScaleError
from harness.load.rigadmin import REMOTE_RIG_SESSION


def test_check_remote_bands_disjoint_and_overlap() -> None:
    # Two disjoint bands -> the flat union of local sink listeners.
    ports = rr.check_remote_bands([20000, 21000], [40000, 41000], count=100, sink_ports=4)
    assert ports == (40000, 40001, 40002, 40003, 41000, 41001, 41002, 41003)
    # Overlapping sink bands are rejected (they would double-bind).
    with pytest.raises(ConnScaleError):
        rr.check_remote_bands([20000], [40000, 40002], count=10, sink_ports=4)
    # Mismatched band counts are rejected.
    with pytest.raises(ConnScaleError):
        rr.check_remote_bands([20000, 21000], [40000], count=10, sink_ports=4)
    # An inbound block colliding with a sink block is rejected.
    with pytest.raises(ConnScaleError):
        rr.check_remote_bands([40000], [40050], count=100, sink_ports=4)
    # Running past 65535 is rejected.
    with pytest.raises(ConnScaleError):
        rr.check_remote_bands([65500], [40000], count=100, sink_ports=1)


def _install_remote_fakes(monkeypatch: pytest.MonkeyPatch) -> types.SimpleNamespace:
    rec = types.SimpleNamespace(
        driver_hosts=[], driver_bases=[], sink=None, poller_urls=[], poller_tokens=[]
    )

    class FakeDriver:
        def __init__(
            self, *, host: str, base_port: int, count: int, correlator: Any, metrics: Any, **kw: Any
        ) -> None:
            rec.driver_hosts.append(host)
            rec.driver_bases.append(base_port)

        async def open(self, *, connect_batch: int, batch_pause_s: float) -> None:
            return None

        async def run_hold(
            self, *, corpus: Any, mix: Any, aggregate_rate: float, hold_seconds: float
        ) -> None:
            return None

        async def stop(self, grace: float) -> None:
            return None

    class FakeSink:
        def __init__(
            self,
            ids: Any,
            correlator: Any,
            metrics: Any,
            *,
            host: str = "127.0.0.1",
            ports: Sequence[int] = (2700,),
            **kw: Any,
        ) -> None:
            rec.sink = (host, tuple(ports))

        async def start(self) -> None:
            return None

        async def stop(self) -> None:
            return None

    class FakePoller:
        def __init__(self, urls: Any, token: Any = None, *, origin: Any = None) -> None:
            rec.poller_urls.append(list(urls))
            rec.poller_tokens.append(token)
            self.baseline: Any = None
            self.final: Any = None

        async def open(self) -> None:
            return None

        async def sample_once(self) -> Any:
            return None

        async def await_drain(self, *, timeout: float, interval: float) -> float | None:
            return None  # skips sample_until_reconciled; final = sample_once() = None

        async def close(self) -> None:
            return None

    async def fake_await_port(host: str, port: int, *, timeout: float) -> None:
        return None

    monkeypatch.setattr(rr, "ConnScaleDriver", FakeDriver)
    monkeypatch.setattr(rr, "EnginePoller", FakePoller)
    monkeypatch.setattr(rr, "_await_port", fake_await_port)
    monkeypatch.setattr(rr, "_build_ms_corpus", lambda ids: object())
    monkeypatch.setattr("harness.load.sink.CorrelationSink", FakeSink)
    return rec


async def test_run_connscale_remote_wires_remote_engines_and_local_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rec = _install_remote_fakes(monkeypatch)
    engine_ip, loadgen_ip = "10.0.0.5", "10.0.0.9"
    report = await rr.run_connscale_remote(
        engine_urls=[f"http://{engine_ip}:9000", f"http://{engine_ip}:9001"],
        engine_host=engine_ip,
        inbound_bases=[20000, 21000],
        sink_host=loadgen_ip,
        sink_bases=[40000, 41000],
        sink_ports=3,
        count=8,
        per_conn_rate=1.0,
        hold_seconds=0.1,
        drain_timeout=1.0,
        engine_index_base=2,
    )
    # One driver per band, each dialing the ENGINE box at its own inbound base.
    assert set(rec.driver_hosts) == {engine_ip}
    assert rec.driver_bases == [20000, 21000]
    # The sink binds LOCALLY on the load-gen box, over the UNION of the two disjoint 3-port bands.
    assert rec.sink == (loadgen_ip, (40000, 40001, 40002, 41000, 41001, 41002))
    # The poller reads the REMOTE engine /stats URLs.
    assert rec.poller_urls == [[f"http://{engine_ip}:9000", f"http://{engine_ip}:9001"]]
    # ...signed in, and with the credential that ANOTHER process's engines were provisioned with:
    # the remote marker refuses to draw one of its own, which could only be wrong there.
    assert rec.poller_tokens == [REMOTE_RIG_SESSION]
    assert report.engine_bands == 2
    assert report.sink_ports == (40000, 40001, 40002, 41000, 41001, 41002)
    assert report.engine_index_base == 2
    assert report.offered_aggregate_rate == pytest.approx(2 * 8 * 1.0)


async def test_run_connscale_remote_rejects_url_band_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_remote_fakes(monkeypatch)
    with pytest.raises(ConnScaleError):
        await rr.run_connscale_remote(
            engine_urls=["http://10.0.0.5:9000"],  # 1 url
            engine_host="10.0.0.5",
            inbound_bases=[20000, 21000],  # 2 bands
            sink_host="10.0.0.9",
            sink_bases=[40000, 41000],
            count=8,
            per_conn_rate=1.0,
            hold_seconds=0.1,
            drain_timeout=1.0,
        )


# --------------------------------------------------------------------------------------------------
# CLI flag threading
# --------------------------------------------------------------------------------------------------


def test_connscale_remote_cli_threads_flags(monkeypatch: pytest.MonkeyPatch) -> None:
    import harness.__main__ as hmain

    captured: dict[str, object] = {}

    async def fake_run(**kwargs: Any) -> Any:
        captured.update(kwargs)
        return types.SimpleNamespace(
            render_console=lambda: "", exit_code=0, to_json_dict=lambda: {}
        )

    monkeypatch.setattr("harness.load.connscale.remote.run_connscale_remote", fake_run)
    rc = hmain.main(
        [
            "connscale-remote",
            "--engine-url",
            "http://10.0.0.5:9000",
            "--engine-url",
            "http://10.0.0.5:9001",
            "--engine-host",
            "10.0.0.5",
            "--inbound-base",
            "20000,21000",
            "--sink-host",
            "0.0.0.0",
            "--sink-base",
            "40000,41000",
            "--sink-ports",
            "4",
            "--count",
            "512",
            "--per-conn-rate",
            "0.78",
            "--hold-seconds",
            "60",
            "--drain-timeout",
            "300",
            "--engine-index-base",
            "3",
        ]
    )
    assert rc == 0
    assert captured["engine_urls"] == ["http://10.0.0.5:9000", "http://10.0.0.5:9001"]
    assert captured["engine_host"] == "10.0.0.5"
    assert captured["inbound_bases"] == [20000, 21000]
    assert captured["sink_host"] == "0.0.0.0"
    assert captured["sink_bases"] == [40000, 41000]
    assert captured["sink_ports"] == 4
    assert captured["count"] == 512
    assert captured["engine_index_base"] == 3


def _remote_report(**over: Any) -> rr.ConnScaleRemoteReport:
    from harness.load.connscale.report import NoLoss

    fields: dict[str, Any] = {
        "engine_bands": 1,
        "count_per_band": 4,
        "per_conn_rate": 1.0,
        "offered_aggregate_rate": 4.0,
        "engine_index_base": 0,
        "sink_host": "127.0.0.1",
        "sink_ports": (40000,),
        "hold_start_iso": "2026-09-30T00:00:00Z",
        "drain_complete_iso": "2026-09-30T00:00:05Z",
        "achieved_aggregate_rate": 4.0,
        "delivered_aggregate_rate": 4.0,
        "sent": 8,
        "acked": 8,
        "nak": 0,
        "deferred": 0,
        "timeouts": 0,
        "no_loss": NoLoss(True, 8, 8, 8, 8, 0, "ok"),
        "in_pipeline_peak": 0,
        "drain_seconds": 0.5,
    }
    fields.update(over)
    return rr.ConnScaleRemoteReport(**fields)


def test_remote_result_ok_refuses_an_empty_or_undrained_run_bug_5431() -> None:
    from harness.load.connscale.report import NoLoss

    assert _remote_report().result_ok
    # Nothing sent: the reconcile passes vacuously, the verdict must not.
    empty = _remote_report(sent=0, acked=0, no_loss=NoLoss(True, 0, 0, 0, 0, 0, "ok"))
    assert not empty.result_ok
    assert empty.exit_code == 1
    assert empty.to_json_dict()["result"] == "FAIL"
    # A timed-out drain: rows may be stranded upstream of the outbound backlog the reconcile reads.
    undrained = _remote_report(drain_seconds=None)
    assert not undrained.result_ok
    assert undrained.exit_code == 1


def test_remote_json_names_no_rate_window_when_a_bracket_sample_failed_bug_5431() -> None:
    from harness.load.connscale.report import HOLD_BRACKET_RATE_WINDOW

    measured = _remote_report().to_json_dict()["throughput"]
    assert isinstance(measured, dict)
    assert measured["rate_window"] == HOLD_BRACKET_RATE_WINDOW
    unmeasured = _remote_report(rates_measured=False).to_json_dict()["throughput"]
    assert isinstance(unmeasured, dict)
    assert unmeasured["rate_window"] is None


async def test_run_connscale_remote_marks_unsampled_rates_bug_5431(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_remote_fakes(monkeypatch)  # every /stats sample is None, and the drain times out
    report = await rr.run_connscale_remote(
        engine_urls=["http://10.0.0.5:9000"],
        engine_host="10.0.0.5",
        inbound_bases=[20000],
        sink_host="10.0.0.9",
        sink_bases=[40000],
        sink_ports=1,
        count=2,
        per_conn_rate=1.0,
        hold_seconds=0.1,
        drain_timeout=1.0,
    )
    assert not report.rates_measured
    assert not report.result_ok
