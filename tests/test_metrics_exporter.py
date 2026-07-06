# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Prometheus ``/metrics`` exporter + delivery-latency histogram (BACKLOG #21).

The headline test is the **PHI guard**: a message whose body carries a unique sentinel is
routed and delivered, then ``/metrics`` is scraped and proven to contain neither the sentinel
nor any label name outside the strict allowlist ``{connection, destination, status, version,
le}``. The exporter only ever reads aggregate counts/latency keyed by connection name — never a
message field — so the sentinel must never surface.

REST is exercised with httpx's ASGI transport (async; shares this test's loop, so the real
async engine/store run). Latency is driven with controlled ``now=`` timestamps on
``enqueue_message`` (created_at) + ``mark_done`` (updated_at).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families

from messagefoundry.api import create_app
from messagefoundry.api.metrics import (
    DEFAULT_LATENCY_BUCKETS,
    METRICS_CONTENT_TYPE,
    gather_snapshot,
    render_metrics,
)
from messagefoundry.auth import Role
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline import Engine
from messagefoundry.store import OutboxStatus

# The only label names the exposition is ever allowed to carry (the PHI contract).
ALLOWED_LABELS = {"connection", "destination", "status", "version", "le"}

# A unique token planted in a PID field. If it ever appears in the exposition the exporter has
# leaked a message body into a label/value — the one thing #21 forbids.
SENTINEL = "ZZSENTINELMRN9999"

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    f"PID|1||{SENTINEL}^^^H^MR||DOE^JANE\r"
)
TRANSFORMED = (
    "MSH|^~\\&|MEFOR|RFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    f"PID|1||{SENTINEL}^^^H^MR||DOE^JANE\r"
    "ZXF|transformed-by-mefor\r"
)

PW = "a-strong-test-passphrase"  # ≥15, no app/vendor terms — satisfies the ASVS policy (WP-3)


@pytest.fixture
async def engine(tmp_path: Path) -> AsyncIterator[Engine]:
    eng = await Engine.create(tmp_path / "metrics.db", poll_interval=0.02)
    # The fixture never calls start(), so started_at stays 0.0 and `since=started_at or now`
    # would window the counters to `now`, hiding pre-seeded rows. Pin it to a small truthy
    # value before any seeded timestamp so the process-lifetime counters cover the test data.
    eng.started_at = 1.0
    yield eng
    await eng.stop()


@pytest.fixture
async def client(engine: Engine) -> AsyncIterator[httpx.AsyncClient]:
    transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        yield c


async def _deliver(engine: Engine, *, channel: str, dest: str, created: float, done: float) -> None:
    """Seed one outbound row carrying the sentinel and drive it to ``done`` with controlled
    created_at/updated_at so its latency is exactly ``done - created`` seconds."""
    await engine.store.enqueue_message(
        channel_id=channel,
        raw=ADT,
        deliveries=[(dest, TRANSFORMED)],
        control_id="MSG1",
        message_type="ADT^A01",
        source_type="file",
        now=created,
    )
    item = (await engine.store.claim_ready(now=created, destination_name=dest))[0]
    await engine.store.mark_done(item.id, now=done)


# --- 1. shape: 200 + parseable text + expected metric names ------------------


async def test_metrics_endpoint_returns_parseable_exposition(
    engine: Engine, client: httpx.AsyncClient
) -> None:
    await _deliver(engine, channel="adt_in", dest="adt_archive", created=100.0, done=101.0)

    r = await client.get("/metrics")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/plain")
    assert METRICS_CONTENT_TYPE.startswith("text/plain")

    families = {f.name for f in text_string_to_metric_families(r.text)}
    # Always-rendered families (build_info + the unwindowed gauges/histogram). CounterMetricFamily
    # names parse back WITHOUT the _total suffix.
    expected = {
        "messagefoundry_build_info",
        "messagefoundry_messages_received",
        "messagefoundry_deliveries",
        "messagefoundry_outbox_status",
        "messagefoundry_in_pipeline",
        "messagefoundry_delivery_latency_seconds",
    }
    assert expected <= families, f"missing families: {expected - families}"


# --- 2. PHI GUARD (the headline test) ----------------------------------------


async def test_metrics_never_leak_phi(engine: Engine, client: httpx.AsyncClient) -> None:
    # Route + deliver a message whose PID carries a unique sentinel, then scrape.
    await _deliver(engine, channel="adt_in", dest="adt_archive", created=100.0, done=101.0)

    r = await client.get("/metrics")
    assert r.status_code == 200
    body = r.text

    # The body must reflect the delivery (so we know we're not trivially passing on an empty
    # exposition) but must NOT contain the message-body sentinel anywhere.
    assert "adt_in" in body and "adt_archive" in body
    assert SENTINEL not in body

    # Every label NAME present must be in the strict allowlist — no message field ever becomes one.
    seen_labels: set[str] = set()
    for family in text_string_to_metric_families(body):
        for sample in family.samples:
            seen_labels.update(sample.labels.keys())
    assert seen_labels, "expected at least one labelled sample"
    assert seen_labels <= ALLOWED_LABELS, f"disallowed labels: {seen_labels - ALLOWED_LABELS}"


# --- 3. store delivery_latency_histogram unit test ---------------------------


async def test_delivery_latency_histogram_cumulative_counts(engine: Engine) -> None:
    store = engine.store
    # Three done deliveries on the same lane with latencies 0.1s, 1.0s, 3.0s.
    await _deliver(engine, channel="lat", dest="d1", created=100.0, done=100.1)
    await _deliver(engine, channel="lat", dest="d1", created=200.0, done=201.0)
    await _deliver(engine, channel="lat", dest="d1", created=300.0, done=303.0)
    # A still-pending row on the same lane MUST be excluded (only status='done' counts).
    await store.enqueue_message(
        channel_id="lat", raw=ADT, deliveries=[("d1", TRANSFORMED)], now=400.0
    )

    hists = await store.delivery_latency_histogram(buckets=DEFAULT_LATENCY_BUCKETS, now=1000.0)
    assert len(hists) == 1
    h = hists[0]
    assert h.channel_id == "lat"
    assert h.destination_name == "d1"
    assert h.count == 3  # only the done rows; the pending row is excluded
    assert h.sum_seconds == pytest.approx(0.1 + 1.0 + 3.0)

    # bucket_counts are CUMULATIVE (rows with latency <= buckets[i]).
    assert len(h.bucket_counts) == len(DEFAULT_LATENCY_BUCKETS)
    for boundary, cum in zip(DEFAULT_LATENCY_BUCKETS, h.bucket_counts):
        expected = sum(1 for lat in (0.1, 1.0, 3.0) if lat <= boundary)
        assert cum == expected, f"le={boundary}: expected {expected}, got {cum}"
    # Sanity on the ladder ends: le=0.05 catches none; le=300 catches all three.
    assert h.bucket_counts[0] == 0
    assert h.bucket_counts[-1] == 3


async def test_latency_histogram_clamps_negative_latency(engine: Engine) -> None:
    # Clock-skew guard: updated_at < created_at must contribute 0 to the sum, not a negative.
    await _deliver(engine, channel="skew", dest="d1", created=500.0, done=499.0)  # -1s raw
    hists = await engine.store.delivery_latency_histogram(
        buckets=DEFAULT_LATENCY_BUCKETS, now=1000.0
    )
    assert len(hists) == 1
    h = hists[0]
    assert h.count == 1
    assert h.sum_seconds == 0.0  # clamped to >= 0
    # latency clamps to 0, which is <= every bucket boundary, so every cumulative count is 1.
    assert all(c == 1 for c in h.bucket_counts)


# --- 3b. snapshot is built off a single set of awaits (no I/O in collect) ----


async def test_gather_snapshot_carries_aggregates(engine: Engine) -> None:
    await _deliver(engine, channel="adt_in", dest="adt_archive", created=100.0, done=101.0)
    snap = await gather_snapshot(engine)
    assert snap.version
    # Done outbound rows are not pending, so they leave the outbox-status/in-pipeline gauges, but
    # the latency snapshot must carry the delivered lane.
    assert any(
        h.channel_id == "adt_in" and h.destination_name == "adt_archive" for h in snap.latency
    )
    # render_metrics returns bytes (pure-sync generate_latest over the snapshot).
    body = await render_metrics(engine)
    assert isinstance(body, bytes)
    assert SENTINEL.encode() not in body
    assert OutboxStatus.DONE.value  # enum value is the label, used in outbox_status family


# --- 4. AUTH: /metrics is gated by monitoring:read ---------------------------


async def _auth_service(engine: Engine) -> AuthService:
    service = AuthService(engine.store, AuthSettings())
    await service.initialize()
    return service


async def _add(service: AuthService, username: str, *roles: Role) -> None:
    user_id = await service.create_local_user(
        username=username,
        password=PW,
        display_name=None,
        email=None,
        roles=[r.value for r in roles],
        actor="test",
    )
    user = await service.store.get_user(user_id)
    assert user is not None and user.password_hash is not None
    await service.store.set_password(
        user_id, password_hash=user.password_hash, must_change_password=False
    )


async def _login_token(c: httpx.AsyncClient, username: str) -> str:
    r = await c.post(
        "/auth/login", json={"username": username, "password": PW, "provider": "local"}
    )
    return str(r.json()["token"])


def _bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


async def test_metrics_gated_by_monitoring_read(engine: Engine) -> None:
    # Mirror test_cluster_endpoints_gated_by_monitoring_read: VIEWER holds monitoring:read (200);
    # a role-less user lacks it (403); no/invalid token fails closed (401).
    service = await _auth_service(engine)
    await _add(service, "vw", Role.VIEWER)
    await _add(service, "norole")  # empty roles list → no permissions
    transport = httpx.ASGITransport(app=create_app(engine, auth=service))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        # No token under enabled auth → fail closed (401), not an open read.
        assert (await c.get("/metrics")).status_code == 401
        # An invalid token is equally rejected.
        assert (await c.get("/metrics", headers=_bearer("not-a-real-token"))).status_code == 401
        # VIEWER (has monitoring:read) → 200.
        vw = _bearer(await _login_token(c, "vw"))
        assert (await c.get("/metrics", headers=vw)).status_code == 200
        # A role-less user lacks monitoring:read → 403.
        nr = _bearer(await _login_token(c, "norole"))
        assert (await c.get("/metrics", headers=nr)).status_code == 403


# --- 5. OTel seam (skips cleanly when opentelemetry isn't installed) ---------


async def test_otel_seam_records_without_phi(engine: Engine) -> None:
    pytest.importorskip("opentelemetry")
    from messagefoundry.api.metrics import OtelMetricsExporter, build_otel_meter_provider

    # The provider builds with the SDK present (no OTLP endpoint required to construct it).
    provider = build_otel_meter_provider()
    assert provider is not None
    shutdown = getattr(provider, "shutdown", None)
    if shutdown is not None:
        shutdown()

    await _deliver(engine, channel="adt_in", dest="adt_archive", created=100.0, done=101.0)
    exporter = OtelMetricsExporter(engine)
    try:
        await exporter.refresh()  # pulls the snapshot off-loop; observable callbacks read it
        # The observable callbacks must read only aggregate snapshot fields, never a body.
        for obs in exporter._observe_queue_depth(None):  # pyright: ignore[reportPrivateUsage]
            for value in (obs.attributes or {}).values():
                assert SENTINEL not in str(value)
    finally:
        await exporter.aclose()
