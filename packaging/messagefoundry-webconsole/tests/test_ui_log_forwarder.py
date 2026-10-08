# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The status page and the nav heart show the off-box log forwarder (BACKLOG #2612)."""

from __future__ import annotations

import pytest

from messagefoundry.api.models import (
    ClusterNodeList,
    ClusterStatus,
    DbInfo,
    DrStatus,
    EngineInfo,
    LogForwarderInfo,
    SecurityPosture,
    ServiceStatusInfo,
    SystemStatus,
)
from messagefoundry_webconsole.pages import status
from messagefoundry_webconsole.pages._common import _log_forwarder_reason
from messagefoundry_webconsole.routes.status import _derive_health

NOT_INSTALLED = LogForwarderInfo(state="not_installed", installed=False, start_failure="permanent")
DROPPING = LogForwarderInfo(state="degraded", installed=True, lost=7, queue_dropped=7)
HELD = LogForwarderInfo(state="degraded", installed=True, send_failing=True, spool_read_errors=2)
HEALTHY = LogForwarderInfo(state="healthy", installed=True)


def _sys(forwarder: LogForwarderInfo | None) -> SystemStatus:
    return SystemStatus(
        engine=EngineInfo(
            version="0",
            uptime_seconds=10.0,
            pid=1,
            channels_total=1,
            channels_running=1,
            channels_stopped=0,
            outbox_by_status={},
        ),
        db=DbInfo(
            path="db",
            size_bytes=1,
            disk_free_bytes=100 * 1024**3,
            journal_mode="wal",
            messages=0,
            events=0,
            audit=0,
        ),
        log_forwarder=forwarder,
    )


def _page(forwarder: LogForwarderInfo | None) -> str:
    posture = SecurityPosture(
        backend="sqlite",
        encryption_enabled=True,
        key_source="auto",
        key_id="abc123",
        require_encryption=True,
        allow_unencrypted_phi=False,
        kex_groups="inherited (test read-out)",
    )
    cluster = ClusterStatus(
        node_id="n1", clustered=False, is_leader=True, role="single-node", config_version=0
    )
    nodes = ClusterNodeList(nodes=[], leader_node_id="n1", lease_owner=None, lease_expires_at=None)
    dr = DrStatus(enabled=False, active=False, threshold="P1", activation_mode="manual")
    svc = ServiceStatusInfo(enabled=True, state="running", service_name="MEFOR_Engine")
    return str(status(_sys(forwarder), posture, cluster, nodes, dr, svc))


@pytest.mark.parametrize(
    ("forwarder", "reason"),
    [
        (None, None),
        (HEALTHY, None),
        (NOT_INSTALLED, "off-box log forwarding is not running (permanent failure at start)"),
        (DROPPING, "off-box log forwarding is degraded: 7 record(s) lost since start"),
        (
            HELD,
            "off-box log forwarding is degraded: the collector is not answering; "
            "2 spool read(s) failed",
        ),
    ],
)
def test_the_reason_sentence(forwarder: LogForwarderInfo | None, reason: str | None) -> None:
    assert _log_forwarder_reason(forwarder) == reason


@pytest.mark.parametrize("forwarder", [NOT_INSTALLED, DROPPING, HELD])
def test_an_absent_or_degraded_forwarder_turns_the_heart_to_warn(
    forwarder: LogForwarderInfo,
) -> None:
    assert _derive_health(_sys(forwarder), None, None, None) == (
        "warn",
        _log_forwarder_reason(forwarder),
    )


@pytest.mark.parametrize("forwarder", [None, HEALTHY])
def test_no_forwarder_and_a_healthy_one_leave_the_heart_ok(
    forwarder: LogForwarderInfo | None,
) -> None:
    assert _derive_health(_sys(forwarder), None, None, None) == ("ok", None)


def test_the_status_page_row() -> None:
    assert "Off-box log forwarding" not in _page(None)  # not configured: no row
    healthy = _page(HEALTHY)
    assert "Off-box log forwarding" in healthy and "status-failed" not in healthy
    failed = _page(NOT_INSTALLED)
    assert "off-box log forwarding is not running (permanent failure at start)" in failed
    assert "status-failed" in failed
