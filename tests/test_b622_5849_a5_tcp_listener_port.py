# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness A5 probe covers every listener its matrix row names (BACKLOG #5849).

Row A5 reads "Firewall rules for listener ports (MLLP/DICOM/TCP/API)", but the probe's port map
held only MLLP, DICOM and API, so the raw-TCP listener's port was never reported. The SO_REUSEADDR
half of the finding was fixed under BACKLOG #5389; ``tests/test_b532r_verify_harness_a5.py`` holds
those tests, and the last test here repeats one against the TCP entry itself."""

from __future__ import annotations

import socket
import sys

import pytest

from harness.acceptance import probes
from harness.acceptance.matrix import MATRIX, Status
from harness.endpoints import Endpoint
from harness.endpoints import tcp as tcp_endpoints


def _a5_title() -> str:
    return next(row.title for row in MATRIX if row.id == "A5")


def test_every_listener_row_a5_names_is_in_the_probe_port_map() -> None:
    # The row title's parenthesised list is the contract; a map key per named listener.
    named = _a5_title().partition("(")[2].rstrip(")").split("/")
    assert named == ["MLLP", "DICOM", "TCP", "API"]  # control: the title parses as expected
    assert sorted(probes._DEFAULT_PORTS) == sorted(named)


def _tcp_in() -> Endpoint:
    return next(e for e in tcp_endpoints.ENDPOINTS if e.key == "tcp_in")


def _tcp_evidence() -> str:
    result = probes.probe_firewall_ports()
    assert result.status is Status.MANUAL
    return next(p for p in result.evidence.split("; ") if p.startswith("TCP "))


def test_the_tcp_port_is_the_harness_tcp_inbound_default(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_tcp_in().env, raising=False)
    assert _tcp_evidence().startswith(f"TCP {_tcp_in().default}: ")


def test_the_tcp_port_follows_the_endpoint_override(monkeypatch: pytest.MonkeyPatch) -> None:
    # Under an override IB_Harness_TCP binds the override, so that is the port A5 must report.
    monkeypatch.setenv(_tcp_in().env, "3580")
    assert _tcp_evidence().startswith("TCP 3580: ")


def test_a_malformed_tcp_override_is_reported_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_tcp_in().env, "not-a-port")
    assert _tcp_evidence().startswith("TCP not-a-port: invalid port")


def test_a5_reports_a_held_tcp_port_as_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        if sys.platform == "win32":
            # The non-exclusive listener a SO_REUSEADDR probe would have shared and read as free.
            held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind(("127.0.0.1", 0))
        held.listen()
        port = held.getsockname()[1]
        monkeypatch.setenv(_tcp_in().env, str(port))
        evidence = _tcp_evidence()
    assert evidence == f"TCP {port}: in use/bound"
