# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness A5 probe reads a held port as the verifier's ``host.ports`` row does (BACKLOG #5389).

The harness kept its own copy of the old probe, which bound 127.0.0.1 with ``SO_REUSEADDR``: on
Windows it read a wildcard or a non-exclusive listener as free."""

from __future__ import annotations

import socket
import sys

import pytest

from harness.acceptance import probes
from harness.acceptance.matrix import Status


def _evidence_for(monkeypatch: pytest.MonkeyPatch, port: int) -> str:
    monkeypatch.setattr(probes, "_DEFAULT_PORTS", {"P": port})
    result = probes.probe_firewall_ports()
    assert result.status is Status.MANUAL
    return result.evidence.removeprefix(f"P {port}: ")


def test_a5_reads_a_wildcard_listener_as_in_use(monkeypatch: pytest.MonkeyPatch) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("0.0.0.0", 0))  # nosec B104 -- bound and never listened on
        if sys.platform.startswith("linux"):
            held.listen()
        assert _evidence_for(monkeypatch, held.getsockname()[1]) == "in use/bound"


@pytest.mark.skipif(sys.platform != "win32", reason="SO_REUSEADDR port sharing is Windows-only")
def test_a5_reads_a_non_exclusive_windows_listener_as_in_use(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        held.bind(("127.0.0.1", 0))
        held.listen()
        assert _evidence_for(monkeypatch, held.getsockname()[1]) == "in use/bound"


def test_a5_reads_a_released_port_as_free(monkeypatch: pytest.MonkeyPatch) -> None:
    # Positive control: a probe that reads every port as in use would pass the tests above.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as held:
        held.bind(("127.0.0.1", 0))
        port = held.getsockname()[1]
    assert _evidence_for(monkeypatch, port) == "free"
