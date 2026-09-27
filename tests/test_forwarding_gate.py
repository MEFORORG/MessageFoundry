# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The R4 (a) forwarding start-gate predicate (BACKLOG #1966, ADR 0200, ASVS 16.4.3).

The predicate passes only verified TLS to a non-loopback collector, and reads configuration alone.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import LoggingSettings, forwarding_gate_refusal


def _log(**kwargs: Any) -> LoggingSettings:
    return LoggingSettings(**kwargs)


def _verified(tmp_path: Path, host: str = "siem.example.org") -> LoggingSettings:
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder; the predicate never opens it\n")
    return _log(forward_host=host, forward_protocol="tls", forward_tls_ca_file=str(ca))


def test_verified_tls_to_a_remote_collector_passes(tmp_path: Path) -> None:
    assert forwarding_gate_refusal(_verified(tmp_path)) is None


@pytest.mark.parametrize(
    ("settings", "needle"),
    [
        ({}, "no off-box collector"),
        ({"forward_host": "siem.example.org", "forward_enabled": False}, "no off-box collector"),
        ({"forward_host": "siem.example.org"}, "'udp', not 'tls'"),
        ({"forward_host": "siem.example.org", "forward_protocol": "tcp"}, "'tcp', not 'tls'"),
        (
            {
                "forward_host": "siem.example.org",
                "forward_protocol": "tls",
                "forward_tls_verify": False,
            },
            "not authenticated",
        ),
    ],
)
def test_anything_short_of_verified_tls_is_refused(settings: dict[str, Any], needle: str) -> None:
    reason = forwarding_gate_refusal(_log(**settings))
    assert reason is not None and needle in reason


@pytest.mark.parametrize("host", ["127.0.0.1", "127.8.9.10", "localhost", "::1"])
def test_a_loopback_collector_is_refused_even_over_verified_tls(tmp_path: Path, host: str) -> None:
    reason = forwarding_gate_refusal(_verified(tmp_path, host=host))
    assert reason is not None and "loopback" in reason


def test_an_attested_plaintext_hop_does_not_pass_the_gate() -> None:
    """``forward_hop_attested`` answers a different question and must not answer this one."""
    reason = forwarding_gate_refusal(
        _log(
            forward_host="siem.example.org",
            forward_protocol="tcp",
            forward_hop_attested=True,
            forward_hop_attested_reason="an IPsec tunnel covers the hop",
        )
    )
    assert reason is not None and "not 'tls'" in reason


def test_the_gate_opens_no_connection_and_resolves_no_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keyed on configuration, so a down collector cannot block a start through it. Any socket or
    name lookup during the check fails the test."""
    settings = _verified(tmp_path)

    def _no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the forwarding gate touched the network")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    assert forwarding_gate_refusal(settings) is None
    assert forwarding_gate_refusal(_log()) is not None
