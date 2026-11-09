# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The provisioned log collector is answered in-process, never by DNS (BACKLOG #2279 item 3).

Every test that starts the forwarder under the #1966 provision names ``siem.invalid``. Before the
stub, each such start asked the machine's resolver for it: 16 live lookups across
``tests/test_alert_smtp_tls.py`` and ``tests/test_config_anchoring.py``, measured with a
``getaddrinfo`` spy loaded ahead of ``tests/conftest.py``. With the stub the same spy counts 0.
"""

from __future__ import annotations

import socket
from typing import Any

import pytest

from messagefoundry.logging_setup import (
    SyslogForward,
    _build_syslog_handler,
    is_permanent_connect_error,
)
from tests._phi_gate_provisions import VERIFIED_LOG_FORWARDING_HOST, ProvisionedCollectorResolver


def _no_network(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError(f"the real resolver was asked for {args[:1]!r}")


@pytest.mark.parametrize(
    "host",
    [VERIFIED_LOG_FORWARDING_HOST, "SIEM.Invalid.", VERIFIED_LOG_FORWARDING_HOST.encode()],
    ids=["as-provisioned", "case-and-root-dot", "bytes"],
)
def test_the_provisioned_collector_is_refused_as_no_such_name_without_a_lookup(host: Any) -> None:
    resolver = ProvisionedCollectorResolver(_no_network)
    with pytest.raises(socket.gaierror) as caught:
        resolver(host, 514, 0, socket.SOCK_STREAM)
    assert caught.value.errno == socket.EAI_NONAME
    assert is_permanent_connect_error(caught.value)


def test_every_other_host_goes_to_the_real_resolver() -> None:
    asked: list[object] = []

    def _real(host: object, *args: Any, **kwargs: Any) -> str:
        asked.append(host)
        return "answer"

    resolver = ProvisionedCollectorResolver(_real)
    for host in ("127.0.0.1", "siem.invalid.example.org", "xsiem.invalid", None):
        assert resolver(host, 514) == "answer"
    assert asked == ["127.0.0.1", "siem.invalid.example.org", "xsiem.invalid", None]


def test_the_session_stub_answers_the_forwarder_s_own_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The real forwarder build, behind the stub ``tests/conftest.py`` installs, reports the name
    as permanently missing while the real resolver behind the stub would fail the test if asked."""
    installed = socket.getaddrinfo
    assert isinstance(installed, ProvisionedCollectorResolver)
    monkeypatch.setattr(installed, "real", _no_network)
    with pytest.raises(socket.gaierror) as caught:
        _build_syslog_handler(
            SyslogForward(host=VERIFIED_LOG_FORWARDING_HOST, port=6514, protocol="tcp")
        )
    assert is_permanent_connect_error(caught.value)
