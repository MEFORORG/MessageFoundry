# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5333: the inbound peer-IP allowlist is read once, so a single-pass iterable keeps its
entries, a bare string is refused, and the listen-source rule holds for an empty allowlist too."""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.wiring import MLLP, File, WiringError, build_inbound_connection, env


def _inbound(transport: Any, allowlist: Any) -> Any:
    return build_inbound_connection("IB", transport, router="r", source_ip_allowlist=allowlist)


def test_generator_allowlist_keeps_its_entries() -> None:
    ic = _inbound(MLLP(port=2575), (entry for entry in ["127.0.0.1", "10.0.0.0/8"]))
    assert ic.source_ip_allowlist == ("127.0.0.1", "10.0.0.0/8")


def test_generator_allowlist_entries_are_still_validated() -> None:
    with pytest.raises(WiringError, match="not a valid IP address or CIDR"):
        _inbound(MLLP(port=2575), (entry for entry in ["127.0.0.1", "999.1.1.1"]))


@pytest.mark.parametrize(
    "value", ["127.0.0.1", b"127.0.0.1", 5, {"10.0.0.1": "lab"}, {"10.0.0.1"}, frozenset()]
)
def test_a_value_that_is_not_a_list_is_refused(value: object) -> None:
    with pytest.raises(WiringError, match="must be a list of IP addresses"):
        _inbound(MLLP(port=2575), value)


def test_an_env_allowlist_is_refused_by_name() -> None:
    with pytest.raises(WiringError, match="does not take an env"):
        _inbound(MLLP(port=2575), env("ips"))


@pytest.mark.parametrize("value", [[], ()])
def test_empty_allowlist_on_non_listen_source_refused(value: object, tmp_path: Any) -> None:
    with pytest.raises(WiringError, match="only valid for an"):
        _inbound(File(directory=str(tmp_path)), value)


def test_empty_allowlist_on_listen_source_is_no_restriction() -> None:
    assert _inbound(MLLP(port=2575), []).source_ip_allowlist is None
