# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[logging].forward_host`` refuses the IPv4 limited broadcast address at load (BACKLOG #5923).

The forwarder never sets ``SO_BROADCAST``, so the OS refuses each UDP send to it, and with a spool
every later record would wait behind the first. A load-time refusal names the setting instead.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import LoggingSettings


@pytest.mark.parametrize(
    "host",
    [
        "255.255.255.255",
        "255.255.255.255.",
        "[255.255.255.255]",
        # Code review round 1: the IPv4-mapped spelling reaches the same IPv4 send.
        "::ffff:255.255.255.255",
        "[::ffff:255.255.255.255]",
    ],
)
def test_the_limited_broadcast_address_is_refused(host: str) -> None:
    with pytest.raises(ValidationError) as ei:
        LoggingSettings(forward_host=host)
    text = str(ei.value)
    assert "[logging].forward_host" in text and "broadcast" in text


@pytest.mark.parametrize(
    "host", ["siem.local", "10.0.0.255", "192.0.2.10", "255.255.255.254", "::ffff:192.0.2.10"]
)
def test_a_collector_address_still_loads(host: str) -> None:
    """The negative control: a name, a host address, and an address that only looks like a
    directed subnet broadcast, which this check does not read, all load as before."""
    assert LoggingSettings(forward_host=host).forward_host == host


def test_the_broadcast_address_loads_while_forwarding_is_off() -> None:
    """Code review round 2: with forwarding off no socket opens, so a config that loaded before
    #5923 still loads."""
    settings = LoggingSettings(forward_host="255.255.255.255", forward_enabled=False)
    assert settings.forward_enabled is False
