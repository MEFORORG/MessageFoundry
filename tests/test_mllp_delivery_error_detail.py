# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""DeliveryError must carry the OS-level cause (WS-C claim-storm campaign, 2026-07-02): ~18.6k
dead-letters recorded ``last_error`` ending at "failed:" because ``str(exc)`` was empty for the
underlying exception — the actual cause (ephemeral-port exhaustion, WinError 10055-class) was
invisible in every dead-letter row. The describe helper names the exception type and appends
errno/winerror/strerror when they aren't already in the text, so a dead-letter's message is
diagnosable on its own."""

from __future__ import annotations

import asyncio
import socket

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.mllp import MLLPDestination

_describe = MLLPDestination._describe_error


def test_bare_timeout_yields_the_type_name() -> None:
    # str(asyncio.TimeoutError()) == "" — exactly the empty-message case from the bench.
    assert _describe(asyncio.TimeoutError()) == "TimeoutError"


def test_oserror_text_is_kept_without_duplicating_errno() -> None:
    exc = OSError(98, "address already in use")
    out = _describe(exc)
    assert out.startswith("OSError")
    assert "address already in use" in out
    # str(OSError(98, ...)) already renders "[Errno 98] ..." — the helper must not repeat it.
    assert out.count("98") == 1


def test_winerror_only_oserror_is_not_blank() -> None:
    # A proactor-style OSError carrying only winerror (str(exc) == "") — the WinError-10055 shape.
    exc = OSError()
    exc.winerror = 10055  # type: ignore[attr-defined]
    out = _describe(exc)
    assert "OSError" in out and "winerror=10055" in out


def test_connect_failure_message_carries_the_cause() -> None:
    # A real refused connect: the DeliveryError must say MORE than "failed:" — the type and/or
    # errno of the underlying cause must be present.
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listening on this port now

    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": port, "connect_timeout": 2.0},
        )
    )
    with pytest.raises(DeliveryError) as ei:
        asyncio.run(dest.send("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X1|P|2.5.1\r"))
    msg = str(ei.value)
    assert f"MLLP connect to 127.0.0.1:{port} failed: " in msg
    tail = msg.split("failed: ", 1)[1]
    assert tail.strip(), f"cause missing after 'failed:': {msg!r}"
    assert "Error" in tail or "errno" in tail or "refused" in tail.lower()
