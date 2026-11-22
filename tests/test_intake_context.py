# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: a stored message names the peer that sent it (vault BACKLOG #2607).

Before this, ``InboundHandler`` took the body and nothing else, so a stored message carried no
address, port or certificate subject.
"""

from __future__ import annotations

from messagefoundry.transports.intake import (
    IntakeAuth,
    IntakeContext,
    deliver,
    intake_handler,
    peer_address,
)

# --- the seam ---------------------------------------------------------------------------------


async def test_deliver_hands_the_context_only_to_a_handler_that_takes_one() -> None:
    seen: list[tuple[bytes, IntakeContext | None]] = []
    ctx = IntakeContext(transport="mllp", peer_host="192.0.2.7", peer_port=40001)

    async def plain(raw: bytes) -> str | None:
        seen.append((raw, None))
        return "plain"

    @intake_handler
    async def aware(raw: bytes, intake: IntakeContext | None = None) -> str | None:
        seen.append((raw, intake))
        return "aware"

    assert await deliver(plain, b"a", ctx) == "plain"
    assert await deliver(aware, b"b", ctx) == "aware"
    assert await deliver(aware, b"c", None) == "aware"
    assert seen == [(b"a", None), (b"b", ctx), (b"c", None)]


def test_the_context_fields_leave_out_what_the_source_could_not_say() -> None:
    ctx = IntakeContext(
        transport="mllp",
        peer_host="192.0.2.7",
        peer_port=40001,
        auth_mode=IntakeAuth.MTLS,
    )
    assert ctx.fields() == {
        "transport": "mllp",
        "peer_host": "192.0.2.7",
        "peer_port": 40001,
        "auth_mode": "mtls",
    }
    assert peer_address(("::1", 2575, 0, 0)) == ("::1", 2575)
    assert peer_address("/tmp/sock") == (None, None)
