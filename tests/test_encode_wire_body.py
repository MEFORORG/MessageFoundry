# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The outbound wire-encode fails CONTENT-FREE.

A bare ``payload.encode(self.encoding)`` raises ``UnicodeEncodeError`` — a ``ValueError``, so a
connector's ``except (TimeoutError, OSError)`` misses it (and in SOAP/REST/FHIR/File the encode sat
*outside* the ``try`` entirely). It escaped ``send()`` into the delivery worker's generic handler,
which persists ``internal error: {safe_exc(exc)}`` into ``queue.last_error`` **and**
``message_events.detail`` — plaintext on a default (``IdentityCipher``) store. And
``str(UnicodeEncodeError)`` **names the offending character**, which is a character of the message:
PHI, or a credential once a config secret can reach the body.

These tests assert the character never reaches an operator-visible or at-rest surface, and that the
failure is **permanent** (the same bytes will never encode on a retry, so it must dead-letter rather
than loop the lane)."""

from __future__ import annotations

import asyncio
import traceback

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import NegativeAckError, encode_wire_body
from tests._content_free import (
    CJK_CHAR,
    PAYLOAD,
    SECRET_CHAR,
    assert_content_free,
    escapes,
    walk_chain,
)


def test_encode_wire_body_is_content_free_and_permanent() -> None:
    with pytest.raises(NegativeAckError) as ei:
        encode_wire_body(PAYLOAD, "ascii", transport="SOAP")
    exc = ei.value
    assert_content_free(exc, encoding="ascii")
    assert exc.permanent is True, "an un-encodable body will never encode on a retry"
    assert exc.code == "encoding"
    assert "SOAP" in str(exc)
    # The POSITION is safe and useful — it is an index, not content.
    assert "position" in str(exc)


def test_encode_wire_body_leaves_no_payload_on_the_context_chain() -> None:
    """The residual `from None` does NOT close: ``__context__`` keeps the whole body.

    Measured against the pre-fix code: ``__cause__`` was ``None`` and ``__suppress_context__`` was
    ``True`` (so the assertions above passed), yet ``exc.__context__.object`` was byte-identical to
    ``PAYLOAD``. Formatting the chain the way a non-default handler does then rendered the message —
    PHI, or a credential once a config secret can reach the body."""
    with pytest.raises(NegativeAckError) as ei:
        encode_wire_body(PAYLOAD, "ascii", transport="SOAP")
    exc = ei.value

    # The direct reach: one attribute access, no formatting involved.
    assert exc.__context__ is None, (
        "the raise must happen outside the `except` block — `from None` leaves __context__ set"
    )
    assert getattr(exc.__context__, "object", None) != PAYLOAD

    # And nothing anywhere on the chain carries the body, in any representation of the characters.
    chain_text = " | ".join(f"{link!r} {getattr(link, 'object', '')!r}" for link in walk_chain(exc))
    assert "Zaf" not in chain_text and "MSH" not in chain_text
    for ch in (SECRET_CHAR, CJK_CHAR):
        for form in escapes(ch):
            assert form not in chain_text, f"the offending character is reachable as {form!r}"

    # A chain-walking formatter renders nothing of the message either. (The DEFAULT printer already
    # honoured __suppress_context__ before the fix, so asserting on it alone would prove nothing.)
    walked = "".join(
        "".join(traceback.TracebackException.from_exception(link).format())
        for link in [exc, *walk_chain(exc)]
    )
    assert "Zaf" not in walked and "\\xe9" not in walked


def test_encode_wire_body_passes_encodable_payloads_through_byte_identically() -> None:
    """The guard must be a pure pass-through when the payload encodes — no behavior change."""
    for encoding in ("utf-8", "latin-1", "ascii"):
        plain = "MSH|^~\\&|A|B\rPID|1||42\r"
        assert encode_wire_body(plain, encoding, transport="T") == plain.encode(encoding)
    assert encode_wire_body(PAYLOAD, "utf-8", transport="T") == PAYLOAD.encode("utf-8")


def test_latin1_catches_what_ascii_would_miss() -> None:
    """latin-1 encodes é but not 病 — proving the guard keys on the codec, not on 'non-ASCII'."""
    assert encode_wire_body(f"ok{SECRET_CHAR}", "latin-1", transport="T") == b"ok\xe9"
    with pytest.raises(NegativeAckError) as ei:
        encode_wire_body(f"ok{CJK_CHAR}", "latin-1", transport="T")
    assert_content_free(ei.value, encoding="latin-1")


# --- the connectors that used to leak ----------------------------------------


@pytest.mark.parametrize(
    ("conn_type", "settings"),
    [
        (ConnectorType.REST, {"url": "http://127.0.0.1:9/x", "encoding": "ascii"}),
        (ConnectorType.SOAP, {"url": "http://127.0.0.1:9/x", "encoding": "ascii"}),
    ],
)
async def test_destination_send_fails_content_free(
    conn_type: ConnectorType, settings: dict[str, object]
) -> None:
    """Drive the connector's real ``send()``. REST and SOAP encode before any socket work, so this
    needs no server: the guard must fire first, and it must fire content-free.

    Before the fix each of these raised a bare ``UnicodeEncodeError`` naming the offending character,
    which the delivery worker then wrote into ``queue.last_error`` and ``message_events.detail``."""
    dest = build_destination(
        Destination(name="OB", type=conn_type, settings=settings),
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PAYLOAD)
    assert_content_free(ei.value, encoding="ascii")
    assert ei.value.permanent is True


async def test_fhir_send_fails_content_free() -> None:
    """FHIR derives its request path by peeking the body, so it needs a real FHIR resource to reach
    the encode at all. The non-ASCII character lives in the patient's family name — i.e. it is PHI."""
    body = f'{{"resourceType":"Patient","name":[{{"family":"Zaf{SECRET_CHAR}r"}}]}}'
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FHIR,
            settings={"url": "http://127.0.0.1:9/fhir", "encoding": "ascii"},
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(body)
    assert_content_free(ei.value, encoding="ascii")
    assert "Patient" not in str(ei.value)
    assert ei.value.permanent is True


async def test_x12_send_fails_content_free() -> None:
    """X12 opens the socket BEFORE it encodes, so this needs a live listener to reach the encode —
    and that ordering is exactly why the bare ``.encode()`` there was inside a ``try`` whose
    ``except (TimeoutError, OSError)`` could never catch a ``UnicodeEncodeError``."""
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = int(server.sockets[0].getsockname()[1])
    try:
        dest = build_destination(
            Destination(
                name="OB",
                type=ConnectorType.X12,
                settings={"host": "127.0.0.1", "port": port, "encoding": "ascii"},
            ),
            egress=EgressSettings(deny_by_default=False),
        )
        with pytest.raises(NegativeAckError) as ei:
            await dest.send(PAYLOAD)
        assert_content_free(ei.value, encoding="ascii")
        assert ei.value.permanent is True
    finally:
        server.close()
        await server.wait_closed()


async def test_file_destination_send_fails_content_free_and_writes_nothing(tmp_path) -> None:
    """The File destination encoded *before* its try/finally, so the same leak applied — and a partial
    file must not be left behind either."""
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "encoding": "ascii"},
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PAYLOAD)
    assert_content_free(ei.value, encoding="ascii")
    assert list(tmp_path.iterdir()) == [], "nothing may be written when the body cannot be encoded"


async def test_encodable_payload_still_reaches_the_wire() -> None:
    """Positive control: the guard must not turn a *deliverable* message into a dead-letter. The
    payload encodes cleanly, so send() proceeds past the encode and fails on the (closed) socket with
    a transient DeliveryError — NOT the permanent NegativeAckError above."""
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.REST,
            settings={"url": "http://127.0.0.1:9/x", "encoding": "utf-8", "timeout_seconds": 1.0},
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    with pytest.raises(Exception) as ei:  # noqa: B017 - the point is what it is NOT
        await dest.send(PAYLOAD)  # utf-8 encodes it fine
    assert not isinstance(ei.value, NegativeAckError), (
        "an encodable payload must not be dead-lettered by the encode guard"
    )
