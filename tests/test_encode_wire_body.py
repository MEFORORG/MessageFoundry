# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.redaction import safe_exc
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import NegativeAckError, encode_wire_body

#: A payload whose non-ASCII characters are the thing that must never be echoed. Distinctive enough
#: that a substring scan cannot miss it, and each is un-encodable in ASCII/latin-1 respectively.
SECRET_CHAR = "é"  # é — un-encodable as ASCII
CJK_CHAR = "病"  # 病 — un-encodable as ASCII *and* latin-1
PAYLOAD = f"MSH|^~\\&|SENDER|FAC|RECV|FAC|20260714||ADT^A01|1|P|2.5\rPID|1||42||Zaf{SECRET_CHAR}r^{CJK_CHAR}\r"


def _escapes(ch: str) -> list[str]:
    """Every rendering of ``ch`` that could betray it in an error string.

    Asserting only ``ch not in text`` is NOT enough, and getting this wrong would have made this whole
    test file worthless: ``str(UnicodeEncodeError)`` does not print the literal character, it prints
    the **escaped codepoint** — ``'ascii' codec can't encode character '\\xe9' in position 69``. A test
    that scanned for a literal ``é`` would therefore have passed against the very bug it was written
    to catch. ``\\xe9`` identifies the character exactly; it is a disclosure, not a redaction."""
    return [
        ch,
        ch.encode("unicode_escape").decode("ascii"),  # '\xe9' / '病'
        f"{ord(ch):x}",  # 'e9' / '75c5'
        repr(ch),
    ]


def _assert_content_free(exc: BaseException, *, encoding: str) -> None:
    """The raised error, and everything the engine derives from it, is free of message content —
    in EVERY representation of the offending character, not just the literal one."""
    rendered = f"{exc} | {exc!r} | {safe_exc(exc)}"
    for ch in (SECRET_CHAR, CJK_CHAR):
        for form in _escapes(ch):
            assert form not in rendered, (
                f"the offending character leaked into the error as {form!r} — "
                "str(UnicodeEncodeError) escapes it rather than printing it, so this is the "
                "representation that actually leaks"
            )
    assert "Zaf" not in rendered and "MSH" not in rendered, "payload content leaked into the error"
    assert encoding in rendered, "the error should name the codec (it is actionable and safe)"
    # `from None` is load-bearing: the chained UnicodeEncodeError's `.object` IS the *entire* payload,
    # so any handler walking `__cause__` would resurrect exactly what we refused to log.
    assert exc.__cause__ is None, "the UnicodeEncodeError must not be chained (use `from None`)"
    assert exc.__context__ is None or exc.__suppress_context__


def test_encode_wire_body_is_content_free_and_permanent() -> None:
    with pytest.raises(NegativeAckError) as ei:
        encode_wire_body(PAYLOAD, "ascii", transport="SOAP")
    exc = ei.value
    _assert_content_free(exc, encoding="ascii")
    assert exc.permanent is True, "an un-encodable body will never encode on a retry"
    assert exc.code == "encoding"
    assert "SOAP" in str(exc)
    # The POSITION is safe and useful — it is an index, not content.
    assert "position" in str(exc)


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
    _assert_content_free(ei.value, encoding="latin-1")


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
    dest = build_destination(Destination(name="OB", type=conn_type, settings=settings))
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PAYLOAD)
    _assert_content_free(ei.value, encoding="ascii")
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
        )
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(body)
    _assert_content_free(ei.value, encoding="ascii")
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
            )
        )
        with pytest.raises(NegativeAckError) as ei:
            await dest.send(PAYLOAD)
        _assert_content_free(ei.value, encoding="ascii")
        assert ei.value.permanent is True
    finally:
        server.close()
        await server.wait_closed()


async def test_file_destination_send_fails_content_free_and_writes_nothing(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The File destination encoded *before* its try/finally, so the same leak applied — and a partial
    file must not be left behind either."""
    dest = build_destination(
        Destination(
            name="OB",
            type=ConnectorType.FILE,
            settings={"directory": str(tmp_path), "encoding": "ascii"},
        )
    )
    with pytest.raises(NegativeAckError) as ei:
        await dest.send(PAYLOAD)
    _assert_content_free(ei.value, encoding="ascii")
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
        )
    )
    with pytest.raises(Exception) as ei:  # noqa: B017 - the point is what it is NOT
        await dest.send(PAYLOAD)  # utf-8 encodes it fine
    assert not isinstance(ei.value, NegativeAckError), (
        "an encodable payload must not be dead-lettered by the encode guard"
    )
