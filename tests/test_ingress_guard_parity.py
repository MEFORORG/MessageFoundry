# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The dry-run applies the ingress guards the live listener applies (BACKLOG #1689, #1690).

``messagefoundry check`` and the Test Bench are pre-deploy gates: a fixture that previews ``RECEIVED``
and would ``NAK`` on the first live message is a gate that lies, and so is one that previews ``ERROR``
for a body the engine takes. Each test below drives ONE guard and fails on the pre-#1689 code, so the
file doubles as the negative control — deleting a guard turns its own test red and nothing else.

The parity assertions at the bottom pin the shared module against the listener's own constants, which
matters because ``_handle_inbound`` still carries an inline copy of the sequence (part B of #1689
points it at the shared function; that method is held by other open work today).
"""

from __future__ import annotations

from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import RawMessage
from messagefoundry.pipeline import ingress_guards, wiring_runner
from messagefoundry.pipeline.dryrun import disposition_for, dry_run, route_message, split_messages
from messagefoundry.store import MessageStatus

#: A conformant 2.5.1 ADT^A01 whose PID-5 family name carries a byte that is latin-1 but NOT UTF-8
#: (U+00DC, "Ü"). Which of the two charsets an inbound declares is exactly what decides whether the
#: engine accepts this message, so it is the discriminating fixture for the decode guard.
ADT_UMLAUT_TEXT = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||MÜLLER^JANE\r"
)
ADT_LATIN1 = ADT_UMLAUT_TEXT.encode("latin-1")
ADT_UTF8 = ADT_UMLAUT_TEXT.encode("utf-8")


def _inbound(
    name: str = "in",
    *,
    content_type: ContentType = ContentType.HL7V2,
    encoding: str | None = None,
    max_message_bytes: int | None = None,
) -> InboundConnection:
    settings: dict[str, object] = {"host": "0.0.0.0", "port": 2575}
    if encoding is not None:
        settings["encoding"] = encoding
    return InboundConnection(
        name,
        ConnectionSpec(ConnectorType.MLLP, settings),
        router="r",
        content_type=content_type,
        validation=Validation(strict=False, hl7_version="2.5.1"),
        max_message_bytes=max_message_bytes,
    )


def _registry(
    ic: InboundConnection,
    *,
    route: Any = None,
    handle: Any = None,
    deployed: bool = True,
) -> Registry:
    """A one-inbound graph whose handler delivers by default, so any non-RECEIVED result is a guard."""
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_outbound(
        OutboundConnection(
            "out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}), deployed=deployed
        )
    )
    reg.add_router("r", route or (lambda m: ["h"]))
    reg.add_handler("h", handle or (lambda m: Send("out", m)))
    return reg


# --- guard 1: decode with the connection's declared charset, errors="strict" -------------------


def test_latin1_body_on_a_latin1_inbound_is_accepted() -> None:
    """The divergence runs BOTH ways: the engine takes this, so the gate must not refuse it.

    Pre-#1689 ``dry_run`` decoded UTF-8/``replace``, which neither refused nor accepted it honestly —
    it substituted U+FFFD for the byte and previewed a routed, transformed message carrying a
    corrupted patient name."""
    reg = _registry(_inbound(encoding="latin-1"))
    result = dry_run(reg, ADT_LATIN1)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert "MÜLLER" in result.raw  # decoded with the DECLARED charset, not mojibake
    assert "�" not in result.raw


def test_latin1_body_on_a_utf8_inbound_is_error() -> None:
    """...and the same bytes on a utf-8 inbound are an ERROR, because the engine NAKs them (AR)."""
    reg = _registry(_inbound(encoding="utf-8"))
    result = dry_run(reg, ADT_LATIN1)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and result.error.startswith("decode error (utf-8)")


def test_utf8_body_on_a_utf8_inbound_is_still_accepted() -> None:
    """The control: tightening the decode must not refuse the ordinary case."""
    result = dry_run(_registry(_inbound(encoding="utf-8")), ADT_UTF8)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert "MÜLLER" in result.raw


def test_a_str_body_skips_the_charset_guard() -> None:
    """A ``str`` has nothing left to decode, so the Test Bench and ``verify smoke`` keep working."""
    result = dry_run(_registry(_inbound(encoding="utf-8")), ADT_UMLAUT_TEXT)
    assert result.disposition is MessageStatus.RECEIVED, result.error


def test_unknown_codec_name_is_error_not_a_raise() -> None:
    """An unknown ``encoding`` must report ERROR rather than escape out of the gate as LookupError."""
    result = dry_run(_registry(_inbound(encoding="no-such-codec")), ADT_UTF8)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "no-such-codec" in result.error


# --- guard 2: reject an embedded NUL ------------------------------------------------------------


def test_nul_in_the_body_is_error_not_received() -> None:
    """INGEST-4: a NUL in PID-5 previewed RECEIVED with one delivery before #1689.

    The live listener dead-letters it BEFORE ``Peek.parse`` and NAKs AR, because a NUL is invalid in
    every text payload accepted here and store-hostile besides."""
    nul_body = ADT_UMLAUT_TEXT.replace("JANE", "JA\x00NE").encode("utf-8")
    result = dry_run(_registry(_inbound(encoding="utf-8")), nul_body)
    assert result.disposition is MessageStatus.ERROR
    assert result.error == ingress_guards.NUL_REJECTED_REASON
    assert result.deliveries == []
    # The rejected body still has to be reportable: a NUL-bearing view escalates to mfb64 carriage
    # rather than being handed to a TEXT store that would truncate or refuse it (ADR 0028).
    assert "\x00" not in result.raw


def test_nul_on_a_non_hl7_inbound_is_error_too() -> None:
    reg = _registry(_inbound(content_type=ContentType.TEXT, encoding="utf-8"))
    result = dry_run(reg, b'{"a": "b\x00c"}')
    assert result.disposition is MessageStatus.ERROR
    assert result.error == ingress_guards.NUL_REJECTED_REASON


# --- guard 3: the size ceiling is the CONNECTION's, not a bare 16 MiB ---------------------------


def test_streaming_inbound_admits_a_body_over_the_engine_default() -> None:
    """#149: a streaming inbound raises the peek ceiling to its ``max_message_bytes``.

    ``dry_run`` called ``Peek.parse(text)`` bare, so it refused at the 16 MiB default a body the
    engine would admit — the gate failing a fixture that works in production."""
    over = ingress_guards.INGRESS_MAX_BYTES + 4096
    padding = "X" * (over - len(ADT_UMLAUT_TEXT))
    body = (ADT_UMLAUT_TEXT + f"OBX|1|ST|NOTE||{padding}\r").encode("utf-8")
    assert len(body) > ingress_guards.INGRESS_MAX_BYTES

    tight = dry_run(_registry(_inbound(encoding="utf-8")), body)
    assert tight.disposition is MessageStatus.ERROR  # the engine default still applies by default
    assert tight.error is not None and "parse error" in tight.error

    streaming = _registry(_inbound(encoding="utf-8", max_message_bytes=256 * 1024 * 1024))
    assert dry_run(streaming, body).disposition is MessageStatus.RECEIVED


def test_below_default_cap_refuses_what_the_default_would_admit() -> None:
    """The same read cuts the other way: a connection capped BELOW the default must refuse sooner."""
    reg = _registry(_inbound(encoding="utf-8", max_message_bytes=len(ADT_UTF8) // 2))
    result = dry_run(reg, ADT_UTF8)
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "parse error" in result.error


def test_non_hl7_body_over_the_ceiling_is_error() -> None:
    """The non-HL7 path had NO size guard at all — the HL7 one rode in on ``Peek.parse``."""
    reg = _registry(_inbound(content_type=ContentType.TEXT, encoding="utf-8"))
    result = dry_run(reg, b"x" * (ingress_guards.INGRESS_MAX_BYTES + 1))
    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and "ingress exceeds max size" in result.error


# --- guard 4: a binary content type is CARRIED, never text-decoded ------------------------------


def test_binary_inbound_carries_bytes_instead_of_decoding_them() -> None:
    """ADR 0028: the listener never decodes a binary body; it hands on ``RawMessage.from_bytes``.

    Pre-#1689 ``_dry_run_raw`` decoded strict UTF-8 outside any ``try``, so a PDF fixture raised
    ``UnicodeDecodeError`` straight out of ``dry_run`` and a decodable one reached the Handler as text
    its codec could not read back as bytes."""
    pdf = b"%PDF-1.7\n\x00\x80\xff binary body \x00"
    seen: list[RawMessage] = []

    def route(msg: RawMessage) -> list[str]:
        seen.append(msg)
        return ["h"]

    reg = _registry(_inbound(content_type=ContentType.BINARY), route=route)
    result = dry_run(reg, pdf)

    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert len(seen) == 1
    assert seen[0].is_binary and seen[0].raw_bytes == pdf  # the exact bytes survive to the codec
    assert result.raw.startswith("mfb64:v1:")


def test_binary_inbound_does_not_double_wrap_a_carriage_string() -> None:
    """Re-running a stored raw through the preview must not wrap ``mfb64:`` inside ``mfb64:``."""
    carried = RawMessage.from_bytes(b"\x00\x01\x02", ContentType.DICOM.value).raw
    reg = _registry(_inbound(content_type=ContentType.DICOM))
    result = dry_run(reg, carried)
    assert result.disposition is MessageStatus.RECEIVED, result.error
    assert result.raw == carried


def test_decode_ingress_refuses_a_binary_inbound() -> None:
    """The split is structural, not a caller's option — asking for a text decode here is a bug."""
    with pytest.raises(ValueError, match="carry_binary_ingress"):
        ingress_guards.decode_ingress(b"abc", _inbound(content_type=ContentType.BINARY))


# --- guard 5: the fixture reader hands on BYTES, so the inbound owns the decode -----------------


def test_split_messages_returns_bytes_verbatim_for_a_single_message() -> None:
    """A non-batch payload comes back byte-identical, exactly as the File source hands one off."""
    assert split_messages(ADT_LATIN1) == [ADT_LATIN1]


def test_split_messages_splits_a_latin1_batch_without_mojibake() -> None:
    """The boundary search is a latin-1 byte view, so it is charset-agnostic and byte-faithful.

    Pre-#1689 this returned ``str`` decoded UTF-8/``replace``, so the second message's name reached
    the Router with U+FFFD in it before any inbound had declared a charset."""
    batch = ADT_LATIN1 + ADT_LATIN1.replace(b"MSG1", b"MSG2")
    parts = split_messages(batch)
    assert len(parts) == 2
    assert all(isinstance(p, bytes) for p in parts)
    assert parts[0].decode("latin-1").startswith("MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1")
    assert "MÜLLER" in parts[1].decode("latin-1")


def test_split_messages_separator_agnostic_on_bytes() -> None:
    """A batch whose MSH-1 is not ``|`` still splits per-message (low-4), now on the byte view."""
    batch = (
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01^M1^P^2.5.1\r"
        b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02^M2^P^2.5.1\r"
    )
    parts = split_messages(batch)
    assert len(parts) == 2
    assert parts[0].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A01")
    assert parts[1].startswith(b"MSH^~|\\&^A^B^C^D^20260101^^ADT~A02")


# --- BACKLOG #1690: a decline is not a filter ---------------------------------------------------


def _declining_registry() -> Registry:
    return _registry(_inbound(), deployed=False)


def test_every_send_declined_previews_not_deployed_not_filtered() -> None:
    """#233 ruled a decline must be distinguishable from an intentional filter; the gate collapsed it.

    An author reading FILTERED goes looking for the filter in their Handler. There isn't one — the
    destination is simply not deployed, which is the one thing the old preview could not say."""
    result = dry_run(_declining_registry(), ADT_UTF8)
    assert result.disposition is MessageStatus.NOT_DEPLOYED
    assert result.handlers == ["h"]
    assert result.deliveries == []
    assert result.declined == ["out"]  # named, so the author knows WHICH destination


def test_a_real_filter_still_previews_filtered() -> None:
    """The control for the branch above: nothing declined means the filter reading is the true one."""
    reg = _registry(_inbound(), handle=lambda m: None)
    result = dry_run(reg, ADT_UTF8)
    assert result.disposition is MessageStatus.FILTERED
    assert result.declined == []


def test_disposition_for_prefers_the_decline_over_the_filter() -> None:
    """A handler that both filters one Send and has another declined still has a decline to report."""
    reg = _declining_registry()
    outcome = route_message(reg, reg.inbound["in"], ADT_UMLAUT_TEXT)
    assert outcome.routed and not outcome.deliveries and outcome.declined == ["out"]
    assert disposition_for(outcome) is MessageStatus.NOT_DEPLOYED


# --- the shared module vs. the listener's inline copy -------------------------------------------


def test_shared_ceiling_matches_the_listeners() -> None:
    """``_handle_inbound`` still carries its own copy of this sequence (part B of #1689 removes it).

    Until it does, these two assertions are the whole drift detector: a change to either side that
    forgets the other turns this red rather than quietly reopening the gap #1689 closed."""
    assert ingress_guards.INGRESS_MAX_BYTES == wiring_runner._INGRESS_MAX_BYTES


def test_shared_nul_reason_matches_the_listeners_wording() -> None:
    # Pinned as a literal because the listener's copy is a local inside `_handle_inbound` and cannot
    # be imported. If either side is reworded, this fails and names the other side.
    assert (
        ingress_guards.NUL_REJECTED_REASON
        == "ingress body contains a NUL (U+0000), invalid in a text/HL7 payload"
    )


def test_peek_max_bytes_resolves_the_per_connection_cap() -> None:
    assert ingress_guards.peek_max_bytes(_inbound()) == ingress_guards.INGRESS_MAX_BYTES
    assert ingress_guards.peek_max_bytes(_inbound(max_message_bytes=99)) == 99


def test_ingress_encoding_falls_back_for_an_absent_or_null_declaration() -> None:
    assert ingress_guards.ingress_encoding(_inbound()) == "utf-8"
    assert ingress_guards.ingress_encoding(_inbound(encoding="latin-1")) == "latin-1"
