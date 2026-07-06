# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-outbound MLLP encoding-character override (Tier 2.5, Corepoint ``-override`` parity).

The override makes an MLLP destination re-encode the outgoing message with a different set of HL7
delimiters (MSH-1 + the four MSH-2 chars) and re-serialize the whole body before framing. These tests
exercise: the pure re-encode helper, override validation, the connector applying it before framing
(over a real loopback socket), full backward compatibility when unset, and a non-HL7 payload failing
loud. SYNTHETIC HL7 only — no real PHI.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP
from messagefoundry.parsing.message import Message
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.mllp import (
    MLLPDestination,
    MLLPSource,
    build_ack,
    parse_encoding_characters,
    reencode_delimiters,
)

# A synthetic ADT with components (MSH-9, PID-3, PID-5), a repeating field (PID-3) and accented names,
# authored with the HL7-default delimiters.
ADT_DEFAULT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECEIVINGAPP|RECEIVINGFAC|20260604120000||ADT^A01|MSG00001|P|2.5.1\r"
    "EVN|A01|20260604120000\r"
    "PID|1||100001^^^HOSP^MR~200002^^^CLINIC^MR||DOE^JANE^Q||19700101|F\r"
    "NTE|1||field-escape \\F\\ and unit \\T\\ markers\r"
    "ZNM|1||Österreich^José^Müller\r"
)

# The HL7 default delimiters expressed as an override string (MSH-1 + MSH-2).
DEFAULT_OVERRIDE = "|^~\\&"
# A fully non-default target set: field=#, component=@, repetition=*, escape=!, subcomponent=%.
ALT_OVERRIDE = "#@*!%"


def _logical_fields(msg: Message) -> dict[str, object]:
    """A snapshot of logical field values, independent of the delimiters they were encoded with."""
    return {
        "msg_type": (msg.message_code, msg.trigger_event),
        "control_id": msg.control_id,
        "sending_app": msg.field("MSH-3"),
        "pid3_reps": msg.repetitions("PID-3.1"),
        "pid3_4_first": msg.field("PID-3.4"),
        "pid5": (msg.field("PID-5.1"), msg.field("PID-5.2"), msg.field("PID-5.3")),
        "znm3": (msg.field("ZNM-3.1"), msg.field("ZNM-3.2"), msg.field("ZNM-3.3")),
    }


# --- validation --------------------------------------------------------------


def test_parse_encoding_characters_splits_in_msh_order() -> None:
    assert parse_encoding_characters(ALT_OVERRIDE) == ("#", "@", "*", "!", "%")
    assert parse_encoding_characters(DEFAULT_OVERRIDE) == ("|", "^", "~", "\\", "&")


@pytest.mark.parametrize("bad", ["", "|^~", "|^~\\&X", "abcdef"])
def test_parse_encoding_characters_rejects_wrong_length(bad: str) -> None:
    with pytest.raises(ValueError, match="exactly 5 characters"):
        parse_encoding_characters(bad)


def test_parse_encoding_characters_rejects_duplicate_delimiter() -> None:
    # Reusing one character for two roles (here '|' as both field and repetition) is ambiguous.
    with pytest.raises(ValueError, match="reuses a delimiter"):
        parse_encoding_characters("|^|\\&")


# --- pure re-encode ----------------------------------------------------------


def test_reencode_to_alt_delimiters_preserves_logical_fields() -> None:
    out = reencode_delimiters(ADT_DEFAULT, parse_encoding_characters(ALT_OVERRIDE))
    # The header advertises the new delimiters and the body uses them, not the originals.
    assert out.startswith("MSH#@*!%#")
    assert "|" not in out  # the old field separator is gone everywhere
    assert "^" not in out  # the old component separator too
    # A downstream re-parse sees the SAME logical fields under the new delimiters.
    reparsed = Message.parse(out)
    assert reparsed.field("MSH-1") == "#"
    assert reparsed.field("MSH-2") == "@*!%"
    assert _logical_fields(reparsed) == _logical_fields(Message.parse(ADT_DEFAULT))


def test_reencode_preserves_non_ascii_names() -> None:
    # python-hl7's unescape/escape corrupt code points above U+007F; the override must not, or it would
    # silently mangle accented/CJK patient names (PHI). The accented ZNM-3 names must survive verbatim.
    out = reencode_delimiters(ADT_DEFAULT, parse_encoding_characters(ALT_OVERRIDE))
    assert "Österreich" in out
    assert "José" in out
    assert "Müller" in out


def test_reencode_translates_escape_character_but_not_named_escapes() -> None:
    # \F\ / \T\ are delimiter-agnostic named escapes — only the surrounding escape char changes.
    out = reencode_delimiters(ADT_DEFAULT, parse_encoding_characters(ALT_OVERRIDE))
    assert "!F!" in out and "!T!" in out  # escape char rewritten \ -> !
    assert "\\F\\" not in out  # no stale old-escape sequence left behind


def test_reencode_handles_source_already_non_default() -> None:
    # Source uses the ALT delimiters; re-encode it back to the HL7 default and confirm fields survive.
    alt = reencode_delimiters(ADT_DEFAULT, parse_encoding_characters(ALT_OVERRIDE))
    back = reencode_delimiters(alt, parse_encoding_characters(DEFAULT_OVERRIDE))
    reparsed = Message.parse(back)
    assert reparsed.field("MSH-1") == "|"
    assert reparsed.field("MSH-2") == "^~\\&"
    assert _logical_fields(reparsed) == _logical_fields(Message.parse(ADT_DEFAULT))


def test_reencode_to_same_delimiters_is_byte_identical() -> None:
    # Overriding to the delimiters the message already uses is a logical no-op: the bytes must match a
    # plain parse/re-encode round-trip exactly (the connector's default no-override path is untouched).
    out = reencode_delimiters(ADT_DEFAULT, parse_encoding_characters(DEFAULT_OVERRIDE))
    assert out == Message.parse(ADT_DEFAULT).encode()


@pytest.mark.parametrize("garbage", ["not hl7 at all", "", "PID|1|2", "MSH|"])
def test_reencode_rejects_unparseable_payload(garbage: str) -> None:
    with pytest.raises(ValueError, match="not parseable HL7"):
        reencode_delimiters(garbage, parse_encoding_characters(ALT_OVERRIDE))


# --- MLLP() factory ----------------------------------------------------------


def test_mllp_factory_defaults_encoding_characters_to_none() -> None:
    # Backward compatible: an unset override means today's behavior.
    assert MLLP(host="h", port=1).settings["encoding_characters"] is None


def test_mllp_factory_carries_encoding_characters() -> None:
    assert (
        MLLP(host="h", port=1, encoding_characters=ALT_OVERRIDE).settings["encoding_characters"]
        == ALT_OVERRIDE
    )


# --- connector __init__ ------------------------------------------------------


def test_destination_without_override_does_not_parse() -> None:
    dest = MLLPDestination(
        Destination(name="out", type=ConnectorType.MLLP, settings={"host": "h", "port": 1})
    )
    assert dest.encoding_characters is None


def test_destination_validates_override_at_build() -> None:
    with pytest.raises(ValueError, match="exactly 5 characters"):
        MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={"host": "h", "port": 1, "encoding_characters": "bad"},
            )
        )


# --- connector send() over a real loopback socket ----------------------------


async def _receive_one(payload: str, settings: dict[str, object]) -> bytes:
    """Stand up an MLLP source on a loopback port, deliver ``payload`` through a destination built with
    ``settings`` (host/port filled in), and return the bytes the receiver actually saw on the wire."""
    received: list[bytes] = []

    async def handler(raw: bytes) -> str:
        received.append(raw)
        return build_ack(raw, code="AA")

    source = MLLPSource(Source(type=ConnectorType.MLLP, settings={"host": "127.0.0.1", "port": 0}))
    await source.start(handler)
    dest: MLLPDestination | None = None
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": source.sockport,
                    "timeout_seconds": 5,
                    **settings,
                },
            )
        )
        await dest.send(payload)
    finally:
        if dest is not None:
            await dest.aclose()  # a persistent destination caches its socket — close it here
        await source.stop()
    assert len(received) == 1
    return received[0]


# The on-the-wire sends run in both connection modes (ADR 0067 AC-12): the override is applied in
# send() before framing, so it must be byte-identical whether the connection is reused or per-send.
@pytest.mark.parametrize("persistent", [True, False])
async def test_send_without_override_is_byte_identical(persistent: bool) -> None:
    # No override -> the receiver sees the exact original bytes (the regression guard for back-compat).
    seen = await _receive_one(ADT_DEFAULT, {"persistent": persistent})
    assert seen == ADT_DEFAULT.encode("utf-8")


@pytest.mark.parametrize("persistent", [True, False])
async def test_send_with_override_reencodes_on_the_wire(persistent: bool) -> None:
    seen = await _receive_one(
        ADT_DEFAULT, {"encoding_characters": ALT_OVERRIDE, "persistent": persistent}
    )
    # The downstream peer receives the message re-encoded with the override delimiters...
    assert seen.startswith(b"MSH#@*!%#")
    # ...and a re-parse yields the same logical fields as the original.
    reparsed = Message.parse(seen.decode("utf-8"))
    assert reparsed.field("MSH-2") == "@*!%"
    assert _logical_fields(reparsed) == _logical_fields(Message.parse(ADT_DEFAULT))


async def test_send_with_override_fails_loud_on_non_hl7() -> None:
    with pytest.raises(DeliveryError, match="encoding-character override failed"):
        await _receive_one("this is not an HL7 message", {"encoding_characters": ALT_OVERRIDE})


async def test_send_non_hl7_raises_before_any_io() -> None:
    # The override re-encode happens BEFORE connecting, so a bad payload fails with the override error
    # without touching a socket. host/port point at a closed port: if the re-encode ran after connect
    # we'd instead get a *connect* DeliveryError, so matching the override message proves the ordering.
    dest = MLLPDestination(
        Destination(
            name="out",
            type=ConnectorType.MLLP,
            settings={
                "host": "127.0.0.1",
                "port": 1,
                "timeout_seconds": 1,
                "encoding_characters": ALT_OVERRIDE,
            },
        )
    )
    with pytest.raises(DeliveryError, match="encoding-character override failed"):
        await dest.send("garbage payload")
