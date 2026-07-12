# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-outbound opt-in to emit reserved HL7 separators as RAW bytes (BACKLOG #107).

The deliberate escape-hatch for a partner that cannot decode HL7 escapes: when enabled on an MLLP
outbound, the four reserved STRUCTURAL separators are emitted as raw bytes (``\\F\\ \\S\\ \\R\\ \\T\\``
→ the message's own field/component/repetition/subcomponent char) instead of their escape sequences.
These tests exercise the pure parsing codec (``unescape_separators`` / ``encode_raw_separators`` /
``emit_raw_separators``), MSH-derived (non-default) separators, the escaped-escape protection, full
byte-identical backward compatibility when disabled, the config plumbing (models / MLLP factory /
_dest_config), and the connector applying it on a real loopback socket. SYNTHETIC HL7 only — no PHI.
"""

from __future__ import annotations

import hl7
import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import MLLP
from messagefoundry.parsing._builtin_hl7 import (
    encode_raw_separators,
    parse,
    unescape_separators,
)
from messagefoundry.parsing.message import Message, emit_raw_separators
from messagefoundry.transports.base import DeliveryError
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource, build_ack

# HL7-default separators: field=|, component=^, repetition=~, subcomponent=&, escape=\.
DEFAULT_SEPS = ("|", "^", "~", "&", "\\")

# A synthetic ADT whose leaves carry every structural escape: \S\ (component), \F\ (field), \R\
# (repetition), \T\ (subcomponent) — plus accented names and a NON-structural escape (\.br\, \X41\)
# that must be left untouched.
ADT_ESCAPED = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECEIVINGAPP|RECEIVINGFAC|20260604120000||ADT^A01|MSG00001|P|2.5.1\r"
    "EVN|A01|20260604120000\r"
    "PID|1||100001^^^HOSP^MR~200002^^^CLINIC^MR||O\\S\\BRIEN^JOSE\\S\\LUIS||19700101|F\r"
    "NTE|1||field \\F\\ sub \\T\\ rep \\R\\ done\r"
    "NTE|2||keep \\.br\\ and \\X41\\ untouched\r"
    "ZNM|1||Österreich^José^Müller\r"
)

# A plain ADT with NO structural escapes anywhere — the byte-identical regression baseline.
ADT_PLAIN = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECEIVINGAPP|RECEIVINGFAC|20260604120000||ADT^A01|MSG00001|P|2.5.1\r"
    "EVN|A01|20260604120000\r"
    "PID|1||100001^^^HOSP^MR||DOE^JANE^Q||19700101|F\r"
)


# --- unescape_separators (the leaf codec) ------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("O\\S\\BRIEN", "O^BRIEN"),  # \S\ -> component sep
        ("a\\F\\b", "a|b"),  # \F\ -> field sep
        ("a\\R\\b", "a~b"),  # \R\ -> repetition sep
        ("a\\T\\b", "a&b"),  # \T\ -> subcomponent sep
        ("plain text", "plain text"),  # no escape at all -> unchanged
        ("A^B~C", "A^B~C"),  # already-raw separators pass straight through
    ],
)
def test_unescape_separators_maps_only_structural(value: str, expected: str) -> None:
    assert unescape_separators(value, DEFAULT_SEPS) == expected


def test_unescape_separators_leaves_non_structural_escapes_verbatim() -> None:
    # \E\ (escaped escape), hex, and rich-text runs are NOT structural separators — pass them through
    # unchanged (unlike full unescape(), which would expand/translate them).
    assert unescape_separators("a\\E\\b", DEFAULT_SEPS) == "a\\E\\b"
    assert unescape_separators("x\\X41\\y", DEFAULT_SEPS) == "x\\X41\\y"
    assert unescape_separators("p\\.br\\q", DEFAULT_SEPS) == "p\\.br\\q"


def test_unescape_separators_protects_escaped_escape_adjacency() -> None:
    # A literal backslash datum encoded as \E\ must never let its neighbours form a false \F\. The
    # state machine consumes \E\ as one unit, so \E\F\E\ (a literal "\F\" datum) is preserved verbatim
    # — a blind str.replace of "\F\" would corrupt it into a raw field separator.
    assert unescape_separators("\\E\\F\\E\\", DEFAULT_SEPS) == "\\E\\F\\E\\"


def test_unescape_separators_unterminated_escape_is_not_dropped() -> None:
    # An unterminated trailing escape run is emitted verbatim (data preservation), never silently lost.
    assert unescape_separators("abc\\S", DEFAULT_SEPS) == "abc\\S"


def test_unescape_separators_reads_custom_separators() -> None:
    # Non-default separators (field=#, component=@, rep=*, sub=%, escape=!) come from the caller, never
    # hardcoded: !S! must map to the component char @, not the default ^.
    custom = ("#", "@", "*", "%", "!")
    assert unescape_separators("O!S!BRIEN", custom) == "O@BRIEN"
    assert (
        unescape_separators("O\\S\\BRIEN", custom) == "O\\S\\BRIEN"
    )  # default esc is not '!' here


# --- encode_raw_separators / emit_raw_separators -----------------------------


def test_emit_raw_separators_converts_structural_escapes() -> None:
    out = emit_raw_separators(ADT_ESCAPED)
    pid = next(line for line in out.split("\r") if line.startswith("PID"))
    # \S\ inside the leaves is now a raw component separator; deliberately non-conformant.
    assert "O^BRIEN^JOSE^LUIS" in pid
    assert "\\S\\" not in pid  # no structural escape survives


def test_emit_raw_separators_maps_all_four_structural() -> None:
    out = emit_raw_separators(ADT_ESCAPED)
    nte1 = next(line for line in out.split("\r") if line.startswith("NTE|1"))
    # \F\->| \T\->& \R\->~ all raw-ized on the one NTE-3 leaf.
    assert nte1 == "NTE|1||field | sub & rep ~ done"


def test_emit_raw_separators_leaves_non_structural_escapes() -> None:
    out = emit_raw_separators(ADT_ESCAPED)
    nte2 = next(line for line in out.split("\r") if line.startswith("NTE|2"))
    assert "\\.br\\" in nte2 and "\\X41\\" in nte2  # rich-text / hex not expanded


def test_emit_raw_separators_keeps_msh_header_intact() -> None:
    # MSH-1/MSH-2 (which literally carries the escape char) must NOT be run through the codec.
    out = emit_raw_separators(ADT_ESCAPED)
    assert out.split("\r")[0].startswith("MSH|^~\\&|")


def test_emit_raw_separators_preserves_non_ascii() -> None:
    out = emit_raw_separators(ADT_ESCAPED)
    assert "Österreich" in out and "José" in out and "Müller" in out


def test_emit_raw_separators_byte_identical_when_no_structural_escapes() -> None:
    # The whole point of default-off: a message with no structural escapes round-trips byte-for-byte
    # identical to a normal encode (the regression guard).
    assert emit_raw_separators(ADT_PLAIN) == Message.parse(ADT_PLAIN).encode()


def test_encode_raw_separators_honours_msh_derived_separators() -> None:
    # A message that DECLARES non-default separators in MSH-2 (component=@, sub=%, escape=!): the codec
    # reads them from MSH and maps !S! to @, never to the HL7-default ^.
    raw = "MSH|@~!%|A|B|C|D|20200101||ADT^A01|1|P|2.5\rPID|1||O!S!Brien\r"
    out = encode_raw_separators(parse(raw))
    pid = next(line for line in out.split("\r") if line.startswith("PID"))
    assert pid == "PID|1||O@Brien"


def test_message_encode_raw_separators_method() -> None:
    m = Message.parse(ADT_ESCAPED)
    assert m.encode_raw_separators() == emit_raw_separators(ADT_ESCAPED)
    # The escaping (normal) encode is unaffected — the two paths diverge only on structural escapes.
    assert "\\S\\" in m.encode()


@pytest.mark.parametrize("garbage", ["not hl7 at all", "", "PID|1|2"])
def test_emit_raw_separators_rejects_unparseable_payload(garbage: str) -> None:
    with pytest.raises(hl7.HL7Exception):
        emit_raw_separators(garbage)


# --- config plumbing ---------------------------------------------------------


def test_mllp_factory_defaults_raw_separators_off() -> None:
    assert MLLP(host="h", port=1).settings["hl7_raw_separators"] is False


def test_mllp_factory_carries_raw_separators() -> None:
    assert MLLP(host="h", port=1, hl7_raw_separators=True).settings["hl7_raw_separators"] is True


def test_destination_model_defaults_raw_separators_off() -> None:
    dest = Destination(name="out", type=ConnectorType.MLLP)
    assert dest.hl7_raw_separators is False


def test_dest_config_surfaces_raw_separators_from_settings() -> None:
    # _dest_config assembles the typed field from the outbound's setting (like sign_* → sign).
    from messagefoundry.config.wiring import build_outbound_connection
    from messagefoundry.pipeline.wiring_runner import _dest_config

    oc = build_outbound_connection(
        "OB_TEST", MLLP(host="h", port=1, hl7_raw_separators=True), source_file="t", source_line=1
    )
    assert _dest_config(oc, {}).hl7_raw_separators is True

    oc_off = build_outbound_connection(
        "OB_TEST2", MLLP(host="h", port=1), source_file="t", source_line=1
    )
    assert _dest_config(oc_off, {}).hl7_raw_separators is False


# --- connector __init__ ------------------------------------------------------


def test_destination_reads_raw_separators_flag() -> None:
    on = MLLPDestination(
        Destination(name="o", type=ConnectorType.MLLP, settings={"host": "h", "port": 1})
    )
    assert on.hl7_raw_separators is False
    dest = MLLPDestination(
        Destination(
            name="o",
            type=ConnectorType.MLLP,
            settings={"host": "h", "port": 1},
            hl7_raw_separators=True,
        )
    )
    assert dest.hl7_raw_separators is True


# --- connector send() over a real loopback socket ----------------------------


async def _receive_one(
    payload: str, dest_kwargs: dict[str, object], *, persistent: bool = False
) -> bytes:
    """Deliver ``payload`` through a loopback MLLP destination built with ``dest_kwargs`` (top-level
    Destination fields) and return the exact bytes the receiver saw on the wire."""
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
                    "persistent": persistent,
                },
                **dest_kwargs,
            )
        )
        await dest.send(payload)
    finally:
        if dest is not None:
            await dest.aclose()
        await source.stop()
    assert len(received) == 1
    return received[0]


@pytest.mark.parametrize("persistent", [True, False])
async def test_send_without_flag_is_byte_identical(persistent: bool) -> None:
    # Default off -> the receiver sees the exact original bytes, escapes intact (back-compat guard).
    seen = await _receive_one(ADT_ESCAPED, {}, persistent=persistent)
    assert seen == ADT_ESCAPED.encode("utf-8")


@pytest.mark.parametrize("persistent", [True, False])
async def test_send_with_flag_emits_raw_separators_on_the_wire(persistent: bool) -> None:
    seen = await _receive_one(ADT_ESCAPED, {"hl7_raw_separators": True}, persistent=persistent)
    text = seen.decode("utf-8")
    pid = next(line for line in text.split("\r") if line.startswith("PID"))
    assert "O^BRIEN^JOSE^LUIS" in pid  # \S\ shipped as raw ^
    assert "\\S\\" not in pid
    assert text.split("\r")[0].startswith("MSH|^~\\&|")  # header intact


async def test_send_with_flag_fails_loud_on_non_hl7() -> None:
    with pytest.raises(DeliveryError, match="hl7_raw_separators emit failed"):
        await _receive_one("this is not an HL7 message", {"hl7_raw_separators": True})
