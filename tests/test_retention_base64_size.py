# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Retention sizing preserves decoder semantics without decoding normal documents."""

import base64

import pytest

from messagefoundry.parsing import binary
from messagefoundry.parsing.message import Message

_HL7 = "MSH|^~\\&|A|B|C|D|20260101||ORU^R01|1|P|2.5.1\rOBX|1|ED|||"
_AT = 1_700_000_000.0


def _message(value: str) -> Message:
    message = Message.parse(_HL7)
    message.set("OBX-5.4", "Base64")
    message.set("OBX-5.5", value.replace("\r", "").replace("\n", ""))
    return message


@pytest.mark.parametrize("carriage", ["whole", "hl7"])
@pytest.mark.parametrize("length", [0, 1, 2, 3, 1024 * 1024])
@pytest.mark.parametrize("whitespace", [False, True])
def test_retention_sizes_without_decoding(monkeypatch, length, whitespace, carriage):
    value = base64.b64encode(b"a" * length).decode()
    if whitespace:
        value = "\u2003" + " \t".join(value[i : i + 80] for i in range(0, len(value), 80))
    message = _message(value)

    def forbidden_decode(*args, **kwargs):
        raise AssertionError("retention decoded a normal document")

    monkeypatch.setattr(binary, "_b64decode", forbidden_decode)
    monkeypatch.setattr(base64, "b64decode", forbidden_decode)
    raw = binary.MARKER + value
    expected = binary.make_document_tombstone(length, "application/octet-stream", _AT)
    if carriage == "whole":
        assert binary.strip_documents(raw, pruned_at=_AT) == (expected, 1, len(raw) - len(expected))
        assert binary.strip_documents(raw, pruned_at=_AT, min_bytes=length + 1) == (raw, 0, 0)
    else:
        before = message.encode()
        assert binary.strip_documents_in_hl7(message, pruned_at=_AT, min_bytes=length + 1) == (0, 0)
        assert message.encode() == before
        assert binary.strip_documents_in_hl7(message, pruned_at=_AT)[0] == int(bool(value))
        if value:
            assert message.field("OBX-5.5") == expected
            assert message.field("OBX-5.4") is None


@pytest.mark.parametrize(
    "value",
    [
        "",
        " ",
        "Zg==",
        "Zm8=",
        "Zm9v",
        "Zh==",
        "Zm9=",
        " Z g = =\t\n",
        "\u2003Zg==\u001c",
        "Zm9v=",
        "Zm9v====",
        "Zg===",
        "Zm8==",
        "=",
        "====",
        "A",
        "AA",
        "AAA",
        "A===",
        "AA=A",
        "AA==AA==",
        "AA==!",
        "AA-_",
        "é",
        "AA\x00==",
        "AA\u200b==",
        "AAAA\u00a0AAAA",
    ],
)
def test_retention_matches_decoder_on_edge_cases(value):
    raw = binary.MARKER + value
    message = _message(value)
    try:
        size = len(binary._b64decode(value))
    except binary.BinaryCarriageError:
        assert binary.strip_documents(raw, pruned_at=_AT) == (raw, 0, 0)
        before = message.encode()
        assert binary.strip_documents_in_hl7(message, pruned_at=_AT) == (0, 0)
        assert message.encode() == before
    else:
        expected = binary.make_document_tombstone(size, "application/octet-stream", _AT)
        assert binary.strip_documents(raw, pruned_at=_AT) == (expected, 1, len(raw) - len(expected))
        assert binary.strip_documents(raw, pruned_at=_AT, min_bytes=size + 1) == (raw, 0, 0)
        assert binary.strip_documents_in_hl7(message, pruned_at=_AT)[0] == int(bool(value))
        if value:
            assert message.field("OBX-5.5") == expected
