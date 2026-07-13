# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The lens emits a handler's recognized HL7 message type (ADR 0104 §2.3 P2) for the field-picker scope."""

from __future__ import annotations

from messagefoundry.lens import parse_source


def _handler(body: str) -> dict[str, object]:
    return parse_source(body, module="m")[0]


def test_accepts_types_from_decorator() -> None:
    h = _handler(
        "from messagefoundry import handler, message_type_of, Send\n"
        '@handler("a", accepts=message_type_of("ADT^A01", "ORU^R01"))\n'
        'def a(msg):\n    return Send("O", msg)\n'
    )
    assert h["accepts_types"] == [
        "ADT^A01",
        "ORU^R01",
    ]  # authoritative — from the enforced predicate
    assert "inferred_type" not in h


def test_inferred_type_from_leading_message_code_guard() -> None:
    h = _handler(
        "from messagefoundry import handler, Send\n"
        '@handler("b")\n'
        'def b(msg):\n    if msg.message_code != "ADT":\n        return []\n    return Send("O", msg)\n'
    )
    assert h["inferred_type"] == {"code": "ADT"}
    assert "accepts_types" not in h


def test_inferred_type_from_message_type_whole_field() -> None:
    h = _handler(
        "from messagefoundry import handler, Send\n"
        '@handler("d")\n'
        'def d(msg):\n    if msg.message_type == "ADT^A01":\n        return Send("O", msg)\n    return None\n'
    )
    assert h["inferred_type"] == {"code": "ADT", "trigger": "A01"}


def test_subscript_guard_is_not_inferred() -> None:
    # A msg["MSH-9.2"] subscript guard is deliberately NOT inferred (too varied) — accepts= is authoritative.
    h = _handler(
        "from messagefoundry import handler, Send\n"
        '@handler("c")\n'
        'def c(msg):\n    if msg["MSH-9.2"] not in ("A01",):\n        return None\n    return Send("O", msg)\n'
    )
    assert "inferred_type" not in h and "accepts_types" not in h


def test_typeless_handler_omits_both_fields() -> None:
    # A typeless handler is byte-identical to the pre-P2 contract (→ generic, unscoped picker).
    h = _handler(
        "from messagefoundry import handler, Send\n"
        '@handler("e")\ndef e(msg):\n    return Send("O", msg)\n'
    )
    assert "accepts_types" not in h and "inferred_type" not in h
