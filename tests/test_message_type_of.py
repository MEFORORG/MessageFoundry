# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``message_type_of`` — the ADR 0104 / ADR 0084 ``accepts=`` enforcement predicate.

Verifies AC-5 (component-wise MSH-9.1+9.2 match via the message's own MSH-2 — a 3-component
``ADT^A01^ADT_A01`` and a custom component separator both match; code-only / wildcard / variadic-union
grammar) and AC-6 (fail-loud ``MessageTypeError`` on any body with no single usable MSH-9, and the
author-time ``WiringError`` grammar guard + the ADR 0084 static ``accepts=`` acceptance).
"""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import (
    MessageTypeError,
    WiringError,
    _check_accepts_predicate,
    message_type_of,
)
from messagefoundry.parsing._backend import backend
from messagefoundry.parsing.message import Message, RawMessage

_ADT = (
    "MSH|^~\\&|SENDA|SENDF|RECV|RFAC|20200101||ADT^A01^ADT_A01|MSG1|P|2.5\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)
_ADT_CUSTOM_SEP = "MSH|@~\\&|A|B|C|D|20200101||ADT@A01@ADT_A01|MSG1|P|2.5\rPID|1||100\r"
_ORU = "MSH|^~\\&|A|B|C|D|20200101||ORU^R01|MSG1|P|2.5\rOBR|1\r"
_ADT_CODE_ONLY = "MSH|^~\\&|A|B|C|D|20200101||ADT|MSG1|P|2.5\r"


@pytest.mark.parametrize("builtin", [True, False], ids=["builtin", "python_hl7"])
def test_component_wise_match_three_component_and_custom_sep(builtin: bool) -> None:
    """AC-5: matches a conformant 3-component MSH-9 and a custom component separator (never a whole-field
    caret-literal compare)."""
    with backend(builtin=builtin):
        adt = Message.parse(_ADT)
        assert message_type_of("ADT^A01")(adt) is True  # 3-component source, 2-component spec
        assert message_type_of("ADT^A01^ADT_A01")(adt) is True  # structure component ignored
        assert message_type_of("ADT")(adt) is True  # code-only
        assert message_type_of("ADT^*")(adt) is True  # wildcard trigger
        assert message_type_of("*^A01")(adt) is True  # wildcard code
        assert message_type_of("ORU^R01")(adt) is False
        assert message_type_of("ADT^A02")(adt) is False  # right code, wrong trigger
        assert message_type_of("ORU^R01", "ADT^A01")(adt) is True  # variadic union

        custom = Message.parse(_ADT_CUSTOM_SEP)  # MSH-2 component sep is '@'
        assert message_type_of("ADT^A01")(custom) is True


def test_code_only_message_matches_code_specs() -> None:
    """A code-only MSH-9 (no trigger) matches a code-only spec and a wildcard trigger, not an exact one."""
    m = Message.parse(_ADT_CODE_ONLY)
    assert message_type_of("ADT")(m) is True
    assert message_type_of("ADT^*")(m) is True
    assert message_type_of("ADT^A01")(m) is False  # spec wants a trigger the message lacks


def test_fail_loud_on_non_hl7_and_batches() -> None:
    """AC-6: the predicate raises ``MessageTypeError`` (→ ERROR/dead-letter, never a silent decline) on
    any body with no single usable MSH-9."""
    pred = message_type_of("ADT^A01")
    with pytest.raises(MessageTypeError):
        pred(RawMessage("{}", "json"))  # no MSH-9 API at all
    with pytest.raises(MessageTypeError):
        pred(Message.parse("BHS|^~\\&|A|B\r" + _ADT))  # BHS-led batch envelope
    with pytest.raises(MessageTypeError):
        pred(Message.parse("FHS|^~\\&|A|B\r" + _ADT))  # FHS-led batch envelope
    with pytest.raises(MessageTypeError):
        pred(Message.parse(_ADT + _ORU))  # bare multi-MSH batch (2 MSH segments)
    with pytest.raises(MessageTypeError):
        pred(Message.parse("MSH|^~\\&|A|B|C|D|20200101|||MSG1|P|2.5\r"))  # empty MSH-9.1


def test_fail_loud_is_rerun_stable() -> None:
    """The raise is deterministic on the same input (re-run stability)."""
    pred = message_type_of("ADT^A01")
    bad = RawMessage("{}", "json")
    for _ in range(3):
        with pytest.raises(MessageTypeError):
            pred(bad)


def test_grammar_errors_are_author_time_wiring_errors() -> None:
    """AC-6: a malformed spec fails LOUD at ``message_type_of(...)`` construction (config-load/``check``
    time) as a ``WiringError`` — distinct from the per-message ``MessageTypeError``."""
    with pytest.raises(WiringError):
        message_type_of()  # no specs
    with pytest.raises(WiringError):
        message_type_of("")  # empty spec
    with pytest.raises(WiringError):
        message_type_of("ADT^A01^X^Y")  # >3 components
    with pytest.raises(WiringError):
        message_type_of("^A01")  # empty code component
    with pytest.raises(WiringError):
        message_type_of("ADT^")  # empty trigger component


def test_predicate_passes_accepts_static_check() -> None:
    """The returned closure satisfies the ADR 0084 ``accepts=`` static guard (it reads no run-scoped
    ``state_get``/``response_get``), so ``@handler(accepts=message_type_of(...))`` loads cleanly."""
    pred = message_type_of("ADT^A01")
    _check_accepts_predicate("adt_handler", pred)  # must not raise


def test_message_type_error_is_valueerror() -> None:
    """``MessageTypeError`` subclasses ``ValueError`` so a broad content-fault handler classifies it."""
    assert issubclass(MessageTypeError, ValueError)
