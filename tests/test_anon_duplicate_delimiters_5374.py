# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5374: ``read_message_seps`` refuses a header whose four MSH-2 encoding characters
repeat, in both ``surrogates.py`` copies, so the anonymizer refuses the message rather than
rewriting it on a mis-split. Synthetic HL7 only."""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType

import pytest

from messagefoundry_toolkit.anon import anonymize as toolkit_anonymize
from messagefoundry_toolkit.anon import leak as toolkit_leak
from messagefoundry_toolkit.anon import surrogates as toolkit_surrogates
from tee.anon import anonymize as tee_anonymize
from tee.anon import leak as tee_leak
from tee.anon import surrogates as tee_surrogates

_BODY = "|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||SYN1^^^H^MR||ZZTEST^ALPHA"
_SALT = "b5374-salt-0123456789abcdef"
_BOTH = pytest.mark.parametrize(
    "module", [toolkit_surrogates, tee_surrogates], ids=["toolkit", "tee"]
)

#: MSH-2 values with four characters, one repeated, in each pair of positions. MSH-1 cannot repeat
#: in MSH-2: MSH-2 is read up to the first MSH-1, so it never holds one.
_REPEATING = ("^^\\&", "^~^&", "^~\\^", "^~~&", "^~\\~", "^~\\\\")


@_BOTH
@pytest.mark.parametrize("enc", _REPEATING)
def test_repeating_encoding_characters_are_refused(module: ModuleType, enc: str) -> None:
    assert module.read_message_seps(f"MSH|{enc}{_BODY}") is None


@_BOTH
@pytest.mark.parametrize("enc", ["^~\\&", "^~\\&#", "^~\\&^"])
def test_the_control_four_distinct_characters_are_read(module: ModuleType, enc: str) -> None:
    """Only the first four are read, so a repeat in a fifth character is not one of theirs."""
    parsed = module.read_message_seps(f"MSH|{enc}{_BODY}")
    assert parsed is not None
    seps, field = parsed
    assert (field, seps.component, seps.repetition, seps.escape, seps.subcomponent) == (
        "|", "^", "~", "\\", "&",
    )  # fmt: skip


@pytest.mark.parametrize("anonymize", [toolkit_anonymize, tee_anonymize], ids=["toolkit", "tee"])
@pytest.mark.parametrize("enc", _REPEATING)
def test_the_anonymizer_refuses_a_message_with_repeating_delimiters(
    anonymize: Callable[..., str], enc: str
) -> None:
    # AnonError subclasses ValueError; the reason names the repeat, not a missing MSH.
    with pytest.raises(ValueError, match="repeats an encoding character"):
        anonymize(f"MSH|{enc}{_BODY}", salt=_SALT)


@pytest.mark.parametrize("anonymize", [toolkit_anonymize, tee_anonymize], ids=["toolkit", "tee"])
def test_the_control_the_anonymizer_rewrites_distinct_delimiters(
    anonymize: Callable[..., str],
) -> None:
    assert "ZZTEST" not in anonymize(f"MSH|^~\\&{_BODY}", salt=_SALT)


@pytest.mark.parametrize("leak", [toolkit_leak, tee_leak], ids=["toolkit", "tee"])
@pytest.mark.parametrize("enc", _REPEATING)
def test_the_structural_leak_check_reports_repeating_delimiters(leak: ModuleType, enc: str) -> None:
    """Found by code review round 1: a refused header read as "no parseable MSH" to the leak
    check, which returns no hit for that, so a direct caller saw a clean structural result."""
    hits = leak.structural_phi_hits(f"MSH|{enc}{_BODY}", set())
    assert hits == [leak.REPEATED_ENCODING_HIT]


@pytest.mark.parametrize("leak", [toolkit_leak, tee_leak], ids=["toolkit", "tee"])
def test_a_token_only_leak_report_reports_repeating_delimiters(leak: ModuleType) -> None:
    """Found by code review round 2: with no rules the structural walk is skipped, so the repeat
    was reported nowhere and a token-only call read the message as clean."""
    report = leak.leak_report(f"MSH|^~^&{_BODY}")
    assert leak.REPEATED_ENCODING_HIT in report.hits
    assert leak.REPEATED_ENCODING_HIT in report.structural_hits
    assert leak.leak_report(f"MSH|^~\\&{_BODY}").structural_hits == []


@pytest.mark.parametrize("leak", [toolkit_leak, tee_leak], ids=["toolkit", "tee"])
def test_the_refusal_advice_says_to_repair_the_header(leak: ModuleType) -> None:
    """Found by code review round 2: the hit read as a PHI shape, so the advice was to extend the
    rule map, which cannot fix it."""
    report = leak.leak_report(f"MSH|^~^&{_BODY}")
    advice = leak.refusal_advice(report)
    assert "Repair the header" in advice
    # A token hit asks for the rule map on its own account; which fires depends on the ambient token
    # source (a loaded site prefix can match the header's timestamp), so only a report with none
    # is held to leaving that step out.
    if report.hits == report.structural_hits:
        assert "Extend the rule map" not in advice


@pytest.mark.parametrize("leak", [toolkit_leak, tee_leak], ids=["toolkit", "tee"])
def test_the_control_a_message_without_a_header_still_reports_nothing(leak: ModuleType) -> None:
    assert leak.structural_phi_hits("PID|1||SYN1", set()) == []
