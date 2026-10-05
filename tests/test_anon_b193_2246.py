# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Plain ``anonymize`` refuses a line no rule can reach (vault BACKLOG #2246).

Before this, only ``anonymize_checked`` refused such a line, in its leak-check. Plain ``anonymize``
passed it through untouched, so a wrapped name could reach a dataset. The refusal now lives in the
shared ``normalized_message``, which both entry points and both copies (engine and tee) run first.

A legal empty segment, such as a bare ``PV2``, is not such a line (vault BACKLOG #2247), so each
refusal here is paired with a line that must still pass. Synthetic text only.

Measured red: with the refusal taken out of the engine copy of normalized_message, 30 tests
across the five anonymizer test files failed. The tee arms stayed green, which is the control.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon.surrogates import normalized_message as engine_normalized
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import leak as tee_leak
from tee.anon.surrogates import normalized_message as tee_normalized

_SALT = "b193-salt-0123456789abcdef"
_HEADER = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1"
_PID = "PID|1||1^^^H^MR||X^Y"

_ENTRY_POINTS = pytest.mark.parametrize(
    "entry",
    (engine_anonymize, tee_anonymize, engine_anonymize_checked, tee_anonymize_checked),
    ids=("engine-plain", "tee-plain", "engine-checked", "tee-checked"),
)

_UNREACHABLE = pytest.mark.parametrize(
    ("line", "needle"),
    [
        ("ZZTEST SYNTH|wrapped note", "ZZTEST"),  # first field is not a segment id
        ("ZZTEST SYNTH", "ZZTEST"),  # the same, with no field separator
        ("LEE", "LEE"),  # three letters shaped like a segment id that no HL7 version defines
        ("ZOE", "ZOE"),  # a Z-prefix alone does not make bare text a segment
        ("msh|ZZTEST SYNTH", "ZZTEST"),  # a second, lowercase MSH line is not the header
        ("|ZZTEST", "ZZTEST"),  # an empty first field
    ],
    ids=("not-an-id", "not-an-id-bare", "bare-name", "bare-z-name", "second-msh", "empty-id"),
)


def _msg(*lines: str) -> str:
    return "\r".join((_HEADER, _PID, *lines))


@_ENTRY_POINTS
@_UNREACHABLE
def test_every_entry_point_refuses_a_line_no_rule_can_reach(
    entry: Callable[..., str], line: str, needle: str
) -> None:
    """The four entry points agree: each raises the same body-free ``AnonError``."""
    with pytest.raises(ValueError, match="a line no rule can reach") as exc:
        entry(_msg(line), salt=_SALT)
    assert type(exc.value).__name__ == "AnonError"
    assert needle not in str(exc.value)  # the refusal never carries the line's text


@_ENTRY_POINTS
@_UNREACHABLE
def test_the_refusal_does_not_depend_on_where_the_line_sits(
    entry: Callable[..., str], line: str, needle: str
) -> None:
    """A wrapped line is as often in the middle of a message as at its end."""
    with pytest.raises(ValueError, match="a line no rule can reach"):
        entry(_msg(line, "NK1|1|Q^Z"), salt=_SALT)


_REACHABLE = pytest.mark.parametrize(
    "line",
    [
        "PV2",  # a legal empty segment, no separator (BACKLOG #2247 defect 1)
        "PV2|",  # the same with a trailing separator
        "NK1|1|Q^Z",  # an ordinary mapped segment
        "ZPD|free",  # a Z-segment with a field is reachable: an overlay rule can name ZPD-1
        "KIM|F",  # shaped like a segment, so its fields are checked; the id is never printed
    ],
    ids=("empty-segment", "empty-segment-sep", "mapped", "z-segment", "unknown-id"),
)


@_ENTRY_POINTS
@_REACHABLE
def test_a_reachable_line_is_not_refused(entry: Callable[..., str], line: str) -> None:
    """The control for the refusals above. Without it, a rule that refused every message would pass
    them. A bare ``PV2`` is the case the old no-separator rule got wrong."""
    out = entry(_msg(line), salt=_SALT)
    assert out.split("\r")[-1].split("|")[0] == line.split("|")[0]  # the line is still there


@_REACHABLE
def test_engine_and_tee_agree_on_a_reachable_line(line: str) -> None:
    msg = _msg(line, "NK1|1|Q^Z")
    assert engine_anonymize(msg, salt=_SALT) == tee_anonymize(msg, salt=_SALT)


def test_a_bare_segment_id_is_legal_only_where_the_hl7_version_defines_it() -> None:
    """``DON`` is a segment from HL7 2.8 on. Bare, it is an empty segment in a 2.8 message and
    unreachable text in a 2.5.1 one, where it may as well be a wrapped name."""
    v28 = _HEADER.replace("2.5.1", "2.8")
    for side in (engine_anonymize, tee_anonymize):
        assert side("\r".join((v28, _PID, "DON")), salt=_SALT).endswith("\rDON")
        with pytest.raises(ValueError, match="a line no rule can reach"):
            side("\r".join((_HEADER, _PID, "DON")), salt=_SALT)


def test_a_message_with_no_msh_keeps_its_own_refusal() -> None:
    """The unreachable-line check needs the field separator, so it stays out of the way when there
    is no header to read one from. The adapters' older refusal still names the real cause."""
    for side in (engine_anonymize, tee_anonymize):
        with pytest.raises(ValueError, match="no parseable MSH"):
            side("ZZTEST SYNTH|wrapped note", salt=_SALT)


def test_the_leak_check_and_the_anonymizer_use_one_definition() -> None:
    """``has_unreachable_line`` is the leak-check's own walk, so the two cannot drift apart: for
    each line, the anonymizer refuses exactly when the leak-check reports a malformed line."""
    lines = ["ZZTEST SYNTH|x", "LEE", "ZOE", "msh|x", "PV2", "PV2|", "KIM|F", "ZPD|free", "  "]
    for leak, normalized in ((engine_leak, engine_normalized), (tee_leak, tee_normalized)):
        for line in lines:
            msg = _msg(line)
            reported = leak.MALFORMED_LINE_HIT in leak.structural_phi_hits(msg, set())
            assert leak.has_unreachable_line(msg) is reported, line
            try:
                normalized(msg)
                refused = False
            except ValueError:
                refused = True
            assert refused is reported, line
