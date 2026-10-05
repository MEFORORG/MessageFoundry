# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An MSH rule is applied by BOTH adapters, to every MSH line (vault BACKLOG #2265).

The leak-check counts an ``MSH-N`` rule's field on a later MSH line as scrubbed. The tee adapter
used to skip every MSH rule, so a value such a rule named stayed in the tee's output and the
check still passed it. The engine adapter always applied the rule. These tests pin that the two
now agree, and that a rule which cannot be honoured (``MSH-1``, ``MSH-2``) is refused.

Every value here is synthetic. The dashed number is the made-up shape the detector matches.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest

from messagefoundry.anon import DEFAULT_RULES, AnonError, FieldRule, SurrogateKind
from messagefoundry.anon import anonymize as engine_anonymize
from messagefoundry.anon import anonymize_checked as engine_anonymize_checked
from messagefoundry.anon import hl7 as engine_hl7
from tee.anon import DEFAULT_RULES as TEE_DEFAULT_RULES
from tee.anon import AnonError as TeeAnonError
from tee.anon import FieldRule as TeeFieldRule
from tee.anon import anonymize as tee_anonymize
from tee.anon import anonymize_checked as tee_anonymize_checked
from tee.anon import hl7 as tee_hl7

_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/security/scan_forbidden.py (absent on an installed wheel)",
)

_SALT = "b193-2265-salt-0123456789abcdef"
_SSN = "123-45-6789"
_HEADER = r"MSH|^~\&|APP|FAC|RCV|RFAC|20260101120000||ADT^A01|M1|P|2.5.1"
_PID = "PID|1||1^^^H^MR||X^Y"
#: A second MSH line with the dashed number in MSH-8, which is split index 7.
_SECOND = rf"MSH|^~\&|APP2|FAC2|RCV|RFAC|20260101120000|{_SSN}|ADT^A01|M2|P|2.5.1"
_MSG = "\r".join((_HEADER, _PID, _SECOND))

_PLAIN = pytest.mark.parametrize(
    "anonymize", (engine_anonymize, tee_anonymize), ids=("engine", "tee")
)
_CHECKED = pytest.mark.parametrize(
    "checked", (engine_anonymize_checked, tee_anonymize_checked), ids=("engine", "tee")
)
#: Every kind that rewrites a field. KEEP is the one kind that rewrites nothing.
_REWRITING_KINDS = tuple(kind for kind in SurrogateKind if kind != SurrogateKind.KEEP)


def _with(path: str, kind: SurrogateKind) -> tuple[FieldRule, ...]:
    """The default rules plus one rule. The tee coerces an engine ``FieldRule`` kind by value."""
    return (*DEFAULT_RULES, FieldRule(path, kind))


def _tee_with(path: str, kind: SurrogateKind) -> tuple[TeeFieldRule, ...]:
    """The same rule set built from the tee's own classes, for a direct call to the tee."""
    return (*TEE_DEFAULT_RULES, TeeFieldRule(path, kind.value))  # type: ignore[arg-type]


def _msh_lines(output: str) -> list[list[str]]:
    return [line.split("|") for line in output.split("\r") if line.startswith("MSH")]


def test_the_fixture_puts_the_number_in_msh_8_of_the_second_line() -> None:
    """The control for everything below: MSH-N sits at split index N-1."""
    assert _SECOND.split("|")[7] == _SSN
    assert _SSN not in _HEADER


@_PLAIN
def test_a_drop_rule_blanks_the_field_on_a_second_msh_line(anonymize: Callable[..., str]) -> None:
    """The reproduction. Before the fix the tee left the number in place (RED on the tee, and the
    engine case was already green)."""
    out = anonymize(_MSG, salt=_SALT, rules=_with("MSH-8", SurrogateKind.DROP))
    assert _SSN not in out
    header, second = _msh_lines(out)
    assert second[7] == ""
    assert second[6] == "20260101120000"  # the neighbour is untouched
    assert header[7] == ""  # empty before, empty after


@_NO_SCANNER
@_CHECKED
def test_a_rule_one_field_off_still_refuses(checked: Callable[..., str]) -> None:
    """The discriminating control: the rule names MSH-9, so MSH-8 is unmapped and is refused."""
    with pytest.raises(Exception, match="SSN-shaped value in MSH-8") as exc:
        checked(_MSG, salt=_SALT, rules=_with("MSH-9", SurrogateKind.DROP))
    assert type(exc.value).__name__ == "LeakError"
    assert _SSN not in str(exc.value)


@pytest.mark.parametrize("kind", _REWRITING_KINDS, ids=lambda kind: kind.value)
def test_every_rewriting_kind_gives_the_same_bytes_on_both_sides(kind: SurrogateKind) -> None:
    """Each kind rewrites MSH-8 on the second line, and the two adapters agree byte for byte."""
    engine = engine_anonymize(_MSG, salt=_SALT, rules=_with("MSH-8", kind))
    tee = tee_anonymize(_MSG, salt=_SALT, rules=_tee_with("MSH-8", kind))
    assert engine == tee
    assert _SSN not in tee


@_PLAIN
def test_an_msh_rule_reaches_the_header_line_too(anonymize: Callable[..., str]) -> None:
    """A rule is not tied to one occurrence, so it rewrites the header as well as a later line.
    An operator who maps the sending facility gets it scrubbed on both sides."""
    out = anonymize(_MSG, salt=_SALT, rules=_with("MSH-4", SurrogateKind.FREETEXT))
    header, second = _msh_lines(out)
    assert header[3] == "[REDACTED]"
    assert second[3] == "[REDACTED]"
    assert header[2] == "APP" and second[2] == "APP2"  # MSH-3, the neighbour, is untouched


@_PLAIN
def test_the_default_rules_leave_every_msh_line_alone(anonymize: Callable[..., str]) -> None:
    """No default rule names an MSH field, so the fix changes nothing for a caller with no MSH
    rule: MSH-7 is kept for capture matching (ADR 0030)."""
    out = anonymize(_MSG, salt=_SALT)
    assert [line for line in out.split("\r") if line.startswith("MSH")] == [_HEADER, _SECOND]


@_PLAIN
def test_a_rule_past_the_end_of_a_short_msh_line_changes_nothing(
    anonymize: Callable[..., str],
) -> None:
    out = anonymize(
        "\r".join((_HEADER, _PID, r"MSH|^~\&|APP2|FAC2")),
        salt=_SALT,
        rules=_with("MSH-30", SurrogateKind.DROP),
    )
    assert out.split("\r")[-1] == r"MSH|^~\&|APP2|FAC2"


@_PLAIN
def test_an_msh_rule_reads_the_messages_own_separators(anonymize: Callable[..., str]) -> None:
    """A message that declares `!` as its field separator is split on `!`, on both sides."""
    header = r"MSH!*~\&!APP!FAC!RCV!RFAC!20260101120000!!ADT*A01!M1!P!2.5.1"
    second = rf"MSH!*~\&!APP2!FAC2!RCV!RFAC!20260101120000!{_SSN}!ADT*A01!M2!P!2.5.1"
    assert second.split("!")[7] == _SSN
    out = anonymize(
        "\r".join((header, "PID!1!!1***H*MR!!X*Y", second)),
        salt=_SALT,
        rules=_with("MSH-8", SurrogateKind.DROP),
    )
    assert _SSN not in out
    assert out.split("\r")[-1].split("!")[6:9] == ["20260101120000", "", "ADT*A01"]


#: Spellings ``load_rules`` accepts (the last one too: its pattern ends in ``$``, which matches
#: before a final newline), then spellings only a rule built in code can carry. ``int()`` reads a
#: number below 3 from every one of them, and ``int()`` is how the adapters read a path.
_UNWRITABLE_MSH_PATHS = [
    "MSH-0",
    "MSH-00",
    "MSH-1",
    "MSH-01",
    "MSH-2",
    "MSH-02",
    "MSH-002",
    "MSH-2\n",
    "MSH- 2",
    "MSH-2 ",
    "MSH-+2",
    "MSH-0_2",
    "MSH--1",
    "msh-2",
]


@pytest.mark.parametrize("path", _UNWRITABLE_MSH_PATHS, ids=repr)
@pytest.mark.parametrize("kind", _REWRITING_KINDS, ids=lambda kind: kind.value)
@_PLAIN
def test_a_rule_that_would_rewrite_the_delimiters_is_refused(
    anonymize: Callable[..., str], kind: SurrogateKind, path: str
) -> None:
    """MSH-1 and MSH-2 hold the delimiters. Before the fix the engine emitted a header with no
    readable delimiters for some kinds, and the tee ignored the rule. Both now refuse, and the
    refusal carries no message text.

    The field NUMBER decides, read the way the adapters read it: ``MSH-02`` is field 2 to
    ``int()``, so a text comparison with ``MSH-2`` would let it through and blank the encoding
    characters. A digits-only test such as ``str.isdecimal`` lets ``"MSH-2\\n"`` through the same
    way. ``MSH-0`` would be split index -1 on the tee, the LAST field of the line."""
    segment, _, number = path.partition("-")
    named = re.escape(f"{segment}-{int(number)}")
    with pytest.raises(ValueError, match=f"a rule names {named},") as exc:
        anonymize(_MSG, salt=_SALT, rules=_with(path, kind))
    assert isinstance(exc.value, (AnonError, TeeAnonError))
    assert _SSN not in str(exc.value) and "APP2" not in str(exc.value)


@_PLAIN
def test_the_refusal_names_every_unwritable_field(anonymize: Callable[..., str]) -> None:
    rules = (*_with("MSH-2", SurrogateKind.DROP), FieldRule("MSH-1", SurrogateKind.DROP))
    with pytest.raises(ValueError, match="a rule names MSH-1, MSH-2,"):
        anonymize(_MSG, salt=_SALT, rules=rules)


@_PLAIN
def test_a_rule_for_field_zero_of_any_segment_is_refused(anonymize: Callable[..., str]) -> None:
    """Field 0 is the segment id. Before, the tee blanked the id (split index 0) and the engine
    refused the message as malformed; both now give the same named refusal. ``PID-1`` is the
    control: the lowest field a rule may rewrite outside MSH."""
    with pytest.raises(ValueError, match="a rule names PID-0,"):
        anonymize(_MSG, salt=_SALT, rules=_with("PID-0", SurrogateKind.DROP))
    out = anonymize(_MSG, salt=_SALT, rules=_with("PID-1", SurrogateKind.DROP))
    assert out.split("\r")[1].startswith("PID||")


@pytest.mark.parametrize("module", (engine_hl7, tee_hl7), ids=("engine", "tee"))
def test_the_refusal_lets_a_keep_and_a_non_field_path_through(module: ModuleType) -> None:
    """``anonymize`` strips KEEP rules before the adapter, so the exemption is pinned here, at the
    check itself. A path whose number ``int()`` cannot read is not this check's to refuse. The
    last line is the control: the same paths with a rewriting kind are refused."""
    refuse = module._refuse_unwritable_rules
    keeps = tuple(module.FieldRule(p, "keep") for p in ("MSH-0", "MSH-1", "MSH-2", "PID-0"))
    refuse(keeps)
    refuse((module.FieldRule("MSH-9.1", "drop"), module.FieldRule("MSH", "drop")))
    with pytest.raises(ValueError, match="a rule names MSH-0, MSH-1, MSH-2, PID-0,"):
        refuse(tuple(module.FieldRule(rule.path, "drop") for rule in keeps))


@_NO_SCANNER
@_CHECKED
def test_a_keep_on_msh_2_is_allowed_and_the_field_is_still_scanned(
    checked: Callable[..., str],
) -> None:
    """A KEEP rewrites nothing, so it is not refused. It also hides nothing: a second MSH line
    with the dashed number where MSH-2 belongs is still refused by the leak-check."""
    rules = _with("MSH-2", SurrogateKind.KEEP)
    clean = _SECOND.replace(_SSN, "")
    assert clean in checked("\r".join((_HEADER, _PID, clean)), salt=_SALT, rules=rules)
    with pytest.raises(Exception, match="SSN-shaped value in MSH-2") as exc:
        checked("\r".join((_HEADER, _PID, f"MSH|{_SSN}|APP2")), salt=_SALT, rules=rules)
    assert type(exc.value).__name__ == "LeakError"


@_NO_SCANNER
@_CHECKED
@pytest.mark.parametrize(
    ("line", "path", "index"),
    [
        (_SECOND, "MSH-8", 7),
        (rf"MSH|^~\&|APP2|{_SSN}", "MSH-4", 3),
        (rf"MSH|^~\&|APP2|FAC2|{_SSN}|", "MSH-5", 4),
        (rf"MSH|^~\&|APP2|FAC2|RCV|RFAC|2026|||||||||{_SSN}", "MSH-16", 15),
    ],
    ids=("the-row-case", "short-line", "middle-field", "last-field"),
)
def test_the_rule_and_the_check_agree_on_every_position(
    checked: Callable[..., str], line: str, path: str, index: int
) -> None:
    """Wherever the number sits on a later MSH line, the rule for that address removes it and
    the rule for the address one lower does not. That is the same numbering the leak-check uses.

    The first row is the ledger row's own case: a DROP rule names the field that holds a dashed
    number on a second MSH line. The check may pass it, because the number is gone. Before the
    fix the tee passed it with the number still there."""
    assert line.split("|")[index] == _SSN
    msg = "\r".join((_HEADER, _PID, line))
    out = checked(msg, salt=_SALT, rules=_with(path, SurrogateKind.DROP))
    assert _SSN not in out
    lower = f"MSH-{index}"
    with pytest.raises(Exception, match=f"SSN-shaped value in {path}"):
        checked(msg, salt=_SALT, rules=_with(lower, SurrogateKind.DROP))


@_NO_SCANNER
def test_an_overlay_drop_reaches_a_second_msh_line_through_the_tee(tmp_path: Path) -> None:
    """The operator's route: an ``anon.toml`` drop naming an MSH field. The tee now honours it."""
    overlay = tmp_path / "anon.toml"
    overlay.write_text('[hl7]\ndrop = ["MSH-8"]\n', encoding="utf-8")
    out = tee_anonymize_checked(_MSG, salt=_SALT, overlay=overlay)
    assert _SSN not in out
    assert out == engine_anonymize_checked(_MSG, salt=_SALT, overlay=overlay)


@_NO_SCANNER
@_CHECKED
def test_full_coverage_reports_the_scrubbed_msh_field_as_decided(
    checked: Callable[..., str],
) -> None:
    """With the coverage switch on, a second line's MSH-8 counts as decided because a rule names
    it, and the rule was applied: the field holds the redaction, not its old value. Before the
    fix the tee counted it decided and left the value in place (RED on the tee).

    The kind is FREETEXT so the field is still PRESENT in the output; a DROP would empty it, and
    the check skips an empty field before it looks at any rule. The control is the same call
    without the MSH-8 rule, which is refused for that one field."""
    msg = _MSG.replace(_SSN, "OLDVALUE")
    keeps = tuple(
        FieldRule(f"MSH-{n}", SurrogateKind.KEEP) for n in (2, 3, 4, 5, 6, 7, 9, 10, 11, 12)
    )
    reports: list[object] = []
    out = checked(
        msg,
        salt=_SALT,
        rules=(*_with("MSH-8", SurrogateKind.FREETEXT), *keeps),
        require_full_coverage=True,
        on_report=reports.append,
    )
    (report,) = reports
    assert report.undecided_fields == ()  # type: ignore[attr-defined]
    assert "OLDVALUE" not in out
    assert _msh_lines(out)[1][7] == "[REDACTED]"
    with pytest.raises(Exception, match=r"1 field\(s\) with no rule and no keep: MSH-8"):
        checked(msg, salt=_SALT, rules=(*DEFAULT_RULES, *keeps), require_full_coverage=True)


def test_the_lowest_rewritable_msh_field_is_three() -> None:
    """The control for the refusal above: MSH-3 is rewritten, not refused."""
    engine = engine_anonymize(_MSG, salt=_SALT, rules=_with("MSH-3", SurrogateKind.DROP))
    tee = tee_anonymize(_MSG, salt=_SALT, rules=_tee_with("MSH-3", SurrogateKind.DROP))
    assert engine == tee
    assert [line[2] for line in _msh_lines(tee)] == ["", ""]


def test_the_tee_applies_an_msh_rule_to_a_header_not_in_capitals() -> None:
    """The separators are read from an ``Msh`` header and the leak-check skips it as the header,
    so the tee must apply an MSH rule to it. (The engine refuses such a message outright.)"""
    msg = "\r".join((_HEADER.replace("MSH", "Msh", 1), _PID))
    out = tee_anonymize(msg, salt=_SALT, rules=_tee_with("MSH-4", SurrogateKind.FREETEXT))
    assert out.split("\r")[0].split("|")[3] == "[REDACTED]"
    with pytest.raises(ValueError):
        engine_anonymize(msg, salt=_SALT, rules=_with("MSH-4", SurrogateKind.FREETEXT))


def test_a_later_line_not_in_capitals_is_not_an_msh_line_to_either_side() -> None:
    """Only the HEADER is matched in any case. A later ``Msh`` line is not an MSH line to the
    engine or to the leak-check, so the tee must leave it alone too: same bytes from both, and
    the leak-check then refuses the line as one no rule can reach."""
    later = _SECOND.replace("MSH", "Msh", 1)
    msg = "\r".join((_HEADER, _PID, later))
    engine = engine_anonymize(msg, salt=_SALT, rules=_with("MSH-8", SurrogateKind.DROP))
    tee = tee_anonymize(msg, salt=_SALT, rules=_tee_with("MSH-8", SurrogateKind.DROP))
    assert engine == tee
    assert tee.split("\r")[-1] == later


#: Messages with a later MSH line in shapes the one fixture above does not have.
_PARITY_MESSAGES = {
    "fixture": _MSG,
    "two-later-lines": "\r".join((_MSG, rf"MSH|^~\&|APP3|FAC3|RCV|RFAC|2026|{_SSN}|ADT^A01|M3")),
    "repetitions-and-escapes": "\r".join(
        (_HEADER, _PID, rf"MSH|^~\&|A~B^C&D|F\T\G|RCV|RFAC|2026|{_SSN}~{_SSN}|ADT^A01|M2")
    ),
    "three-fields": "\r".join((_HEADER, _PID, r"MSH|^~\&|APP2")),
    "msh-between-segments": "\r".join((_HEADER, _SECOND, _PID, "NK1|1|Z^Q")),
    "own-separators": "\r".join(
        (
            r"MSH!*~\&!APP!FAC!RCV!RFAC!20260101120000!!ADT*A01!M1!P!2.5.1",
            "PID!1!!1***H*MR!!X*Y",
            rf"MSH!*~\&!APP2!FAC2!RCV!RFAC!20260101120000!{_SSN}!ADT*A01!M2!P!2.5.1",
        )
    ),
}


@pytest.mark.parametrize("message", _PARITY_MESSAGES.values(), ids=_PARITY_MESSAGES.keys())
@pytest.mark.parametrize("path", ["MSH-3", "MSH-4", "MSH-8", "MSH-9", "MSH-12", "MSH-30"])
@pytest.mark.parametrize("kind", _REWRITING_KINDS, ids=lambda kind: kind.value)
def test_an_msh_rule_gives_the_same_bytes_on_both_sides(
    message: str, path: str, kind: SurrogateKind
) -> None:
    """Engine and tee output are equal byte for byte under an MSH rule, for each message shape,
    field and kind. The parity file's own inputs run with the default rules, which name no MSH
    field, so they cannot show this."""
    engine = engine_anonymize(message, salt=_SALT, rules=_with(path, kind))
    tee = tee_anonymize(message, salt=_SALT, rules=_tee_with(path, kind))
    assert engine == tee
