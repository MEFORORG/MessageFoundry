# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A passed bare line gets a coverage record, and the header is one line (vault BACKLOG #3001).

A bare line is a line with no field separator. When its whole text is a segment id the message's
HL7 version defines, or a rule names, it is a legal empty segment and it passes. That stays. What
was missing is a record: a wrapped line of free text that is exactly such an id looks the same,
and the walk recorded nothing for it, so ``require_full_coverage`` could not refuse it.

The second half is the header. The walk took the first line that started ``MSH`` as the header,
bare or short, and judged every line before it against the ids of EVERY HL7 version. The header
is now the one line ``read_message_seps`` takes the separators from, and every line is judged
against that header's own version.

Every value here is synthetic.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import messagefoundry.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.anon import leak as engine_leak
from messagefoundry.anon import rules as engine_rules
from tee.anon import leak as tee_leak
from tee.anon import rules as tee_rules

_LEAK_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "security" / "scan_forbidden.py"
_NO_SCANNER = pytest.mark.skipif(
    not _LEAK_SCANNER.exists(),
    reason="leak-check needs scripts/security/scan_forbidden.py (absent on an installed wheel)",
)

_SALT = "b254-3001-Kq7#vT2m!xW9$eR4zL8p-Hd5"
_PID = "PID|1||1^^^H^MR||X^Y"
_NO_FIELDS = " (line with no fields)"
_ADVICE = "For a line with no fields, add a rule or a keep for any field of that segment."

#: Each side with its own package's classes, as a real caller would hold them.
_ENGINE = SimpleNamespace(anon=engine_anon, rules=engine_rules, leak=engine_leak)
_TEE = SimpleNamespace(anon=tee_anon, rules=tee_rules, leak=tee_leak)
_SIDES = pytest.mark.parametrize("side", (_ENGINE, _TEE), ids=("engine", "tee"))


def _msh(version: str, seg: str = "MSH") -> str:
    return rf"{seg}|^~\&|APP|FAC|RCV|RFAC|20260101120000||ADT^A01|M1|P|{version}"


def _message(*lines: str, version: str = "2.5") -> str:
    """A header of ``version``, a PID, then ``lines``."""
    return "\r".join((_msh(version), _PID, *lines))


def _leading(*lines: str, version: str = "2.3") -> str:
    """``lines`` AHEAD of the header, as a wrapped line or a batch header would sit."""
    return "\r".join((*lines, _msh(version), _PID))


def _rules(side: Any, *extra: tuple[str, str]) -> tuple[Any, ...]:
    return (*side.rules.DEFAULT_RULES, *(side.rules.FieldRule(p, k) for p, k in extra))


def _checked(side: Any, message: str, rules: tuple[Any, ...], **kwargs: Any) -> tuple[str, Any]:
    reports: list[Any] = []
    out = side.anon.anonymize_checked(
        message, salt=_SALT, rules=rules, on_report=reports.append, **kwargs
    )
    (report,) = reports
    return out, report


# --- part 1: a passed bare line leaves a record ---------------------------------------------------


@_NO_SCANNER
@_SIDES
def test_the_base_message_passes_full_coverage(side: Any) -> None:
    """The control for every full-coverage case below: with no bare line, nothing is undecided."""
    _, report = _checked(side, _message(), _rules(side), require_full_coverage=True)
    assert report.undecided_fields == ()
    assert not any(address.endswith(_NO_FIELDS) for address in report.unmapped_fields)


@_NO_SCANNER
@_SIDES
def test_a_passed_bare_line_gets_a_coverage_record(side: Any) -> None:
    """The reproduction. A bare ``PV2`` in a 2.5 message is emitted, as before, and now the
    report names it. Before the fix both lists came back without it."""
    out, report = _checked(side, _message("PV2"), _rules(side))
    assert out.split("\r")[-1] == "PV2"
    assert f"PV2{_NO_FIELDS}" in report.unmapped_fields
    assert f"PV2{_NO_FIELDS}" in report.undecided_fields
    assert report.structural_hits == []


@_SIDES
def test_the_record_holds_no_value_and_no_position(side: Any) -> None:
    """The record is the id and the marker, with an empty value, wherever the line sits. It is
    not the malformed-line address, so the message is not refused as unreachable."""
    for message in (_message("PV2"), _message("PV2", "EVN|A01"), _message("EVN|A01", "PV2", "PV2")):
        records = [
            pair
            for pair in side.leak.unmapped_field_values(message, set())
            if pair[0].startswith("PV2")
        ]
        assert set(records) == {(f"PV2{_NO_FIELDS}", "")}
        assert side.leak.has_unreachable_line(message) is False
        mapped = {rule.path for rule in side.rules.DEFAULT_RULES}
        assert side.leak.structural_phi_hits(message, mapped) == []


@_NO_SCANNER
@_SIDES
def test_full_coverage_refuses_an_undecided_bare_line(side: Any) -> None:
    """No rule and no keep names a ``PV2`` field, so nobody decided the line. Before the fix the
    full-coverage run emitted it. It passes without the switch, which is the relaxation."""
    message = _message("PV2")
    _checked(side, message, _rules(side))  # passes with the switch off
    with pytest.raises(side.anon.LeakError) as exc:
        _checked(side, message, _rules(side), require_full_coverage=True)
    text = str(exc.value)
    assert f"1 field(s) with no rule and no keep: PV2{_NO_FIELDS}" in text
    assert _ADVICE in text


@_NO_SCANNER
@_SIDES
def test_the_bare_line_advice_is_for_a_bare_line_only(side: Any) -> None:
    """The control for the advice: a coverage refusal over an ordinary field does not carry it."""
    with pytest.raises(side.anon.LeakError) as exc:
        _checked(side, _message("PV2|||WARD"), _rules(side), require_full_coverage=True)
    assert "PV2-3" in str(exc.value)
    assert _ADVICE not in str(exc.value)


@_NO_SCANNER
@pytest.mark.parametrize("kind", ("keep", "drop"))
@_SIDES
def test_a_rule_or_keep_on_any_field_of_the_segment_decides_it(side: Any, kind: str) -> None:
    """A bare line has no field a rule could name, so naming any field of its segment is the
    decision. The record stays in the coverage report either way."""
    _, report = _checked(
        side, _message("PV2"), _rules(side, ("PV2-3", kind)), require_full_coverage=True
    )
    assert f"PV2{_NO_FIELDS}" in report.unmapped_fields
    assert report.undecided_fields == ()


@_NO_SCANNER
@_SIDES
def test_a_rule_on_another_segment_does_not_decide_it(side: Any) -> None:
    """The control for the case above: the deciding rule must name the bare line's own segment."""
    with pytest.raises(side.anon.LeakError, match="PV2 .line with no fields."):
        _checked(side, _message("PV2"), _rules(side, ("EVN-3", "keep")), require_full_coverage=True)


@_NO_SCANNER
@_SIDES
def test_a_bare_z_id_a_rule_names_gets_a_record_and_is_decided(side: Any) -> None:
    """A bare ``ZPD`` passes only because a rewriting rule names ``ZPD``. That rule also decides
    it, so full coverage emits it, and the report still names the line."""
    out, report = _checked(
        side, _message("ZPD"), _rules(side, ("ZPD-3", "drop")), require_full_coverage=True
    )
    assert out.split("\r")[-1] == "ZPD"
    assert f"ZPD{_NO_FIELDS}" in report.unmapped_fields
    assert report.undecided_fields == ()


@pytest.mark.parametrize(
    ("line", "version", "extra"),
    (
        ("LEE", "2.5", ()),  # three letters no version defines
        ("ZPD", "2.5", ()),  # a Z id no rule names
        ("ZPD", "2.5", (("ZPD-3", "keep"),)),  # a keep does not make a bare id reachable
        ("SFT", "2.3", ()),  # an id only a later version defines
        ("MSH", "2.5", ()),  # a header id carries the separators
    ),
    ids=("no-version", "z-unnamed", "z-keep-only", "later-version", "header-id"),
)
@_SIDES
def test_the_refused_bare_lines_are_still_refused(
    side: Any, line: str, version: str, extra: tuple[tuple[str, str], ...]
) -> None:
    """The controls: the record is for a line that PASSES. These never did and still do not, so
    none of them is turned into a record."""
    message = _message(line, version=version)
    rules = _rules(side, *extra)
    with pytest.raises(side.anon.AnonError, match="no rule can reach"):
        side.anon.anonymize(message, salt=_SALT, rules=rules)
    rewriting = {rule.path for rule in rules if rule.kind != "keep"}
    addresses = [address for address, _ in side.leak.unmapped_field_values(message, rewriting)]
    assert "(malformed segment)-0" in addresses
    assert not any(address.endswith(_NO_FIELDS) for address in addresses)


@_NO_SCANNER
@_SIDES
def test_a_long_run_keeps_one_entry_per_segment_id(side: Any) -> None:
    """The address holds no line position, so the tally does not grow with the dataset."""
    tally = side.leak.CoverageTally(full_coverage=True)
    for message in (_message("PV2"), _message("EVN|A01", "PV2"), _message("PV2", "PV2")):
        side.anon.anonymize_checked(message, salt=_SALT, rules=_rules(side), on_report=tally.add)
    assert tally.counts[f"PV2{_NO_FIELDS}"] == 3
    assert tally.undecided[f"PV2{_NO_FIELDS}"] == 3
    assert [address for address in tally.counts if address.startswith("PV2")] == [
        f"PV2{_NO_FIELDS}"
    ]
    assert f"PV2{_NO_FIELDS} x3" in tally.summary()


# --- parts 2 and 3: the header is one line, and its version judges every line ---------------------


@pytest.mark.parametrize("bare", ("MSH", "msh"))
def test_the_tee_refuses_a_leading_bare_msh(bare: str) -> None:
    """Before the fix the tee took a leading bare ``MSH``, in either case, as the header. It
    emitted the line whole and read the version as empty."""
    with pytest.raises(tee_anon.AnonError, match="no rule can reach"):
        tee_anon.anonymize(_leading(bare), salt=_SALT, rules=_rules(_TEE))


@pytest.mark.parametrize("bare", ("MSH", "msh"))
def test_the_tee_refuses_a_later_version_id_behind_a_leading_bare_msh(bare: str) -> None:
    """With the version read as empty, a bare ``SFT`` passed in a 2.3 message. ``SFT`` is 2.5."""
    message = "\r".join((bare, _msh("2.3"), _PID, "SFT"))
    with pytest.raises(tee_anon.AnonError, match="no rule can reach"):
        tee_anon.anonymize(message, salt=_SALT, rules=_rules(_TEE))


def test_the_tee_refuses_a_leading_bare_id_of_a_later_version() -> None:
    """Before the fix a line ahead of the header was judged against every HL7 version, so a
    bare ``SFT`` ahead of a 2.3 header was emitted. After the header it was always refused."""
    with pytest.raises(tee_anon.AnonError, match="no rule can reach"):
        tee_anon.anonymize(_leading("SFT", version="2.3"), salt=_SALT, rules=_rules(_TEE))


@_NO_SCANNER
def test_the_tee_passes_a_leading_bare_id_of_its_own_version_with_a_record() -> None:
    """The emitting control for the case above: the same bare ``SFT`` ahead of a 2.5 header is a
    legal empty segment of that version. It passes, and it gets its record."""
    out, report = _checked(_TEE, _leading("SFT", version="2.5"), _rules(_TEE))
    assert out.split("\r")[0] == "SFT"
    assert f"SFT{_NO_FIELDS}" in report.unmapped_fields


@pytest.mark.parametrize("leading", ("MSH", "msh", "SFT", "MSH|x"))
@_SIDES
def test_the_walk_refuses_a_bad_line_ahead_of_the_header(side: Any, leading: str) -> None:
    """The same four inputs at the shared walk, on both sides. ``MSH|x`` is a header id with no
    encoding characters; the walk took it as the header too."""
    message = _leading(leading, version="2.3")
    assert side.leak.has_unreachable_line(message) is True
    addresses = [address for address, _ in side.leak.unmapped_field_values(message, set())]
    assert addresses[0] == "(malformed segment)-0"
    assert not any(address.startswith("MSH-") for address in addresses)


@_SIDES
def test_the_walk_passes_a_leading_bare_id_of_the_messages_own_version(side: Any) -> None:
    """The control for the case above: ``PV2`` is defined from 2.2 on, so ahead of a 2.3 header
    it is not a line the walk refuses."""
    message = _leading("PV2", version="2.3")
    assert side.leak.has_unreachable_line(message) is False
    assert side.leak.unmapped_field_values(message, set())[0] == (f"PV2{_NO_FIELDS}", "")


@pytest.mark.parametrize("leading", ("MSH|a|b", "MSH|^~|x", "msh|a|b"))
@_SIDES
def test_an_msh_line_ahead_of_the_header_is_refused_and_the_header_skipped(
    side: Any, leading: str
) -> None:
    """``MSH|a|b`` has three fields and no encoding characters, so it is not the header. Before
    the fix it was skipped whole and the real header was walked as a later MSH line. It is
    refused: the tee adapter would take it as ITS header, and an MSH rule would miss the real one."""
    message = _leading(leading, version="2.3")
    addresses = [address for address, _ in side.leak.unmapped_field_values(message, set())]
    assert addresses[0] == "(malformed segment)-0"
    assert not any(address.startswith("MSH-") for address in addresses)  # the real header's


def test_the_tee_refuses_a_short_msh_line_ahead_of_a_header_not_in_capitals() -> None:
    """The case the refusal above is for. The tee adapter binds its header to the first line
    whose id reads ``MSH``. With the short line emitted, an ``MSH-4`` rule would rewrite that
    line and leave the real header, which the leak-check never walks, as it came."""
    message = "\r".join(("MSH|^~|x", _msh("2.3", seg="msh"), _PID))
    with pytest.raises(tee_anon.AnonError, match="no rule can reach"):
        tee_anon.anonymize(message, salt=_SALT, rules=_rules(_TEE, ("MSH-4", "drop")))


@_SIDES
def test_a_header_whose_separator_is_a_letter_of_its_id_is_refused(side: Any) -> None:
    """``MSHH^~\\&H...`` splits on ``H`` to the id ``MS``. Both sides refused it before the header
    was found by line, and they still do."""
    message = "\r".join((r"MSHH^~\&HAPPHFAC", "PIDH1HHX"))
    assert side.leak.has_unreachable_line(message) is True


@_SIDES
def test_a_header_not_in_capitals_is_still_the_header(side: Any) -> None:
    """The control for the header search: ``read_message_seps`` accepts ``msh`` with its four
    encoding characters, so that line is the header, and its version still judges a bare id."""
    lower = "\r".join((_msh("2.3", seg="msh"), _PID, "PV2"))
    addresses = [address for address, _ in side.leak.unmapped_field_values(lower, set())]
    assert f"PV2{_NO_FIELDS}" in addresses
    assert not any(address.startswith(("MSH-", "(")) for address in addresses)
    later = "\r".join((_msh("2.3", seg="msh"), _PID, "SFT"))
    assert side.leak.has_unreachable_line(later) is True
