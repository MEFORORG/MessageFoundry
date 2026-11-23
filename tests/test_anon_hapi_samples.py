# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The de-identified HAPI sample corpora, and the manifest that describes the set (BACKLOG #5557, #5558, #5825).

``batch_18_messages.txt``, ``oml_o21.hl7`` and ``adt_a03.txt`` under ``samples/messages/hapi-hl7v2/`` were scrubbed
by DEFAULT_RULES plus a committed overlay each, under ``tests/fixtures/anon/``. These tests hold
each corpus to its overlay in two ways, and adt_a03 in a third:

* no field of any message is undecided: a rule scrubs it or the overlay keeps it; and
* each field a rule scrubs holds what that rule writes. A name, clinician or address must come from
  the surrogate pools, a redacted field must hold the redaction marker, a date must already be
  filled, and an identifier must have the components an identifier surrogate blanks blank.

The second check cannot see every kind. A phone, an SSN, a date of birth and the first component of
an identifier are fabricated in the shape of the value they replace, so a residue of those kinds
passes it. For adt_a03 a third check covers that gap: digests of its upstream identifying values
must not match any token of the file.

The README's manifest must count each file's messages, since ``samples/send_mllp.py`` refuses a
multi-message file; that test checks only counts and the type of a one-message file. Every message
here is synthetic or upstream public test data (CLAUDE.md section 9).
"""

from __future__ import annotations

import functools
import hashlib
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

import pytest

from messagefoundry.parsing.message import Message
from messagefoundry_toolkit.anon import (
    DEFAULT_RULES,
    FieldRule,
    SurrogateKind,
    _pools,
    anonymize,
    leak_report,
    load_rules,
)
from messagefoundry_toolkit.anon.hl7 import _kind_for, _skip_obx5
from messagefoundry_toolkit.anon.surrogates import (
    _CX_KEPT_COMPONENTS,
    REDACTED,
    Seps,
    _filled_date,
    _kept_tail,
    read_message_seps,
)

_REPO = Path(__file__).resolve().parent.parent
_HAPI = _REPO / "samples" / "messages" / "hapi-hl7v2"
_FIXTURES = _REPO / "tests" / "fixtures" / "anon"


class _Corpus(NamedTuple):
    overlay: Path
    #: How many fields the overlay itself scrubs, so one added or dropped is noticed.
    overlay_fields: int
    #: The least number of values of a judged kind the surrogate check must read, so a walk that
    #: stopped early fails instead of passing empty. adt_a03 is one frozen message, so its floor
    #: is its exact count.
    min_checked: int


_CORPORA = {
    "batch_18_messages.txt": _Corpus(_FIXTURES / "batch_18.anon.toml", 19, 100),
    "oml_o21.hl7": _Corpus(_FIXTURES / "oml_o21.anon.toml", 7, 100),
    "adt_a03.txt": _Corpus(_FIXTURES / "adt_a03.anon.toml", 3, 17),
}
#: SHA-256 digests of identifying values upstream adt_a03.txt carried, held as digests only so the
#: literal text is not in this file. They are unsalted, so a short value is easily recovered from
#: one: this is not de-identification. They are the patient key, the fiscal code, the birth date, the
#: visit number, the hospital, and the sending facility. The surrogate check cannot see an id or a
#: birth date put back, since both are fabricated in the shape of the value they replace.
_ADT_A03_UPSTREAM_DIGESTS = frozenset(
    {
        "3c31063b0923ca11d10d15bdddb73c4ef829cd0040632df03a3a42b10fd10dd1",
        "e68a6c5954f614c27b39ef34431cfc351fc27a8b46246e830bfd9b04215728d8",
        "d416af96205ae608dc302a2aecdd60216e03fb9b30d560798b67713ca6035035",
        "76c11cd770cf2925c1f66f1e2fadff9d4033d6912833e24607db0c02265aaf26",
        "fd3d10d124504d6d08ba270f1d7979686ae53e5c6eed408cb00ea1b9f798991a",
        "ead80e2d92df57a355f122729044633d4b9f51046947fb84971f074186e0a84e",
    }
)
_SEGMENT = re.compile(r"[A-Z][A-Z0-9]{2}\|")
# batch_18 keeps one malformed MSH-2 on purpose: three encoding characters, so no parser can read
# its separators. The README says the scrub repaired it to this and restored it afterward. The
# check reads it repaired the same way; the file is not touched.
_MALFORMED_MSH2 = "MSH|^~}|"
_REPAIRED_MSH2 = "MSH|^~\\}|"


@functools.cache
def _messages(name: str) -> tuple[str, ...]:
    """The messages of a sample file, each a CR-joined run of segment lines from an MSH line on.
    Comment and blank lines between messages are not part of one."""
    text = (_HAPI / name).read_bytes().decode("utf-8")
    messages: list[list[str]] = []
    for line in text.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        if line.startswith(_MALFORMED_MSH2):
            line = _REPAIRED_MSH2 + line.removeprefix(_MALFORMED_MSH2)
        if line.startswith("MSH"):
            messages.append([line])
        elif messages and _SEGMENT.match(line):
            messages[-1].append(line)
        else:
            # Only a blank or comment line may be left out, or its text would be checked by nothing.
            assert not line.strip() or line.lstrip().startswith(("//", "/*", "*")), name
    return tuple("\r".join(lines) for lines in messages)


@functools.cache
def _rules(name: str) -> tuple[FieldRule, ...]:
    return load_rules(_CORPORA[name].overlay)


_CASES = [(name, i) for name in _CORPORA for i in range(len(_messages(name)))]


def _is_pool_name(comps: list[str], rep: str, seps: Seps) -> bool:
    given = comps[1] if len(comps) > 1 else ""
    return comps[0] in _pools.FAMILY_NAMES and given in _pools.GIVEN_NAMES


def _is_pool_clinician(comps: list[str], rep: str, seps: Seps) -> bool:
    return tuple(comps[:3]) in _pools.CLINICIANS


def _is_pool_address(comps: list[str], rep: str, seps: Seps) -> bool:
    return comps[0] in _pools.STREETS and tuple(comps[2:5]) in _pools.CITIES


def _is_redacted(comps: list[str], rep: str, seps: Seps) -> bool:
    return rep == REDACTED


def _is_filled_date(comps: list[str], rep: str, seps: Seps) -> bool:
    return _filled_date(rep, seps) == rep


def _is_identifier(comps: list[str], rep: str, seps: Seps) -> bool:
    # The surrogate leaves an empty id empty and still writes the kept components, as in adt_a03's
    # ``^^^^TEAM`` repetition, so an empty id passes when every component set beside it is one the
    # surrogate keeps. That also passes an empty repetition, which the surrogate writes for ``^``.
    return _kept_tail(comps, _CX_KEPT_COMPONENTS) == comps[1:]


_IDENTIFIER = (_is_identifier, "components an identifier surrogate blanks are set")
#: What each kind this can judge writes, and the reason named when a value is not that. The other
#: kinds fabricate in the replaced value's shape, so a residue of them cannot be told apart.
_CHECKS: dict[SurrogateKind, tuple[Callable[[list[str], str, Seps], bool], str]] = {
    SurrogateKind.NAME: (_is_pool_name, "not a pool name"),
    SurrogateKind.PROVIDER: (_is_pool_clinician, "not a pool clinician"),
    SurrogateKind.ADDRESS: (_is_pool_address, "not a pool address"),
    SurrogateKind.FREETEXT: (_is_redacted, "not redacted"),
    SurrogateKind.DATE: (_is_filled_date, "not a filled date"),
    SurrogateKind.ID: _IDENTIFIER,
    SurrogateKind.MRN: _IDENTIFIER,
}


def _residue(message: str, rules: tuple[FieldRule, ...]) -> tuple[int, list[str]]:
    """How many values of a judged kind were checked, and ``address#occurrence: reason`` for each
    scrubbed field whose value no rule could have written. Never the value itself."""
    parsed = read_message_seps(message)
    assert parsed is not None, "a message with no readable separators would be checked by nothing"
    seps = parsed[0]
    msg = Message.parse(message)
    checked = 0
    found: list[str] = []
    for rule in rules:
        seg_id = rule.path.split("-")[0]
        for occ in range(1, msg.count_segments(seg_id) + 1):
            value = msg.field(rule.path, occurrence=occ)
            # The anonymizer's own OBX-5 decisions: an allowlisted value is kept as captured, and
            # a date-typed one takes the date kind.
            if not value or _skip_obx5(rule, msg, occ, value, seps):
                continue
            check = _CHECKS.get(_kind_for(rule, msg, occ))
            if check is None:
                continue
            is_surrogate, reason = check
            for rep in value.split(seps.repetition):
                checked += 1
                if not is_surrogate(rep.split(seps.component), rep, seps):
                    found.append(f"{rule.path}#{occ}: {reason}")
    return checked, found


@pytest.mark.parametrize(("name", "index"), _CASES)
def test_every_message_parses(name: str, index: int) -> None:
    """Without this, an unreadable message would pass both checks below: on one, ``leak_report``
    finds no field at all."""
    assert Message.parse(_messages(name)[index]).field("MSH-9")


@pytest.mark.parametrize(("name", "index"), _CASES)
def test_no_field_of_the_corpus_is_undecided(name: str, index: int) -> None:
    report = leak_report(_messages(name)[index], rules=_rules(name))
    assert report.undecided_fields == ()
    assert report.hits == []


def test_the_coverage_check_names_a_field_whose_keep_is_removed() -> None:
    """The control for the test above: without one keep, its field is reported undecided."""
    message = next(m for m in _messages("batch_18_messages.txt") if "\rORC|" in m)
    rules = tuple(r for r in _rules("batch_18_messages.txt") if r.path != "OBR-24")
    assert "OBR-24" in leak_report(message, rules=rules).undecided_fields


@pytest.mark.parametrize("name", sorted(_CORPORA))
def test_the_overlay_scrubs_only_fields_no_default_maps(name: str) -> None:
    """Each overlay says why its scrubbed fields are not defaults. If one becomes a default, that
    reason is stale, and this is the prompt to rewrite it."""
    with _CORPORA[name].overlay.open("rb") as handle:
        overlay_fields = set(tomllib.load(handle)["hl7"].get("fields", {}))
    assert len(overlay_fields) == _CORPORA[name].overlay_fields
    assert overlay_fields.isdisjoint(rule.path for rule in DEFAULT_RULES)


@pytest.mark.parametrize("name", sorted(_CORPORA))
def test_every_scrubbed_field_holds_a_surrogate(name: str) -> None:
    checked = 0
    found: list[str] = []
    for i, message in enumerate(_messages(name)):
        count, problems = _residue(message, _rules(name))
        checked += count
        found += [f"msg{i + 1} {problem}" for problem in problems]
    # Far fewer judged values than the corpus holds means the walk stopped reading fields, and
    # then an empty list below would prove nothing.
    assert checked >= _CORPORA[name].min_checked
    assert found == []


# One synthetic message with a value no rule writes, in a field of each kind the check can judge.
_UNSCRUBBED = "\r".join(
    (
        r"MSH|^~\&|SAPP|SFAC|RAPP|RFAC|20260315142233||ADT^A01|MSGCTRL|P|2.5.1",
        "EVN|A01|20260315142233",
        "PID|1|429313192^8^M10|12345^^^HOSP^MR||UPSTREAMFAMILY^GIVEN||19800101|M|||"
        "1 UPSTREAM RD^^TESTVILLE^ZZ^00001|510",
        "PV1|1|I|N77^7714^01",
        "ORC|NW|||||||||OPERATOR51",
    )
)
_CONTROL_RULES = tuple(
    FieldRule(path, kind)
    for path, kind in (
        ("EVN-2", SurrogateKind.DATE),
        ("PID-2", SurrogateKind.MRN),
        ("PID-5", SurrogateKind.NAME),
        ("PID-11", SurrogateKind.ADDRESS),
        ("PID-12", SurrogateKind.FREETEXT),
        ("PV1-3", SurrogateKind.FREETEXT),
        ("ORC-10", SurrogateKind.PROVIDER),
    )
)


def test_the_surrogate_check_fires_on_each_kind_it_judges() -> None:
    """The positive control: an unscrubbed value of each judged kind is named."""
    checked, found = _residue(_UNSCRUBBED, _CONTROL_RULES)
    assert checked == len(_CONTROL_RULES)
    assert {entry.split("#")[0] for entry in found} == {rule.path for rule in _CONTROL_RULES}


def test_the_surrogate_check_passes_what_the_anonymizer_writes() -> None:
    """The other control: the same message, anonymized by the same rules, is not named."""
    scrubbed = anonymize(_UNSCRUBBED, salt="hapi-samples-control-salt", rules=_CONTROL_RULES)
    checked, found = _residue(scrubbed, _CONTROL_RULES)
    assert checked == len(_CONTROL_RULES)
    assert found == []


@pytest.mark.parametrize(
    ("rep", "expected"),
    [
        ("^^^^TEAM", True),  # what the surrogate writes for an empty id beside a type code
        ("6075145^^^PK^PK", True),
        ("", True),  # what the surrogate writes for ``^``
        ("^", False),
        ("^8^M10", False),  # a check digit left beside an empty id
        ("^^^^TEAM^^20260101", False),  # an effective date left beside an empty id
    ],
)
def test_the_identifier_check_judges_an_empty_id(rep: str, expected: bool) -> None:
    assert _is_identifier(rep.split("^"), rep, Seps()) is expected


def _tokens(text: str) -> set[str]:
    """Every value in ``text``, comment lines included, split on the separators its first MSH
    declares."""
    parsed = read_message_seps(text.replace("\r\n", "\r").split("\r", 1)[0])
    assert parsed is not None
    seps = parsed[0]
    splitters = {"|", seps.component, seps.repetition, seps.subcomponent, "\r", "\n"}
    return set(re.split("|".join(map(re.escape, splitters)), text)) - {""}


def test_no_upstream_identifier_is_left_in_adt_a03() -> None:
    """A put-back id or birth date passes the surrogate check, so the upstream values are pinned
    absent by digest. A token of the committed file is found, so the tokens were read; on the
    upstream file this test fails."""
    digests = {
        hashlib.sha256(t.encode()).hexdigest()
        for t in _tokens((_HAPI / "adt_a03.txt").read_bytes().decode("utf-8"))
    }
    assert digests.isdisjoint(_ADT_A03_UPSTREAM_DIGESTS)
    assert hashlib.sha256(b"ADT").hexdigest() in digests


_MANIFEST_ROW = re.compile(r"^\| `([^`]+)` \| ([^|]+) \| [^|]+ \| *(\d+) \|", re.M)


@functools.cache
def _readme() -> str:
    return (_HAPI / "README.md").read_text(encoding="utf-8")


def _manifest() -> dict[str, tuple[str, int]]:
    rows = _MANIFEST_ROW.findall(_readme())
    return {name: (msg_type.strip(), int(count)) for name, msg_type, count in rows}


def test_the_manifest_lists_every_sample_file() -> None:
    files = {p.name for p in _HAPI.iterdir() if p.suffix in (".hl7", ".txt")}
    assert len(files) >= 7
    assert set(_manifest()) == files


@pytest.mark.parametrize("name", sorted(_manifest()))
def test_the_manifest_counts_each_files_messages(name: str) -> None:
    msg_type, count = _manifest()[name]
    messages = _messages(name)
    assert len(messages) == count
    if count == 1:
        assert Message.parse(messages[0]).field("MSH-9") == msg_type.split(" ")[0]


def test_the_manifest_total_is_the_sum_of_its_rows() -> None:
    total = re.search(r"Across the set: \*\*(\d+) messages\*\*", _readme())
    assert total is not None
    assert int(total.group(1)) == sum(count for _type, count in _manifest().values())
