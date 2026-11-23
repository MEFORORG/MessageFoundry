# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Residual anonymizer gaps of vault BACKLOG #5532, #5533, #5534, #5540, #5541 and #5654.

* #5541: the site-code check reads a prefix table of its own, loaded in ``surrogates.py``, while
  the report's liveness reads the publish guard's. After a reload of one alone, a report called
  the denylist live while the site-code check matched other prefixes or none. It now reads not
  live, naming the split. A source with a ``[site_prefix]`` entry that is not two digits reads
  not live too (BACKLOG #5366).
* #5540: under a digit MSH-1 or MSH-2, the site-code pass wrote fabricated digits that could be
  a separator, so a field shifted past its rule. The pass now writes no such digit.
* #5534: an identifier surrogate lettered a non-ASCII subcomponent separator or escape character,
  rewrote an escape body letter by letter, and gave an empty id six fabricated digits.
* #5654: an ``MR`` subcomponent in XCN.13 or XON.7, a default-ignorable character outside Cc and
  Cf, a fullwidth digit or letter, a dashed SSN or phone hidden by an invisible or a ``\\H\\``
  escape and a multi-dot IPv6 trailer passed. White space a consumer shows, and a dot that joins
  a version number to an address, are read as origin/main read them.

Every value here is synthetic: made-up ids and site prefixes, IPv6 addresses built from the
unallocated 4000::/3 range, and tokens that name no real partner or vendor.
"""

from __future__ import annotations

import contextlib
import random
from collections.abc import Iterator
from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry.parsing._builtin_hl7 import _RICH_TEXT_MAP, MAX_ESCAPE_REPEAT
from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from messagefoundry_toolkit.anon.keying import Keyer
from tee.anon import leak as tee_leak
from tee.anon import surrogates as tee_surrogates
from tests.test_anon_core import _NO_SCANNER

_SALT = "wave2-a-salt-0123456789abcdef"
_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])
_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
_SURROGATES = pytest.mark.parametrize(
    "surrogates", [engine_surrogates, tee_surrogates], ids=["engine", "tee"]
)
#: A sectioned token source with every floor section filled. The prefix is made up.
_TOKENS = "[names]\nzqsynthpartner | synthetic partner\n[estate]\nzqsynthestate\n[site_prefix]\n"


def _zpd(value: str, head: str = _HEAD) -> str:
    return f"{head}\rZPD|1|||{value}"


def _guards() -> list[ModuleType]:
    """The two publish-guard instances, the toolkit's and the tee's, each a module of its own."""
    guards: list[ModuleType] = []
    with contextlib.suppress(engine_leak.LeakCheckUnavailable):
        guards.append(engine_leak._scanner())
    if isinstance(tee_leak._GUARD, ModuleType):
        guards.append(tee_leak._GUARD)
    return guards


@contextlib.contextmanager
def _token_source(
    monkeypatch: pytest.MonkeyPatch, prefixes: str, *, guards: bool, surrogates: bool
) -> Iterator[None]:
    """``prefixes`` under ``[site_prefix]`` in a full token source, reloaded into the guards and
    the two ``surrogates`` tables as asked. On the way out the source goes back and every table is
    reloaded under it, so no other test sees these."""
    _guards()  # loaded before the source changes, as tests/test_anon_b224_5632.py does
    try:
        monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", _TOKENS + prefixes)
        if guards:
            for guard in _guards():
                guard.reload_tokens()
        if surrogates:
            engine_surrogates.reload_site_prefixes()
            tee_surrogates.reload_site_prefixes()
        yield
    finally:
        monkeypatch.undo()
        for guard in _guards():
            guard.reload_tokens()
        engine_surrogates.reload_site_prefixes()
        tee_surrogates.reload_site_prefixes()


# --- #5541: the site-code table and the guard's ----------------------------------------------------


@_NO_SCANNER
@_LEAKS
def test_both_tables_reloaded_read_live(leak: ModuleType, monkeypatch: pytest.MonkeyPatch) -> None:
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        report = leak.leak_report(f"{_HEAD}\rPV2|1", rules=engine_anon.DEFAULT_RULES)
        assert leak.denylist_is_live(report), report.token_floor_reason


@_NO_SCANNER
@_LEAKS
def test_a_guard_reload_alone_reads_not_live(
    leak: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The guard counts a prefix the site-code check never loaded, so the report says so."""
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=False):
        if set(engine_surrogates._SITE_PREFIXES) == {"97"}:
            pytest.skip("the real token source already loads this made-up prefix")
        report = leak.leak_report(f"{_HEAD}\rPV2|1", rules=engine_anon.DEFAULT_RULES)
        assert not leak.denylist_is_live(report)
        reason = report.token_floor_reason or ""
        assert "site-code check" in reason
        # Counts only: the reason never names a prefix, which names a real estate.
        assert "97" not in reason


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize("prefixes", ["975\n", "97\n975\n"], ids=["three-digit", "two-and-three"])
def test_one_source_with_a_prefix_that_is_not_two_digits_reads_not_live(
    leak: ModuleType, prefixes: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The site-code table loads two-digit prefixes only, so the guard refuses a source holding
    another (BACKLOG #5366), and the advice does not ask to load a source that loaded."""
    with _token_source(monkeypatch, prefixes, guards=True, surrogates=True):
        report = leak.leak_report(f"{_HEAD}\rPV2|1", rules=engine_anon.DEFAULT_RULES)
        assert not leak.denylist_is_live(report)
        assert engine_surrogates.SITE_PREFIX_WIDTH_MARK in (report.token_floor_reason or "")
        advice = leak.refusal_advice(report, denylist_refused=True)
        assert "two-digit prefixes only" in advice
        assert "Load the denylist token source" not in advice


@_NO_SCANNER
@_SIDES
def test_the_opt_in_refuses_on_a_split_table(
    anon: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=False):
        if set(engine_surrogates._SITE_PREFIXES) == {"97"}:
            pytest.skip("the real token source already loads this made-up prefix")
        with pytest.raises(
            anon.LeakError, match="denylist not live: the site-code check"
        ) as caught:
            anon.anonymize_checked(f"{_HEAD}\rPV2|1", salt=_SALT, require_live_denylist=True)
    # The source is loaded, so the advice names the split, not a source to load.
    assert "prefixes differ from the publish guard's [site_prefix] table" in str(caught.value)
    assert "Load the denylist token source." not in str(caught.value)


@_LEAKS
@pytest.mark.parametrize(
    "reason",
    [
        f"{engine_surrogates.SITE_PREFIX_SPLIT_LEAD} 1 two-digit prefix(es)",
        f"1 [site_prefix] entry is not exactly 2 ASCII digits, and "
        f"{engine_surrogates.SITE_PREFIX_WIDTH_MARK} (surrogates.py)",
    ],
    ids=["split", "width"],
)
def test_the_split_advice_names_no_removal_of_a_site_prefix_entry(
    leak: ModuleType, reason: str
) -> None:
    """The publish guard reads every numeric ``[site_prefix]`` entry, so advice to remove or edit
    one would delete a guard detector (BACKLOG #5541)."""
    report = leak.LeakReport(
        hits=[],
        unmapped_fields=(),
        structural_hits=[],
        token_tables_live=False,
        token_floor_reason=reason,
    )
    advice = leak.refusal_advice(report, denylist_refused=True)
    assert "[site_prefix]" in advice  # the control: this is a site-prefix step
    assert "Load the denylist token source" not in advice
    for verb in ("remove", "delete", "drop", "edit", "rename", "replace", "change"):
        assert verb not in advice.lower(), verb


# --- #5540: the site-code pass under a digit separator ---------------------------------------------


@_SIDES
@pytest.mark.parametrize("sep", ["0", "3", "4", "8"])
def test_the_site_code_pass_never_writes_a_digit_field_separator(
    anon: ModuleType, sep: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every site code here holds no ``sep``, so the line splits as written; the surrogate must
    hold none either, or the field after it moves (BACKLOG #5540)."""
    # Many codes, so a fabricated digit drawn from all ten would hit ``sep`` in almost every run.
    codes = [f"97{n:04d}" for n in range(1000, 10000, 97) if sep not in f"{n:04d}"]
    assert len(codes) >= 20
    fields = ["ZPD", "1", *codes, "AFTERMARK"]
    header = sep.join(
        # No other value holds a digit, so only the site codes can carry one.
        ("MSH", "^~\\&", "APP", "FAC", "RCV", "RFAC", "", "", "ADT", "M", "P", "")
    )
    raw = f"{header}\r{sep.join(fields)}"
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        out = anon.anonymize(raw, salt=_SALT)
    line = next(seg for seg in out.split("\r") if seg.startswith("ZPD"))
    written = line.split(sep)
    assert len(written) == len(fields), "a fabricated site code held the field separator"
    assert written[-1] == "AFTERMARK"
    for code, fake in zip(codes, written[2:-1], strict=True):
        assert fake != code and len(fake) == len(code)


@_SURROGATES
def test_the_site_code_pass_never_writes_a_digit_component_separator(
    surrogates: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seps = surrogates.Seps(component="7", repetition="~", escape="\\", subcomponent="&")
    with _token_source(monkeypatch, "92\n", guards=False, surrogates=True):
        fakes = [
            surrogates.scrub_site_codes(f"92{n:04d}", Keyer(_SALT), seps)
            for n in range(1000, 1300, 7)
            if "7" not in f"{n:04d}"
        ]
    assert fakes and not any("7" in fake for fake in fakes)


# --- #5534: identifier surrogates keep structure, not content --------------------------------------


@_SURROGATES
def test_an_escape_sequence_in_an_id_becomes_letters_of_its_width(surrogates: ModuleType) -> None:
    seps = surrogates.Seps()
    for rep in ("AB\\E\\CD", "AB\\X41\\CD", "AB\\T\\CD", "\\123456\\", "\\X3132\\"):
        out = surrogates.surrogate_id(f"{rep}^^^H^MR", Keyer(_SALT), seps)
        fabricated = out.split("^", 1)[0]
        assert "\\" not in fabricated, out
        # The width holds, so an id that is one escape sequence does not shrink to one letter.
        assert len(fabricated) == len(rep), out
    # Two subcomponents: HL7 splits before it decodes, so no escape closes across the ``&``.
    out = surrogates.surrogate_id("AB\\C&D\\E^^^H^MR", Keyer(_SALT), seps)
    assert out.split("^", 1)[0].count("&") == 1, out


@_SURROGATES
@pytest.mark.parametrize("salt", [_SALT, _SALT + "1", _SALT + "2"])
def test_a_digit_declared_as_a_separator_is_still_fabricated(
    surrogates: ModuleType, salt: str
) -> None:
    """Under MSH-2 ``^~\\5`` a ``5`` in the real id is a declared subcomponent separator; copying
    it kept the real id whole. Every digit is fabricated, and none is a declared ``5``."""
    seps = surrogates.Seps(subcomponent="5")
    for real in ("555555", "1525354"):
        fabricated = surrogates.surrogate_id(f"{real}^^^H^MR", Keyer(salt), seps).split("^", 1)[0]
        assert fabricated != real and "5" not in fabricated, fabricated
        assert len(fabricated) == len(real) and fabricated.isdigit(), fabricated


@_SURROGATES
@pytest.mark.parametrize("real", ["123-45-6789", "123456789", "NID 1234"])
def test_an_ssn_surrogate_writes_no_declared_separator_digit(
    surrogates: ModuleType, real: str
) -> None:
    """Under MSH-2 ``^~\\5`` a fabricated ``5`` would split the id into subcomponents (#5540)."""
    seps = surrogates.Seps(subcomponent="5")
    for n in range(40):
        fabricated = surrogates.surrogate_ssn(f"{real}^^^H^SS", Keyer(f"{_SALT}{n}"), seps)
        assert "5" not in fabricated.split("^", 1)[0], fabricated


def _fabricated_before(char: str) -> bool:
    """True where the id surrogate before BACKLOG #5534 wrote a fabricated character in place of
    ``char``: a digit, a letter or a non-ASCII character. It kept only ASCII punctuation and
    spaces."""
    return char.isdigit() or char.isalpha() or not char.isascii()


#: Ids and the separators they are read under, where a declared separator or escape character is
#: a letter, a digit or not ASCII. The first three are the reviewer's cases of round 022b1dea.
_DECLARED_LETTER_CASES = [
    ({"escape": "Q"}, "QWERTYQ7Q"),
    ({"escape": "\u00e9"}, "J\u00e9R\u00d4ME12"),
    ({"subcomponent": "\u00e9"}, "AB\u00e9CD"),
    ({"subcomponent": "\u00a7", "escape": "\u00b6"}, "AB\u00a7CD\u00b6"),
    ({"subcomponent": "S", "escape": "\\"}, "A\\BSC\\D"),
    ({"escape": "Q"}, "AQBQC&DQ"),
    ({"subcomponent": "5"}, "1525354"),
]


@_SURROGATES
@pytest.mark.parametrize(("declared", "real"), _DECLARED_LETTER_CASES)
def test_an_id_surrogate_keeps_no_character_it_used_to_fabricate(
    surrogates: ModuleType, declared: dict[str, str], real: str
) -> None:
    """A declared escape or subcomponent character that is a letter, a digit or not ASCII is
    fabricated like any other character of its kind. Keeping it kept a real character of the id,
    so ``QWERTYQ7Q`` under escape ``Q`` left its last ``Q``. A character fabricated under every
    one of many salts is not copied; a copied one matches the real id under all of them."""
    seps = surrogates.Seps(**declared)
    outs = [
        surrogates.surrogate_id(f"{real}^^^H^MR", Keyer(f"{_SALT}{n}"), seps).split("^", 1)[0]
        for n in range(40)
    ]
    reserved = "".join(declared.values()) + "|^~&\\"
    for out in outs:
        assert len(out) == len(real) and out.isascii(), out
        # No fabricated character is a declared separator or escape character, so a fabricated
        # letter never pairs with another into an escape sequence the sender did not write.
        assert not any(
            c in reserved for c, r in zip(out, real, strict=True) if _fabricated_before(r)
        )
        assert seps.escape not in out, out
    for at, char in enumerate(real):
        if _fabricated_before(char):
            assert any(out[at] != char for out in outs), (real, at)


@_SURROGATES
def test_the_reviewers_ids_leave_no_real_character(surrogates: ModuleType) -> None:
    for declared, real in _DECLARED_LETTER_CASES[:2]:
        out = surrogates.surrogate_id(f"{real}^^^H^MR", Keyer(_SALT), surrogates.Seps(**declared))
        fabricated = out.split("^", 1)[0]
        assert declared["escape"] not in fabricated, fabricated
        assert fabricated.isascii(), ascii(fabricated)


@_SURROGATES
def test_no_id_surrogate_keeps_a_character_the_old_one_fabricated(
    surrogates: ModuleType,
) -> None:
    """Differential against the surrogate before BACKLOG #5534 (:func:`_fabricated_before`), over
    ids drawn from letters, digits, non-ASCII characters, punctuation and the declared characters,
    under declarations that make a letter, a digit or a non-ASCII character a separator."""
    pool = "AQZ059\u00e9\u00d4\u00a7\u00b6&\\-. S"
    declarations = [
        {},
        {"escape": "Q"},
        {"escape": "\u00e9"},
        {"subcomponent": "\u00a7", "escape": "\u00b6"},
        {"subcomponent": "S"},
        {"subcomponent": "5", "escape": "9"},
    ]
    draw = random.Random(5534)
    for declared in declarations:
        seps = surrogates.Seps(**declared)
        for _ in range(60):
            real = "".join(draw.choice(pool) for _ in range(draw.randrange(1, 10)))
            outs = [
                surrogates.surrogate_id(f"{real}^^^H^MR", Keyer(f"{_SALT}{n}"), seps).split("^", 1)[
                    0
                ]
                for n in range(25)
            ]
            for at, char in enumerate(real):
                if _fabricated_before(char):
                    assert any(out[at] != char for out in outs), (declared, ascii(real), at)


@_SURROGATES
def test_an_empty_id_stays_empty(surrogates: ModuleType) -> None:
    seps = surrogates.Seps()
    for fn in (surrogates.surrogate_id, surrogates.surrogate_mrn, surrogates.surrogate_ssn):
        assert fn("^^^H^MR", Keyer(_SALT), seps) == "^^^H^MR"
        assert fn("", Keyer(_SALT), seps) == ""
    assert (
        surrogates.surrogate_field(
            engine_anon.SurrogateKind.MRN, "1^^^H^MR~~2^^^H^MR", Keyer(_SALT), seps
        ).split("~")[1]
        == ""
    )


# --- #5654: the shapes the leak-check passed --------------------------------------------------------


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "1234^DOE^JOHN^^^^^^AUTH^^^^X&MR",  # XCN.13
        "ACME^L^^^^AUTH^X&MR",  # XON.7
        "12345^M\u034fR",  # a combining grapheme joiner, category Mn
        "12345^MR\ufe0f",  # a variation selector, category Mn
        "12345^M\u3164R",  # a Hangul filler, category Lo
        "12345^\uff2d\uff32",  # fullwidth MR
        "12345^\U0001d426\U0001d42b",  # mathematical bold small m and r, folded to lower case
        "12345^M\u2065R",  # U+2065, unassigned but default-ignorable
    ],
    ids=[
        "xcn-13",
        "xon-7",
        "cgj",
        "variation-selector",
        "hangul-filler",
        "fullwidth",
        "math-bold",
        "u2065",
    ],
)
def test_an_mrn_type_the_check_passed_is_a_hit(leak: ModuleType, value: str) -> None:
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any("MRN" in hit and "ZPD-4" in hit for hit in hits), hits


@_LEAKS
@pytest.mark.parametrize(
    "value",
    ["1234^DOE^JOHN^^^^^^AUTH^^^X&MR", "ACME^L^^^^X&MR", "70553^PET&MR^C4"],
    ids=["xcn-12", "xon-6", "ce-2"],
)
def test_an_mr_subcomponent_beside_an_id_type_component_is_no_hit(
    leak: ModuleType, value: str
) -> None:
    """Near-miss controls: the neighbouring components are not read subcomponent by subcomponent."""
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "123-45-67\\XAD\\89",  # a soft hyphen, escaped
        "123-45-67\u00ad89",  # a soft hyphen, written
        "555-555-01\\X00\\99",  # a NUL, escaped
        "123\\H\\-45-6789",  # a display that shows highlighting drops the escape
        "555-55\\N\\5-0199",
    ],
    ids=["soft-hyphen-escaped", "soft-hyphen", "nul", "highlight", "highlight-off"],
)
def test_a_dashed_shape_behind_an_invisible_or_highlight_is_a_hit(
    leak: ModuleType, value: str
) -> None:
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any("ZPD-4" in hit for hit in hits), hits


#: The control characters a consumer shows as white space, written and escaped. origin/main read
#: none of them as dropped in the shape or token readings, so none may join two runs there.
_SHOWN_WHITESPACE = pytest.mark.parametrize(
    "space",
    ["\t", "\x0c", "\x85", "\x0b", "\\X09\\", "\\X0C\\", "\\X85\\"],
    ids=["tab", "form-feed", "nel", "vertical-tab", "tab-escaped", "ff-escaped", "nel-escaped"],
)


@_LEAKS
@_SHOWN_WHITESPACE
def test_white_space_a_consumer_shows_joins_no_shape(leak: ModuleType, space: str) -> None:
    """origin/main passed these; the readings that drop invisible characters keep white space."""
    for value in (f"1{space}23-45-6789", f"55{space}5-555-0199"):
        assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == [], value
    # The control: the same value behind a character a consumer drops is a hit.
    hits = leak.structural_phi_hits(_zpd("1​23-45-6789"), {"PID-3", "PID-5"})
    assert any("ZPD-4" in hit for hit in hits), hits


#: A header whose field separator is ``-``, so a dashed SSN is cut across fields.
_DASH_HEAD = "-".join(
    ("MSH", "^~\\&", "A", "B", "C", "D", "20260101", "", "ADT^A01", "M1", "P", "2.5.1")
)


@_LEAKS
@pytest.mark.parametrize(
    "tail",
    ["123-45-67\u00ad89", "123-45-67\\XAD\\89", "123\\H\\-45-6789", "123-45\\N\\-6789"],
    ids=["soft-hyphen", "soft-hyphen-escaped", "highlight", "highlight-off"],
)
def test_a_cut_shape_behind_an_invisible_or_highlight_is_a_hit(leak: ModuleType, tail: str) -> None:
    """The cut-across check takes the readings the one-field detectors take (BACKLOG #5654)."""
    hits = leak.structural_phi_hits(f"{_DASH_HEAD}\rZPD-1-{tail}", set())
    assert any("cut by the field separator" in hit for hit in hits), hits


@_LEAKS
@_SHOWN_WHITESPACE
def test_white_space_a_consumer_shows_joins_no_cut_shape(leak: ModuleType, space: str) -> None:
    assert leak.structural_phi_hits(f"{_DASH_HEAD}\rZPD-1-1{space}23-45-6789", set()) == []
    hits = leak.structural_phi_hits(f"{_DASH_HEAD}\rZPD-1-1​23-45-6789", set())
    assert any("cut by the field separator" in hit for hit in hits), hits


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "zqsynth\\H\\partner",
        "zqsynth\\N\\partner",
        "zqsynth\\X00\\partner",
        "zqsynth\u200bpartner",
        "zqsynth\u034fpartner",
    ],
    ids=["highlight", "highlight-off", "nul-escaped", "zero-width-space", "cgj"],
)
def test_a_token_behind_an_invisible_or_highlight_is_a_hit(
    leak: ModuleType, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The token scan takes the readings the cut-shape check takes (BACKLOG #5654)."""
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert "synthetic partner" in leak.leak_report(_zpd(value)).hits


@_NO_SCANNER
@_LEAKS
@_SHOWN_WHITESPACE
def test_white_space_a_consumer_shows_joins_no_token(
    leak: ModuleType, space: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert leak.leak_report(_zpd(f"zqsynth{space}partner")).hits == []
        assert "synthetic partner" in leak.leak_report(_zpd("zqsynth​partner")).hits


@_NO_SCANNER
@_LEAKS
def test_a_token_across_a_line_break_is_no_hit(
    leak: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping invisible characters line by line never joins two lines into a token."""
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert leak.leak_report(f"{_zpd('zqsynth')}\rpartner|1").hits == []


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "4000:a1::5.1.2",
        "::ffff:8.8.8.8.1.2",  # an IPv4-mapped address with two trailing groups
        "::8.8.8.8.1.2",  # an IPv4-compatible one
        "::ffff:1.2.8.8.8.8",  # the IPv4 part last
    ],
)
def test_an_ipv6_form_the_check_passed_is_a_hit(leak: ModuleType, value: str) -> None:
    hits = leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"})
    assert any(leak.IPV6_REASON in hit for hit in hits), hits


@_LEAKS
@pytest.mark.parametrize("value", ["fe80::1.2", "fe80::1.fd00::5", "::ffff:10.0.0.1"])
def test_an_allowed_dotted_ipv6_form_is_no_hit(leak: ModuleType, value: str) -> None:
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []


@_LEAKS
@pytest.mark.parametrize("value", ["1.2.3::a", "1.2.2600::1"])
def test_a_dot_joined_non_address_is_no_hit(leak: ModuleType, value: str) -> None:
    """origin/main passed these, which hold no address before the dot; a run is not cut at a dot
    with no colon before it, so ``3::a`` or ``2600::1`` is not judged on its own. A dot after an
    address, as in ``fe80::1.2600::1``, does cut (tests/test_anon_b224_5654.py)."""
    assert leak.structural_phi_hits(_zpd(value), {"PID-3", "PID-5"}) == []
    # The control: a routable address in the same field is a hit.
    hits = leak.structural_phi_hits(_zpd("4000:a1::5"), {"PID-3", "PID-5"})
    assert any(leak.IPV6_REASON in hit for hit in hits), hits


@_SURROGATES
@pytest.mark.parametrize(
    "part",
    [
        "9\u034f71234",  # a combining grapheme joiner
        "971234\ufe0f",  # a variation selector
        "\uff19\uff17\uff11\uff12\uff13\uff14",  # fullwidth digits
        "97\uff11\uff12\uff13\uff14",
    ],
    ids=["cgj", "variation-selector", "fullwidth", "fullwidth-tail"],
)
def test_a_site_code_the_check_passed_is_found_and_scrubbed(
    surrogates: ModuleType, part: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    seps = surrogates.Seps()
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        assert surrogates._reads_as_site_code(part, seps, "|")
        scrubbed = surrogates.scrub_site_codes(part, Keyer(_SALT), seps)
        assert scrubbed != part and not surrogates._reads_as_site_code(scrubbed, seps, "|")


@_SURROGATES
def test_a_fullwidth_digit_in_an_escape_body_reads_as_the_plain_reading_does(
    surrogates: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    seps = surrogates.Seps()
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        assert surrogates._reads_as_site_code("\\Z97\uff11\uff12\uff13\uff14 x\\", seps, "|")


@_SURROGATES
@pytest.mark.parametrize(
    "part",
    ["\\Z97\u00b9\u00b2\u00b3\u2074 x\\", "\\Z97\u2460\u2461\u2462\u2463 x\\"],
    ids=["superscript", "circled"],
)
def test_a_folded_digit_in_an_escape_body_reads_as_a_site_code(
    surrogates: ModuleType, part: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``\\D`` splits a superscript or circled digit off, so the body is also split folded."""
    seps = surrogates.Seps()
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        assert surrogates._reads_as_site_code(part, seps, "|")
        assert surrogates.scrub_site_codes(part, Keyer(_SALT), seps) != part


@_SURROGATES
@pytest.mark.parametrize(
    "part",
    [
        "X\\971234\u0663\\Y",  # an Arabic-Indic digit after the code
        "X\\971234\uff15\\Y",  # a fullwidth digit after the code
        "X\\\uff15971234\\Y",  # a fullwidth digit before it
        "X\\Z971234\u0663\\Y",
    ],
    ids=["arabic-indic-tail", "fullwidth-tail", "fullwidth-lead", "z-arabic-indic-tail"],
)
def test_an_ascii_code_beside_a_non_ascii_digit_in_an_escape_body_is_found(
    surrogates: ModuleType, part: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A split at every non-digit keeps a non-ASCII digit on the code, so the body is also split
    at every character that is not an ASCII digit, as it was before (BACKLOG #5654)."""
    seps = surrogates.Seps()
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        assert surrogates._reads_as_site_code(part, seps, "|")
        assert surrogates.scrub_site_codes(part, Keyer(_SALT), seps) != part


def _header(sep: str, encoding: str = "^~\\&") -> str:
    return sep.join(
        ("MSH", encoding, "A", "B", "C", "D", "20260101", "", "ADT^A01", "M1", "P", "2.3")
    )


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    "sep", ["\t", "\x1f", "\u00ad"], ids=["tab", "unit-separator", "soft-hyphen"]
)
def test_an_invisible_field_separator_keeps_two_fields_apart(
    leak: ModuleType, sep: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Dropping invisible characters keeps the declared separators, so two fields never join
    into a token (BACKLOG #5654). The same token inside one field, behind an invisible character
    that is no separator, is still found."""
    head = _header(sep)
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert leak.leak_report(f"{head}\rZPD{sep}1{sep}zqsynth{sep}partner").hits == []
        within = leak.leak_report(f"{head}\rZPD{sep}1{sep}zqsynth\u200bpartner").hits
        assert "synthetic partner" in within


@_NO_SCANNER
@_LEAKS
def test_an_invisible_component_separator_keeps_two_components_apart(
    leak: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    head = _header("|", "\x1f~\\&")
    with _token_source(monkeypatch, "97\n", guards=True, surrogates=True):
        assert leak.leak_report(f"{head}\rZPD|1|zqsynth\x1fpartner").hits == []
        assert "synthetic partner" in leak.leak_report(f"{head}\rZPD|1|zqsynth\x1epartner").hits


@_SURROGATES
@pytest.mark.parametrize("salt", [_SALT, _SALT + "1", _SALT + "2"])
def test_an_identifier_surrogate_writes_no_digit_field_separator(
    surrogates: ModuleType, salt: str
) -> None:
    """Under MSH-1 ``5`` a fabricated ``5`` would split the field (BACKLOG #5540)."""
    seps = surrogates.Seps(field="5")
    for real in ("1234678", "98764321", "A0049"):
        out = surrogates.surrogate_id(f"{real}^^^H^MR", Keyer(salt), seps)
        assert "5" not in out, out
    for real in ("123-46-7890", "123467890"):
        out = surrogates.surrogate_ssn(f"{real}^^^H^SS", Keyer(salt), seps)
        assert "5" not in out, out


@_SIDES
def test_anonymize_under_a_digit_field_separator_keeps_every_field(
    anon: ModuleType, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Many ids, so a fabricated digit drawn from all ten would hit ``5`` in almost every run."""
    ids = [f"{n:07d}" for n in range(1000000, 1400000, 9973) if "5" not in f"{n:07d}"]
    assert len(ids) >= 20
    pid = "5".join(("PID", "1", "", "~".join(f"{i}^^^H^MR" for i in ids), "", "DOE^JOHN"))
    raw = f"{_header('5')}\r{pid}"
    with _token_source(monkeypatch, "97\n", guards=False, surrogates=True):
        out = anon.anonymize(raw, salt=_SALT)
    line = next(seg for seg in out.split("\r") if seg.startswith("PID"))
    assert len(line.split("5")) == len(pid.split("5")), "a fabricated id held the field separator"


# --- #5532: the decoder's copy of the engine's formatting commands ---------------------------------


@_SURROGATES
def test_the_spacing_commands_are_the_engines(surrogates: ModuleType) -> None:
    """``surrogates.py`` cannot import the engine (the tee copy is standalone), so it holds a copy
    of the commands that write a break or spaces; this pins the copy to the engine's map."""
    writes_text = {command for command, text in _RICH_TEXT_MAP.items() if text}
    assert writes_text == surrogates._SPACING_FORMAT_COMMANDS
    assert surrogates._MAX_ESCAPE_REPEAT == MAX_ESCAPE_REPEAT
