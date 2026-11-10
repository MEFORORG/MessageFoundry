# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The leak-check decodes HL7 escape sequences before its detectors look (BACKLOG #5532).

The shape detectors and the token scan read each unmapped field as wire text. A dashed SSN whose
dashes are written ``\\X2D\\``, an id type written ``M\\X52\\``, or a token with a delimiter
written ``\\T\\`` passed both, so ``anonymize_checked`` would have emitted them. Each is decoded
now, by the escape character the message's own MSH-2 declares, and still read as written too.

Every value here is synthetic: made-up numbers in the shapes the detectors match, and made-up
tokens loaded for one test only.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from tee.anon import leak as tee_leak
from tee.anon import surrogates as tee_surrogates
from tests.test_anon_core import _NO_SCANNER

_SALT = "b214-5532-salt-0123456789abcdef"
_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_LEAKS = pytest.mark.parametrize("leak", [engine_leak, tee_leak], ids=["engine", "tee"])
_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
_SURROGATES = pytest.mark.parametrize(
    "surrogates", [engine_surrogates, tee_surrogates], ids=["engine", "tee"]
)


def _hits(leak: ModuleType, value: str, head: str = _HEAD, seg: str = "ZPD|1|||") -> list[str]:
    """The structural hits for ``value`` in an unmapped Z-segment field under ``head``."""
    hits: list[str] = leak.structural_phi_hits(f"{head}\r{seg}{value}", {"PID-3", "PID-5"})
    return hits


@_SURROGATES
def test_the_escape_character_is_read_from_msh_2(surrogates: ModuleType) -> None:
    parsed = surrogates.read_message_seps("MSH|^~#&|A")
    assert parsed is not None
    assert parsed[0].escape == "#"
    assert surrogates.Seps().escape == "\\"


@_LEAKS
@pytest.mark.parametrize(
    ("value", "shape"),
    [
        ("123\\X2D\\45\\X2D\\6789", "SSN"),
        ("555\\X2D\\555\\X2D\\1212", "phone"),
        ("(555) 555\\X2D\\1212", "phone"),
        ("\\X3132332D34352D36373839\\", "SSN"),
        ("123\\H\\-45-6789", "SSN"),
        ("M1^^^H^\\X4D52\\", "MRN"),
        ("M1^^^H^M\\X52\\", "MRN"),
    ],
    ids=[
        "ssn-hex",
        "phone-hex",
        "phone-paren-hex",
        "ssn-one-escape",
        "highlight",
        "mr-hex",
        "mr-one-letter-escaped",
    ],
)
def test_an_escaped_shape_in_an_unmapped_field_is_a_hit(
    leak: ModuleType, value: str, shape: str
) -> None:
    hits = _hits(leak, value)
    assert any(shape in hit and "ZPD-4" in hit for hit in hits), hits
    # The reason names the shape and the address, never the value.
    assert not any(re.search(r"\d{4}", hit) for hit in hits), hits


@_LEAKS
def test_each_delimiter_escape_decodes_to_the_message_s_own_delimiter(leak: ModuleType) -> None:
    """``\\S\\`` is the component separator the message declares. Under ``-`` it is a dash, so the
    value below is a dashed SSN; under ``^`` the same value is three digit groups and no hit."""
    dash_head = "MSH|-~\\&|A|B|C|D|20260101||ADT-A01|M1|P|2.5.1\rPID|1||1---H-MR||X-Y"
    assert _hits(leak, "123\\S\\45\\S\\6789", head=dash_head)
    assert _hits(leak, "123\\S\\45\\S\\6789") == []
    assert _hits(leak, "123\\T\\45\\T\\6789", head=dash_head.replace("|-~\\&", "|^~\\-")) != []
    assert _hits(leak, "123\\R\\45\\R\\6789", head=dash_head.replace("|-~\\&", "|^-\\&")) != []


@_LEAKS
def test_the_escape_character_is_the_one_msh_2_declares(leak: ModuleType) -> None:
    """A backslash is not the escape character when MSH-2 names another, so ``\\X2D\\`` there is
    text and no dash."""
    hash_head = _HEAD.replace("^~\\&", "^~#&", 1)
    assert _hits(leak, "123#X2D#45#X2D#6789", head=hash_head)
    assert _hits(leak, "123\\X2D\\45\\X2D\\6789", head=hash_head) == []


@_LEAKS
@pytest.mark.parametrize(
    "value",
    [
        "SMITH\\T\\JONES^ANN",  # an escaped subcomponent separator in a name
        "555\\.br\\555-1212",  # a line break between two runs of digits never joins them
        "A\\F\\B\\S\\C\\R\\D\\E\\",  # every delimiter escape, no shape in it
        "123\\X2\\45",  # a hex escape with an odd digit count is kept as written
        "123\\Q\\45\\X2D",  # an unknown escape, and an escape with no closing character
        "\\",  # a lone escape character
    ],
)
def test_ordinary_or_malformed_escapes_add_no_hit(leak: ModuleType, value: str) -> None:
    """The false-positive budget (ADR 0030 section 5): decoding must not light up a value with no
    shape in it, and a malformed escape must not raise."""
    assert _hits(leak, value) == []


@_LEAKS
def test_a_retarget_residue_is_decoded_too(leak: ModuleType) -> None:
    """The residue a retarget leaves goes through the same detectors (BACKLOG #3493)."""
    module = engine_anon if leak is engine_leak else tee_anon
    kept = tuple(rule for rule in module.DEFAULT_RULES if rule.path != "PID-5")
    retarget = (*kept, module.FieldRule("PID-5", module.SurrogateKind.ID))
    text = f"{_HEAD.split(chr(13))[0]}\rPID|1||1^^^H^MR||X^000\\X2D\\12\\X2D\\3456"
    hits = leak.retarget_residue_hits(text, retarget)
    assert any("SSN" in hit and "PID-5" in hit for hit in hits), hits


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_refuses_an_escaped_ssn(anon: ModuleType) -> None:
    with pytest.raises(anon.LeakError, match="SSN-shaped value in ZPD-4") as exc:
        anon.anonymize_checked(f"{_HEAD}\rZPD|1|||123\\X2D\\45\\X2D\\6789", salt=_SALT)
    assert "6789" not in str(exc.value)


@_LEAKS
def test_unescaped_message_leaves_the_header_encoding_characters(leak: ModuleType) -> None:
    text = f"{_HEAD}\rZPD|1|A\\T\\B"
    decoded = leak.unescaped_message(text)
    assert decoded.split("\r")[0] == _HEAD.split("\r")[0]
    assert decoded.split("\r")[-1] == "ZPD|1|A&B"
    plain = f"{_HEAD}\rZPD|1|AB"
    assert leak.unescaped_message(plain) is plain


# --- the token scan ------------------------------------------------------------------------------
# Made-up tokens, put into the loaded guard for one test and restored by monkeypatch. Neither is a
# real partner or vendor name.
_NAME = "zqsynth&partner"
_ESTATE = "zqsynthestate"


def _guard(leak: ModuleType) -> object:
    guard: object = leak._scanner() if leak is engine_leak else leak._GUARD
    if guard is None:
        pytest.skip("no publish guard reachable (an installed wheel has no scripts/security)")
    return guard


@_NO_SCANNER
@_LEAKS
@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ("ZQSYNTH\\T\\PARTNER", "synthetic partner"),
        ("zqsynth\\X65\\state", f"estate token ({_ESTATE})"),
    ],
    ids=["name-with-delimiter", "estate-hex"],
)
def test_an_escaped_token_is_found(
    leak: ModuleType, value: str, reason: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    guard = _guard(leak)
    monkeypatch.setattr(
        guard, "FORBIDDEN", [(re.compile(re.escape(_NAME), re.IGNORECASE), "synthetic partner")]
    )
    monkeypatch.setattr(guard, "ESTATE_TOKENS", (_ESTATE,))
    text = f"{_HEAD}\rZPD|1|{value}"
    hits: list[str] = leak.leak_report(text).hits
    assert hits.count(reason) == 1, hits
    # Control: written plainly, the same token is found once, not twice.
    plain = leak.unescape(value, leak.Seps(), "|")
    plain_hits: list[str] = leak.leak_report(f"{_HEAD}\rZPD|1|{plain}").hits
    assert plain_hits.count(reason) == 1, plain_hits


def test_merged_token_hits_scans_the_decoded_text_once_more() -> None:
    seen: list[str] = []

    def scan(text: str) -> list[str]:
        seen.append(text)
        return ["r"] if "A&B" in text else []

    for leak in (engine_leak, tee_leak):
        seen.clear()
        merge: Callable[[Callable[[str], list[str]], str], list[str]] = leak._merged_token_hits
        assert merge(scan, f"{_HEAD}\rZPD|1|A\\T\\B") == ["r"]
        assert len(seen) == 2
