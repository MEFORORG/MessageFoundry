# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A site code is found and scrubbed on any reading a consumer can take (BACKLOG #5632, and #5533
item 8's site-code limb).

The site-code scrub and its leak-check twin matched each component and subcomponent as written
only, so a site code joined to an escaped delimiter (``971234\\S\\X``) or written with a hex escape
(``97\\X31\\234``) survived for any consumer that unescapes the field. Both now read a part as
written, decoded, and decoded and then split again on the message's delimiters and its field
separator, and the scrub replaces the whole part as written with digits of its own width.

Every value here is synthetic: a made-up two-digit site prefix loaded for these tests only, and
made-up numbers.
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator
from types import ModuleType

import pytest

import messagefoundry_toolkit.anon as engine_anon
import tee.anon as tee_anon
from messagefoundry_toolkit.anon import leak as engine_leak
from messagefoundry_toolkit.anon import surrogates as engine_surrogates
from messagefoundry_toolkit.anon.keying import Keyer
from tee.anon import surrogates as tee_surrogates
from tests.test_anon_core import _NO_SCANNER

_SALT = "b224-5632-salt-0123456789abcdef"
_HEAD = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||1^^^H^MR||X^Y"
_SURROGATES = pytest.mark.parametrize(
    "surrogates", [engine_surrogates, tee_surrogates], ids=["engine", "tee"]
)
_SIDES = pytest.mark.parametrize("anon", [engine_anon, tee_anon], ids=["engine", "tee"])
_PREFIX = "97"


def _zpd(value: str, head: str = _HEAD) -> str:
    return f"{head}\rZPD|1|||{value}"


@pytest.fixture
def site_prefix(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """A synthetic site prefix in BOTH copies. The engine's scanner loads first, so it never reads
    the patched token source (as ``tests/test_anon_b193_2330.py`` does)."""
    with contextlib.suppress(engine_leak.LeakCheckUnavailable):
        engine_leak._scanner()
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", f"[site_prefix]\n{_PREFIX}\n")
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()
    yield _PREFIX
    monkeypatch.undo()  # restore the real source BEFORE recomputing, as tests/test_anon_core.py does
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()


_ESCAPED_SITE_CODES = pytest.mark.parametrize(
    "value",
    [
        "971234\\S\\X",
        "X\\T\\971234",
        "971234\\R\\X",
        "X\\F\\971234",
        "97\\X31\\234",
        "\\X393731323334\\",
        "97\\.fi\\1234",
        "97\\X&\\1234",
        "A^971234\\S\\X&B",
        "971234\\X20\\",
        "\\.br\\971234",
        "X\\X0D\\971234",
        "97\\H\\1234",
        "971234\\.br\\X",
        "971234\\E\\",
        "\\E\\971234",
        "971234\\X00\\",
        "971234\\X7F\\X",
        "X\\X01\\971234",
        "\\Z971234\\",
        "X\\Z971234\\Y",
        "\\.sp971234\\",
        "\\971234\\",
        "\\Z-971234\\",
        "\\.Z971234\\",
        "\\.sp971234 x\\",
        "\\Z971234 x\\",
        "\\ZZ971234\\",
        "\\.ti+971234\\",
        "x\\Z971234",
        "971234\\X9C\\",
        "971234\\XAD\\",
        "97\\XAD\\1234",
        "97\\X00\\1234",
        "971234\x00X",
        "97\x001234",
        "971234\u200b",
        "97\u200b1234",
        "9\u00ad71234",
        "9\u200b71234",
        "9\x0071234",
        "\\X41\\971234",
        "\\X41\\971234\\",
        "\\X2D\\971234",
        "971234\\X2D\\",
        "971234\\X41\\",
    ],
    ids=[
        "component-escape",
        "subcomponent-escape",
        "repetition-escape",
        "field-escape",
        "hex-digit",
        "all-hex",
        "dropped-command",
        "pairs-across-subcomponents",
        "inside-a-subcomponent",
        "padded",
        "after-a-break",
        "after-a-carriage-return",
        "highlighting-dropped",
        "before-a-break-command",
        "escape-escape-after",
        "escape-escape-before",
        "nul-padded",
        "del-split",
        "c0-split",
        "z-escape-body",
        "z-escape-body-inside",
        "out-of-range-spacing-command",
        "bare-escape-body",
        "z-body-dash",
        "dotted-unknown-command",
        "spacing-command-then-text",
        "z-body-then-text",
        "two-letter-opener",
        "signed-spacing-command",
        "unclosed-tail",
        "c1-padded",
        "soft-hyphen-padded",
        "soft-hyphen-inside",
        "nul-inside",
        "raw-nul-split",
        "raw-nul-inside",
        "zero-width-padded",
        "zero-width-inside",
        "soft-hyphen-in-prefix",
        "zero-width-in-prefix",
        "nul-in-prefix",
        "after-hex-letter",
        "after-hex-letter-unclosed-tail",
        "after-hex-dash",
        "before-hex-dash",
        "before-hex-letter",
    ],
)


@_SURROGATES
@_ESCAPED_SITE_CODES
def test_an_escaped_site_code_is_found_and_scrubbed(
    surrogates: ModuleType, site_prefix: str, value: str
) -> None:
    text = _zpd(value)
    assert surrogates.message_has_site_code(text)
    scrubbed = surrogates.scrub_message_site_codes(text, Keyer(_SALT), ())
    assert not surrogates.message_has_site_code(scrubbed), scrubbed
    assert scrubbed != text
    # The scrub keeps the field's width and is deterministic.
    assert len(scrubbed) == len(text)
    assert scrubbed == surrogates.scrub_message_site_codes(text, Keyer(_SALT), ())


@_SURROGATES
@pytest.mark.parametrize(
    "value",
    [
        "9712345\\S\\X",
        "A971234",
        "97\\X31\\2345",
        "9712345\\X41\\",
        "20260101\\S\\971",
        "Call\t971234\ttoday",
        "Order\t971234",
    ],
    ids=[
        "seven-digits",
        "glued-letter",
        "hex-seven-digits",
        "hex-letter-seven-digits",
        "date",
        "tab-separated-free-text",
        "tab-before",
    ],
)
def test_a_site_code_run_inside_a_longer_value_is_left(
    surrogates: ModuleType, site_prefix: str, value: str
) -> None:
    text = _zpd(value)
    assert not surrogates.message_has_site_code(text)
    assert surrogates.scrub_message_site_codes(text, Keyer(_SALT), ()) == text


@pytest.fixture
def other_prefix(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> Iterator[str]:
    """``request.param`` loaded as the only site prefix in BOTH copies, as :func:`site_prefix`
    loads its own."""
    prefix: str = request.param
    with contextlib.suppress(engine_leak.LeakCheckUnavailable):
        engine_leak._scanner()
    monkeypatch.setenv("MEFOR_FORBIDDEN_TOKENS", f"[site_prefix]\n{prefix}\n")
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()
    yield prefix
    monkeypatch.undo()
    engine_surrogates.reload_site_prefixes()
    tee_surrogates.reload_site_prefixes()


@_SURROGATES
@pytest.mark.parametrize(
    ("other_prefix", "value"),
    [
        ("24", "\\M242844\\Yamada"),
        ("41", "Name \\X414243\\"),
        ("41", "\\X414243\\"),
        ("28", "\\C282842\\Name"),
        ("24", "Yamada^\\M242844\\Taro&\\M242844\\X"),
    ],
    ids=["multibyte-charset", "hex-data", "hex-data-whole", "single-byte-charset", "in-parts"],
    indirect=["other_prefix"],
)
def test_a_hex_or_charset_escape_argument_is_no_site_code(
    surrogates: ModuleType, other_prefix: str, value: str
) -> None:
    """The argument of ``\\M..\\``, ``\\X..\\`` or ``\\C..\\`` codes a character set or bytes. Read
    as digits, it turned a name to a site-code surrogate (BACKLOG #5654)."""
    text = _zpd(value)
    assert not surrogates.message_has_site_code(text)
    assert surrogates.scrub_message_site_codes(text, Keyer(_SALT), ()) == text


@_SURROGATES
@pytest.mark.parametrize(
    ("other_prefix", "value"),
    [
        ("24", "\\M242844\\Yamada\\.br\\242844"),
        ("24", "\\Z242844\\"),
        ("24", "Call 242844 now\\M2842\\"),
        ("41", "\\X414243"),
        ("41", "\\X414243Z\\"),
        ("41", "\\X3431343234\\3"),
    ],
    ids=[
        "beside-a-break",
        "local-escape",
        "free-text-beside-a-charset-escape",
        "unclosed-tail",
        "not-hex",
        "hex-digits-decoded",
    ],
    indirect=["other_prefix"],
)
def test_a_site_code_beside_or_inside_another_escape_is_still_found(
    surrogates: ModuleType, other_prefix: str, value: str
) -> None:
    """Only a closed hex or character-set escape's own argument is left: a code beside one, in a
    locally defined ``\\Z..\\`` escape, in an unclosed tail, in a body that is not hex, or that
    the hex data decodes to, is still found and scrubbed."""
    text = _zpd(value)
    assert surrogates.message_has_site_code(text)
    scrubbed = surrogates.scrub_message_site_codes(text, Keyer(_SALT), ())
    assert not surrogates.message_has_site_code(scrubbed), scrubbed


@_SURROGATES
def test_the_field_separator_escape_decodes_to_the_message_s_own(
    surrogates: ModuleType, site_prefix: str
) -> None:
    """``\\F\\`` is the field separator MSH-1 declares, so under ``#`` the check splits there."""
    text = f"{_HEAD.replace('|', '#')}\rZPD#1###X\\F\\971234"
    assert surrogates.message_has_site_code(text)
    assert not surrogates.message_has_site_code(
        surrogates.scrub_message_site_codes(text, Keyer(_SALT), ())
    )


def test_trimming_a_long_whitespace_run_is_linear() -> None:
    """A run of spaces inside a value does not make the trim backtrack: the old end-anchored
    pattern took over a second at 16k spaces."""
    import time

    started = time.perf_counter()
    for surrogates in (engine_surrogates, tee_surrogates):
        assert surrogates.trim("A" + " " * 16_000 + "B") == "A" + " " * 16_000 + "B"
        assert surrogates.trim(" \x00　MR\x7f\t") == "MR"
    assert time.perf_counter() - started < 0.5


@_SURROGATES
def test_a_code_beside_an_escaped_code_in_a_sibling_subcomponent_is_scrubbed(
    surrogates: ModuleType, site_prefix: str
) -> None:
    """Replacing the escaped subcomponent first removed the escape that makes the component
    split on whitespace, so the raw code beside it survived and the check passed."""
    text = _zpd("Call 971234&97\\X31\\234")
    scrubbed = surrogates.scrub_message_site_codes(text, Keyer(_SALT), ())
    assert "971234" not in scrubbed.split("\r")[-1], scrubbed
    assert not surrogates.message_has_site_code(scrubbed)


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_emits_no_code_beside_an_escaped_code(
    anon: ModuleType, site_prefix: str
) -> None:
    out = anon.anonymize_checked(_zpd("Call 971234&97\\X31\\234"), salt=_SALT)
    assert "971234" not in out


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_emits_no_escaped_site_code(anon: ModuleType, site_prefix: str) -> None:
    """End to end on both adapters: the scrub replaces the escaped site code, so the leak-check
    passes the output and the code does not survive in any reading."""
    out = anon.anonymize_checked(_zpd("971234\\S\\X"), salt=_SALT)
    assert "971234" not in out
    assert not engine_surrogates.message_has_site_code(out)
