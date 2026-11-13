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
    ["9712345\\S\\X", "A971234", "97\\X31\\2345", "971234\\X41\\", "20260101\\S\\971"],
    ids=["seven-digits", "glued-letter", "hex-seven-digits", "hex-letter", "date"],
)
def test_a_site_code_run_inside_a_longer_value_is_left(
    surrogates: ModuleType, site_prefix: str, value: str
) -> None:
    text = _zpd(value)
    assert not surrogates.message_has_site_code(text)
    assert surrogates.scrub_message_site_codes(text, Keyer(_SALT), ()) == text


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


@_NO_SCANNER
@_SIDES
def test_anonymize_checked_emits_no_escaped_site_code(anon: ModuleType, site_prefix: str) -> None:
    """End to end on both adapters: the scrub replaces the escaped site code, so the leak-check
    passes the output and the code does not survive in any reading."""
    out = anon.anonymize_checked(_zpd("971234\\S\\X"), salt=_SALT)
    assert "971234" not in out
    assert not engine_surrogates.message_has_site_code(out)
