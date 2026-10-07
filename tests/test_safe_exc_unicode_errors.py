# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``safe_exc`` renders a ``UnicodeError`` without the character or byte it failed on (vault
BACKLOG #3033).

``str(UnicodeEncodeError)`` reads ``'ascii' codec can't encode character '\\xe9' in position 5``.
The character is a character of the message, and :func:`redact` scrubs HL7 shapes, not single
escaped characters. Any encode or decode site that skips ``encode_wire_body`` put that character
into a stored ``last_error`` or a log line through ``safe_exc``. All payloads here are synthetic."""

from __future__ import annotations

import pytest

from messagefoundry.redaction import safe_exc
from tests._content_free import escapes

#: Synthetic. Distinctive enough that a substring scan of the output cannot miss them.
#: Its bare hex, ``15a``, holds a letter, so no decimal position in the output can match it.
_CHAR = "\u015a"  # S with acute: not ASCII, not latin-1
_BYTE = 0xFE  # never valid in UTF-8
_PREFIX = "PID|1||ZZQ"
_TEXT = f"{_PREFIX}{_CHAR}X"
_POSITION = len(_PREFIX)


def _byte_forms(byte: int) -> list[str]:
    return [f"0x{byte:02x}", f"\\x{byte:02x}", f"{byte:02x}", str(byte)]


def _encode_error() -> UnicodeEncodeError:
    with pytest.raises(UnicodeEncodeError) as caught:
        _TEXT.encode("ascii")
    return caught.value


def _decode_error(data: bytes) -> UnicodeDecodeError:
    with pytest.raises(UnicodeDecodeError) as caught:
        data.decode("utf-8")
    return caught.value


def _translate_error() -> UnicodeTranslateError:
    # No stdlib str method raises this, so build it the way a codec's translate path does.
    return UnicodeTranslateError(_TEXT, _POSITION, _POSITION + 1, "character maps to <undefined>")


def _assert_no_content(text: str) -> None:
    assert _PREFIX not in text and "ZZQ" not in text, f"payload text leaked: {text!r}"
    for form in escapes(_CHAR):
        assert form not in text, f"the offending character leaked as {form!r}: {text!r}"


def test_the_unguarded_text_does_leak() -> None:
    """POSITIVE CONTROL for the instrument: ``str()`` of each error carries what the scans below
    look for. A scan that could not find it here proves nothing by finding nothing later."""
    assert "\\u015a" in str(_encode_error())
    assert "0xfe" in str(_decode_error(_PREFIX.encode() + bytes([_BYTE])))
    assert "\\u015a" in str(_translate_error())


def test_an_encode_error_names_codec_and_position_and_never_the_character() -> None:
    text = safe_exc(_encode_error())
    _assert_no_content(text)
    assert text.startswith("UnicodeEncodeError: ")
    assert "'ascii' codec" in text
    assert f"position {_POSITION}" in text
    assert "ordinal not in range(128)" in text


def test_a_decode_error_names_codec_and_position_and_never_the_byte() -> None:
    text = safe_exc(_decode_error(_PREFIX.encode() + bytes([_BYTE]) + b"X"))
    _assert_no_content(text)
    for form in _byte_forms(_BYTE):
        assert form not in text, f"the offending byte leaked as {form!r}: {text!r}"
    assert text.startswith("UnicodeDecodeError: ")
    assert "'utf-8' codec" in text
    assert f"position {_POSITION}" in text
    assert "invalid start byte" in text


def test_a_multi_byte_span_is_a_range_and_names_no_byte() -> None:
    # 0xE2 0x82 then end of data: utf-8 reports the two-byte span, and str() would print both.
    data = _PREFIX.encode() + b"\xe2\x82"
    exc = _decode_error(data)
    assert exc.end - exc.start == 2, "the probe must exercise the multi-byte arm"
    text = safe_exc(exc)
    for byte in (0xE2, 0x82):
        for form in _byte_forms(byte):
            assert form not in text, f"a byte leaked as {form!r}: {text!r}"
    assert f"positions {_POSITION}-{_POSITION + 1}" in text


def test_a_translate_error_names_position_and_never_the_character() -> None:
    text = safe_exc(_translate_error())
    _assert_no_content(text)
    assert text.startswith("UnicodeTranslateError: ")
    assert f"position {_POSITION}" in text


def test_a_charmap_encode_names_its_codec() -> None:
    # cp1252 reports itself as "charmap", a real codec name, so it is kept.
    with pytest.raises(UnicodeEncodeError) as caught:
        _TEXT.encode("cp1252")
    text = safe_exc(caught.value)
    _assert_no_content(text)
    assert "'charmap' codec" in text and f"position {_POSITION}" in text


@pytest.mark.parametrize(
    "exc",
    [
        UnicodeError(f"label too long: {_TEXT}"),
        UnicodeDecodeError("utf-8", _TEXT.encode(), 5, 2, "backwards"),
    ],
    ids=["bare-UnicodeError", "end-before-start"],
)
def test_odd_attributes_fall_back_to_the_class_name(exc: UnicodeError) -> None:
    assert safe_exc(exc) == type(exc).__name__


def test_an_empty_span_still_names_codec_and_position() -> None:
    # Windows mbcs raises with start == end, so an empty span is a real shape, not an odd one.
    exc = UnicodeEncodeError("mbcs", _TEXT, _POSITION, _POSITION, "invalid character")
    assert safe_exc(exc) == (
        f"UnicodeEncodeError: 'mbcs' codec cannot encode at position {_POSITION}: invalid character"
    )


def test_a_stdlib_codec_whose_label_is_not_a_lookup_name_is_still_named() -> None:
    # unicode_escape reports itself as "unicodeescape", which codecs.lookup does not answer to.
    with pytest.raises(UnicodeDecodeError) as caught:
        (_PREFIX.encode() + b"\\x4").decode("unicode_escape")
    assert caught.value.encoding == "unicodeescape"
    assert "'unicodeescape' codec cannot decode at positions" in safe_exc(caught.value)


def test_a_reason_that_only_compares_equal_to_a_listed_phrase_is_dropped() -> None:
    class _Lookalike(str):
        def __eq__(self, other: object) -> bool:
            return True

        def __hash__(self) -> int:
            return hash("surrogates not allowed")

    exc = UnicodeEncodeError("ascii", _TEXT, _POSITION, _POSITION + 1, "x")
    # A single non-ASCII character: no redact() pattern removes it, so only the type check can.
    exc.reason = _Lookalike(f"note {_CHAR}")
    text = safe_exc(exc)
    _assert_no_content(text)
    assert "note" not in text


def test_an_ordinal_reason_with_other_digits_is_dropped() -> None:
    for digits in ("5551234", "１２８"):
        exc = UnicodeEncodeError(
            "ascii", _TEXT, _POSITION, _POSITION + 1, f"ordinal not in range({digits})"
        )
        assert digits not in safe_exc(exc)


def test_an_encoding_attribute_not_shaped_like_a_codec_is_dropped() -> None:
    exc = UnicodeEncodeError("ascii", _TEXT, _POSITION, _POSITION + 1, "ordinal not in range(128)")
    exc.encoding = f"x {_TEXT}"
    text = safe_exc(exc)
    _assert_no_content(text)
    assert "codec" not in text and f"position {_POSITION}" in text


def test_an_encoding_attribute_naming_no_codec_is_dropped() -> None:
    # Shaped like a codec name, but no codec answers to it: an identifier someone set there.
    exc = UnicodeEncodeError("ascii", _TEXT, _POSITION, _POSITION + 1, "ordinal not in range(128)")
    exc.encoding = "MRN123456789"
    text = safe_exc(exc)
    assert "MRN" not in text and "123456789" not in text
    assert "codec" not in text and f"position {_POSITION}" in text


def test_a_reason_that_quotes_the_input_is_dropped() -> None:
    """The stdlib idna codec puts the offending character INTO ``.reason``, so a reason is kept
    only from a fixed list. Measured on Python 3.14: ``Invalid character '\\ue000'``."""
    with pytest.raises(UnicodeError) as caught:
        f"doe{_CHAR}\ue000jane.example".encode("idna")
    assert "\\ue000" in str(caught.value), "the probe must quote the character, or it tests nothing"
    text = safe_exc(caught.value)
    _assert_no_content(text)
    for form in escapes("\ue000"):
        assert form not in text, f"the reason leaked the character as {form!r}: {text!r}"
    assert "doe" not in text and "jane" not in text


def test_a_punycode_round_trip_reason_naming_the_label_is_dropped() -> None:
    label = b"xn--" + "doeﬁjane".encode("punycode")
    with pytest.raises(UnicodeError) as caught:
        label.decode("idna")
    assert "doe" in str(caught.value), "the probe must quote the label, or it tests nothing"
    text = safe_exc(caught.value)
    assert "doe" not in text and "jane" not in text, text


def test_an_unlisted_reason_is_dropped_and_a_listed_one_kept() -> None:
    kept = UnicodeEncodeError("ascii", _TEXT, _POSITION, _POSITION + 1, "surrogates not allowed")
    dropped = UnicodeEncodeError("ascii", _TEXT, _POSITION, _POSITION + 1, f"bad {_CHAR}")
    assert safe_exc(kept).endswith(": surrogates not allowed")
    assert (
        safe_exc(dropped)
        == f"UnicodeEncodeError: 'ascii' codec cannot encode at position {_POSITION}"
    )


class _RaisingReason(UnicodeEncodeError):
    @property
    def reason(self) -> str:  # type: ignore[override]
        raise ValueError("unreadable")


def test_an_attribute_that_raises_falls_back_to_the_class_name() -> None:
    """``safe_exc`` runs inside other handlers' except arms, so it must not raise in their place."""
    exc = _RaisingReason("ascii", _TEXT, _POSITION, _POSITION + 1, "ordinal not in range(128)")
    assert safe_exc(exc) == "_RaisingReason"
