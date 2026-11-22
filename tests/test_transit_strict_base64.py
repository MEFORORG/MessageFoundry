# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Transit ``plaintext`` that is not base64 once ASCII whitespace is removed is refused as that
value's own error (BACKLOG #5964). Non-strict decoding drops every character outside the alphabet,
so ``!!!!`` would have opened as an empty cell and a stray character as a value Transit never
returned. A reply with whitespace added around or inside its base64 still opens as it did. These tests pin the plain :class:`CipherError` a refused reply has today; they do not decide
whether it should instead read as an outage. Synthetic data only."""

from __future__ import annotations

import base64
from typing import Any

import pytest

pytest.importorskip("requests", reason="Transit tests need the [vault] extra")
pytest.importorskip("hvac", reason="Transit tests need the [vault] extra")

from messagefoundry.store import crypto
from messagefoundry.store.crypto import CipherError, cell_aad, gave_no_verdict
from messagefoundry.store.crypto_transit import _plaintext
from tests.test_transit_batch import _BatchTransit, _cipher, _sealed

#: Replies refused here that a non-strict decode opens as a value. Form feed and vertical tab are
#: ASCII whitespace outside the four characters removed.
_NOT_STRICT = {
    "only-non-alphabet": "!!!!",
    "only-newline": "\n",
    "only-whitespace": " \t\r\n",
    "url-safe-alphabet": "-_-_",
    "stray-inside": "dmFs!dWU=",
    "form-feed": "dmFs\fdWU=",
    "vertical-tab": "dmFs\vdWU=",
    "only-padding": "====",
    "excess-padding": "QQ===",
    "padding-after-full-group": "QUJD=",
    "data-after-padding": "QQ==QQ==",
}
#: Unicode spaces, which must not be removed as whitespace is.
_NON_ASCII_SPACES = {
    "no-break-space": f"dmFs{chr(0xA0)}dWU=",
    "em-space": f"dmFs{chr(0x2003)}dWU=",
    "next-line": f"dmFs{chr(0x85)}dWU=",
}
#: Valid base64 of bytes that are not UTF-8.
_NOT_UTF8 = base64.b64encode(b"synthetic \xff").decode("ascii")
_each_bad_reply = pytest.mark.parametrize(
    "reply",
    [*_NOT_STRICT.values(), *_NON_ASCII_SPACES.values(), _NOT_UTF8],
    ids=[*_NOT_STRICT, *_NON_ASCII_SPACES, "not-utf8"],
)
#: ``value`` with space, tab, CR or LF added: the same bytes.
_each_wrapped_reply = pytest.mark.parametrize(
    "reply",
    [" dmFsdWU=", "dmFsdWU=\n", "dmFs\ndWU=", "\tdmFsdWU=\r\n", "dmFsdWU\n="],
    ids=["leading-space", "trailing-newline", "embedded-newline", "tab-crlf", "inside-padding"],
)


class _PlantingTransit(_BatchTransit):
    """Answers the ciphertexts in :attr:`planted` with the planted ``plaintext``, in a single
    request and in a batch alike."""

    def __init__(self) -> None:
        super().__init__()
        self.planted: dict[str, str] = {}

    def decrypt_data(self, **kw: Any) -> dict[str, Any]:
        reply = super().decrypt_data(**kw)
        data = reply["data"]
        asked = kw.get("batch_input") or [kw]
        for item, result in zip(asked, data.get("batch_results", [data]), strict=True):
            if item["ciphertext"] in self.planted:
                result["plaintext"] = self.planted[item["ciphertext"]]
        return reply


def _plant(transit: _PlantingTransit, stored: str, reply: str) -> None:
    transit.planted[stored.removeprefix("mfenc:v3:")] = reply


def _assert_plain_refusal(result: object) -> None:
    """The existing malformed-plaintext refusal: exactly CipherError, and a verdict on the value."""
    assert type(result) is CipherError
    assert "Transit returned malformed plaintext" in str(result)
    assert not gave_no_verdict(result)


@_each_bad_reply
def test_decrypt_refuses_a_reply_that_is_not_strict_base64_of_utf8(reply: str) -> None:
    transit = _PlantingTransit()
    cipher = _cipher(transit)
    stored, aad = _sealed(cipher, 1)[0]
    _plant(transit, stored, reply)
    with pytest.raises(CipherError) as caught:
        cipher.decrypt(stored, aad=aad)
    _assert_plain_refusal(caught.value)


@_each_bad_reply
def test_a_bad_reply_mid_batch_leaves_every_other_result_alone(reply: str) -> None:
    transit = _PlantingTransit()
    cipher = _cipher(transit)
    # Past one batch, so a refusal that read as an outage would fail the whole second request.
    count = crypto.BATCH_MAX_ITEMS + 2
    items = _sealed(cipher, count)
    _plant(transit, items[1][0], reply)

    results = cipher.decrypt_many(items)

    _assert_plain_refusal(results[1])
    assert [r for i, r in enumerate(results) if i != 1] == [
        f"value {i}" for i in range(count) if i != 1
    ]
    assert transit.decrypt_requests == 2  # both batches sent, none retried alone
    assert cipher._batch_alone is False


@_each_wrapped_reply
def test_a_whitespace_wrapped_reply_opens_to_the_same_value(reply: str) -> None:
    transit = _PlantingTransit()
    cipher = _cipher(transit)
    items = _sealed(cipher, 3)
    _plant(transit, items[1][0], reply)
    assert cipher.decrypt(items[1][0], aad=items[1][1]) == "value"
    assert cipher.decrypt_many(items) == ["value 0", "value", "value 2"]


@pytest.mark.parametrize(
    "value",
    [None, 7, 1.5, ["QQ=="], {"a": 1}, b"QQ==", bytearray(b"QQ=="), memoryview(b"QQ==")],
    ids=["none", "int", "float", "list", "dict", "bytes", "bytearray", "memoryview"],
)
def test_a_value_that_is_not_a_str_is_none(value: object) -> None:
    assert _plaintext(value) is None


def test_a_true_empty_reply_opens_as_empty() -> None:
    assert _plaintext("") == ""


@pytest.mark.parametrize(("reply", "text"), [("QR==", "A"), ("dmFsdWX=", "value")])
def test_non_zero_trailing_bits_keep_their_result(reply: str, text: str) -> None:
    assert _plaintext(reply) == text


@pytest.mark.parametrize("text", ["", "a", "ab", "abc", "~~~", "???", "café"])
def test_every_padding_length_and_both_symbols_still_open(text: str) -> None:
    """Control: the standard alphabet with padding, as Transit returns it. ``~~~`` encodes with a
    ``+`` and ``???`` with a ``/``."""
    transit = _BatchTransit()
    cipher = _cipher(transit)
    aads = [cell_aad("t", "c", i) for i in range(2)]
    stored = [cipher.encrypt(text, aad=aad) for aad in aads]
    assert cipher.decrypt(stored[0], aad=aads[0]) == text
    assert cipher.decrypt_many(list(zip(stored, aads, strict=True))) == [text, text]
