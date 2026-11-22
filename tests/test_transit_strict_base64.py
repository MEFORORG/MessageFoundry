# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Transit ``plaintext`` that is not strict base64 is refused as that value's own error (BACKLOG
#5964). Non-strict decoding drops characters outside the alphabet, so ``!!!!`` would have opened as
an empty cell and a stray character would have opened as a value Transit never returned. Which
class such a reply should carry is left open on the row, so these tests pin the plain
:class:`CipherError` it has today. Synthetic data only."""

from __future__ import annotations

import base64
from typing import Any

import pytest

pytest.importorskip("requests", reason="Transit tests need the [vault] extra")
pytest.importorskip("hvac", reason="Transit tests need the [vault] extra")

from messagefoundry.store import crypto
from messagefoundry.store.crypto import CipherError, cell_aad, gave_no_verdict
from tests.test_transit_batch import _BatchTransit, _cipher, _sealed

#: Replies that are not strict base64. A non-strict decode opens all but the last as a value.
_NOT_STRICT = {
    "only-non-alphabet": "!!!!",
    "url-safe-alphabet": "-_-_",
    "stray-inside": "dmFs!dWU=",
    "leading-space": " dmFsdWU=",
    "trailing-newline": "dmFsdWU=\n",
    "embedded-newline": "dmFs\ndWU=",
    "data-after-padding": "dmFsdWU=dmFs",
}
#: Valid base64 of bytes that are not UTF-8.
_NOT_UTF8 = base64.b64encode(b"synthetic \xff").decode("ascii")
_each_bad_reply = pytest.mark.parametrize(
    "reply", [*_NOT_STRICT.values(), _NOT_UTF8], ids=[*_NOT_STRICT, "not-utf8"]
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
