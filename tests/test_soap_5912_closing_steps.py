# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5912 closing steps 6, 9 and 11: the SOAP fault classifier's Body anchor steps over a
Body start tag inside markup, a code element holding only whitespace reads as one that holds no
code, and the fallback reuses the first-child read's Fault close-tag search where that search
stepped over no markup. Synthetic replies only."""

from __future__ import annotations

import re
from typing import Any

import pytest

from messagefoundry.transports import soap
from messagefoundry.transports.base import NegativeAckError
from messagefoundry.transports.soap import _classify_soap, _fault_code


def _outcome(failure: object) -> str:
    if failure is None:
        return "delivered"
    if isinstance(failure, NegativeAckError):
        assert failure.permanent
        return failure.code
    return "transient"


# --- step 6: the Body anchor steps over a Body start tag inside markup ----------------------------

#: Each reply puts a Body start tag inside markup ahead of a Header that holds a Fault-named
#: element or a WS-Security code, and a real Body that holds a Receiver fault. Before the fix the
#: Body start tag inside markup was the anchor, so what the Header held decided the reply.
_BODY_TAG_IN_MARKUP_BEFORE_THE_HEADER = {
    "header-client-fault": (
        "<!-- <soap:Body> --><soap:Envelope><soap:Header><x:Fault><faultcode>soap:Client"
        "</faultcode></x:Fault></soap:Header><soap:Body><soap:Fault><faultcode>soap:Server"
        "</faultcode></soap:Fault></soap:Body></soap:Envelope>",
        "soap-sender",
    ),
    "header-wssecurity-code": (
        "<soap:Envelope><soap:Header><!-- <soap:Body> --><x:Note>FailedAuthentication</x:Note>"
        "</soap:Header><soap:Body><soap:Fault><faultcode>soap:Server</faultcode></soap:Fault>"
        "</soap:Body></soap:Envelope>",
        "wssecurity",
    ),
    "cdata-body-tag": (
        "<soap:Envelope><soap:Header><![CDATA[<soap:Body>]]><x:Fault><faultcode>soap:Client"
        "</faultcode></x:Fault></soap:Header><soap:Body><soap:Fault><faultcode>soap:Server"
        "</faultcode></soap:Fault></soap:Body></soap:Envelope>",
        "soap-sender",
    ),
}


@pytest.mark.parametrize(
    ("body", "unanchored"),
    list(_BODY_TAG_IN_MARKUP_BEFORE_THE_HEADER.values()),
    ids=list(_BODY_TAG_IN_MARKUP_BEFORE_THE_HEADER),
)
def test_a_body_start_tag_inside_markup_is_not_the_anchor(
    body: str, unanchored: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The real Body's Receiver fault decides, on 200 and 500. Control: with the plain Body
    pattern patched in for the outside-markup one, the Body start tag inside markup is the anchor
    again and the Header decides, as before the fix."""
    assert _outcome(_classify_soap(200, body)) == "transient"
    assert _outcome(_classify_soap(500, body)) == "transient"
    assert _fault_code(body) == "soap:Server"
    monkeypatch.setattr(soap, "_BODY_OUTSIDE_MARKUP_RE", soap._BODY_RE)
    assert _outcome(_classify_soap(200, body)) == unanchored


def test_with_every_body_start_tag_inside_markup_the_whole_reply_is_searched() -> None:
    """A Body start tag only inside markup is no Body, so the Fault search reads the reply whole,
    as it reads one with no Body start tag, and the reply still reads as a fault."""
    body = "<!-- <soap:Body> --><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>"
    assert _outcome(_classify_soap(200, body)) == "soap-sender"


# --- step 9: a whitespace-only code element reads as one that holds no code -----------------------

#: Replies that differ only in whether the first-child code element is empty or holds only
#: whitespace. Before the fix the empty one fell back to the earlier search and the blank one did
#: not, so the two read differently.
_EMPTY_AND_BLANK = {
    "faultcode-after-a-commented-value": (
        "<soap:Body><soap:Fault><!-- <x:Value>soap:Server</x:Value> --><faultcode>{}</faultcode>"
        "</soap:Fault></soap:Body>"
    ),
    "value-after-a-commented-value": (
        "<env:Body><env:Fault><!-- <x:Value>env:Receiver</x:Value> --><env:Code><env:Value>{}"
        "</env:Value></env:Code></env:Fault></env:Body>"
    ),
}


@pytest.mark.parametrize("shape", list(_EMPTY_AND_BLANK.values()), ids=list(_EMPTY_AND_BLANK))
@pytest.mark.parametrize("blank", [" ", "\n\t ", "\r\n"])
def test_a_blank_code_element_reads_as_an_empty_one(shape: str, blank: str) -> None:
    """Control: the empty element's reading, which the fallback decides."""
    empty, spaced = shape.format(""), shape.format(blank)
    assert _outcome(_classify_soap(200, empty)) == "transient"
    assert _fault_code(spaced) == _fault_code(empty)
    assert _outcome(_classify_soap(200, spaced)) == _outcome(_classify_soap(200, empty))


# --- step 11: the fallback reuses the close-tag search where no markup was stepped over -----------


class _CountingPattern:
    """A stand-in for a compiled pattern that records each ``search`` call's range."""

    def __init__(self, pattern: re.Pattern[str]) -> None:
        self._pattern = pattern
        self.searches: list[tuple[int, int]] = []

    def search(self, string: str, pos: int = 0, endpos: int | None = None) -> Any:
        end = len(string) if endpos is None else endpos
        self.searches.append((pos, end))
        return self._pattern.search(string, pos, end)

    def match(self, string: str, pos: int = 0, endpos: int | None = None) -> Any:
        return self._pattern.match(string, pos, len(string) if endpos is None else endpos)


#: Replies whose first child yields no code, so the fallback runs; none holds markup.
_FALLBACK_NO_MARKUP = {
    "faultstring-first": (
        "<soap:Body><soap:Fault><faultstring>busy</faultstring><faultcode>soap:Server"
        "</faultcode></soap:Fault></soap:Body>" + "<x/>" * 50
    ),
    "reason-first": (
        "<env:Body><env:Fault><env:Reason><env:Text>busy</env:Text></env:Reason><env:Code>"
        "<env:Value>env:Receiver</env:Value></env:Code></env:Fault></env:Body>"
    ),
    "no-close-tag": "<Fault><faultstring>busy</faultstring><faultcode>Server</faultcode>",
}


@pytest.mark.parametrize("body", list(_FALLBACK_NO_MARKUP.values()), ids=list(_FALLBACK_NO_MARKUP))
def test_the_fallback_does_not_rescan_for_the_fault_close_tag(
    body: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Where the first-child read's close-tag search stepped over no markup, its Fault close tag
    is the fallback's, so no plain ``_FAULT_END_RE`` scan runs past the Fault start tag. Control:
    the code read is a Receiver one, which only the fallback finds in these shapes."""
    expected = _fault_code(body)
    assert soap._RECEIVER_RE.search(expected), "the shape must reach the fallback's code"
    counting = _CountingPattern(soap._FAULT_END_RE)
    monkeypatch.setattr(soap, "_FAULT_END_RE", counting)
    assert _fault_code(body) == expected
    fault = soap._FAULT_RE.search(body)
    assert fault is not None
    gt = body.index(">", fault.end() - 1)
    # At most the bounded search of the Fault start tag's own text, never one past its end.
    assert all(end <= gt + 1 for _, end in counting.searches), counting.searches


def test_the_fallback_still_ends_at_a_close_tag_inside_markup() -> None:
    """Where the close-tag search stepped over markup, the fallback's range still ends at the first
    plain Fault close tag, as before #5912 (the shape the changelog names)."""
    body = (
        "<soap:Fault><faultstring>busy</faultstring><!-- </soap:Fault> -->"
        "<faultcode>soap:Server</faultcode>"
    )
    assert _fault_code(body) == ""
    assert _outcome(_classify_soap(200, body)) == "soap-fault"


def test_a_close_tag_inside_the_fault_start_tag_still_ends_the_fallback_range() -> None:
    """The earlier search's range starts where the Fault's name ends, so a Fault close tag inside
    the start tag's own text ends it, as before."""
    body = "<Fault </Fault><faultstring>x</faultstring><faultcode>soap:Server</faultcode>"
    assert _fault_code(body) == ""
