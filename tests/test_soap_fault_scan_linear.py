# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2827: the SOAP fault-code scan is linear in the reply, and it runs off the event loop.

The former ``_FAULTCODE_RE`` and ``_CODEVALUE_RE`` ended ``[^>]*>(.*?)</`` under DOTALL, so every
start tag with no close after it rescanned to the end of the reply. A partner reply of repeated start
tags then cost the square of its length, and on the 2xx path that cost ran on the event loop.

Three things are pinned here: what the new extraction reads, its time grows linearly, and the 2xx
classification runs in the worker thread. BACKLOG #5913 adds a fourth at the end of the file: the
WS-* envelope wrap and the body-secret substitution run in that same worker hop, before the POST.
The old patterns are kept below, verbatim, as the positive control for the second, and inside the
reference for the first.

The new extraction is NOT the old one everywhere. The old patterns read the first faultcode anywhere
in the reply, else the first Value, the Header included, and an empty ``<faultcode/>`` took the next element's text as its
code. Both could make a permanent fault read as a Receiver one and retry until the attempt limit;
the named tests below pin each, with a control. The Fault is searched for from the SOAP Body start
tag, ``_find_fault`` says how, and the Body tests pin that, each with a control. BACKLOG #5912
reads the code first from the Fault's first child, a faultcode or a Code and the Value that is that
Code's first child, so where that read yields a code a Value anywhere else in the Fault, inside
markup say, does not decide it; its tests pin that against the PR 2790 reading, which took the
Fault's first Value. Where that read yields no code, the fallback reads the code as the PR 2790
reading did (the PR 2936 hold of 2026-11-14), and its tests pin that too.

The third is about which thread runs the scan, not about the loop staying responsive.
``SoapDestination._post_and_classify`` says why the two differ, and what bounds the difference.
"""

from __future__ import annotations

import asyncio
import gc
import random
import re
import threading
from collections.abc import Callable
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import Soap
from messagefoundry.transports import build_destination, soap
from messagefoundry.transports.base import DeliveryError, NegativeAckError
from messagefoundry.transports.soap import SoapDestination, _classify_soap, _fault_code
from tests._growth import _growth_between

# The patterns as they stood at engine origin/main 7051dbc552, before BACKLOG #2827.
_OLD_FAULTCODE_RE = re.compile(
    r"<\s*(?:[\w.\-]+:)?faultcode\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL
)
_OLD_CODEVALUE_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Value\b[^>]*>(.*?)</", re.IGNORECASE | re.DOTALL)


def _old_fault_code(body: str, fault: object = None) -> str:
    m = _OLD_FAULTCODE_RE.search(body) or _OLD_CODEVALUE_RE.search(body)
    return m.group(1) if m else ""


# The reference reading: the old patterns, run on the Fault's first child element, a comment, CDATA
# section or processing instruction before it skipped whole. The Fault is the first Fault start tag after the first
# Body start tag (or anywhere, with no Body start tag or no Fault after it), read to its close tag.
# BACKLOG #5912: the Fault start tag, and the Fault and Code close tags, are found outside markup,
# each markup taken whole; only where every Fault start tag is inside markup is the first one taken.
# A faultcode child is read whole; a Code child is read up to its close tag, and its own first child
# must be the Value (BACKLOG #5912). An element that cannot hold a code reads as empty. It reuses the
# production faultcode and Value close-tag patterns and the nested-tag pattern, so it re-checks the
# str.find bounds and captures, not those patterns; the named shapes pin what they read. The Code
# start and close tags are written out here, independently of _CODE_RE and _CODE_END_RE.
#: Markup that is not an element, whole: what the first-child search steps over and, BACKLOG
#: #5912, what the Fault search and the Fault and Code close-tag searches step over.
_REF_MARKUP = r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>"
_REF_BODY_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Body[\s/>](.*)", re.IGNORECASE | re.DOTALL)
#: Text read lazily, each markup taken whole; atomic, so no backtrack lets a tag inside one match.
_REF_TEXT = rf"(?:(?>{_REF_MARKUP}|.))*?"
_REF_FAULT_TAG = r"(?i:<\s*(?:[\w.\-]+:)?Fault[\s/>])"
#: The reply read from its start as tokens: each markup whole, a Fault start tag (group 1), or one
#: character, so a Fault start tag in group 1 is outside markup.
_REF_TOKEN_RE = re.compile(rf"(?>{_REF_MARKUP})|({_REF_FAULT_TAG})|.", re.DOTALL)
_REF_FAULT_ANYWHERE_RE = re.compile(_REF_FAULT_TAG)
#: From the end of the Fault start tag to its close tag outside markup, or the reply's end.
_REF_FAULT_INNER_RE = re.compile(
    rf"({_REF_TEXT})(?:(?i:</\s*(?:[\w.\-]+:)?Fault\s*>)|\Z)", re.DOTALL
)
_REF_START_TAG_RE = re.compile(r"[^>]*>")
_REF_BEFORE_THE_CHILD_RE = re.compile(rf"(?:[^<]|{_REF_MARKUP})*", re.DOTALL)
_REF_CODE_RE = re.compile(
    rf"(?i:<\s*(?:[\w.\-]+:)?Code(?=[\s/>]))([^>]*>)({_REF_TEXT})"
    r"(?:(?i:</\s*(?:[\w.\-]+:)?Code\s*>)|\Z)",
    re.DOTALL,
)


def _ref_code_text(m: re.Match[str] | None, inner: str, own_close: re.Pattern[str]) -> str:
    if m is None:
        return ""
    code = m.group(1)
    self_closing = inner[m.start(1) - 2] == "/"
    holds_an_element = soap._TAG_OPEN_RE.search(code) is not None
    if self_closing or holds_an_element or not own_close.match(inner, m.end() - 2):
        return ""
    return code


def _ref_fault_tag_end(body: str) -> int | None:
    """Where the Fault start tag's name ends: the first after the Body start tag, else the first
    before it, or with no Body start tag the first anywhere; on each side one outside markup first
    and, failing that, any (BACKLOG #5912)."""
    outside = [t.span(1) for t in _REF_TOKEN_RE.finditer(body) if t.group(1)]
    anywhere = [t.span() for t in _REF_FAULT_ANYWHERE_RE.finditer(body)]
    in_body = _REF_BODY_RE.search(body)
    sides = (
        [(0, len(body))]
        if in_body is None
        else [(in_body.start(1), len(body)), (0, in_body.start())]
    )
    for low, high in sides:
        for spans in (outside, anywhere):
            found = [end for start, end in spans if low <= start < high]
            if found:
                return found[0]
    return None


def _ref_fault_code(body: str) -> str:
    name_end = _ref_fault_tag_end(body)
    if name_end is None:
        return ""
    fault_tag = _REF_START_TAG_RE.match(body, name_end - 1)
    if fault_tag is None or fault_tag.group().endswith("/>"):
        return ""
    fault_inner = _REF_FAULT_INNER_RE.match(body, fault_tag.end())
    inner = "" if fault_inner is None else fault_inner.group(1)
    code = _ref_first_child_code(inner)
    if code:
        return code
    plain_end = _REF_FAULT_CLOSE_ANYWHERE_RE.search(body, name_end)
    return _ref_searched_code(
        body[name_end : len(body) if plain_end is None else plain_end.start()]
    )


#: The fallback's range ends at the first Fault close tag, markup not stepped over.
_REF_FAULT_CLOSE_ANYWHERE_RE = re.compile(r"(?i:</\s*(?:[\w.\-]+:)?Fault\s*>)")
#: The fallback's start-tag names, written out independently of _FAULTCODE_RE and _CODEVALUE_RE.
_REF_FAULTCODE_NAME_RE = re.compile(r"<\s*(?:[\w.\-]+:)?faultcode\b", re.IGNORECASE)
_REF_VALUE_NAME_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Value\b", re.IGNORECASE)


def _ref_searched_code(inner: str) -> str:
    """The fallback: the old patterns' search over the old range, a Value only ahead of the first
    faultcode, markup not stepped over (BACKLOG #5912)."""
    faultcode = _REF_FAULTCODE_NAME_RE.search(inner)
    head = inner if faultcode is None else inner[: faultcode.start()]
    value = _REF_VALUE_NAME_RE.search(head)
    # Only each name is searched for; its capture, the old pattern's, may run past the faultcode.
    if value is not None:
        old_value = _OLD_CODEVALUE_RE.match(inner, value.start())
        return _ref_code_text(old_value, inner, soap._CODEVALUE_END_RE)
    if faultcode is None:
        return ""
    old_faultcode = _OLD_FAULTCODE_RE.match(inner, faultcode.start())
    return _ref_code_text(old_faultcode, inner, soap._FAULTCODE_END_RE)


def _ref_first_child_code(inner: str) -> str:
    lead = _REF_BEFORE_THE_CHILD_RE.match(inner)
    child = inner[lead.end() :] if lead is not None else ""
    faultcode = _OLD_FAULTCODE_RE.match(child)
    if faultcode is not None:
        return _ref_code_text(faultcode, child, soap._FAULTCODE_END_RE)
    code = _REF_CODE_RE.match(child)
    if code is None or code.group(1).endswith("/>"):
        return ""
    in_code = code.group(2)
    lead = _REF_BEFORE_THE_CHILD_RE.match(in_code)
    child = in_code[lead.end() :] if lead is not None else ""
    return _ref_code_text(_OLD_CODEVALUE_RE.match(child), child, soap._CODEVALUE_END_RE)


# --- what the extraction reads ------------------------------------------------------------------

#: Each shape, and the code read from it.
_NAMED_SHAPES = {
    "soap11": ("<soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>", "soap:Client"),
    "soap12": ("<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code></s:Fault>", "s:Sender"),
    "soap12-subcode": (
        "<Fault><Code><Value>env:Receiver</Value><Subcode><Value>m:Busy</Value></Subcode>"
        "</Code></Fault>",
        "env:Receiver",
    ),
    "SOAP-ENV": (
        "<SOAP-ENV:Fault><faultcode>SOAP-ENV:Server</faultcode></SOAP-ENV:Fault>",
        "SOAP-ENV:Server",
    ),
    "dotted-prefix": (
        "<a.b:Fault><a.b:faultcode>a.b:Client</a.b:faultcode></a.b:Fault>",
        "a.b:Client",
    ),
    "spaced": (
        "< soap:Fault >< soap:faultcode  xmlns:q='u' >q:Client</ soap:faultcode>",
        "q:Client",
    ),
    "upper": ("<FAULT><FAULTCODE>CLIENT</FAULTCODE></FAULT>", "CLIENT"),
    "attr-with-gt": ('<Fault><faultcode a="x>y">soap:Client</faultcode></Fault>', 'y">soap:Client'),
    "cdata": (
        "<Fault><faultcode><![CDATA[soap:Server]]></faultcode></Fault>",
        "<![CDATA[soap:Server]]>",
    ),
    "comment": (
        "<Fault><faultcode><!-- c -->soap:Server</faultcode></Fault>",
        "<!-- c -->soap:Server",
    ),
    "multiline": ("<Fault><faultcode>\n  soap:Client\n</faultcode></Fault>", "\n  soap:Client\n"),
    # BACKLOG #5912: the Fault's first child is read first. Where it yields no code, the earlier
    # search is the fallback (PR 2936 hold of 2026-11-14): the first faultcode, or a Value before it.
    "bare-value-then-faultcode": ("<Fault><Value>x:Sender</Value><faultcode>y", "x:Sender"),
    "name-only-prefix-match": ("<Fault><faultcodeX>a</faultcodeX><Value>v</Value></Fault>", "v"),
    "code-name-prefix-match": ("<Fault><CodeX><Value>v</Value></CodeX></Fault>", "v"),
    "code-then-faultcode": (
        "<Fault><Code><Value>env:Sender</Value></Code><faultcode>soap:Server</faultcode></Fault>",
        "env:Sender",
    ),
    "faultcode-then-code": (
        "<Fault><faultcode>soap:Client</faultcode><Code><Value>Receiver</Value></Code></Fault>",
        "soap:Client",
    ),
    "comment-before-the-code": (
        "<env:Fault><!-- c --><env:Code><env:Value>env:Sender</env:Value></env:Code></env:Fault>",
        "env:Sender",
    ),
    "code-without-value": ("<Fault><Code><Subcode/></Code><Detail><Value>v</Value></Detail>", "v"),
    "self-closing-code": (
        "<Fault><Code/><Detail><Value>Receiver</Value></Detail></Fault>",
        "Receiver",
    ),
    "unclosed-code": ("<Fault><Code><Value>env:Sender</Value>", "env:Sender"),
    # Markup that is not an element is stepped over whole, so a tag inside it is not the child.
    "comment-holding-a-faultcode": (
        "<soap:Fault><!-- <faultcode>soap:Server</faultcode> --><faultcode>soap:Client</faultcode>"
        "</soap:Fault>",
        "soap:Client",
    ),
    "pi-holding-a-faultcode": (
        "<Fault><?pi <faultcode>Server</faultcode>?><faultcode>soap:Client</faultcode></Fault>",
        "soap:Client",
    ),
    "cdata-holding-a-faultcode": (
        "<Fault><![CDATA[<faultcode>Server</faultcode>]]><faultcode>soap:Client</faultcode></Fault>",
        "soap:Client",
    ),
    "comment-in-the-code": (
        "<Fault><Code><!-- <Value>Receiver</Value> --><Value>Sender</Value></Code></Fault>",
        "Sender",
    ),
    # Where the first-child read stops, the fallback reads the code as the earlier search did.
    "unterminated-comment": ("<Fault><!-- <faultcode>Server</faultcode></Fault>", "Server"),
    "doctype-before-the-code": (
        "<Fault><!DOCTYPE x><faultcode>Server</faultcode></Fault>",
        "Server",
    ),
    "bang-before-the-code": ("<Fault><!foo><faultcode>Server</faultcode></Fault>", "Server"),
    "lowercase-cdata-before-the-code": (
        "<Fault><![cdata[x]]><faultcode>soap:Server</faultcode></Fault>",
        "soap:Server",
    ),
    # The Code's own first child must be its Value for the first read; a Subcode first leaves the
    # fallback, which takes the Fault's first Value.
    "subcode-first": (
        "<Fault><Code><Subcode><Value>Receiver</Value></Subcode><Value>Sender</Value></Code></Fault>",
        "Receiver",
    ),
    "unclosed-code-then-detail": (
        "<Fault><Code><Reason><Text>t</Text></Reason><Detail><Value>Receiver</Value></Detail></Fault>",
        "Receiver",
    ),
    "value-tag-past-the-code": ("<Fault><Code><Value</Code>Receiver</Value></Fault>", "Receiver"),
    # The faultcode name ends at a non-word character.
    "faultcode-name-boundary": ("<Fault><faultcodeX>Server</faultcode></Fault>", ""),
    # SOAP 1.1's schema puts faultcode first; after a faultstring only the fallback reads it.
    "faultstring-before-faultcode": (
        "<soap:Fault><faultstring>busy</faultstring><faultcode>soap:Server</faultcode></soap:Fault>",
        "soap:Server",
    ),
    "reason-before-the-code": (
        "<env:Fault><env:Reason><env:Text>busy</env:Text></env:Reason><env:Code>"
        "<env:Value>env:Receiver</env:Value></env:Code></env:Fault>",
        "env:Receiver",
    ),
    # The first code element decides: an empty one is not passed over for the Value after it.
    "empty": ("<Fault><faultcode></faultcode><Value>x:Sender</Value></Fault>", ""),
    "nested": ("<Fault><faultcode><b>soap:Client</b></faultcode></Fault>", ""),
    "self-closing": ("<Fault><faultcode/>x</y>", ""),
    "foreign-close": ("<Fault><faultcode>soap:Server</faultstring></Fault>", ""),
    "processing-instruction": (
        "<Fault><faultcode><?pi?>soap:Server</faultcode></Fault>",
        "<?pi?>soap:Server",
    ),
    "spaced-self-closing-fault": ("<Fault /><faultcode>soap:Server</faultcode>", ""),
    "no-gt": ("<Fault><faultcode", ""),
    "no-close": ("<Fault><faultcode>soap:Client", ""),
    "code-outside-any-fault": ("<faultcode>soap:Server</faultcode>", ""),
    "no-fault": ("<soap:Body>ok</soap:Body>", ""),
    "blank": ("", ""),
}


@pytest.mark.parametrize(("body", "code"), list(_NAMED_SHAPES.values()), ids=list(_NAMED_SHAPES))
def test_each_named_shape_yields_its_code(body: str, code: str) -> None:
    assert _fault_code(body) == code
    assert _ref_fault_code(body) == code


# Defect 1: the code was the first faultcode, else the first Value, anywhere in the reply, so a
# Header element, or a faultcode in a SOAP 1.2 Detail, decided the Fault.
_OUTSIDE_THE_CODE = {
    "soap12-header-value": (
        "<env:Envelope><env:Header><x:Value>Receiver</x:Value></env:Header><env:Body>"
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value></env:Code></env:Fault>"
        "</env:Body></env:Envelope>",
        "env:Sender",
    ),
    "soap11-header-faultcode": (
        "<soap:Envelope><soap:Header><x:faultcode>Server</x:faultcode></soap:Header>"
        "<soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault></soap:Body>"
        "</soap:Envelope>",
        "soap:Client",
    ),
    "soap12-detail-faultcode": (
        "<env:Fault><env:Code><env:Value>env:Sender</env:Value></env:Code><env:Detail>"
        "<app:faultcode>SERVER_ERROR</app:faultcode></env:Detail></env:Fault>",
        "env:Sender",
    ),
}


@pytest.mark.parametrize(
    ("body", "code"), list(_OUTSIDE_THE_CODE.values()), ids=list(_OUTSIDE_THE_CODE)
)
def test_a_code_in_the_header_does_not_decide_a_sender_fault(body: str, code: str) -> None:
    """Red on the old reading, which took the Header's, or the Detail's, Receiver code and retried
    a Sender fault."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the defect"
    assert _fault_code(body) == code
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.permanent
    assert failure.code == "soap-sender"


_AFTER_THE_FAULT = {
    "after-the-close-tag": (
        "<Fault><faultstring>bad</faultstring></Fault><Value>env:Receiver</Value>"
    ),
    "after-a-self-closing-fault": "<env:Body><x:Fault/><r><Value>Receiver</Value></r></env:Body>",
}


@pytest.mark.parametrize("body", list(_AFTER_THE_FAULT.values()), ids=list(_AFTER_THE_FAULT))
def test_a_code_after_the_fault_does_not_decide_it(body: str) -> None:
    """The read stops at the Fault's close tag, and a self-closing Fault holds no code."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the bound"
    assert _fault_code(body) == ""
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.code == "soap-fault"


# Defect 2: an element that cannot hold a code read the next element's text as its code.
_EMPTY_CODE = {
    "self-closing-faultcode": (
        "<soap:Fault><faultcode/><faultstring>Server busy</faultstring></soap:Fault>"
    ),
    "faultcode-holding-an-element": (
        "<soap:Fault><faultcode><faultstring>Server busy</faultstring></faultcode></soap:Fault>"
    ),
    "self-closing-value": (
        "<env:Fault><env:Code><env:Value/><env:Subcode><env:Value>m:Server</env:Value>"
        "</env:Subcode></env:Code></env:Fault>"
    ),
}


@pytest.mark.parametrize("body", list(_EMPTY_CODE.values()), ids=list(_EMPTY_CODE))
def test_an_empty_code_element_yields_no_code(body: str) -> None:
    """Red on the old reading, which took ``<faultstring>Server busy`` as a Receiver code. With no
    code the fault reads as the empty-code path reads it: permanent, as ``soap-fault``."""
    assert soap._RECEIVER_RE.search(_old_fault_code(body)), "the shape must exercise the defect"
    assert _fault_code(body) == ""
    failure = _classify_soap(200, body)
    assert isinstance(failure, NegativeAckError) and failure.permanent
    assert failure.code == "soap-fault"


# BACKLOG #5912: the PR 2790 reading took the Fault's first Value before any faultcode. Each shape
# here has no code the Fault's first child yields, so the fallback reads it that way: the first five
# by a Value in a Reason, Node, Role or Detail, or ahead of a SOAP 1.1 faultcode (#6664 item 5), the
# rest the shapes of the PR 2936 hold of 2026-11-14, which head 933e347fe8 dead-lettered.
_NO_FIRST_CHILD_CODE = {
    "soap12-detail-value-no-code": (
        "<env:Body><env:Fault><env:Reason><env:Text>bad</env:Text></env:Reason><env:Detail>"
        "<app:Value>Receiver</app:Value></env:Detail></env:Fault></env:Body>"
    ),
    "soap12-role-before-the-code": (
        "<env:Body><env:Fault><env:Role><x:Value>Receiver</x:Value></env:Role><env:Code>"
        "<env:Value>env:Sender</env:Value></env:Code></env:Fault></env:Body>"
    ),
    "soap12-node-value-no-code": (
        "<env:Fault><env:Node><x:Value>Server</x:Value></env:Node></env:Fault>"
    ),
    "soap11-detail-value-before-faultcode": (
        "<soap:Body><soap:Fault><detail><Value>Server</Value></detail>"
        "<faultcode>soap:Client</faultcode></soap:Fault></soap:Body>"
    ),
    "soap11-bare-value-before-faultcode": (
        "<soap:Fault><Value>Server</Value><faultcode>soap:Client</faultcode></soap:Fault>"
    ),
    # Hold shape C: a `<!` the first-child read does not step over, ahead of the faultcode.
    "doctype-before-the-faultcode": (
        "<soap:Envelope><soap:Body><soap:Fault><!DOCTYPE x><faultcode>soap:Server</faultcode>"
        "</soap:Fault></soap:Body></soap:Envelope>"
    ),
    "bang-before-the-faultcode": (
        "<soap:Envelope><soap:Body><soap:Fault><!foo><faultcode>soap:Server</faultcode>"
        "</soap:Fault></soap:Body></soap:Envelope>"
    ),
    # Hold shape D: SOAP 1.1's faultstring ahead of its faultcode.
    "faultstring-before-the-faultcode": (
        "<soap:Envelope><soap:Body><soap:Fault><faultstring>busy</faultstring>"
        "<faultcode>soap:Server</faultcode></soap:Fault></soap:Body></soap:Envelope>"
    ),
    "reason-before-the-code": (
        "<env:Envelope><env:Body><env:Fault><env:Reason><env:Text xml:lang='en'>busy</env:Text>"
        "</env:Reason><env:Code><env:Value>env:Receiver</env:Value></env:Code></env:Fault>"
        "</env:Body></env:Envelope>"
    ),
    "unterminated-comment-in-the-fault": (
        "<soap:Envelope><soap:Body><soap:Fault><!-- note <faultcode>soap:Server</faultcode>"
        "</soap:Fault></soap:Body></soap:Envelope>"
    ),
    "lowercase-cdata-before-the-faultcode": (
        "<soap:Envelope><soap:Body><soap:Fault><![cdata[note]]><faultcode>soap:Server</faultcode>"
        "</soap:Fault></soap:Body></soap:Envelope>"
    ),
}


def _pr2790_fault_code(body: str) -> str:
    """The PR 2790 reading, kept as this test's control: the Fault's first Value before any
    faultcode, else that faultcode."""
    fault, _ = soap._find_fault(body)
    if fault is None:
        return ""
    end_match = soap._FAULT_END_RE.search(body, fault.end())
    end = len(body) if end_match is None else end_match.start()
    faultcode = soap._FAULTCODE_RE.search(body, fault.end(), end)
    value = soap._CODEVALUE_RE.search(
        body, fault.end(), end if faultcode is None else faultcode.start()
    )
    if value is not None:
        return soap._code_text(value, soap._CODEVALUE_END_RE, body, end)
    if faultcode is not None:
        return soap._code_text(faultcode, soap._FAULTCODE_END_RE, body, end)
    return ""


@pytest.mark.parametrize(
    "body", list(_NO_FIRST_CHILD_CODE.values()), ids=list(_NO_FIRST_CHILD_CODE)
)
def test_with_no_first_child_code_the_fallback_reads_as_before(body: str) -> None:
    """The PR 2936 hold of 2026-11-14: where the Fault's first child yields no code, the fallback
    reads each shape as the PR 2790 reading did, so none is newly dead-lettered. That keeps the PR
    2790 trade for these shapes: a Value outside the Code decides them, as it did before #5912, so
    the three whose real code is Sender or Client (the Role one and the two ahead of a faultcode)
    retry, as main retries them. ``_pr2790_fault_code`` shares this module's patterns and Fault
    search, so it pins the reading's order; the written-out reference checks the patterns. Control: with the fallback patched
    out, each reads as no code, a permanent fault, as PR 2936 head 933e347fe8 read it."""
    reading = _pr2790_fault_code(body)
    assert soap._RECEIVER_RE.search(reading), "the shape must hold a retryable reading"
    assert _fault_code(body) == reading == _ref_fault_code(body)
    assert _outcome(_classify_soap(200, body)) == "transient"
    assert _outcome(_classify_soap(500, body)) == "transient"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(soap, "_searched_code", lambda body, start, end: "")
        assert _fault_code(body) == ""
        assert _outcome(_classify_soap(200, body)) == "soap-fault"


#: BACKLOG #5912: where the first child holds the code, a Value outside the Code, here inside markup
#: ahead of it, does not decide the fault, though the PR 2790 reading took it.
_VALUE_IN_MARKUP_BEFORE_THE_CODE = {
    "soap11-commented-value-before-faultcode": (
        "<soap:Fault><!-- <Value>Server</Value> --><faultcode>soap:Client</faultcode></soap:Fault>",
        "soap:Client",
    ),
    "soap12-commented-value-in-the-code": (
        "<env:Fault><env:Code><!-- <x:Value>Receiver</x:Value> --><env:Value>env:Sender"
        "</env:Value></env:Code></env:Fault>",
        "env:Sender",
    ),
}


@pytest.mark.parametrize(
    ("body", "code"),
    list(_VALUE_IN_MARKUP_BEFORE_THE_CODE.values()),
    ids=list(_VALUE_IN_MARKUP_BEFORE_THE_CODE),
)
def test_a_value_outside_the_first_child_code_does_not_decide_the_fault(
    body: str, code: str
) -> None:
    """Red on the PR 2790 reading, which retried each of these as a Receiver fault. At least these
    shapes, a Sender code read past a Value inside markup, are main-retried replies now
    dead-lettered; a Client fault after a commented Server fault is another."""
    assert soap._RECEIVER_RE.search(_pr2790_fault_code(body)), "the shape must exercise the defect"
    assert _fault_code(body) == code
    assert _outcome(_classify_soap(200, body)) == "soap-sender"
    assert _outcome(_classify_soap(500, body)) == "soap-sender"


_STILL_RECEIVER = {
    "header-sender-fault-receiver": (
        "<env:Envelope><env:Header><x:Value>Sender</x:Value></env:Header><env:Body>"
        "<env:Fault><env:Code><env:Value>env:Receiver</env:Value></env:Code></env:Fault>"
        "</env:Body></env:Envelope>"
    ),
    "faultcode-then-faultstring": (
        "<soap:Fault><faultcode>soap:Server</faultcode><faultstring>Client busy</faultstring>"
        "</soap:Fault>"
    ),
    # BACKLOG #5912: a Value in the Detail does not override the Code's.
    "code-receiver-detail-sender": (
        "<env:Fault><env:Code><env:Value>env:Receiver</env:Value></env:Code><env:Detail>"
        "<x:Value>Sender</x:Value></env:Detail></env:Fault>"
    ),
}


@pytest.mark.parametrize("body", list(_STILL_RECEIVER.values()), ids=list(_STILL_RECEIVER))
def test_a_receiver_code_in_the_fault_still_retries(body: str) -> None:
    """Control for both defects: a real Receiver code inside the Fault still reads as transient, so
    the two tests above do not pass by reading every fault as permanent."""
    failure = _classify_soap(200, body)
    assert isinstance(failure, DeliveryError) and not isinstance(failure, NegativeAckError)


# The Fault is read from the SOAP Body. Each test's control patches the Body anchor out, so the
# whole reply is searched as it is with no Body start tag, and shows the shape reads otherwise.
_NO_BODY_ANCHOR = re.compile(r"(?!)")

_SOAP11_RECEIVER_BODY = (
    "<soap:Body><soap:Fault><faultcode>soap:Server</faultcode></soap:Fault></soap:Body>"
    "</soap:Envelope>"
)
_SOAP12_RECEIVER_BODY = (
    "<env:Body><env:Fault><env:Code><env:Value>env:Receiver</env:Value></env:Code></env:Fault>"
    "</env:Body></env:Envelope>"
)
#: Each shape, its outcome, and its outcome with the anchor patched out.
_BEFORE_THE_BODY = {
    # A Fault-named element, or a WS-Security code, before a Body Receiver fault.
    "header-self-closing-fault": (
        "<soap:Envelope><soap:Header><x:Fault/></soap:Header>" + _SOAP11_RECEIVER_BODY,
        "transient",
        "soap-fault",
    ),
    "header-fault-with-text": (
        "<env:Envelope><env:Header><x:Fault>none</x:Fault></env:Header>" + _SOAP12_RECEIVER_BODY,
        "transient",
        "soap-fault",
    ),
    "header-wsse-code": (
        "<env:Envelope><env:Header><x:Note>MessageExpired</x:Note></env:Header>"
        + _SOAP12_RECEIVER_BODY,
        "transient",
        "wssecurity",
    ),
    # A Body Sender fault still dead-letters.
    "header-self-closing-fault-sender-body": (
        "<soap:Envelope><soap:Header><x:Fault/></soap:Header><soap:Body><soap:Fault>"
        "<faultcode>soap:Client</faultcode></soap:Fault></soap:Body></soap:Envelope>",
        "soap-sender",
        "soap-fault",
    ),
    "header-receiver-fault-sender-body": (
        "<env:Envelope><env:Header><x:Fault><x:Code><x:Value>Receiver</x:Value></x:Code></x:Fault>"
        "</env:Header><env:Body><env:Fault><env:Code><env:Value>env:Sender</env:Value></env:Code>"
        "</env:Fault></env:Body></env:Envelope>",
        "soap-sender",
        "transient",
    ),
}


def _outcome(failure: DeliveryError | None) -> str:
    """``delivered``, ``transient``, or a permanent failure's code."""
    if failure is None:
        return "delivered"
    if isinstance(failure, NegativeAckError):
        assert failure.permanent
        return failure.code
    return "transient"


@pytest.mark.parametrize(
    ("body", "outcome", "unanchored"), list(_BEFORE_THE_BODY.values()), ids=list(_BEFORE_THE_BODY)
)
def test_the_fault_is_read_from_the_body(
    body: str, outcome: str, unanchored: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """What comes before the Body does not decide the reply's class. Control: with the anchor
    patched out the shape reads otherwise, as it did when the first Fault, and any WS-Security
    code, anywhere was read."""
    assert _outcome(_classify_soap(200, body)) == outcome
    monkeypatch.setattr(soap, "_BODY_RE", _NO_BODY_ANCHOR)
    assert _outcome(_classify_soap(200, body)) == unanchored


#: BACKLOG #5912, the PR 2936 hold: a Fault start tag, or a Fault or Code close tag, inside a
#: comment, a CDATA section or a processing instruction is not markup the Fault search, or its
#: close-tag searches, may stop at. Each shape, its outcome, and its outcome with that step-over
#: patched out, as PR 2936 head adfdcd5d31 read it; where the two are the same, the shape pins a
#: reading the step-over must not change.
_FAULT_TAG_IN_MARKUP = {
    "comment-fault-before-a-server-fault": (
        "<soap:Envelope><soap:Body><!-- <soap:Fault> --><soap:Fault><faultcode>soap:Server"
        "</faultcode><faultstring>busy</faultstring></soap:Fault></soap:Body></soap:Envelope>",
        "transient",
        "soap-fault",
    ),
    "cdata-fault-before-a-server-fault": (
        "<soap:Envelope><soap:Body><![CDATA[<soap:Fault>]]><soap:Fault><faultcode>soap:Server"
        "</faultcode></soap:Fault></soap:Body></soap:Envelope>",
        "transient",
        "soap-fault",
    ),
    "pi-fault-before-a-server-fault": (
        "<soap:Envelope><soap:Body><?note <soap:Fault>?><soap:Fault><faultcode>soap:Server"
        "</faultcode></soap:Fault></soap:Body></soap:Envelope>",
        "transient",
        "soap-fault",
    ),
    "comment-fault-before-a-receiver-fault": (
        "<env:Envelope><env:Body><!-- <env:Fault> --><env:Fault><env:Code><env:Value>env:Receiver"
        "</env:Value></env:Code></env:Fault></env:Body></env:Envelope>",
        "transient",
        "soap-fault",
    ),
    "comment-fault-no-envelope": (
        "<!-- <Fault> --><Fault><faultcode>soap:Server</faultcode></Fault>",
        "transient",
        "soap-fault",
    ),
    "comment-before-the-envelope": (
        "<!-- <Fault/> --><soap:Envelope>" + _SOAP11_RECEIVER_BODY,
        "transient",
        "transient",
    ),
    "comment-before-the-body": (
        "<env:Envelope><!-- <Fault/> -->" + _SOAP12_RECEIVER_BODY,
        "transient",
        "transient",
    ),
    "comment-fault-close-before-the-code": (
        "<soap:Body><soap:Fault><!-- </soap:Fault> --><faultcode>soap:Server</faultcode>"
        "</soap:Fault></soap:Body>",
        "transient",
        "soap-fault",
    ),
    "comment-code-close-before-the-value": (
        "<env:Body><env:Fault><env:Code><!-- </env:Code> --><env:Value>env:Receiver</env:Value>"
        "</env:Code></env:Fault></env:Body>",
        "transient",
        "soap-fault",
    ),
    # Cut short at the commented close tag, the Code yields no code, and the fallback would read
    # the commented Value ahead of it, so this one pins the Code close-tag step-over even with the
    # fallback in place.
    "comment-code-close-after-a-commented-value": (
        "<env:Body><env:Fault><!-- <x:Value>Sender</x:Value> --><env:Code><!-- </env:Code> -->"
        "<env:Value>env:Receiver</env:Value></env:Code></env:Fault></env:Body>",
        "transient",
        "soap-fault",
    ),
    # Controls: a Sender fault after a commented Fault still dead-letters.
    "comment-fault-before-a-client-fault": (
        "<soap:Body><!-- <soap:Fault> --><soap:Fault><faultcode>soap:Client</faultcode>"
        "</soap:Fault></soap:Body>",
        "soap-sender",
        "soap-fault",
    ),
    # With every Fault start tag in markup the search reads as it did before: the reply is never
    # newly read as delivered.
    "only-a-commented-fault": (
        "<soap:Body><!-- <soap:Fault><faultcode>soap:Client</faultcode></soap:Fault> -->"
        "<m:Ack/></soap:Body>",
        "soap-sender",
        "soap-sender",
    ),
    # The first Body start tag inside a comment: the markup it sits in is known after it, so the
    # Fault in the same comment is not the Body's.
    "body-tag-in-a-comment": (
        "<!-- <soap:Body><soap:Fault><faultcode>soap:Server</faultcode></soap:Fault> -->"
        "<soap:Envelope><soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault>"
        "</soap:Body></soap:Envelope>",
        "soap-sender",
        "transient",
    ),
    "body-tag-in-a-comment-server-fault": (
        "<!-- <soap:Body><soap:Fault><faultcode>soap:Client</faultcode></soap:Fault> -->"
        "<soap:Envelope><soap:Body><soap:Fault><faultcode>soap:Server</faultcode></soap:Fault>"
        "</soap:Body></soap:Envelope>",
        "transient",
        "soap-sender",
    ),
    # A commented Fault in the Body still comes before a Header Fault outside markup, as the Body
    # anchor has it.
    "header-fault-and-a-commented-body-fault": (
        "<env:Envelope><env:Header><x:Fault>none</x:Fault></env:Header><env:Body><!-- <env:Fault>"
        "<env:Code><env:Value>env:Receiver</env:Value></env:Code></env:Fault> --></env:Body>"
        "</env:Envelope>",
        "transient",
        "transient",
    ),
}


@pytest.mark.parametrize(
    ("body", "outcome", "unmarked"),
    list(_FAULT_TAG_IN_MARKUP.values()),
    ids=list(_FAULT_TAG_IN_MARKUP),
)
def test_a_fault_tag_inside_markup_does_not_decide_the_fault(
    body: str, outcome: str, unmarked: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A Fault-named tag inside markup is stepped over. Control: each shape holds such a tag, and
    with the plain tag patterns patched in for the outside-markup ones, and the fallback patched
    out, the shape reads as PR 2936 head adfdcd5d31 read it, so a shape whose two outcomes differ
    was red there. With the fallback in place, at least the two body-tag-in-a-comment shapes and
    comment-code-close-after-a-commented-value still go red without the step-over; the fallback
    reads the rest as their outcome anyway."""
    spans = [m.span() for m in re.finditer(_REF_MARKUP, body, re.DOTALL)]
    tags = (soap._FAULT_RE, soap._FAULT_END_RE, soap._CODE_END_RE)
    assert any(a < m.start() < b for rx in tags for m in rx.finditer(body) for a, b in spans), (
        "the shape must hold a Fault-named tag inside markup"
    )
    assert _outcome(_classify_soap(200, body)) == outcome
    assert _outcome(_classify_soap(500, body)) == outcome
    assert _fault_code(body) == _ref_fault_code(body)
    monkeypatch.setattr(soap, "_FAULT_OUTSIDE_MARKUP_RE", soap._FAULT_RE)
    monkeypatch.setattr(soap, "_FAULT_END_OUTSIDE_MARKUP_RE", soap._FAULT_END_RE)
    monkeypatch.setattr(soap, "_CODE_END_OUTSIDE_MARKUP_RE", soap._CODE_END_RE)
    # Head adfdcd5d31 had no fallback to the earlier search, which may read such a shape too.
    monkeypatch.setattr(soap, "_searched_code", lambda body, start, end: "")
    assert _outcome(_classify_soap(200, body)) == unmarked


def test_each_outside_markup_pattern_is_its_tag_and_the_markup_openers() -> None:
    """The three patterns are literal, so this pins that each is the markup openers the first-child
    search steps over and the plain tag pattern, in any case: a markup kind or a tag rule changed in
    one place only would otherwise drift silently."""
    openers = r"<!--|<!\[CDATA\[|<\?"
    assert [re.fullmatch(openers, o) is not None for o, _ in soap._NON_ELEMENT_MARKUP] == [True] * 3
    for outside, tag in (
        (soap._FAULT_OUTSIDE_MARKUP_RE, soap._FAULT_RE),
        (soap._FAULT_END_OUTSIDE_MARKUP_RE, soap._FAULT_END_RE),
        (soap._CODE_END_OUTSIDE_MARKUP_RE, soap._CODE_END_RE),
    ):
        assert tag.flags & re.IGNORECASE
        assert outside.pattern == openers + "|(?i:" + tag.pattern + ")"


_NO_FAULT_AFTER_THE_BODY = {
    # A Fault reply with no envelope, and a Body-named element in its detail.
    "body-in-the-fault-detail": (
        "<soap:Fault><faultcode>soap:Client</faultcode><detail><Body>x</Body></detail></soap:Fault>",
        "soap-sender",
    ),
    "body-in-a-wsse-fault-detail": (
        "<soap:Fault><faultcode>wsse:FailedAuthentication</faultcode><detail><x:body >x</x:body>"
        "</detail></soap:Fault>",
        "wssecurity",
    ),
    # A Fault only before the Body still reads as one.
    "header-fault-only": (
        "<soap:Envelope><soap:Header><x:Fault/></soap:Header><soap:Body><m:Ack>ok</m:Ack>"
        "</soap:Body></soap:Envelope>",
        "soap-fault",
    ),
}


@pytest.mark.parametrize(
    ("body", "outcome"), list(_NO_FAULT_AFTER_THE_BODY.values()), ids=list(_NO_FAULT_AFTER_THE_BODY)
)
def test_with_no_fault_after_the_body_the_whole_reply_is_read(body: str, outcome: str) -> None:
    """Even on HTTP 200, so a rejection is never recorded as delivered. Control: no Fault follows
    the first Body start tag, so the search from there alone would find none."""
    body_tag = soap._BODY_RE.search(body)
    assert body_tag is not None and soap._FAULT_RE.search(body, body_tag.end()) is None
    assert _outcome(_classify_soap(200, body)) == outcome


#: Fragments a random reply is built from: the delimiters the scan looks for, the names, legal and
#: illegal prefixes, whitespace, and text.
_FRAGMENTS = (
    "<", ">", "</", "/>", " ", "\n", "faultcode", "FaultCode", "Value", "VALUE", "Fault",
    "soap:", "SOAP-ENV:", "a.b:", ":", "x", "Client", "Receiver", '"', "'", "=", "<!--", "-->",
    "<![CDATA[", "]]>", "faultcodes", "Values", "Body", "<x:Body>", "Code", "<Code>", "</Code>",
)  # fmt: skip
#: What goes before the Body: the fragments, and Fault-named elements the Body anchor must skip,
#: two of them holding a code so the anchor changes what is read.
_HEAD_FRAGMENTS = _FRAGMENTS + (
    "<x:Fault>", "<x:Fault/>", "</x:Fault>", "<!-- <Fault/> -->", "<?a <x:Fault>?>", "<?", "?>",
    "<x:Fault><x:faultcode>Server</x:faultcode>", "<x:Fault><x:Code><x:Value>Receiver</x:Value>",
)  # fmt: skip
#: Each envelope's text before its head fragments, and from there to its Fault's first child. The
#: last has no envelope, so a Body-named fragment after its Fault comes after the Fault.
_ENVELOPES = (
    ("<soap:Envelope><soap:Header>", "</soap:Header><soap:Body><soap:Fault>"),
    ("<env:Envelope>", "<env:Body ><env:Fault><env:Code>"),
    ("<Envelope><Header>", "</Header><Body><Fault><Code>"),
    # BACKLOG #5912: markup holding a Fault start tag between the Body and the real Fault.
    ("<s:Envelope><s:Header>", "</s:Header><s:Body><!-- <s:Fault> --><?p <Fault>?><s:Fault>"),
    ("", "<soap:Fault>"),
)
#: What may come between a Fault's, or a Code's, start tag and its first child: markup the
#: first-child search steps over whole (some holding a code element), an unterminated comment, a
#: DOCTYPE, text, and nothing, the most likely.
_BEFORE_THE_CHILD = (
    "", "", "", "", " ", "t", "<!-- <faultcode>Server</faultcode> -->", "<?pi <Value>Receiver?>",
    "<![CDATA[<Value>Receiver</Value>]]>", "<!-- -->", "<!--", "<!DOCTYPE x>", "<?x?>",
)  # fmt: skip
#: A code element's start tag and its own close tag, around random fragments.
_CODE_ELEMENTS = (
    ("<faultcode>", "</faultcode>"),
    ("<soap:faultcode a='b'>", "</soap:faultcode >"),
    ("<Value>", "</Value>"),
    ("<env:Value >", "</env:Value>"),
)


def _random_reply(rng: random.Random) -> str:
    def fragments(alphabet: tuple[str, ...], most: int) -> str:
        return "".join(rng.choice(alphabet) for _ in range(rng.randint(0, most)))

    envelope, body_to_fault = rng.choice(_ENVELOPES)
    start, close = rng.choice(_CODE_ELEMENTS)
    return (
        envelope
        + fragments(_HEAD_FRAGMENTS, 6)
        + body_to_fault
        + fragments(_BEFORE_THE_CHILD, 1)
        + start
        + fragments(_FRAGMENTS, 2)
        + close
        + fragments(_FRAGMENTS, 12)
    )


def test_random_replies_yield_the_reference_reading() -> None:
    """The argument is in ``_fault_code``'s docstring; this samples it against the regex reference.
    Seeded, so a failure replays.

    Each reply opens a Fault and a code element, most of them inside an Envelope and a Body, so the
    floors below hold: at least a fifth of the replies yield a code, at least one in twenty reads
    differently when the Fault is searched for from the reply's start, and at least one in fifty
    has a Body start tag with no Fault after it. Without them a sample of bodies that yield no
    code, or that never reach the anchor or its fallback, would pass any extraction (the seeded
    sample read about 54%, 6.8% and 4.5% on 2026-11-04, and 24.8%, 12.6% and 4.5% after BACKLOG
    #5912 on 2026-11-13: a Value outside a Code, and a code element that is not the Fault's first
    child, now yield none, the head fragments gained two Faults that hold a code, and markup the
    first-child search steps over may precede the code element; and 25.3%, 16.9% and 3.5% after
    the PR 2936 repair, the same day, which added markup holding Fault start tags to the head
    fragments and to one envelope's Body; and 56.2%, 15.8% and 3.5% after the 2026-11-14 hold
    repair, whose fallback to the earlier search reads a code from most of the replies the
    first-child read yields none for)."""
    rng = random.Random(2827)
    total, with_a_code, anchored, fallback = 5_000, 0, 0, 0
    for _ in range(total):
        body = _random_reply(rng)
        code = _fault_code(body)
        assert code == _ref_fault_code(body), repr(body)
        with_a_code += bool(code)
        anchored += code != _fault_code(body, soap._FAULT_RE.search(body))
        body_tag = soap._BODY_RE.search(body)
        fallback += body_tag is not None and not soap._FAULT_RE.search(body, body_tag.end())
    assert with_a_code >= total // 5, f"only {with_a_code} of {total} replies yield a code"
    assert anchored >= total // 20, f"the Body anchor decided only {anchored} of {total} replies"
    assert fallback >= total // 50, f"only {fallback} of {total} replies had no Fault after a Body"


# --- linear growth, with a positive control -----------------------------------------------------

#: The time ratio between an input four times as long and the base one. A linear scan gives about
#: 4 and a quadratic one about 16, so 8 splits them with room for runner noise either way. The same
#: line and attempt rule as tests/test_ad_group_dn_only.py.
_MAX_LINEAR_RATIO = 8.0

#: Replies shaped to make the old tails rescan: many start tags, none of them closed. ``long-prefixes``,
#: ``lt-run`` and ``long-close-prefixes`` name neither element, so they never reached the old tails;
#: the three ``long-code-*`` shapes reach a code element's checks: ``long-code-close-prefix`` and
#: ``long-code-text`` the faultcode's, in ``_code_text``, and ``long-code-close-prefixes`` the Code's
#: close-tag search, ``_CODE_END_RE``. Since BACKLOG
#: #5912 the name regexes are tried first anchored, ``faultcode`` and ``Code`` at the Fault's first
#: child and ``Value`` at the Code's; where that read yields no code, as on ``long-prefixes``,
#: ``value-start-tags`` and ``unterminated-value-tags``, the fallback's ``faultcode`` and ``Value``
#: name scans run over the Fault too, so those shapes time them as well; ``unterminated-value-tags-in-a-code`` reaches the Value path. ``long-prefixes`` is here for the
#: name regexes' ``[\w.\-]+:`` prefix class, which backtracks over each run that has no colon, and
#: ``long-close-prefixes`` for the same class in the Fault close-tag scan, ``_FAULT_END_RE``.
#: ``lt-run`` is the shape measured in ``SoapDestination._post_and_classify``'s docstring.
_PATHOLOGICAL_REPLIES: dict[str, Callable[[int], str]] = {
    "faultcode-start-tags": lambda k: "<soap:Fault>" + "<faultcode>" * (k // 11),
    "value-start-tags": lambda k: "<soap:Fault>" + "<soap:Value>" * (k // 12),
    "unterminated-faultcode-tags": lambda k: "<Fault>" + "<faultcode " * (k // 11),
    "unterminated-value-tags": lambda k: "<Fault>" + "<Value " * (k // 7),
    "long-prefixes": lambda k: "<Fault>" + ("<" + "a." * 50) * (k // 101),
    "lt-run": lambda k: "<Fault>" + "<" * k,
    # The Fault close-tag scan's prefix class, over close tags with no colon.
    "long-close-prefixes": lambda k: "<Fault>" + ("</" + "a." * 50) * (k // 102),
    # A code element's own close-tag check, over one long prefix run with no colon, and its scan
    # for a nested start tag, over a long run of comment openers.
    "long-code-close-prefix": lambda k: "<Fault><faultcode>x</" + "a." * (k // 2),
    "long-code-text": lambda k: "<Fault><faultcode>" + "<!x" * (k // 3) + "</faultcode>",
    # BACKLOG #5912: the SOAP 1.2 Code read, over unterminated Value start tags inside one Code,
    # and its close-tag scan over close tags with no colon.
    "unterminated-value-tags-in-a-code": lambda k: "<Fault><Code>" + "<Value " * (k // 7),
    # The first-child search's step over comments, processing instructions and unterminated ones.
    "comment-run": lambda k: "<Fault>" + "<!---->" * (k // 7),
    "unterminated-comments": lambda k: "<Fault>" + "<!--" * (k // 4),
    "pi-run-in-a-code": lambda k: "<Fault><Code>" + "<?a?>" * (k // 5),
    "long-code-close-prefixes": lambda k: "<Fault><Code>x" + ("</" + "a." * 50) * (k // 102),
    # The Body anchor's scan, ``_BODY_RE``, over the same prefix runs and a run of ``<``, before a
    # Body that holds the Fault.
    "long-prefixes-before-the-body": lambda k: ("<" + "a." * 50) * (k // 101) + "<Body><Fault>",
    "lt-run-before-the-body": lambda k: "<" * k + "<Body><Fault><faultcode>",
    # BACKLOG #5912: the Fault search's step over markup, terminated and not, and the close-tag
    # searches' step over comments holding a close tag.
    "commented-faults-before-the-fault": lambda k: "<!-- <Fault> -->" * (k // 16) + "<Fault>",
    "unterminated-markup-before-the-fault": lambda k: "<![CDATA[<?<!--" * (k // 15) + "<Fault>",
    "commented-faults-after-the-body": lambda k: "<soap:Body>" + "<!-- <Fault> -->" * (k // 16),
    "commented-body-and-pis-after-it": lambda k: (
        "<!-- <Body> -->" + "<Body>" + "<?a <Fault>?>" * (k // 13)
    ),
    "commented-close-tags-in-a-code": lambda k: (
        "<Fault><Code>" + "<!-- </Code></Fault> -->" * (k // 24)
    ),
    # The fallback when no Fault follows the Body: the search after it, then the one before it.
    "lt-runs-around-a-trailing-body": lambda k: (
        "<Fault>" + "<" * (k // 2) + "<Body>" + "<" * (k // 2)
    ),
}


def _attempt_ratio(scan: Callable[[str], object], small: str, large: str) -> float:
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        return _growth_between(scan, small, large, rounds=3)
    finally:
        if was_enabled:
            gc.enable()


def _scaling_ratios(
    scan: Callable[[str], object], make: Callable[[int], str], k: int
) -> list[float]:
    """Time on a ``4 * k`` reply over time on a ``k`` one, re-measured up to three times while a
    reading is at or over the line, so one preemption cannot fake a curve. The lowest is the
    verdict for both the linear checks and the control."""
    small, large = make(k), make(4 * k)
    readings: list[float] = []
    for _ in range(3):
        readings.append(_attempt_ratio(scan, small, large))
        if readings[-1] < _MAX_LINEAR_RATIO:
            break
    return readings


def _attempts(readings: list[float]) -> str:
    return "attempts: " + ", ".join(f"{reading:.2f}x" for reading in readings)


def _classify_2xx(body: str) -> object:
    return _classify_soap(200, body)


@pytest.mark.parametrize(
    "make", list(_PATHOLOGICAL_REPLIES.values()), ids=list(_PATHOLOGICAL_REPLIES)
)
def test_a_pathological_reply_is_classified_in_linear_time(make: Callable[[int], str]) -> None:
    """The whole 2xx classification, every regex in it, on a reply up to 400,000 characters. Each
    shape is first shown to read as a fault, so the timing covers the fault-code extraction rather
    than a fault-less fall-through to the status."""
    assert isinstance(_classify_2xx(make(1_000)), NegativeAckError)
    readings = _scaling_ratios(_classify_2xx, make, 100_000)
    ratio = min(readings)
    assert ratio < _MAX_LINEAR_RATIO, (
        f"4x the reply took {ratio:.2f}x the time ({_attempts(readings)})"
    )


@pytest.mark.parametrize(
    ("shape", "k"), [("faultcode-start-tags", 2_000), ("unterminated-value-tags", 8_000)]
)
def test_the_linear_check_fails_the_old_patterns(
    shape: str, k: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Positive control: the check above must fail the patterns #2827 replaced, or its pass proves
    nothing. It times the same subject, the 2xx classification, with the old extraction patched
    in, and asserts exactly the negation of that pass condition, once per old pattern and once per
    tail (``(.*?)</`` and ``[^>]*>``).

    The old patterns took about 0.4 s at 44,000 characters, so this runs far below the linear
    check's sizes. Each ``k`` is where the old curve read well clear of the line in 12 runs on one
    workstation (2026-11-03): 13.8x to 15.8x and 12.9x to 15.9x. The ``(.*?)</`` tail is the
    costlier one, so its ``k`` is smaller; at 4,000 it read once at 9.6x and took 1.6 s a run."""
    monkeypatch.setattr(soap, "_fault_code", _old_fault_code)
    readings = _scaling_ratios(_classify_2xx, _PATHOLOGICAL_REPLIES[shape], k)
    ratio = min(readings)
    assert ratio >= _MAX_LINEAR_RATIO, (
        f"the old patterns scaled by only {ratio:.2f}x ({_attempts(readings)})"
    )


# --- the 2xx classification runs off the event loop ---------------------------------------------


class _Resp:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def read(self, amt: int = -1) -> bytes:
        return self._body if amt < 0 else self._body[:amt]

    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *a: object) -> None:
        return None


class _Opener:
    def __init__(self, body: bytes) -> None:
        self._body = body

    def open(self, req: object, timeout: float | None = None) -> _Resp:
        return _Resp(self._body)


def _dest(*, capture_response: bool, **settings: Any) -> SoapDestination:
    d = build_destination(
        Destination(
            name="OB_SOAP",
            type=ConnectorType.SOAP,
            settings=Soap(
                url="https://api.example.com/svc", capture_response=capture_response, **settings
            ).settings,
        ),
        egress=EgressSettings(deny_by_default=False),
    )
    assert isinstance(d, SoapDestination)
    return d


_SECRET = "an-echoed-credential"


def _counting_hops(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    hops: list[object] = []
    to_thread = asyncio.to_thread

    async def counting_to_thread[T](func: Callable[..., T], /, *args: object) -> T:
        hops.append(func)
        return await to_thread(func, *args)

    monkeypatch.setattr(asyncio, "to_thread", counting_to_thread)
    return hops


@pytest.mark.parametrize("capture_response", [False, True], ids=["raising", "capturing"])
async def test_a_2xx_reply_is_classified_off_the_event_loop(
    capture_response: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The POST, the classification and the capture scrub run in one ``to_thread`` hop, on a
    thread that is not the loop's.

    Mutation: classify, or scrub, in ``send`` after the thread returns, as before #2827. Red: that
    recorded thread is the loop's. Mutation: a second ``to_thread`` hop for either. Red: the hop
    count. The thread ids alone cannot see that one, since the pool may hand both hops to the same
    idle worker."""
    threads: dict[str, list[int]] = {"post": [], "classify": [], "scrub": []}
    hops = _counting_hops(monkeypatch)

    def classify(status: int, body: str) -> DeliveryError | None:
        threads["classify"].append(threading.get_ident())
        return _classify_soap(status, body)

    monkeypatch.setattr(soap, "_classify_soap", classify)
    dest = _dest(capture_response=capture_response)
    # A secret the partner echoes in its Fault, which a capturing connection must mask.
    dest._body_secrets = (("{{TOKEN}}", _SECRET),)
    post, scrub = dest._post, dest._scrub_body_secrets

    def recording_post(payload: str) -> tuple[str, int, dict[str, str]]:
        threads["post"].append(threading.get_ident())
        return post(payload)

    def recording_scrub(text: str) -> str:
        threads["scrub"].append(threading.get_ident())
        return scrub(text)

    monkeypatch.setattr(dest, "_post", recording_post)
    monkeypatch.setattr(dest, "_scrub_body_secrets", recording_scrub)
    fault = f"<soap:Fault><faultcode>soap:Client</faultcode>{_SECRET}</soap:Fault>"
    dest._opener = _Opener(fault.encode())  # type: ignore[assignment]
    if capture_response:
        response = await dest.send("<env>{{TOKEN}}</env>")
        assert response is not None and response.outcome == "rejected"
        assert _SECRET not in response.body and "***" in response.body
        assert threads["scrub"], "a capturing connection with body_secrets scrubs the reply"
    else:
        with pytest.raises(NegativeAckError, match="Sender fault"):
            await dest.send("<env>{{TOKEN}}</env>")
        assert not threads["scrub"]
    assert len(hops) == 1, f"one to_thread hop, not {len(hops)}"
    (worker,) = threads["post"]
    assert worker != threading.get_ident()
    assert threads["classify"] == [worker]
    assert set(threads["scrub"]) <= {worker}


# --- the envelope wrap and the body secrets run in the same hop, before the POST ----------------


def _ws_dest() -> SoapDestination:
    dest = _dest(
        capture_response=True,
        soap_version="1.2",
        ws_addressing=True,
        ws_security=True,
        soap_action="urn:Submit",
    )
    dest._body_secrets = (("{{TOKEN}}", _SECRET),)
    dest._opener = _Opener(b"<ok/>")  # type: ignore[assignment]
    return dest


async def test_the_envelope_and_the_body_secrets_are_applied_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5913: the WS-* wrap, with its SAX fragment gate and its Timestamp read, and the
    body-secret substitution run in the same ``to_thread`` hop as the POST, in the order wrap,
    secrets, POST.

    Mutation: wrap, or substitute, in ``send`` before the hop, as before #5913. Red: that recorded
    thread is the loop's. Mutation: a hop of its own for either. Red: the hop count. Mutation:
    substitute before wrapping, or read the clock in ``send``. Red: the recorded order."""
    hops = _counting_hops(monkeypatch)
    dest = _ws_dest()
    calls: list[tuple[str, int]] = []
    sent: list[str] = []
    wrap, apply, post, now = dest._wrap_envelope, dest._apply_body_secrets, dest._post, dest._now_fn
    hop = dest._post_and_classify

    def recording_wrap(fragment: str) -> str:
        calls.append(("wrap", threading.get_ident()))
        return wrap(fragment)

    def recording_now() -> float:
        calls.append(("clock", threading.get_ident()))
        return now()

    def recording_apply(payload: str) -> str:
        calls.append(("secrets", threading.get_ident()))
        return apply(payload)

    def recording_post(payload: str) -> tuple[str, int, dict[str, str]]:
        calls.append(("post", threading.get_ident()))
        sent.append(payload)
        return post(payload)

    monkeypatch.setattr(dest, "_wrap_envelope", recording_wrap)
    monkeypatch.setattr(dest, "_apply_body_secrets", recording_apply)
    monkeypatch.setattr(dest, "_post", recording_post)
    monkeypatch.setattr(dest, "_now_fn", recording_now)
    response = await dest.send("<op>{{TOKEN}}</op>")
    assert response is not None and response.outcome == "accepted"
    assert hops == [hop], f"one to_thread hop, of _post_and_classify, not {hops}"
    assert [name for name, _ in calls] == ["wrap", "clock", "secrets", "post"]
    workers = {ident for _, ident in calls}
    assert len(workers) == 1 and threading.get_ident() not in workers
    (wire,) = sent
    assert "<soap:Envelope" in wire and "<wsu:Timestamp" in wire
    assert f"<soap:Body><op>{_SECRET}</op></soap:Body>" in wire
    assert "{{TOKEN}}" not in wire


@pytest.mark.parametrize(
    ("fragment", "error", "match"),
    [
        ("<op>{{TOKEN}}", ValueError, "not well-formed"),
        ("<op/>", NegativeAckError, "must appear exactly once"),
    ],
    ids=["fragment-gate", "body-secret-gate"],
)
async def test_a_refused_body_posts_nothing_from_the_worker_thread(
    fragment: str, error: type[Exception], match: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The fragment gate and the body-secret count gate still refuse before a byte crosses, now
    from inside the one hop, and the refusal reaches the caller with the type it had before #5913.
    The fragment gate's bare ValueError is that earlier type, kept rather than reclassified here."""
    hops = _counting_hops(monkeypatch)
    dest = _ws_dest()
    posted: list[str] = []

    def recording_post(payload: str) -> tuple[str, int, dict[str, str]]:
        posted.append(payload)
        return "", 200, {}

    hop = dest._post_and_classify
    monkeypatch.setattr(dest, "_post", recording_post)
    with pytest.raises(error, match=match):
        await dest.send(fragment)
    assert not posted, "nothing is POSTed before the gates pass"
    assert hops == [hop], f"one to_thread hop, of _post_and_classify, not {hops}"
