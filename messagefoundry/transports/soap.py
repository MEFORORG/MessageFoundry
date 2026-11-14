# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
r"""SOAP transport: a destination that POSTs a SOAP envelope to a web service.

The **destination** is a thin SOAP layer over the same stdlib HTTP client the REST connector uses
(ADR 0003) — it reuses REST's no-redirect, http(s)-only opener (so a 3xx can't divert a PHI-bearing
request; ASVS 15.3.2) and the fail-closed ``[egress].allowed_http`` host gate.

**Two modes (ADR 0015).**
- *Plain* (the default): the Handler produces the **full SOAP envelope** (XML); this adds the SOAP
  ``Content-Type`` + action and POSTs it — byte-identical to the original connector.
- *WS-\** (opt-in, `ws_addressing`/`ws_security`): the Handler produces only the operation **`<Body>`
  fragment**; the **transport** wraps it in the envelope and **stamps the non-deterministic
  WS-Addressing / WS-Security headers** (``<wsa:MessageID>``, ``<wsu:Timestamp>``, optional
  ``<wsse:UsernameToken>`` Nonce/Created) **in `send()`** — after the queue boundary, so a pure
  transform never produces a per-call nonce/timestamp and re-run purity holds (ADR 0015 §1). Envelope
  assembly is **stdlib string templating** (no XML parser); the attacker-influenceable ``<Body>``
  fragment is checked once with a hardened, non-resolving, no-DTD well-formedness gate (XXE-negative).
  WS-\* requires SOAP 1.2.

**Mutual TLS (ADR 0015).** ``client_cert_file``/``client_key_file`` present a client certificate via a
per-connection opener (server verification stays on); incompatible with ``verify_tls=False``.

**SOAP version.** ``1.1`` → ``Content-Type: text/xml; charset=utf-8`` + a ``SOAPAction`` header;
``1.2`` → ``Content-Type: application/soap+xml; charset=utf-8; action="…"`` (no ``SOAPAction`` header).

**Fault mapping.** A response is inspected for a SOAP ``Fault`` (faults can arrive as HTTP 500 *or* an
HTTP 200 body). A WS-Security fault (FailedAuthentication / InvalidSecurityToken / MessageExpired) →
:class:`NegativeAckError` (``permanent=True``) → dead-letter (a credential/expiry reject won't fix on a
retry). A **Sender/Client** fault → permanent dead-letter; a **Receiver/Server** fault →
:class:`DeliveryError` (retry). The code is read first from the Fault's first child, its faultcode or
Code, and where that yields none, from the Fault's first faultcode or a Value ahead of it
(``_fault_code`` says how). An unrecognized fault is treated as permanent. With no fault, the HTTP
status decides: 2xx delivered, 5xx retry, other 4xx / refused 3xx dead-letter; a connection/timeout
error retries. Fault bodies are **not** echoed into errors/logs (they may carry PHI) — only the SOAP
fault role + HTTP status are.

**Idempotency.** Delivery is at-least-once, so a retry **re-sends** (minting a fresh ``<wsa:MessageID>``
in WS-\* mode — correct WS-\* retry semantics). The service operation **must be idempotent** and its
dedup must treat a re-send as a retry, not a duplicate. See docs/CONNECTIONS.md.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import io
import logging
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.sax  # nosec B406 — hardened, non-resolving, no-DTD well-formedness gate only (ADR 0015 §2a)
from collections.abc import Callable, Mapping
from typing import Any
from xml.sax.handler import (  # nosec B406 — see _assert_well_formed_fragment (external entities OFF)
    ContentHandler,
    feature_external_ges,
    feature_external_pes,
)
from xml.sax.saxutils import escape as _xml_escape  # nosec B406 — pure string escaper, not a parser
from xml.sax.xmlreader import InputSource  # nosec B406 — fed only the hardened, no-DTD parser

from messagefoundry.config.models import ConnectorType, Destination, bool_setting
from messagefoundry.config.tls_policy import (
    SYSTEM_TRUST_ANCHOR,
    TrustAnchor,
    build_verifying_client_context,
    harden_cipher_suites,
    hop_name_prefix,
    narrow_to_approved_suites,
    relax_verify_expiry,
)
from messagefoundry.keywrap import load_checked_cert_chain
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    count_setting,
    encode_wire_body,
    float_setting,
    register_destination,
)
from messagefoundry.transports.bounded_read import (
    EgressReplyError,
    build_strict_opener,
    drain_bounded,
    hop_identity,
    read_2xx_reply_text,
    read_bounded_text,
)

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture.
from messagefoundry.transports.rest import (
    AUTH_CHALLENGE_REFUSED,
    HttpAuthError,
    InsecureHopGuard,
    ProxyConfig,
    _expiry_relaxed_opener,
    _insecure_opener,
    _is_shared_no_redirect_opener,
    _no_redirect_opener,
    _NoRedirectHandler,
    _redact_url,
    _shared_no_redirect_opener,
    assert_probe_hop,
    auth_challenge_refused,
    capture_response_headers,
    egress_route_from_settings,
    enforce_outbound_length_limits,
    enforce_send_time_length_limits,
    enforce_signature_header_limits,
    hop_reaches_a_proxy,
    http_credentials_sent,
    http_family_trust_anchor,
    normalize_header_allowlist,
    refuse_cleartext_credential_hop,
    refuse_cleartext_credentials,
    refuse_cleartext_egress,
    refuse_unrevoked_verified_hop,
    refuse_url_credentials,
    refuse_verify_off,
    url_scheme,
)
from messagefoundry.transports.signing import MessageSigner, signer_from_destination

__all__ = ["SoapDestination"]

logger = logging.getLogger(__name__)

# The prefix class must admit '.' and '-': `SOAP-ENV` is the prefix the SOAP 1.1 specification uses in
# its OWN examples, and it is what Apache Axis and much of the Java/.NET estate emit. `\w` excludes the
# hyphen, so a `\w+:` class silently fails to recognise the single most canonical fault envelope there
# is — and _classify_soap then falls through to the HTTP status, where a fault delivered (as SOAP
# faults routinely are) with HTTP 200 reads as SUCCESS. That is a wrong disposition on a real delivery,
# not a cosmetic miss. Kept identical to _HEADER_EL_RE below, which already had it right.
_FAULT_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Fault[\s/>]", re.IGNORECASE)
# The SOAP Body start tag. BACKLOG #2827: a SOAP 1.1 or 1.2 fault is a Body child, so _classify_soap
# searches for the Fault, and for a WS-Security code, from the first one; _find_fault says when it
# searches the whole reply instead.
_BODY_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Body[\s/>]", re.IGNORECASE)
_SENDER_RE = re.compile(r"client|sender", re.IGNORECASE)
_RECEIVER_RE = re.compile(r"server|receiver", re.IGNORECASE)
# WS-Security fault codes that are PERMANENT (a retry won't fix a rejected/expired credential).
_WSSE_FAULT_RE = re.compile(
    r"FailedAuthentication|InvalidSecurityToken|MessageExpired", re.IGNORECASE
)
# SOAP 1.1 <faultcode>…</faultcode>; SOAP 1.2 <Code><Value>…</Value></Code>. Only the start tag's
# NAME is a regex. BACKLOG #2827: the former `[^>]*>(.*?)</` tail rescanned to the end of the reply
# from every start tag lacking a close, so a partner reply of repeated start tags cost the square of
# its length. _code_text finds the `>` and `</` with str.find, once per code element, at most two
# (the first-child read's, then the fallback's), and only inside the Fault _find_fault took, up to
# that Fault's close tag or the reply's end. BACKLOG #5912: the code element is the Fault's first child, a faultcode or a Code (_CODE_RE),
# and for a Code the Value that is its own first child, up to its close tag (_CODE_END_RE);
# _fault_code says why, and when it falls back to the earlier search (_searched_code). For the
# first-child read the Fault and Code close tags are searched for outside markup, with
# _FAULT_END_OUTSIDE_MARKUP_RE and _CODE_END_OUTSIDE_MARKUP_RE, which hold _FAULT_END_RE and
# _CODE_END_RE; the fallback's range ends at the first plain _FAULT_END_RE match, markup not stepped over.
_FAULTCODE_RE = re.compile(r"<\s*(?:[\w.\-]+:)?faultcode\b", re.IGNORECASE)
_CODE_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Code(?=[\s/>])", re.IGNORECASE)
_CODEVALUE_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Value\b", re.IGNORECASE)
# The close tags, with the start tags' optional prefix. Literal, so tests/test_security_static.py
# can read them.
_FAULTCODE_END_RE = re.compile(r"</\s*(?:[\w.\-]+:)?faultcode\s*>", re.IGNORECASE)
_CODE_END_RE = re.compile(r"</\s*(?:[\w.\-]+:)?Code\s*>", re.IGNORECASE)
_CODEVALUE_END_RE = re.compile(r"</\s*(?:[\w.\-]+:)?Value\s*>", re.IGNORECASE)
_FAULT_END_RE = re.compile(r"</\s*(?:[\w.\-]+:)?Fault\s*>", re.IGNORECASE)
# A `<` that opens neither a comment, a CDATA section nor a processing instruction: another element.
_TAG_OPEN_RE = re.compile(r"<(?![!?])")
# Markup that is not an element, and its terminator: what _first_child steps over whole.
_NON_ELEMENT_MARKUP = (("<!--", "-->"), ("<![CDATA[", "]]>"), ("<?", "?>"))
_MARKUP_CLOSER = dict(_NON_ELEMENT_MARKUP)
# BACKLOG #5912: _FAULT_RE, _FAULT_END_RE and _CODE_END_RE, each with the openers of that markup as
# alternatives, so _search_outside_markup can step over a comment, CDATA section or processing
# instruction that holds a Fault start tag or a Fault or Code close tag. The openers stay
# case-sensitive, as XML has them; only each tag is matched in any case.
_FAULT_OUTSIDE_MARKUP_RE = re.compile(r"<!--|<!\[CDATA\[|<\?|(?i:<\s*(?:[\w.\-]+:)?Fault[\s/>])")
_FAULT_END_OUTSIDE_MARKUP_RE = re.compile(r"<!--|<!\[CDATA\[|<\?|(?i:</\s*(?:[\w.\-]+:)?Fault\s*>)")
_CODE_END_OUTSIDE_MARKUP_RE = re.compile(r"<!--|<!\[CDATA\[|<\?|(?i:</\s*(?:[\w.\-]+:)?Code\s*>)")
# A <…:Header> element (any/no namespace prefix) smuggled into a <Body> fragment (purity-leak lint).
_HEADER_EL_RE = re.compile(r"<\s*(?:[\w.\-]+:)?Header[\s/>]", re.IGNORECASE)

# Namespace URIs (fixed; the transport's header is namespace-controlled, ADR 0015 §2a).
_NS_SOAP12 = "http://www.w3.org/2003/05/soap-envelope"
_NS_WSA = "http://www.w3.org/2005/08/addressing"
_NS_WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
_NS_WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
_PW_TEXT = (
    "http://docs.oasis-open.org/wss/2004/01/"
    "oasis-200401-wss-username-token-profile-1.0#PasswordText"
)

# The envelope skeleton (SOAP 1.2 only; WS-* requires 1.2). Built by string concatenation, NOT
# str.format — an HL7-derived <Body> fragment may contain literal { } that would break .format.
_ENV_OPEN = (
    '<?xml version="1.0" encoding="utf-8"?>'
    f'<soap:Envelope xmlns:soap="{_NS_SOAP12}" xmlns:wsa="{_NS_WSA}" '
    f'xmlns:wsse="{_NS_WSSE}" xmlns:wsu="{_NS_WSU}">'
)


def _start_tag_gt(body: str, pos: int, end: int) -> int:
    """The ``>`` that ends the start tag whose name ends at ``pos``, or ``-1`` when it has none
    before ``end`` or is self-closing, so the element holds nothing."""
    gt = body.find(">", pos, end)
    return -1 if gt < 0 or body[gt - 1] == "/" else gt


def _code_text(m: re.Match[str], end_re: re.Pattern[str], body: str, end: int) -> str:
    """The text from the ``>`` of the start tag ``m`` begins to the next ``</``, before ``end``, or
    ``""`` when there is none or the element cannot hold a code.

    The capture is the one the former ``name[^>]*>(.*?)</`` DOTALL search took. BACKLOG #2827: the
    element cannot hold a code when it is self-closing, when the capture holds another element's
    start tag, or when the ``</`` is not ``end_re``, its own close tag. The capture would then be
    another element's text, such as ``<faultstring>Server busy`` after ``<faultcode/>``."""
    gt = _start_tag_gt(body, m.end(), end)
    close = -1 if gt < 0 else body.find("</", gt + 1, end)
    # Cheapest first: the scan for a nested start tag is the only check that reads the whole text.
    if close < 0 or not end_re.match(body, close, end) or _TAG_OPEN_RE.search(body, gt + 1, close):
        return ""
    return body[gt + 1 : close]


def _first_child(body: str, pos: int, end: int) -> int:
    """Where the first element tag at or after ``pos`` and before ``end`` starts, or ``-1``.

    BACKLOG #5912: a comment, a CDATA section or a processing instruction is stepped over whole, so
    markup inside one is never taken for the child. Where one has no terminator before ``end``, or
    a ``<!`` opens anything else, such as a DOCTYPE, there is no child: the first-child read then
    yields no code, and :func:`_fault_code` falls back to :func:`_searched_code`. Each step
    resumes after the markup it passed, so the search is linear."""
    while True:
        lt = body.find("<", pos, end)
        if lt < 0:
            return -1
        for opener, closer in _NON_ELEMENT_MARKUP:
            if body.startswith(opener, lt, end):
                close = body.find(closer, lt + len(opener), end)
                if close < 0:
                    return -1
                pos = close + len(closer)
                break
        else:
            return -1 if body.startswith("<!", lt, end) else lt


def _search_outside_markup(
    pattern: re.Pattern[str], body: str, pos: int, end: int, first: int = 0
) -> re.Match[str] | None:
    """The first match of ``pattern``'s tag in ``body[pos:end]`` that is not inside a comment, a
    CDATA section or a processing instruction, and starts at or after ``first``, or ``None``.
    ``pattern`` is one of the ``*_OUTSIDE_MARKUP_RE`` patterns, whose other alternatives are those
    markups' openers. The scan knows only the markup it opens after ``pos``, so ``pos`` should be
    outside such markup: :func:`_find_fault` scans from ``0``, or from the end of an earlier match
    of the same scan, and passes the Body start tag's end as ``first``. Where ``pos`` is inside
    markup, after a Fault start tag :func:`_find_fault` took from inside markup say, a close tag
    later in that same markup is taken as real.

    BACKLOG #5912: each markup is stepped over whole, as :func:`_first_child` steps over it, except
    for an opener with no terminator before ``end``: :func:`_first_child` reads that as no child,
    and this reads it as text, as it reads every later opener of its kind, since none of them can
    have a terminator either. So the search resumes after each step and stays linear in the
    reply."""
    unterminated: set[str] = set()
    while (m := pattern.search(body, pos, end)) is not None:
        opener = m.group()
        closer = _MARKUP_CLOSER.get(opener)
        pos = m.end()
        if closer is None:
            if m.start() >= first:
                return m
            continue
        close = -1 if opener in unterminated else body.find(closer, pos, end)
        if close < 0:
            unterminated.add(opener)
        else:
            pos = close + len(closer)
    return None


def _find_fault(body: str) -> tuple[re.Match[str] | None, int]:
    """The first Fault start tag from where the fault searches start, and that start: the end of
    the first ``_BODY_RE`` match where a Fault follows it, else ``0``, the whole reply.

    BACKLOG #2827: so a Fault-named element before the Body, in the Header say, does not decide the
    class of the Body's fault. The first Body start tag is taken even when it sits in a comment, a
    CDATA section or the Header. With no Body start tag, or no Fault after it, the reply is searched
    whole, as it was before the anchor: a Fault reply with no envelope may carry a Body-named
    element in its detail, and a Fault found only before the Body still reads as one.

    BACKLOG #5912: on each side of the Body start tag, a Fault start tag inside a comment, a CDATA
    section or a processing instruction is stepped over (:func:`_search_outside_markup`), so the
    real Fault after it is the one read. Only where every Fault start tag on that side is inside
    such markup is the first of them read, as before, so the Body side still comes first and such a
    reply still reads as a fault, never newly as delivered."""
    plain = _FAULT_RE.search(body)
    if plain is None:
        # Every match below is a _FAULT_RE match, so a reply with none, the delivered case, takes
        # one scan.
        return None, 0
    # One scan from 0, so markup opened before the Body start tag is known after it.
    outside = _search_outside_markup(_FAULT_OUTSIDE_MARKUP_RE, body, 0, len(body))
    m = _BODY_RE.search(body)
    if m is None:
        return outside or plain, 0
    after = outside
    if after is not None and after.start() < m.end():
        after = _search_outside_markup(
            _FAULT_OUTSIDE_MARKUP_RE, body, after.end(), len(body), first=m.end()
        )
    if after is None:
        after = _FAULT_RE.search(body, m.end())
    if after is not None:
        return after, m.end()
    # No Fault follows the Body start tag, so plain, and any outside-markup one, is before it.
    return outside or plain, 0


def _fault_code(body: str, fault: re.Match[str] | None = None) -> str:
    """The fault code text (e.g. ``soap:Client`` / ``soap:Receiver``), SOAP 1.1 or 1.2, or ``""``.

    BACKLOG #2827: read only inside ``fault``, a Fault start-tag match (:func:`_find_fault`'s when
    not given), from its start tag to its close tag or, with none, the reply's end, so a ``faultcode``
    or ``Value`` outside it, in the Header say, does not decide the fault's class. A self-closing
    Fault holds no code.

    BACKLOG #5912: the code element is the Fault's first child element (:func:`_first_child`):
    SOAP 1.1's ``faultcode`` or SOAP 1.2's ``Code``, which both schemas put first. For ``Code`` the
    code is the ``Value`` that is the Code's own first child, read only up to the Code's close tag.
    A ``Value`` anywhere else in the Fault, in a Subcode, Reason, Node, Role or Detail, never
    decides permanent versus retryable when the first child yields a code. A Fault or Code close
    tag inside a comment, a CDATA section or a processing instruction does not end either element
    (:func:`_search_outside_markup`).

    Where the first-child read yields no code, because the first child is neither element, it
    cannot hold a code, or a ``<!`` the read does not step over (a DOCTYPE, a lowercase
    ``<![cdata[``, an unterminated comment) stops it, the code falls back to the earlier search
    (:func:`_searched_code`), by that search's rule for its range: from the Fault start tag
    :func:`_find_fault` took to the first plain Fault close tag, or the reply's end, markup not
    stepped over. So, where :func:`_find_fault` takes the Fault start tag the code before #5912
    took, such a reply reads as it did then. A plain Receiver code the first-child read cannot
    place, after a SOAP 1.1 ``faultstring`` or a SOAP 1.2 ``Reason`` say, is read and retried, unless
    a Fault close tag inside a comment ahead of it ends the range first, when the fault reads no
    code and dead-letters; and, as before #5912, a ``Value`` ahead of
    the code element, or after a code element that holds no code, decides the class there, so a
    Sender fault of such a shape may read as a Receiver one and retry. Only where both reads find nothing is
    the code ``""``, which :func:`_classify_soap` reads as a permanent fault, never as delivered.
    Each read is one scan forward from the Fault, so the whole stays linear in the reply."""
    if fault is None:
        fault, _ = _find_fault(body)
        if fault is None:
            return ""
    start = fault.end()
    gt = _start_tag_gt(body, start - 1, len(body))
    if gt < 0:
        return ""
    fault_end = _search_outside_markup(_FAULT_END_OUTSIDE_MARKUP_RE, body, gt + 1, len(body))
    end = len(body) if fault_end is None else fault_end.start()
    code = _first_child_code(body, gt + 1, end)
    if code:
        return code
    # The earlier search's rule for its range's end: the first plain Fault close tag.
    plain_end = _FAULT_END_RE.search(body, start)
    return _searched_code(body, start, len(body) if plain_end is None else plain_end.start())


def _first_child_code(body: str, start: int, end: int) -> str:
    """The code the first child element in ``body[start:end]`` holds, or ``""``: the read
    :func:`_fault_code` tries first, ``start`` just after the Fault start tag's ``>`` and ``end``
    where the Fault ends."""
    child = _first_child(body, start, end)
    if child < 0:
        return ""
    faultcode = _FAULTCODE_RE.match(body, child, end)
    if faultcode is not None:
        return _code_text(faultcode, _FAULTCODE_END_RE, body, end)
    code = _CODE_RE.match(body, child, end)
    code_gt = -1 if code is None else _start_tag_gt(body, code.end(), end)
    if code_gt < 0:
        return ""
    code_end = _search_outside_markup(_CODE_END_OUTSIDE_MARKUP_RE, body, code_gt + 1, end)
    stop = end if code_end is None else code_end.start()
    child = _first_child(body, code_gt + 1, stop)
    value = None if child < 0 else _CODEVALUE_RE.match(body, child, stop)
    return "" if value is None else _code_text(value, _CODEVALUE_END_RE, body, stop)


def _searched_code(body: str, start: int, end: int) -> str:
    """The code the earlier search finds in ``body[start:end]``, or ``""``: :func:`_fault_code`'s
    fallback, the search the code ran before BACKLOG #5912, over a range that ends where that
    search's did, at the first plain Fault close tag. The first ``faultcode`` or ``Value`` start tag
    there is the code element, a ``Value`` taken only before the first ``faultcode``, and only that
    first tag is read: SOAP 1.2's Code/Value and SOAP 1.1's faultcode come before a Detail that may
    carry an element of the other name. Markup is not stepped over, as it was not before."""
    faultcode = _FAULTCODE_RE.search(body, start, end)
    value = _CODEVALUE_RE.search(body, start, end if faultcode is None else faultcode.start())
    if value is not None:
        return _code_text(value, _CODEVALUE_END_RE, body, end)
    if faultcode is not None:
        return _code_text(faultcode, _FAULTCODE_END_RE, body, end)
    return ""


def _classify_soap(status: int, body: str) -> DeliveryError | None:
    """``None`` if delivered, else the classified failure. A WS-Security fault (auth/expiry) →
    permanent; a SOAP fault is classified by its code (Sender/Client → permanent; Receiver/Server →
    transient; unrecognized → permanent so a rejected request can't loop the lane); a fault-less
    response falls back to the HTTP status. The Fault and the WS-Security code are searched for from
    where :func:`_find_fault` starts."""
    fault, start = _find_fault(body)
    if fault:
        code = _fault_code(body, fault)
        # The code is a slice of the reply after start, so this search covers it too.
        if _WSSE_FAULT_RE.search(body, start):
            return NegativeAckError(
                f"WS-Security fault (HTTP {status})", code="wssecurity", permanent=True
            )
        if _SENDER_RE.search(code):
            return NegativeAckError(
                f"SOAP Sender fault (HTTP {status})", code="soap-sender", permanent=True
            )
        if _RECEIVER_RE.search(code):
            return DeliveryError(f"SOAP Receiver fault (HTTP {status})")
        return NegativeAckError(f"SOAP fault (HTTP {status})", code="soap-fault", permanent=True)
    if 200 <= status < 300:
        return None
    if 500 <= status < 600:
        return DeliveryError(f"SOAP endpoint returned HTTP {status}")
    return NegativeAckError(
        f"SOAP endpoint rejected with HTTP {status}", code=str(status), permanent=True
    )


def _client_cert_opener(
    certfile: str,
    keyfile: str,
    password: str | None,
    *extra_handlers: urllib.request.BaseHandler,
    allow_expired: bool = False,
    host: str = "",
    trust_anchor: TrustAnchor = SYSTEM_TRUST_ANCHOR,
) -> urllib.request.OpenerDirector:
    """A no-redirect opener that presents a **client certificate** for mutual TLS (ADR 0015 §3).

    Server verification stays on (``create_default_context`` verifies the peer + hostname); a client
    cert against an unverified peer is incoherent and rejected at construction, so this never combines
    with ``verify_tls=False``. TLS 1.2+ floor (ADR 0002), as in ``mllp.py``/``api/tls.py``. Per
    connection — REST's shared module-level openers are left untouched.

    ``allow_expired`` (#129, ADR 0094) relaxes the validity-period checks (the chain's signatures +
    hostname stay enforced) -- at least the peer cert's, the intermediates' and the trust anchor's, and
    a CRL's own window, not the peer cert's alone (vault BACKLOG #5089). The granular expiry
    tolerance, composable with mTLS. Default off = byte-identical.

    ``trust_anchor`` (#1180, ADR 0093) selects the roots that verify the SERVER; the client identity
    loaded below is a separate direction and is untouched by it. The default resolves to the OS trust
    store, which is the ``ssl.create_default_context()`` this line used to be. mTLS is exactly the
    deployment where an internal CA is likeliest, so leaving this hop unable to name one was the
    sharpest edge of the inexpressible slice."""
    ctx = build_verifying_client_context(trust_anchor)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # BACKLOG #1352 / #1171: refuse a weak passphrase wrap, or an encrypted key with no passphrase,
    # before OpenSSL decrypts it; the empty callback behind the check keeps OpenSSL off the terminal.
    load_checked_cert_chain(
        ctx,
        certfile,
        keyfile,
        password,
        cert_setting="client_cert_file",
        key_setting="client_key_file",
        unlock_setting="client_key_password (through env())",
    )
    if allow_expired:
        relax_verify_expiry(
            ctx, host=host
        )  # chain signatures + hostname still verified; validity windows relaxed (BACKLOG #5089)
    # Assert forward secrecy LAST, so it sees the final suite list (ASVS 12.1.2). The docstring above
    # already claimed parity with mllp.py / api/tls.py on the TLS floor; this makes the claim true of
    # the cipher assertion those siblings also carry.
    narrow_to_approved_suites(ctx)  # approved AEAD default (BACKLOG #300)
    harden_cipher_suites(ctx, connector="SOAP destination (mutual TLS)")
    return build_strict_opener(
        _NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx), *extra_handlers
    )


def _assert_well_formed_fragment(fragment: str) -> None:
    """Reject a ``<Body>`` fragment that is not well-formed XML, **before** it reaches the wire
    (ADR 0015 §2a). Uses a single hardened, **non-resolving, no-DTD** ``xml.sax`` parse of the fragment
    *in isolation* (wrapped in a throwaway shell we discard) — external entity resolution is OFF, so it
    is **not** an XXE vector; a DOCTYPE is rejected outright (no internal entity expansion). This is a
    balanced-tags / no-smuggled-close gate on attacker-influenceable HL7-derived content, not a schema
    check; no parsed tree is kept or trusted."""
    if "<!doctype" in fragment.lower():
        raise ValueError("SOAP <Body> fragment must not contain a DOCTYPE (ADR 0015)")
    parser = xml.sax.make_parser()  # noqa: S317  # nosec B317 — hardened below: external entities OFF
    parser.setFeature(feature_external_ges, False)
    parser.setFeature(feature_external_pes, False)
    parser.setContentHandler(ContentHandler())
    source = InputSource()
    source.setByteStream(io.BytesIO(f"<_mf_frag>{fragment}</_mf_frag>".encode()))
    try:
        parser.parse(source)
    except xml.sax.SAXException as exc:
        raise ValueError(f"SOAP <Body> fragment is not well-formed XML: {exc}") from exc


def _reject_ws_leak(fragment: str) -> None:
    """Best-effort lint (ADR 0015 §2b, NOT a structural guarantee): reject a ``<Body>`` fragment that
    already carries a ``<Header>`` or a WS-\\* element **by namespace URI** — i.e. an author trying to
    hand-build the non-deterministic header inside the (pure) transform. The real purity guarantee is
    §1's value-placement; this only catches an accidental mistake early. Matches on URI (prefixes are
    author-chosen) so it can be evaded (a URI in a comment/CDATA) and is intentionally conservative."""
    if any(ns in fragment for ns in (_NS_WSA, _NS_WSSE, _NS_WSU)):
        raise ValueError(
            "SOAP <Body> fragment declares a WS-* namespace (wsa/wsse/wsu); the transport stamps those "
            "headers in send() to preserve re-run purity — the Handler must return only the <Body> "
            "operation fragment (ADR 0015)"
        )
    if _HEADER_EL_RE.search(fragment):
        raise ValueError(
            "SOAP <Body> fragment contains a <Header> element; in WS-* mode the Handler returns only "
            "the operation <Body> fragment and the transport builds the <Header> (ADR 0015)"
        )


# A credential substituted into the <Body> (ADR 0015 amendment, #236) is escaped for BOTH element and
# attribute contexts. `_xml_escape` (saxutils.escape) does only & < > — but the well-formedness gate
# accepts a token in an attribute (`<cred pw="TOKEN"/>` parses) and runs BEFORE substitution, so a
# secret containing " or ' could break out of the attribute and inject markup into an already-validated
# envelope. Escape all five XML metacharacters.
def _escape_body_secret(value: str) -> str:
    return _xml_escape(value, {'"': "&quot;", "'": "&apos;"})


# The C0 control characters illegal in XML 1.0 character data: everything below 0x20 except tab
# (0x09), LF (0x0a) and CR (0x0d). Such a char in a credential is legal for saxutils.escape but
# would make the substituted envelope not well-formed; rejecting it at connector BUILD keeps the
# secret out of the persisted SAXParseException string a send-time failure would otherwise produce.
_XML_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

_SCRUB_MIN_LEN = 8


def _drop_authorization(headers: dict[str, str]) -> None:
    """Remove every spelling of ``Authorization`` from a static header table, so the credential the
    connection configures owns the one header (BACKLOG #5526). For a name in plain letters urllib
    capitalises it and the last write wins, so the configured value already crossed, though the
    table held two keys. A name ending in a space or a tab, or with a NUL or a DEL at either end,
    is not merged, so the static value crossed too, as a second header a peer may read as
    ``Authorization``. A leading space or tab made ``http.client`` refuse the request instead. The
    REST, FHIR and DICOMweb header builders do not purge. A signing header named ``Authorization``
    is not in this table: ``_post`` writes it per request, and it is refused only beside Digest."""
    from messagefoundry.transports.http_auth import is_authorization_header_name

    for key in [k for k in headers if is_authorization_header_name(k)]:
        del headers[key]


def _iso(t: float) -> str:
    """An XSD ``dateTime`` in UTC, e.g. ``2026-06-15T05:30:00Z`` (WS-Security Created/Expires)."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _default_message_id() -> str:
    """A fresh WS-Addressing MessageID (a per-call URN); overridable for deterministic tests."""
    return f"urn:uuid:{uuid.uuid4()}"


class SoapDestination(DestinationConnector):
    """POST each SOAP envelope to a web-service endpoint (plain or WS-* mode; ADR 0003 + 0015)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError("SOAP destination requires a 'url' setting")
        scheme = url_scheme(url, "SOAP destination 'url'")
        if scheme not in ("http", "https"):
            raise ValueError(f"SOAP destination 'url' must be http or https, got scheme {scheme!r}")
        refuse_url_credentials(url, "SOAP destination 'url'")
        self.url = url
        # BACKLOG #2060: names this hop in a bounded-read refusal, which never carries the URL.
        self._hop = hop_identity("SOAP", config.name)
        self.timeout: float = float_setting(
            s.get("timeout_seconds", 30.0), knob="timeout_seconds", transport="SOAP destination"
        )
        self.encoding: str = s.get("encoding", "utf-8")
        self.version: str = str(s.get("soap_version", "1.1"))
        if self.version not in ("1.1", "1.2"):
            raise ValueError(
                f"SOAP destination soap_version must be 1.1 or 1.2, got {self.version!r}"
            )
        # The action is the single source of truth: the 1.2 Content-Type action param AND wsa:Action.
        self.soap_action: str = str(s.get("soap_action") or "")
        # ADR 0013: capture the SOAP response envelope. Default False → returns None, byte-identical.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # #154: allow-list of HTTP response headers to capture into the DeliveryResponse (empty default →
        # byte-identical). Shared parser/filter with REST (SOAP reuses REST's HTTP plumbing).
        self.capture_response_headers = normalize_header_allowlist(
            s.get("capture_response_headers")
        )

        # --- ADR 0015: WS-* + mutual-TLS settings -----------------------------------------------
        self.client_cert_file: str | None = s.get("client_cert_file") or None
        self.client_key_file: str | None = s.get("client_key_file") or None
        self.client_key_password: str | None = s.get("client_key_password") or None
        self.ws_addressing: bool = bool(s.get("ws_addressing", False))
        self.ws_security: bool = bool(s.get("ws_security", False))
        # BACKLOG #5526 (ADR 0015 amendment 2026-11-10): no fallback to basic_user/basic_password.
        # Borrowing the Basic pair sent one password twice, in the Authorization header and the token.
        self.ws_username: str | None = s.get("ws_username") or None
        self.ws_password: str | None = s.get("ws_password") or None
        self.ws_password_type: str = str(s.get("ws_password_type", "text"))
        self.ws_timestamp_ttl_seconds: int = count_setting(
            s.get("ws_timestamp_ttl_seconds", 300),
            knob="ws_timestamp_ttl_seconds",
            transport="SOAP destination",
        )
        self._ws_mode: bool = self.ws_addressing or self.ws_security

        # Non-deterministic generators — instance attributes so tests can inject a fixed clock / UUID /
        # nonce and assert the values are minted in send() (ADR 0015 testing strategy).
        self._now_fn: Callable[[], float] = time.time
        self._uuid_fn: Callable[[], str] = _default_message_id

        # #200 (ADR 0092): the per-connection insecure-hop attestation, keying the posture-keyed refusal.
        attested = config.tls_hop_attested
        # ADR 0153 decision 2: the OPPOSITE per-connection declaration — this hop is cleartext, is not
        # secure, and that is accepted (WARN + audit, never a silent ALLOW). It never reaches the
        # credential hops below (vault BACKLOG #3533 item 4).
        accepted, accept_reason = config.cleartext_accepted, config.cleartext_reason
        # Held because the WS-Security / body-secret credential refusals name the connection.
        self._connection_name = config.name
        # Captured at construction; re-asserted (zero I/O) at the byte-crossing in _post (decision 4).
        self._hop_guard: InsecureHopGuard | None = None
        # BACKLOG #5529: refused before any hop gate logs a crossing for a connection that never builds,
        # and before the half-pair check, so a lone basic_user beside Digest hears the Digest rule.
        from messagefoundry.transports.http_auth import (
            refuse_authorization_signer_beside_digest,
            refuse_http_digest_conflicts,
        )

        digest_selected = refuse_http_digest_conflicts(s)
        self._refuse_half_credential_pairs(s)
        self._validate_ws(scheme, s)

        # BACKLOG #112/#127/#128 (ADR 0126): per-connection forward/egress proxy (None → byte-identical).
        self._proxy: ProxyConfig | None = egress_route_from_settings(
            s,
            dest_scheme=scheme,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
            connection=config.name,
        )
        proxy_dest = self._proxy.for_host(self.url) if self._proxy is not None else None
        proxy_handlers = proxy_dest.opener_handlers() if proxy_dest is not None else ()

        self._headers = self._build_headers(s)
        if proxy_dest is not None:
            # Pre-emptive Proxy-Authorization (Basic; empty for Digest/none) — tunnelled for https (0126).
            self._headers.update(proxy_dest.auth_headers())
        enforce_outbound_length_limits(self.url, self._headers)
        refuse_cleartext_credentials(
            scheme,
            self._headers,
            self.url,
            credentials=http_credentials_sent(
                ConnectorType.SOAP,
                s,
                cleartext=True,
                proxied=hop_reaches_a_proxy(proxy_dest, proxy_handlers, self.url),
            ),
            connection=config.name,
        )
        # ASVS 12.2.1: the SOAP envelope body is PHI, so a cleartext http egress to a non-loopback
        # host is refused even without credentials (loopback stays byte-identical). See rest.py.
        self._hop_guard = refuse_cleartext_egress(
            scheme,
            self.url,
            attested=attested,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
            connection=config.name,
        )
        # ASVS 4.1.5 (ADR 0018): opt-in detached-JWS signing of the outbound envelope. None = off
        # (byte-identical). Built here so a bad key/algorithm fails loud at connector construction; the
        # signature is minted in _post over the FINAL wire bytes (the WS-* wrapped envelope, ADR 0015).
        self._signer: MessageSigner | None = signer_from_destination(config)
        refuse_authorization_signer_beside_digest(
            None if self._signer is None else self._signer.header_name,
            digest=digest_selected,
            connection=config.name,
        )
        # ASVS 4.2.5: the detached-JWS headers are added after the URL/header gate above.
        # Message-independent, so they are bounded once here rather than on every send.
        enforce_signature_header_limits(self._signer, connector="SOAP destination")

        # #1180 (ADR 0093): the client trust anchor, shared by every VERIFYING branch below. Not
        # resolved on the verify_tls=false branch, which is CERT_NONE and has no roots to choose.
        anchor = http_family_trust_anchor(
            s, url=self.url, trust_anchor_policy=config.trust_anchor_policy
        )
        verify = bool_setting(s, "verify_tls", default=True)
        if self.client_cert_file and self.client_key_file:  # NEW — mutual TLS, takes precedence
            self._opener: urllib.request.OpenerDirector = _client_cert_opener(
                self.client_cert_file,
                self.client_key_file,
                self.client_key_password,
                *proxy_handlers,  # ADR 0126: forward proxy threaded through the mTLS opener too
                allow_expired=bool(s.get("tls_allow_expired", False)),  # #129 (ADR 0094)
                host=urllib.parse.urlsplit(self.url).hostname or "",
                trust_anchor=anchor,
            )
        elif verify:
            # #129 (ADR 0094): granular expiry-only relaxation — verify the chain's signatures + hostname
            # but tolerate an expired peer cert, and at least the other chain certificates' and a CRL's
            # validity windows (opt-in; default off = the shared verifying opener, byte-identical).
            if bool(s.get("tls_allow_expired", False)):
                self._opener = _expiry_relaxed_opener(
                    urllib.parse.urlsplit(self.url).hostname or "",
                    *proxy_handlers,
                    trust_anchor=anchor,
                )
            elif proxy_handlers or anchor.narrows:
                # A forward proxy → a per-connection verifying opener carrying it (never the shared one).
                # A narrowed trust anchor needs its own opener for the same reason.
                self._opener = _no_redirect_opener(*proxy_handlers, trust_anchor=anchor)
            else:
                self._opener = _shared_no_redirect_opener()
        else:
            # verify_tls=false makes the https hop MITM-able — a posture-keyed insecure hop (#200).
            guard = refuse_verify_off(
                scheme,
                self.url,
                connector="SOAP destination",
                connection=config.name,
                credentials=http_credentials_sent(ConnectorType.SOAP, s),
                attested=attested,
            )
            if guard is not None:
                self._hop_guard = guard
            logger.warning(
                "SOAP destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.url),
            )
            self._opener = _insecure_opener(*proxy_handlers)
        # #65: opt-in generic HTTP auth on the SOAP transport (independent of WS-Security, which secures
        # the SOAP *message*; this secures the HTTP *hop*). A bearer provider (OAuth2 client-credentials —
        # SMART is FHIR/REST-only) injected per-request in _post, OR HTTP Digest folded into the opener.
        # Both None (default) → byte-identical. Mutually exclusive with each other.
        from messagefoundry.transports.http_auth import (
            bearer_provider_from_settings,
            digest_handler_from_settings,
        )

        # ADR 0126: the token-endpoint call must ALSO traverse the proxy — thread the same ProxyConfig in.
        # #1660: and the instance [tls] trust-anchor policy, resolved for the TOKEN host, so the hop
        # that carries the client_secret honours the same internal CA the delivery hop already does.
        self._token_provider = bearer_provider_from_settings(
            s, proxy=self._proxy, trust_anchor_policy=config.trust_anchor_policy
        )
        if self._token_provider is not None:
            refuse_cleartext_credentials(
                scheme,
                {**self._headers, "Authorization": "Bearer"},
                self.url,
                credentials=(),
                connection=config.name,
            )
        digest = digest_handler_from_settings(s, url=self.url)
        if digest is not None:
            # A bearer provider beside Digest was refused in refuse_http_digest_conflicts (#5529).
            if _is_shared_no_redirect_opener(self._opener):
                # _no_redirect_opener, not a bare build_opener: the bare form lets urllib fill in an
                # HTTPSHandler whose context the engine never names, so the forward-secrecy assertion
                # cannot reach this hop (ASVS 12.1.2).
                self._opener = _no_redirect_opener()
            self._opener.add_handler(digest)

        # #201 (ADR 0078 amendment): the verify-ON https hops above (mTLS, expiry-relaxed and the plain
        # verifying opener) validate the peer cert but do no OCSP/CRL revocation (stdlib ssl has none)
        # — refuse an off-loopback production-PHI verified hop unless revocation is attested or this
        # hop's own opener checks a CRL. Gated on verify-ON so it is disjoint from the verify_tls=false
        # / cleartext #200 gates.
        #
        # Below every statement that builds or replaces `self._opener`, and no opener with
        # tls_allow_expired: see refuse_unrevoked_verified_hop.
        if verify:
            allow_expired = bool(s.get("tls_allow_expired", False))
            refuse_unrevoked_verified_hop(
                scheme,
                self.url,
                connector="SOAP destination",
                revocation_attested=config.tls_revocation_attested,
                revocation_attested_reason=config.tls_revocation_attested_reason,
                opener=None if allow_expired else self._opener,
                expiry_relaxed=allow_expired,
                connection=config.name,
            )

        # ADR 0015 amendment (#236): body-secret substitution. Parsed last so the credential validation
        # runs after the hop/TLS posture is settled. Empty tuple (no body_secrets) → send() is
        # byte-identical to before.
        self._body_secrets: tuple[tuple[str, str], ...] = self._parse_body_secrets(s, scheme)

    def _parse_body_secrets(self, s: dict[str, Any], scheme: str) -> tuple[tuple[str, str], ...]:
        """Read the flat ``body_secret_tokens`` + ``body_secret_value_<i>`` settings (already
        env()-resolved by the loader) into ``(token, secret)`` pairs (ADR 0015 amendment, #236).

        **Every error here names the TOKEN or the index, never the value.** An exception raised in a
        connector ``__init__`` fans out — ``_record_failed`` logs it with a traceback, pushes it to the
        AlertSink (off-box), serves it as the ``/connections/{n}/metadata`` ``error`` field, and writes
        it into ``queue.last_error`` — and none of those redact a credential (``safe_exc`` scrubs PHI
        shapes only). So the value must never enter an exception string."""
        tokens = s.get("body_secret_tokens")
        if not tokens:
            return ()
        pairs: list[tuple[str, str]] = []
        for i, token in enumerate(tokens):
            raw = s.get(f"body_secret_value_{i}")
            # str-coerce (a value resolved from a native TOML int would break the XML escaper). A
            # present-but-EMPTY env value resolves cleanly (resolve_env_settings tests membership, not
            # truthiness), so an empty credential is caught HERE rather than silently shipped.
            secret = "" if raw is None else str(raw)
            if not secret:
                raise ValueError(
                    f"SOAP body secret for placeholder {token!r} resolved to an empty value — "
                    "set its env() value for this environment"
                )
            if _XML_ILLEGAL_RE.search(secret):
                raise ValueError(
                    f"SOAP body secret for placeholder {token!r} contains a control character illegal "
                    "in XML 1.0 character data"
                )
            # Reject a secret that cannot be encoded in this connection's `encoding` at BUILD, naming the
            # token + codec — never the value or the offending character. The send-time wire encode
            # (`_post`) would otherwise raise UnicodeEncodeError, and str(UnicodeEncodeError) names the
            # character; catching it here (fail-fast, before any message flows) keeps that character out
            # of the persisted last_error a send-time failure would produce. (`encoding` defaults to
            # utf-8, which encodes any str, so this only bites a deliberately-lossy codec like 'ascii'.)
            # The raise sits OUTSIDE the handler on purpose: `raise ... from None` would leave the
            # UnicodeEncodeError on `__context__`, and its `.object` is the SECRET itself. See
            # `encode_wire_body` in transports/base.py for why the flag alone does not detach it.
            offending_position: int | None = None
            try:
                secret.encode(self.encoding)
            except UnicodeEncodeError as exc:
                offending_position = exc.start
            if offending_position is not None:
                raise ValueError(
                    f"SOAP body secret for placeholder {token!r} is not encodable as "
                    f"{self.encoding!r} (offending code point at position {offending_position}) — "
                    "set an encodable value or widen the connection's encoding"
                )
            pairs.append((str(token), secret))
        # A body-carried credential over a cleartext http hop is a plaintext-credential egress, exactly
        # like the WS-Security UsernameToken, so it takes the same rule: only a loopback host lets it
        # cross (vault BACKLOG #3533 item 4).
        refuse_cleartext_credential_hop(
            scheme,
            self.url,
            credential="SOAP body secret",
            connection=self._connection_name,
        )
        return tuple(pairs)

    def _apply_body_secrets(self, payload: str) -> str:
        """Substitute each placeholder token with its XML-escaped secret, immediately before the wire
        encode (ADR 0015 amendment, #236). No-op (byte-identical) when no body_secrets are configured.

        Fail-closed on a token that does not appear **exactly once**: 0 occurrences (a Handler branch
        that forgot the token) or ≥2 (an attacker-influenceable HL7 body that happens to carry it) →
        a **permanent** dead-letter, and **nothing is POSTed**. The error names only the token and the
        count — never the secret, never the payload."""
        if not self._body_secrets:
            return payload
        for token, secret in self._body_secrets:
            count = payload.count(token)
            if count != 1:
                raise NegativeAckError(
                    f"SOAP body secret placeholder {token!r} must appear exactly once in the body, "
                    f"found {count} — refusing to send (nothing was transmitted)",
                    code="body-secret",
                    permanent=True,
                )
            payload = payload.replace(token, _escape_body_secret(secret))
        return payload

    def _scrub_body_secrets(self, text: str) -> str:
        """Best-effort reverse-map of any configured secret (raw and XML-escaped forms) to ``"***"`` in
        a captured partner reply (ADR 0015 amendment, #236).

        **Defence in depth, not a seal:** the match is literal, so a secret the partner echoes in any
        transformed form passes through unmasked. Treat a captured reply as potentially secret-bearing
        regardless of this pass — that is the operator-facing consequence, and it holds whatever the
        transformation was. Only secrets of at least :data:`_SCRUB_MIN_LEN` chars are masked — a
        reverse-map replace of a short, low-entropy value (a facility code a CDC-IIS ACK legitimately
        echoes) would shred the operator's reconciliation text."""
        if not self._body_secrets or not text:
            return text
        for _token, secret in self._body_secrets:
            if len(secret) < _SCRUB_MIN_LEN:
                continue
            for form in (secret, _escape_body_secret(secret)):
                if form in text:
                    text = text.replace(form, "***")
        return text

    def _refuse_half_credential_pairs(self, s: dict[str, Any]) -> None:
        """A credential pair is both halves or neither (BACKLOG #5526). Read here, on the resolved
        settings, because the ``Soap()`` factory sees ``env()`` references and cannot tell one that
        resolves empty from a set value. One Basic half alone would send no HTTP Basic header; a
        token user alone would stamp a UsernameToken with an empty password, and a token password
        alone would stamp none. The message names keys, never a value."""
        prefix = hop_name_prefix(self._connection_name)
        if bool(s.get("basic_user")) != bool(s.get("basic_password")):
            raise HttpAuthError(
                f"{prefix}SOAP destination basic_user and basic_password must be set together; "
                "one without the other would send no HTTP Basic credential"
            )
        # The token is stamped only with ws_security on, so the pair binds only then. With neither
        # half, ws_security stamps the Timestamp alone, a profile a mutual-TLS service may ask for.
        if self.ws_security and bool(self.ws_username) != bool(self.ws_password):
            raise HttpAuthError(
                f"{prefix}SOAP destination ws_username and ws_password must be set together with "
                "ws_security on; the UsernameToken does not use basic_user/basic_password"
            )

    def _validate_ws(self, scheme: str, s: dict[str, Any]) -> None:
        """Runtime validation of the WS-* / mTLS settings (also enforced at wiring time by
        ``build_outbound_connection`` so ``check``/dry-run catches it without a store; the url-scheme
        checks need the resolved url and live here). ADR 0015 §6."""
        if self.client_cert_file and not self.client_key_file:
            raise ValueError("SOAP client_cert_file requires client_key_file (ADR 0015)")
        if self.client_key_file and not self.client_cert_file:
            raise ValueError("SOAP client_key_file requires client_cert_file (ADR 0015)")
        if self.client_cert_file:
            if scheme != "https":
                raise ValueError("SOAP client certificate requires an https url (ADR 0015)")
            if not bool_setting(s, "verify_tls", default=True):
                raise ValueError(
                    "SOAP client cert is incompatible with verify_tls=false — the peer must be "
                    "verified (ADR 0015)"
                )
        if self.ws_password_type == "digest":  # nosec B105 -- a password *type*, not a secret
            raise ValueError(
                "SOAP ws_password_type='digest' is retired (BACKLOG #1171, ASVS 11.4.1). The "
                "WS-Security UsernameToken PasswordDigest construction is defined by its profile as "
                "Base64(SHA1(Nonce + Created + Password)), so the option could not be moved to an "
                "approved hash without leaving the profile. It also bought nothing here: this "
                "connector already refuses a UsernameToken over a cleartext hop, so the channel "
                "protects the credential either way, and PasswordDigest additionally requires the "
                "far side to store the password recoverably. Use ws_password_type='text' over the "
                "TLS hop this connector already requires."
            )
        if self.ws_password_type != "text":  # nosec B105 -- a password *type*, not a secret
            raise ValueError("SOAP ws_password_type must be 'text' (ADR 0015, BACKLOG #1171)")
        if self._ws_mode and self.version != "1.2":
            raise ValueError("SOAP ws_addressing/ws_security require soap_version='1.2' (ADR 0015)")
        # A UsernameToken password over cleartext http is a credential on the wire, refused like the
        # header credentials: only a loopback host lets it cross, never a declaration or the escape
        # (vault BACKLOG #3533 item 4). Only with ws_security on: without it no token is stamped.
        # ws_username no longer falls back to basic_user (#5526), which is judged as HTTP Basic.
        if self.ws_security and self.ws_username:
            refuse_cleartext_credential_hop(
                scheme,
                self.url,
                credential="WS-Security UsernameToken credential",
                connection=self._connection_name,
            )

    def _build_headers(self, s: dict[str, Any]) -> dict[str, str]:
        """SOAP Content-Type (+ SOAPAction for 1.1) + static ``headers`` + optional bearer/basic auth."""
        action = str(s.get("soap_action") or "")
        headers: dict[str, str] = {}
        if self.version == "1.2":
            ctype = "application/soap+xml; charset=utf-8"
            if action:
                ctype += f'; action="{action}"'
            headers["Content-Type"] = ctype
        else:
            headers["Content-Type"] = "text/xml; charset=utf-8"
            headers["SOAPAction"] = f'"{action}"'  # quoted; an empty "" is the no-action convention
        extra = s.get("headers") or {}
        if isinstance(extra, dict):
            headers.update({str(k): str(v) for k, v in extra.items()})
        token = s.get("bearer_token")
        user, password = s.get("basic_user"), s.get("basic_password")
        auth: str | None = None
        if user and password:  # Basic wins over a static bearer_token, as it always has
            auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode("ascii")
        elif token:
            auth = f"Bearer {token}"
        from messagefoundry.transports.http_auth import oauth2_auth_configured
        from messagefoundry.transports.smart import smart_auth_configured

        # A minted bearer owns the header too: _post and _probe write it per request (#5526). A static
        # `headers` Authorization is purged here, before the length gate judges this table, so the
        # gate does not refuse that header, which is never sent. One case the purge does not cover:
        # with OAuth2 or SMART configured, a configured bearer_token or Basic pair is still written
        # back below and judged by the length gate, although the minted bearer replaces it on every
        # request, so an over-long bearer_token beside OAuth2 is refused at construction.
        # The cleartext and verify-off refusals read the settings (http_credentials_sent), not this.
        if auth is not None or oauth2_auth_configured(s) or smart_auth_configured(s):
            _drop_authorization(headers)
        if auth is not None:
            headers["Authorization"] = auth
        return headers

    # --- WS-* envelope assembly (non-deterministic values minted here, per send, in its worker) ---

    def _build_wsa_header(self) -> str:
        # wsa:Action is sourced from soap_action — the single source of truth, never a divergent second
        # value (ADR 0015 §6). wsa:To is the static endpoint url; wsa:MessageID is per-call.
        action = _xml_escape(self.soap_action)
        to = _xml_escape(self.url)
        message_id = _xml_escape(self._uuid_fn())
        return (
            f"<wsa:Action>{action}</wsa:Action>"
            f"<wsa:To>{to}</wsa:To>"
            f"<wsa:MessageID>{message_id}</wsa:MessageID>"
        )

    def _build_wsse_header(self, now: float) -> str:
        created = _iso(now)
        expires = _iso(now + self.ws_timestamp_ttl_seconds)
        timestamp = (
            '<wsu:Timestamp wsu:Id="TS-1">'
            f"<wsu:Created>{created}</wsu:Created><wsu:Expires>{expires}</wsu:Expires>"
            "</wsu:Timestamp>"
        )
        token = self._build_username_token(created) if self.ws_username else ""
        return f'<wsse:Security soap:mustUnderstand="true">{timestamp}{token}</wsse:Security>'

    def _build_username_token(self, created: str) -> str:
        username = _xml_escape(self.ws_username or "")
        # PasswordText only. The PasswordDigest alternative was retired in BACKLOG #1171 -- see
        # __init__'s refusal for the reasoning. `created` stays a parameter because the enclosing
        # <wsu:Timestamp> uses it; the UsernameToken itself no longer carries a Created or a Nonce.
        password = _xml_escape(self.ws_password or "")
        return (
            f"<wsse:UsernameToken><wsse:Username>{username}</wsse:Username>"
            f'<wsse:Password Type="{_PW_TEXT}">{password}</wsse:Password></wsse:UsernameToken>'
        )

    def _wrap_envelope(self, body_fragment: str) -> str:
        """Wrap the Handler's operation ``<Body>`` fragment in a transport-built envelope + stamped
        ``<Header>`` (ADR 0015 §2). The fragment is well-formedness-checked and lint-screened first."""
        _assert_well_formed_fragment(body_fragment)
        _reject_ws_leak(body_fragment)
        now = self._now_fn()
        header = ""
        if self.ws_addressing:
            header += self._build_wsa_header()
        if self.ws_security:
            header += self._build_wsse_header(now)
        return (
            _ENV_OPEN
            + f"<soap:Header>{header}</soap:Header>"
            + f"<soap:Body>{body_fragment}</soap:Body>"
            + "</soap:Envelope>"
        )

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): SOAP has no per-message header knob; unused
        # BACKLOG #5913: the WS-* wrap and the body-secret substitution run in the same worker hop
        # as the POST; _post_and_classify says in what order, and what that does not buy.
        body, status, headers, failure = await asyncio.to_thread(self._post_and_classify, payload)
        if not self.capture_response:
            if failure is not None:
                raise failure  # byte-identical: a 2xx <Fault> still dead-letters/retries
            return None
        if failure is not None:
            # Capturing: record the application <Fault> as a rejected reply rather than raising, so the
            # row is delivered-with-a-rejection (operators reconcile from the captured response).
            return DeliveryResponse(
                body=body, outcome="rejected", detail=f"SOAP fault (HTTP {status})", headers=headers
            )
        if not body:
            return DeliveryResponse(
                body="", outcome="no_reply", detail=f"HTTP {status}", headers=headers
            )
        return DeliveryResponse(
            body=body, outcome="accepted", detail=f"HTTP {status}", headers=headers
        )

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: a HEAD reaches the endpoint without POSTing an envelope. An HTTP response
        # means the host answered (a 405 is still a pass), but a 401/403 means the configured
        # credentials would be rejected — surface that as a failure. Connection/DNS/TLS/timeout fails.
        # BACKLOG #2196: the hop re-check _post runs, before the bearer is minted below.
        assert_probe_hop(self._hop_guard, self.url, connector="SOAP")
        headers = self._headers
        if self._token_provider is not None:
            # BACKLOG #5526: the probe presents the credential a send presents. Construction purges a
            # static `headers` Authorization once a provider exists, but keeps a configured
            # bearer_token or Basic pair, so a probe that did not mint would carry either no
            # credential or that static one, never the minted bearer a send presents. A
            # token-endpoint failure raises DeliveryError.
            headers = {
                **self._headers,
                "Authorization": f"Bearer {self._token_provider.access_token()}",
            }
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url, headers=headers, method="HEAD"
        )
        # ASVS 4.2.5: the minted bearer is the one value the construction gate could not see; the URL
        # and the static headers were bounded there. As in the REST and FHIR probes.
        try:
            enforce_send_time_length_limits(
                req.full_url,
                headers,
                connector=f"SOAP {_redact_url(self.url)} probe",
                minted_credential_names=(
                    frozenset({"Authorization"})
                    if self._token_provider is not None
                    else frozenset()
                ),
            )
        except NegativeAckError as exc:
            if exc.credential_fault and self._token_provider is not None:
                self._token_provider.invalidate()
            raise
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # ASVS 15.2.2: the HEAD probe body is discarded, but an unbounded drain would let a
                # reachability check be turned into a memory exhaustion. The peer chooses the body.
                drain_bounded(resp, connector=f"{self._hop} probe")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"SOAP {_redact_url(self.url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except HttpAuthError as exc:
            # BACKLOG #2323: as in _post, with the fixed text on the DeliveryError a probe raises.
            raise DeliveryError(f"SOAP {_redact_url(self.url)} {AUTH_CHALLENGE_REFUSED}") from exc
        except (ValueError, http.client.InvalidURL) as exc:
            # BACKLOG #1793: the probe is the test-connection reply; see the same arm in _post.
            raise DeliveryError(
                f"SOAP {_redact_url(self.url)} rejected an invalid request value"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} failed: {exc}") from exc
        except EgressReplyError:
            raise  # as in _post
        except http.client.HTTPException as exc:
            # BACKLOG #2113: as in _post, so the probe reply names the class and nothing else.
            raise DeliveryError(
                f"SOAP {_redact_url(self.url)} sent a malformed HTTP reply ({type(exc).__name__})"
            ) from exc

    def _post_and_classify(
        self, payload: str
    ) -> tuple[str, int, dict[str, str], DeliveryError | None]:
        """The WS-* wrap and the body secrets, then :meth:`_post`, then the 2xx reply's
        classification and capture scrub, all in the caller's one worker thread.

        BACKLOG #5913: the wrap SAX-parses the Handler's fragment and the substitution counts and
        replaces each token over the whole payload, so both run here rather than on the loop's
        thread, as the reply passes below already did. Their order is unchanged: the wrap's
        fragment gate and lint first, then the secrets, then the POST, so a refused fragment or a
        token that does not appear exactly once raises before a byte crosses, and the refusal
        reaches ``send`` with its type unchanged. The GIL caveat below holds for these passes too:
        at least the fragment's lower-cased copy, its encode, the envelope concatenation and each
        token's ``str.count`` and ``str.replace`` are single full-length C calls that can hold the
        loop while they run. On the loop's thread the loop waited for the sum of these passes; here
        it waits, at worst, for the longest one in turn, each linear in the payload. That shortens
        the wait; it does not remove it.

        A fault can arrive inside a 2xx body, so the reply is classified. Transport-level faults
        (non-2xx, URL/timeout) already raised inside _post, for both modes. The RAW reply is
        classified: a partner fault names none of OUR secrets, and _WSSE_FAULT_RE must see the
        unscrubbed text. BACKLOG #2827: both passes read up to the 16 MiB reply cap, so they run here
        rather than on the loop's thread, as the non-2xx scan inside _post already did.

        THIS DOES NOT MAKE THE LOOP IMMUNE TO THE SCAN. On the default CPython build, at least each
        ``re`` search, each ``str.find``, each ``str`` replace and ``_code_text``'s slice copy of up
        to 16 MiB is one C call that holds the GIL until it returns, so the loop waits while one
        runs, and can wait out several in turn while several worker threads scan. What bounds each
        wait is the scan being linear: each call is one pass over at most the 16 MiB reply, and
        which call is longest depends on the reply's shape. On one 16-core desktop (Ryzen 9 9950X,
        CPython 3.14.7, 2026-11-04, shared with other work), crafted replies took about 2 to 2.6 s
        in ``_classify_soap`` alone, without the decode in _post or the capture scrub. The longest
        single call, about 0.7 to 1.5 s, was a ``_FAULTCODE_RE`` or ``_CODEVALUE_RE`` name scan over
        a reply of ``<Fault>`` followed by one long run of ``<``. On a bare run of ``<``,
        ``_FAULT_RE`` finds nothing and the name scans never run. Those are that machine's readings,
        not a bound on another. Later #2827 changes added scans, at least ``_find_fault``'s and the
        code-element checks in ``_code_text``, and BACKLOG #5912 put up to three anchored matches
        ahead of the name scans, ``faultcode`` then ``Code`` at the Fault's first child and ``Value``
        at the Code's, each child found by :func:`_first_child`'s Python-level loop, and added the
        Code close-tag search. The name scans still run, in :func:`_searched_code`, wherever that
        first-child read yields no code, as it does on a ``<Fault>`` followed by a run of ``<``; the PR 2936 repair moved the Fault start-tag search and the Fault
        and Code close-tag searches into :func:`_search_outside_markup`'s Python-level loop, which
        a reply of many markup runs makes several times slower. So they are not a reading of this
        code."""
        # WS-* mode: the Handler returned only the <Body> fragment; wrap + stamp here (post-queue
        # boundary), so the per-call MessageID and Timestamp never live in a pure transform.
        if self._ws_mode:
            payload = self._wrap_envelope(payload)
        # ADR 0015 amendment (#236): swap placeholder tokens for the real secret HERE — after the
        # payload left the store and (in WS-* mode) was wrapped, and before _post encodes + signs it —
        # so the wire (and any detached JWS over those bytes) carries the secret while the store still
        # holds only the token. No-op / byte-identical when no body_secrets are configured.
        payload = self._apply_body_secrets(payload)
        body, status, headers = self._post(payload)
        failure = _classify_soap(status, body)
        # Capturing: the reply is PERSISTED (response.body + captured headers), so best-effort scrub any
        # echoed secret before send() returns it (a validating registry may echo a bad credential in
        # its <Fault>). Guarded so a no-body_secrets connection is byte-identical.
        if self.capture_response and self._body_secrets:
            body = self._scrub_body_secrets(body)
            headers = {k: self._scrub_body_secrets(v) for k, v in headers.items()}
        return body, status, headers, failure

    def _post(self, payload: str) -> tuple[str, int, dict[str, str]]:
        # #200 (ADR 0092 decision 4): zero-I/O send-time re-assertion of a permitted insecure hop before
        # a byte crosses (a None guard — secure/loopback — is byte-identical).
        if self._hop_guard is not None:
            # BACKLOG #2989: classified, so a refusal does not leave _post as a raw ValueError.
            self._hop_guard.assert_delivery_url(self.url, connector="SOAP")
        # payload is the FINAL wire body (in WS-* mode _post_and_classify already wrapped + stamped it),
        # so signing over these bytes covers exactly what the partner receives.
        data = encode_wire_body(payload, self.encoding, transport="SOAP")
        headers = self._headers
        if self._token_provider is not None or self._signer is not None:
            headers = dict(self._headers)
            if self._token_provider is not None:
                # #65: a fresh OAuth2-CC bearer per request, acquired off-loop past the queue boundary (a
                # retry re-mints — re-run purity holds). Overrides any static bearer_token.
                headers["Authorization"] = f"Bearer {self._token_provider.access_token()}"
            if self._signer is not None:
                # ASVS 4.1.5 (ADR 0018): detached JWS over the envelope, minted off-loop past the queue
                # boundary so a retry re-mints it (re-run purity holds, like the WS-Security nonce).
                headers.update(self._signer.signature_headers(data))
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self.url,
            data=data,
            headers=headers,
            method="POST",
        )
        # ASVS 4.2.5: bound what actually ships. SOAP has no message-derived header class (see send()
        # -- metadata is documented as unused here), so the only values added after the construction
        # gate are the minted bearer and the JWS headers.
        try:
            enforce_send_time_length_limits(
                req.full_url,
                headers,
                connector=f"SOAP {_redact_url(self.url)}",
                minted_credential_names=(
                    frozenset({"Authorization"})
                    if self._token_provider is not None
                    else frozenset()
                ),
            )
        except NegativeAckError as exc:
            if exc.credential_fault and self._token_provider is not None:
                self._token_provider.invalidate()
            raise
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # ASVS 15.2.2: bounded on the socket read. One SOAP response envelope sits far under
                # the 16 MiB ceiling, so this refuses only a peer that is broken or hostile.
                # vault BACKLOG #2180: the status here is 2xx, so an over-cap body must not
                # re-send. A Fault can sit inside a 2xx, so _post_and_classify reads this body in both
                # capture modes, and the refusal is permanent.
                body = read_2xx_reply_text(
                    resp, connector=self._hop, encoding=self.encoding, body_is_needed=True
                )
                status = int(getattr(resp, "status", 200))
                # #154: capture only the allow-listed response headers (empty allow-list → {}).
                headers = capture_response_headers(
                    getattr(resp, "headers", None), self.capture_response_headers
                )
                return body, status, headers
        except urllib.error.HTTPError as exc:
            try:
                # ASVS 15.2.2: the fault body is bounded too. It is only ever read to CLASSIFY the
                # non-2xx, so an over-cap one is logged and dropped rather than raised: the delivery
                # already fails below on the status, and raising here would swap a classified
                # failure for an unclassified one.
                body = read_bounded_text(
                    exc,
                    connector=f"{self._hop} fault body",
                    encoding=self.encoding,
                )
            except EgressReplyError:
                # The FAMILY, not just the byte bound -- see the twin arm in fhir.py.
                logger.warning(
                    "%s returned an HTTP %s fault body the engine could not read whole; "
                    "classifying on the status alone",
                    self._hop,
                    exc.code,
                )
                body = ""
            except Exception:  # noqa: BLE001 - a body we can't read just becomes status-only
                body = ""
            # A non-2xx status: _classify_soap always returns a failure here (it returns None only on
            # 2xx). This is a transport-level fault — raised for BOTH capturing and non-capturing.
            raise (
                _classify_soap(exc.code, body)
                or DeliveryError(f"SOAP endpoint answered HTTP {exc.code}")
            ) from exc
        except urllib.error.URLError as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} unreachable: {exc.reason}") from exc
        except HttpAuthError as exc:
            # BACKLOG #2323: a refused Digest challenge is the connection's fault, not this
            # message's. Before the ValueError arm, which it would otherwise match.
            raise auth_challenge_refused(f"SOAP {_redact_url(self.url)}") from exc
        except (ValueError, http.client.InvalidURL) as exc:
            # BACKLOG #1793: the same arm as rest.py's _post, and the same reasoning. Without it an
            # InvalidURL escaped as an internal error, and its text could hold a password.
            raise NegativeAckError(
                f"SOAP {_redact_url(self.url)} rejected an invalid request value",
                code="bad-request-value",
                permanent=True,
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"SOAP {_redact_url(self.url)} failed: {exc}") from exc
        except EgressReplyError:
            # A refused reply can be an HTTPException too. It is already a DeliveryError with a
            # fixed reason, so it passes through unchanged rather than being retyped below.
            raise
        except http.client.HTTPException as exc:
            # BACKLOG #2113: a malformed status or header line (BadStatusLine, LineTooLong) is
            # neither an OSError nor a URLError, so it escaped as an internal error. Retryable, and
            # named by class only: its text can echo the partner's bytes. Last, so InvalidURL and
            # RemoteDisconnected keep the arms above.
            raise DeliveryError(
                f"SOAP {_redact_url(self.url)} sent a malformed HTTP reply ({type(exc).__name__})"
            ) from exc


register_destination(ConnectorType.SOAP, SoapDestination)
