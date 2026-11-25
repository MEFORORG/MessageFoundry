# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""DICOMweb STOW-RS transport (ADR 0025 Phase 2): an HTTP destination that **stores** a DICOM object to
a DICOMweb service via STOW-RS.

``DicomWebDestination`` is a sibling :class:`~messagefoundry.transports.base.DestinationConnector` that
**reuses** the hardened HTTP plumbing in :mod:`messagefoundry.transports.rest` — exactly as
:mod:`messagefoundry.transports.fhir` and :mod:`messagefoundry.transports.soap` do — rather than wrapping
``RestDestination``: the no-redirect, http(s)-only, TLS-verifying opener (a 3xx can't divert a
PHI-bearing POST to an unintended host; ASVS 15.3.2), the cleartext-credential refusal, and the outbound
length limits. The fail-closed ``[egress].allowed_http`` host gate is enforced by ``build_destination`` (it folds
DICOMWEB into the REST/SOAP/FHIR arm — see transports.egress ``_allowlist_for`` / ``check_egress_allowed``).
It needs **no** ``pydicom``: the object rides as bytes, so DICOMweb works without the DIMSE stack. A
202 reply is compared with the object's File Meta Media Storage SOP Instance UID, read by hand
(:func:`_sent_instance_uid`), and, when ``pydicom`` is installed, its data set SOP Instance UID
(:func:`_data_set_instance_uid`), both read before the POST (:func:`_read_sent_uids`; BACKLOG
#5914). An installed ``pydicom`` that does not load, or whose read of the object raises, is taken
as reading no data set UID, with one WARNING per process for each of the two, so the object is
still sent; a :class:`MemoryError` from the load or the read is raised instead, before the POST,
and the object is not sent. A read that raises a fault the codec wraps (an object it cannot
parse) also reads as no data set UID, with no WARNING. A read that raises a fault the codec does not wrap, on an object with no File Meta UID,
lets a 202 naming any UID confirm it (:func:`_unconfirmed_202`). :func:`_data_set_instance_uid` says
which faults do what.

**STOW-RS layer (on top of REST):**
- The outgoing object is a **binary** DICOM Part-10 body, base64-carried through the str/store substrate
  (ADR 0028); the bytes are recovered via the shared
  :func:`~messagefoundry.transports.dicom.recover_dicom_object_bytes` (the one decode) and framed as a
  ``multipart/related; type="application/dicom"`` request body — **one instance per request** (a
  single-instance MVP; multi-instance batching is deferred).
- ``POST {base}/studies`` (the server assigns the study) or ``POST {base}/studies/{study_uid}`` (store
  into a known study) when a ``study_uid`` is configured. ``Accept: application/dicom+json``.
- Response classification refines the HTTP-status retry model: some 2xx replies are a permanent
  refusal, a per-instance **FailedSOPSequence** (``00081198``) among them, though not every 2xx that
  fails to confirm the store. :func:`_stowrs_refusal` holds the rule, and docs/CONNECTIONS.md
  *DICOMweb*, *Status classification*, states it in full. Other 4xx, a 409 (all instances failed)
  or a refused 3xx is permanent; 5xx / 408 / 429 / connection-timeout is a transient retry. **A
  5xx stays transient**, but a 2xx is not always a delivery (BACKLOG #5914).

**PHI:** a STOW-RS ``dicom+json`` response can name patient/study identifiers, so it is **never** echoed
into a log/error — only the HTTP status and a redacted URL are. **Idempotency:** delivery is
at-least-once, so a retry re-stores the same object; a re-store of the same ``SOPInstanceUID`` is the
native idempotency lever (STOW-RS treats it as already-stored).
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import importlib.util
import logging
import secrets
import struct
import threading
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any, NamedTuple

from messagefoundry.config.models import ConnectorType, Destination, bool_setting
from messagefoundry.config.tls_policy import refuse_chain_check_on_os_roots
from messagefoundry.controlchars import has_control_char, has_lone_surrogate
from messagefoundry.parsing.dicom._deps import load_dcmread, load_header_readers
from messagefoundry.parsing.dicom.errors import DicomError
from messagefoundry.parsing.dicom.peek import DicomPeek
from messagefoundry.redaction import json_loads_or_refusal, refuse_repeated_keys
from messagefoundry.transports.base import (
    DeliveryError,
    DeliveryResponse,
    DestinationConnector,
    NegativeAckError,
    positive_seconds,
    register_destination,
)
from messagefoundry.transports.bounded_read import (
    EgressReplyError,
    drain_bounded,
    hop_identity,
    read_2xx_reply_text,
)
from messagefoundry.transports.dicom import (
    _ignore_pydicom_value_warnings,
    _install_record_screen,
    _logs_held,
    _write_held,
    recover_dicom_object_bytes,
)

# Reuse REST's hardened HTTP plumbing — same transports/ package, same no-redirect + TLS posture (NOT a
# wrapper around RestDestination; ADR 0025 §2, exactly as fhir.py / soap.py do).
from messagefoundry.transports.rest import (
    _RETRYABLE_4XX,
    AUTH_CHALLENGE_REFUSED,
    HttpAuthError,
    InsecureHopGuard,
    ProxyConfig,
    _insecure_opener,
    _latin1_refusal_position,
    _redact_url,
    _verifying_opener,
    assert_probe_hop,
    auth_challenge_refused,
    egress_route_from_settings,
    enforce_outbound_length_limits,
    hop_name_prefix,
    hop_reaches_a_proxy,
    http_credentials_sent,
    http_family_trust_anchor,
    refuse_cleartext_credentials,
    refuse_cleartext_egress,
    refuse_unrevoked_verified_hop,
    refuse_unsendable_static_request,
    refuse_url_credentials,
    refuse_verify_off,
    url_scheme,
)

__all__ = ["DicomWebDestination", "dicomweb_credential_problem"]

logger = logging.getLogger(__name__)

# A per-request random multipart boundary (RFC 2046 §5.1.1), generated fresh in _multipart_body and
# verified absent from the object bytes — a collision would let a conforming STOW-RS server split the part
# early (truncating the stored PHI) or smuggle a forged part. A different boundary on a retry is harmless:
# it is transport framing, not message content, and a re-store of the same SOPInstanceUID is idempotent
# (the same posture as rest.py minting a fresh JWS/SMART credential per send).
_BOUNDARY_PREFIX = "mf-stow-"
_DICOM_PART_TYPE = "application/dicom"
_DICOM_JSON = "application/dicom+json"
# DICOM Tag (group,element) for the STOW-RS FailedSOPSequence in the dicom+json response (DICOM PS3.18).
_FAILED_SOP_SEQUENCE = "00081198"
# ReferencedSOPSequence: the instances the server stored. A 202 must name the instance sent (#5914),
# except as _unconfirmed_202 says; see _named_uid and _sent_instance_uid.
_REFERENCED_SOP_SEQUENCE = "00081199"
_REFERENCED_SOP_INSTANCE_UID = "00081155"
# PS3.10 section 7.1: a 128-byte preamble, then "DICM", then the File Meta group in Explicit VR
# Little Endian. These VRs take the short form, a 2-byte length (PS3.5 section 7.1.2). Every other
# VR, an unknown one included, takes the long form: two reserved bytes, then a 4-byte length, as
# PS3.5 tells a reader to assume for a VR it does not know.
_PART10_PREAMBLE = 128
# fmt: off
_SHORT_FORM_VRS = frozenset({
    b"AE", b"AS", b"AT", b"CS", b"DA", b"DS", b"DT", b"FL", b"FD", b"IS", b"LO",
    b"LT", b"PN", b"SH", b"SL", b"SS", b"ST", b"TM", b"UI", b"UL", b"US",
})
# fmt: on
# The File Meta group read is bounded by this many bytes after "DICM": a conformant group is a few
# hundred bytes, so the cap refuses only a broken or hostile object (BACKLOG #5914).
_FILE_META_CAP = 64 * 1024
# Why the object sent has no File Meta UID to compare: fixed text, never a value (PHI-safe). No two
# capitalised words sit side by side, so the PHI name-run redaction leaves them whole. They end the
# unconfirmed-202 reason (_unconfirmed_202), which is cut twice before it is stored: safe_exc cuts
# the message at 200 characters, and the store cuts again at 200 after the "NegativeAckError: "
# prefix. The replay advice before the cause survives both cuts, as on main; the cause may be cut
# part-way in the stored text.
_META_NO_MAGIC = "no Part-10 preamble and DICM magic"
_META_NO_0003 = "no (0002,0003) in the file meta group"
_META_WRONG_VR = "a (0002,0003) whose VR is not UI"
_META_NOT_A_UID = "a (0002,0003) value that is not a UID"
_META_OVERRUN = "a file meta element past the object end"
_META_TOO_LONG = "a file meta group past the read cap"
# PS3.18 Annex F: the only keys a sequence (SQ) or UID (UI) element may carry. BulkDataURI and
# InlineBinary are never allowed on SQ or UI, so an element read here carrying any other key is
# malformed and fails closed -- an allow-list, so a misspelt "value" cannot read as an empty
# sequence.
_ELEMENT_KEYS = frozenset({"vr", "Value"})
# Written by name, never as a raw character an editor can silently drop (as fhir.py's _BOM).
_BOM = "\N{ZERO WIDTH NO-BREAK SPACE}"
_JSON_WHITESPACE = (
    " \t\r\n"  # RFC 8259 section 2; str.strip() would also take NBSP and C0 separators
)
# The advice a reply refusal that does not prove a rejection carries: the partner may have stored it.
_NOT_SENT = "not sent again, and the partner may hold the instance, so check it before a replay"


# DICOM PS3.5 section 9.1: a UID is dot-separated numeric components, at most 64 characters.
#
# Checked WITHOUT a regex, deliberately. The natural pattern for this grammar is
# `\A[0-9]+(?:\.[0-9]+)*\Z`, which nests '+' inside '*' and so trips this repo's ReDoS gate
# (`test_security_static.py::test_no_catastrophic_regex_in_source`). Measured against a known-
# catastrophic control, that pattern is LINEAR -- 200x the input costs 183x the time, while the
# control goes exponential -- so the gate is matching the SHAPE, not real backtracking. That is NOT
# a reason to take an exception: a split-and-check is simpler, obviously linear, and leaves the
# gate's conservatism (which is the design -- BACKLOG #1235) untouched. A false positive is a reason
# to change the code, not to weaken the check.
#
# `str.isdigit()` is unusable here: it is Unicode-aware and returns True for superscript and
# Arabic-Indic digits, so it would admit non-ASCII into the URL path and reopen the very hole this
# screen closes. The explicit ASCII set is the control, not an optimisation.
_UID_DIGITS = frozenset("0123456789")
_DICOM_UID_MAX_LEN = 64


def _uid_components_ok(value: str) -> bool:
    """True when every dot-separated component is non-empty and entirely ASCII digits."""
    # Requiring non-empty is what makes '..', a leading dot and a trailing dot illegal -- they are
    # excluded STRUCTURALLY, not by enumeration. A trailing newline is excluded for free (it lands
    # inside the final component and is not a digit), which is the hole a `$`-anchored regex would
    # have left open -- #1240's defect.
    return all(part and _UID_DIGITS.issuperset(part) for part in value.split("."))


def _is_uid(value: object) -> bool:
    """True when ``value`` is a string of dot-separated ASCII-digit components, at most 64
    characters: the grammar :func:`_reject_non_uid` gates, which admits leading-zero components
    although PS3.5 forbids them (that docstring says why)."""
    return isinstance(value, str) and len(value) <= _DICOM_UID_MAX_LEN and _uid_components_ok(value)


def _reject_non_uid(value: str, field: str) -> None:
    """Gate a configured DICOM UID to its PS3.5 grammar before it flows into the URL path.

    ``_reject_url_control_chars`` rejects CR/LF/NUL but **not** the path metacharacters ('/', '..', '?',
    '#', '@') that would redirect a PHI-bearing STOW-RS POST to a different study, or to another service
    entirely, on the same allow-listed host (CWE-918). Digits-and-dots admits none of them **by
    construction**, which is the right polarity for a screen: an allow-list cannot be outflanked by a bad
    shape nobody thought to enumerate. PHI-safe — names the field, never the value.

    Leading zeros within a component are **deliberately admitted** although PS3.5 forbids them. That is a
    conformance rule, not a security one: it constrains no character this gate is here to exclude, and
    refusing a real-world non-conformant UID at startup would block a legitimate deployment for no gain
    in containment.
    """
    if len(value) > _DICOM_UID_MAX_LEN:
        raise ValueError(
            f"DICOMweb {field} is longer than the {_DICOM_UID_MAX_LEN}-character UID limit of DICOM"
        )
    if not _uid_components_ok(value):
        raise ValueError(
            f"DICOMweb {field} is not a valid UID for DICOM (dot-separated digits, no other characters)"
        )


def _reject_url_control_chars(value: str, field: str) -> None:
    """Reject a configured value that carries a C0/DEL control char before it flows into the URL path. A
    CR/LF in ``study_uid`` would let it split the request line; urllib would reject it with a bare
    ``ValueError`` at send. Surface it as a clear construction-time ``ValueError`` (caught at
    ``check``/dry-run as a ``WiringError``) — PHI-safe (names the field, never the value)."""
    if has_control_char(value):
        raise ValueError(f"DICOMweb {field} contains an illegal control character")


def _refuse_base_url_query_or_fragment(url: str, connection: str | None) -> None:
    """Refuse a base ``url`` that carries a query or a fragment (vault BACKLOG #5358).

    The STOW-RS target is DERIVED by appending ``/studies`` to the base, so a ``?`` would put the
    appended path inside the query and a ``#`` would make it a fragment the client never sends: the
    POST would go to an endpoint the operator did not name. Any ``?`` or ``#`` counts, an empty
    query or fragment included, because the appended path lands after it either way. Names the
    connection and the setting, never the value."""
    if "?" in url or "#" in url:
        raise ValueError(
            f"{hop_name_prefix(connection)}DICOMweb destination 'url' must be the service base URL with no query string or "
            "fragment ('?' or '#'); the STOW-RS path is appended to it"
        )


def dicomweb_credential_problem(s: Mapping[str, Any]) -> str | None:
    """Why a DICOMweb destination's credential settings refuse its build, or ``None`` (vault BACKLOG
    #5359). The one test behind :func:`_refuse_ambiguous_credentials` and the
    static-credential census; ``config.static_credentials._dicomweb_build_refused`` says when the
    census leaves a hop out. ``s`` holds resolved values: an unresolved ``env()`` reference is the
    caller's to resolve or to leave unjudged.

    ``basic_user`` without ``basic_password``, or the reverse, would send no credential at all; a
    ``bearer_token`` beside a Basic pair, or either beside an ``Authorization`` entry in the static
    ``headers``, would have one silently replace the other or go out as a second header. A Basic
    user-id may not hold a colon (RFC 7617 section 2: the first colon ends it, so the server would
    split the pair somewhere else). No credential may hold a control character: RFC 7617 section 2
    excludes control characters from the Basic user-id and password, and RFC 6750 section 2.1
    admits none in a bearer token. A Basic half may not hold a lone surrogate, which
    its UTF-8 encode cannot write, and the bearer token, which goes on the wire as written, may not
    hold a character ``http.client``'s latin-1 header encode cannot write; either would otherwise
    surface as an encoder error quoting part of the secret. A colon in the password is legal and
    admitted. The reason names settings, never a value."""
    # Lazy, as rest.py imports it: http_auth imports this package's siblings at its top.
    from messagefoundry.transports.http_auth import is_authorization_header_name

    token, user, password = s.get("bearer_token"), s.get("basic_user"), s.get("basic_password")
    if bool(user) != bool(password):
        return (
            "basic_user and basic_password must be set together; one without the other "
            "would send no HTTP Basic credential"
        )
    if token and user:
        return (
            "sets both bearer_token and basic_user/basic_password; set one credential, "
            "since only one Authorization header can be sent"
        )
    extra = s.get("headers") or {}
    if (
        (token or user)
        and isinstance(extra, dict)
        and any(is_authorization_header_name(str(name)) for name in extra)
    ):
        return (
            "sets an Authorization entry in headers beside bearer_token or "
            "basic_user/basic_password; set the credential in one place"
        )
    for field, value in (
        ("bearer_token", token),
        ("basic_user", user),
        ("basic_password", password),
    ):
        if not value:
            continue
        text = str(value)
        if has_control_char(text):
            return f"{field} contains an illegal control character"
        # The bearer goes out as a raw header value; a Basic half is UTF-8 inside base64.
        if (
            _latin1_refusal_position(text) is not None
            if field == "bearer_token"
            else has_lone_surrogate(text)
        ):
            return f"{field} holds a character the request cannot encode"
    if user and ":" in str(user):
        return "basic_user may not contain a colon (RFC 7617 section 2)"
    return None


def _refuse_ambiguous_credentials(s: Mapping[str, Any], connection: str | None) -> None:
    """Raise :class:`HttpAuthError` for what :func:`dicomweb_credential_problem` finds.

    Called in the constructor, before any proxy or hop guard records a crossing for a
    connection that will not build. Raises :class:`HttpAuthError`, as SOAP's half-pair refusal does,
    naming the connection and the settings, never a value."""
    problem = dicomweb_credential_problem(s)
    if problem is not None:
        raise HttpAuthError(f"{hop_name_prefix(connection)}DICOMweb destination {problem}")


def _reply_is_empty(body: str) -> bool:
    """True for a reply with nothing in it: empty, or only JSON whitespace once a leading BOM is
    dropped. send() and :func:`_stowrs_refusal` both read emptiness through this one test."""
    return not body.lstrip(_BOM).strip(_JSON_WHITESPACE)


def _element_values(element: Any) -> list[Any] | None:
    """The ``Value`` array of a dicom+json SQ or UI element, ``[]`` when it has none, or ``None``
    when the element is in a shape dicom+json does not allow: not an object, a ``Value`` that is not
    an array, or any key but ``vr`` and ``Value``. One reader, so the two sides cannot drift."""
    if not isinstance(element, dict) or not element.keys() <= _ELEMENT_KEYS:
        return None
    value = element.get("Value", [])
    return value if isinstance(value, list) else None


def _sequence_items(datasets: list[dict[str, Any]], tag: str) -> list[Any] | None:
    """Every item of the ``tag`` sequence across the datasets, in order, or ``None`` when the
    element is present in a shape :func:`_element_values` refuses. An absent element, or one with
    no ``Value`` and no other key, is an empty sequence (PS3.18 F.2.5). Only the shape is read,
    never an item's contents (PHI-safe)."""
    items: list[Any] = []
    for ds in datasets:
        if tag not in ds:
            continue
        value = _element_values(ds[tag])
        if value is None:
            return None
        items.extend(value)
    return items


def _failed_sop_state(datasets: list[dict[str, Any]]) -> tuple[bool, bool]:
    """``(proven, malformed)`` for the FailedSOPSequence (``00081198``) across the datasets.

    ``proven``: some dataset's sequence is well formed and holds an item, a rejection the reply
    proves. ``malformed``: some dataset's sequence is in a shape dicom+json does not allow, so it
    proves nothing: one :func:`_element_values` refuses, or one that holds an item while its own
    ``vr`` is absent or not ``SQ``, or whose items are not all dataset objects (BACKLOG #5914). Each dataset is judged
    alone, so a malformed sequence in one does not hide a proven rejection in another. An absent
    element, or one :func:`_element_values` passes with no item, is neither, whatever its ``vr``.
    Only the shape is read, never an item's contents (PHI-safe)."""
    proven = malformed = False
    for ds in datasets:
        if _FAILED_SOP_SEQUENCE not in ds:
            continue
        element = ds[_FAILED_SOP_SEQUENCE]
        items = _element_values(element)
        if items is None:
            malformed = True
        elif items:
            well_formed = element.get("vr") == "SQ" and all(
                isinstance(item, dict) for item in items
            )
            proven = proven or well_formed
            malformed = malformed or not well_formed
    return proven, malformed


def _sent_instance_uid(obj: bytes) -> tuple[str | None, str]:
    """``(uid, "")`` for the Media Storage SOP Instance UID (``0002,0003``) in the File Meta group
    of the Part-10 object sent, or ``(None, cause)`` when there is none to compare, ``cause`` being
    one of the fixed ``_META_*`` strings (BACKLOG #5914).

    Read by hand, so the destination still needs no ``pydicom``: after the 128-byte preamble and
    ``DICM``, the File Meta elements are always Explicit VR Little Endian (PS3.10 section 7.1). The
    walk stops at the first element outside group ``0002`` and at :data:`_FILE_META_CAP` bytes, so
    a hostile object cannot make it walk the whole object. The (0002,0000) Group Length is not
    read: pydicom ignores a wrong one too, so one that is absent, zero, too short, over the cap or
    undefined changes nothing. The VR of (0002,0003) is checked before its value, at most the cap,
    is sliced; its NUL or space padding is dropped before the 64-character check. The UID is never
    logged (PHI-safe)."""
    if obj[_PART10_PREAMBLE : _PART10_PREAMBLE + 4] != b"DICM":
        return None, _META_NO_MAGIC
    pos = _PART10_PREAMBLE + 4
    size = len(obj)
    limit = min(size, pos + _FILE_META_CAP)

    def past(reach: int) -> str:
        # Bytes needed up to ``reach`` that the object does not hold are an overrun; ones it holds
        # past the cap are a group longer than the reader reads.
        return _META_OVERRUN if reach > size else _META_TOO_LONG

    while pos + 8 <= limit:
        group, element = struct.unpack_from("<HH", obj, pos)
        if group != 0x0002:
            return None, _META_NO_0003
        vr = obj[pos + 4 : pos + 6]
        if vr in _SHORT_FORM_VRS:
            (length,) = struct.unpack_from("<H", obj, pos + 6)
            start = pos + 8
        else:
            if pos + 12 > limit:
                return None, past(pos + 12)
            (length,) = struct.unpack_from("<I", obj, pos + 8)
            start = pos + 12
        end = start + length  # an undefined length (0xFFFFFFFF) runs past the limit, so is refused
        if end > limit:
            return None, past(end)
        if element == 0x0003:
            if vr != b"UI":
                return None, _META_WRONG_VR
            raw = obj[start:end].rstrip(b"\0 ")
            if len(raw) > _DICOM_UID_MAX_LEN or not raw.isascii():
                return None, _META_NOT_A_UID
            uid = raw.decode("ascii")
            return (uid, "") if _is_uid(uid) else (None, _META_NOT_A_UID)
        pos = end
    # The walk met its limit: a partial element header was cut off by it, or the cap stopped the
    # walk; otherwise the object ended with no (0002,0003).
    if pos < limit:
        return None, past(pos + 8)
    if limit < size:
        return None, _META_TOO_LONG
    return None, _META_NO_0003


def _dicom_extra_installed() -> bool:
    """Whether ``pydicom``, the optional ``[dicom]`` extra, can be found on this host, asked on each
    send. A spec with no ``origin`` is a namespace package, such as a ``pydicom`` directory an
    uninstall left behind, and is taken as absent: it holds no ``pydicom`` to load. Once ``pydicom``
    is imported, ``find_spec`` answers from the imported module, so an extra removed after that is
    still taken as installed. A ``pydicom`` in ``sys.modules`` with no spec, on which ``find_spec``
    raises, is taken as installed, so :func:`_dicom_extra_fault` judges it."""
    try:
        spec = importlib.util.find_spec("pydicom")
    except ValueError:
        return True
    return spec is not None and spec.origin is not None


class _SentUids(NamedTuple):
    """The SOP Instance UIDs of the object sent that a 202 is compared with, read before the POST
    (:func:`_read_sent_uids`). ``meta`` is the File Meta (0002,0003) UID or ``None``, with
    ``cause`` one of the fixed ``_META_*`` strings saying why when it is ``None``; ``data_set`` is
    the data set (0008,0018) UID or ``None``; ``read_fault`` is whether the codec's read of the
    object raised a fault it does not wrap, so the data set UID is unknown rather than absent.
    Never logged (PHI-safe)."""

    meta: str | None
    cause: str
    data_set: str | None
    read_fault: bool = False


# Which of the two pre-read WARNINGs ("load", "read") have been written in this process (BACKLOG
# #5914). The read runs on every send, so without it each send would warn.
_pre_read_warned: set[str] = set()
_pre_read_warned_lock = threading.Lock()


def _first_pre_read_warning(kind: str) -> bool:
    """Whether this is the first pre-read WARNING of ``kind`` in this process, marking it written."""
    with _pre_read_warned_lock:
        if kind in _pre_read_warned:
            return False
        _pre_read_warned.add(kind)
        return True


def _dicom_extra_fault() -> str | None:
    """The class name of what the ``[dicom]`` extra raised when loaded, or ``None`` when it loads:
    the ``dcmread`` reader and the readers the deflate guard replays
    (:mod:`messagefoundry.parsing.dicom._deps`), checked apart from any object, as the SCU loads
    them before its parse. An import can raise an exception of any class, so any
    :class:`Exception` but a :class:`MemoryError` counts; a :class:`BaseException` that is not an
    :class:`Exception` is not caught (BACKLOG #5914)."""
    try:
        load_dcmread()
        load_header_readers()
    except MemoryError:
        raise
    except Exception as exc:  # noqa: BLE001 - a broken package's import can raise any class
        return type(exc).__name__
    return None


def _warn_extra_unusable(fault: str) -> None:
    """Write, once per process, the WARNING that the installed ``[dicom]`` extra does not load, so
    DICOMweb compares a 202 with the File Meta UID alone, as with no extra (BACKLOG #5914).
    ``fault`` is the class name of what the load raised; the load's own text is not written. A
    reload keeps the ``pydicom`` modules already imported, so the line says to restart."""
    if not _first_pre_read_warning("load"):
        return
    logger.warning(
        "DICOMweb: the [dicom] extra (pydicom) on this host is installed but does not load (%s), "
        "so a 202 is compared with the file meta SOP Instance UID alone, as without the extra; "
        "repair or remove the extra, then restart the engine",
        fault,
    )


def _warn_read_fault(fault: str, held: list[logging.LogRecord]) -> None:
    """Write, once per process, the WARNING that the codec's read of an object raised ``fault``, the
    class name of a fault it does not wrap, so that object's data set UID is not compared (BACKLOG
    #5914). The fault's own text can carry a value, so it is not written (PHI-safe). With the first
    WARNING go the lines pydicom logged during that read, ``held``, through the DICOM transport's
    default-deny screen (:func:`~messagefoundry.transports.dicom._write_held` says how), so a line
    no template pins is written withheld, not redacted. Later reads' lines are dropped, as on a read
    that succeeds."""
    if not _first_pre_read_warning("read"):
        return
    _write_held(held)
    logger.warning(
        "DICOMweb: reading an object's data set with the [dicom] extra (pydicom) raised %s before "
        "it was sent, so its data set SOP Instance UID is not compared: a 202 is compared with the "
        "file meta SOP Instance UID alone, or, for an object with none, confirmed by any UID it "
        "names; this is written once per process, and the extra may be broken",
        fault,
    )


def _data_set_instance_uid(obj: bytes) -> tuple[str | None, bool]:
    """The data set's SOP Instance UID (``0008,0018``) of the object sent, read with the engine's
    DICOM codec (:class:`~messagefoundry.parsing.dicom.peek.DicomPeek`: a header read that never
    materialises pixel data, behind its deflate guard, though not held to :data:`_FILE_META_CAP`),
    or ``None`` when none is read: the optional ``[dicom]`` extra is absent or does not load, the
    object does not parse (a :class:`~messagefoundry.parsing.dicom.errors.DicomError`), the read
    raises another fault, or it carries no UID in the grammar :func:`_is_uid` checks. The second
    item is whether the read raised such another fault. A server builds its reply from this UID, so a 202 for an object
    whose File Meta was not rewritten after a re-UID still names it (BACKLOG #5914).

    Run before the POST. The extra is loaded first, apart from the object, as the SCU loads it
    before its parse (``DicomScuDestination._store_object``): an extra that is found but does not
    load is taken as absent, so the object is sent and a 202 is compared with its File Meta UID
    alone, and :func:`_warn_extra_unusable` writes one WARNING per process. A
    :class:`~messagefoundry.parsing.dicom.errors.DicomError` from the parse reads as no
    UID, and so does a fault of a class the codec wraps into one, even one a broken extra raised.
    Any other :class:`Exception` but a :class:`MemoryError` from the parse, a warning the filters
    turn into an error included, also reads as no UID, and :func:`_warn_read_fault` writes one
    WARNING per process naming its class, never its text; nothing is refused before the POST. The
    screening log record factory is put back first
    (:func:`~messagefoundry.transports.dicom._install_record_screen`), as the SCP start, each
    C-STORE and each SCU association put it back. With the extra found, the SCU's ignore is put back
    next: one ``warnings`` filter for every warning attributed to a pydicom module, since pydicom's
    ``warn_and_log`` raises a warning with the same text as its log line, value included. pydicom's
    log lines from the parse, on the loggers the DICOM transport's filter is on, are held, as the
    SCP holds its reads' lines (:func:`~messagefoundry.transports.dicom._logs_held`), and written
    only with that first WARNING, through the same default-deny screen as the SCP's
    (:func:`~messagefoundry.transports.dicom._write_held`); otherwise none is written, since the
    object is sent as bytes and a line on how pydicom read it says nothing about the send. A line
    on another pydicom logger is not held: the record factory screens it and it is written as it
    is logged. pydicom's own copy of such a line as a Python warning is not held;
    that ignore drops it, where it is in force. A parse failure is logged by exception class only,
    never the UID or the bytes (PHI-safe)."""
    _install_record_screen()  # a host may have replaced the record factory since the import
    if not _dicom_extra_installed():
        logger.debug(
            "DICOMweb: the [dicom] extra is absent, so no data set SOP Instance UID is read"
        )
        return None, False
    _ignore_pydicom_value_warnings()
    extra_fault = _dicom_extra_fault()
    if extra_fault is not None:
        _warn_extra_unusable(extra_fault)
        return None, False
    parse_fault: str | None = None
    uid: str | None = None
    with _logs_held() as held:
        try:
            uid = DicomPeek.parse(obj).sop_instance_uid
        except DicomError as exc:
            logger.debug("DICOMweb: no data set SOP Instance UID read (%s)", type(exc).__name__)
            return None, False
        except MemoryError:
            raise
        except Exception as exc:  # noqa: BLE001 - pydicom's faults on an object share no base
            parse_fault = type(exc).__name__
    if parse_fault is not None:
        _warn_read_fault(parse_fault, held)
        return None, True
    if uid is None:
        return None, False
    uid = uid.rstrip("\0 ")
    return (uid if _is_uid(uid) else None), False


def _read_sent_uids(obj: bytes) -> _SentUids:
    """Both comparable UIDs of the object sent: the File Meta one by hand
    (:func:`_sent_instance_uid`) and the data set one with the codec
    (:func:`_data_set_instance_uid`). Called before the POST, as the SCU parses before it
    associates (BACKLOG #5914). At least a :class:`MemoryError` from loading the extra or from the
    codec's read, a :class:`BaseException` that is not an :class:`Exception`, and a fault in finding
    the extra (:func:`_dicom_extra_installed`) other than a :class:`ValueError` are not caught; any
    other fault in the read reads as no data set UID, and the object is still sent."""
    meta, cause = _sent_instance_uid(obj)
    data_set, read_fault = _data_set_instance_uid(obj)
    return _SentUids(meta, cause, data_set, read_fault)


def _named_uid(item: Any) -> str | None:
    """The UID a ReferencedSOPSequence item names, padding dropped, or ``None``: a dataset whose
    ReferencedSOPInstanceUID element has ``vr`` ``UI``, passes :func:`_element_values`, and holds
    exactly one value (the attribute's VM is 1), a string that passes :func:`_is_uid` once
    trailing NUL or space padding, which a binary-to-JSON converter can leave, is dropped.
    Anything else names nothing (BACKLOG #5914). The UID is compared, never logged (PHI-safe)."""
    if not isinstance(item, dict):
        return None
    element = item.get(_REFERENCED_SOP_INSTANCE_UID)
    if not isinstance(element, dict) or element.get("vr") != "UI":
        return None
    value = _element_values(element)
    if value is None or len(value) != 1 or not isinstance(value[0], str):
        return None
    uid = value[0].rstrip("\0 ")
    return uid if _is_uid(uid) else None


def _stowrs_refusal(body: str, status: int, sent: _SentUids) -> tuple[str, str] | None:
    """The refusal for a 2xx STOW-RS reply, or ``None`` when it is a delivery. Not every reply
    that fails to confirm the store is refused (see the last paragraph). Every code is permanent: a
    re-send would get the same reply.

    - ``unparseable-reply``: the body is not JSON, repeats a key at any depth (``json.loads`` keeps
      the last of two, so a FailedSOPSequence could be read two ways), is nested past json's
      recursion limit (a ``RecursionError``, which a ``ValueError`` arm does not reach), is not
      a dataset object or a non-empty array of them, or carries a FailedSOPSequence in a shape
      dicom+json does not allow (:func:`_failed_sop_state`) and none that proves a rejection --
      that direction fails closed, under this code and not ``failed-sop``, since such a sequence
      proves no rejection (BACKLOG #5914).
    - ``failed-sop``: a well-formed FailedSOPSequence (``00081198``) with an item, in any of the
      datasets, a proven rejection.
    - ``unconfirmed-202``: a 202 (stored with warnings, or some instances failed) not refused
      above whose reply does not name the instance sent (:func:`_unconfirmed_202`): no
      ReferencedSOPSequence (``00081199``) item that names its File Meta Media Storage SOP Instance
      UID or its data set SOP Instance UID. An empty 202 is one. When ``sent`` has neither UID
      there is nothing to compare, so a 202 not refused above is one whatever its reply names,
      with a reason naming why (BACKLOG #5914, decisions of 2026-11-23), except where the data
      set read raised a fault the codec does not wrap (``read_fault``): then an item naming any UID
      confirms it, as the BACKLOG #5914 reply check did before the UID comparison; an empty 202, or one naming no valid UID, is still refused
      (Manager decision of 2026-11-24).

    An empty reply (:func:`_reply_is_empty`) on any other 2xx is not refused. A 200 is not held to
    the ReferencedSOPSequence rule and is not compared with ``sent`` (BACKLOG #5914 ruling), so a 200
    dataset that confirms nothing and is not refused above, ``{}`` included, is delivered.
    docs/CONNECTIONS.md *DICOMweb*, *Status classification*, states the rule in full.

    Returned as ``(code, reason)``; both are fixed strings that name no reply content and no UID."""
    if _reply_is_empty(body):
        return _unconfirmed_202([], sent) if status == 202 else None
    # A refused parse is (None, hint), and None is not a dataset, so the hint need not be read.
    obj, _ = json_loads_or_refusal(body.lstrip(_BOM), object_pairs_hook=refuse_repeated_keys)
    if isinstance(obj, dict):
        datasets = [obj]
    elif isinstance(obj, list) and obj and all(isinstance(ds, dict) for ds in obj):
        datasets = obj
    else:
        return "unparseable-reply", f"a reply that is not parseable dicom+json; {_NOT_SENT}"
    proven, malformed = _failed_sop_state(datasets)
    if proven:
        return "failed-sop", "a FailedSOPSequence (instance rejected)"
    if malformed:
        # A malformed sequence proves no rejection, so it is not failed-sop, and it carries the
        # replay advice.
        return (
            "unparseable-reply",
            f"a FailedSOPSequence in a shape dicom+json does not allow; {_NOT_SENT}",
        )
    if status == 202:
        return _unconfirmed_202(_sequence_items(datasets, _REFERENCED_SOP_SEQUENCE) or [], sent)
    return None


def _unconfirmed_202(referenced: list[Any], sent: _SentUids) -> tuple[str, str] | None:
    """The ``unconfirmed-202`` refusal for a 202 whose ReferencedSOPSequence items are
    ``referenced``, or ``None`` when an item names the instance sent: by its File Meta UID or its
    data set's SOP Instance UID, both read before the POST (:func:`_read_sent_uids`), so nothing
    here parses the object. With neither UID to compare, the reason names why the File Meta has
    none (BACKLOG #5914). The exception is an object with no File Meta UID whose data set read
    raised a fault the codec does not wrap (``read_fault``): nothing can be compared, so a 202 is
    confirmed as the BACKLOG #5914 reply check did before the UID comparison, by an item that names any UID; with none named it is
    still refused."""
    named = {uid for uid in map(_named_uid, referenced) if uid is not None}
    if any(uid in named for uid in (sent.meta, sent.data_set)):
        return None
    if sent.meta is None and sent.read_fault and named:
        return None
    if sent.meta is None and sent.data_set is None:
        # The replay advice goes before the cause, so the stored text's two cuts keep it.
        return "unconfirmed-202", f"no UID to compare; {_NOT_SENT}; the object has {sent.cause}"
    return "unconfirmed-202", f"no ReferencedSOPSequence confirming the instance sent; {_NOT_SENT}"


def _classify_stowrs(status: int, base_url: str) -> DeliveryError:
    """Classify a non-2xx STOW-RS response. 5xx / 408 / 429 → transient :class:`DeliveryError`; other 4xx
    (incl. 409 'all instances failed') / a refused 3xx → permanent :class:`NegativeAckError`. PHI-safe:
    only the status + a redacted URL are named, never the ``dicom+json`` body."""
    if status in _RETRYABLE_4XX or 500 <= status < 600:
        return DeliveryError(f"DICOMweb {_redact_url(base_url)} returned HTTP {status}")
    return NegativeAckError(
        f"DICOMweb {_redact_url(base_url)} rejected with HTTP {status}",
        code=str(status),
        permanent=True,
    )


class DicomWebDestination(DestinationConnector):
    """Store a DICOM object to a DICOMweb service via STOW-RS (outbound only; ADR 0025 Phase 2)."""

    def __init__(self, config: Destination) -> None:
        s = config.settings
        url = s.get("url")
        if not isinstance(url, str) or not url:
            raise ValueError(
                "DICOMweb destination requires a 'url' setting (the DICOMweb service base URL)"
            )
        _reject_url_control_chars(url, "url")
        scheme = url_scheme(url, "DICOMweb destination 'url'")
        if scheme not in ("http", "https"):
            raise ValueError(
                f"DICOMweb destination 'url' must be http or https, got scheme {scheme!r}"
            )
        refuse_url_credentials(url, "DICOMweb destination 'url'")
        _refuse_base_url_query_or_fragment(url, config.name)
        _refuse_ambiguous_credentials(s, config.name)
        self.base_url = url
        # BACKLOG #2060: names this hop in a bounded-read refusal, which never carries the URL.
        self._hop = hop_identity("DICOMweb", config.name)
        study_uid = s.get("study_uid")
        self.study_uid: str | None = str(study_uid) if study_uid else None
        if self.study_uid is not None:
            _reject_url_control_chars(self.study_uid, "study_uid")  # it flows into the URL path
            # BACKLOG #1241: and the control-char screen alone is not enough for a value that becomes a
            # path SEGMENT — refuse at construction, where the operator sees it, not at the URL layer.
            _reject_non_uid(self.study_uid, "study_uid")
        # BACKLOG #5959: above zero, as REST's; positive_seconds says why.
        self.timeout: float = positive_seconds(
            s.get("timeout_seconds", 30.0), knob="timeout_seconds", transport="DICOMweb destination"
        )
        self.encoding: str = s.get("encoding", "utf-8")
        # ADR 0013: capture the STOW-RS dicom+json response. Default False → returns None, byte-identical.
        self.capture_response: bool = bool(s.get("capture_response", False))
        # #200 (ADR 0092): the per-connection insecure-hop attestation, keying the posture-keyed refusal.
        attested = config.tls_hop_attested
        # ADR 0153 decision 2: the OPPOSITE per-connection declaration — this hop is cleartext, is not
        # secure, and that is accepted (WARN + audit, never a silent ALLOW).
        accepted, accept_reason = config.cleartext_accepted, config.cleartext_reason
        # Captured at construction; re-asserted (zero I/O) at the byte-crossing in _post (decision 4).
        self._hop_guard: InsecureHopGuard | None = None
        # BACKLOG #5911: a static url or header the wire refuses fails the connection here, before
        # the proxy route's hop gate, rather than every message at send time. The url judged is the
        # STOW-RS target, which is sent with no further path appended.
        self._headers = self._build_headers(s)
        refuse_unsendable_static_request(
            self._resolve_target_url(),
            self._headers,
            setting="DICOMweb destination",
            sent_as_is=True,
            leave_proxy_credential_names=True,
        )
        # BACKLOG #112/#127/#128 (ADR 0126): per-connection forward/egress proxy (None → byte-identical).
        self._proxy: ProxyConfig | None = egress_route_from_settings(
            s,
            dest_scheme=scheme,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
            connection=config.name,
        )
        proxy_dest = self._proxy.for_host(self.base_url) if self._proxy is not None else None
        proxy_handlers = proxy_dest.opener_handlers() if proxy_dest is not None else ()
        if proxy_dest is not None:
            # Pre-emptive Proxy-Authorization (Basic; empty for Digest/none) — tunnelled for https (0126).
            self._headers.update(proxy_dest.auth_headers())
        # The multipart Content-Type (with the generated boundary) is set per-request in _post — it is not
        # operator-supplied, so it is excluded from the length check (which guards URL + supplied headers).
        enforce_outbound_length_limits(self.base_url, self._headers)
        refuse_cleartext_credentials(
            scheme,
            self._headers,
            self.base_url,
            credentials=http_credentials_sent(
                ConnectorType.DICOMWEB,
                s,
                cleartext=True,
                proxied=hop_reaches_a_proxy(proxy_dest, proxy_handlers, self.base_url),
            ),
            connection=config.name,
        )
        # ASVS 12.2.1: the STOW-RS multipart body carries the DICOM object (PHI), so a cleartext http
        # egress to a non-loopback host is refused even without credentials (loopback byte-identical).
        self._hop_guard = refuse_cleartext_egress(
            scheme,
            self.base_url,
            attested=attested,
            cleartext_accepted=accepted,
            cleartext_reason=accept_reason,
            connection=config.name,
        )
        if bool_setting(s, "verify_tls", default=True):
            # #1180 (ADR 0093): the client trust anchor for this STOW-RS hop.
            anchor = http_family_trust_anchor(
                s, url=self.base_url, trust_anchor_policy=config.trust_anchor_policy
            )
            if scheme == "http":
                # The same refusal for an http url, worded so it does not say the hop verifies its
                # server: the opener makes no TLS connection to the partner (vault BACKLOG #5511).
                refuse_chain_check_on_os_roots(
                    anchor, cleartext=True, connection_kind="DICOMweb connection"
                )
            self._opener: urllib.request.OpenerDirector = _verifying_opener(
                *proxy_handlers, trust_anchor=anchor
            )
            # #201 (ADR 0078 amendment): the verify-ON https hop validates the DICOMweb-server cert but
            # does no OCSP/CRL revocation (stdlib ssl has none) — refuse an off-loopback production-PHI
            # verified STOW-RS hop unless revocation is attested or this hop's own opener checks a CRL.
            # Same posture-keyed guard as its REST/SOAP/FHIR siblings; composes with #200 (fires only
            # on the verify-ON https path, disjoint from the cleartext/verify-off gates above, so no hop
            # is ever double-refused).
            #
            # Below `self._opener`, which nothing later replaces: see refuse_unrevoked_verified_hop.
            refuse_unrevoked_verified_hop(
                scheme,
                self.base_url,
                connector="DICOMweb destination",
                revocation_attested=config.tls_revocation_attested,
                revocation_attested_reason=config.tls_revocation_attested_reason,
                opener=self._opener,
                connection=config.name,
            )
        else:
            # verify_tls=false makes the https hop MITM-able — a posture-keyed insecure hop (#200).
            guard = refuse_verify_off(
                scheme,
                self.base_url,
                connector="DICOMweb destination",
                connection=config.name,
                credentials=http_credentials_sent(ConnectorType.DICOMWEB, s),
                attested=attested,
            )
            if guard is not None:
                self._hop_guard = guard
            logger.warning(
                "DICOMweb destination %s has TLS verification DISABLED (verify_tls=false)",
                _redact_url(self.base_url),
            )
            self._opener = _insecure_opener(*proxy_handlers)
        self._target_url = self._resolve_target_url()
        # ASVS 4.2.5: the gate above measured base_url, but _target_url is DERIVED from it 33 lines
        # later and is what actually ships on every STOW-RS POST and OPTIONS probe. Bounding only the
        # base left the derived URL unmeasured -- an ordering gap, not a missing call.
        enforce_outbound_length_limits(self._target_url, self._headers)

    def _resolve_target_url(self) -> str:
        """``{base}/studies`` (server assigns the study) or ``{base}/studies/{study_uid}`` when set."""
        base = self.base_url.rstrip("/")
        if self.study_uid:
            # Defense-in-depth percent-encode, matching the fhir.py path-segment treatment this file was
            # asymmetric with (BACKLOG #1241). It is a NO-OP today by construction — the UID grammar
            # admits only digits and dots, both RFC 3986 unreserved — and that is the point: it is here
            # so a later loosening of the grammar cannot silently put a raw metacharacter in the path.
            return f"{base}/studies/{urllib.parse.quote(self.study_uid, safe='')}"
        return f"{base}/studies"

    def _build_headers(self, s: dict[str, Any]) -> dict[str, str]:
        """STOW-RS request headers: ``Accept: application/dicom+json`` + static ``headers`` + optional
        bearer/basic auth. The multipart ``Content-Type`` (with the boundary) is set per-request in
        :meth:`_post`, not here."""
        headers: dict[str, str] = {"Accept": _DICOM_JSON}
        extra = s.get("headers") or {}
        if isinstance(extra, dict):
            # Screened for the same reason study_uid is, and NAMES as well as values: both halves land
            # on the wire, so a CRLF in either splits the request. Unlike a URL a header value has no
            # incidental neutralisation downstream -- nothing strips or re-encodes it.
            for k, v in extra.items():
                _reject_url_control_chars(str(k), "header name")
                _reject_url_control_chars(str(v), f"header {str(k)!r} value")
            headers.update({str(k): str(v) for k, v in extra.items()})
        token = s.get("bearer_token")
        user, password = s.get("basic_user"), s.get("basic_password")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        elif user and password:
            raw = f"{user}:{password}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
        return headers

    @staticmethod
    def _multipart_body(dicom_bytes: bytes) -> tuple[bytes, str]:
        """Frame one DICOM instance as a ``multipart/related`` body (STOW-RS single-instance MVP), with a
        fresh random boundary **guaranteed absent** from the object bytes (RFC 2046 §5.1.1). Returns
        ``(body, boundary)`` so the caller sets the matching ``Content-Type`` boundary parameter."""
        boundary = _BOUNDARY_PREFIX + secrets.token_hex(16)
        # The delimiter a parser scans for is "\r\n--<boundary>"; regenerate (practically never) on the
        # astronomically-unlikely chance the random token collides with the binary payload.
        while b"--" + boundary.encode("ascii") in dicom_bytes:
            boundary = _BOUNDARY_PREFIX + secrets.token_hex(16)
        crlf = b"\r\n"
        delim = boundary.encode("ascii")
        body = b"".join(
            [
                b"--",
                delim,
                crlf,
                b"Content-Type: ",
                _DICOM_PART_TYPE.encode("ascii"),
                crlf,
                crlf,
                dicom_bytes,
                crlf,
                b"--",
                delim,
                b"--",
                crlf,
            ]
        )
        return body, boundary

    async def send(
        self, payload: str, *, metadata: Mapping[str, str] | None = None
    ) -> DeliveryResponse | None:  # metadata (#68): unused — no per-message header knob here
        dicom_bytes = recover_dicom_object_bytes(payload, label="DICOMweb STOW-RS")
        # urllib is blocking — keep it off the event loop (the delivery worker awaits this).
        body, status = await asyncio.to_thread(self._post, dicom_bytes)
        # A non-2xx, or a 2xx that _stowrs_refusal refuses, already raised inside _post (transient
        # retry / permanent dead-letter).
        if not self.capture_response:
            return None
        if _reply_is_empty(body):
            return DeliveryResponse(body="", outcome="no_reply", detail=f"HTTP {status}")
        return DeliveryResponse(body=body, outcome="accepted", detail=f"HTTP {status}")

    async def test_connection(self) -> None:
        await asyncio.to_thread(self._probe)

    def _probe(self) -> None:
        # Reachability only: an OPTIONS to the studies endpoint reaches the host without storing an object.
        # Any HTTP response means the host answered; 401/403 means the configured credentials would be
        # rejected (which a real store dead-letters). Connection/DNS/TLS/timeout always fails.
        # BACKLOG #2196: the hop re-check _post runs, before a byte crosses.
        assert_probe_hop(self._hop_guard, self.base_url, connector="DICOMweb")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
            self._target_url, headers=self._headers, method="OPTIONS"
        )
        try:
            with self._opener.open(req, timeout=self.timeout) as resp:
                # ASVS 15.2.2: the probe body is discarded, but draining it unbounded would let an
                # unreachability check be turned into a memory exhaustion. Over-cap raises
                # ResponseTooLargeError (a DeliveryError), which the operator sees as a failed
                # "test connection" rather than as a reachable host.
                drain_bounded(resp, connector=f"{self._hop} probe")
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise DeliveryError(
                    f"DICOMweb {_redact_url(self.base_url)} returned HTTP {exc.code} (check credentials)"
                ) from exc
            return  # any other status (the host answered) → reachable
        except urllib.error.URLError as exc:
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except HttpAuthError as exc:
            # BACKLOG #2323: as in _post, with the fixed text on the DeliveryError a probe raises.
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} {AUTH_CHALLENGE_REFUSED}"
            ) from exc
        except (ValueError, http.client.InvalidURL) as exc:
            # BACKLOG #1793: the probe is the test-connection reply, so an escaped InvalidURL put its
            # text -- which can hold a password -- in front of anyone holding connections:test.
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} rejected an invalid request value"
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"DICOMweb {_redact_url(self.base_url)} failed: {exc}") from exc
        except EgressReplyError:
            raise  # as in _post
        except http.client.HTTPException as exc:
            # BACKLOG #2113: as in _post, so the probe reply names the class and nothing else.
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} sent a malformed HTTP reply "
                f"({type(exc).__name__})"
            ) from exc

    def _post(self, dicom_bytes: bytes) -> tuple[str, int]:
        # #200 (ADR 0092 decision 4): zero-I/O send-time re-assertion of a permitted insecure hop before
        # a byte crosses (a None guard — secure/loopback — is byte-identical).
        if self._hop_guard is not None:
            # BACKLOG #2989: classified, so a refusal does not leave _post as a raw ValueError.
            self._hop_guard.assert_delivery_url(self.base_url, connector="DICOMweb")
        # BACKLOG #5914: the UIDs a 202 is compared with are read before a byte is sent, as the SCU
        # parses before it associates; a fault in the read reads as no data set UID
        # (_data_set_instance_uid says which).
        sent = _read_sent_uids(dicom_bytes)
        data, boundary = self._multipart_body(dicom_bytes)
        headers = {
            **self._headers,
            "Content-Type": f'multipart/related; type="{_DICOM_PART_TYPE}"; boundary={boundary}',
        }
        try:
            req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme constrained to http(s) in __init__
                self._target_url,
                data=data,
                headers=headers,
                method="POST",
            )
            with self._opener.open(req, timeout=self.timeout) as resp:
                # ASVS 15.2.2: bounded on the socket read. A STOW-RS reply is a small result
                # document, so the 16 MiB ceiling refuses only a peer that is broken or hostile.
                # vault BACKLOG #2180: the status here is 2xx, so an over-cap body must not
                # re-send. A FailedSOPSequence can sit inside a 2xx, so the body is classified
                # below in both capture modes, and the refusal is permanent.
                body = read_2xx_reply_text(
                    resp,
                    connector=self._hop,
                    encoding=self.encoding,
                    body_is_needed=True,
                )
                status = int(getattr(resp, "status", 200))
        except urllib.error.HTTPError as exc:
            # Non-2xx: classify transient vs permanent. Raised for BOTH capturing and non-capturing — a
            # non-2xx is a transport/server failure, not a captured reply. PHI-safe: never the body.
            raise _classify_stowrs(exc.code, self.base_url) from exc
        except urllib.error.URLError as exc:  # DNS / connection refused / TLS / timeout
            raise DeliveryError(
                f"DICOMweb {_redact_url(self.base_url)} unreachable: {exc.reason}"
            ) from exc
        except HttpAuthError as exc:
            # BACKLOG #2323: the web proxy's refused Digest challenge is the connection's fault, not
            # this object's. Before the ValueError arm, which it would otherwise match.
            raise auth_challenge_refused(f"DICOMweb {_redact_url(self.base_url)}") from exc
        except (ValueError, http.client.InvalidURL) as exc:
            # urllib rejected an illegal request value (a CRLF in a header/URL slipped past the guard). A
            # retry re-sends the same request → permanent. PHI-safe: redacted url only.
            # BACKLOG #1793: InvalidURL is named for the reason rest.py's _post gives. Its text could
            # hold a password, and it reached queue.last_error.
            raise NegativeAckError(
                f"DICOMweb {_redact_url(self.base_url)} rejected an invalid request value",
                code="bad-request-value",
                permanent=True,
            ) from exc
        except (TimeoutError, OSError) as exc:
            raise DeliveryError(f"DICOMweb {_redact_url(self.base_url)} failed: {exc}") from exc
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
                f"DICOMweb {_redact_url(self.base_url)} sent a malformed HTTP reply "
                f"({type(exc).__name__})"
            ) from exc
        # BACKLOG #5914: a 2xx does not by itself confirm the store. Classified on this worker thread,
        # after the response is closed, and outside the try: no urllib arm above can retype a fault
        # here, and with no handler active no decode error -- which holds the whole body -- rides
        # the refusal's __context__. The code leads the text, so a cut stored error keeps it; the
        # text names no reply content.
        refused = _stowrs_refusal(body, status, sent)
        if refused is not None:
            code, reason = refused
            raise NegativeAckError(
                f"DICOMweb {code}: HTTP {status} with {reason} ({_redact_url(self.base_url)})",
                code=code,
                permanent=True,
            )
        return body, status


register_destination(ConnectorType.DICOMWEB, DicomWebDestination)
