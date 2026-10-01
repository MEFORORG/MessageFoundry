# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ingress decode + post-decode guards, in ONE place, so the gate and the engine cannot diverge.

An inbound body is decoded and guarded *before* anything looks at it: decode with the connection's
declared ``encoding`` at ``errors="strict"``, reject an embedded ``NUL``, and bound the size. The
live listener (:meth:`~messagefoundry.pipeline.wiring_runner.RegistryRunner._handle_inbound`) runs
that sequence; :func:`~messagefoundry.pipeline.dryrun.dry_run` did **not**, so ``messagefoundry
check`` and the Test Bench previewed ``RECEIVED`` for fixtures the engine would ``NAK`` — and
previewed ``ERROR``/mojibake for bodies the engine accepts (BACKLOG #1689).

This module holds the rule once. It is **pure** — no store, no ACK, no event loop — which is exactly
the subset both callers share. The one exception is :func:`admit_resubmission`, the operator resend's
async entry point, which only schedules the pure checks onto worker threads as the listener does: the live listener's remaining work (recording the ``ERROR`` row,
building the AR/AE frame, capturing the ACK) is I/O the dry-run has no business simulating, so the
seam sits at "decoded text, or the reason it was refused".

**Both listeners call it** (part B of #1689). ``_handle_inbound`` and ``_handle_inbound_http`` run
:func:`decode_body` then :func:`check_decoded`, or :func:`check_binary_size` then
:func:`carry_binary_ingress` for a binary type, and then :func:`check_declared_type` on a non-HL7
body. The dry-run runs the decode, NUL and size guards through :func:`decode_ingress` and
:func:`carry_binary_ingress`. So the listener carries no copy of these guards, and
``tests/test_ingress_guard_parity.py`` fails if it grows one back.

**The two callers still differ in at least these places.** How they resolve the codec NAME, stated
at :func:`decode_ingress`. The declared-type sniff, which the dry-run does not run: ``messagefoundry
check`` sends each fixture to every inbound, so adding the sniff there would fail an HL7 fixture on
every X12 or FHIR inbound of a mixed config, and that choice is not this module's to make. The HL7
parse step, which each caller runs itself: the stored ``parse error`` text differs, and the dry-run
catches only ``HL7PeekError`` where the listener catches every peek-read fault. And the two live
guards below.

**Two live guards are deliberately NOT mirrored for the dry-run, and both omissions are by design:**

* **the strict-validation timeout.** The listener runs ``hl7apy`` off the event loop under
  ``validation.strict_timeout_s`` and records ``ERROR`` + ``AE`` on expiry. Honouring it in the
  dry-run would force :func:`~messagefoundry.pipeline.dryrun.dry_run` to become ``async``, which
  ripples into ``checks.py``, ``verify/smoke.py`` and ``dryrun_trace.py``. A dry-run therefore
  validates **un-timed**: it can report ``RECEIVED``/``ERROR`` for a pathological body the engine
  would ``AE``-NAK on a timeout instead. The operator resend (:func:`admit_resubmitted_body`) is
  already off the loop, so it does honour the timeout.
* **document detach** (``_detach_documents``, #149 / ADR 0105). It is ``async`` and it *writes*
  attachment rows, so there is no honest pure mirror of it. A dry-run consequently previews the
  whole body where a streaming inbound would have detached its documents.
"""

from __future__ import annotations

import asyncio
import codecs
import re
from typing import Any

from messagefoundry.config.models import ContentType
from messagefoundry.config.wiring import InboundConnection
from messagefoundry.parsing import RawMessage, normalize
from messagefoundry.parsing.binary import MARKER as CARRIAGE_MARKER
from messagefoundry.parsing.binary import BinaryCarriageError, is_marked
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    HL7PeekError,
    Peek,
    enforce_size_limits,
)
from messagefoundry.parsing.sniff import _content_matches_declared, text_sniff_head
from messagefoundry.parsing.validate import validate
from messagefoundry.redaction import safe_exc

__all__ = [
    "INGRESS_MAX_BYTES",
    "NUL_REJECTED_REASON",
    "STRICT_VALIDATE_TIMEOUT_SECONDS",
    "IngressGuardError",
    "IngressNulRejected",
    "admit_resubmission",
    "admit_resubmitted_body",
    "carry_binary_ingress",
    "check_binary_size",
    "check_declared_type",
    "check_decoded",
    "decode_body",
    "decode_ingress",
    "ingress_encoding",
    "ingress_size_error",
    "listener_encoding",
    "peek_max_bytes",
    "raise_if_strictly_invalid",
    "reingress_size_error",
    "store_safe_raw",
    "streaming_over_threshold",
    "strict_validate_timeout",
    "strict_validation_due",
]

# How long a single strict hl7apy validate may run before the message dead-letters (#89, DoS backstop).
# Mirrors the _LOOKUP_RESULT_TIMEOUT_SECONDS rationale: a pathological body that makes hl7apy's
# structure/cardinality parse spin can otherwise pin the listener's off-loop worker; the timeout frees
# the listener and routes the message to ERROR/dead-letter. It CANNOT kill the worker thread (no
# thread cancellation in CPython) — the orphaned validate leaks its thread until it returns, bounded by
# the 16 MiB / segment caps enforce_size_limits fires BEFORE the slow parse (validate.py). Per-inbound
# `validation.strict_timeout_s` overrides this; <= 0 there disables the backstop entirely. Owner-tunable.
# The listener reads it as ``wiring_runner._STRICT_VALIDATE_TIMEOUT_SECONDS``; it lives here so the
# resend (BACKLOG #1911) and the listener resolve it by one rule.
STRICT_VALIDATE_TIMEOUT_SECONDS = 5.0


def strict_validate_timeout(ic: InboundConnection) -> float | None:
    """The effective wall-clock (seconds) for this inbound's strict validate, or ``None`` if disabled.

    Resolves the per-connection ``validation.strict_timeout_s`` against the engine default (#89):
    ``None`` inherits :data:`STRICT_VALIDATE_TIMEOUT_SECONDS`; ``<= 0`` disables the backstop (returns
    ``None``, so the caller runs the validate un-timed, the pre-#89 behaviour). The value is trusted
    config, not an HL7 field."""
    configured = ic.validation.strict_timeout_s
    effective = STRICT_VALIDATE_TIMEOUT_SECONDS if configured is None else configured
    return effective if effective > 0 else None


#: Engine-level ingress size ceiling (SEC-017, CWE-770) for a NON-HL7 body, and the only one: the
#: listeners, the dry-run, the resend and the loopback re-ingress all read it here. It makes the 16 MiB
#: ceiling an engine invariant rather than a per-transport frame cap an operator can disable. The HL7
#: path gets the same ceiling through ``Peek.parse`` -> ``enforce_size_limits`` instead, at the
#: per-connection cap :func:`peek_max_bytes` resolves.
INGRESS_MAX_BYTES = DEFAULT_MAX_MESSAGE_BYTES

#: The listener's own wording for INGEST-4, quoted verbatim so a preview and a live ERROR row read the
#: same. A NUL is invalid in every text payload accepted here (HL7 v2 field data, JSON, XML 1.0, X12)
#: and store-hostile besides (Postgres rejects it at bind; SQLite / SQL Server truncate at it).
NUL_REJECTED_REASON = "ingress body contains a NUL (U+0000), invalid in a text/HL7 payload"


class IngressGuardError(Exception):
    """An ingress guard refused the body; ``reason`` is the operator-facing text.

    ``phase`` names which guard fired (``"decode"`` or ``"size"``) and matches the live listener's ACK
    phase labels, so a caller that records dispositions can map it onto the same one the engine writes.
    :func:`admit_resubmitted_body` adds three more, ``"type"`` for the declared-type sniff,
    ``"parse"`` for ``Peek.parse`` and ``"strict"`` for strict ``hl7apy`` validation; the dry-run entry
    points never raise any of them.

    **Never raised with a body-holding error on its chain (BACKLOG #1796).** The caught error can hold
    the body: a ``UnicodeEncodeError``'s or ``UnicodeDecodeError``'s ``.object`` is the WHOLE text or
    byte string, and an ``HL7PeekError`` can wrap a parser error that quotes what it failed on. ``from exc`` puts
    that on ``__cause__``. ``from None`` only hides it from the default traceback printer and leaves it
    on ``__context__``, where a structured-logging serializer or a crash reporter still reads it. So
    each handler here that catches such an error keeps only the content-free reason in a local and
    raises after the handler has ended, which leaves both empty. ``reason`` is the same text either
    way. The one ``from None`` left, :func:`admit_resubmission`'s strict timeout, catches a
    ``TimeoutError`` that holds nothing.
    """

    def __init__(self, reason: str, *, phase: str) -> None:
        super().__init__(reason)
        self.reason = reason
        self.phase = phase


def ingress_encoding(ic: InboundConnection) -> str:
    """The charset this inbound declares for decoding received bodies (default ``utf-8``).

    An explicit ``None`` in the settings means "not declared", not "no encoding", so it falls back the
    same way an absent key does."""
    declared = ic.spec.settings.get("encoding")
    return str(declared) if declared else "utf-8"


def listener_encoding(ic: InboundConnection) -> Any:
    """The ``encoding`` setting as the live listener reads it: the value as declared, unresolved.

    Only an absent key falls back to ``utf-8``. How that differs from :func:`ingress_encoding`, and
    what it costs, is stated once, at :func:`decode_ingress`."""
    return ic.spec.settings.get("encoding", "utf-8")


def peek_max_bytes(ic: InboundConnection) -> int:
    """The body ceiling ``Peek.parse`` must enforce for this inbound.

    A streaming inbound (#149, ADR 0105) raises the ceiling to its per-connection
    ``max_message_bytes`` so a large document is admitted and then detached under the cap; every other
    inbound keeps the engine's 16 MiB default. Reading the per-connection value matters in **both**
    directions: with the bare default a preview refuses a 256 MiB body the engine would take, and it
    admits a body a connection configured *below* the default would refuse."""
    return ic.max_message_bytes or DEFAULT_MAX_MESSAGE_BYTES


def ingress_size_error(size: int) -> str | None:
    """The listener's oversize text for a body of ``size`` units, or ``None`` when it fits.

    The unit is the caller's, matching the live split: raw **bytes** before base64 inflation for a
    binary content type, decoded **characters** for a text one (``enforce_size_limits`` measures
    ``len(norm)`` the same way)."""
    if size > INGRESS_MAX_BYTES:
        return f"ingress exceeds max size ({size} > {INGRESS_MAX_BYTES} bytes)"
    return None


#: Unbroken, canonically padded base64: the only carriage form sized by the bytes it carries.
_CANONICAL_B64 = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def _canonical_carried_size(payload: str) -> int | None:
    """The byte count ``payload`` carries if it is canonical base64, else ``None``.

    Whitespace is not stripped first. A decoder tolerates it, but here it would let padding of any
    length measure as nothing, so a padded or otherwise noncanonical payload has no byte count."""
    if len(payload) % 4 or _CANONICAL_B64.fullmatch(payload) is None:
        return None
    padding = 2 if payload.endswith("==") else int(payload.endswith("="))
    return len(payload) // 4 * 3 - padding


def reingress_size_error(ic: InboundConnection, body: str) -> str | None:
    """The oversize text for a loopback re-ingress ``body`` (BACKLOG #1914), or ``None`` when it fits.

    A loopback has no listener, so the re-ingress worker applies the engine ceiling itself. Canonical
    ``mfb64:v1:`` carriage on a binary loopback is sized by the bytes it carries, as the listener
    sizes a binary body. Every other body is held and routed as text, so it is sized in characters,
    as the listener sizes a text body. That includes the decoded text a capturing transport hands a
    binary loopback, and carriage that is padded or corrupt. An HL7 body always returns ``None``
    here: ``Peek.parse`` in the re-ingress step already refuses one over the engine ceiling, after it
    normalizes line endings, so measuring the raw text first could refuse a body the peek admits.

    The reason carries only a length, never a byte of the body."""
    if ic.content_type is ContentType.HL7V2:
        return None
    if ic.content_type.is_binary and is_marked(body):
        payload = body[len(CARRIAGE_MARKER) :]
        if 3 * len(payload) // 4 <= INGRESS_MAX_BYTES:
            # No base64 this short can carry more than the ceiling, and whitespace only shortens it.
            # That also bounds a padded or corrupt carriage to the length of a ceiling-size one.
            return None
        carried = _canonical_carried_size(payload)
        if carried is not None:
            return ingress_size_error(carried)
    return ingress_size_error(len(body))


def _raise_if_oversize(size: int) -> None:
    """Raise the ``size``-phase refusal when :func:`ingress_size_error` reports an overrun."""
    oversize = ingress_size_error(size)
    if oversize is not None:
        raise IngressGuardError(oversize, phase="size")


def store_safe_raw(raw: str | bytes, content_type: str, *, text: str | None = None) -> str:
    """A ``str`` view of a REJECTED body that a TEXT store can hold (INGEST-4 / ADR 0028).

    U+0000 is the only latin-1 codepoint a TEXT column cannot carry. SQLite / SQL Server truncate
    there, and Postgres rejects it at bind: in a listener that raise would unwind into the transport
    and drop the connection with no ERROR row, a count-and-log violation. So keep the faithful,
    human-readable view when it is NUL-free and escalate to ``mfb64:v1:`` byte-carriage only when it
    is not; the exact bytes then come back through ``RawMessage.raw_bytes``. ``b"\\x00" in raw`` and
    ``"\\x00" in raw.decode("latin-1")`` are bijective, so testing the view is exact.

    ``text`` supplies an already-decoded view, which the post-decode NUL refusal passes; without it the
    view is the lossless ``latin-1`` one. The listeners' ERROR rows use this, and so do the dry-run
    entry points, which also pass a ``str`` ``raw`` the transport-fed listener never sees."""
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "surrogatepass")
    view = text if text is not None else data.decode("latin-1")
    if "\x00" not in view:
        return view
    return RawMessage.from_bytes(data, content_type).raw


def _encode_declared(raw: str, ic: InboundConnection) -> bytes:
    """``raw`` in the inbound's declared charset, or the ``decode``-phase refusal when it cannot be.

    A text a charset cannot hold is one the listener could never have decoded from a sender's bytes.
    The reason names a position and never the character: ``str(UnicodeEncodeError)`` quotes the
    offending character, which is a byte of the body. The refusal is raised after the handler ends,
    because the caught error's ``.object`` is the whole body (see :class:`IngressGuardError`)."""
    encoding = ingress_encoding(ic)
    try:
        return raw.encode(encoding)
    except UnicodeEncodeError as exc:
        reason = f"encode error ({encoding}): {exc.reason} at position {exc.start}"
    except LookupError as exc:
        reason = f"encode error ({encoding}): {safe_exc(exc)}"
    raise IngressGuardError(reason, phase="decode")


#: Codecs in which every ASCII character encodes, so an ASCII-only text needs no trial encode.
_ASCII_SUPERSET_CODECS = frozenset({"ascii", "utf-8", "iso8859-1", "cp1252"})


def _check_encodable(raw: str, ic: InboundConnection) -> None:
    """Refuse ``raw`` when the inbound's declared charset cannot hold it (``decode`` phase).

    An ASCII-only text in an ASCII-superset codec is skipped rather than encoded: a trial encode of an
    upload-sized body is a full copy for an answer that is already known. Any other case, including
    an unknown codec name, goes to :func:`_encode_declared`, which owns the refusal wording."""
    try:
        name: str | None = codecs.lookup(ingress_encoding(ic)).name
    except LookupError:
        name = None
    if name in _ASCII_SUPERSET_CODECS and raw.isascii():
        return
    _encode_declared(raw, ic)


def carry_binary_ingress(raw: str | bytes, ic: InboundConnection) -> str:
    """Carry a BYTE-oriented body (``content_type.is_binary``) the way the listener does — no decode.

    A binary inbound's bytes are base64-carried at the source boundary behind ``mfb64:v1:`` (ADR 0028)
    and routed as a :class:`~messagefoundry.parsing.message.RawMessage`; a codec recovers them via
    ``.raw_bytes``. Text-decoding them instead is what the dry-run used to do, and it is wrong twice
    over: it mangles the body a Handler's codec then reads, and it fails outright on bytes that are
    not valid in the declared charset — for a content type where *no* charset applies.

    A ``str`` that already carries the marker is passed through rather than re-encoded, so re-running a
    stored raw through the preview does not double-wrap it. Any other ``str`` is encoded with the
    declared charset first, because a caller holding text for a binary feed has no bytes to offer."""
    if isinstance(raw, str):
        if is_marked(raw):
            return raw
        data = _encode_declared(raw, ic)
    else:
        data = raw
    check_binary_size(data)
    return RawMessage.from_bytes(data, ic.content_type.value).raw


def check_binary_size(data: bytes) -> None:
    """Bound a binary body at the engine ceiling (SEC-017); the ``size``-phase refusal on an overrun.

    Measured on the RAW bytes, pre-base64-inflation, so the carriage codec cannot walk past the
    ceiling. :func:`carry_binary_ingress` runs it before it encodes. The listener also runs it on its
    own, ahead of the declared-type sniff, so a body the sniff refuses is never base64-encoded."""
    _raise_if_oversize(len(data))


class IngressNulRejected(IngressGuardError):
    """The NUL guard's refusal (INGEST-4), told apart from a charset failure by its type alone.

    Both are the ``decode`` phase, but the listener answers them differently: a different MSA-3 text
    on the AR, and a different stored view of the rejected body. So the caller needs to know which one
    fired without matching on the reason text."""

    def __init__(self) -> None:
        super().__init__(NUL_REJECTED_REASON, phase="decode")


def decode_body(raw: str | bytes, ic: InboundConnection, *, encoding: str) -> str:
    """Decode one received text body for ``ic`` in ``encoding`` at ``errors="strict"``; return the text.

    HL7 additionally collapses line endings to ``\\r``. A non-HL7 body is decoded verbatim, since
    ``\\r``-normalizing JSON/XML/X12 would corrupt it. A ``str`` ``raw`` has nothing to decode, so it
    passes through (HL7 still gets its line endings collapsed).

    A ``UnicodeDecodeError`` is the ``decode``-phase :class:`IngressGuardError`. Nothing else is
    caught, on purpose: a bad codec name escapes to the caller, which is the live listener's rule.
    :func:`decode_ingress` states where the dry-run parts from it."""
    if ic.content_type.is_binary:
        raise ValueError(
            f"inbound {ic.name!r} declares binary content_type {ic.content_type.value!r}; "
            "use carry_binary_ingress (ADR 0028), never a text decode"
        )
    try:
        if ic.content_type is ContentType.HL7V2:
            return normalize(raw, encoding=encoding, errors="strict")
        return raw.decode(encoding) if isinstance(raw, bytes) else raw
    except UnicodeDecodeError as exc:
        refused = _decode_refusal(encoding, exc)
    raise IngressGuardError(refused, phase="decode")


def _decode_refusal(encoding: str, exc: Exception) -> str:
    """The ``decode``-phase reason, one wording for the listener's charset failure and the dry-run's
    unknown codec. ``safe_exc`` keeps the body out of it."""
    return f"decode error ({encoding}): {safe_exc(exc)}"


def check_decoded(text: str, ic: InboundConnection) -> None:
    """The post-decode guards, in the listener's order: reject an embedded NUL, then bound the length.

    Order is the load-bearing part, which is why the two share one function: the NUL check must run
    on the DECODED text and BEFORE anything derives a control id, a summary or a stored raw from it,
    or those derived values carry the NUL onward into a store that cannot hold it.

    The NUL refusal is :class:`IngressNulRejected`. The length bound is the ``size``-phase
    :class:`IngressGuardError` and applies to a non-HL7 body only: the HL7 ceiling is ``Peek.parse``'s,
    at :func:`peek_max_bytes`, which is where the per-connection cap lives."""
    if "\x00" in text:
        raise IngressNulRejected()
    if ic.content_type is not ContentType.HL7V2:
        _raise_if_oversize(len(text))


def decode_ingress(raw: str | bytes, ic: InboundConnection) -> str:
    """Decode one received body for ``ic`` and run the post-decode guards; return the text or raise.

    :func:`decode_body` then :func:`check_decoded`, the same two calls the live listener makes, so the
    dry-run and the engine share the sequence rather than a copy of it. A ``str`` ``raw`` skips the
    charset guard and still gets the NUL and size guards: the dry-run entry points accept text, and the
    transport-fed listener never does.

    **One deliberate difference from the listener, and it sits in the codec name, not the guards.**
    This resolves the name with :func:`ingress_encoding`, so an absent or ``None`` declaration decodes
    as ``utf-8``. It also refuses an unknown codec (``LookupError``) as a ``decode`` error. The listener
    passes :func:`listener_encoding` to :func:`decode_body` and lets both failures escape into its
    transport.
    ``Registry.encoding_problems`` refuses an unknown literal name at load, so the case that remains
    live is a non-``str`` setting: ``None`` from code-first config, or an unresolved inbound ``env()``
    reference (see ``resolved_encoding_problems`` in ``config/wiring.py``)."""
    encoding = ingress_encoding(ic)
    try:
        text = decode_body(raw, ic, encoding=encoding)
    except LookupError as exc:
        refused = _decode_refusal(encoding, exc)
    else:
        check_decoded(text, ic)
        return text
    raise IngressGuardError(refused, phase="decode")


def admit_resubmitted_body(raw: str, ic: InboundConnection | None) -> str:
    """Admit an operator-resubmitted body the way the inbound ``ic`` admits a sender's (BACKLOG #1911).

    The upload resend (``POST /uploads/{file_id}/resend``) and the edit-resend re-route write straight
    to the ingress stage, so the listener never sees the body. This runs the listener's guards over it
    first, raises :class:`IngressGuardError` for the first one that fails, and otherwise returns the
    form the listener would have committed -- the caller commits that, not ``raw``:

    * **decode** -- a text inbound's declared charset must be able to hold the text, since the listener
      could only ever have produced it by decoding bytes in that charset; then the NUL rule. A binary
      inbound's ``mfb64:v1:`` carriage must decode.
    * **size** -- for an HL7 inbound, the size and segment caps ``Peek.parse`` enforces at
      :func:`peek_max_bytes`, so a connection's own lower ``max_message_bytes`` holds, but never above
      the engine ceiling (see below); the engine ceiling for any other type, in the listener's units.
    * **type** -- the declared-type magic-byte sniff the listener applies to a non-HL7 body.
    * **parse** -- an HL7 body must pass ``Peek.parse``, which is the listener's only HL7 type check.

    Strict ``hl7apy`` validation is NOT run here, because the listener times it and a synchronous
    function cannot time itself without a thread of its own. :func:`admit_resubmission` runs this and
    then the strict step, timed as the listener times it; call that one.

    The committed form is the ``\\r``-normalized text for HL7, the text verbatim for another text
    type, and canonical ``mfb64:v1:`` carriage for a binary type.

    ``ic`` is ``None`` when there is no inbound to guard for: the edit-resend direct path writes an
    outbound row, and a re-route whose origin inbound is no longer registered has no declared type. Only
    the engine-wide rules apply then, the NUL rule and the engine ceiling, and ``raw`` is returned as
    is. Strict validation is an inbound's setting, so it never applies there either. Both callers today
    already bound that body below the ceiling (``EditResendRequest.raw`` and the API's 1 MiB request
    cap), so the ceiling there is a backstop.

    **Not mirrored, and a resubmission can therefore still differ from a sender's body:** document
    detach. A streaming inbound raises ``max_message_bytes`` to pay for a detach this path does not do,
    so its HL7 ceiling here stays at the engine default rather than the raised value.

    The reason never carries a byte of the body, so a caller may return it to the operator and audit it."""
    if ic is None:
        if "\x00" in raw:
            raise IngressNulRejected()
        _raise_if_oversize(len(raw))
        return raw
    # The reason a caught error refused the body, raised once its handler has ended.
    refused: str | None = None
    if ic.content_type.is_binary:
        if is_marked(raw):
            try:
                data = decode_carriage(raw)
            except BinaryCarriageError as exc:
                refused = f"binary carriage error: {safe_exc(exc)}"
            if refused is not None:
                raise IngressGuardError(refused, phase="decode")
        else:
            data = _encode_declared(raw, ic)
        # Measured on the raw bytes, before base64 inflation, as the listener measures a binary body.
        _raise_if_oversize(len(data))
        check_declared_type(ic, data)
        # A binary inbound's rows are carriage (ADR 0028); text committed bare would fail .raw_bytes.
        # Re-encoded even when it arrived marked, so a non-canonical form (a line break inside the
        # base64) is stored as the listener's canonical, unbroken carriage.
        return RawMessage.from_bytes(data, ic.content_type.value).raw
    _check_encodable(raw, ic)
    text = decode_ingress(raw, ic)
    if ic.content_type is ContentType.HL7V2:
        # The listener's HL7 type check IS Peek.parse, and the magic-byte sniff is NOT applied here,
        # as the listener does not apply it: the two disagree in BOTH directions (the sniff admits an
        # FHS/BHS- or BOM-led body Peek refuses, and refuses a body led by NBSP or \x1c that Peek's
        # str.lstrip() accepts). The size and segment caps run first, on their own, so an oversize
        # body is told apart from a malformed one. The ceiling is capped at the engine
        # default because a streaming inbound's raised max_message_bytes pays for a detach that this
        # path does not do.
        ceiling = min(peek_max_bytes(ic), DEFAULT_MAX_MESSAGE_BYTES)
        try:
            enforce_size_limits(text, max_bytes=ceiling)
        except HL7PeekError as exc:
            refused = str(exc)
        if refused is not None:
            raise IngressGuardError(refused, phase="size")
        try:
            Peek.parse(text, max_bytes=ceiling)
        except HL7PeekError as exc:
            refused = f"parse error: {safe_exc(exc)}"
        if refused is not None:
            raise IngressGuardError(refused, phase="parse")
    else:
        check_declared_type(ic, text_sniff_head(text))
    return text


def streaming_over_threshold(ic: InboundConnection, text: str) -> bool:
    """Whether ``ic`` is a streaming inbound (``stream_threshold_bytes`` set) and ``text`` is at or
    above that threshold (#149, ADR 0105 Phase 1a). The listener gates its detach path on this, and
    downgrades strict validation to header-only for such a body. Below threshold or unset, ``False``."""
    threshold = ic.stream_threshold_bytes
    return threshold is not None and len(text) >= threshold


def strict_validation_due(ic: InboundConnection | None, text: str) -> bool:
    """Whether the listener would run whole-body strict ``hl7apy`` validation on ``text`` for ``ic``.

    It does when the inbound sets ``validation.strict``, unless the body is a streaming inbound's at or
    over its threshold: there the listener validates the header only, which ``Peek.parse`` has already
    done. With no inbound there is no setting to read, so never. The HL7 check restates what wiring
    already enforces, since ``validation.strict`` is refused on any other content type."""
    return (
        ic is not None
        and ic.content_type is ContentType.HL7V2
        and ic.validation.strict
        and not streaming_over_threshold(ic, text)
    )


def raise_if_strictly_invalid(text: str, ic: InboundConnection) -> None:
    """Run the listener's strict ``hl7apy`` validate over ``text``; raise the ``strict`` refusal.

    The same call the listener makes, :func:`~messagefoundry.parsing.validate.validate` against
    ``validation.hl7_version``. Blocking and CPU-bound, so run it off the event loop.

    The reason names no field and quotes no value. ``hl7apy``'s error text can carry a byte of the body
    (it echoes an unsupported MSH-12 verbatim, for one), and ``safe_text`` does not scrub a bare token,
    so the text is not carried at all. The reason counts the errors instead and points at the dry run,
    which lists them to a caller that may see message content."""
    result = validate(text, expected_version=ic.validation.hl7_version)
    if not result.ok:
        count = len(result.errors)
        plural = "" if count == 1 else "s"
        raise IngressGuardError(
            f"strict-validation failed ({count} error{plural}); a dry run of the body against "
            f"inbound {ic.name!r} lists them",
            phase="strict",
        )


async def admit_resubmission(raw: str, ic: InboundConnection | None) -> str:
    """Admit an operator-resubmitted body as the inbound ``ic``'s listener would (BACKLOG #1911).

    :func:`admit_resubmitted_body` off the event loop, then, where :func:`strict_validation_due` says
    the listener would, :func:`raise_if_strictly_invalid` in the listener's own shape: on a pooled
    worker thread under :func:`strict_validate_timeout`. A timeout is the listener's refusal too, so it
    raises the ``strict`` phase with the listener's wording. As on the listener, the timeout frees this
    call and cannot stop the worker, which runs on until the size and segment caps let it finish.

    Returns the form to commit; raises :class:`IngressGuardError` for the first guard that refuses."""
    text = await asyncio.to_thread(admit_resubmitted_body, raw, ic)
    if ic is not None and strict_validation_due(ic, text):
        timeout = strict_validate_timeout(ic)
        try:
            await asyncio.wait_for(asyncio.to_thread(raise_if_strictly_invalid, text, ic), timeout)
        except TimeoutError:
            raise IngressGuardError(
                f"strict-validation timed out after {timeout}s", phase="strict"
            ) from None
    return text


def check_declared_type(ic: InboundConnection, head: bytes) -> None:
    """Raise the ``type``-phase refusal when ``head`` contradicts the inbound's declared type.

    The magic-byte sniff (ASVS 5.2.2, BACKLOG #1109) the listeners run on a NON-HL7 body after the size
    guard, and the operator resend runs the same way. The dry-run does not; the module docstring says
    why. ``head`` is the raw bytes for a
    binary type and :func:`text_sniff_head` of the decoded text for a text one. Never applied to HL7,
    whose type check is ``Peek.parse``. The reason names the declared type only, never a body byte."""
    if not _content_matches_declared(ic.content_type, head):
        raise IngressGuardError(
            f"ingress body does not match its declared content type "
            f"{ic.content_type.value!r} (no matching magic bytes)",
            phase="type",
        )
