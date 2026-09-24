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
the subset both callers share: the live listener's remaining work (recording the ``ERROR`` row,
building the AR/AE frame, capturing the ACK) is I/O the dry-run has no business simulating, so the
seam sits at "decoded text, or the reason it was refused".

**The live listener does not call this yet.** Pointing ``_handle_inbound`` at it is part B of #1689
and is deliberately not in this change (that method is held by other open work). Until then the
runner keeps its own inline copy of the sequence, and
``tests/test_ingress_guard_parity.py`` pins the two against each other so the copy cannot drift
silently.

**Two live guards are deliberately NOT mirrored here, and both omissions are by design:**

* **the strict-validation timeout.** The listener runs ``hl7apy`` off the event loop under
  ``validation.strict_timeout_s`` and records ``ERROR`` + ``AE`` on expiry. Honouring it here would
  force :func:`~messagefoundry.pipeline.dryrun.dry_run` to become ``async``, which ripples into
  ``checks.py``, ``verify/smoke.py`` and ``dryrun_trace.py``. A dry-run therefore validates
  **un-timed**: it can report ``RECEIVED``/``ERROR`` for a pathological body the engine would
  ``AE``-NAK on a timeout instead.
* **document detach** (``_detach_documents``, #149 / ADR 0105). It is ``async`` and it *writes*
  attachment rows, so there is no honest pure mirror of it. A dry-run consequently previews the
  whole body where a streaming inbound would have detached its documents.
"""

from __future__ import annotations

import codecs

from messagefoundry.config.models import ContentType
from messagefoundry.config.wiring import InboundConnection
from messagefoundry.parsing import RawMessage, normalize
from messagefoundry.parsing.binary import BinaryCarriageError, is_marked
from messagefoundry.parsing.binary import decode as decode_carriage
from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    HL7PeekError,
    Peek,
    enforce_size_limits,
)
from messagefoundry.parsing.sniff import _content_matches_declared, text_sniff_head
from messagefoundry.redaction import safe_exc

__all__ = [
    "INGRESS_MAX_BYTES",
    "NUL_REJECTED_REASON",
    "IngressGuardError",
    "admit_resubmitted_body",
    "carry_binary_ingress",
    "decode_ingress",
    "ingress_encoding",
    "ingress_size_error",
    "peek_max_bytes",
    "store_safe_raw",
]

#: Engine-level ingress size ceiling (SEC-017, CWE-770). Mirrors ``wiring_runner._INGRESS_MAX_BYTES``;
#: the HL7 path gets the same ceiling through ``Peek.parse`` -> ``enforce_size_limits`` instead, at the
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
    :func:`admit_resubmitted_body` adds two more, ``"type"`` for the declared-type sniff and
    ``"parse"`` for ``Peek.parse``; the dry-run entry points never raise either.
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


def _raise_if_oversize(size: int) -> None:
    """Raise the ``size``-phase refusal when :func:`ingress_size_error` reports an overrun."""
    oversize = ingress_size_error(size)
    if oversize is not None:
        raise IngressGuardError(oversize, phase="size")


def store_safe_raw(raw: str | bytes, content_type: str, *, text: str | None = None) -> str:
    """A ``str`` view of a REJECTED body that a TEXT store can hold (INGEST-4 / ADR 0028).

    U+0000 is the only latin-1 codepoint a TEXT column cannot carry (Postgres rejects it at bind;
    SQLite / SQL Server truncate there), so keep the faithful, human-readable view when it is NUL-free
    and escalate to ``mfb64:v1:`` byte-carriage only when it is not. ``b"\\x00" in raw`` and
    ``"\\x00" in raw.decode("latin-1")`` are bijective, so testing the view is exact.

    Mirrors ``wiring_runner._nul_safe_error_raw`` and additionally accepts a ``str`` ``raw``, which
    the dry-run entry points take and the transport-fed listener never sees."""
    data = raw if isinstance(raw, bytes) else raw.encode("utf-8", "surrogatepass")
    view = text if text is not None else data.decode("latin-1")
    if "\x00" not in view:
        return view
    return RawMessage.from_bytes(data, content_type).raw


def _encode_declared(raw: str, ic: InboundConnection) -> bytes:
    """``raw`` in the inbound's declared charset, or the ``decode``-phase refusal when it cannot be.

    A text a charset cannot hold is one the listener could never have decoded from a sender's bytes.
    The reason names a position and never the character: ``str(UnicodeEncodeError)`` quotes the
    offending character, which is a byte of the body."""
    encoding = ingress_encoding(ic)
    try:
        return raw.encode(encoding)
    except UnicodeEncodeError as exc:
        raise IngressGuardError(
            f"encode error ({encoding}): {exc.reason} at position {exc.start}", phase="decode"
        ) from exc
    except LookupError as exc:
        raise IngressGuardError(
            f"encode error ({encoding}): {safe_exc(exc)}", phase="decode"
        ) from exc


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
    # Measured on the RAW bytes, pre-base64-inflation, so the carriage codec cannot walk past the
    # ceiling — the same side of the encode the listener measures on.
    _raise_if_oversize(len(data))
    return RawMessage.from_bytes(data, ic.content_type.value).raw


def decode_ingress(raw: str | bytes, ic: InboundConnection) -> str:
    """Decode one received body for ``ic`` and run the post-decode guards; return the text or raise.

    The sequence, and its order, is the listener's: decode with the declared ``encoding`` at
    ``errors="strict"`` (HL7 additionally collapses line endings to ``\\r``; a non-HL7 body is decoded
    verbatim, since ``\\r``-normalizing JSON/XML/X12 would corrupt it), then reject an embedded NUL,
    then bound a non-HL7 body's length. The HL7 ceiling is *not* applied here — ``Peek.parse`` enforces
    it at :func:`peek_max_bytes`, which is where the per-connection cap lives.

    Order is the load-bearing part, which is why this is one function rather than three: the NUL check
    must run on the DECODED text and BEFORE anything derives a control id, a summary or a stored raw
    from it, or those derived values carry the NUL onward into a store that cannot hold it.

    A ``str`` ``raw`` has nothing to decode, so it skips the charset guard and still gets the NUL and
    size guards — the dry-run entry points accept text, the transport-fed listener never does.

    Raises :class:`IngressGuardError` for every refusal, including an unknown codec name
    (``LookupError``), which the listener lets escape into its transport instead. Refusing it here is
    strictly narrower: a preview cannot thereby accept anything the engine would reject."""
    if ic.content_type.is_binary:
        raise ValueError(
            f"inbound {ic.name!r} declares binary content_type {ic.content_type.value!r}; "
            "use carry_binary_ingress (ADR 0028), never a text decode"
        )
    hl7v2 = ic.content_type is ContentType.HL7V2
    encoding = ingress_encoding(ic)
    try:
        if hl7v2:
            text = normalize(raw, encoding=encoding, errors="strict")
        else:
            text = raw.decode(encoding) if isinstance(raw, bytes) else raw
    except (UnicodeDecodeError, LookupError) as exc:
        raise IngressGuardError(
            f"decode error ({encoding}): {safe_exc(exc)}", phase="decode"
        ) from exc
    if "\x00" in text:
        raise IngressGuardError(NUL_REJECTED_REASON, phase="decode")
    if not hl7v2:
        _raise_if_oversize(len(text))
    return text


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

    The committed form is the ``\\r``-normalized text for HL7, the text verbatim for another text
    type, and canonical ``mfb64:v1:`` carriage for a binary type.

    ``ic`` is ``None`` when there is no inbound to guard for: the edit-resend direct path writes an
    outbound row, and a re-route whose origin inbound is no longer registered has no declared type. Only
    the engine-wide rules apply then, the NUL rule and the engine ceiling, and ``raw`` is returned as
    is. Both callers today already bound that body below the ceiling (``EditResendRequest.raw`` and the
    API's 1 MiB request cap), so the ceiling there is a backstop.

    **Not mirrored, and a resubmission can therefore still differ from a sender's body:** strict
    ``hl7apy`` validation (an inbound with ``validation.strict`` would ``AE``-NAK a body this admits),
    and document detach. A streaming inbound raises ``max_message_bytes`` to pay for a detach this path
    does not do, so its HL7 ceiling here stays at the engine default rather than the raised value.

    The reason never carries a byte of the body, so a caller may return it to the operator and audit it."""
    if ic is None:
        if "\x00" in raw:
            raise IngressGuardError(NUL_REJECTED_REASON, phase="decode")
        _raise_if_oversize(len(raw))
        return raw
    if ic.content_type.is_binary:
        if is_marked(raw):
            try:
                data = decode_carriage(raw)
            except BinaryCarriageError as exc:
                raise IngressGuardError(
                    f"binary carriage error: {safe_exc(exc)}", phase="decode"
                ) from exc
        else:
            data = _encode_declared(raw, ic)
        # Measured on the raw bytes, before base64 inflation, as the listener measures a binary body.
        _raise_if_oversize(len(data))
        _raise_if_mistyped(ic, data)
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
            raise IngressGuardError(str(exc), phase="size") from exc
        try:
            Peek.parse(text, max_bytes=ceiling)
        except HL7PeekError as exc:
            raise IngressGuardError(f"parse error: {safe_exc(exc)}", phase="parse") from exc
    else:
        _raise_if_mistyped(ic, text_sniff_head(text))
    return text


def _raise_if_mistyped(ic: InboundConnection, head: bytes) -> None:
    """Raise the ``type``-phase refusal when ``head`` contradicts the inbound's declared type."""
    if not _content_matches_declared(ic.content_type, head):
        raise IngressGuardError(
            f"ingress body does not match its declared content type "
            f"{ic.content_type.value!r} (no matching magic bytes)",
            phase="type",
        )
