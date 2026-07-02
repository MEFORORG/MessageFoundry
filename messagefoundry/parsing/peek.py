# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tolerant HL7 v2 *peek* — fast field extraction for routing/filtering.

This is the hot path: every inbound message is peeked to pull the handful of MSH
fields the engine routes on (message type, trigger event, control id, version) and to
let channel/destination filters test arbitrary fields by path (e.g. ``MSH-9.1``).

It is built on ``python-hl7``, which parses tolerantly — real-world feeds are routinely
non-conformant and must still route. We never raise on a *structurally* odd-but-parseable
message; we only raise :class:`HL7PeekError` when the bytes are not an HL7 message at all
(no MSH) or a field *path* is malformed.

HL7 uses a carriage return (``\\r``) between segments. Inbound bytes arrive with all
manner of line endings (MLLP strips its own framing; files may be ``\\n`` or ``\\r\\n``),
so :func:`normalize` collapses them to ``\\r`` before parsing.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import cast

import hl7

import messagefoundry.parsing._backend as _backend
import messagefoundry.parsing._builtin_hl7 as _builtin_hl7

logger = logging.getLogger(__name__)

__all__ = [
    "Peek",
    "HL7PeekError",
    "normalize",
    "parse_path",
    "DEFAULT_MAX_MESSAGE_BYTES",
    "DEFAULT_MAX_SEGMENTS",
    "enforce_size_limits",
]

# Pre-parse resource caps (DoS guards). A complete-but-pathological message — multi-MiB, or
# tens of thousands of segments — would otherwise be parsed/walked whole (python-hl7 here,
# hl7apy on the strict path), multiplying memory and CPU. Checked *before* parsing so an
# oversized message is rejected cheaply. ``None`` disables a cap.
DEFAULT_MAX_MESSAGE_BYTES = 16 * 1024 * 1024  # 16 MiB — matches the MLLP/file ingress caps
DEFAULT_MAX_SEGMENTS = 10_000  # generous for big batches/ORUs, bounds segment-count blow-up


class HL7PeekError(ValueError):
    """Raised when bytes are not a parseable HL7 message, or a field path is malformed."""


def enforce_size_limits(
    norm: str,
    *,
    max_bytes: int | None = DEFAULT_MAX_MESSAGE_BYTES,
    max_segments: int | None = DEFAULT_MAX_SEGMENTS,
) -> None:
    """Raise :class:`HL7PeekError` if the normalized message exceeds the size/segment caps.

    Operates on the ``\\r``-normalized text so it covers every ingress (MLLP, file). Shared
    by :meth:`Peek.parse`, :func:`~messagefoundry.parsing.validate.validate` and
    :func:`~messagefoundry.parsing.tree.parse_tree`."""
    if max_bytes is not None and len(norm) > max_bytes:
        raise HL7PeekError(f"message exceeds max size ({len(norm)} > {max_bytes} bytes)")
    if max_segments is not None:
        segment_count = norm.count("\r") + 1
        if segment_count > max_segments:
            raise HL7PeekError(f"message exceeds max segments ({segment_count} > {max_segments})")


# SEG-F[.C[.S]] — segment id, field, optional component, optional subcomponent.
# Repetition defaults to the first; segment to its first occurrence (Phase 1).
_PATH_RE = re.compile(
    r"^(?P<seg>[A-Z][A-Z0-9]{2})-(?P<field>\d+)"
    r"(?:\.(?P<comp>\d+)(?:\.(?P<sub>\d+))?)?$"
)


def parse_path(path: str) -> tuple[str, int, int | None, int | None]:
    """Split an HL7 field path into ``(segment, field, component, subcomponent)``.

    Component/subcomponent are ``None`` when omitted. Raises :class:`HL7PeekError` on a
    malformed path. Shared by :meth:`Peek.field` (read) and the transform engine (write).
    """
    m = _PATH_RE.match(path)
    if not m:
        raise HL7PeekError(f"invalid HL7 field path: {path!r}")
    return (
        m["seg"],
        int(m["field"]),
        int(m["comp"]) if m["comp"] else None,
        int(m["sub"]) if m["sub"] else None,
    )


def normalize(raw: str | bytes, *, encoding: str = "utf-8", errors: str = "replace") -> str:
    """Decode (if ``raw`` is bytes) with ``encoding``/``errors`` and collapse all line endings to
    HL7's ``\\r`` separator.

    The default is tolerant (``utf-8``/``replace``) so the hot path keeps routing a slightly-off
    message rather than choking. The engine's inbound path instead passes the connection's declared
    encoding with ``errors="strict"`` and routes a genuine ``UnicodeDecodeError`` to the ERROR
    disposition, so a wrong-charset feed isn't silently turned into U+FFFD in the stored raw and the
    delivered copy (review H-3)."""
    if isinstance(raw, (bytes, bytearray)):
        raw = bytes(raw).decode(encoding, errors)
    return raw.replace("\r\n", "\r").replace("\n", "\r")


@dataclass(frozen=True)
class Peek:
    """A parsed view over an inbound message exposing routing fields + path access.

    Construct via :meth:`parse`. ``message`` is the underlying parse — either a built-ins
    :data:`~messagefoundry.parsing._builtin_hl7.ParsedMessage` (ADR 0054, the default backend) or a
    legacy ``python-hl7`` :class:`hl7.Message` (when ``_backend.USE_BUILTIN`` is off or the built-ins
    path fell back). ``raw`` is the normalized (``\\r``-delimited) text it was parsed from. Field
    access dispatches on the backing type, so the public surface is identical either way.
    """

    message: _builtin_hl7.ParsedMessage | hl7.Message
    raw: str

    @classmethod
    def parse(
        cls,
        raw: str | bytes,
        *,
        max_bytes: int | None = DEFAULT_MAX_MESSAGE_BYTES,
        max_segments: int | None = DEFAULT_MAX_SEGMENTS,
    ) -> "Peek":
        norm = normalize(raw)
        if not norm.strip():
            raise HL7PeekError("empty message")
        enforce_size_limits(norm, max_bytes=max_bytes, max_segments=max_segments)
        if not norm.lstrip().startswith("MSH"):
            raise HL7PeekError("message does not start with an MSH segment")
        if _backend.use_builtin():
            try:
                return cls(message=_builtin_hl7.parse(norm), raw=norm)
            except Exception:  # noqa: BLE001 — fallback guard: any unexpected built-ins error
                # The contract guards (empty/no-MSH) already ran above and raised HL7PeekError, so
                # anything here is an *internal* built-ins fault. Fall back to the proven python-hl7
                # path rather than failing a connection, and log so the gap is visible (ADR 0054
                # Phase-1 fallback guard).
                logger.warning(
                    "built-ins HL7 parse failed; falling back to python-hl7", exc_info=True
                )
        try:
            message = hl7.parse(norm)
        except Exception as exc:  # python-hl7 raises a variety of ValueErrors
            raise HL7PeekError(f"could not parse HL7 message: {exc}") from exc
        return cls(message=message, raw=norm)

    # --- generic field access (for filters) ----------------------------------

    def field(self, path: str) -> str | None:
        """Return the value at an HL7 path like ``MSH-9``, ``MSH-9.1`` or ``PID-5.1.1``.

        Returns ``None`` if the segment/field/component is absent or empty. Uses the
        first occurrence of the segment and the first repetition of the field.
        """
        seg, fld, comp, sub = parse_path(path)
        return self._resolve(seg, fld, comp, sub)

    def _resolve(self, seg: str, fld: int, comp: int | None, sub: int | None) -> str | None:
        if isinstance(self.message, dict):
            return self._resolve_builtin(
                cast("_builtin_hl7.ParsedMessage", self.message), seg, fld, comp, sub
            )
        return self._resolve_hl7(self.message, seg, fld, comp, sub)

    @staticmethod
    def _resolve_builtin(
        msg: _builtin_hl7.ParsedMessage, seg: str, fld: int, comp: int | None, sub: int | None
    ) -> str | None:
        # python-hl7 resolves the segment through its ``segments()`` scan, which blows up with an
        # IndexError on any blank/empty segment *before* the value extraction — and that error is NOT
        # caught by the legacy path's inner ``except IndexError`` (which only wraps ``extract_field``).
        # Run the equivalent scan first, outside the catch, so a blank-segment error propagates exactly
        # like the legacy path while a genuine invalid-depth over-index still maps to None below.
        _builtin_hl7.raise_if_blank_segment_scan(msg)
        # The built-ins ``extract_field`` mirrors python-hl7's ``Segment.extract_field`` exactly,
        # including the whole-value-no-component rule and the ""-vs-IndexError asymmetry; an
        # invalid-depth index surfaces here as IndexError, mapped to None like the python-hl7 path.
        try:
            return _builtin_hl7.extract_field(msg, seg, fld, comp, sub)
        except (IndexError, ValueError):
            # IndexError = invalid-depth over-index, mapped to None exactly like the python-hl7 path.
            # ValueError is defense-in-depth for a malformed escape count surfacing from unescape
            # (DELTA-02): a field read on the pre-ACK summarize() path must never crash the
            # connection — an absent/unreadable value is None.
            return None

    @staticmethod
    def _resolve_hl7(
        message: hl7.Message, seg: str, fld: int, comp: int | None, sub: int | None
    ) -> str | None:
        try:
            segment = message.segment(seg)
        except KeyError:
            return None
        try:
            field_obj = segment[fld]
        except (IndexError, KeyError):
            return None
        if comp is None:
            return str(field_obj) or None
        # For component/subcomponent access use python-hl7's extractor (first segment, first
        # repetition). It correctly returns the whole value when the field carries no component
        # separator — manual indexing would otherwise walk into the *string* and return a single
        # character (e.g. "ORC-2.1" of "PLACER123" => "P"). Out-of-range parts raise IndexError.
        try:
            value = message.extract_field(seg, 1, fld, 1, comp, sub if sub is not None else 1)
        except IndexError:
            return None
        return value or None

    # --- named routing fields (the common case) ------------------------------

    @property
    def message_code(self) -> str | None:
        """MSH-9.1, e.g. ``ADT``."""
        return self.field("MSH-9.1")

    @property
    def trigger_event(self) -> str | None:
        """MSH-9.2, e.g. ``A01``."""
        return self.field("MSH-9.2")

    @property
    def message_structure(self) -> str | None:
        """MSH-9.3, e.g. ``ADT_A01`` (often absent)."""
        return self.field("MSH-9.3")

    @property
    def message_type(self) -> str | None:
        """MSH-9 as sent, e.g. ``ADT^A01``."""
        return self.field("MSH-9")

    @property
    def control_id(self) -> str | None:
        """MSH-10 — the message control id, used for de-dup/correlation."""
        return self.field("MSH-10")

    @property
    def version(self) -> str | None:
        """MSH-12, e.g. ``2.5.1`` (None if the sender omitted it)."""
        return self.field("MSH-12")

    @property
    def sending_app(self) -> str | None:
        return self.field("MSH-3")

    @property
    def sending_facility(self) -> str | None:
        return self.field("MSH-4")

    @property
    def receiving_app(self) -> str | None:
        return self.field("MSH-5")

    @property
    def receiving_facility(self) -> str | None:
        return self.field("MSH-6")

    @property
    def timestamp(self) -> str | None:
        """MSH-7 — message date/time as sent."""
        return self.field("MSH-7")

    def routing(self) -> dict[str, str | None]:
        """The routing/correlation fields the store records. No PHI segments here."""
        return {
            "message_type": self.message_type,
            "control_id": self.control_id,
            "version": self.version,
            "sending_app": self.sending_app,
            "sending_facility": self.sending_facility,
            "receiving_app": self.receiving_app,
            "receiving_facility": self.receiving_facility,
            "timestamp": self.timestamp,
        }

    def segments(self) -> list[str]:
        """Ordered segment ids, e.g. ``["MSH", "EVN", "PID", "PV1"]``."""
        if isinstance(self.message, dict):
            return _builtin_hl7.segment_ids(cast("_builtin_hl7.ParsedMessage", self.message))
        return [str(seg[0]) for seg in self.message]
