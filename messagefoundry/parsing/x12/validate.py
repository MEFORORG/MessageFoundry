# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in **strict** X12 validation — the slow tier behind the tolerant ``X12Peek``/``X12Message`` hot
path (ADR 0012, BACKLOG #32), mirroring how :mod:`messagefoundry.parsing.validate` (hl7apy) sits behind
the tolerant HL7 v2 peek.

Two tiers, by design (do not route the hot path through this):

* **Tolerant (built):** :class:`~messagefoundry.parsing.x12.peek.X12Peek` /
  :class:`~messagefoundry.parsing.x12.message.X12Message` — cheap, dependency-free routing/transform.
* **Strict (here):** :func:`validate` walks a parsed interchange against pyx12's bundled
  implementation-guide maps (e.g. ``005010X222A1`` for 837P) and reports every conformance violation.
  ``pyx12`` lives behind the optional ``[x12]`` extra (loaded lazily via
  :mod:`messagefoundry.parsing.x12._deps`), so importing this module is free until :func:`validate`
  is called — a Handler invokes it **on demand** against a
  :class:`~messagefoundry.parsing.message.RawMessage`, never the engine pipeline.

**Free acknowledgment generation.** pyx12's validator emits a conforming **999** (005010) or **997**
(004010) Functional Acknowledgment as a by-product of the walk, so :attr:`X12ValidationResult.ack`
carries a ready-to-return negative ack — no separate ack builder needed.

**PHI rule (do not break).** A failing X12 element error from pyx12 embeds the *offending data value*
(potential PHI) in its raw error string. This module **never** surfaces that: each
:class:`X12SegmentError` carries only structural locators — the error code, the segment/element id, a
schema-label *type name*, and the line/position — never the input value. The full interchange goes only
to the secured store (CLAUDE.md §9). The pyx12 logger tree (which logs the raw, value-bearing strings
at ERROR) is muted from the first validation pass on, and never unmuted.

Pure: no I/O to disk/network, no engine imports. ``pyx12``'s sole runtime dependency is ``defusedxml``
(already in tree), used to parse its bundled, trusted map XML — not attacker input.
"""

from __future__ import annotations

import io
import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.x12._deps import load_x12_code_resolver, load_x12_validator
from messagefoundry.parsing.x12.errors import X12ValidationError
from messagefoundry.redaction import json_loads_or_refusal

__all__ = ["X12SegmentError", "X12ValidationResult", "validate"]


@dataclass(frozen=True)
class X12SegmentError:
    """One conformance violation, reduced to **PHI-safe structural locators only**.

    ``code`` is the X12 error code pyx12 maps it to, preferring the code list of the ack pyx12 picks
    from the last group's GS08 (997 AK for 004010, also when no ack is generated; 999 IK otherwise;
    e.g. ``"8"``) and taking the other list's code where pyx12 has only that one, except a 999-only
    ``I`` code on a 997 pass; pyx12's own error name stands in where no code applies;
    ``message`` is a synthesized, value-free description;
    ``segment_id`` / ``element_position`` / ``line`` / ``loop`` locate it; ``element_name`` is the
    *schema* data-element label (e.g. ``"Transaction Set Creation Date"``), never the input value."""

    code: str
    message: str
    segment_id: str | None = None
    element_position: int | None = None
    element_name: str | None = None
    line: int | None = None
    loop: str | None = None


@dataclass(frozen=True)
class X12ValidationResult:
    """The outcome of a strict pass. ``valid`` is True iff pyx12 found no errors. ``errors`` is the
    flattened, PHI-safe violation list (empty when valid). ``ack`` is the generated 997/999
    Functional Acknowledgment ready to return to the sender (``None`` only if pyx12 emitted none, e.g.
    for an already-FA transaction); ``ack_transaction`` names which (``"997"``/``"999"``), and is ``None``
    with no ack or with a fragment pyx12's ack writer left when it failed before the closing IEA. Such
    a fragment is still returned in ``ack`` but is not a ready-to-return ack: send ``ack`` only when
    ``ack_transaction`` is set."""

    valid: bool
    errors: tuple[X12SegmentError, ...] = ()
    ack: str | None = None
    ack_transaction: str | None = None


#: The one handler the ``pyx12`` logger tree ends at. A single module-level instance, because
#: ``Logger.addHandler`` skips a handler already attached, under logging's own lock.
_log = logging.getLogger(__name__)

_PYX12_SINK = logging.NullHandler()
#: Above CRITICAL, so a logger at this level builds no record at all.
_MUTED = logging.CRITICAL + 1


def _mute_pyx12_logger() -> None:
    """Mute the whole ``pyx12`` logger tree, and never unmute it (BACKLOG #1603).

    pyx12 logs each violation's *raw* error string, which embeds the offending data value (potential
    PHI), at ERROR from child loggers such as ``pyx12.error_handler``. We build our own value-free
    errors from pyx12's structured JSON instead, so nothing pyx12 logs is wanted anywhere.

    **No restore step, on purpose.** The old context manager raised the level for one pass and put
    the previous level back afterwards. Two overlapping passes on two threads would interleave: the
    first to finish would unmute the logger while the second was still logging. No caller runs
    passes concurrently today (a Handler calls :func:`validate` synchronously on its transform
    worker). But the fix costs nothing: every call writes the same muted state, so concurrent calls
    cannot disagree. Calling it on every pass, not once at import, also re-mutes a tree that a later
    logging reconfiguration has reset.

    Two layers, in this order:

    1. The ``pyx12`` parent stops propagation and ends at a :class:`~logging.NullHandler` sink, so
       no record from anywhere in the tree reaches the root logger's handlers, which feed the
       general log. The sink goes on first: a record that meets no handler at all goes to
       :data:`logging.lastResort`, which prints WARNING and above to stderr, and NSSM keeps stderr.
    2. Every ``pyx12`` logger that exists now is set above CRITICAL, so it builds no record at all.
       Setting only the parent is not enough: ``pyx12.error_997``, ``pyx12.error_999`` and
       ``pyx12.error_html`` pin their own level to DEBUG at import. A logger created later inherits
       the parent's level; one that pins itself later is still held by layer 1.

    Layer 1 does not reach a handler someone attaches directly to a ``pyx12`` logger. Layer 2
    covers that for every logger that exists when a pass starts, until something re-pins a
    logger's level; the next pass mutes it again.

    Only a logger not already muted is written, because ``setLevel`` clears every logger's cache
    under logging's global lock. This mutes pyx12 for the whole process, including a Handler that
    imports pyx12 itself. That is the intent under the PHI rule (CLAUDE.md section 9)."""
    parent = logging.getLogger("pyx12")
    parent.addHandler(_PYX12_SINK)
    parent.propagate = False
    # ``copy()`` rather than iterating the live dict: another thread may create a logger meanwhile.
    for name, logger in logging.Logger.manager.loggerDict.copy().items():
        if (
            (name == "pyx12" or name.startswith("pyx12."))
            and isinstance(logger, logging.Logger)
            and logger.level != _MUTED
        ):
            logger.setLevel(_MUTED)


class _AckBuffer(io.StringIO):
    """The ack sink, which also keeps the last chunk written. Both of pyx12's ack writers write one
    whole segment per ``write`` call, so a finished ack's last chunk is its IEA. The ack's text cannot
    show that: a fragment echoes sender values, and with other separators a GS06 of
    ``1~IEA*1*000000001`` makes a fragment's text end in an IEA that pyx12 never wrote."""

    def __init__(self) -> None:
        super().__init__()
        self.last_write = ""

    def write(self, s: str, /) -> int:
        if s.strip():
            self.last_write = s
        return super().write(s)

    def complete(self) -> bool:
        return self.last_write.lstrip().startswith("IEA*")


# pyx12's ack choice by the last GS08's first six characters; any other version gets no ack.
_ACK_FOR_VERSION = {"004010": "997", "005010": "999"}


def _last_group_version(report: dict[str, Any]) -> str:
    """The GS08 of the last group pyx12 walked, from its report. pyx12 picks the ack from exactly that
    value (a 997 when it starts ``004010``, a 999 when ``005010``, none for a GS01 of ``FA``), so the
    ack type and the code list are read here, never from the ack text: the ack echoes sender fields,
    and with other separators those can forge a segment boundary or shift the ISA's fixed offsets."""
    vriic = ""
    for interchange in report.get("interchanges", []):
        for group in interchange.get("groups", []):
            vriic = str(group.get("vriic") or "")
    return vriic


def _segment_error(code: str, seg: dict[str, Any], err: dict[str, Any]) -> X12SegmentError:
    """A PHI-safe :class:`X12SegmentError` from a pyx12 segment-level error dict (drops ``err_str`` /
    ``err_val`` — they can embed the input value — keeping only structural locators)."""
    seg_id = seg.get("seg_id")
    return X12SegmentError(
        code=code,
        message=f"segment {seg_id or '?'}: error {code}",
        segment_id=seg_id,
        line=seg.get("cur_line"),
        loop=seg.get("name"),
    )


def _element_error(code: str, seg: dict[str, Any], ele: dict[str, Any]) -> X12SegmentError:
    """A PHI-safe :class:`X12SegmentError` from a pyx12 element-level error dict. ``name`` is the
    data-element *type* label (schema), not the value; ``err_str``/``err_val`` are dropped."""
    seg_id = seg.get("seg_id")
    pos = ele.get("ele_pos")
    name = ele.get("name")
    return X12SegmentError(
        code=code,
        message=f"element {seg_id or '?'}{pos:02d}: error {code}"
        if pos
        else f"element error {code}",
        segment_id=seg_id,
        element_position=pos,
        element_name=name,
        line=seg.get("cur_line"),
        loop=seg.get("name"),
    )


def _error_code(err: dict[str, Any], resolve: Callable[..., str | None], prefer_5010: bool) -> str:
    """The X12 error code for one pyx12 JSON error dict. Since pyx12 4.0.1, ``err_cde`` holds pyx12's
    own error name (e.g. ``"ELE_8_invalid_date"``) at segment, element and interchange level, while
    group and transaction level still emit raw X12 numbers, which ``resolve`` passes through. The
    report's ``x12_code`` field is not read: pyx12 fills it 999-first whatever the version, so a 997
    pass would report 999-only codes (``"I4"`` for a not-used segment where the 997 says ``"2"``).
    The name stands in where pyx12 maps it to no X12 code (e.g. ``SEG_8_hl_count_mismatch``), and on a
    997 pass where pyx12's table has no AK code for it (e.g. ``ELE_I10_NOT_USED``, whose only code is
    the 999's ``"I10"``), an error pyx12's 997 omits."""
    err_cde = str(err.get("err_cde", ""))
    x12_code = resolve(err_cde, prefer_5010=prefer_5010)
    return err_cde if x12_code is None else x12_code


def _flatten_errors(
    report: dict[str, Any], resolve: Callable[..., str | None], prefer_5010: bool
) -> list[X12SegmentError]:
    """Walk pyx12's nested JSON error report (interchange → group → transaction → segment → element),
    flattening every recorded error into a PHI-safe :class:`X12SegmentError`. ``prefer_5010`` is False
    when the last group is ``004010``: pyx12 picks one ack per document (from the last GS08), so the
    codes follow that ack rather than each group's own version."""
    out: list[X12SegmentError] = []
    for interchange in report.get("interchanges", []):
        # ISA-level codes are the same in the 997 and the 999 (TA1 note codes), so no version is needed.
        for err in interchange.get("errors", []):
            code = _error_code(err, resolve, True)
            out.append(X12SegmentError(code=code, message="interchange error"))
        for group in interchange.get("groups", []):
            for err in group.get("errors", []):
                code = _error_code(err, resolve, prefer_5010)
                out.append(X12SegmentError(code=code, message="group error"))
            for txn in group.get("transactions", []):
                for err in txn.get("errors", []):
                    code = _error_code(err, resolve, prefer_5010)
                    out.append(X12SegmentError(code=code, message="transaction error"))
                for seg in txn.get("segments", []):
                    for err in seg.get("errors", []):
                        out.append(_segment_error(_error_code(err, resolve, prefer_5010), seg, err))
                    for ele in seg.get("elements", []):
                        for err in ele.get("errors", []):
                            out.append(
                                _element_error(_error_code(err, resolve, prefer_5010), seg, ele)
                            )
    return out


def validate(raw: str | bytes) -> X12ValidationResult:
    """Strictly validate an X12 interchange against pyx12's bundled implementation-guide maps.

    ``raw`` is the interchange text (bytes are decoded UTF-8/replace, matching
    :meth:`X12Message.parse`). Returns an :class:`X12ValidationResult` carrying the conformance verdict,
    the PHI-safe error list, and the generated 997/999 acknowledgment.

    Raises :class:`~messagefoundry.parsing.x12.errors.X12ValidationError` only when no validation pass
    could run at all (e.g. the bytes are not a parseable X12 data file — there is no envelope to walk);
    a *failed* validation of a parseable interchange is returned as data (``valid=False``), not raised,
    so a Handler can still emit the negative ack. Raises :class:`RuntimeError` if the ``[x12]`` extra
    is absent (a deploy/config error, distinct from the ``ValueError``-rooted data errors)."""
    if isinstance(raw, (bytes, bytearray)):  # noqa: SIM108
        text = bytes(raw).decode("utf-8", "replace")
    else:
        text = raw

    x12n_document, make_params = load_x12_validator()
    resolve = load_x12_code_resolver()  # before the walk, so a pyx12 older than 4.0.1 fails first
    params = make_params()
    fd_ack = _AckBuffer()
    fd_json = io.StringIO()

    _mute_pyx12_logger()
    try:
        valid = bool(x12n_document(params, io.StringIO(text), fd_ack, None, None, fd_json))
    except Exception as exc:  # pyx12 raises bare Exception/EngineError on unwalkable input
        raise X12ValidationError(
            "strict X12 validation could not run: the bytes are not a parseable X12 interchange"
        ) from exc

    raw_json = fd_json.getvalue()
    if not raw_json.strip():
        # pyx12 wrote no report (it rejected the input before opening an interchange).
        raise X12ValidationError(
            "strict X12 validation could not run: input does not look like an X12 data file"
        )
    # pyx12's report quotes the interchange's segments, so a refusal must not chain the decode error
    # that holds it (BACKLOG #2085).
    report, refused = json_loads_or_refusal(raw_json)
    if refused is not None:  # pragma: no cover - pyx12 emits well-formed JSON
        raise X12ValidationError("strict X12 validation produced an unreadable error report")

    ack_text = fd_ack.getvalue().strip()
    ack = ack_text or None
    version = _last_group_version(report)
    ack_for_version = _ACK_FOR_VERSION.get(version[:6])
    # A writer that raises partway is caught and logged by pyx12 (muted here), leaving a fragment;
    # only an ack whose last write was its closing IEA is labelled.
    ack_transaction = ack_for_version if fd_ack.complete() else None
    if ack and ack_transaction is None:
        _log.warning("pyx12's ack writer stopped before the closing IEA; the ack is incomplete")
    prefer_5010 = ack_for_version != "997"
    errors = tuple(_flatten_errors(report, resolve, prefer_5010=prefer_5010))
    return X12ValidationResult(
        valid=valid and not errors,
        errors=errors,
        ack=ack,
        ack_transaction=ack_transaction,
    )
