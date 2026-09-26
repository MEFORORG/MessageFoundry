# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in **strict** X12 validation — the slow tier behind the tolerant ``X12Peek``/``X12Message`` hot
path (ADR 0012, BACKLOG #32), mirroring how :mod:`messagefoundry.parsing.validate` (hl7apy) sits behind
the python-hl7 peek for HL7 v2.

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
import json
import logging
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.x12._deps import load_x12_validator
from messagefoundry.parsing.x12.errors import X12ValidationError

__all__ = ["X12SegmentError", "X12ValidationResult", "validate"]


@dataclass(frozen=True)
class X12SegmentError:
    """One conformance violation, reduced to **PHI-safe structural locators only**.

    ``code`` is pyx12's numeric error code; ``message`` is a synthesized, value-free description;
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
    for an already-FA transaction); ``ack_transaction`` names which (``"997"``/``"999"``/``None``)."""

    valid: bool
    errors: tuple[X12SegmentError, ...] = ()
    ack: str | None = None
    ack_transaction: str | None = None


#: The one handler the ``pyx12`` logger tree ends at. A single module-level instance, because
#: ``Logger.addHandler`` skips a handler already attached, under logging's own lock.
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


def _ack_transaction(ack_text: str) -> str | None:
    """Identify a generated ack as ``"999"`` or ``"997"`` by its ST01, structurally (no value parse)."""
    for token in ("ST*999", "ST*997"):
        if token in ack_text:
            return token.split("*", 1)[1]
    return None


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


def _flatten_errors(report: dict[str, Any]) -> list[X12SegmentError]:
    """Walk pyx12's nested JSON error report (interchange → group → transaction → segment → element),
    flattening every recorded error into a PHI-safe :class:`X12SegmentError`."""
    out: list[X12SegmentError] = []
    for interchange in report.get("interchanges", []):
        for err in interchange.get("errors", []):
            out.append(
                X12SegmentError(code=str(err.get("err_cde", "")), message="interchange error")
            )
        for group in interchange.get("groups", []):
            for err in group.get("errors", []):
                out.append(X12SegmentError(code=str(err.get("err_cde", "")), message="group error"))
            for txn in group.get("transactions", []):
                for err in txn.get("errors", []):
                    out.append(
                        X12SegmentError(
                            code=str(err.get("err_cde", "")), message="transaction error"
                        )
                    )
                for seg in txn.get("segments", []):
                    for err in seg.get("errors", []):
                        out.append(_segment_error(str(err.get("err_cde", "")), seg, err))
                    for ele in seg.get("elements", []):
                        for err in ele.get("errors", []):
                            out.append(_element_error(str(err.get("err_cde", "")), seg, ele))
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
    params = make_params()
    fd_ack = io.StringIO()
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
    try:
        report = json.loads(raw_json)
    except json.JSONDecodeError as exc:  # pragma: no cover - pyx12 emits well-formed JSON
        raise X12ValidationError(
            "strict X12 validation produced an unreadable error report"
        ) from exc

    errors = tuple(_flatten_errors(report))
    ack_text = fd_ack.getvalue().strip()
    ack = ack_text or None
    return X12ValidationResult(
        valid=valid and not errors,
        errors=errors,
        ack=ack,
        ack_transaction=_ack_transaction(ack_text) if ack else None,
    )
