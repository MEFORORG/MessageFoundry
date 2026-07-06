# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
to the secured store (CLAUDE.md §9). The pyx12 logger (which logs the raw, value-bearing strings at
ERROR) is silenced for the duration of the validation pass.

Pure: no I/O to disk/network, no engine imports. ``pyx12``'s sole runtime dependency is ``defusedxml``
(already in tree), used to parse its bundled, trusted map XML — not attacker input.
"""

from __future__ import annotations

import io
import json
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

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


@contextmanager
def _silence_pyx12_logger() -> Iterator[None]:
    """Suppress pyx12's own logging during a pass. pyx12 logs each violation's *raw* error string —
    which embeds the offending data value (potential PHI) — at ERROR, from child loggers under the
    ``pyx12`` tree (e.g. ``pyx12.error_handler``). We extract our own value-free errors from pyx12's
    structured JSON instead, so the whole ``pyx12.*`` tree is muted for the duration.

    Raising the ``pyx12`` parent logger's level above CRITICAL suppresses the children too: they sit at
    NOTSET and inherit the parent's effective level, so their ERROR records are dropped at the source
    (before any handler/propagation) — without touching the global ``logging.disable`` or other
    loggers. The previous level is restored afterward, even on exception."""
    logger = logging.getLogger("pyx12")
    previous = logger.level
    logger.setLevel(logging.CRITICAL + 1)
    try:
        yield
    finally:
        logger.setLevel(previous)


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
    if isinstance(raw, (bytes, bytearray)):
        text = bytes(raw).decode("utf-8", "replace")
    else:
        text = raw

    x12n_document, make_params = load_x12_validator()
    params = make_params()
    fd_ack = io.StringIO()
    fd_json = io.StringIO()

    with _silence_pyx12_logger():
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
