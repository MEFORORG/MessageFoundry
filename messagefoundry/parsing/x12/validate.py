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

**Free acknowledgment generation.** pyx12's validator emits a **999** (005010) or **997** (004010)
Functional Acknowledgment as a by-product of the walk, so :attr:`X12ValidationResult.ack` carries the
negative ack — no separate ack builder needed. An ack pyx12 did not finish is not returned (``ack`` is
then ``None``). A returned ack echoes sender values unescaped, so it is complete but not thereby
well-formed; see :class:`X12ValidationResult`.

**PHI rule (do not break).** A failing X12 element error from pyx12 embeds the *offending data value*
(potential PHI) in its raw error string, and an exception pyx12 raises can quote the interchange. An
:class:`X12SegmentError` drops those strings and holds structural locators (its docstring names them,
and a limit on its segment id), and a refusal chains no pyx12 exception. The ack does echo sender
values, so it is left out of the result's repr. The full interchange goes only to the secured store
(CLAUDE.md §9). The pyx12 logger tree is muted from the first validation pass on, and never
unmuted, because its ERROR records can carry those values (:func:`_mute_pyx12_logger` says when).

No network I/O and no engine imports. Disk reads include pyx12's bundled map XML, by pyx12 and by
the segment id check. ``pyx12``'s sole runtime dependency is ``defusedxml`` (already in tree), used
to parse that bundled, trusted XML — not attacker input.
"""

from __future__ import annotations

import io
import logging
import re
import threading
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from messagefoundry.parsing.x12._deps import (
    is_x12_install_fault,
    load_x12_code_resolver,
    load_x12_map_segment_ids,
    load_x12_validator,
)
from messagefoundry.parsing.x12.errors import X12ValidationError
from messagefoundry.redaction import json_loads_or_refusal

__all__ = ["X12SegmentError", "X12ValidationResult", "validate"]


@dataclass(frozen=True)
class X12SegmentError:
    """One conformance violation, reduced to **structural locators**.

    ``code`` is the X12 error code pyx12 maps it to in one code list, chosen by the last group's GS08:
    the 997 AK list for 004010, also when no ack is generated, and the 999 IK list otherwise (e.g.
    ``"8"``). pyx12's own error name stands in where that list has no code for it;
    ``message`` is synthesized from the code and the locators below;
    ``element_position`` / ``line`` are numbers; ``loop`` is the *schema* name of the map node the
    walk was at, which for a segment that matched no node is the last node it did match;
    ``element_name`` is the *schema* data-element label (e.g. ``"Transaction Set Creation Date"``).

    ``segment_id`` comes from the input, so it is kept only when it has an X12 segment id's shape (a
    capital, then one or two capitals or digits) and a map in pyx12's bundled index defines it, and
    is ``None`` otherwise (BACKLOG #5370). The set is the union of those maps, so a sender value equal
    to any id in it, for example ``LIN`` or ``PAT``, standing where the id goes is still kept, in
    ``segment_id`` and in ``message``, even in a transaction whose own map does not define that id.
    A terminator inside a name can put the name's tail there: ``O~LE`` keeps ``LE``, with ``loop``
    naming the segment the name was in."""

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
    flattened violation list of structural locators (empty when valid). ``ack`` is the generated
    997/999 Functional Acknowledgment, complete to its closing IEA, or ``None`` when pyx12 emitted
    none (e.g. for an already-FA transaction) or its ack writer failed before the closing IEA. A
    fragment such a writer left is dropped, with a WARNING; a writer that failed before writing
    anything leaves no fragment and no WARNING. ``ack_transaction`` names which
    (``"997"``/``"999"``), ``None`` with no ack. A complete ack echoes sender values unescaped, so
    it is not thereby well-formed.

    ``ack`` is left out of the repr because those echoed values can be PHI, for example a date of
    birth in AK404, and logging a result would otherwise write them (BACKLOG #5370)."""

    valid: bool
    errors: tuple[X12SegmentError, ...] = ()
    ack: str | None = field(default=None, repr=False)
    ack_transaction: str | None = None


_log = logging.getLogger(__name__)

#: The one handler the ``pyx12`` logger tree ends at. A single module-level instance, because
#: ``Logger.addHandler`` skips a handler already attached, under logging's own lock.
_PYX12_SINK = logging.NullHandler()
#: Above CRITICAL, so a logger at this level builds no record at all.
_MUTED = logging.CRITICAL + 1


def _mute_pyx12_logger() -> None:
    """Mute the whole ``pyx12`` logger tree, and never unmute it (BACKLOG #1603).

    pyx12 logs each violation at ERROR from child loggers such as ``pyx12.error_handler``. The
    record embeds the *raw* error string, with the offending data value (potential PHI), under
    pyx12 4.0.1, and under 4.1.0 when ``log_data_values`` is on, which a pyx12 config file can set.
    We build our own errors from pyx12's structured JSON instead, so nothing pyx12 logs is wanted
    anywhere.

    **No restore step, on purpose.** The old context manager raised the level for one pass and put
    the previous level back afterwards. Two overlapping passes on two threads would interleave: the
    first to finish would unmute the logger while the second was still logging. Passes can overlap:
    without a subprocess sandbox, the transform workers of two inbound connections run their
    Handlers on ``asyncio.to_thread`` threads, and a Handler calls :func:`validate` synchronously
    there. Every call writes the same muted state, so concurrent calls cannot disagree. Calling it
    on every pass, not once at import, also re-mutes a tree that a later logging reconfiguration
    has reset.

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

#: Used with ``fullmatch``, since ``$`` would also accept a trailing newline.
_SEGMENT_ID = re.compile(r"[A-Z][A-Z0-9]{1,2}")


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


def _structural_segment_id(seg: dict[str, Any]) -> str | None:
    """pyx12's ``seg_id`` when it has an X12 segment id's shape and a map in pyx12's bundled index
    defines it, otherwise ``None``.

    pyx12 takes everything before the first element separator as the id, so a wrongly delimited
    segment (``NM1|IL|1|DOE|ROBERT``) puts the sender's whole segment there, and a terminator inside
    a name (``NM1*IL*1*O~LEE*A*B~``) puts the name's tail there, in an id's shape. The error code
    cannot tell those apart: pyx12 emits code 1 for sender text and for a real id in the wrong place.
    The map check drops ``LEE``; :class:`X12SegmentError` states what it cannot drop.
    The shape is checked first, so text without it never makes this read the maps."""
    seg_id = seg.get("seg_id")
    if (
        isinstance(seg_id, str)
        and _SEGMENT_ID.fullmatch(seg_id)
        and seg_id in load_x12_map_segment_ids()
    ):
        return seg_id
    return None


def _segment_error(code: str, seg: dict[str, Any], err: dict[str, Any]) -> X12SegmentError:
    """A :class:`X12SegmentError` from a pyx12 segment-level error dict. It drops ``err_str`` /
    ``err_val``, which can embed the input value."""
    seg_id = _structural_segment_id(seg)
    return X12SegmentError(
        code=code,
        message=f"segment {seg_id or '?'}: error {code}",
        segment_id=seg_id,
        line=seg.get("cur_line"),
        loop=seg.get("name"),
    )


def _element_error(code: str, seg: dict[str, Any], ele: dict[str, Any]) -> X12SegmentError:
    """A :class:`X12SegmentError` from a pyx12 element-level error dict. ``name`` is the data-element
    *type* label (schema), not the value; ``err_str``/``err_val`` are dropped."""
    seg_id = _structural_segment_id(seg)
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
    flattening every recorded error into an :class:`X12SegmentError`. ``prefer_5010`` is False
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


def _walk_refusal(failure: str, *, install_fault: bool, no_map: bool) -> Exception:
    """The exception for a walk, or its params, that raised, holding only the class name. An install
    fault is a :class:`RuntimeError`, which a Handler's ``except ValueError`` does not catch. Every
    other failure is an :class:`X12ValidationError`, which says what pyx12 could not do and does not
    claim the interchange is bad: it can conform to a guide pyx12 does not bundle. Called outside
    the ``except`` block, so a logging fault here cannot chain the pyx12 exception."""
    if install_fault:
        return RuntimeError(
            "strict X12 validation could not run: pyx12's maps, modules or config could not be "
            f"loaded ({failure}); check pyx12's config file or reinstall the optional 'x12' "
            "extra: pip install 'messagefoundry[x12]'"
        )
    _note_walk_refusal(failure, no_map=no_map)
    reason = (
        "pyx12 has no map that selects this interchange, which may follow a guide it does not "
        "bundle"
        if no_map
        else "pyx12 stopped partway through this interchange"
    )
    return X12ValidationError(f"strict X12 validation could not run: {reason} ({failure})")


#: How often one exception class's refusal line is written. A sender chooses how often a refusal
#: runs, so the log is bounded the way :class:`~messagefoundry.transports.admission.RefusalLog`
#: bounds a listener's, which ``parsing`` cannot import.
_WALK_REFUSAL_LOG_SECONDS = 60.0
_WALK_REFUSAL_LOCK = threading.Lock()
# Keyed by exception class name and the no-map flag, a set pyx12's code fixes and no input can grow.
_walk_refusal_counts: Counter[tuple[str, bool]] = Counter()
_walk_refusal_logged_at: dict[tuple[str, bool], float] = {}


def _note_walk_refusal(failure: str, *, no_map: bool) -> None:
    """Count one refused walk, and log its class at WARNING at most once per
    :data:`_WALK_REFUSAL_LOG_SECONDS` per key, so a flood of one kind cannot hide another. No-map
    refusals have their own key because a sender can raise them at will with the ``EngineError``
    that a damaged map also raises. The line holds the class name and the running count, never the
    exception's message, arguments or chain, which can quote the interchange."""
    key = (failure, no_map)
    now = time.monotonic()
    with _WALK_REFUSAL_LOCK:
        _walk_refusal_counts[key] += 1
        count = _walk_refusal_counts[key]
        logged_at = _walk_refusal_logged_at.get(key)
        if logged_at is not None and now - logged_at < _WALK_REFUSAL_LOG_SECONDS:
            return
        _walk_refusal_logged_at[key] = now
    _log.warning(
        "strict X12 validation refused an interchange pyx12 has no map for (%s, %d in all since "
        "start, logged at most once every %gs)"
        if no_map
        else "strict X12 validation refused an interchange after pyx12 raised %s (%d in all since "
        "start, logged at most once every %gs per class); a run of one class can mean a damaged "
        "pyx12 install",
        failure,
        count,
        _WALK_REFUSAL_LOG_SECONDS,
    )


def validate(raw: str | bytes) -> X12ValidationResult:
    """Strictly validate an X12 interchange against pyx12's bundled implementation-guide maps.

    ``raw`` is the interchange text (bytes are decoded UTF-8/replace, matching
    :meth:`X12Message.parse`). Returns an :class:`X12ValidationResult` carrying the conformance verdict,
    the structural error list, and the generated 997/999 acknowledgment.

    Raises :class:`~messagefoundry.parsing.x12.errors.X12ValidationError` when pyx12 could not finish
    a pass over this interchange: at least when the bytes are not a parseable X12 data file, when
    pyx12 has no map that selects it, which a conformant interchange under a guide pyx12 does not
    bundle also meets, and when pyx12 raises partway through a walk, as a non-numeric GE01 makes it
    do. It chains no pyx12 exception. A pass that finishes with violations is returned as data
    (``valid=False``), not raised, so a Handler can still emit the negative ack.

    Raises :class:`RuntimeError`, a deploy/config error distinct from the ``ValueError``-rooted data
    errors, if the ``[x12]`` extra is absent or too old, if pyx12's params cannot be built, or if
    the walk raises a type :func:`~messagefoundry.parsing.x12._deps.is_x12_install_fault` names. The
    last two keep only the exception's class name and chain nothing. The first chains its
    ``ImportError``, which is raised before any interchange is read.

    **A damaged install does not always reach that path**: :class:`X12ValidationError` says when it
    does not, and :func:`_note_walk_refusal` what an operator then sees."""
    if isinstance(raw, (bytes, bytearray)):  # noqa: SIM108
        text = bytes(raw).decode("utf-8", "replace")
    else:
        text = raw

    x12n_document, make_params = load_x12_validator()
    resolve = load_x12_code_resolver()  # before the walk, so a pyx12 older than 4.0.1 fails first
    fd_ack = _AckBuffer()
    fd_json = io.StringIO()

    _mute_pyx12_logger()
    params_failure: str | None = None
    try:
        params = make_params()
    except Exception as exc:  # it reads pyx12's config and no sender data, so never a refusal
        params_failure = type(exc).__name__
    if params_failure is not None:  # raised out here so that nothing is chained
        raise _walk_refusal(params_failure, install_fault=True, no_map=False)

    walk_failure: str | None = None
    install_fault = no_map = False
    try:
        valid = bool(x12n_document(params, io.StringIO(text), fd_ack, None, None, fd_json))
    except Exception as exc:  # pyx12 raises bare Exception/EngineError on unwalkable input
        walk_failure = type(exc).__name__
        install_fault = is_x12_install_fault(exc)
        # By name, because an import here could raise and chain this exception. The text is compared
        # with pyx12's own fixed prefix and not kept.
        no_map = walk_failure == "EngineError" and str(exc).startswith("Map not found")
    # Raised out here, because pyx12's messages quote the interchange (a whole ISA, GS08, GE01):
    # `from exc` puts that on __cause__, and `from None` still leaves it on __context__ (BACKLOG
    # #5370, the pattern of json_loads_or_refusal, #2085). Only the class name is kept.
    if walk_failure is not None:
        raise _walk_refusal(walk_failure, install_fault=install_fault, no_map=no_map)

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
    version = _last_group_version(report)
    ack_for_version = _ACK_FOR_VERSION.get(version[:6])
    # A writer that raises partway is caught and logged by pyx12 (muted here), leaving a fragment;
    # only an ack whose last write was its closing IEA is returned and labelled.
    complete = fd_ack.complete()
    ack = ack_text if ack_text and complete else None
    ack_transaction = ack_for_version if ack else None
    if ack_text and not complete:
        _log.warning("pyx12's ack writer stopped before the closing IEA; no ack is returned")
    prefer_5010 = ack_for_version != "997"
    errors = tuple(_flatten_errors(report, resolve, prefer_5010=prefer_5010))
    return X12ValidationResult(
        valid=valid and not errors,
        errors=errors,
        ack=ack,
        ack_transaction=ack_transaction,
    )
