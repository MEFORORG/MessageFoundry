# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Strict, version-aware HL7 v2 validation — the opt-in tier.

Built on ``hl7apy``, which knows the official HL7 message structures per version. This tier
checks **structure, cardinality and required fields**: a supported HL7 version, a known
message structure for the trigger, a required segment present and a non-repeating one not
duplicated, a required field (PID-3, PV1-2) present, and no field or component past the end
of its segment's or datatype's definition. The wording in
:class:`~messagefoundry.config.models.Validation` is the single statement: *structural*,
not *profile*.

It does **not** check field *content*. A malformed date in PID-7, a 300-character PID-3 and
a PID-8 value outside HL7 table 0001 all validate ``ok=True``. The cause is ours, not a
limit of ``hl7apy``: :func:`validate` parses at hl7apy's ``TOLERANT`` level, which skips
datatype and length checks. Its ``STRICT`` level would reject the date and the length (not
the table value), and it would also change what every strict inbound accepts, so it is not
a doc-sized switch. ``tests/test_validate_scope.py`` pins both halves, so a change to
either is noticed rather than assumed. Field-content checks belong in a Handler, via
:mod:`~messagefoundry.parsing.consistency`.

hl7apy's grouping parse silently drops a line it cannot place in the structure, and validates only
the tree it built, while the tolerant parser keeps and forwards that line. So :func:`validate`
compares the tree with the tolerant parser's segments and refuses a message carrying a segment
hl7apy dropped: an unknown one, a known one the structure has no place for, or a line that is not
a segment at all (BACKLOG #5920), and a message type hl7apy has no structure for, since then
nothing was validated. A **Z-segment** ("Z" plus exactly two letters or digits, then a field
separator) is a site extension HL7 leaves undefined: it is left out of the text hl7apy parses, so
it never breaks hl7apy's grouping, and listed in :attr:`ValidationResult.unvalidated_segments`.
A refusal names at most a three-character segment ID the message's HL7 version defines, and the
segment's 1-based position counting as the tolerant parser does (empty lines skipped), never the
line's text: ``segment ORC at line N ...``, ``unknown segment at line N`` or ``unrecognised line
N``. Where the structure has HL7's "any HL7 segment" slot, which hl7apy's tables spell
``ANYHL7SEGMENT`` and its grouping never fills (MFN_M01 and QVR_Q17 among others), a dropped
segment whose ID the message's version defines is not refused, and passes unvalidated; an ID the
version does not define is still refused. The exemption is per structure, not per slot: it does
not count against the slot's cardinality or position. It holds only where MSH-9.1 names the
structure's own message code, so a structure borrowed through MSH-9.3 (``ADT^A01^MFN_M01``) gets
none. Segment order is not checked as such:
hl7apy keeps each segment where the message has it, so an out-of-order message may pass.

It is slower and far stricter than :mod:`~messagefoundry.parsing.peek`, so it runs only when
a channel sets ``validation.strict = true`` and is kept off the routing hot path.

``hl7apy`` raises on the *first* problem it finds, which is exactly what a strict channel
needs: one conformance error is enough to NACK. We surface that single message rather
than writing a full multi-error report to disk — a report file of a PHI message is a
data-leak we don't want by default. (Full reporting can become an explicit, opt-in,
redaction-aware feature later.)

A ``choice`` group (the order detail of ORM^O01, for one) means "exactly one of these". hl7apy
1.3.5 checks it as "all of these", so this module carries the upstream fix at its own boundary
rather than patching hl7apy: see :func:`_choice_fix_needed`.
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass
from functools import cache
from typing import Any

from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7MessageTooLarge,
    HL7PeekError,
    drop_blank_segments,
    enforce_size_limits,
    normalize,
)

__all__ = ["ValidationResult", "is_choice_group", "validate", "warm_validation"]

logger = logging.getLogger(__name__)

# hl7apy's structure tables are nested tuples, ``(kind, children, ...)``. Each child entry is a
# list, ``[name, reference, (min, max), "SEG" | "GRP"]``, and ``kind`` is ``"sequence"`` or
# ``"choice"``. Typed loosely because hl7apy ships no types.
_Reference = tuple[Any, ...]

# hl7apy 1.3.5 validates a ``choice`` group as a ``sequence`` (upstream crs4/hl7apy issue 151).
# That makes every alternative of a choice required, so strict validation would reject any
# ORM^O01 or ORR^O02 carrying an order detail (ORC then OBR, say), and any other structure with a
# choice group, in every HL7 version hl7apy ships from 2.2 on. The first probe is such a message,
# valid and synthetic; the second puts two alternatives in one choice group, so a conformant
# validator must reject it. The fix, PR 152, merged into hl7apy's ``develop`` branch on
# 2026-10-26. On that date no release carried it (PyPI's latest was 1.3.5, which the lock pins),
# so the probes below keep the shim on.
_CHOICE_PROBE = (
    "MSH|^~\\&|SND|SND|RCV|RCV|20260101120000||ORM^O01|PROBE|P|2.5.1\r"
    "PID|1||1^^^HOSP^MR||DOE^JOHN\r"
    "ORC|NW|ORD1\r"
    "OBR|1|ORD1||PANEL^Panel"
)
_TWO_ALTERNATIVES_PROBE = _CHOICE_PROBE + "\rRXO|RX1^Drug|1||MG"

# Groups that hl7apy's tables label ``choice`` although HL7 defines them as sequences. Each is a
# named group of parts that go together: a query acknowledgment (QAK then QPD), a query (QPD then
# RCP), an invoice (IVC with optional PYE, CTD and more), a payment header (PMT then PYE), a
# device record (SDD then optional SCDs). An "exactly one of" rule would reject every valid
# message of these structures, and unaided hl7apy already validates them correctly as sequences,
# so the shim leaves them alone. PR 152 as merged relabels all sixteen as sequences in hl7apy's
# own tables; its first draft applied the rule to them too.
_SEQUENCES_LABELLED_CHOICE = frozenset(
    {
        "EHC_E01_INVOICE_INFORMATION",
        "EHC_E01_INVOICE_INFORMATION_SUBMIT",
        "EHC_E02_INVOICE_INFORMATION",
        "EHC_E02_INVOICE_INFORMATION_CANCEL",
        "EHC_E04_REASSESSMENT_REQUEST_INFO",
        "EHC_E15_PAYMENT_REMITTANCE_HEADER_INFO",
        "EHC_E20_AUTHORIZATION_REQUEST",
        "EHC_E21_AUTHORIZATION_REQUEST",
        "EHC_E24_AUTHORIZATION_RESPONSE_INFO",
        "QBP_E03_QUERY_INFORMATION",
        "QBP_E22_QUERY",
        "RSP_E03_QUERY_ACK",
        "RSP_E03_QUERY_ACK_IPR",
        "RSP_E22_QUERY_ACK",
        "SDR_S31_ANTI_MICROBIAL_DEVICE_DATA",
        "SDR_S32_ANTI_MICROBIAL_DEVICE_CYCLE_DATA",
    }
)
# A valid RSP^E22: RSP_E22_QUERY_ACK carries both QAK and QPD, as HL7 requires.
_LABELLED_CHOICE_PROBE = (
    "MSH|^~\\&|SND|SND|RCV|RCV|20260101120000||RSP^E22^RSP_E22|PROBE|P|2.6\r"
    "MSA|AA|MSG000\r"
    "QAK|Q1|OK\r"
    "QPD|E22^Auth^HL70471|Q1"
)


@cache
def _choice_fix_needed() -> bool:
    """True unless the installed hl7apy, unaided, gets all three choice probes right.

    Asked of hl7apy's behaviour rather than its version number, once per process, so the shim
    switches itself off on the first release that validates choice groups correctly, and stays
    on under an unpinned install of a newer release that does not. It also stays on for a
    release that accepts the valid probe only by no longer checking choice groups at all, and
    for one that ships PR 152's first draft and so rejects the labelled-choice probe.
    ``tests/test_validate_choice_groups.py`` goes red on a fixed release, so the shim gets deleted.
    Keep :func:`is_choice_group` and ``_SEQUENCES_LABELLED_CHOICE`` when it is: the generator
    uses them.
    """
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.exceptions import HL7apyException
    from hl7apy.parser import parse_message
    from hl7apy.validation import Validator

    def accepted(raw: str) -> bool:
        message = parse_message(raw, find_groups=True, validation_level=VALIDATION_LEVEL.TOLERANT)
        try:
            Validator.validate(message)
        except HL7apyException:
            return False
        return True

    try:
        correct = (
            accepted(_CHOICE_PROBE)
            and not accepted(_TWO_ALTERNATIVES_PROBE)
            and accepted(_LABELLED_CHOICE_PROBE)
        )
        return not correct
    except Exception:
        # The shim is correct whatever hl7apy does with a choice, so a probe that cannot run
        # leaves it on rather than letting a strict inbound fall back to the bug.
        logger.warning(
            "hl7apy choice-group probe failed; keeping the issue 151 shim on", exc_info=True
        )
        return True


# Structures whose table the rewrite could not read, so each is logged once, not per message.
_rewrite_failures: set[tuple[str, str | None]] = set()


def is_choice_group(name: str, ref: _Reference) -> bool:
    """True if hl7apy table entry ``ref`` for group ``name`` is a real "exactly one of" choice.

    The synthetic-message generator uses this too, so it emits one alternative where strict
    validation wants one. This predicate and ``_SEQUENCES_LABELLED_CHOICE`` describe hl7apy's
    tables, not issue 151, so they outlive the shim: deleting the shim must keep them.
    """
    return ref[0] == "choice" and name not in _SEQUENCES_LABELLED_CHOICE


def _as_sequence(ref: _Reference, *, choice: bool = False) -> _Reference:
    """Copy ``ref`` with every choice group below it turned into a sequence of optional parts.

    hl7apy then still checks each alternative's upper bound, its content and every other
    group, and :func:`_choice_errors` adds the "exactly one alternative" rule it cannot express.
    Only group entries are rewritten; segment references are shared, not copied.
    """
    children = []
    for name, sub, (low, high), marker in ref[1]:
        if marker == "GRP":
            sub = _as_sequence(sub, choice=is_choice_group(name, sub))
        children.append([name, sub, (0, high) if choice else (low, high), marker])
    return ("sequence", tuple(children), *ref[2:])


# Unbounded is safe: the key space is hl7apy's shipped tables, since an unknown name raises and
# a raise is not cached.
@cache
def _references(name: str, classname: str, hl7_version: str) -> tuple[_Reference, _Reference]:
    """The structure's hl7apy table, and the same table with its choice groups rewritten."""
    from hl7apy import load_reference

    ref: _Reference = load_reference(name, classname, hl7_version)
    return ref, _as_sequence(ref)


def _tolerant_parse(norm: str) -> Any:
    """hl7apy's parse of ``norm`` as :func:`validate` runs it, shared with :func:`warm_validation`
    so the warm-up cannot drift from the parse it warms. Raises what ``parse_message`` raises.
    Each caller imports ``hl7apy`` itself first, outside its own ``except``."""
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.parser import parse_message

    # TOLERANT, stated rather than inherited: it is hl7apy's default, but that default is
    # process-wide and settable, and the scope in this module's docstring depends on it.
    return parse_message(norm, find_groups=True, validation_level=VALIDATION_LEVEL.TOLERANT)


def _occurrences(element: Any, name: str) -> list[Any]:
    from hl7apy.exceptions import HL7apyException

    try:
        return list(element.children.get(name))
    except HL7apyException:
        return []  # hl7apy's validator skips a name its tables cannot resolve; so do we


def _choice_error(group: Any, ref: _Reference) -> str | None:
    """The error for ``group`` unless exactly one of its alternatives is present.

    Uses the error text of the upstream fix (PR 152). hl7apy checks the chosen alternative's
    upper bound through the rewritten reference; no shipped alternative has a lower bound above
    one, so a present alternative always meets it.
    """
    alternatives = [alt[0] for alt in ref[1]]
    present = [name for name in alternatives if _occurrences(group, name)]
    if not present:
        return (
            f"Missing required child for choice group {group.name} "
            f"(exactly one of {alternatives} is required)"
        )
    if len(present) > 1:
        return f"Only one child allowed for choice group {group.name}: found {present}"
    return None


def _first_choice_error(element: Any, ref: _Reference) -> str | None:
    """Walk the groups of ``element`` in order and return the first choice-group error."""
    for name, sub, _cardinality, marker in ref[1]:
        if marker != "GRP":
            continue
        for group in _occurrences(element, name):
            error = _choice_error(group, sub) if is_choice_group(name, sub) else None
            if error is None:
                error = _first_choice_error(group, sub)
            if error is not None:
                return error
    return None


# A segment ID as HL7 v2 spells one; a Z-segment is such an ID starting with "Z".
_SEGMENT_ID = re.compile(r"[A-Z][A-Z0-9]{2}")


def _segment_names(element: Any) -> Counter[str]:
    """How many segments of each name ``element``'s parsed tree holds, at any group depth."""
    from hl7apy.core import Segment

    counts: Counter[str] = Counter()
    for child in element.children:
        if isinstance(child, Segment):
            counts[child.name] += 1
        else:
            counts.update(_segment_names(child))
    return counts


@dataclass(frozen=True)
class _Lines:
    """``norm`` split as the tolerant parser splits it, with the Z-segments set apart.

    ``segments`` holds each other line's ID, as the tolerant parser files it, and its 1-based
    position; ``z_segments`` the same for each Z-segment; ``strict_text`` is the body hl7apy
    parses, the Z-segment lines left out so that one inside a group does not break hl7apy's
    grouping of the segments around it. The lines are whole and unmodified: this text is only
    validated, never forwarded."""

    segments: list[tuple[str, int]]
    z_segments: list[tuple[str, int]]
    strict_text: str


def _split_lines(norm: str) -> _Lines:
    # As _builtin_hl7.parse splits a body: empty lines dropped, the whole body stripped. Its ID is
    # the text before the first field separator, so ``PIDX|`` is PIDX, not hl7apy's PID.
    lines = drop_blank_segments(norm).strip().split("\r")
    field_sep = lines[0][3:4] or "|"
    segments: list[tuple[str, int]] = []
    z_segments: list[tuple[str, int]] = []
    kept_lines: list[str] = []
    for number, line in enumerate(lines, start=1):
        name = line.split(field_sep, 1)[0]
        # A Z-segment carries a field separator after its ID: a bare ``ZOE`` is likely a wrapped
        # name, so it is compared like any other line rather than tolerated.
        if number > 1 and line != name and name[:1] == "Z" and _SEGMENT_ID.fullmatch(name):
            z_segments.append((name, number))
        else:
            segments.append((name, number))
            kept_lines.append(line)
    return _Lines(segments, z_segments, "\r".join(kept_lines))


def _holds_any_segment(ref: _Reference) -> bool:
    return any(
        name == "ANYHL7SEGMENT" or (marker == "GRP" and _holds_any_segment(sub))
        for name, sub, _cardinality, marker in ref[1]
    )


# Cached over hl7apy's shipped tables, as _references is. It reads the table itself rather than
# through _references, so a failure of the issue 151 rewrite cannot reach this check.
@cache
def _has_any_segment_slot(name: str, classname: str, hl7_version: str) -> bool:
    """True if the structure has the "any HL7 segment" slot at any group depth (module docstring)."""
    from hl7apy import load_reference

    return _holds_any_segment(load_reference(name, classname, hl7_version))


def _exempts_defined_segments(message: Any) -> bool:
    """True if ``message``'s structure has the "any HL7 segment" slot and is its own.

    hl7apy takes the structure from MSH-9.3 when one is given, so ``ADT^A01^MFN_M01`` would
    borrow MFN_M01's slot for an ADT body. The exemption holds only where MSH-9.1 names the
    structure's own message code, which fails closed on a borrowed one."""
    code = message.msh.msh_9.msh_9_1.to_er7()
    return code == message.name.split("_", 1)[0] and _has_any_segment_slot(
        message.name, message.classname, message.version
    )


# Structures whose tree the dropped-segment check could not read, so each is logged once.
_compare_failures: set[tuple[str, str | None]] = set()


def _dropped_lines(lines: _Lines, message: Any) -> list[str]:
    """Refusals for the segments in ``lines`` that ``message``'s hl7apy tree lacks.

    Worded as the module docstring sets out. An ID is printed only when the message's own HL7
    version defines it: any other, such as ``KIM``, is likely a wrapped field, so it reads
    ``unknown segment``, the rule ``docs/PHI.md`` sets for the anonymization report. Which
    occurrence of a repeated ID was dropped is not knowable from the tree, so the later ones are
    named; the count per ID is exact. In a structure with an "any HL7 segment" slot, a defined ID
    is not refused, as the module docstring says.
    """
    import hl7apy

    kept = _segment_names(message)
    if not kept:
        # A message type hl7apy has no structure for (a site's ZZZ^Z01, say) builds an empty tree
        # that hl7apy's validator passes, so nothing at all was validated.
        return ["no segment could be validated: hl7apy has no structure for this message type"]
    defined = hl7apy.load_library(message.version).SEGMENTS
    refusals: list[str] = []
    for name, number in lines.segments:
        if kept[name] > 0:
            kept[name] -= 1
        elif _SEGMENT_ID.fullmatch(name) is None:
            refusals.append(f"unrecognised line {number}")
        elif name in defined:
            if not _exempts_defined_segments(message):
                refusals.append(
                    f"segment {name} at line {number} has no place in this message's structure"
                )
        else:
            refusals.append(f"unknown segment at line {number}")
    return refusals


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of strict validation. Truthy iff the message is conformant.

    ``oversize`` is True when the message failed :func:`validate`'s ``max_bytes`` cap, measured on
    the text that function itself normalizes, so a caller can answer a size refusal as one without
    re-deriving that measurement (BACKLOG #2105).

    ``unvalidated_segments`` lists the Z-segments strict validation left unchecked, each as its
    ``(segment ID, 1-based position)``; the module docstring has the rule. No engine surface
    shows it yet."""

    ok: bool
    version: str | None
    errors: list[str]
    oversize: bool = False
    unvalidated_segments: tuple[tuple[str, int], ...] = ()

    def __bool__(self) -> bool:
        return self.ok


# There is deliberately NO ``profile`` parameter here, and a new one must not be added until
# something reads it. One sat in this signature until 2026-09-06, typed ``object | None`` and
# documented as "reserved for a conformance-profile object (Phase 2+); passing one today is
# accepted but not yet enforced" -- accepted by every call and read by none. That is a
# control-shaped parameter that is not a control: a Handler author who passed a conformance
# profile would reasonably believe conformance was being checked, and nothing at runtime would
# have told them otherwise. ``object | None`` accepts anything, so strict mypy could not warn
# them either. Measured across the tree on 2026-09-06: ZERO call sites passed it, against a
# positive control of 13 sites passing the sibling ``expected_version=``, so deleting it broke
# no caller. The roadmap commitment is not lost -- a persisted message-definition model plus a
# conformance validator is BACKLOG #78, demand-gated -- and when that lands it should add a
# TYPED parameter rather than restore an untyped placeholder.
def validate(
    raw: str | bytes,
    *,
    expected_version: str | None = None,
    max_bytes: int | None = DEFAULT_MAX_MESSAGE_BYTES,
    max_segments: int | None = DEFAULT_MAX_SEGMENTS,
) -> ValidationResult:
    """Validate ``raw`` against the official structures for its (or ``expected_version``).

    ``expected_version`` cross-checks MSH-12: if the message declares a different version
    that is reported as an error (a feed sending the wrong version is a misconfiguration
    a strict channel should reject). ``max_bytes`` / ``max_segments`` reject an oversized
    message before the (slow) strict parse.

    Every engine caller leaves ``max_bytes`` at the engine default, deliberately, so it does NOT
    follow an inbound's ``max_message_bytes`` (BACKLOG #5078). That setting admits a larger body
    to the tolerant parse, and this function then refuses one over 16 MiB as ``oversize``: this is
    the whole-body ``hl7apy`` parse the cap exists to bound, and it runs on a worker thread the
    listener's timeout cannot stop. ``docs/HL7-VALIDATION.md`` says so for operators.
    """
    # Imported here, outside any except, so a broken install raises rather than reading as a
    # parse refusal; _tolerant_parse's own imports are then cache hits.
    from hl7apy.consts import VALIDATION_LEVEL  # noqa: F401
    from hl7apy.exceptions import ChildNotFound, HL7apyException
    from hl7apy.parser import parse_message  # noqa: F401
    from hl7apy.validation import Validator

    norm = normalize(raw).strip("\r")
    if not norm:
        return ValidationResult(False, expected_version, ["empty message"])

    # Bound resource use before the (slow) strict parse — the MLLP frame cap doesn't protect
    # a complete-but-huge message, and hl7apy's structure builder is the heavier amplifier.
    try:
        enforce_size_limits(norm, max_bytes=max_bytes, max_segments=max_segments)
    except HL7PeekError as exc:
        return ValidationResult(
            False, expected_version, [str(exc)], oversize=isinstance(exc, HL7MessageTooLarge)
        )

    lines = _split_lines(norm)
    try:
        message = _tolerant_parse(lines.strict_text)
    except HL7apyException as exc:
        return ValidationResult(False, expected_version, [f"parse error: {exc}"])
    except Exception as exc:  # defensive: never let validation crash the pipeline
        return ValidationResult(False, expected_version, [f"parse error: {exc}"])

    version = getattr(message, "version", None)
    errors: list[str] = []

    if expected_version and version and expected_version != version:
        errors.append(f"version mismatch: message is {version}, channel expects {expected_version}")

    references: tuple[_Reference, _Reference] | None = None
    if _choice_fix_needed():
        try:
            references = _references(message.name, message.classname, version)
        except ChildNotFound:
            pass  # an unknown structure: hl7apy reports it below, exactly as before
        except Exception:
            # A table shape the rewrite does not know. Validate as hl7apy does unaided, which
            # brings the false reject back for this structure, so say so rather than hide it.
            # The test over every shipped table keeps this from happening with hl7apy's own.
            # Once per structure: a raise is not cached, so this path repeats per message.
            if (message.name, version) not in _rewrite_failures:
                _rewrite_failures.add((message.name, version))
                logger.warning(
                    "issue 151 shim could not read hl7apy's table for %s v%s",
                    message.name,
                    version,
                    exc_info=True,
                )

    try:
        Validator.validate(message, reference=references[1] if references else None)
    except HL7apyException as exc:
        errors.append(str(exc))
    except Exception as exc:  # defensive
        errors.append(str(exc))
    else:
        # Only when hl7apy found nothing, and only the first, keeping the one-error contract.
        if references is not None:
            try:
                if (choice_error := _first_choice_error(message, references[0])) is not None:
                    errors.append(choice_error)
            except Exception as exc:  # defensive, as above
                errors.append(str(exc))

    # hl7apy validated only the tree it built, so a line it dropped while grouping went
    # unchecked, and the tolerant parser forwards it all the same.
    # Only when nothing else refused, keeping the one-error contract.
    if not errors:
        try:
            refusals = _dropped_lines(lines, message)
        except Exception as exc:  # defensive, and closed: an unread tree is not a validated one
            # Once per structure, as the shim's path above: a persistent fault repeats per message.
            key = (getattr(message, "name", ""), version)
            if key not in _compare_failures:
                _compare_failures.add(key)
                logger.warning(
                    "dropped-segment check could not compare the tree for %s v%s",
                    key[0],
                    version,
                    exc_info=True,
                )
            refusals = [
                f"could not compare the parsed tree with the message ({type(exc).__name__})"
            ]
        if refusals:
            more = len(refusals) - 1
            errors.append(refusals[0] + (f" (and {more} more)" if more else ""))

    return ValidationResult(
        ok=not errors,
        version=version,
        errors=errors,
        unvalidated_segments=tuple(lines.z_segments),
    )


# How much of a body the warm-up reads to find its MSH segment: far past any real MSH.
_WARM_HEAD_CHARS = 64 * 1024


def warm_validation(raw: str | bytes) -> None:
    """Pay, once, what a first :func:`validate` of ``raw`` would pay before it validates anything.

    That is the cold ``hl7apy`` import, the cached :func:`_choice_fix_needed` probe, hl7apy's
    library for the message's version and the structure's cached reference table, so a caller that
    times :func:`validate` measures the validate and not the process's first use of it (BACKLOG
    #5107). It parses the first segment of a bounded head of ``raw``, leading whitespace stripped
    as hl7apy strips it, which is enough to learn the structure and version, so neither the copy
    nor the parse grows with the body. A body it cannot read is left for the timed validate to
    refuse; a broken ``hl7apy`` install still raises, as :func:`validate` would.
    """
    # Imported here, outside any except, so a broken install raises rather than reading as a
    # parse refusal; _tolerant_parse's own imports are then cache hits.
    from hl7apy.consts import VALIDATION_LEVEL  # noqa: F401
    from hl7apy.parser import parse_message  # noqa: F401
    from hl7apy.validation import Validator  # noqa: F401 -- imported for its load time

    choice_fix = _choice_fix_needed()
    msh = normalize(raw[:_WARM_HEAD_CHARS]).lstrip().split("\r", 1)[0]
    try:
        message = _tolerant_parse(msh)
        if choice_fix:
            _references(message.name, message.classname, getattr(message, "version", None))
    except Exception as exc:
        # Broad on purpose: validate() itself turns any parse fault into a refusal, so a narrower
        # catch would make the warm-up crash a dry run that validate would answer. The class only:
        # an hl7apy error can quote the message.
        logger.debug("strict-validation warm-up skipped on %s", type(exc).__name__)
