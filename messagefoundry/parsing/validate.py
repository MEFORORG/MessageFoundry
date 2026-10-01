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
from dataclasses import dataclass
from functools import cache
from typing import Any

from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7PeekError,
    enforce_size_limits,
    normalize,
)

__all__ = ["ValidationResult", "is_choice_group", "validate"]

logger = logging.getLogger(__name__)

# hl7apy's structure tables are nested tuples, ``(kind, children, ...)``. Each child entry is a
# list, ``[name, reference, (min, max), "SEG" | "GRP"]``, and ``kind`` is ``"sequence"`` or
# ``"choice"``. Typed loosely because hl7apy ships no types.
_Reference = tuple[Any, ...]

# hl7apy 1.3.5 validates a ``choice`` group as a ``sequence`` (upstream crs4/hl7apy issue 151;
# the fix, PR 152, was open and unmerged on 2026-09-30). That makes every alternative of a choice
# required, so strict validation would reject any ORM^O01 or ORR^O02 carrying an order detail
# (ORC then OBR, say), and any other structure with a choice group, in every HL7 version hl7apy
# ships from 2.2 on. The first probe is such a message, valid and synthetic; the second puts two
# alternatives in one choice group, so a conformant validator must reject it.
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
# so the shim leaves them alone. PR 152 as written would apply the rule to them too.
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
    for one that merges PR 152 as written and so rejects the labelled-choice probe.
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


@dataclass(frozen=True)
class ValidationResult:
    """Outcome of strict validation. Truthy iff the message is conformant."""

    ok: bool
    version: str | None
    errors: list[str]

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
    """
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.exceptions import ChildNotFound, HL7apyException
    from hl7apy.parser import parse_message
    from hl7apy.validation import Validator

    norm = normalize(raw).strip("\r")
    if not norm:
        return ValidationResult(False, expected_version, ["empty message"])

    # Bound resource use before the (slow) strict parse — the MLLP frame cap doesn't protect
    # a complete-but-huge message, and hl7apy's structure builder is the heavier amplifier.
    try:
        enforce_size_limits(norm, max_bytes=max_bytes, max_segments=max_segments)
    except HL7PeekError as exc:
        return ValidationResult(False, expected_version, [str(exc)])

    try:
        # TOLERANT, stated rather than inherited: it is hl7apy's default, but that default is
        # process-wide and settable, and the scope in this module's docstring depends on it.
        message = parse_message(norm, find_groups=True, validation_level=VALIDATION_LEVEL.TOLERANT)
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

    return ValidationResult(ok=not errors, version=version, errors=errors)
