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
rather than patching hl7apy: see :data:`_LAST_HL7APY_WITH_CHOICE_BUG`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import metadata
from typing import Any

from messagefoundry.parsing.peek import (
    DEFAULT_MAX_MESSAGE_BYTES,
    DEFAULT_MAX_SEGMENTS,
    HL7PeekError,
    enforce_size_limits,
    normalize,
)

__all__ = ["ValidationResult", "validate"]

# hl7apy's structure tables are nested tuples, ``(kind, children, ...)``. Each child entry is a
# list, ``[name, reference, (min, max), "SEG" | "GRP"]``, and ``kind`` is ``"sequence"`` or
# ``"choice"``. Typed loosely because hl7apy ships no types.
_Reference = tuple[Any, ...]

# The last hl7apy release known to validate a ``choice`` group as a ``sequence``: upstream
# crs4/hl7apy issue 151, fixed by PR 152, which was open and unmerged on 2026-09-30. The bug
# makes every alternative of a choice required, so strict validation would reject any ORM^O01
# or ORR^O02 that carries an order detail (ORC then OBR, say), and any other structure with a
# choice group, in every HL7 version hl7apy ships from 2.2 on.
_LAST_HL7APY_WITH_CHOICE_BUG = (1, 3, 5)


@lru_cache(maxsize=1)
def _choice_fix_needed() -> bool:
    """True while the installed hl7apy is at or below the last release known to have the bug.

    The guard switches the shim off on any newer release. ``tests/test_validate_choice_groups.py``
    checks that choice against hl7apy's own behaviour, so it goes red if a newer release still
    has the bug, or if the shim outlives the upstream fix.
    """
    try:
        installed = metadata.version("hl7apy")
    except metadata.PackageNotFoundError:
        return False
    parts = tuple(int(p) for p in re.findall(r"\d+", installed)[:3])
    return parts <= _LAST_HL7APY_WITH_CHOICE_BUG


def _as_sequence(ref: _Reference) -> _Reference:
    """Copy ``ref`` with every choice group below it turned into a sequence of optional parts.

    hl7apy then still checks each alternative's upper bound, its content and every other
    group, and :func:`_choice_errors` adds the "exactly one alternative" rule it cannot express.
    Only group entries are rewritten; segment references are shared, not copied.
    """
    is_choice = ref[0] == "choice"
    children = []
    for name, sub, (low, high), marker in ref[1]:
        if marker == "GRP":
            sub = _as_sequence(sub)
        children.append([name, sub, (0, high) if is_choice else (low, high), marker])
    return ("sequence", tuple(children), *ref[2:])


@lru_cache(maxsize=512)
def _reference_without_choices(name: str, classname: str, hl7_version: str) -> _Reference:
    from hl7apy import load_reference

    ref: _Reference = load_reference(name, classname, hl7_version)
    return _as_sequence(ref)


def _occurrences(element: Any, name: str) -> list[Any]:
    from hl7apy.exceptions import HL7apyException

    try:
        return list(element.children.get(name))
    except HL7apyException:
        return []  # hl7apy's validator skips a name its tables cannot resolve; so do we


def _choice_errors(element: Any, ref: _Reference, errors: list[str]) -> None:
    """Walk the groups of ``element`` and report each choice group without exactly one part.

    Mirrors the rule of the upstream fix (PR 152) and its error text, so the message an operator
    sees does not change when the shim is deleted.
    """
    for name, sub, _cardinality, marker in ref[1]:
        if marker != "GRP":
            continue
        for group in _occurrences(element, name):
            if sub[0] == "choice":
                # (name, minimum, count) for each alternative the message carries
                chosen = [
                    (alt[0], alt[2][0], count)
                    for alt in sub[1]
                    if (count := len(_occurrences(group, alt[0]))) > 0
                ]
                if not chosen:
                    errors.append(
                        f"Missing required child for choice group {group.name} "
                        f"(exactly one of {[alt[0] for alt in sub[1]]} is required)"
                    )
                elif len(chosen) > 1:
                    errors.append(
                        f"Only one child allowed for choice group {group.name}: "
                        f"found {[c[0] for c in chosen]}"
                    )
                elif chosen[0][2] < chosen[0][1]:
                    errors.append(f"Missing required child {group.name}.{chosen[0][0]}")
            _choice_errors(group, sub, errors)


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
    from hl7apy import load_reference
    from hl7apy.consts import VALIDATION_LEVEL
    from hl7apy.exceptions import HL7apyException
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

    reference: _Reference | None = None
    if _choice_fix_needed():
        try:
            reference = _reference_without_choices(message.name, message.classname, version)
        except Exception:
            # An unknown structure (ChildNotFound), or a table shape the rewrite does not know:
            # validate as hl7apy does unaided. The guard test over every shipped table keeps
            # the second case from happening silently.
            reference = None

    try:
        Validator.validate(message, reference=reference)
    except HL7apyException as exc:
        errors.append(str(exc))
    except Exception as exc:  # defensive
        errors.append(str(exc))

    if reference is not None:
        try:
            _choice_errors(
                message, load_reference(message.name, message.classname, version), errors
            )
        except Exception as exc:  # defensive, as above
            errors.append(str(exc))

    return ValidationResult(ok=not errors, version=version, errors=errors)
