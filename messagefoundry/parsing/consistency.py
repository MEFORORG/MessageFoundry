# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cross-field HL7 consistency checks for Routers/Handlers (WP-7b; ASVS 2.2.3/2.1.2/2.2.1).

Strict validation ([validate.py](validate.py), opt-in `validation.strict`) checks message
*structure* — segment cardinality, datatypes, table values, lengths — against the official HL7
schema. It does **not** check *business coherence across fields*: that a required identifier is
present, that a value is echoed consistently across segments, or that admit ≤ discharge. ASVS 2.2.3 /
2.1.2 place that "combined-item" consistency on the application — here, the Router/Handler.

This module is a small, **pure** (side-effect-free) toolkit of reusable checks a Handler composes.
Each primitive takes a parsed :class:`~messagefoundry.parsing.message.Message` plus field *paths*
(``"PID-3"``, ``"PV1-44.1"``) and returns a list of :class:`Violation`\\s — it **detects, it does not
decide**. The Handler chooses what to do with a non-empty result: ``return None`` to drop the message
(logged ``FILTERED``) or ``raise ConsistencyError(...)`` to send it to the error/dead-letter path
(logged ``ERROR``). Keeping the library pure preserves the at-least-once *re-run* invariant (a Handler
must be a pure function of the message — see CLAUDE.md §2).

**PHI-safety:** a :class:`Violation` records the **rule and the field path(s)**, never the field
*value*. So a Handler can log/aggregate violations, or let them ride the ``safe_exc()`` chokepoint
(WP-6c) into a stored disposition, without leaking PHI (a date violation reads "PID-7 is not a valid
HL7 date/time", never the offending value).

The primitives are **generic** (no HL7 version or message-type assumptions); compose them into
message-type-specific checks in your config (see ``samples/consistency`` for a worked ADT example).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime

from messagefoundry.parsing.message import Message

__all__ = [
    "Violation",
    "ConsistencyError",
    "required",
    "same_across",
    "valid_date",
    "dates_in_order",
    "matches",
    "check",
]


@dataclass(frozen=True)
class Violation:
    """A single failed consistency check. ``rule`` names the primitive; ``paths`` are the field
    path(s) involved. PHI-safe by construction — it never carries a field *value*."""

    rule: str
    paths: tuple[str, ...]

    @property
    def message(self) -> str:
        """A PHI-safe, human-readable description (rule + paths only, never values)."""
        where = ", ".join(self.paths)
        return {
            "required": f"{where} is required but missing/empty",
            "same_across": f"fields disagree (must match): {where}",
            "valid_date": f"{where} is not a valid HL7 date/time",
            "dates_in_order": f"dates out of order (must be non-decreasing): {where}",
            "matches": f"{where} does not match the required format",
        }.get(self.rule, f"{self.rule}: {where}")

    def __str__(self) -> str:
        return self.message


class ConsistencyError(Exception):
    """Raise from a Handler to route an inconsistent message to the error/dead-letter path. Its
    string form is PHI-safe (built from each :attr:`Violation.message`), so it is safe to log."""

    def __init__(self, violations: Iterable[Violation]) -> None:
        self.violations: list[Violation] = list(violations)
        super().__init__(
            "; ".join(v.message for v in self.violations) or "consistency check failed"
        )


def required(msg: Message, *paths: str) -> list[Violation]:
    """A :class:`Violation` for each path that is absent or empty (``msg.field(path) is None``)."""
    return [Violation("required", (p,)) for p in paths if msg.field(p) is None]


def same_across(msg: Message, *paths: str) -> list[Violation]:
    """One :class:`Violation` if the values at ``paths`` are not all identical — covering both
    differing values *and* present-vs-absent (``None`` is treated as a distinct value). Two or more
    paths required; all-absent is considered consistent (use :func:`required` to assert presence)."""
    if len(paths) < 2:
        return []
    values = {msg.field(p) for p in paths}
    return [Violation("same_across", tuple(paths))] if len(values) > 1 else []


def valid_date(msg: Message, path: str) -> list[Violation]:
    """A :class:`Violation` if the value at ``path`` is present but not a valid HL7 date/time. An
    **absent** value is not flagged (assert presence with :func:`required` if it's mandatory)."""
    value = msg.field(path)
    if value is None:
        return []
    return [] if _parse_hl7_dt(value) is not None else [Violation("valid_date", (path,))]


def dates_in_order(msg: Message, earlier: str, later: str) -> list[Violation]:
    """A :class:`Violation` if both dates are present and valid but ``earlier`` > ``later`` (e.g.
    admit after discharge). Skips the check when either is absent or unparseable — those are the
    concern of :func:`required` / :func:`valid_date`, kept separate so each violation is precise."""
    a, b = msg.field(earlier), msg.field(later)
    if a is None or b is None:
        return []
    da, db = _parse_hl7_dt(a), _parse_hl7_dt(b)
    if da is None or db is None:
        return []
    return [Violation("dates_in_order", (earlier, later))] if da > db else []


def matches(msg: Message, path: str, pattern: str) -> list[Violation]:
    """A :class:`Violation` if the value at ``path`` is present but does not **fully** match
    ``pattern`` (an anchored :func:`re.fullmatch`). An absent value is not flagged."""
    value = msg.field(path)
    if value is None:
        return []
    return [] if re.fullmatch(pattern, value) is not None else [Violation("matches", (path,))]


def check(*groups: Sequence[Violation]) -> list[Violation]:
    """Flatten the results of several checks into one list, for a single ``if violations:`` decision::

    violations = check(
        required(msg, "PID-3", "PID-5", "MSH-10"),
        dates_in_order(msg, "PV1-44", "PV1-45"),
    )
    """
    return [v for group in groups for v in group]


# HL7 TS/DTM is ``YYYY[MM[DD[HH[MM[SS[.S+]]]]]][+/-ZZZZ]`` — all digits, optional fractional second
# and timezone offset. We accept the common precisions and require a real calendar date; missing
# low-order parts default to their minimum so partial timestamps still compare for ordering.
_HL7_DT = re.compile(r"(?P<digits>\d{4,14})(?:\.\d+)?(?:[+-]\d{2,4})?$")


def _parse_hl7_dt(value: str) -> datetime | None:
    """Parse an HL7 date/time to a comparable ``datetime``; ``None`` if malformed or not a real date.
    Pure and timezone-naive: the optional ``+/-ZZZZ`` offset is ignored for ordering (a feed mixing
    offsets is rare; document it if it matters)."""
    m = _HL7_DT.fullmatch(value.strip())
    if m is None:
        return None
    digits = m.group("digits")
    if len(digits) % 2 != 0:  # valid precisions are 4/6/8/10/12/14 — odd lengths are malformed
        return None
    try:
        year = int(digits[0:4])
        month = int(digits[4:6]) if len(digits) >= 6 else 1
        day = int(digits[6:8]) if len(digits) >= 8 else 1
        hour = int(digits[8:10]) if len(digits) >= 10 else 0
        minute = int(digits[10:12]) if len(digits) >= 12 else 0
        second = int(digits[12:14]) if len(digits) >= 14 else 0
        return datetime(year, month, day, hour, minute, second)  # noqa: DTZ001 (naive by design)
    except ValueError:
        return None
