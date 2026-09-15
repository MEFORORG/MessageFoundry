# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Capture log records through the PRODUCTION filter chain (BACKLOG #1748).

``caplog`` reads records before any handler filter runs, so it cannot answer the question this helper
exists for: *what would actually reach the NSSM-captured log*. :class:`FilteredCapture` attaches the
same chain ``logging_setup._install_phi_filters`` puts on every shipped sink, then the same text
formatter, so a line it collects is the line an operator would read.

The chain is BUILT by ``_install_phi_filters`` rather than listed here, for the reason
``tests/test_logging.py`` records: a hand-listed chain silently ran a filter set no handler carried the
moment a fourth filter was installed.

Shared by the File and REMOTEFILE source tests rather than inlined in each. Two copies would be free
to drift, and a *weaker* copy is the failure that matters — an assertion that passes because it
examined less than it claimed.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager

from messagefoundry.logging_setup import _install_phi_filters, _make_formatter

#: File names shaped the way a partner names a drop: an MRN, a surname/forename pair, a birthdate, an
#: accession. **Synthetic — no real identifier appears here or in any test that imports this.** One
#: definition, shared by the redaction unit tests and both source tests, because a second copy is free
#: to be the weaker one.
IDENTIFIER_SHAPED_NAMES = (
    "MRN123456789_ADT.hl7",
    "DOE_JANE_19800505_ADT.hl7",
    "PID-100001-DOE-JANE.hl7",
)

#: Identifier shapes a partner's file name carries: a long digit run (an MRN, an accession, a bare
#: ``YYYYMMDD`` birthdate) or a pair of capitalised tokens joined by ``_``/``-`` (a surname/forename
#: pair). Deliberately NOT the redaction module's own patterns — those are what the item measured as
#: blind to a file name, so reusing them would ask the suspect to grade itself.
IDENTIFIER_SHAPE = re.compile(r"\d{5,}|[A-Z]{2,}[_-][A-Z]{2,}")
#: A well-formed :func:`~messagefoundry.redaction.safe_name` label: a 12-hex digest plus up to two
#: short alphanumeric extensions.
SAFE_NAME_LABEL = re.compile(r"\[name:[0-9a-f]{12}(?:\.[A-Za-z0-9]{1,8}){0,2}\]")


def strip_safe_labels(line: str) -> str:
    """``line`` with every well-formed :data:`SAFE_NAME_LABEL` removed.

    A digest is 12 random hex characters, so one in some runs of them contains five digits in a row and
    would trip :data:`IDENTIFIER_SHAPE` by luck. Removing only the *well-formed* label keeps the
    assertion sharp: a leaked cleartext name does not match that shape, so it survives the strip and is
    still scanned."""
    return SAFE_NAME_LABEL.sub("", line)


class FilteredCapture(logging.Handler):
    """A log sink carrying the production PHI-redaction filter chain and the production text
    formatter. What lands in :attr:`lines` is what a shipped sink would write."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.lines: list[str] = []
        _install_phi_filters(self)
        self.setFormatter(_make_formatter("text"))

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))

    @property
    def text(self) -> str:
        return "\n".join(self.lines)


@contextmanager
def filtered_sink(logger_name: str) -> Iterator[FilteredCapture]:
    """Attach a :class:`FilteredCapture` to ``logger_name`` for the duration of the block.

    ``propagate`` is left alone and the logger's own level is lowered to WARNING, so the records this
    sink sees are the ones the shipped code emits, through the shipped chain."""
    logger = logging.getLogger(logger_name)
    sink = FilteredCapture()
    previous = logger.level
    logger.setLevel(logging.WARNING)
    logger.addHandler(sink)
    try:
        yield sink
    finally:
        logger.removeHandler(sink)
        logger.setLevel(previous)
