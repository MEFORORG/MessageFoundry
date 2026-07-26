# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Spreadsheet formula-injection neutralization for the harness reports (CWE-1236 / ASVS 1.2.10).

A **deliberate mirror** of ``messagefoundry/spreadsheet.py``, not an import of it: the harness is a
separate process that reaches the engine only through the HTTP API client, and may import from the
engine only ``parsing/`` and the API's Pydantic models (CLAUDE.md §4/§10). Copying ~20 lines is the
cheaper price than widening that boundary for a report-formatting helper.

The copy is what previously drifted (three harness writers carried ``=+-@\\t\\r\\x00`` while the
engine carried ``=+-@\\t\\r\\n``, and the copies checked only ``value[:1]``, so ``"   =evil()"`` rode
through them). ``tests/test_csv_formula_consistency.py`` now asserts the two modules agree on the
trigger set *and* produce identical output over a shared vector list, so a re-divergence is a red
build rather than a finding.

See the engine module for the full rationale — including why NUL/TAB/CR/LF are triggers and why the
leading-run skip goes past C0 controls and zero-width characters, not just whitespace.
"""

from __future__ import annotations

import re
from typing import overload

__all__ = [
    "SPREADSHEET_FORMULA_TRIGGERS",
    "spreadsheet_safe",
    "spreadsheet_lead",
    "xlsx_cell_text",
]

#: Mirror of ``messagefoundry.spreadsheet.SPREADSHEET_FORMULA_TRIGGERS``.
SPREADSHEET_FORMULA_TRIGGERS = frozenset("=+-@\t\r\n\x00")

#: Mirror of ``messagefoundry.spreadsheet._LEADING_NOISE``.
_LEADING_NOISE = frozenset(
    "".join(chr(c) for c in range(0x20))  # C0 controls: NUL..US (str.lstrip strips none of these)
    + "\x7f"  # DEL
    + "﻿​‌‍⁠"  # BOM/ZWNBSP, ZWSP, ZWNJ, ZWJ, word joiner
)


def spreadsheet_lead(value: str) -> str:
    """The first character a spreadsheet importer would actually judge the cell on (``""`` if none)."""
    index = 0
    while index < len(value) and (value[index].isspace() or value[index] in _LEADING_NOISE):
        index += 1
    return value[index : index + 1]


@overload
def spreadsheet_safe(value: str) -> str: ...


@overload
def spreadsheet_safe(value: object) -> object: ...


def spreadsheet_safe(value: object) -> object:
    """Neutralize spreadsheet formula injection in one cell; anything else passes through unchanged."""
    if not isinstance(value, str) or not value:
        return value
    if value[0] in SPREADSHEET_FORMULA_TRIGGERS:
        return "'" + value
    if spreadsheet_lead(value) in SPREADSHEET_FORMULA_TRIGGERS:
        return "'" + value
    return value


# --- .xlsx (ASVS 1.2.10 covers "CSV **or other spreadsheet formats**") -------

#: Characters openpyxl refuses to store at all (``openpyxl.cell.cell.ILLEGAL_CHARACTERS_RE``): the C0
#: control range minus TAB/LF/CR. Assigning one raises ``IllegalCharacterError``, which derives
#: straight from ``Exception`` — so it escapes the acceptance CLI's ``(RuntimeError, OSError)`` handler
#: and kills the run with a traceback instead of the intended "xlsx write-back failed" + exit 2.
_XLSX_ILLEGAL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def xlsx_cell_text(value: str) -> str:
    """Prepare a free-text value for an ``.xlsx`` cell: storable, and inert when opened.

    Two distinct defects, both real and both measured against openpyxl 3.1.5:

    * **Live formula.** openpyxl infers a FORMULA cell (``<f>`` element, ``data_type == 'f'``) from
      any string starting with ``=``, so an ``=``-leading result detail executes when the workbook is
      opened. A leading apostrophe forces literal text. The XLSX threat scope is *narrower* than
      CSV's — ``+``/``-``/``@``/TAB-leading strings are stored as inline strings and are NOT re-parsed
      the way a CSV import re-parses them — so this deliberately neutralizes only ``=`` rather than
      applying the full CSV trigger set and mutating text that was never dangerous.
    * **Unstorable control characters.** Anything in :data:`_XLSX_ILLEGAL_RE` is dropped; the value
      could not be written at all otherwise.

    Pure and dependency-free on purpose: openpyxl is not a project dependency, so the regression test
    for this must not need it.
    """
    text = _XLSX_ILLEGAL_RE.sub("", value)
    return "'" + text if text.startswith("=") else text
