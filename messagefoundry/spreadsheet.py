# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Spreadsheet formula-injection neutralization (CWE-1236 / ASVS 1.2.10) — the canonical rule.

Excel/Sheets/LibreOffice re-parse a CSV cell on import and *execute* it when it begins with ``=``,
``+``, ``-`` or ``@`` — a DDE/formula payload in a report a compliance officer opens. TAB/CR/LF and
NUL are in the trigger set too, because an importer may strip or ignore them and expose the ``=``
behind them; for the same reason the check looks past any run of leading characters an importer can
drop (whitespace, the C0 control range, the zero-width/BOM family), not just ``str.lstrip``'s
whitespace.

Every CSV/XLSX writer in the tree routes its free-text cells through **this** rule. The harness keeps
its own byte-identical mirror in ``harness/_spreadsheet.py`` (a test harness must not import engine
internals, CLAUDE.md §4/§10); ``tests/test_csv_formula_consistency.py`` is the gate that keeps the
two — and every writer that uses them — from drifting apart again.

Neutralization is a leading apostrophe, which a spreadsheet consumes to force literal text. It is
**not** loss-free for a consumer that re-parses the file as data: see
:func:`~messagefoundry.config.codeset_edit._spreadsheet_safe`'s round-trip caveat, the one writer
whose output is read back by the loader.
"""

from __future__ import annotations

from typing import overload

__all__ = ["SPREADSHEET_FORMULA_TRIGGERS", "spreadsheet_safe", "spreadsheet_lead"]

#: Leading characters that make a spreadsheet treat a cell as a formula (``= + - @``) or that can
#: smuggle one past an importer's leading trim (TAB / CR / LF / NUL). OWASP "CSV Injection".
SPREADSHEET_FORMULA_TRIGGERS = frozenset("=+-@\t\r\n\x00")

#: Characters an importer may drop or fold away *before* deciding whether a cell is a formula: the
#: whole C0 control range (which ``str.lstrip`` does NOT strip — NUL, SOH…US), DEL, and the
#: zero-width / BOM / non-breaking family. ``str.isspace`` covers the rest of Unicode whitespace.
_LEADING_NOISE = frozenset(
    "".join(chr(c) for c in range(0x20))  # C0 controls: NUL..US (str.lstrip strips none of these)
    + "\x7f"  # DEL
    + "﻿​‌‍⁠"  # BOM/ZWNBSP, ZWSP, ZWNJ, ZWJ, word joiner
)


def spreadsheet_lead(value: str) -> str:
    """The first character a spreadsheet importer would actually judge the cell on (``""`` if none).

    Skips every leading character an importer can drop — Unicode whitespace, C0 controls, DEL and the
    zero-width/BOM family — so ``"\\u200b   =cmd|'/c calc'!A1"`` leads on ``"="``, not ``"\\u200b"``.
    """
    index = 0
    while index < len(value) and (value[index].isspace() or value[index] in _LEADING_NOISE):
        index += 1
    return value[index : index + 1]


@overload
def spreadsheet_safe(value: str) -> str: ...


@overload
def spreadsheet_safe(value: object) -> object: ...


def spreadsheet_safe(value: object) -> object:
    """Neutralize spreadsheet formula injection in one cell; anything else passes through unchanged.

    A string whose **raw** first character, or whose first character after the importer-droppable run
    (:func:`spreadsheet_lead`), is in :data:`SPREADSHEET_FORMULA_TRIGGERS` gets a single leading
    apostrophe so the spreadsheet renders it as literal text. Idempotent in practice: an
    already-prefixed value no longer leads on a trigger. Non-strings (ints, floats, ``None``, enum
    members) and empty strings are returned as they came, so a writer can pipe a whole heterogeneous
    row through it.
    """
    if not isinstance(value, str) or not value:
        return value
    if value[0] in SPREADSHEET_FORMULA_TRIGGERS:
        return "'" + value
    if spreadsheet_lead(value) in SPREADSHEET_FORMULA_TRIGGERS:
        return "'" + value
    return value
