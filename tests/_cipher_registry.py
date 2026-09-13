# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One definition of "which cells are cipher-covered", shared by the tests that need it.

There are TWO mechanisms, and a test that knows only the first will pass while the code and the prose
disagree:

1. **The id-keyed registry**, ``MessageStore._CIPHER_COLUMNS``. Its AAD binds the row id, so it only
   works where the id is known at the encrypting INSERT.
2. **Composite passes**, hand-written loops calling ``cell_aad("<table>", "<column>", ...)`` with
   insert-time-known natural columns instead. There is NO registry to read for these -- the only
   literal signal is the call site itself.

Mechanism 2 is not an edge case. ``store.py`` states the rule for choosing it: "The autoincrement-id
tables bind cell_aad to natural columns (see _CIPHER_COLUMNS)". Every table with a server-assigned id
must use it, which today is ``message_events``, ``connection_event`` and ``alert_instance`` -- none of
which appear in ``_CIPHER_COLUMNS``.

**This module exists because that fact caught a guard out** (BACKLOG #1198). The off-box tee's guard
read only mechanism 1 while claiming to fail "in BOTH directions", and ``audit_log.id`` is
``AUTOINCREMENT`` / ``BIGSERIAL`` / ``IDENTITY``, so the branch it tested was unreachable by
construction rather than merely untriggered. Settled by adversarial review: both sides recommended
widening, and the side arguing to keep it narrow conceded on this fact.

The walks were previously defined inside ``test_phi_at_rest_inventory.py`` and are moved here rather
than copied. A second definition of "cipher-covered" is the defect this module prevents, the same way
``backlog_status_check.parse_items`` is the single definition of backlog item status.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
PKG = _ROOT / "messagefoundry"

#: The backend modules whose DDL and cipher passes are scanned.
BACKEND_MODULES = (
    PKG / "store" / "store.py",
    PKG / "store" / "sqlserver.py",
    PKG / "store" / "postgres.py",
)

#: The functions whose literal ``(table, column)`` tuples enumerate the cipher registry.
CIPHER_PASS_FUNCS = frozenset({"_encrypt_existing_rows", "reencrypt_to_active"})

#: Table names as declared by the backends' own DDL -- used to reject AAD column tuples.
CREATE_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?#?([A-Za-z_][A-Za-z0-9_]*)", re.IGNORECASE
)


def cell_aad_pairs() -> set[tuple[str, str]]:
    """Every ``cell_aad("<table>", "<column>", ...)`` literal call across the package."""
    pairs: set[tuple[str, str]] = set()
    for path in sorted(PKG.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "cell_aad"
                and len(node.args) >= 2
            ):
                continue
            first, second = node.args[0], node.args[1]
            if not (isinstance(first, ast.Constant) and isinstance(second, ast.Constant)):
                continue
            table, column = first.value, second.value
            if isinstance(table, str) and isinstance(column, str):
                pairs.add((table, column))
    return pairs


def string_pairs(node: ast.AST) -> set[tuple[str, str]]:
    """Literal two-string tuples anywhere under ``node``."""
    out: set[tuple[str, str]] = set()
    for sub in ast.walk(node):
        if not (isinstance(sub, ast.Tuple) and len(sub.elts) == 2):
            continue
        first, second = sub.elts
        if not (isinstance(first, ast.Constant) and isinstance(second, ast.Constant)):
            continue
        table, column = first.value, second.value
        if isinstance(table, str) and isinstance(column, str):
            out.add((table, column))
    return out


def migration_pass_pairs() -> set[tuple[str, str]]:
    """Literal ``(table, column)`` pairs in each backend's cipher registry / migration / rotation code.

    Only pairs whose first element is a table that backend's own DDL creates are kept, so AAD *column*
    tuples (``("namespace", "key")``, ``("attachment_id", "seq")``) can never masquerade as tiers.
    """
    pairs: set[tuple[str, str]] = set()
    for path in BACKEND_MODULES:
        src = path.read_text(encoding="utf-8")
        tables = {m.lower() for m in CREATE_TABLE_RE.findall(src)}
        tree = ast.parse(src)
        for node in ast.walk(tree):
            interesting = isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and (
                node.name in CIPHER_PASS_FUNCS
            )
            if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "_CIPHER_COLUMNS" for t in node.targets
            ):
                interesting = True
            if not interesting:
                continue
            pairs |= {p for p in string_pairs(node) if p[0].lower() in tables}
    return pairs


def covered_pairs() -> set[tuple[str, str]]:
    """Every cipher-covered ``(table, column)``, by EITHER mechanism."""
    return cell_aad_pairs() | migration_pass_pairs()


def covered_tables() -> set[str]:
    """Every table with at least one cipher-covered column, by either mechanism.

    Table granularity is deliberate and matches the claim it is used to check: the tee's docstring
    makes a table-level statement about ``audit_log``. A future audit-chain MAC binding
    ``cell_aad("audit_log", "row_hash", ...)`` would therefore trip a guard built on this, which is
    correct -- that docstring would need re-reading either way.
    """
    return {table for table, _column in covered_pairs()}
