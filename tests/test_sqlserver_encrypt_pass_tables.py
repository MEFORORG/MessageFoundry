# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every ciphered (table, column) the SQL Server backend sweeps must name a table it actually creates.

**This guard exists because CI cannot catch the defect any other way.** `_encrypt_existing_rows`
early-returns at `if not self._cipher.encrypts: return` — and **every** SQL Server CI step runs
*keyless* (`MEFOR_STORE_ENCRYPTION_KEY` appears nowhere in the seven SS steps or the five PG steps of
`.github/workflows/ci.yml`). So the `SELECT ... FROM <table>` loop below that early return **never
executes on any CI leg**. A `(table, column)` pair naming a dropped table is therefore invisible to the
entire test suite, right up until a *keyed* production open crash-loops on `Invalid object name`.

That is not hypothetical: ASVS 14.2.7 removes the legacy `outbox` table from `_SCHEMA`, and the pair
`("outbox", "payload")` sits ~1200 lines away in a different method. Removing one and forgetting the
other is a startup crash-loop in production and a green suite in CI.

So this test does what CI's runtime cannot: it reads the source. No database, no driver, no key — it
runs on the plain leg, which is the only leg guaranteed to exist.

Deliberately checking the sweep passes against the module's OWN `CREATE TABLE` set rather than against
a live database: a live check would need the SS leg (which is keyless, see above) and would pass on a
database whose schema had drifted from the code that ships.
"""

from __future__ import annotations

import ast
import pathlib
import re

import pytest

_SQLSERVER = (
    pathlib.Path(__file__).resolve().parents[1] / "messagefoundry" / "store" / "sqlserver.py"
)

#: The methods whose (table, column) literals must resolve. Both walk ciphered cells; both are reached
#: only on a KEYED handle, which is exactly why neither is exercised in CI.
_SWEEP_FUNCTIONS = ("_encrypt_existing_rows", "reencrypt_to_active")

#: `CREATE TABLE [dbo].[name]` / `CREATE TABLE name` — the schema this module actually deploys.
_CREATE_TABLE = re.compile(r"CREATE TABLE\s+(?:\[?dbo\]?\.)?\[?([A-Za-z_][A-Za-z0-9_]*)\]?")


def _created_tables(source: str) -> set[str]:
    return set(_CREATE_TABLE.findall(source))


def _swept_pairs(source: str) -> list[tuple[str, str, int]]:
    """Every ``(table, column)`` literal driving a sweep loop, with its line.

    Anchored on the LOOP (``for table, <col> in (...)``), not on "any 2-string tuple in the function".
    The naive version over-matched immediately and usefully: both functions also build composite AAD
    tuples like ``("body", "detail")`` and ``("event_type", "connection")``, whose first element is a
    COLUMN, not a table. Flagging those would have made this guard cry wolf on ~14 legitimate pairs,
    and a guard that always fails gets deleted or `xfail`ed — which is how a real detector dies.

    Walks the AST rather than grepping, so a pair split across lines or carrying a trailing comment is
    still found: the `("users", "totp_secret")` entry is wrapped across three lines in the real source,
    and a line-based scan misses it (asserted below).
    """
    tree = ast.parse(source)
    found: list[tuple[str, str, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef):
            continue
        if node.name not in _SWEEP_FUNCTIONS:
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.For | ast.AsyncFor):
                continue
            target = inner.target
            # `for table, column in (...)` / `for table, ncol in (...)` — the first bound name must be
            # `table`, which is what makes element[0] a table name rather than a column.
            if not isinstance(target, ast.Tuple) or not target.elts:
                continue
            first_name = target.elts[0]
            if not isinstance(first_name, ast.Name) or first_name.id != "table":
                continue
            if not isinstance(inner.iter, ast.Tuple | ast.List):
                continue
            for element in inner.iter.elts:
                if not isinstance(element, ast.Tuple) or not element.elts:
                    continue
                table = element.elts[0]
                column = element.elts[1] if len(element.elts) > 1 else None
                if isinstance(table, ast.Constant) and isinstance(table.value, str):
                    col = column.value if isinstance(column, ast.Constant) else "?"
                    found.append((table.value, str(col), element.lineno))
    return found


def test_every_swept_table_is_created_by_this_module() -> None:
    """A ciphered-cell sweep may only name a table `_SCHEMA` creates.

    Mutation: add `("nonexistent_table", "x")` to `_encrypt_existing_rows` — reds here, on the plain
    leg, with no database. After the legacy `outbox` table is dropped, re-adding `("outbox", "payload")`
    reds here too, which is the entire reason this file exists.
    """
    source = _SQLSERVER.read_text(encoding="utf-8")
    created = _created_tables(source)
    pairs = _swept_pairs(source)

    # Liveness receipt. A parse that silently found nothing would make the assertion below pass
    # vacuously, which is precisely the failure mode this guard is meant to prevent elsewhere.
    assert created, "no CREATE TABLE statements found — the regex or the module shape changed"
    assert pairs, (
        f"no (table, column) literals found in {_SWEEP_FUNCTIONS} — either the functions were renamed "
        f"or the AST walk is broken, and this guard is asserting nothing"
    )

    unknown = sorted({(t, c, ln) for t, c, ln in pairs if t not in created})
    assert not unknown, (
        "a ciphered-cell sweep names a table this module does not CREATE. On a KEYED open this is "
        "'Invalid object name' at startup — a crash-loop — and no CI leg catches it, because every "
        "SQL Server CI step is keyless and returns before the sweep.\n"
        + "\n".join(
            f"  sqlserver.py:{ln}  ({t!r}, {c!r})  <- table {t!r} is never created"
            for t, c, ln in unknown
        )
        + f"\n\ncreated tables: {', '.join(sorted(created))}"
    )


def test_the_guard_can_actually_see_an_unknown_table() -> None:
    """Prove the detector fires, rather than trusting that it would.

    The test above passing tells you nothing on its own — it passes identically if `_swept_pairs`
    returns garbage or `_created_tables` over-matches. Drive the same functions over a synthetic module
    containing a known-bad pair and assert it is found.
    """
    synthetic = """
_SCHEMA = ["IF OBJECT_ID('queue','U') IS NULL CREATE TABLE queue (id INT)"]

class S:
    async def _encrypt_existing_rows(self) -> None:
        for table, column in (("queue", "payload"), ("outbox", "payload")):
            pass
"""
    created = _created_tables(synthetic)
    pairs = _swept_pairs(synthetic)
    assert created == {"queue"}, created
    assert ("outbox", "payload", 6) in [(t, c, ln) for t, c, ln in pairs], pairs
    unknown = [t for t, _c, _ln in pairs if t not in created]
    assert unknown == ["outbox"], f"the detector did not flag the unknown table: {unknown}"


@pytest.mark.parametrize("wrapped_across_lines", [True, False])
def test_the_ast_walk_finds_pairs_a_line_scan_would_miss(wrapped_across_lines: bool) -> None:
    """The real source wraps `("users", "totp_secret")` across three lines with a trailing comment.

    A grep-based implementation misses it, silently shrinking the checked set — a guard that examines
    less than it claims to. Assert both spellings are found so the walk cannot regress to line-based.
    """
    pair = (
        '(\n                "users",\n                "totp_secret",\n            ),  # a comment'
        if wrapped_across_lines
        else '("users", "totp_secret"),'
    )
    synthetic = f"""
class S:
    async def _encrypt_existing_rows(self) -> None:
        for table, column in (
            {pair}
        ):
            pass
"""
    pairs = [(t, c) for t, c, _ln in _swept_pairs(synthetic)]
    assert ("users", "totp_secret") in pairs, f"wrapped={wrapped_across_lines}: {pairs}"
