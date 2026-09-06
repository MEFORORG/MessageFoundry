# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every cipher-covered cell a backend WRITES must be named by BOTH of that backend's sweeps.

**The gap this closes, and why the existing guard could not see it.**
``tests/test_sqlserver_encrypt_pass_tables.py`` checks the sweeps in the *other* direction: a table a
sweep names must be a table the module creates. That catches a sweep pointing at a dropped table. It
cannot catch the opposite and more likely drift — a covered table that **no sweep names at all** —
because an omission has no literal to inspect. That is exactly what shipped: ``attachment_chunk``
(#149, ADR 0105) was added to all three backends with a rotation pass but, on Postgres and SQL
Server, no ON-OPEN migration pass. SQLite had one. Nothing anywhere compared them.

**Why both sweeps and not just one.** They handle the two different transitions and are not
interchangeable: ``_encrypt_existing_rows`` runs at every keyed open and seals legacy plaintext;
``reencrypt_to_active`` runs offline under ``rotate-key`` and moves values onto the active key. A
cell covered by only the second stays plaintext at rest until someone rotates a key.

**Scoped to tables the module INSERTs into, which is the part that keeps this honest.** A naive
"every ``cell_aad`` cell must be swept" rule falsely accuses both server backends over
``shared_body``: they declare the table for schema parity but never write a row into it, so there is
nothing for a migration to seal. ``INSERT INTO`` is the instrument that separates a real omission
from a table a backend merely declares — and it is the same instrument that corrected #1169's
originally-reported ``shared_body`` precondition. That fact is pinned in
``tests/test_phi_at_rest_inventory.py`` and is deliberately not restated here.

BACKLOG #1169, ASVS 11.3.3. Reads engine source; needs no database, driver or key, so it runs on the
plain leg — the SQL Server and Postgres CI legs are all KEYLESS and return before either sweep body.
"""

from __future__ import annotations

import ast
import functools
import pathlib
import re

import pytest

import messagefoundry

_STORE_DIR = pathlib.Path(messagefoundry.__file__).resolve().parent / "store"
_BACKENDS = ("store.py", "postgres.py", "sqlserver.py")

#: The two passes. Both are reached only on a KEYED handle, which is why CI never executes either.
_SWEEPS = ("_encrypt_existing_rows", "reencrypt_to_active")

_INSERT_INTO = re.compile(r"INSERT INTO\s+(\w+)", re.IGNORECASE)


def _covered_cells(tree: ast.AST) -> set[tuple[str, str]]:
    """Every ``cell_aad("<table>", "<column>", ...)`` literal in the module.

    This is the module's OWN definition of a cipher-covered cell, not a second list that can drift
    from it: the same call builds the AAD on the write path and on the read path, so a cell that
    appears here is a cell whose value is sealed and must therefore be migrated and rotated.
    """
    found: set[tuple[str, str]] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or len(node.args) < 2:
            continue
        fn = node.func
        name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if name != "cell_aad":
            continue
        table, column = node.args[0], node.args[1]
        if (
            isinstance(table, ast.Constant)
            and isinstance(column, ast.Constant)
            and isinstance(table.value, str)
            and isinstance(column.value, str)
        ):
            found.add((table.value, column.value))
    return found


def _executable_strings(node: ast.AST) -> set[str]:
    """Every string constant under ``node`` that the code actually USES.

    Docstrings and bare string statements are excluded, and comments never enter the AST at all.
    **That exclusion is the whole point.** The first version of this check matched table names
    against raw source text and reported the shipped Postgres omission as CLEAN — because a comment
    two lines above the missing call said the word ``attachment_chunk``. Prose describing coverage
    satisfied a check about coverage: the instrument was answering "is this table mentioned here",
    not "is this table swept here" (CLAUDE.md section 11, SDS-3.8). A table name only counts when it
    reaches a SQL string or a sweep tuple that runs.
    """
    docstrings = {
        id(child.value)
        for child in ast.walk(node)
        if isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant)
    }
    return {
        child.value
        for child in ast.walk(node)
        if isinstance(child, ast.Constant)
        and isinstance(child.value, str)
        and id(child) not in docstrings
    }


def _declarations(tree: ast.AST) -> dict[str, ast.Assign]:
    """MODULE- and CLASS-level assignments only — the sweep tuples like ``_CIPHER_COLUMNS``.

    Deliberately not ``ast.walk``: that also collects every local inside every function (~250 names
    per backend, last-wins), so an incidental local called ``value`` or ``total`` would drag an
    unrelated assignment's SQL into the reach set. Since a bigger reach set makes :func:`_is_swept`
    EASIER to satisfy, over-collecting here silently weakens the very detection this file exists for.
    """
    out: dict[str, ast.Assign] = {}
    bodies = [getattr(tree, "body", [])]
    bodies += [node.body for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    for body in bodies:
        for node in body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        out[target.id] = node
    return out


def _sweep_strings(tree: ast.AST, entry: str) -> set[str]:
    """The executable strings a sweep can reach: its own body, the same-module helpers it CALLS
    DIRECTLY, and the module/class-level declarations it names.

    All three matter. ``_encrypt_existing_rows`` delegates most tables to helpers
    (``_encrypt_existing_composite``, ``_encrypt_message_events``), and the id-keyed tables are not
    literals in any function at all — they live in the ``_CIPHER_COLUMNS`` class attribute the loop
    iterates. Reading only a function body reports four tables missing on every backend, which is
    how a guard ends up crying wolf and getting switched off.

    **One level of delegation, not transitive closure.** Following calls all the way down reaches
    ``close``, ``checkpoint_cipher_invocations`` and the connection-pool machinery — 13 to 14
    functions on ``sqlserver.py`` — and every SQL string in them then counts as "the sweep names
    this table". Every real pass is a direct callee, so the extra depth adds only dilution.
    """
    functions = {
        node.name: node
        for node in ast.walk(tree)
        if isinstance(node, ast.AsyncFunctionDef | ast.FunctionDef)
    }
    entry_fn = functions.get(entry)
    if entry_fn is None:
        return set()
    declarations = _declarations(tree)
    strings: set[str] = set()
    reached: list[ast.AsyncFunctionDef | ast.FunctionDef] = [entry_fn]
    for node in ast.walk(entry_fn):
        if not isinstance(node, ast.Call):
            continue
        fn = node.func
        called = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", None)
        if called and called in functions and called != entry:
            reached.append(functions[called])
    for function in reached:
        strings |= _executable_strings(function)
        named = {
            child.id if isinstance(child, ast.Name) else child.attr
            for child in ast.walk(function)
            if isinstance(child, ast.Name | ast.Attribute)
        }
        for name in named & declarations.keys():
            strings |= _executable_strings(declarations[name])
    return strings


def _written_cells(source: str, tree: ast.AST) -> set[tuple[str, str]]:
    """Covered cells whose table this module actually INSERTs into — the ones it must sweep."""
    written = set(_INSERT_INTO.findall(source))
    return {cell for cell in _covered_cells(tree) if cell[0] in written}


def _is_swept(cell: tuple[str, str], reach: set[str]) -> bool:
    """A cell is swept when both its table and its column reach an executable string — either as an
    exact sweep-tuple entry (``("messages", "raw")``) or inside a SQL statement.

    **The table and the column are matched INDEPENDENTLY, and that looseness is forced — do not
    "fix" it to require co-occurrence in one string.** The backends express a pass in two different
    shapes: the id-keyed tables arrive as separate constants from the ``_CIPHER_COLUMNS`` tuple,
    where ``"messages"`` and ``"raw"`` never appear in the same string, while the composite passes
    arrive as f-string SQL where they do. Requiring one string to hold both immediately reds every
    id-keyed cell on all three backends. So this proves a table and its column are both reachable
    from the sweep, not that a specific statement exists — which is exactly enough to catch the
    omission this file was written for, and no more. Tightening it needs the source to be data
    first (see the module docstring).
    """
    table, column = cell
    return any(table in s for s in reach) and any(column in s for s in reach)


@functools.cache
def _parsed(backend: str) -> tuple[str, ast.Module]:
    """Source + AST for one backend, parsed ONCE. The two parametrize axes cross (3 backends x 2
    sweeps), and these modules are 4,700 to 8,300 lines — re-parsing per case costs about half a
    second for nothing. The trees are only ever read here, so sharing them is safe."""
    source = (_STORE_DIR / backend).read_text(encoding="utf-8")
    return source, ast.parse(source)


@pytest.mark.parametrize("backend", _BACKENDS)
@pytest.mark.parametrize("sweep", _SWEEPS)
def test_every_written_cipher_cell_is_swept(backend: str, sweep: str) -> None:
    """A covered cell this backend writes must be reachable from this sweep.

    Mutation receipt: deleting the ``attachment_chunk`` pass from ``postgres.py``'s
    ``_encrypt_existing_rows`` reds this, on the plain leg, with no database — which is the state
    that shipped before BACKLOG #1169.
    """
    source, tree = _parsed(backend)
    cells = _written_cells(source, tree)
    reach = _sweep_strings(tree, sweep)

    # Liveness receipts. Either of these silently empty makes the assertion below vacuous, which is
    # the exact failure this file exists to prevent elsewhere.
    assert cells, f"{backend}: no cell_aad cells found in INSERTed tables — the walk is broken"
    assert reach, f"{backend}: {sweep} was not found — renamed, or the AST walk is broken"

    unswept = sorted(c for c in cells if not _is_swept(c, reach))
    assert not unswept, (
        f"{backend}: {sweep} never names these cipher-covered cells, so a value written to them "
        "is left behind by that transition (plaintext at rest, or stranded under a retired key). "
        "No CI leg can catch this at runtime: every SQL Server and Postgres leg is keyless and "
        f"returns before the sweep body.\n  unswept: {unswept}"
    )


def test_the_guard_can_actually_see_an_unswept_cell() -> None:
    """Prove the detector fires rather than trusting that it would.

    The parametrized test passing tells you nothing on its own — it passes identically if
    ``_covered_cells`` returns nothing or ``_sweep_reach`` returns the whole module. Drive the same
    functions over synthetic source with one swept cell and one omitted cell.
    """
    # Faithful to the real module shape: a covered cell is declared by a LITERAL cell_aad call on a
    # read/write path, while the sweep reaches it through the `_CIPHER_COLUMNS` tuple, whose loop
    # passes variables. Both halves have to work or the guard mis-reports.
    synthetic = """
class S:
    _CIPHER_COLUMNS = (("messages", "raw"),)

    async def put_message(self) -> None:
        self._cipher.encrypt(raw, aad=cell_aad("messages", "raw", mid))
        await self._db.execute("INSERT INTO messages (raw) VALUES (?)")

    async def _encrypt_existing_rows(self) -> None:
        for table, column in self._CIPHER_COLUMNS:
            self._cipher.encrypt(v, aad=cell_aad(table, column, r["id"]))

    async def put_chunk(self) -> None:
        self._cipher.encrypt(c, aad=cell_aad("attachment_chunk", "ciphertext", ref, seq))
        await self._db.execute("INSERT INTO attachment_chunk (ciphertext) VALUES (?)")
"""
    tree = ast.parse(synthetic)
    cells = _written_cells(synthetic, tree)
    assert cells == {("messages", "raw"), ("attachment_chunk", "ciphertext")}, cells

    reach = _sweep_strings(tree, "_encrypt_existing_rows")
    unswept = sorted(c for c in cells if not _is_swept(c, reach))
    assert unswept == [("attachment_chunk", "ciphertext")], unswept

    # And the id-keyed cell IS seen, only because the class attribute was pulled in — the failure
    # mode that would make this guard accuse every backend of omitting `messages`.
    assert _is_swept(("messages", "raw"), reach)


def test_a_comment_naming_the_table_does_not_count_as_sweeping_it() -> None:
    """The false-NEGATIVE guard, and it is here because this check failed it once.

    Matching table names against raw source text reported the real shipped Postgres omission as
    clean: a comment above the missing call said ``attachment_chunk``, and the substring search could
    not tell prose from code. A guard that green-lights the exact defect it was written for is worse
    than no guard, because it also certifies the absence.
    """
    synthetic = '''
class S:
    async def put_chunk(self) -> None:
        self._cipher.encrypt(c, aad=cell_aad("attachment_chunk", "ciphertext", ref, seq))
        await self._db.execute("INSERT INTO attachment_chunk (ciphertext) VALUES (?)")

    async def _encrypt_existing_rows(self) -> None:
        """Seals attachment_chunk.ciphertext among others."""
        # The `attachment_chunk` table rides its own pass below.
        return None
'''
    tree = ast.parse(synthetic)
    cells = _written_cells(synthetic, tree)
    assert ("attachment_chunk", "ciphertext") in cells

    reach = _sweep_strings(tree, "_encrypt_existing_rows")
    assert not _is_swept(("attachment_chunk", "ciphertext"), reach), (
        "a comment and a docstring naming the table were accepted as sweeping it"
    )
    assert reach == set(), reach  # the sweep executes no strings at all


def test_a_declared_but_never_written_table_is_not_demanded() -> None:
    """The false-accusation guard: a table a backend declares but never INSERTs into is out of
    scope, because there is no value of its to seal.

    Without this rule the check reds on Postgres and SQL Server over ``shared_body`` — a real
    finding-shaped result that is not a finding, and the kind that gets a guard switched off.
    """
    synthetic = """
_SCHEMA = ["CREATE TABLE shared_body (hash TEXT PRIMARY KEY, body TEXT)"]


class S:
    async def read_body(self) -> None:
        self._cipher.decrypt(row, aad=cell_aad("shared_body", "body", h))

    async def _encrypt_existing_rows(self) -> None:
        return None
"""
    tree = ast.parse(synthetic)
    assert ("shared_body", "body") in _covered_cells(tree)  # it IS a covered cell
    assert _written_cells(synthetic, tree) == set()  # but nothing here writes one
    # And the CREATE TABLE text must not be what rescues it: declaring is not writing.
    assert not _is_swept(("shared_body", "body"), _sweep_strings(tree, "_encrypt_existing_rows"))

    # NOTE: "only SQLite writes shared_body" is NOT re-asserted here. It is already pinned, with the
    # same `INSERT INTO shared_body` instrument and the same reasoning, by
    # `tests/test_phi_at_rest_inventory.py::_per_backend_cipher_counts` — which predates BACKLOG
    # #1169 and therefore already contradicted that item's originally-reported precondition. Stating
    # a load-bearing fact once and linking to it is the rule (CLAUDE.md section 11, SDS-3.5); two
    # copies drift, and the copy a reader finds first wins.
