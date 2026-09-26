# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**Scoped to tables the module WRITES a row into, which is the part that keeps this honest.** A naive
"every ``cell_aad`` cell must be swept" rule falsely accuses both server backends over
``shared_body``: they declare the table for schema parity but never write a row into it, so there is
nothing for a migration to seal. The write scan is the instrument that separates a real omission
from a table a backend merely declares — and it is the same instrument that corrected #1169's
originally-reported ``shared_body`` precondition. That fact is pinned in
``tests/test_phi_at_rest_inventory.py`` and is deliberately not restated here.

**The write scan must know every upsert dialect, because a guard blind to one reports OK over a
hole (BACKLOG #1723).** It originally matched ``INSERT INTO`` alone. SQLite writes ``state`` with
``INSERT OR REPLACE INTO`` and SQL Server with ``MERGE``, so ``state.value`` — a PHI-bearing
transform-state cell — was out of scope on exactly the two backends whose writer uses the native
upsert, and deleting SQLite's ``state`` on-open pass left this file green. Widening the scan is not
enough on its own: :func:`test_the_write_scan_sees_every_upsert_dialect` pins the scope so it cannot
silently narrow again, and :func:`test_the_scanner_catches_a_deliberately_bad_line` plants an
omission in each dialect so the widened scan is proven to create demand rather than merely parse.
Receipt for those two, measured by pinning ``_WRITES`` back to ``INSERT INTO`` alone: 10 of the 12
dialect cases red, the 2 that stay green are the plain-``INSERT INTO`` case that was never blind, and
the scope receipt reds on ``store.py`` and ``sqlserver.py`` — the two backends the item named.

**The scan reads executable strings, not raw source, for the same reason the sweep side does** (see
:func:`_executable_strings`): a table named only in a comment or a docstring is prose, and prose must
not decide scope in either direction. Measured at the widening: the two instruments agree cell-for-
cell on all three backends, and the AST one drops 12 comment-prose captures (1 on ``store.py``, 4 on
``postgres.py``, 7 on ``sqlserver.py`` — ``the``, ``with``, ``under``, ``would`` and the like) that a
raw-text scan of the same pattern had been treating as table names. Nothing goes the other way.

BACKLOG #1169, #1723, ASVS 11.3.3. Reads engine source; needs no database, driver or key, so it runs
on the plain leg. The RUNTIME proof that a keyless-to-keyed open really seals these cells is a
different test on a different leg: ``test_migration_encrypts_existing_state_value`` in
``tests/test_store_encryption.py`` on the plain leg for SQLite,
``test_legacy_plaintext_migrated_on_keyed_reopen`` in ``tests/test_postgres_store.py`` on the
``postgres-store`` leg, and ``test_legacy_plaintext_error_detail_migrated_on_open`` plus
``test_state_plaintext_migrated_on_keyed_reopen`` in ``tests/test_sqlserver_store.py`` on the
``sqlserver-store`` leg. Those legs open KEYLESS by default, so each of those tests opens its own
keyed handle; everything they do not name is covered only by the static parity check here.
"""

from __future__ import annotations

import ast
import functools
import pathlib
import re

import pytest

import messagefoundry
from messagefoundry.store.cipher_cells import SQLITE_CIPHER_CELLS
from messagefoundry.store.store import MessageStore

_STORE_DIR = pathlib.Path(messagefoundry.__file__).resolve().parent / "store"
_BACKENDS = ("store.py", "postgres.py", "sqlserver.py")

#: The two passes. Both are reached only on a KEYED handle, and the routine CI legs open keyless, so
#: only the named migration tests in the module docstring ever execute either body.
_SWEEPS = ("_encrypt_existing_rows", "reencrypt_to_active")

#: Every statement shape a backend uses to put a row into a table; the capture is that table.
#:
#: ``INSERT INTO`` alone was the original scan and it is the narrowest shape here: SQLite reaches for
#: ``INSERT OR REPLACE INTO`` and SQL Server for ``MERGE`` wherever the write is an upsert. The
#: optional ``[`` admits T-SQL's bracket-quoted identifiers. ``MERGE`` needs no ``INTO`` — it is
#: optional in T-SQL and the engine omits it — so the trailing word is captured either way.
_WRITES = re.compile(
    r"\b(?:INSERT(?:\s+OR\s+\w+)?\s+INTO|MERGE(?:\s+INTO)?)\s+\[?(\w+)", re.IGNORECASE
)

#: The cell that exposed the blind spot, written by a DIFFERENT dialect on each backend
#: (``INSERT OR REPLACE INTO`` on SQLite, ``MERGE`` on SQL Server, plain ``INSERT INTO`` on
#: Postgres). Pinning it by name is what stops the scan narrowing back without anyone noticing.
_UPSERT_WRITTEN_CELL = ("state", "value")

#: Floor on the per-backend scope, so an instrument that quietly stops finding writes reds instead of
#: reporting OK over a shrunken sweep. Measured at the #1723 widening: 18 on ``store.py`` (it alone
#: writes ``shared_body``) and 17 on both server backends. A floor, not an equality: adding a
#: cipher-covered cell is routine and must not red this file.
_MIN_WRITTEN_CELLS = 17


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
    (``_seal_surface``, since BACKLOG #1169), and the id-keyed tables are not
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


def _written_tables(tree: ast.AST) -> set[str]:
    """Every table an executable SQL string in this module puts a row into, in any upsert dialect.

    Driven off :func:`_executable_strings` rather than the raw file text, so a table named in a
    comment or a docstring cannot decide scope. That mattered the moment ``MERGE`` entered the
    pattern: ``MERGE`` is a common word in this codebase's prose, and a raw-text scan read
    ``MERGE with HOLDLOCK`` and ``MERGE in dispatch 2`` as writes to tables called ``with`` and
    ``in``. Harmless while the names were nonsense, but the rule that comments are not code is the
    same rule :func:`_executable_strings` exists for, and it should not hold on only one side.
    """
    tables: set[str] = set()
    for text in _executable_strings(tree):
        tables |= set(_WRITES.findall(text))
    return tables


def _written_cells(tree: ast.AST) -> set[tuple[str, str]]:
    """Covered cells whose table this module actually writes a row into — the ones it must sweep."""
    written = _written_tables(tree)
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
def _parsed(backend: str) -> ast.Module:
    """AST for one backend, parsed ONCE. The two parametrize axes cross (3 backends x 2 sweeps), and
    these modules are 4,700 to 8,300 lines — re-parsing per case costs about half a second for
    nothing. The trees are only ever read here, so sharing them is safe."""
    return ast.parse((_STORE_DIR / backend).read_text(encoding="utf-8"))


@pytest.mark.parametrize("backend", _BACKENDS)
@pytest.mark.parametrize("sweep", _SWEEPS)
def test_every_written_cipher_cell_is_swept(backend: str, sweep: str) -> None:
    """A covered cell this backend writes must be reachable from this sweep.

    Mutation receipt: deleting the ``attachment_chunk`` pass from ``postgres.py``'s
    ``_encrypt_existing_rows`` reds this, on the plain leg, with no database — which is the state
    that shipped before BACKLOG #1169.

    Second mutation receipt, measured at the #1723 widening and the reason that item existed:
    renaming ``state`` out of ``store.py``'s ``_encrypt_existing_rows`` (8 occurrences, that function
    only) leaves the ``INSERT INTO``-only scan reporting NOTHING unswept, and reds this one with
    ``[('state', 'value')]``. Same tree, same sweep, same assertion — only the scope differed.
    """
    tree = _parsed(backend)
    cells = _written_cells(tree)
    reach = _sweep_strings(tree, sweep)

    # Liveness receipts. Either of these silently empty makes the assertion below vacuous, which is
    # the exact failure this file exists to prevent elsewhere. A COUNT floor, not merely non-empty:
    # a scan that found one table would satisfy `assert cells` and still be reporting OK over a
    # sweep it never looked at (BACKLOG #1723). The named-cell pin lives in the test below.
    assert len(cells) >= _MIN_WRITTEN_CELLS, (
        f"{backend}: the write scan found only {len(cells)} cipher-covered written cells, under the "
        f"floor of {_MIN_WRITTEN_CELLS}. The scan has narrowed, so this file is now green over the "
        f"cells it stopped seeing.\n  found: {sorted(cells)}"
    )
    assert reach, f"{backend}: {sweep} was not found — renamed, or the AST walk is broken"

    unswept = sorted(c for c in cells if not _is_swept(c, reach))
    assert not unswept, (
        f"{backend}: {sweep} never names these cipher-covered cells, so a value written to them "
        "is left behind by that transition (plaintext at rest, or stranded under a retired key). "
        "The server legs open keyless by default, so nothing there executes the sweep body except "
        f"the named migration tests in the module docstring.\n  unswept: {unswept}"
    )


@pytest.mark.parametrize("backend", _BACKENDS)
def test_the_write_scan_sees_every_upsert_dialect(backend: str) -> None:
    """SCOPE RECEIPT. The one cell whose writer differs per backend must be in scope on ALL of them.

    This is the defect from BACKLOG #1723 pinned as an assertion rather than as prose. ``state`` is
    written by ``INSERT OR REPLACE INTO`` on SQLite, ``MERGE`` on SQL Server and plain
    ``INSERT INTO`` on Postgres, so the original ``INSERT INTO``-only scan demanded ``state.value``
    on exactly one of the three — and deleting SQLite's ``state`` on-open pass left this file green.
    A guard that passes because it examined nothing is indistinguishable from one that passes
    because the rule held, so the scope is asserted here instead of assumed.
    """
    cells = _written_cells(_parsed(backend))
    assert _UPSERT_WRITTEN_CELL in cells, (
        f"{backend}: {_UPSERT_WRITTEN_CELL} is cipher-covered and written, but the write scan does "
        "not see it — the scan has lost an upsert dialect and the parity check above is now blind "
        f"to that cell.\n  in scope: {sorted(cells)}"
    )


#: One statement per dialect the engine writes ``state`` with, each targeting
#: ``_UPSERT_WRITTEN_CELL``'s table. The T-SQL bracket form is here because ``MERGE [state]`` is
#: legal and a scan that stops at the bracket reports the same false clean as one that never saw
#: ``MERGE`` at all; the lowercase case is here because SQL keywords are not case-carrying.
_UPSERT_DIALECTS = (
    "INSERT INTO state (namespace, key, value) VALUES (?, ?, ?)",
    "INSERT OR REPLACE INTO state (namespace, key, value) VALUES (?, ?, ?)",
    "insert or ignore into state (namespace, key) values (?, ?)",
    "MERGE state WITH (HOLDLOCK) AS t USING (VALUES (?)) AS s (value) ON 1=0",
    "MERGE INTO state AS t USING (VALUES (?)) AS s (value) ON 1=0",
    "MERGE [state] WITH (HOLDLOCK) AS t USING (VALUES (?)) AS s (value) ON 1=0",
)

#: The planted defect: a cipher-covered cell written by one of the dialects above, under a sweep that
#: names nothing. Every case is reported CLEAN by the ``INSERT INTO``-only scan, which is how
#: BACKLOG #1723 shipped.
_PLANTED = """
class S:
    async def put_state(self) -> None:
        self._cipher.encrypt(v, aad=cell_aad("state", "value", ns, key))
        await self._db.execute({statement!r})

    async def _encrypt_existing_rows(self) -> None:
        return None
"""


@pytest.mark.parametrize("statement", _UPSERT_DIALECTS)
def test_each_upsert_dialect_is_read_as_a_write(statement: str) -> None:
    """POSITIVE CONTROL on the pattern itself, one case per dialect.

    Cheap, and it localises a regression: when the backend-wide scope receipt above reds, this says
    whether the pattern lost a dialect or the engine stopped writing the cell.
    """
    tables = _written_tables(ast.parse(f"x = {statement!r}"))
    assert tables == {_UPSERT_WRITTEN_CELL[0]}, tables


@pytest.mark.parametrize("statement", _UPSERT_DIALECTS)
def test_the_scanner_catches_a_deliberately_bad_line(statement: str) -> None:
    """POSITIVE CONTROL end to end, and the one that proves this file can go red.

    Widening a pattern and watching the suite stay green proves nothing: the same green follows from
    a pattern that matches and a scope that demands nothing of what it matched. So plant the real
    defect and require the guard to report it — per dialect, so the failure names which one broke.
    """
    tree = ast.parse(_PLANTED.format(statement=statement))
    cells = _written_cells(tree)
    assert _UPSERT_WRITTEN_CELL in cells, f"the scope missed the planted write: {statement}"

    reach = _sweep_strings(tree, "_encrypt_existing_rows")
    unswept = sorted(c for c in cells if not _is_swept(c, reach))
    assert unswept == [_UPSERT_WRITTEN_CELL], (
        "the guard did not report the planted omission — it is green over a cell written at rest "
        f"and swept by nothing.\n  statement: {statement}\n  unswept: {unswept}"
    )


def test_reading_a_table_does_not_put_it_in_scope() -> None:
    """The matching NEGATIVE control, so the widening cannot be satisfied by a pattern that matches
    anything: a SELECT names the table without putting a row in it, so there is nothing to seal."""
    selecting = ast.parse(
        'x = "SELECT value FROM state WHERE namespace=?"\ny = cell_aad("state", "value", ns, key)\n'
    )
    assert ("state", "value") in _covered_cells(selecting)  # it IS a covered cell
    assert _written_cells(selecting) == set(), _written_cells(selecting)


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
    cells = _written_cells(tree)
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
    cells = _written_cells(tree)
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
    assert _written_cells(tree) == set()  # but nothing here writes one
    # And the CREATE TABLE text must not be what rescues it: declaring is not writing.
    assert not _is_swept(("shared_body", "body"), _sweep_strings(tree, "_encrypt_existing_rows"))

    # NOTE: "only SQLite writes shared_body" is NOT re-asserted here. It is already pinned, with the
    # same `INSERT INTO shared_body` instrument and the same reasoning, by
    # `tests/test_phi_at_rest_inventory.py::_per_backend_cipher_counts` — which predates BACKLOG
    # #1169 and therefore already contradicted that item's originally-reported precondition. Stating
    # a load-bearing fact once and linking to it is the rule (CLAUDE.md section 11, SDS-3.5); two
    # copies drift, and the copy a reader finds first wins.


def test_the_readback_declaration_names_every_composite_cipher_cell() -> None:
    """The full restore-verify's cell list must be exactly the store's covered cells (BACKLOG #1719).

    ``_decrypt_check`` walks ``SQLITE_CIPHER_CELLS``: the store's own ``_CIPHER_COLUMNS`` plus a
    declaration of the composite-key cells beside the store. A declaration is the thing that drifts, so
    pin it here against the same instrument the sweeps are held to: every literal ``cell_aad`` cell in
    ``store.py``. A new composite cipher cell with no entry reds this, and so does an entry naming a
    cell the store no longer seals.

    Equality, not a subset: an entry with no writer would make the verify look for a column that holds
    nothing, and pass over it without saying so. No duplicates either, which also rules out a cell in
    both halves being read twice. Whether each entry's AAD COLUMNS match the writer is a runtime
    question, answered by ``tests/test_cipher_cells_readback.py``.
    """
    covered = _covered_cells(_parsed("store.py"))
    id_keyed = set(MessageStore._CIPHER_COLUMNS)
    declared = [(cell.table, cell.column) for cell in SQLITE_CIPHER_CELLS]

    assert len(declared) == len(set(declared)), f"a cell is declared twice: {sorted(declared)}"
    # The id-keyed half is the store's own tuple, so pin it to a writer too: an entry nothing seals
    # would be walked over in silence.
    assert id_keyed <= covered, f"sealed by no cell_aad writer: {sorted(id_keyed - covered)}"
    composite = set(declared) - id_keyed
    assert covered - id_keyed == composite, (
        "messagefoundry/store/cipher_cells.py has drifted from store.py's cell_aad calls.\n"
        f"  sealed by store.py, not declared: {sorted(covered - id_keyed - composite)}\n"
        f"  declared, not sealed by store.py: {sorted(composite - (covered - id_keyed))}"
    )
