# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""No test fixture may issue an UNGUARDED ``DELETE FROM outbox`` once the legacy table is retired.

ASVS 14.2.7 migrates the legacy SQL Server ``outbox`` table into ``queue`` and DROPs it. After that, a
fixture doing::

    for table in ("message_events", "state", "queue", "response", "outbox", "messages"):
        await cur.execute(f"DELETE FROM {table}")

fails with *Invalid object name 'outbox'* and takes its whole module with it.

**Why a source scanner rather than "run the tests and see":** of the eighteen files carrying such a
reset list, **nine appear in no SQL Server CI step at all** — `test_adr0071_dispatch_wiring_sqlserver`,
`test_adr0071_fused_callables_sqlserver`, `test_adr0075_batch_sqlserver`, `test_adr0114_claim_proc_live`,
`test_batch_completion`, `test_metadata_bag`, `test_outbound_batch`, `test_shard_recovery_sqlserver`,
`test_sqlserver_sync_handoff`. A mutation planted in any of those **passes vacuously**, so "the SS leg
is green" is not evidence that the reset lists were all updated. This test needs no database and runs
on the plain leg, which is the only leg guaranteed to exist.

The **guarded** form is fine and stays::

    await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}")

— it is a no-op once the table is gone. That distinction is structural, not stylistic, which is why this
scanner reads the loop body rather than grepping for the word ``outbox``.

**The two source-level retirement guards at the bottom live here for the same reason.** They assert
things about `_SCHEMA` and about the engine package that need no database, and the live migration
suite (`tests/test_sqlserver_legacy_outbox_migration.py`) carries a MODULE-level
``skipif(not MEFOR_TEST_SQLSERVER)``. Leaving them there would have gated a pure source check behind a
running SQL Server — the same "runs on a leg that may not exist" trap this module was built to avoid.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

from messagefoundry.store import Stage

_TESTS = pathlib.Path(__file__).resolve().parent

#: Existence-guard markers. A reset whose statement contains one of these degrades to a no-op when the
#: table is absent, so it survives the retirement untouched.
_GUARD_MARKERS = ("OBJECT_ID", "IF EXISTS", "information_schema", "in existing", "to_regclass")

#: `"outbox"` appears in these for reasons that are not a reset list. Exempted by FILE, with the reason,
#: because a blanket substring skip would also hide a real one landing in the same file later.
_NOT_RESET_LISTS = {
    # A Pydantic field-name allow-list and a forbidden-substring tuple — neither is a table name.
    "test_security_doc_drift.py": "_MAPPED_MODEL_NON_PHI_FIELDS — model field names, not tables",
    "test_tray_boundary.py": "_FORBIDDEN_FIELD_SUBSTRINGS — substring matching, not tables",
    # Response-payload dict keys asserted in API tests.
    "test_api.py": "response-body keys, not tables",
    "test_api_auth.py": "response-body keys, not tables",
    # This scanner and the AST guard both name the table in prose/fixtures on purpose.
    "test_fixture_outbox_reset.py": "this file",
    "test_sqlserver_encrypt_pass_tables.py": "synthetic fixtures naming the table deliberately",
}


def _unguarded_outbox_resets(path: pathlib.Path) -> list[tuple[int, str]]:
    """Loops over a literal table tuple containing ``"outbox"`` whose body issues a BARE delete.

    Anchored on the `for` node and its body's source span, so the guarded and unguarded spellings are
    told apart by what the statement actually does — not by whether the word ``outbox`` is nearby.
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - a test file that does not parse fails elsewhere
        return []
    lines = source.splitlines()
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.For | ast.AsyncFor):
            continue
        if not isinstance(node.iter, ast.Tuple | ast.List | ast.Set):
            continue
        names = {
            e.value
            for e in node.iter.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        }
        if "outbox" not in names:
            continue
        body_lines: list[str] = []
        for stmt in node.body:
            body_lines.extend(lines[stmt.lineno - 1 : (stmt.end_lineno or stmt.lineno)])
        body_src = "\n".join(body_lines)
        if "DELETE FROM" not in body_src.upper():
            continue
        if any(marker.upper() in body_src.upper() for marker in _GUARD_MARKERS):
            continue  # existence-guarded — a no-op once the table is gone
        hits.append((node.lineno, body_src.strip().splitlines()[0][:100]))
    return hits


def _scanned_files() -> list[pathlib.Path]:
    return sorted(p for p in _TESTS.glob("test_*.py") if p.name not in _NOT_RESET_LISTS)


def test_no_fixture_issues_an_unguarded_outbox_delete() -> None:
    """After the legacy table is retired, an unguarded reset is a module-wide failure.

    Mutation: add `"outbox"` to the reset tuple in `tests/test_metadata_bag.py` — reds here on the plain
    leg naming the file and line, which is the only place it can be caught for the nine files that run
    on no SQL Server CI step.

    This test shipped one commit ahead of the retirement carrying `xfail(strict=True)`, with the 21
    offending sites as its failure list. `strict` is what made that self-clearing: fixing the last reset
    list turned the xfail into an XPASS, which strict reports as a FAILURE, so the marker could not be
    left behind to rot silently green — removing it here was forced, not remembered.
    """
    scanned = _scanned_files()
    # Liveness receipt: report what was EXAMINED, not just what was found. A glob that silently matched
    # nothing would make this pass while checking zero files.
    assert len(scanned) > 100, f"only scanned {len(scanned)} test files — the glob looks broken"

    offenders: list[str] = []
    for path in scanned:
        for lineno, snippet in _unguarded_outbox_resets(path):
            offenders.append(f"  {path.name}:{lineno}  {snippet}")

    assert not offenders, (
        f"scanned {len(scanned)} test files; {len(offenders)} carry an UNGUARDED "
        f"`DELETE FROM outbox` reset. Once the legacy table is dropped each of these fails with "
        f"'Invalid object name' and takes its whole module with it — and nine of them run on no SQL "
        f"Server CI step, so no live leg would tell you:\n" + "\n".join(offenders) + "\n\n"
        "Fix by removing 'outbox' from the tuple, or by using the guarded form:\n"
        "  await cur.execute(f\"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}\")"
    )


def test_the_scanner_distinguishes_guarded_from_unguarded() -> None:
    """Prove the detector's discrimination, rather than trusting it.

    A scanner that flagged everything would make the test above permanently red and get deleted; one
    that flagged nothing would pass forever. Drive both spellings through it.
    """
    unguarded = _TESTS / "_scan_fixture_unguarded.py"
    guarded = _TESTS / "_scan_fixture_guarded.py"
    unguarded.write_text(
        "async def f(cur):\n"
        '    for table in ("queue", "outbox", "messages"):\n'
        '        await cur.execute(f"DELETE FROM {table}")\n',
        encoding="utf-8",
    )
    guarded.write_text(
        "async def f(cur):\n"
        '    for table in ("queue", "outbox", "messages"):\n'
        "        await cur.execute(\n"
        "            f\"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}\"\n"
        "        )\n",
        encoding="utf-8",
    )
    try:
        assert _unguarded_outbox_resets(unguarded), "the bare DELETE was NOT flagged"
        assert not _unguarded_outbox_resets(guarded), (
            "the OBJECT_ID-guarded DELETE was wrongly flagged"
        )
    finally:
        unguarded.unlink(missing_ok=True)
        guarded.unlink(missing_ok=True)


@pytest.mark.parametrize("exempt", sorted(_NOT_RESET_LISTS))
def test_every_exemption_still_exists_and_still_needs_exempting(exempt: str) -> None:
    """An exemption for a file that no longer exists, or no longer mentions the table, is dead weight
    that quietly widens the next person's blind spot. Fail when one goes stale."""
    path = _TESTS / exempt
    assert path.exists(), f"exempted file {exempt} is gone — drop it from _NOT_RESET_LISTS"
    assert "outbox" in path.read_text(encoding="utf-8"), (
        f"{exempt} no longer mentions 'outbox' — the exemption is stale and should be removed, "
        f"otherwise a genuine reset list landing in this file later would be silently skipped"
    )


def test_the_migration_ships_in_the_schema_batch_not_open_path_code() -> None:
    """No database needed. `_schema_hash()` alone decides whether the DDL batch runs at all, so a
    migration outside `_SCHEMA` is invisible to that decision and would never fire on an upgrade.

    Mutation: move the statement into an open-path method — reds here, on the plain leg, rather than
    silently never running against a real customer upgrade.
    """
    from messagefoundry.store.sqlserver import _SCHEMA

    migrations = [s for s in _SCHEMA if "DROP TABLE outbox" in s]
    assert len(migrations) == 1, (
        f"expected exactly one outbox migrate-and-drop statement in _SCHEMA, found {len(migrations)}"
    )
    stmt = migrations[0]
    assert "IF OBJECT_ID('outbox','U') IS NOT NULL" in stmt, (
        "the migration is not existence-guarded"
    )
    assert "INSERT INTO queue" in stmt, "the statement drops the table without migrating its rows"
    assert f"'{Stage.OUTBOUND.value}'" in stmt, "migrated rows must land at the outbound stage"
    assert "EXISTS (SELECT 1 FROM messages" in stmt, "the FK orphan filter is gone"
    assert "NOT EXISTS (SELECT 1 FROM queue" in stmt, "the PK anti-join is gone"

    # Placement matters as much as presence: SQL Server defers name resolution, so a statement placed
    # before `queue` exists would parse and then fail at RUN time on a legacy DB.
    queue_ddl = [i for i, s in enumerate(_SCHEMA) if "CREATE TABLE queue" in s]
    assert len(queue_ddl) == 1, "could not locate the queue DDL to check migration ordering"
    assert _SCHEMA.index(stmt) > queue_ddl[0], (
        "the migration runs BEFORE `queue` is created; on a legacy DB old enough to lack `queue` that "
        "is a failed open inside the batch's single transaction — a startup crash-loop"
    )


#: The ONLY engine modules allowed to name the retired table, and how many SQL references each may
#: carry. A migration must obviously still address the table it is migrating away, so a flat ban would
#: be unsatisfiable — but "some references are fine" is how a stray read hides forever. Pinning the
#: COUNT is what keeps the carve-out honest: a new `FROM outbox` anywhere in these files moves the
#: number and reds, even though the file is exempt from the ban itself.
_MIGRATION_MODULES = {
    # POSIX keys, matched against a POSIX-normalised path below. Native separators would key on
    # backslashes and MISS on the ubuntu leg, reporting both migrations as stray — a guard that is red
    # on one OS and green on another, which is worse than no guard.
    "store/store.py": (2, "_migrate_outbox_to_queue — the SQLite fold-into-queue + DROP"),
    "store/sqlserver.py": (1, "the _SCHEMA migrate-and-drop statement (ASVS 14.2.7)"),
}


def test_only_the_two_migrations_still_reference_the_retired_table() -> None:
    """No database needed. Anywhere else, a surviving read/write is *Invalid object name* at runtime.

    The keyed encrypt pass is covered separately and structurally by
    `tests/test_sqlserver_encrypt_pass_tables.py`; this is the broad sweep for everything else.

    Mutation: add a `SELECT ... FROM outbox` to any engine module — reds naming the file and line. Add
    one to a MIGRATION module — still reds, on the pinned count, which is the case a plain
    file-exemption list would have missed.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parents[1] / "messagefoundry"
    files = sorted(root.rglob("*.py"))
    # Liveness receipt: report what was EXAMINED. A glob matching nothing would pass vacuously.
    assert len(files) > 40, (
        f"liveness: only {len(files)} engine modules scanned — the glob is broken"
    )

    # Statements that would actually touch the table. `outbox_id`, `outbox_for`, `outbox_by_status`
    # and friends are API/method names, not the table, so the pattern is anchored on SQL keywords.
    sql = re.compile(r"\b(FROM|INTO|UPDATE|TABLE|JOIN)\s+outbox\b", re.I)
    stray: list[str] = []
    counts: dict[str, int] = {}
    for path in files:
        rel = path.relative_to(root).as_posix()
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not sql.search(line) or "DROP TABLE outbox" in line:
                continue
            if rel in _MIGRATION_MODULES:
                counts[rel] = counts.get(rel, 0) + 1
                continue
            stray.append(f"  {rel}:{lineno}: {line.strip()[:100]}")

    assert not stray, (
        f"scanned {len(files)} engine modules; these still address the retired `outbox` table "
        f"outside a migration:\n" + "\n".join(stray)
    )
    for rel, (expected, reason) in _MIGRATION_MODULES.items():
        got = counts.get(rel, 0)
        assert got == expected, (
            f"{rel} carries {got} SQL references to `outbox`, expected {expected} ({reason}). "
            f"More means a new one crept into a module exempt from the ban; fewer means the migration "
            f"itself was removed or rewritten — in which case a legacy store never gets folded in and "
            f"its PHI bodies stay unpurgeable, which is the whole point of the retirement."
        )
        assert "DROP TABLE outbox" in (root / rel).read_text(encoding="utf-8"), (
            f"{rel} is exempted as a MIGRATION but no longer DROPs the table — the exemption is stale"
        )
